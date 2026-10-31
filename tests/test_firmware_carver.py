#!/usr/bin/env python3
"""Synthetic regression tests for bounded firmware container parsing."""

import contextlib
import gzip
import io
import os
import struct
import sys
import tempfile
import unittest
import zlib
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import firmware_carver  # noqa: E402


UIMAGE_MAGIC = 0x27051956


def make_uimage(declared_size, payload=b"", name=b"synthetic-test", compression=0):
    header = bytearray(struct.pack(
        ">IIIIIIIBBBB32s",
        UIMAGE_MAGIC,
        0,              # header CRC is calculated after the header is complete
        1700000000,
        declared_size,
        0,              # load address
        0,              # entry point
        zlib.crc32(payload) & 0xFFFFFFFF,
        5,              # Linux
        1,              # ARM
        2,              # kernel
        compression,    # U-Boot compression ID
        name[:31].ljust(31, b"\x00") + b"\x00",
    ))
    if len(header) != 64:
        raise AssertionError("synthetic uImage header must be 64 bytes")
    struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
    return bytes(header) + payload


class UImageBoundsTests(unittest.TestCase):
    def test_valid_payload_size_is_preserved(self):
        payload = b"firmware-payload"
        data = b"prefix" + make_uimage(len(payload), payload)
        found = firmware_carver.parse_uimage(data, len(b"prefix"))
        self.assertIsNotNone(found)
        self.assertEqual(found["offset"], len(b"prefix"))
        self.assertEqual(found["payload_size"], len(payload))
        self.assertEqual(found["total_size"], 64 + len(payload))
        self.assertTrue(found["header_crc32"].startswith("0x"))
        self.assertTrue(found["data_crc32"].startswith("0x"))

    def test_declared_payload_larger_than_remaining_bytes_is_rejected(self):
        data = make_uimage(100, b"short")
        self.assertIsNone(firmware_carver.parse_uimage(data, 0))

    def test_rejects_corrupt_header_crc(self):
        data = bytearray(make_uimage(16, b"firmware-payload"))
        data[16] ^= 0x01  # change load address without updating ih_hcrc
        self.assertIsNone(firmware_carver.parse_uimage(data, 0))

    def test_rejects_corrupt_payload_crc(self):
        data = bytearray(make_uimage(16, b"firmware-payload"))
        data[-1] ^= 0x01  # payload no longer matches ih_dcrc
        self.assertIsNone(firmware_carver.parse_uimage(data, 0))

    def test_scan_warns_and_ignores_bad_uimage_payload_crc(self):
        data = bytearray(make_uimage(16, b"firmware-payload"))
        data[-1] ^= 0x01
        with tempfile.NamedTemporaryFile(prefix="uimage-bad-crc-", suffix=".bin") as handle:
            handle.write(data)
            handle.flush()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                findings = firmware_carver.scan_file(handle.name)

        self.assertFalse(any(item.get("type") == "uimage" for item in findings))
        self.assertIn("header or payload CRC-32 mismatch", stderr.getvalue())

    def test_parser_rejects_negative_and_out_of_range_offsets(self):
        data = make_uimage(0)
        self.assertIsNone(firmware_carver.parse_uimage(data, -1))
        self.assertIsNone(firmware_carver.parse_uimage(data, len(data) + 1))

    def test_scan_warns_and_does_not_report_truncated_image(self):
        data = make_uimage(128, b"only-five")
        with tempfile.NamedTemporaryFile(prefix="uimage-truncated-", suffix=".bin") as handle:
            handle.write(data)
            handle.flush()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                findings = firmware_carver.scan_file(handle.name)

        self.assertFalse(any(item.get("type") == "uimage" for item in findings))
        diagnostic = stderr.getvalue()
        self.assertIn("Ignoring truncated uImage", diagnostic)
        self.assertIn("header declares 128 payload bytes", diagnostic)
        self.assertIn("only 9 remain", diagnostic)

    def test_extract_does_not_write_truncated_image(self):
        data = make_uimage(512, b"short")
        with tempfile.TemporaryDirectory(prefix="uimage-bounds-") as temp:
            source = os.path.join(temp, "truncated.bin")
            output = os.path.join(temp, "carved")
            with open(source, "wb") as handle:
                handle.write(data)

            with contextlib.redirect_stderr(io.StringIO()):
                extracted = firmware_carver.extract_containers(source, output)

            self.assertEqual(extracted, [])
            self.assertEqual(os.listdir(output), [])


class RecursiveBudgetTests(unittest.TestCase):
    def write_source(self, directory, payload, name="firmware.bin"):
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(payload)
        return path

    def test_empty_input_is_scannable(self):
        with tempfile.NamedTemporaryFile(prefix="empty-firmware-") as handle:
            self.assertEqual(firmware_carver.scan_file(handle.name), [])

    def test_nested_gzip_streams_are_extracted_recursively_with_provenance(self):
        leaf = b"nested firmware stage"
        inner = gzip.compress(leaf, mtime=0)
        outer = gzip.compress(inner, mtime=0)
        with tempfile.TemporaryDirectory(prefix="nested-gzip-") as temp:
            source = self.write_source(temp, outer)
            output = os.path.join(temp, "carved")
            limits = firmware_carver.CarveLimits(timeout_seconds=10)
            extracted = firmware_carver.extract_containers(source, output, limits)

            self.assertEqual(len(extracted), 2)
            self.assertEqual(
                [item["info"]["depth"] for item in extracted],
                [0, 1],
            )
            self.assertEqual(extracted[0]["info"]["source"], "firmware.bin")
            self.assertEqual(
                extracted[1]["info"]["parent"],
                os.path.basename(extracted[0]["path"]),
            )
            self.assertTrue(extracted[0]["decompressed_path"])
            self.assertTrue(extracted[1]["decompressed_path"])
            with open(extracted[1]["decompressed_path"], "rb") as handle:
                self.assertEqual(handle.read(), leaf)

    def test_depth_limit_stops_scanning_nested_output(self):
        inner = gzip.compress(b"nested stage", mtime=0)
        outer = gzip.compress(inner, mtime=0)
        with tempfile.TemporaryDirectory(prefix="gzip-depth-") as temp:
            source = self.write_source(temp, outer)
            output = os.path.join(temp, "carved")
            limits = firmware_carver.CarveLimits(max_depth=0, timeout_seconds=10)
            extracted = firmware_carver.extract_containers(source, output, limits)

            self.assertEqual(len(extracted), 1)
            self.assertEqual(extracted[0]["info"]["depth"], 0)
            self.assertIsNotNone(extracted[0]["decompressed_path"])
            self.assertEqual(len(os.listdir(output)), 2)

    def test_file_count_limit_prevents_unbounded_expansion_artifacts(self):
        compressed = gzip.compress(b"small firmware stage", mtime=0)
        with tempfile.TemporaryDirectory(prefix="gzip-file-budget-") as temp:
            source = self.write_source(temp, compressed)
            output = os.path.join(temp, "carved")
            limits = firmware_carver.CarveLimits(max_files=1, timeout_seconds=10)
            with contextlib.redirect_stderr(io.StringIO()):
                extracted = firmware_carver.extract_containers(source, output, limits)

            self.assertEqual(len(extracted), 1)
            self.assertIsNone(extracted[0]["decompressed_path"])
            self.assertEqual(len(os.listdir(output)), 1)

    def test_total_output_budget_fails_closed_before_writing(self):
        compressed = gzip.compress(b"payload", mtime=0)
        with tempfile.TemporaryDirectory(prefix="gzip-total-budget-") as temp:
            source = self.write_source(temp, compressed)
            output = os.path.join(temp, "carved")
            limits = firmware_carver.CarveLimits(
                max_total_bytes=len(compressed) - 1,
                timeout_seconds=10,
            )
            with contextlib.redirect_stderr(io.StringIO()):
                extracted = firmware_carver.extract_containers(source, output, limits)

            self.assertEqual(extracted, [])
            self.assertEqual(os.listdir(output), [])

    def test_per_file_limit_rejects_an_oversized_uimage(self):
        payload = b"U" * 128
        data = make_uimage(len(payload), payload)
        with tempfile.TemporaryDirectory(prefix="uimage-file-budget-") as temp:
            source = self.write_source(temp, data)
            output = os.path.join(temp, "carved")
            limits = firmware_carver.CarveLimits(
                max_file_bytes=100,
                timeout_seconds=10,
            )
            with contextlib.redirect_stderr(io.StringIO()):
                extracted = firmware_carver.extract_containers(source, output, limits)

            self.assertEqual(extracted, [])
            self.assertEqual(os.listdir(output), [])

    def test_high_expansion_ratio_gzip_is_not_accepted(self):
        compressed = gzip.compress(b"A" * 10000, mtime=0)
        with tempfile.NamedTemporaryFile(prefix="gzip-ratio-") as handle:
            handle.write(compressed)
            handle.flush()
            limits = firmware_carver.CarveLimits(
                max_compression_ratio=5,
                timeout_seconds=10,
            )
            self.assertEqual(firmware_carver.scan_file(handle.name, limits), [])

    def test_truncated_or_corrupt_gzip_is_not_accepted(self):
        compressed = gzip.compress(b"firmware", mtime=0)
        for damaged in (compressed[:-4], compressed[:-1] + bytes([compressed[-1] ^ 0xFF])):
            with self.subTest(size=len(damaged)):
                with tempfile.NamedTemporaryFile(prefix="gzip-corrupt-") as handle:
                    handle.write(damaged)
                    handle.flush()
                    self.assertEqual(firmware_carver.scan_file(handle.name), [])

    def test_gzip_uimage_payload_is_streamed_within_budgets(self):
        plain = b"kernel image payload"
        compressed = gzip.compress(plain, mtime=0)
        data = make_uimage(len(compressed), compressed, compression=1)
        with tempfile.TemporaryDirectory(prefix="uimage-gzip-") as temp:
            source = self.write_source(temp, data)
            output = os.path.join(temp, "carved")
            extracted = firmware_carver.extract_containers(
                source, output, firmware_carver.CarveLimits(timeout_seconds=10)
            )

            self.assertEqual(len(extracted), 1)
            with open(extracted[0]["decompressed_path"], "rb") as handle:
                self.assertEqual(handle.read(), plain)

    def test_environment_limits_are_validated(self):
        with patch.dict(os.environ, {"GHIDRA_CARVE_MAX_FILES": "0"}):
            with self.assertRaisesRegex(ValueError, "GHIDRA_CARVE_MAX_FILES"):
                firmware_carver.CarveLimits.from_env()

        for name, value in (
            ("GHIDRA_CARVE_MAX_COMPRESSION_RATIO", "nan"),
            ("GHIDRA_CARVE_MAX_COMPRESSION_RATIO", "inf"),
            ("GHIDRA_CARVE_TIMEOUT_SECONDS", "nan"),
            ("GHIDRA_CARVE_TIMEOUT_SECONDS", "inf"),
        ):
            with self.subTest(name=name, value=value):
                with patch.dict(os.environ, {name: value}):
                    with self.assertRaisesRegex(ValueError, name):
                        firmware_carver.CarveLimits.from_env()


if __name__ == "__main__":
    unittest.main(verbosity=2)
