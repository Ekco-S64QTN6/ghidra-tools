#!/usr/bin/env python3
"""Synthetic regression tests for bounded firmware container parsing."""

import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import firmware_carver  # noqa: E402


UIMAGE_MAGIC = 0x27051956


def make_uimage(declared_size, payload=b"", name=b"synthetic-test"):
    header = struct.pack(
        ">IIIIIIIBBBB32s",
        UIMAGE_MAGIC,
        0,              # header CRC (not checked by this targeted regression)
        1700000000,
        declared_size,
        0,              # load address
        0,              # entry point
        0,              # data CRC
        5,              # Linux
        1,              # ARM
        2,              # kernel
        0,              # no compression
        name + b"\x00",
    )
    if len(header) != 64:
        raise AssertionError("synthetic uImage header must be 64 bytes")
    return header + payload


class UImageBoundsTests(unittest.TestCase):
    def test_valid_payload_size_is_preserved(self):
        payload = b"firmware-payload"
        data = b"prefix" + make_uimage(len(payload), payload)
        found = firmware_carver.parse_uimage(data, len(b"prefix"))
        self.assertIsNotNone(found)
        self.assertEqual(found["offset"], len(b"prefix"))
        self.assertEqual(found["payload_size"], len(payload))
        self.assertEqual(found["total_size"], 64 + len(payload))

    def test_declared_payload_larger_than_remaining_bytes_is_rejected(self):
        data = make_uimage(100, b"short")
        self.assertIsNone(firmware_carver.parse_uimage(data, 0))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
