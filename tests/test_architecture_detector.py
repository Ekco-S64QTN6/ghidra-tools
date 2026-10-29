#!/usr/bin/env python3
"""Synthetic, dependency-free tests for file format and ELF language detection."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
import architecture_detector as detector  # noqa: E402


def write_fixture(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def make_elf(elf_class, data_encoding, machine, length=None):
    required = 52 if elf_class == 1 else 64
    data = bytearray(length if length is not None else required)
    data[:4] = b"\x7fELF"
    data[4] = elf_class
    data[5] = data_encoding
    data[6] = 1
    endian = "<" if data_encoding == 1 else ">"
    if len(data) >= 20:
        struct.pack_into(endian + "H", data, 18, machine)
    return bytes(data)


def make_pe():
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x2102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    return bytes(data)


def make_snes():
    data = bytearray(b"\xFF" * 0x10000)
    header_offset = 0x7FC0
    data[header_offset:header_offset + 21] = b"DETECTION TEST ROM    "
    data[header_offset + 21] = 0x20
    struct.pack_into("<HH", data, header_offset + 28, 0x1234, 0xEDCB)
    struct.pack_into("<H", data, header_offset + 60, 0x8000)
    return bytes(data)


def make_gba():
    data = bytearray(0xC0)
    data[4:12] = detector.GBA_LOGO_PREFIX
    for index in range(0xA0, 0xBD):
        data[index] = index & 0xFF
    data[0xBD] = (-(0x19 + sum(data[0xA0:0xBD]))) & 0xFF
    return bytes(data)


class ArchitectureDetectorTests(unittest.TestCase):
    def test_elf_processor_mapping_uses_class_endianness_and_machine(self):
        cases = [
            (1, 1, 3, "x86:LE:32:default"),
            (2, 1, 62, "x86:LE:64:default"),
            (1, 1, 40, "ARM:LE:32:v8"),
            (2, 1, 183, "AARCH64:LE:64:v8A"),
            (1, 2, 8, "MIPS:BE:32:default"),
            (1, 1, 8, "MIPS:LE:32:default"),
            (2, 2, 8, "MIPS:BE:64:default"),
            (1, 1, 243, "RISCV:LE:32:RV32GC"),
            (2, 1, 243, "RISCV:LE:64:RV64GC"),
            (1, 2, 20, "PowerPC:BE:32:default"),
            (1, 1, 20, "PowerPC:LE:32:default"),
            (2, 2, 21, "PowerPC:BE:64:default"),
        ]
        with tempfile.TemporaryDirectory(prefix="architecture-elf-") as temp:
            for elf_class, encoding, machine, expected in cases:
                with self.subTest(elf_class=elf_class, encoding=encoding, machine=machine):
                    path = write_fixture(temp, "fixture.elf", make_elf(elf_class, encoding, machine))
                    result = detector.inspect_file(path)
                    self.assertEqual(result["format"], "elf")
                    self.assertEqual(result["processor"], expected)

    def test_unknown_machine_is_elf_but_does_not_guess_a_processor(self):
        with tempfile.TemporaryDirectory() as temp:
            path = write_fixture(temp, "unknown.bin", make_elf(2, 1, 0xFFFF))
            result = detector.inspect_file(path)
            self.assertEqual(result["format"], "elf")
            self.assertIsNone(result["processor"])
            self.assertIn("defer language selection", result["evidence"])

    def test_truncated_or_malformed_elf_never_selects_a_processor(self):
        with tempfile.TemporaryDirectory() as temp:
            short_path = write_fixture(temp, "short.elf", make_elf(2, 1, 62, length=32))
            short = detector.inspect_file(short_path)
            self.assertEqual(short["format"], "raw")
            self.assertIsNone(short["processor"])
            self.assertIn("truncated", short["evidence"])

            bad_path = write_fixture(temp, "bad.elf", make_elf(3, 1, 62))
            malformed = detector.inspect_file(bad_path)
            self.assertEqual(malformed["format"], "raw")
            self.assertIsNone(malformed["processor"])

    def test_valid_headers_override_mislabeled_extensions(self):
        with tempfile.TemporaryDirectory() as temp:
            pe = detector.inspect_file(write_fixture(temp, "renamed.bin", make_pe()))
            self.assertEqual(pe["format"], "pe")

            elf = detector.inspect_file(write_fixture(temp, "named.dll", make_elf(2, 1, 62)))
            self.assertEqual(elf["format"], "elf")
            self.assertEqual(elf["processor"], "x86:LE:64:default")

    def test_invalid_pe_signature_is_not_treated_as_a_pe(self):
        with tempfile.TemporaryDirectory() as temp:
            data = bytearray(make_pe())
            data[0x80:0x84] = b"NOPE"
            result = detector.inspect_file(write_fixture(temp, "fake.exe", bytes(data)))
            self.assertEqual(result["format"], "raw")
            self.assertIn("valid bounded PE header", result["evidence"])

    def test_console_formats_require_valid_headers_not_only_extensions(self):
        with tempfile.TemporaryDirectory() as temp:
            unknown_bin = detector.inspect_file(write_fixture(temp, "unknown.bin", b"\x00" * 4096))
            self.assertEqual(unknown_bin["format"], "raw")
            self.assertIn("not guessing SNES", unknown_bin["evidence"])

            false_snes = detector.inspect_file(write_fixture(temp, "fake.sfc", b"\x00" * 0x10000))
            self.assertEqual(false_snes["format"], "raw")
            self.assertIn("did not validate", false_snes["evidence"])

            snes = detector.inspect_file(write_fixture(temp, "valid.sfc", make_snes()))
            self.assertEqual(snes["format"], "snes")
            self.assertIn("validated SNES cartridge header", snes["evidence"])

            gba = detector.inspect_file(write_fixture(temp, "valid.GBA", make_gba()))
            self.assertEqual(gba["format"], "gba")
            self.assertIn("checksum", gba["evidence"])

    def test_n64_byte_order_magics_and_psx_header_are_validated(self):
        with tempfile.TemporaryDirectory() as temp:
            for magic, suffix in (
                (b"\x80\x37\x12\x40", ".z64"),
                (b"\x37\x80\x40\x12", ".v64"),
                (b"\x40\x12\x37\x80", ".n64"),
            ):
                path = write_fixture(temp, "game" + suffix, magic + b"\x00" * 32)
                self.assertEqual(detector.inspect_file(path)["format"], "n64")

            short_psx = detector.inspect_file(write_fixture(temp, "bad.psx", b"PS-X EXE" + b"\x00" * 20))
            self.assertEqual(short_psx["format"], "raw")
            valid_psx = detector.inspect_file(write_fixture(temp, "valid.psx", b"PS-X EXE" + b"\x00" * (0x800 - 8)))
            self.assertEqual(valid_psx["format"], "psx")

    def test_cli_and_import_use_the_detected_processor_and_batch_extensions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = write_fixture(temp, "x86_64.bin", make_elf(2, 1, 62))
            root = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "scripts", "architecture_detector.py"), "json", path],
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(root.stdout)
            self.assertEqual(result["processor"], "x86:LE:64:default")

        with open(os.path.join(REPO_ROOT, "ghidra-report.sh"), encoding="utf-8") as handle:
            shell = handle.read()
        self.assertIn('extra_args+=(-processor "$elf_arch")', shell)
        for extension in ('"*.gba"', '"*.psx"', '"*.z64"', '"*.n64"', '"*.v64"'):
            self.assertIn(extension, shell)


if __name__ == "__main__":
    unittest.main(verbosity=2)
