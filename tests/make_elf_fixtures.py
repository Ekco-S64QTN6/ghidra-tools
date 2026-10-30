#!/usr/bin/env python3
"""Generate tiny, redistributable ELF executables for Ghidra architecture acceptance tests."""

import json
import os
import struct
import sys

BASE_ADDRESS = 0x10000
SEGMENT_OFFSET = 0x1000

# name, ELF class, EI_DATA, e_machine, e_flags, expected Ghidra language ID, code bytes
FIXTURES = [
    ("x86-32-le", 1, 1, 3, 0, "x86:LE:32:default", b"\x31\xc0\xc3"),
    ("x86-64-le", 2, 1, 62, 0, "x86:LE:64:default", b"\x31\xc0\xc3"),
    ("arm-32-le", 1, 1, 40, 0x05000000, "ARM:LE:32:v8", b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1"),
    ("arm-32-be", 1, 2, 40, 0x05000000, "ARM:BE:32:v8", b"\xe3\xa0\x00\x00\xe1\x2f\xff\x1e"),
    # BE8 keeps big-endian ELF data while storing instructions in little-endian byte order.
    ("arm-32-be8", 1, 2, 40, 0x05800000, "ARM:LEBE:32:v8LEInstruction", b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1"),
    ("aarch64-64-le", 2, 1, 183, 0, "AARCH64:LE:64:v8A", b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6"),
    ("aarch64-64-be", 2, 2, 183, 0, "AARCH64:BE:64:v8A", b"\xd2\x80\x00\x00\xd6\x5f\x03\xc0"),
    ("mips-32-le", 1, 1, 8, 0x70001000, "MIPS:LE:32:default", b"\x00\x00\x02\x24\x08\x00\xe0\x03\x00\x00\x00\x00"),
    ("mips-32-be", 1, 2, 8, 0x70001000, "MIPS:BE:32:default", b"\x24\x02\x00\x00\x03\xe0\x00\x08\x00\x00\x00\x00"),
    ("riscv-32-le", 1, 1, 243, 0x4, "RISCV:LE:32:default", b"\x13\x05\x00\x00\x67\x80\x00\x00"),
    ("riscv-64-le", 2, 1, 243, 0x4, "RISCV:LE:64:default", b"\x13\x05\x00\x00\x67\x80\x00\x00"),
    ("ppc-32-le", 1, 1, 20, 0, "PowerPC:LE:32:default", b"\x00\x00\x60\x38\x20\x00\x80\x4e"),
    ("ppc-32-be", 1, 2, 20, 0, "PowerPC:BE:32:default", b"\x38\x60\x00\x00\x4e\x80\x00\x20"),
    ("ppc-64-le", 2, 1, 21, 2, "PowerPC:LE:64:default", b"\x00\x00\x60\x38\x20\x00\x80\x4e"),
    ("ppc-64-be", 2, 2, 21, 1, "PowerPC:BE:64:default", b"\x38\x60\x00\x00\x4e\x80\x00\x20"),
]


def build_elf(elf_class, data_encoding, machine, flags, code):
    endian = "<" if data_encoding == 1 else ">"
    is_64 = elf_class == 2
    header_size = 64 if is_64 else 52
    phdr_size = 56 if is_64 else 32
    phoff = header_size

    if is_64:
        header = struct.pack(
            endian + "HHIQQQIHHHHHH",
            2, machine, 1, BASE_ADDRESS, phoff, 0, flags,
            header_size, phdr_size, 1, 64, 0, 0,
        )
        phdr = struct.pack(
            endian + "IIQQQQQQ",
            1, 5, SEGMENT_OFFSET, BASE_ADDRESS, BASE_ADDRESS,
            len(code), len(code), 0x1000,
        )
    else:
        header = struct.pack(
            endian + "HHIIIIIHHHHHH",
            2, machine, 1, BASE_ADDRESS, phoff, 0, flags,
            header_size, phdr_size, 1, 40, 0, 0,
        )
        phdr = struct.pack(
            endian + "IIIIIIII",
            1, SEGMENT_OFFSET, BASE_ADDRESS, BASE_ADDRESS,
            len(code), len(code), 5, 0x1000,
        )

    if 16 + len(header) != header_size or len(phdr) != phdr_size:
        raise ValueError("unexpected ELF header/program-header size")

    data = bytearray(SEGMENT_OFFSET + len(code))
    data[:4] = b"\x7fELF"
    data[4] = elf_class
    data[5] = data_encoding
    data[6] = 1  # EV_CURRENT
    data[7] = 0  # System V ABI
    data[16:16 + len(header)] = header
    data[phoff:phoff + len(phdr)] = phdr
    data[SEGMENT_OFFSET:] = code
    return bytes(data)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {os.path.basename(sys.argv[0])} <output-directory>")
    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)
    manifest = []
    for name, elf_class, data_encoding, machine, flags, language, code in FIXTURES:
        path = os.path.join(output_dir, name + ".elf")
        with open(path, "wb") as handle:
            handle.write(build_elf(elf_class, data_encoding, machine, flags, code))
        manifest.append({"name": name, "path": path, "language_id": language})
    with open(os.path.join(output_dir, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print(f"Generated {len(manifest)} synthetic ELF executables")


if __name__ == "__main__":
    main()
