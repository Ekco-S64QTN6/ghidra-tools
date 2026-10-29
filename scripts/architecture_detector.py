#!/usr/bin/env python3
"""Evidence-based file-format and ELF processor detection for ghidra-report.

The detector intentionally treats filename suffixes as hints, not proof. Unknown
or truncated inputs fall back to raw import instead of being guessed to be SNES.
"""

import json
import os
import struct
import sys


ELF_LANGUAGES = {
    # e_machine: ELF class, e_ident data encoding -> Ghidra language ID
    3: {(1, 1): "x86:LE:32:default"},                       # EM_386
    62: {(2, 1): "x86:LE:64:default"},                     # EM_X86_64
    40: {(1, 1): "ARM:LE:32:v8", (1, 2): "ARM:BE:32:v8"},  # EM_ARM
    183: {(2, 1): "AARCH64:LE:64:v8A", (2, 2): "AARCH64:BE:64:v8A"},
    8: {                                                    # EM_MIPS
        (1, 1): "MIPS:LE:32:default",
        (1, 2): "MIPS:BE:32:default",
        (2, 1): "MIPS:LE:64:default",
        (2, 2): "MIPS:BE:64:default",
    },
    243: {                                                  # EM_RISCV (standard ELF is little-endian)
        (1, 1): "RISCV:LE:32:RV32GC",
        (2, 1): "RISCV:LE:64:RV64GC",
    },
    20: {                                                    # EM_PPC
        (1, 1): "PowerPC:LE:32:default",
        (1, 2): "PowerPC:BE:32:default",
    },
    21: {                                                    # EM_PPC64
        (2, 1): "PowerPC:LE:64:default",
        (2, 2): "PowerPC:BE:64:default",
    },
}
ELF_NAMES = {
    3: "EM_386",
    8: "EM_MIPS",
    20: "EM_PPC",
    21: "EM_PPC64",
    40: "EM_ARM",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}
N64_MAGICS = {
    b"\x80\x37\x12\x40": "N64 big-endian (.z64 layout)",
    b"\x37\x80\x40\x12": "N64 byte-swapped (.v64 layout)",
    b"\x40\x12\x37\x80": "N64 little-endian (.n64 layout)",
}
GBA_LOGO_PREFIX = bytes.fromhex("24 ff ae 51 69 9a a2 21")
KNOWN_EXTENSIONS = {
    ".sfc": "snes",
    ".smc": "snes",
    ".fig": "snes",
    ".gba": "gba",
    ".z64": "n64",
    ".n64": "n64",
    ".v64": "n64",
    ".psx": "psx",
    ".exe": "pe",
    ".dll": "pe",
    ".sys": "pe",
    ".elf": "elf",
    ".so": "elf",
    ".o": "elf",
}


def _read_at(path, offset, size):
    if offset < 0:
        return b""
    try:
        with open(path, "rb") as stream:
            stream.seek(offset)
            return stream.read(size)
    except OSError:
        return b""


def inspect_elf(path):
    """Return parsed ELF identity and, only when known, a processor language ID."""
    header = _read_at(path, 0, 64)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None

    elf_class = header[4]
    data_encoding = header[5]
    ident_version = header[6]
    if elf_class not in (1, 2) or data_encoding not in (1, 2) or ident_version != 1:
        return {
            "valid": False,
            "processor": None,
            "evidence": "ELF magic present, but class/byte-order/version fields are invalid or truncated",
        }

    endian = "<" if data_encoding == 1 else ">"
    machine = struct.unpack(endian + "H", header[18:20])[0]
    elf_bits = 32 if elf_class == 1 else 64
    processor = ELF_LANGUAGES.get(machine, {}).get((elf_class, data_encoding))
    machine_name = ELF_NAMES.get(machine, f"e_machine={machine}")
    endian_name = "little-endian" if data_encoding == 1 else "big-endian"

    evidence = f"ELF{elf_bits}, {endian_name}, {machine_name}"
    if processor:
        evidence += f" -> {processor}"
    else:
        evidence += "; no supported Ghidra language mapping, defer language selection to Ghidra"

    return {
        "valid": True,
        "class": elf_bits,
        "byte_order": endian_name,
        "e_machine": machine,
        "machine_name": machine_name,
        "processor": processor,
        "evidence": evidence,
    }


def _valid_pe(path, size):
    dos = _read_at(path, 0, 64)
    if len(dos) < 64 or dos[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < 64 or pe_offset + 26 > size:
        return False
    pe_header = _read_at(path, pe_offset, 26)
    if len(pe_header) < 26 or pe_header[:4] != b"PE\x00\x00":
        return False
    optional_size = struct.unpack_from("<H", pe_header, 20)[0]
    if optional_size < 2 or pe_offset + 24 + optional_size > size:
        return False
    optional_magic = struct.unpack("<H", _read_at(path, pe_offset + 24, 2))[0]
    return optional_magic in (0x10B, 0x20B)


def _valid_snes_header(path, size):
    """Require a plausible title/mode, checksum complement, and reset vector."""
    for copier_prefix in (0, 512):
        for base in (0x7FC0, 0xFFC0, 0x40FFC0):
            offset = copier_prefix + base
            if offset + 64 > size:
                continue
            header = _read_at(path, offset, 64)
            if len(header) != 64:
                continue
            title = header[:21]
            printable = sum(32 <= byte <= 126 for byte in title)
            map_mode = header[21]
            complement, checksum = struct.unpack_from("<HH", header, 28)
            reset_vector = struct.unpack_from("<H", header, 60)[0]
            if (
                printable >= 16
                and map_mode in (0x20, 0x21, 0x22, 0x23, 0x25, 0x30, 0x31, 0x32, 0x35)
                and ((complement + checksum) & 0xFFFF) == 0xFFFF
                and reset_vector not in (0x0000, 0xFFFF)
            ):
                return f"validated SNES cartridge header at file offset 0x{offset:X}"
    return None


def _valid_gba_header(path, size, extension):
    if extension != ".gba" or size < 0xC0:
        return None
    header = _read_at(path, 0, 0xC0)
    if len(header) < 0xC0 or header[4:12] != GBA_LOGO_PREFIX:
        return None
    calculated = (-(0x19 + sum(header[0xA0:0xBD]))) & 0xFF
    if header[0xBD] != calculated:
        return None
    return "GBA extension plus Nintendo logo signature and header complement checksum"


def inspect_file(path):
    """Return a format classification, evidence, and optional processor ID."""
    extension = os.path.splitext(path)[1].lower()
    try:
        size = os.path.getsize(path)
    except OSError:
        return {
            "format": "raw",
            "processor": None,
            "evidence": "file is missing or unreadable; falling back to raw import",
        }

    if size >= 4:
        magic = _read_at(path, 0, 8)
        if magic[:4] == b"\x7fELF":
            elf = inspect_elf(path)
            if elf and elf.get("valid"):
                return {"format": "elf", "processor": elf["processor"], "evidence": elf["evidence"]}
            return {"format": "raw", "processor": None, "evidence": elf["evidence"] if elf else "truncated ELF header; raw import"}

        if magic[:4] in N64_MAGICS:
            return {"format": "n64", "processor": None, "evidence": N64_MAGICS[magic[:4]]}

        if magic[:8] == b"PS-X EXE":
            if size >= 0x800:
                return {"format": "psx", "processor": None, "evidence": "PS-X EXE magic and minimum 0x800-byte header"}
            return {"format": "raw", "processor": None, "evidence": "PS-X EXE magic but truncated executable header"}

        if magic[:2] == b"MZ":
            if _valid_pe(path, size):
                return {"format": "pe", "processor": None, "evidence": "MZ header, bounded PE signature, and PE32/PE32+ optional-header magic"}
            return {"format": "raw", "processor": None, "evidence": "MZ signature without a valid bounded PE header; raw import"}

    elf = inspect_elf(path)
    if elf and not elf.get("valid"):
        return {"format": "raw", "processor": None, "evidence": elf["evidence"]}

    if _valid_snes_header(path, size):
        return {"format": "snes", "processor": None, "evidence": _valid_snes_header(path, size)}

    gba_evidence = _valid_gba_header(path, size, extension)
    if gba_evidence:
        return {"format": "gba", "processor": None, "evidence": gba_evidence}

    hinted = KNOWN_EXTENSIONS.get(extension)
    if hinted:
        return {
            "format": "raw",
            "processor": None,
            "evidence": f"extension {extension} suggests {hinted}, but the required header signature/fields did not validate; raw import",
        }

    if extension == ".bin" or extension == ".rom":
        return {
            "format": "raw",
            "processor": None,
            "evidence": f"unrecognized header with {extension} extension; not guessing SNES",
        }

    return {"format": "raw", "processor": None, "evidence": "no recognized format signature; raw import"}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2 or argv[0] not in {"type", "arch", "evidence", "json"}:
        print(f"Usage: {os.path.basename(sys.argv[0])} <type|arch|evidence|json> <file>", file=sys.stderr)
        return 2

    command, path = argv
    result = inspect_file(path)
    if command == "type":
        print(result["format"])
    elif command == "arch":
        if result.get("processor"):
            print(result["processor"])
    elif command == "evidence":
        print(result["evidence"])
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
