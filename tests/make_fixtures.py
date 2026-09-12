#!/usr/bin/env python3
"""
tests/make_fixtures.py — synthesize the binaries the integration suite analyzes.

The suite must never read from ingress/: that is a drop folder for whatever the
user is actually triaging, and its contents are git-ignored and machine-specific.
Instead every fixture is generated here, deterministically, from code that ships
with the repo — so a fresh clone (and CI) can run the full suite.

Two fixtures are produced:

  packed_sample.dll  A minimal but structurally valid PE32 DLL carrying every
                     signal the threat engine scores on: a .themida RWX section,
                     a maximum-entropy .boot section, both x86 GetPC shellcode
                     idioms, and a real import table of ATT&CK-tagged APIs.

  console_sample.sfc A 64 KB LoROM SNES cartridge with a checksum-valid header
                     and 65816 code touching >10 distinct PPU MMIO registers
                     plus complete DMA and HDMA channel setups.

                     Note the SNES layout is built for Ghidra's *raw* 65816 import,
                     where file offset equals address, because the SnesRomLoader
                     extension declines both this fixture and real retail ROMs —
                     ghidra-report.sh always lands on the raw fallback. Code and
                     CPU vectors therefore sit at their raw addresses ($8000 and
                     $FFE0-$FFFF), while the cartridge header stays at its LoROM
                     offset ($7FC0) where SnesAnalyzer.parseHeader looks for it.

Usage:  python3 tests/make_fixtures.py <output-dir>
"""

import os
import random
import struct
import sys

# ─────────────────────────────────────────────────────────────────────────────
# PE32 fixture
# ─────────────────────────────────────────────────────────────────────────────

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMPORTS = [
    ("KERNEL32.dll", ["GetModuleHandleA", "VirtualAlloc"]),
    ("SHELL32.dll", ["ShellExecuteA"]),
    ("IPHLPAPI.DLL", ["GetIpAddrTable"]),
    ("PSAPI.DLL", ["GetModuleInformation"]),
]

IMAGE_BASE = 0x10000000
SECT_ALIGN = 0x1000
FILE_ALIGN = 0x200


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _build_import_blob(base_rva):
    """Lays out descriptors, ILT/IAT thunk arrays and name strings for one section."""
    desc_size = (len(IMPORTS) + 1) * 20
    cursor = desc_size

    thunks = []       # (ilt_rva, iat_rva, [hintname_rva...])
    hintnames = {}    # name -> rva
    layout = []

    for _dll, funcs in IMPORTS:
        ilt_off = cursor
        cursor += (len(funcs) + 1) * 4
        iat_off = cursor
        cursor += (len(funcs) + 1) * 4
        thunks.append((ilt_off, iat_off, funcs))

    for _dll, funcs in IMPORTS:
        for fn in funcs:
            if fn not in hintnames:
                hintnames[fn] = cursor
                cursor += 2 + len(fn) + 1
                cursor += cursor % 2  # IMAGE_IMPORT_BY_NAME is word-aligned

    dll_name_offs = {}
    for dll, _funcs in IMPORTS:
        dll_name_offs[dll] = cursor
        cursor += len(dll) + 1

    blob = bytearray(cursor)

    for i, (dll, funcs) in enumerate(IMPORTS):
        ilt_off, iat_off, _ = thunks[i]
        struct.pack_into(
            "<IIIII", blob, i * 20,
            base_rva + ilt_off,        # OriginalFirstThunk
            0,                          # TimeDateStamp
            0,                          # ForwarderChain
            base_rva + dll_name_offs[dll],
            base_rva + iat_off,        # FirstThunk
        )
        for j, fn in enumerate(funcs):
            rva = base_rva + hintnames[fn]
            struct.pack_into("<I", blob, ilt_off + j * 4, rva)
            struct.pack_into("<I", blob, iat_off + j * 4, rva)

    for fn, off in hintnames.items():
        struct.pack_into("<H", blob, off, 0)
        blob[off + 2:off + 2 + len(fn)] = fn.encode("ascii")

    for dll, off in dll_name_offs.items():
        blob[off:off + len(dll)] = dll.encode("ascii")

    layout = (base_rva, desc_size)
    return bytes(blob), layout


def _build_text(iat_rva_base):
    """x86 stub carrying both GetPC idioms the shellcode detector looks for."""
    code = bytearray()
    code += b"\x55\x8b\xec"              # push ebp; mov ebp, esp
    code += b"\xe8\x00\x00\x00\x00"      # call $+5      ─┐ GetPC idiom #1
    code += b"\x58"                       # pop eax       ─┘
    code += b"\xd9\xee"                  # fldz          ─┐ GetPC idiom #2
    code += b"\xd9\x74\x24\xf4"          # fnstenv [esp-12]
    code += b"\x5b"                       # pop ebx       ─┘
    code += b"\x33\xc0"                  # xor eax, eax
    code += b"\x6a\x00"                  # push 0
    code += b"\xff\x15" + struct.pack("<I", IMAGE_BASE + iat_rva_base)  # call [IAT]
    code += b"\x83\xc4\x04"              # add esp, 4
    code += b"\xb8\x01\x00\x00\x00"      # mov eax, 1
    code += b"\x5d"                       # pop ebp
    code += b"\xc2\x0c\x00"              # ret 12
    return bytes(code)


def build_packed_pe(path):
    sections = []

    idata_rva = 0x2000
    import_blob, (_, desc_size) = _build_import_blob(idata_rva)
    # First IAT lives right after the descriptor array + first ILT.
    first_iat_rva = idata_rva + desc_size + (len(IMPORTS[0][1]) + 1) * 4

    text = _build_text(first_iat_rva)

    # Maximum-entropy payload — this is what trips the > 7.2 packed threshold.
    rng = random.Random(0xC0FFEE)
    boot = bytes(rng.randrange(256) for _ in range(0x1000))

    # RWX staging section, named so the packer signature matcher fires.
    themida = b"\x00" * 0x40 + b"TMD\x00" + b"\x00" * 0x1BC

    sections = [
        (".text", text, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ),
        (".idata", import_blob, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ),
        (".boot", boot, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ),
        (".themida", themida,
         IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
    ]

    num_sections = len(sections)
    opt_header_size = 224
    headers_size = 0x80 + 4 + 20 + opt_header_size + num_sections * 40
    size_of_headers = _align(headers_size, FILE_ALIGN)

    placed = []
    va = SECT_ALIGN
    raw = size_of_headers
    for name, data, chars in sections:
        vsize = len(data)
        rawsize = _align(len(data), FILE_ALIGN)
        placed.append((name, data, chars, va, vsize, raw, rawsize))
        va = _align(va + vsize, SECT_ALIGN)
        raw += rawsize
    size_of_image = va

    out = bytearray()

    # ── DOS header + stub ────────────────────────────────────────────────
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x02, 0x90)
    struct.pack_into("<H", dos, 0x04, 0x03)
    struct.pack_into("<H", dos, 0x08, 0x04)
    struct.pack_into("<H", dos, 0x0A, 0x00)
    struct.pack_into("<H", dos, 0x0C, 0xFFFF)
    struct.pack_into("<H", dos, 0x0E, 0xFFFF)
    struct.pack_into("<H", dos, 0x10, 0xB8)
    struct.pack_into("<H", dos, 0x18, 0x40)
    struct.pack_into("<I", dos, 0x3C, 0x80)
    dos[0x40:0x4E] = (b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd"
                      b"\x21\xb8\x01\x4c\xcd\x21")
    dos[0x4E:0x4E + 0x27] = b"This program cannot be run in DOS mode.\r\r\n$"[:0x27]
    out += dos

    # ── PE signature + COFF header ───────────────────────────────────────
    out += b"PE\x00\x00"
    out += struct.pack(
        "<HHIIIHH",
        0x014C,           # Machine: i386
        num_sections,
        0,                # TimeDateStamp
        0, 0,             # symbol table (none)
        opt_header_size,
        0x2102,           # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL
    )

    # ── Optional header (PE32) ───────────────────────────────────────────
    text_meta = placed[0]
    opt = bytearray()
    opt += struct.pack(
        "<HBBIIIIII",
        0x010B,                       # Magic: PE32
        14, 0,                        # linker version
        len(text),                    # SizeOfCode
        sum(len(s[1]) for s in sections[1:]),
        0,                            # SizeOfUninitializedData
        text_meta[3],                 # AddressOfEntryPoint
        text_meta[3],                 # BaseOfCode
        placed[1][3],                 # BaseOfData
    )
    opt += struct.pack(
        "<IIIHHHHHHIIIIHH",
        IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
        6, 0,                         # OS version
        0, 0,                         # image version
        6, 0,                         # subsystem version
        0,                            # Win32VersionValue
        size_of_image, size_of_headers,
        0,                            # CheckSum
        3,                            # Subsystem: CONSOLE
        0x0400,                       # DllCharacteristics: NO_SEH
    )
    opt += struct.pack(
        "<IIIIII",
        0x100000, 0x1000,             # SizeOfStackReserve / Commit
        0x100000, 0x1000,             # SizeOfHeapReserve / Commit
        0,                            # LoaderFlags
        16,                           # NumberOfRvaAndSizes
    )
    # 28 standard + 44 windows-specific + 24 = 96 bytes, leaving 16 * 8 = 128
    # bytes of data directories to reach the declared 224.
    dirs = [(0, 0)] * 16
    dirs[1] = (idata_rva, desc_size)                    # Import table
    dirs[12] = (first_iat_rva, (len(IMPORTS[0][1]) + 1) * 4)  # IAT
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)
    assert len(opt) == opt_header_size, len(opt)
    out += opt

    # ── Section table ────────────────────────────────────────────────────
    for name, _data, chars, va_, vsize, raw_, rawsize in placed:
        out += struct.pack(
            "<8sIIIIIIHHI",
            name.encode("ascii"),
            vsize, va_, rawsize, raw_,
            0, 0, 0, 0,
            chars,
        )

    out += b"\x00" * (size_of_headers - len(out))

    # ── Section bodies ───────────────────────────────────────────────────
    for _name, data, _chars, _va, _vsize, raw_, rawsize in placed:
        assert len(out) == raw_, (len(out), raw_)
        out += data + b"\x00" * (rawsize - len(data))

    with open(path, "wb") as fh:
        fh.write(out)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# SNES fixture
# ─────────────────────────────────────────────────────────────────────────────

ROM_SIZE = 0x10000
HEADER_OFF = 0x7FC0      # cartridge header, where SnesAnalyzer.parseHeader looks
CODE_OFF = 0x8000        # reset target, addressable under the raw 1:1 mapping
NMI_OFF = 0x8200


def build_snes_rom(path):
    rom = bytearray(b"\xFF" * ROM_SIZE)

    code = bytearray()
    code += b"\x78"              # SEI
    code += b"\x18"              # CLC
    code += b"\xFB"              # XCE           → native mode
    code += b"\xE2\x30"          # SEP #$30      → 8-bit A/X/Y

    # Touch a wide spread of PPU registers so the MMIO map has real content.
    for reg in range(0x2100, 0x2116):
        code += b"\xA9" + bytes([reg & 0xFF])     # LDA #imm
        code += b"\x8D" + struct.pack("<H", reg)  # STA $21xx

    # CPU-side registers.
    for reg in (0x4200, 0x420C):
        code += b"\xA9\x81"
        code += b"\x8D" + struct.pack("<H", reg)

    # A complete DMA channel 0 programming sequence.
    for reg, val in ((0x4300, 0x01),   # DMAP0  transfer mode
                     (0x4301, 0x18),   # BBAD0  → VMDATAL
                     (0x4302, 0x00),   # A1T0L
                     (0x4303, 0x80),   # A1T0H
                     (0x4304, 0x00),   # A1B0
                     (0x4305, 0x00),   # DAS0L
                     (0x4306, 0x20)):  # DAS0H
        code += b"\xA9" + bytes([val])
        code += b"\x8D" + struct.pack("<H", reg)
    code += b"\xA9\x01"
    code += b"\x8D\x0B\x42"      # STA $420B  → MDMAEN, kick the transfer

    # An HDMA channel 1 setup, so the DMA table has a second entry.
    for reg, val in ((0x4310, 0x42), (0x4311, 0x22), (0x4312, 0x00), (0x4313, 0x90)):
        code += b"\xA9" + bytes([val])
        code += b"\x8D" + struct.pack("<H", reg)
    code += b"\xA9\x02"
    code += b"\x8D\x0C\x42"      # STA $420C  → HDMAEN

    code += b"\x6B"              # RTL

    # Raw import maps file offset → address 1:1, so the code lives at $8000.
    rom[CODE_OFF:CODE_OFF + len(code)] = code

    # NMI handler — a second function for the priority scorer to rank.
    nmi = bytearray()
    nmi += b"\x08"               # PHP
    nmi += b"\xA9\x0F"           # LDA #$0F
    nmi += b"\x8D\x00\x21"       # STA $2100  (INIDISP)
    nmi += b"\xAD\x10\x42"       # LDA $4210  (RDNMI, acknowledge)
    nmi += b"\x28"               # PLP
    nmi += b"\x40"               # RTI
    rom[NMI_OFF:NMI_OFF + len(nmi)] = nmi

    # ── Cartridge header ─────────────────────────────────────────────────
    title = b"GHIDRA TOOLS FIXTURE "          # exactly 21 bytes
    assert len(title) == 21
    rom[HEADER_OFF:HEADER_OFF + 21] = title
    rom[HEADER_OFF + 21] = 0x20               # LoROM, slow ROM
    rom[HEADER_OFF + 22] = 0x00               # ROM only
    rom[HEADER_OFF + 23] = 0x08               # 2 MBit
    rom[HEADER_OFF + 24] = 0x00               # no SRAM
    rom[HEADER_OFF + 25] = 0x01               # region: NTSC
    rom[HEADER_OFF + 26] = 0x33               # developer id
    rom[HEADER_OFF + 27] = 0x00               # version

    # ── Interrupt vectors ────────────────────────────────────────────────
    # Written twice: at $FFE0-$FFFF, which is where the 65816 actually fetches
    # them under the raw 1:1 mapping and what seeds Ghidra's disassembly, and at
    # the mirrored LoROM offsets so the ROM is also structurally correct.
    vectors = ((0x0A, NMI_OFF),      # native NMI
               (0x0E, CODE_OFF),     # native IRQ
               (0x1A, NMI_OFF),      # emulation NMI
               (0x1C, CODE_OFF),     # emulation RESET
               (0x1E, CODE_OFF))     # emulation IRQ
    for base in (0xFFE0, 0x7FE0):
        for delta, target in vectors:
            struct.pack_into("<H", rom, base + delta, target)

    # ── Checksum pair (the parser requires csum + comp == 0xFFFF) ────────
    struct.pack_into("<H", rom, HEADER_OFF + 28, 0x0000)
    struct.pack_into("<H", rom, HEADER_OFF + 30, 0x0000)
    checksum = sum(rom) & 0xFFFF
    if checksum in (0x0000, 0xFFFF):
        rom[0x1000] ^= 0xA5
        checksum = sum(rom) & 0xFFFF
    complement = checksum ^ 0xFFFF
    struct.pack_into("<H", rom, HEADER_OFF + 28, complement)
    struct.pack_into("<H", rom, HEADER_OFF + 30, checksum)

    with open(path, "wb") as fh:
        fh.write(rom)
    return path


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)
    pe = build_packed_pe(os.path.join(out_dir, "packed_sample.dll"))
    sfc = build_snes_rom(os.path.join(out_dir, "console_sample.sfc"))
    for p in (pe, sfc):
        print(f"{p}  ({os.path.getsize(p):,} bytes)")


if __name__ == "__main__":
    main()
