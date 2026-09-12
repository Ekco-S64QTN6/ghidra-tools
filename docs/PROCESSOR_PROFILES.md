# Processor Profiles & Multi-Architecture Extension Guide

`ghidra-report` supports automatic processor and loader detection across desktop executables (PE, ELF, Mach-O), retro console ROMs (SNES, GBA, N64, PS1), firmware containers, and bare-metal microcontroller memory maps.

---

## 1. Supported Architecture & Loader Ecosystem

All community and bundled extensions reside in the Ghidra Flatpak Extensions directory:  
`~/.config/ghidra/ghidra_12.1.3_FLATPAK/Extensions/`

| Platform / Architecture | Loader Class / Extension | Ghidra Language ID | Detection Signature | Key Capabilities |
|---|---|---|---|---|
| **Super Nintendo (SNES)** | `SnesRomLoader` (`ghidra-snes-master`) | `65816:LE:24:default` | `.sfc`, `.smc`, `.fig` | LoROM/HiROM mapping, WRAM blocks, MMIO registers ($2100-$2143), SPC700 audio protocol |
| **Game Boy Advance (GBA)** | `GBALoader` (`gba-ghidra-loader`) | `ARM:LE:32:v4t` | `.gba` / Nintendo logo offset `0x04` | EWRAM, IWRAM, VRAM, ROM mapping, GBATEK hardware MMIO registers, BIOS SWI table |
| **Nintendo 64 (N64)** | `N64LoaderWVLoader` (`N64LoaderWV`) | `MIPS:BE:64:64-32addr` | `.z64`, `.n64`, `.v64` / Magic `0x80371240` | Big-endian/byte-swapped ROMs, RDRAM, MIPS VR4300 + RSP coprocessor, MMIO registers |
| **Sony PlayStation 1 (PS1)** | `PsxLoader` (`ghidra_psx_ldr`) | `MIPS:LE:32:default` | `.psx` / Magic `PS-X EXE` | MIPS R3000A, GTE (Geometry Engine) coprocessor, scratchpad, BIOS jump vectors |
| **Stripped Go Binaries** | `GolangAnalyzerExtension` | x86, x64, ARM, MIPS | `.gopclntab` section / Go build ID | Recovers function symbols, package hierarchies, source paths, and Go type descriptors |
| **UEFI / BIOS Firmware** | `ghidra-firmware-utils` | x86, x64, ARM | Firmware Volume GUID / FMAP | Parses UEFI FV, Firmware File System (FFS), Intel Flash Descriptor (IFD) |
| **Bare-Metal ARM Cortex-M** | `svd_injector.py` / `ghidra-svd` | `ARM:LE:32:Cortex` | `.svd` (CMSIS-SVD XML) | Vendor register bitfields, peripheral base addresses, interrupt vector tables |
| **Windows Executables** | Native PE Loader | `x86:LE:32:default`, `x86:LE:64:default` | Magic `MZ` | PE headers, imports, exports, TLS callbacks, Themida/packer entropy triage |
| **Linux / BSD Binaries** | Native ELF Loader | Auto-detected via `e_machine` | Magic `\x7fELF` | Symbols, dynamic imports, relocations, section entropy |

---

## 2. ELF `e_machine` Auto-Detection Mapping

In `ghidra-report.sh`, ELF headers are inspected at offset `18-19` (`0x12`) to automatically configure the Ghidra processor language without requiring manual command-line flags:

```bash
case "$machine_id" in
    0x0003) processor="x86:LE:32:default" ;;       # EM_386 (Intel 80386+)
    0x003E) processor="x86:LE:64:default" ;;       # EM_X86_64 (AMD64 / x86-64)
    0x0028) processor="ARM:LE:32:v8T" ;;           # EM_ARM (ARM Thumb / Thumb-2)
    0x00B7) processor="AARCH64:LE:64:v8A" ;;       # EM_AARCH64 (64-bit ARM)
    0x0008) processor="MIPS:BE:32:default" ;;      # EM_MIPS (MIPS 32-bit Big Endian)
    0x00F3) processor="RISCV:LE:32:RV32GC" ;;      # EM_RISCV (RISC-V 32-bit compressed)
    0x0014) processor="PowerPC:BE:32:default" ;;   # EM_PPC (PowerPC 32-bit Big Endian)
esac
```

---

## 3. Fast Format & Architecture Inspection (`--detect-type`)

To verify how `ghidra-report` will classify a binary before triggering a headless build:

```bash
# Check single binary format
./ghidra-report.sh --detect-type ingress/mario.z64
# Output: n64

./ghidra-report.sh --detect-type ingress/game.gba
# Output: gba

./ghidra-report.sh --detect-type ingress/dsetup.dll
# Output: pe
```

---

## 4. Cryptographic Algorithm Tagging (`--findcrypt`)

To scan binary code and data segments for known cryptographic constant signatures during import:

```bash
./ghidra-report.sh ingress/suspicious.dll --findcrypt
```

- **Signature Database:** 124+ pre-compiled signatures located in `~/findcrypt_ghidra/database.d3v` and `scripts/lib/database.d3v`.
- **Supported Algorithms:** AES S-boxes, ChaCha20/Salsa20 sigma, MD5, SHA-1, SHA-256, SHA-512, RC4, CRC32, TEA/XTEA delta (`0x9e3779b9`), DES, and Blowfish.
- **Bookmarks:** Discovered constants are labeled in Ghidra bookmarks and comments, pinpointing cryptographic routines directly in decompiler and disassembly listings.

---

## 5. Adding a New Custom Architecture

1. **Verify Ghidra SLA Specification:**
   Ensure the processor definition exists in Ghidra:
   ```bash
   find /var/lib/flatpak/app/org.ghidra_sre.Ghidra/.../Processors -name "*.sla"
   ```

2. **Add Header Magic / Extension Detection:**
   In `ghidra-report.sh` under `detect_file_type()`:
   Add file extension checks and header magic byte matches.

3. **Configure Loader Dispatch:**
   In `import_and_analyze()`:
   Add your target case to dispatch `-loader <LoaderClassName>` or `-processor <LanguageID>`.

4. **Verify Headless Execution:**
   Test import and report generation:
   ```bash
   ./ghidra-report.sh ingress/sample.bin --format txt
   ```
