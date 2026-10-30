# Processor Profiles & Multi-Architecture Extension Guide

`ghidra-report` supports automatic processor and loader detection across desktop executables (PE, ELF, Mach-O), retro console ROMs (SNES, GBA, N64, PS1), firmware containers, and bare-metal microcontroller memory maps.

---

## 1. Supported Architecture & Loader Ecosystem

Community loader extensions are installed separately and are specific to the installed Ghidra release. For Flatpak, a common per-user location is
`~/.config/ghidra/ghidra_<version>_FLATPAK/Extensions/`; replace `<version>` with the directory present on the host. Discover available extension directories with:

```bash
find ~/.config/ghidra -type d -name Extensions -print
```

The base Docker image installs Ghidra itself, not community loaders or the optional 65816 processor language. Extension-backed paths therefore require separately installed versions compatible with the target Ghidra build. Default container CI validates PE analysis and SNES header detection; raw SNES analysis runs only when the 65816 language definition is present.

| Platform / Architecture | Loader Class / Extension | Ghidra Language ID | Detection Signature | Key Capabilities |
|---|---|---|---|---|
| **Super Nintendo (SNES)** | `SnesRomLoader` (`ghidra-snes-master`) or raw 65816 fallback when a compatible processor extension provides the language | `65816:LE:24:snes` (optional extension; not in base Ghidra 12.2) | Plausible header title/mode, checksum complement, and reset vector at known header offsets; suffix is only a hint | LoROM/HiROM mapping, WRAM blocks, MMIO registers ($2100-$2143), SPC700 audio protocol |
| **Game Boy Advance (GBA)** | `GBALoader` (`gba-ghidra-loader`) | `ARM:LE:32:v4t` | `.gba` plus Nintendo logo prefix and header complement checksum | EWRAM, IWRAM, VRAM, ROM mapping, GBATEK hardware MMIO registers, BIOS SWI table |
| **Nintendo 64 (N64)** | `N64LoaderWVLoader` (`N64LoaderWV`) | `MIPS:BE:64:64-32addr` | Byte-order magics for `.z64`/`.v64`/`.n64` layouts; recognized by bytes, not suffix alone | Big-endian/byte-swapped ROMs, RDRAM, MIPS VR4300 + RSP coprocessor, MMIO registers |
| **Sony PlayStation 1 (PS1)** | `PsxLoader` (`ghidra_psx_ldr`) | `MIPS:LE:32:default` | `PS-X EXE` magic plus minimum 0x800-byte header; suffix is only a hint | MIPS R3000A, GTE (Geometry Engine) coprocessor, scratchpad, BIOS jump vectors |
| **Stripped Go Binaries** | `GolangAnalyzerExtension` | x86, x64, ARM, MIPS | `.gopclntab` section / Go build ID | Recovers function symbols, package hierarchies, source paths, and Go type descriptors |
| **UEFI / BIOS Firmware** | `ghidra-firmware-utils` | x86, x64, ARM | Firmware Volume GUID / FMAP | Parses UEFI FV, Firmware File System (FFS), Intel Flash Descriptor (IFD) |
| **Bare-Metal ARM Cortex-M** | `svd_injector.py` / `ghidra-svd` | `ARM:LE:32:Cortex` | `.svd` (CMSIS-SVD XML) | Vendor register bitfields, peripheral base addresses, interrupt vector tables |
| **Windows Executables** | Native PE Loader | `x86:LE:32:default`, `x86:LE:64:default` | Magic `MZ` | PE headers, imports, exports, TLS callbacks, Themida/packer entropy triage |
| **Linux / BSD Binaries** | Native ELF Loader | Auto-detected via `e_machine` | Magic `\x7fELF` | Symbols, dynamic imports, relocations, section entropy |

---

## 2. ELF Architecture Detection and Processor Selection

`scripts/architecture_detector.py` validates the ELF identification header before reading `e_machine`. The language mapping also uses ELF class and `EI_DATA` byte order; unknown or incompatible combinations do not receive a guessed processor. When a known mapping exists, `ghidra-report.sh` passes that language ID using Ghidra's `-processor` import option. The report writer independently records the language ID of the program Ghidra actually opened.

| `e_machine` | ELF class / byte order | Selected Ghidra language |
|---|---|---|
| `EM_386` | ELF32 little-endian | `x86:LE:32:default` |
| `EM_X86_64` | ELF64 little-endian | `x86:LE:64:default` |
| `EM_ARM` | ELF32 little- or big-endian | `ARM:LE:32:v8` / `ARM:BE:32:v8` |
| `EM_AARCH64` | ELF64 little- or big-endian | `AARCH64:LE:64:v8A` / `AARCH64:BE:64:v8A` |
| `EM_MIPS` | ELF32, either byte order | `MIPS:LE:32:default` / `MIPS:BE:32:default`; ELF64 is deliberately deferred until ABI/ISA flags can disambiguate the decoder |
| `EM_RISCV` | ELF32/ELF64 little-endian | `RISCV:LE:32:default` / `RISCV:LE:64:default` |
| `EM_PPC` | ELF32, either byte order | `PowerPC:{LE,BE}:32:default` |
| `EM_PPC64` | ELF64, either byte order | `PowerPC:{LE,BE}:64:default` |

Check a sample before import with `./ghidra-report.sh --detect-type sample.bin`; use `python3 scripts/architecture_detector.py json sample.elf` to inspect the evidence and optional processor selection.
---

## 3. Fast Format & Architecture Inspection (`--detect-type`)

To verify how `ghidra-report` will classify a binary before triggering a headless build. The detector validates structural fields and leaves invalid or truncated headers as `raw` instead of accepting the suffix alone:

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
