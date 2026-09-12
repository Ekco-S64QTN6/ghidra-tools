# Project Plan — ghidra-report

## Vision

A dead-simple CLI toolkit that wraps Ghidra's headless analyzer to produce human-readable binary analysis reports. Designed for blue team analysts, security researchers, and anyone who wants actionable intelligence out of a binary without becoming a Ghidra power user.

---

## Phase 1: Foundation ✅ (Complete)

Core pipeline: import → analyze → report.

### Completed
- [x] Ghidra headless wrapper (`run-headless.sh`) — works outside Flatpak sandbox
- [x] `ExportFullReport.java` — structured text report with:
  - Program info, MD5/SHA256 hashes
  - Memory map with block permissions (RWX)
  - SNES interrupt vectors (native + emulation mode)
  - Function listing with sizes and calling conventions
  - Symbol/label dump grouped by type
  - String extraction (defined data only)
  - Cross-reference hotspot analysis (top 50 most-referenced functions)
  - Disassembly excerpts (first 15 functions, up to 30 instructions each)
  - Analysis quality indicators and warnings
- [x] Main CLI (`ghidra-report.sh`) with single-file, batch, reimport, and list-projects modes
- [x] File type auto-detection (SNES, PE, ELF, raw)
- [x] SNES ROM Loader fallback to raw 65816 import on loader rejection
- [x] Project management (create/reuse Ghidra projects)
- [x] README with full usage documentation

### Bug Fixes (Merged)
- [x] Banner hardcoded "SNES ROM" regardless of input — replaced with `detectFormatLabel()` that reads `getExecutableFormat()` and language ID
- [x] `printSNESVectors()` called unconditionally — now guarded by `isSNES()` so PE/ELF reports don't emit garbage vector data
- [x] `@category SNES` script annotation — changed to `@category Analysis` so the script appears correctly in Ghidra's script manager for all formats
- [x] `batch_process()` counter uses a subshell via `while` pipe, so `$count` is always 0 at end — fixed with process substitution `< <(find ...)`

---

## Phase 2: Report Intelligence & Smart Analysis ✅ (Complete)

Stop dumping raw data. Start surfacing what matters.

### Priority-Based Disassembly Selection
The current approach dumps the first 15 functions sequentially regardless of importance. Replace with a scored selection:
- [x] Score each function on: call density to interesting addresses, cyclomatic complexity, cross-reference in-count, presence of indirect jumps
- [x] Disassemble the top N highest-scoring functions, not the first N by address
- [x] Add a `--full-disasm` flag to `ghidra-report.sh` that disassembles all functions (useful for small ROMs, risky for large PE/ELF)

### Decompiler Integration
- [x] Use Ghidra's `DecompInterface` to extract C-like pseudocode for selected functions
- [x] Include decompiler output alongside disassembly for the top 5 highest-complexity functions
- [x] Fall back gracefully if the decompiler times out or fails on a function

### Output Format Expansion
- [x] **JSON output** — machine-readable `.json` alongside every `.txt` report; enables SIEM/SOAR ingestion, grep pipelines, and report diffing
- [x] **Markdown output** — `.md` version for pasting into GitHub issues, wikis, and incident reports
- [x] **HTML output** — self-contained styled HTML with syntax-highlighted disassembly; no external dependencies
- [x] Add `--format txt|json|md|html|all` flag to `ghidra-report.sh`

### String Context Enrichment
- [x] For each found string, include the 3 nearest preceding instructions (call context)
- [x] Group strings by likely purpose: UI text, file paths, format strings, encoded blobs

### Report Diffing
- [x] `ghidra-report.sh --diff <report-a> <report-b>` — compare two reports from different binary versions
- [x] Highlight: threat score change, hash comparison, function counts, section size & entropy diffs, newly introduced & removed suspicious APIs

---

## Phase 3: Threat Intelligence & Security Focus ✅ (Complete)

Shift from generic RE output to security-focused triage intelligence and automated capability detection.

### Triage Header & Threat Scoring Engine
- [x] **Executive summary block** at the very top of every report — the analyst's first read:
  ```
  ┌─ THREAT SUMMARY ──────────────────────────────────────────────┐
  │  Risk Score:  72 / 100  [HIGH RISK]                           │
  │  ● High-entropy section detected (.text: 7.6 — likely packed) │
  │  ● 4 process injection APIs found                             │
  │  ● RWX memory segment present                                 │
  │  ● 2 network IOCs extracted from strings                      │
  └────────────────────────────────────────────────────────────────┘
  ```
- [x] Weighted scoring: entropy hits, dangerous API count, RWX presence, shellcode patterns, IOC count (`lib/HeuristicScorer.java`)
- [x] Risk categorization: CRITICAL (80-100), HIGH (60-79), MEDIUM (30-59), LOW (0-29), INFORMATIONAL
- [x] Configurable thresholds via a `~/.config/ghidra-report/config.json` file

### PE & ELF Import/Export Analysis
- [x] **Import table analysis** — enumerate DLLs and imported functions for PE; shared libraries and `plt` entries for ELF
- [x] **Export table inspection** — enumerate exported entry points and labels
- [x] **Rich header / imphash** — extract PE metadata (imphash) for pivot hunting in SIEM (`lib/ImphashCalculator.java`)
- [x] **Suspicious API tagging** with MITRE ATT&CK technique annotations (`lib/ApiTagger.java`):

  | API / Pattern | ATT&CK Technique |
  |---|---|
  | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | T1055 – Process Injection |
  | `NtMapViewOfSection`, `ptrace` | T1055.009 – Proc Hollowing |
  | `RegSetValueEx`, `CreateService` | T1547 – Boot/Logon Autostart |
  | `IsDebuggerPresent`, `NtQueryInformationProcess`, `RDTSC` loops | T1622 – Debugger Evasion |
  | `MiniDumpWriteDump`, `SamIConnect` | T1003 – Credential Dumping |
  | `LoadLibrary`+`GetProcAddress`, `dlsym`+`dlopen` | T1027 – Dynamic API Resolution |
  | Raw `syscall`/`sysenter`/`int 0x80` instructions | T1106 – Native API |

### Entropy Analysis & Packer Detection
- [x] Calculate Shannon entropy per memory block/section ($0.00 - 8.00$) (`lib/EntropyAnalyzer.java`)
- [x] Flag sections with entropy > 7.2 as `PACKED/CRYPT`
- [x] **Auto-detect known packers**: UPX (`UPX0`/`UPX1`), ASPack, Themida/WinLicense signatures
- [x] Emit entropy values and status flags as a column in the memory map table

### IOC & String Intelligence
Pattern-match strings across the binary rather than relying on Ghidra's defined-data-only string scan (`lib/IocExtractor.java`):
- [x] IPv4 address patterns
- [x] HTTP/HTTPS URLs and domain patterns
- [x] Windows registry key paths (`HKLM\...`, `HKCU\...`)
- [x] Filesystem paths (`%APPDATA%`, `/etc/`, `/tmp/`, `C:\Windows\System32\`)
- [x] Base64 blob detection + automatic ASCII decode attempt
- [x] Hex-encoded string detection
- [x] **Stack string reconstruction** — detect strings assembled char-by-char via sequential `MOV` instructions and reconstruct them (`lib/StackStringDetector.java`)

### RWX & Shellcode Heuristics
- [x] Flag any memory block that is simultaneously Read + Write + Execute
- [x] Scan code regions for NOP sled signatures (`0x90` runs), x86 GetPC call/pop sequences, FPU `fnstenv` stubs, and egg-hunter patterns (`lib/ShellcodeDetector.java`)

### Auto-Generated YARA Rules
- [x] Produce a `.yar` file alongside the text report containing (`lib/YaraGenerator.java`):
  - Hex byte sequences from the highest-scoring functions
  - High-signal strings extracted by the IOC engine
  - PE metadata conditions (imphash) and file size bounds
- [x] Rules are immediately usable with `yara rule.yar sample.exe`

### Advanced Deobfuscation & Capability Detection (Phase 3A Expansion)
- [x] **P-Code Emulation Engine (`EmulatorHelper`)** (`lib/EmulatorDeobfuscator.java`) — lightweight P-code emulation over loop-dense and bitwise functions to extract runtime-constructed strings and defeat XOR loops
- [x] **Rule-Driven Capability Engine** (`scripts/capability_engine.py`, `rules/*.yaml`, `--rules`) — YAML-based capability matching rules across instruction, basic block, and function scopes (inspired by Mandiant capa)
- [x] **Dynamic Sandbox Trace Ingestion** (`scripts/trace_correlator.py`, `--trace`) — sliding call window correlation matching runtime API traces (CAPE/DRAKVUF) with static Ghidra imports

---

## Phase 4: Modular Architecture Refactor ✅ (Complete)

`ExportFullReport.java` had grown to ~1,320 lines mixing orchestration, analysis, and four renderers.
It is now an orchestrator only (~410 lines): it drives the analysis passes, populates a single
`ReportModel.ReportData`, and hands it to `MultiFormatWriter`. Every renderer lives in its own
compilation unit under `scripts/lib/` and reads only from that container.

### Module Split
```
scripts/
├── ExportFullReport.java          # [x] Orchestrator — analysis passes + dispatch, no rendering
├── index_report.py                # [x] SQLite3 database indexing & search engine
├── capability_engine.py           # [x] YAML capability rule evaluator (capa-style)
├── trace_correlator.py            # [x] Dynamic sandbox trace correlation
├── firmware_carver.py             # [x] Recursive firmware container carver
├── svd_injector.py                # [x] CMSIS-SVD peripheral parser
├── dashboard.py                   # [x] Standalone web dashboard + REST API
└── lib/
    ├── ReportModel.java           # [x] Shared data model + ReportData container
    ├── ReportFormat.java          # [x] JSON/HTML escaping helpers
    ├── MultiFormatWriter.java     # [x] Format dispatcher (+ YARA/SARIF/MISP adapters)
    ├── TextReportWriter.java      # [x] ASCII terminal renderer
    ├── JsonReportWriter.java      # [x] Machine-readable renderer
    ├── MarkdownReportWriter.java  # [x] GitHub-flavored Markdown renderer
    ├── HtmlReportWriter.java      # [x] Self-contained dark-mode HTML renderer
    ├── DisassemblyPrinter.java    # [x] Priority disassembly + pseudocode sections
    ├── DecompilerExporter.java    # [x] DecompInterface wrapper with count/timeout bounds
    ├── HeuristicScorer.java       # [x] Aggregates indicators → threat score + summary box
    ├── EntropyAnalyzer.java       # [x] Shannon entropy per block & packer detection
    ├── ApiTagger.java             # [x] Import analysis + ATT&CK mapping
    ├── ImphashCalculator.java     # [x] PE import hash computation (MD5)
    ├── ShellcodeDetector.java     # [x] NOP sled & GetPC/egg-hunter scanner
    ├── StackStringDetector.java   # [x] Stack string reconstruction from immediate MOVs
    ├── EmulatorDeobfuscator.java  # [x] P-code emulation string recovery
    ├── IocExtractor.java          # [x] Regex IOC & Base64/Hex decoder engine
    ├── SnesAnalyzer.java          # [x] Cartridge header & MMIO hardware register map
    ├── FindCrypt.java             # [x] Cryptographic constant scanner
    ├── YaraGenerator.java         # [x] Produces .yar detection rules
    ├── SarifExporter.java         # [x] OASIS SARIF v2.1.0 JSON generator
    └── MispExporter.java          # [x] MISP standard threat event JSON generator
```

Refactor invariant: all seven report artifacts are byte-identical before and after the split,
verified against the `dsetup.dll` (PE/Themida) and `DREAM.sfc` (SNES) fixtures. The only
intentional change is correct `&amp;` escaping in HTML headings that previously emitted a bare `&`.

### Configuration File Support
- [x] `~/.config/ghidra-report/config.json` user configuration for:
  - Entropy threshold for flagging (default 7.2)
  - Max functions in disassembly excerpt
  - Custom suspicious API lists
  - Default output formats, webhook URL, and parallel worker count
  - Custom regex IOC patterns

---

## Phase 5: Firmware & Embedded Analysis

Extend to firmware and embedded systems common in IoT and hardware security assessments.

### Deep Boundary Detection & Firmware Extraction (Unblob Integration)
- [x] **Format Carving Pipeline** (`scripts/firmware_carver.py`, `--carve`) — pre-Ghidra extraction pass using format-compliant end-offset calculations to recursively carve SquashFS, CRAMFS, U-Boot uImage, JFFS2, and GZIP streams
- [x] **Kernel & Bootloader Separation** — identify and extract compressed kernels (GZIP, zlib) and U-Boot stages with metadata decoding (OS, Arch, Type, Entry Point)

### Hardware Memory Mapping & SVD Injection
- [x] **CMSIS-SVD Peripheral Injection** (`scripts/svd_injector.py`, `--svd`) — ingest vendor XML SVD files to map hardware peripherals, base addresses, register bitfields, and interrupt vectors for bare-metal ARM Cortex-M and MIPS targets
- [x] **Architecture Auto-Detection** — read ELF `e_machine` to automatically select processor specs without manual flags

### Multi-Architecture & Console Loader Suite
- [x] **Super Nintendo (SNES):** LoROM / HiROM / ExHiROM auto-mapping, DMA channel table detection, MMIO hardware registers ($2100-$213F, $4200-$421F), and SPC700 audio protocol identification
- [x] **Game Boy Advance (GBA):** `gba-ghidra-loader` integration for ARM7TDMI ROMs, GBATEK MMIO register mapping, and BIOS SWI vector resolution
- [x] **Nintendo 64 (N64):** `N64LoaderWV` integration for `.z64`/`.n64`/`.v64` ROMs, endian swapping, MIPS VR4300 CPU, RSP coprocessor, and hardware register blocks
- [x] **Sony PlayStation 1 (PS1):** `ghidra_psx_ldr` integration for MIPS R3000A PSX executables, GTE coprocessor instructions, scratchpad, and BIOS jump table
- [x] **Stripped Go Binaries:** `GolangAnalyzerExtension` integration for `pclntab` parsing, function name recovery, source path reconstruction, and Go type decoding
- [x] **UEFI / BIOS Firmware:** `ghidra-firmware-utils` integration for Firmware Volumes (FV), Firmware File System (FFS), and Intel Flash Descriptor (IFD) parsing
- [x] **Cryptographic Constant Scanner:** `FindCrypt-Ghidra` integration (`--findcrypt`) with 124+ signatures for AES, ChaCha, MD5, SHA, CRC32, RC4, and TEA/XTEA
- [x] **Bundled Flatpak Extensions:** Activated `Jython` (Python 2 GhidraScript engine) and `BSimElasticPlugin` (binary similarity matching)

### SNES-Specific Enhancements
- [x] Auto-detect and report LoROM vs HiROM vs ExHiROM mapping mode
- [x] DMA channel usage summary & HDMA table detection (`SnesAnalyzer.java` & `ExportFullReport.java`)
- [x] MMIO hardware register access map ($2100-$213F video/PPU registers, $4200-$421F CPU/DMA registers)
- [x] SPC700 audio CPU code separation and reporting (`SnesAnalyzer.java` APUIO0-APUIO3 $2140-$2143 ports & protocol detection)

### Custom Architecture Support
- [x] **Architecture auto-detection** — read the ELF `e_machine` field to set the processor (ARM Thumb, MIPS, RISC-V, PowerPC) without manual `-processor` flags
- [x] **Custom processor profile template** (`docs/PROCESSOR_PROFILES.md`) — guide for adding architectures and ELF `e_machine` auto-detection

---

## Phase 6: Automation & Enterprise Integration

Make it production-ready for security workflows, CI/CD, and threat intelligence platforms.

### Enterprise Interoperability & Standardized Formats
- [x] **OASIS SARIF v2.1.0 Export (`.sarif`)** — standard static analysis output for GitHub Code Scanning, Azure DevOps, and AST platforms
- [x] **Semantic Findings Lifecycle** — standardized baseline tracking (`[NEW]`, `[UNCHANGED]`, `[ABSENT]`, `[UPDATED]`) in differential analysis (`--diff`)
- [x] **MISP Event Export** — MISP-compatible JSON format (`.misp.json`) for threat intelligence ingestion

### Execution Engine & Storage Hygiene
- [x] **Per-Binary Output Partitioning** — outputs neatly categorized into `output/<binary_name>/` with `report_latest.*` symlinks
- [x] **Temporary Project Purging (`--purge-projects`)** — automated cleanup routine to purge transient `.rep` and `.gpr` databases
- [x] **Parallel Worker Pool Dispatcher** — multi-process job queue (`--parallel` / `-j`) to analyze ingress files concurrently across multi-core systems
- [x] **Watch Mode Daemon** — inotify/polling ingress watcher (`--watch`) for zero-touch drop analysis

### Deployment & Integrations
- [x] **Dockerized deployment** (`Dockerfile`, `docker-compose.yml`) — container with Eclipse Temurin JDK 21 and Ghidra headless pre-configured
- [x] **GitHub Actions workflow** (`.github/workflows/binary-analysis.yml`) — regression testing and SARIF upload to GitHub Code Scanning
- [x] **Slack/Discord/webhook notifications** — configurable alerts (`--webhook <url>`) on completion or when threat score exceeds threshold
- [x] **SQLite report database** — index all generated reports; enables `ghidra-report --search "CreateRemoteThread"` across historical analyses
- [x] **Web dashboard** (`scripts/dashboard.py`) — standalone Python HTTP server; browse reports, live FTS search, inspect artifacts (`--dashboard [port]`, `--serve`)
- [x] **OpenCTI / Shuffle SOAR integration** (`docs/SOAR_INTEGRATION.md`) — automated webhook playbooks and MISP/SARIF ingestion guides

---

## Phase 7: Polish & Release ✅ (Complete)

### Completed
- [x] Integration test suite (`tests/run_tests.sh`) — automated regression suite testing CLI flags, all 7 formats, threat scores, MISP/SARIF schema, SNES header/MMIO/DMA, semantic diff, firmware carving, SQLite search, dashboard REST APIs, and a clean compile of the Java pipeline
- [x] Self-contained fixtures (`tests/make_fixtures.py`) — synthesizes a packed PE32 and a LoROM SNES cartridge from code, so the suite never reads from `ingress/` and runs on a fresh clone
- [x] Man page (`ghidra-report.1`) — Unix manual page documenting usage, flags, output formats, and architecture
- [x] Homebrew formula and AUR PKGBUILD (`packaging/ghidra-report.rb`, `packaging/PKGBUILD`)
- [x] Pre-built release tarballs (`scripts/package_release.sh` producing standalone `.tar.gz` and sha256 checksums)
- [x] Project logo and README header banner

---

## Architecture

```
  ingress/<binary>
        │
        ▼
┌────────────────────┐     ┌──────────────────────────────┐     ┌──────────────────────┐
│  ghidra-report.sh  │ ──► │  Ghidra Headless Analyzer    │ ──► │  output/<binary>/    │
│  - detect type     │     │                              │     │   report_latest.txt  │
│  - pick loader     │     │  ExportFullReport.java       │     │                .json │
│  - manage project  │     │   (orchestrator only)        │     │                .md   │
│  - dispatch flags  │     │      │                       │     │                .html │
└────────────────────┘     │      ├─ analysis passes ─────┼──┐  │                .yar  │
        │                  │      │   EntropyAnalyzer     │  │  │                .sarif│
        │                  │      │   ApiTagger           │  │  │           .misp.json │
        │                  │      │   IocExtractor        │  │  └──────────────────────┘
        │                  │      │   ShellcodeDetector   │  │            │
        │                  │      │   StackStringDetector │  │            ▼
        │                  │      │   EmulatorDeobfuscator│  │  ┌──────────────────────┐
        │                  │      │   SnesAnalyzer        │  │  │  output/reports.db   │
        │                  │      │   DecompilerExporter  │  │  │  (SQLite FTS index)  │
        │                  │      │   HeuristicScorer     │  │  └──────────────────────┘
        │                  │      ▼                       │  │            │
        │                  │   ReportModel.ReportData ────┘  │            ▼
        │                  │      │                          │  ┌──────────────────────┐
        │                  │      ▼                          │  │  --search            │
        │                  │   MultiFormatWriter             │  │  --dashboard         │
        │                  │    ├─ TextReportWriter          │  │  --diff              │
        │                  │    ├─ JsonReportWriter          │  └──────────────────────┘
        │                  │    ├─ MarkdownReportWriter      │
        │                  │    ├─ HtmlReportWriter          │
        │                  │    └─ Yara/Sarif/Misp adapters  │
        │                  └──────────────────────────────────┘
        ▼
┌────────────────────┐   Python side-pipelines (pre/post Ghidra)
│  projects/         │    firmware_carver.py  --carve
│  (Ghidra DB cache) │    svd_injector.py     --svd
│  --purge-projects  │    capability_engine.py --rules   (rules/*.yaml)
└────────────────────┘    trace_correlator.py --trace
```

## Tech Stack

| Component | Technology |
|---|---|
| CLI | Bash 4+ |
| Ghidra scripts | Java 21 (GhidraScript API) |
| Decompiler integration | `ghidra.app.decompiler.DecompInterface` |
| Report formats | Plain text, JSON, Markdown, HTML, SARIF v2.1.0, YARA, MISP JSON |
| Binary analysis engine | Ghidra 12.x Headless Analyzer |
| Console/firmware loaders | ghidra-snes, gba-ghidra-loader, N64LoaderWV, ghidra_psx_ldr, ghidra-firmware-utils |
| Threat intel output | MISP event JSON, YARA rules, SARIF findings |
| Dashboard | Python stdlib `http.server` (`scripts/dashboard.py`, no dependencies) |
| Report storage | SQLite + FTS5 (`output/reports.db`, `scripts/index_report.py`) |
