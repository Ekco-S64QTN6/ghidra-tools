<div align="center">

# GHIDRA TOOLS

**Drop a binary in a folder. Get the whole story back.**
A headless Ghidra pipeline that turns an unknown executable, ROM or firmware image
into a scored triage report — in seven formats, with no GUI and no reverse-engineering
experience required.

[![Ghidra](https://img.shields.io/badge/Ghidra-12.x_headless-e74c3c?style=flat-square)](https://ghidra-sre.org/)
[![Java](https://img.shields.io/badge/scripts-Java_21-f89820?style=flat-square&logo=openjdk&logoColor=white)](#architecture)
[![Bash](https://img.shields.io/badge/CLI-bash_4%2B-4eaa25?style=flat-square&logo=gnubash&logoColor=white)](#cli-reference)
[![Python](https://img.shields.io/badge/pipelines-python_3_stdlib-3776ab?style=flat-square&logo=python&logoColor=white)](#side-pipelines)
[![Formats](https://img.shields.io/badge/output-7_formats-6fc3df?style=flat-square)](#what-a-report-contains)
[![ATT&CK](https://img.shields.io/badge/tagging-MITRE_ATT%26CK-9c6bff?style=flat-square)](#threat-triage)
[![Tests](https://img.shields.io/badge/tests-self--contained-54e08a?style=flat-square)](#testing)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

[Overview](#overview) · [Quickstart](#quickstart) · [Reports](#what-a-report-contains) · [Triage](#threat-triage) · [CLI](#cli-reference) · [Architecture](#architecture) · [Install](#installation) · [Testing](#testing)

</div>

---

## Overview

Ghidra is the best open-source reverse engineering platform there is, and getting a
single useful sentence out of it takes a GUI, a project, a loader choice, an analysis
pass and a lot of clicking. This wraps the headless analyzer so that the loop is:

```bash
cp suspicious.dll ingress/
./ghidra-report.sh --batch
```

and what comes back is not a data dump. It is a **risk score, the reasons for it, and
the evidence** — high-entropy sections, ATT&CK-tagged imports, RWX segments, shellcode
stubs, decoded stack strings, extracted IOCs, and decompiled C for the functions that
actually matter — rendered simultaneously as a terminal report, a JSON document, a
Markdown file, a standalone HTML page, a SARIF run, a YARA rule and a MISP event.

**What makes it different from a `analyzeHeadless` wrapper**

| | |
|:--|:--|
| **Triage first, data second** | Every report opens with a 0–100 score and the specific indicators that produced it. The 3,000-line dump is below the fold, not above it. |
| **Priority, not address order** | Functions are scored on inbound xrefs, call density, suspicious-API reachability and size. The disassembly and decompiler excerpts follow that ranking, not the memory map. |
| **Sees through obfuscation** | Stack strings are reconstructed from immediate `MOV` sequences, and a P-code emulator runs loop-dense functions to recover runtime-built and XOR-decoded strings. |
| **Rules live outside the code** | Capability detection is YAML (`rules/*.yaml`), evaluated at instruction, block and function scope — capa-style — so detections can be added without touching Java. |
| **Not just PE/ELF** | SNES, GBA, N64, PS1, stripped Go, UEFI volumes and bare-metal ARM via CMSIS-SVD all have first-class loader paths. |
| **Ends in a pipeline, not a file** | SARIF for code scanning, MISP for threat intel, YARA for hunting, SQLite FTS for history, webhooks for alerting. |

---

## Quickstart

```bash
git clone https://github.com/Ekco-S64QTN6/ghidra-tools.git
cd ghidra-tools

cp /path/to/suspicious.dll ingress/     # drop anything in here
./ghidra-report.sh --batch              # analyze everything in ingress/

cat    output/suspicious.dll/report_latest.txt
xdg-open output/suspicious.dll/report_latest.html
```

Or point it straight at one file:

```bash
./ghidra-report.sh /path/to/firmware.bin --format all
```

The only hard requirement is a Ghidra 12.x install. The Flatpak
(`org.ghidra_sre.Ghidra`), `/opt/ghidra` and `/usr/share/ghidra` are all found
automatically; anything else, set `GHIDRA_ROOT`.

---

## What a report contains

One run writes every artifact into `output/<binary>/`, plus `report_latest.*`
symlinks that always point at the newest run.

| Artifact | What it is for |
|:--|:--|
| **`.txt`** | The analyst's read. Triage box, memory map with entropy, ATT&CK table, IOCs, ranked disassembly, decompiled C. |
| **`.json`** | The machine's read. Full structured model — feeds `--diff`, `--search`, the dashboard, and any SIEM/SOAR you point at it. |
| **`.md`** | Paste into a PR, an issue or an incident ticket. |
| **`.html`** | Self-contained dark-mode page. No CDN, no assets, no network. Mail it. |
| **`.sarif`** | OASIS SARIF v2.1.0 — uploads straight to GitHub Code Scanning. |
| **`.yar`** | A usable YARA rule built from the imphash, IOC strings and byte sequences from the top-scoring functions. |
| **`.misp.json`** | A MISP event ready for import into a threat intel platform. |

A real triage header, from the packed sample in `ingress/`:

```
┌─ THREAT TRIAGE SUMMARY ────────────────────────────────────────────────────────┐
│  Risk Score:  100 / 100  [CRITICAL]                                            │
├────────────────────────────────────────────────────────────────────────────────┤
│  ● [T1055] RWX memory block detected: .themida (100b7000 - 10854fff) — possi...│
│  ● [T1027.002] High-entropy section (.boot: 7.95 / 8.00) — likely packed or ...│
│  ● [T1055] FPU fnstenv GetPC shellcode stub detected at 10bce0b1 (+25)         │
│  ● [T1027] Imported KERNEL32.DLL!GetModuleHandleA (Dynamic API Resolution) (+5)│
│  ● [T1059] Imported SHELL32.DLL!ShellExecuteA (Command / Process Execution) ...│
│  ● [T1016] Imported IPHLPAPI.DLL!GetIpAddrTable (Network Config Discovery) (...│
│  ● [T1057] Imported PSAPI.DLL!GetModuleInformation (Process Discovery) (+10)   │
└────────────────────────────────────────────────────────────────────────────────┘

```

...and the memory map that produced two of those lines:

```
  Block Name       Start        End               Size  Perms  Entropy  Status        Notes
  -----------------------------------------------------------------------------------------
  .idata           100b4000     100b4fff          4096  RW--   0.64    NORMAL
  .rsrc            100b6000     100b6fff          4096  R---   2.65    NORMAL
  .themida         100b7000     10854fff       7987200  RWX-   0.00    NORMAL        RWX ALERT
  .boot            10855000     10ce9bff       4803584  R-X-   7.95    PACKED/CRYPT  Themida/WinLicense
```

---

## Threat triage

### Scoring

Indicators are weighted, de-duplicated and clamped to 100. Anything non-hostile by
construction (a SNES cartridge, say) is forced to `INFORMATIONAL` rather than scored
against a malware rubric.

| Band | Score |
|:--|:--|
| `CRITICAL` | 80–100 |
| `HIGH` | 60–79 |
| `MEDIUM` | 30–59 |
| `LOW` | 0–29 |
| `INFORMATIONAL` | non-executable / console targets |

### What raises the score

- **Entropy** — Shannon entropy per section; `> 7.2` is flagged `PACKED/CRYPT`, with
  name-signature detection for UPX, ASPack and Themida/WinLicense.
- **Imports** — every import is matched against the ATT&CK tag table, including
  `A`/`W`/`Ex` suffix normalization.
- **Permissions** — any block that is simultaneously R+W+X.
- **Shellcode** — NOP sleds (≥16 × `0x90`), x86 GetPC call/pop pairs, FPU `fnstenv` stubs.
- **Obfuscation** — reconstructed stack strings, and strings recovered by P-code emulation.
- **IOCs** — IPv4, URLs, registry keys, filesystem paths, and Base64/hex blobs that
  decode to printable ASCII.

### ATT&CK coverage

| API / pattern | Technique |
|:--|:--|
| `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | T1055 — Process Injection |
| `NtMapViewOfSection`, `ptrace` | T1055.009 — Process Hollowing |
| `RegSetValueEx`, `CreateService` | T1547 — Boot/Logon Autostart |
| `IsDebuggerPresent`, `NtQueryInformationProcess` | T1622 — Debugger Evasion |
| `MiniDumpWriteDump`, `SamIConnect` | T1003 — Credential Dumping |
| `LoadLibrary` + `GetProcAddress`, `dlopen` + `dlsym` | T1027 — Dynamic API Resolution |
| `ShellExecute`, `WinExec`, `CreateProcess` | T1059 — Command & Scripting |
| Raw `syscall` / `sysenter` / `int 0x80` | T1106 — Native API |

---

## CLI reference

### Modes

```
./ghidra-report.sh <binary> [options]        Analyze one file
./ghidra-report.sh --batch                   Analyze everything in ingress/
./ghidra-report.sh --watch                   Daemon: analyze new drops as they land
./ghidra-report.sh --reimport <binary>       Discard the cached project, re-analyze
./ghidra-report.sh --diff <a> <b>            Semantic diff of two reports
./ghidra-report.sh --search <term>           Full-text search every past run
./ghidra-report.sh --dashboard [port]        Web UI over the report history
./ghidra-report.sh --rules [report|binary]   Evaluate the YAML capability rules
./ghidra-report.sh --trace <trace.json>      Correlate a sandbox trace with static imports
./ghidra-report.sh --carve <binary> [dir]    Carve embedded firmware containers
./ghidra-report.sh --svd <file.svd>          Inspect / inject CMSIS-SVD peripherals
./ghidra-report.sh --detect-type <file>      Print the detected format and exit
./ghidra-report.sh --list-projects           Show cached Ghidra projects
./ghidra-report.sh --purge-projects          Delete cached .gpr / .rep databases
```

### Options

| Flag | Effect |
|:--|:--|
| `--format <txt\|json\|md\|html\|sarif\|yar\|misp\|all>` | Which artifacts to write (default `all`) |
| `--parallel`, `-j [N]` | Analyze ingress files across N worker processes |
| `--full-disasm` | Disassemble every function, not the top 15 |
| `--findcrypt` | Scan for 124+ cryptographic constants (AES, ChaCha, MD5, SHA, CRC32, RC4, TEA/XTEA) |
| `--webhook <url>` | POST a triage alert to Slack / Discord / any webhook |

Short forms exist for most modes: `-b` batch, `-w` watch, `-s` serve, `-q` query,
`-l` list, `-c` carve, `-r` reimport, `-d` diff, `-h` help.

### Diffing two builds

```bash
./ghidra-report.sh --diff sample_v1.exe sample_v2.exe
```

Reports the threat-score delta, hash and section changes, entropy drift, and a
findings lifecycle — every suspicious API tagged `[NEW]`, `[UNCHANGED]`, `[ABSENT]`
or `[UPDATED]` against the baseline.

### Searching history

Every run is indexed into `output/reports.db` (SQLite + FTS5):

```bash
./ghidra-report.sh --search "CreateRemoteThread"
./ghidra-report.sh --search "Themida"
./ghidra-report.sh --search 10bce0b1
./ghidra-report.sh --dashboard 8080        # or browse it
```

---

## Architecture

`ExportFullReport.java` is an orchestrator and nothing else: it runs the analysis
passes, fills one `ReportModel.ReportData`, and hands it to `MultiFormatWriter`.
Every analyzer and every renderer is a separate compilation unit under `scripts/lib/`
that reads only from that container.

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
└────────────────────┘     │      ├─ analysis passes      │     │                .yar  │
        │                  │      │   EntropyAnalyzer     │     │                .sarif│
        │                  │      │   ApiTagger           │     │           .misp.json │
        │                  │      │   IocExtractor        │     └──────────────────────┘
        │                  │      │   ShellcodeDetector   │                │
        │                  │      │   StackStringDetector │                ▼
        │                  │      │   EmulatorDeobfuscator│     ┌──────────────────────┐
        │                  │      │   SnesAnalyzer        │     │  output/reports.db   │
        │                  │      │   DecompilerExporter  │     │  (SQLite + FTS5)     │
        │                  │      │   HeuristicScorer     │     └──────────────────────┘
        │                  │      ▼                       │                │
        │                  │   ReportModel.ReportData     │                ▼
        │                  │      │                       │     ┌──────────────────────┐
        │                  │      ▼                       │     │  --search            │
        │                  │   MultiFormatWriter          │     │  --dashboard         │
        │                  │    ├─ TextReportWriter       │     │  --diff              │
        │                  │    ├─ JsonReportWriter       │     │  --webhook           │
        │                  │    ├─ MarkdownReportWriter   │     └──────────────────────┘
        │                  │    ├─ HtmlReportWriter       │
        │                  │    └─ Yara/Sarif/Misp        │
        ▼                  └──────────────────────────────┘
┌────────────────────┐
│  projects/         │     Side pipelines (pre/post Ghidra, Python stdlib only)
│  (Ghidra DB cache) │       firmware_carver.py   --carve
│  --purge-projects  │       svd_injector.py      --svd
└────────────────────┘       capability_engine.py --rules   (rules/*.yaml)
                             trace_correlator.py  --trace
```

### Side pipelines

| Script | Flag | What it does |
|:--|:--|:--|
| `firmware_carver.py` | `--carve` | Recursive container carving with format-compliant end-offset math — SquashFS, CRAMFS, JFFS2, U-Boot uImage, gzip/zlib. Runs *before* Ghidra so each sub-image can be analyzed on its own. |
| `svd_injector.py` | `--svd` | Parses vendor CMSIS-SVD XML into peripheral base addresses, register offsets and IRQ vectors for bare-metal ARM Cortex-M / MIPS. |
| `capability_engine.py` | `--rules` | Evaluates `rules/*.yaml` with AND/OR/NOT and N-of-M logic across instruction, block and function scope. |
| `trace_correlator.py` | `--trace` | Correlates a CAPE/DRAKVUF sandbox trace against the static import set using a sliding call window, so multi-step behaviours (alloc → write → create thread) match as one capability. |
| `index_report.py` | *(automatic)* | Indexes every run into `output/reports.db` for `--search` and the dashboard. |
| `dashboard.py` | `--dashboard` | Standalone `http.server` UI + REST API. No Flask, no dependencies. |

### Format support

| Target | Path |
|:--|:--|
| **PE / ELF / Mach-O** | Native Ghidra loaders + imphash, imports/exports, ATT&CK tagging |
| **SNES** | LoROM/HiROM/ExHiROM auto-mapping, interrupt vectors, DMA/HDMA tables, PPU `$2100–$213F` and CPU `$4200–$421F` MMIO maps, SPC700 APUIO protocol detection |
| **GBA / N64 / PS1** | `gba-ghidra-loader`, `N64LoaderWV`, `ghidra_psx_ldr` |
| **Stripped Go** | `GolangAnalyzerExtension` — `pclntab` parsing, function name and source path recovery |
| **UEFI / BIOS** | `ghidra-firmware-utils` — firmware volumes, FFS, Intel flash descriptor |
| **Bare-metal ARM / MIPS** | ELF `e_machine` auto-detection + CMSIS-SVD peripheral injection |
| **Raw / unknown** | Raw import with an explicit processor spec; SNES falls back to raw 65816 if the loader rejects it |

---

## Extending it

### Capability rules

Rules are plain YAML in `rules/`. Eleven ship by default — process injection,
hollowing, credential dumping, anti-debugging, dynamic resolution, persistence,
input capture, network discovery, packer detection, cryptography and process
execution. Add a file, and `--rules` picks it up.

### Configuration

`~/.config/ghidra-report/config.json` overrides the defaults:

```json
{
  "default_format": "all",
  "entropy_threshold": 7.2,
  "max_disasm_functions": 15,
  "webhook_url": "https://hooks.slack.com/services/...",
  "parallel_jobs": 4
}
```

Custom suspicious-API lists and extra IOC regexes go in the same file.

---

## Installation

### From source

```bash
git clone https://github.com/Ekco-S64QTN6/ghidra-tools.git
cd ghidra-tools
./ghidra-report.sh --help
```

Needs Ghidra 12.x and Java 21. `GHIDRA_ROOT` overrides autodetection.

### Docker

```bash
docker compose run --rm ghidra-report --batch
```

The image pins Eclipse Temurin JDK 21 with the headless analyzer preconfigured;
`ingress/` and `output/` are bind-mounted.

### Packages

```bash
./scripts/package_release.sh          # dist/ghidra-report-v0.2.0-linux-x86_64.tar.gz + .sha256
```

Homebrew formula and AUR `PKGBUILD` live in `packaging/`. A man page is at
`ghidra-report.1`.

### CI

`.github/workflows/binary-analysis.yml` runs the regression suite and uploads the
SARIF output to GitHub Code Scanning.

---

## Testing

```bash
./tests/run_tests.sh
```

The suite is self-contained: `tests/make_fixtures.py` synthesizes its own samples,
so a fresh clone runs the whole thing. Nothing is read from `ingress/` — that is a
drop folder for whatever you are actually triaging, its contents are git-ignored,
and a test suite has no business depending on it.

Two fixtures are generated from code:

| Fixture | What it exercises |
|:--|:--|
| `packed_sample.dll` | A structurally valid PE32 carrying every signal the scorer reads — a `.themida` RWX section, a maximum-entropy `.boot` section, both x86 GetPC shellcode idioms, and a real import table of ATT&CK-tagged APIs. Asserts a 100/100 CRITICAL verdict. |
| `console_sample.sfc` | A 64 KB LoROM cartridge with a checksum-valid header and 65816 code driving >10 PPU registers plus DMA and HDMA channel setups. Asserts header parsing, vector seeding, and MMIO/DMA extraction. |

Checks cover all seven output formats, threat scoring, MISP and SARIF schema
validity, SNES header/MMIO/DMA extraction, the semantic diff, firmware carving,
the SQLite search, the dashboard's REST endpoints, the capability and trace
engines, SVD injection, loader auto-detection, the release packager, and a clean
compile of the whole Java pipeline.

---

## Project layout

```
ghidra-report.sh          Main CLI
run-headless.sh           Ghidra headless invocation (works outside the Flatpak sandbox)
scripts/
  ExportFullReport.java   Orchestrator
  lib/*.java              Analyzers and renderers
  *.py                    Side pipelines
rules/*.yaml              Capability detection rules
ingress/                  Drop binaries here
output/<binary>/          Reports, plus reports.db
projects/                 Ghidra project cache (--purge-projects to clear)
docs/                     Processor profiles, SOAR integration
tests/run_tests.sh        Integration suite
tests/make_fixtures.py    Generates the suite's sample binaries
packaging/                Homebrew formula, AUR PKGBUILD
```

---

## License

Released under the [MIT License](LICENSE) — use it, fork it, ship it.

Ghidra itself is Apache-2.0, developed by the NSA's Research Directorate. The
third-party loaders and extensions referenced above ship under their own licenses.
No binary samples are distributed in this repository; `ingress/` is git-ignored.

---

<div align="center">
<sub>

Built by **Ekco** · Reverse engineering without the GUI.

</sub>
</div>
