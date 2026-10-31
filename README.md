<div align="center">

# GHIDRA TOOLS

**Drop a binary in a folder. Get the whole story back.**
A headless Ghidra pipeline that turns an unknown executable, ROM or firmware image
into a scored triage report — in seven formats, with no GUI and no reverse-engineering
experience required.

[![Ghidra](https://img.shields.io/badge/Ghidra-12.2_headless-e74c3c?style=flat-square)](https://ghidra-sre.org/)
[![Java](https://img.shields.io/badge/scripts-Java_25-f89820?style=flat-square&logo=openjdk&logoColor=white)](#architecture)
[![Bash](https://img.shields.io/badge/CLI-bash_4%2B-4eaa25?style=flat-square&logo=gnubash&logoColor=white)](#cli-reference)
[![Python](https://img.shields.io/badge/pipelines-python_stdlib_%2B_PyYAML_for_rules-3776ab?style=flat-square&logo=python&logoColor=white)](#side-pipelines)
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
| **Sees through obfuscation** | Stack strings require a verified Ghidra stack-frame write, a P-code STORE sourced from a constant (directly or through one COPY), and contiguous offsets; register-only values, register-derived stack stores, non-contiguous stack writes, and multi-step value propagation are excluded. A P-code emulator also runs selected loop/XOR functions to recover candidate runtime strings. |
| **Rules live outside the code** | Capability rules are versioned YAML (`rules/*.yaml`); the evaluator supports file-aggregate matching plus API-only per-function call-site matching, but not arbitrary instruction/block patterns. |
| **Beyond PE/ELF** | The CLI detects SNES, GBA, N64, and PS1 formats and has raw fallbacks; community console/firmware loaders must be installed separately and are not bundled in the base container. |
| **Ends in a pipeline, not a file** | SARIF for code scanning, MISP for threat intel, YARA for hunting, searchable SQLite history, webhooks for alerting. |

---

## Quickstart

```bash
git clone https://github.com/Ekco-S64QTN6/ghidra-tools.git
cd ghidra-tools

cp /path/to/suspicious.dll ingress/     # drop anything in here
./ghidra-report.sh --batch              # analyze everything in ingress/

OUTPUT_KEY="$(python3 scripts/project_identity.py output ingress/suspicious.dll)"
cat    "output/$OUTPUT_KEY/report_latest.txt"
xdg-open "output/$OUTPUT_KEY/report_latest.html"
```

Or point it straight at one file:

```bash
./ghidra-report.sh /path/to/firmware.bin --format all
```

The default container is pinned to Ghidra 12.2 with JDK 25, and verifies the
official release archive against its published SHA-256 before installation.
[Ghidra 12.2 requires at least JDK 25](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build).
For a host or Flatpak install, use the JDK required by that specific Ghidra release.
The launcher prints the detected Ghidra root/version and Java runtime to aid diagnosis.
The Flatpak (`org.ghidra_sre.Ghidra`), `/opt/ghidra` and `/usr/share/ghidra` are
all found automatically; for another location, set `GHIDRA_ROOT`.

---

## What a report contains

One run writes every artifact into `output/<output_key>/`, plus `report_latest.*` symlinks that point at the newest report in that identity. The stable key combines a sanitized filename, canonical source-path hash, and content hash, so files with the same basename (or changed bytes at a reused path) do not share outputs. Get the key with `python3 scripts/project_identity.py output <binary_path>`; for `--diff`, `--rules`, and `--trace`, pass that key to select one exact report. A basename is accepted only when it uniquely identifies an output directory.

Exports are first written to a private staging directory inside the identity output directory. Only after the exporter exits successfully are completed files moved into place and each `report_latest.*` symlink atomically replaced. This prevents readers from seeing a half-written report through an existing latest link. The set of links for multiple formats is not switched as one transaction, so a failure between formats can leave links pointing to different successful runs.

Concurrent invocations for the same output identity are serialized across project import, analysis, report export, and `report_latest.*` updates. This protects the shared Ghidra project and latest-report pointers while allowing different identities to run in parallel. The default lock wait is 900 seconds; set `GHIDRA_OUTPUT_LOCK_TIMEOUT` to an integer from 1 to 86400 to change it. A timeout fails closed instead of allowing competing writers to continue.

| Artifact | What it is for |
|:--|:--|
| **`.txt`** | The analyst's read. Triage box, memory map with entropy, ATT&CK table, IOCs, ranked disassembly, decompiled C. |
| **`.json`** | The machine's read. Versioned structured model (`schema_version: 1.0.0`) — feeds `--diff`, `--search`, the dashboard, and SIEM/SOAR consumers. Contract: [`schemas/report-v1.schema.json`](schemas/report-v1.schema.json). |
| **`.md`** | Paste into a PR, an issue or an incident ticket. |
| **`.html`** | Self-contained dark-mode page. No CDN, no assets, no network. Mail it. |
| **`.sarif`** | OASIS SARIF v2.1.0 — uploads straight to GitHub Code Scanning. |
| **`.yar`** | A usable YARA rule built from the imphash, IOC strings and byte sequences from the top-scoring functions. |
| **`.misp.json`** | A MISP event ready for import into a threat intel platform. |

For JSON consumers, the optional root-level `detection` object preserves the CLI's
format classification and evidence separately from Ghidra's import result. It includes
the detector's suggested processor, the processor explicitly passed to Ghidra (if any),
a requested format loader (if any), the import strategy, and ELF `e_flags` when available.
The existing `architecture.language_id` remains the actual language of the opened
Ghidra program. A `detector_deferred` strategy means the CLI intentionally left the
choice to Ghidra; `existing_project_reused` means the current run did not re-import it.
The object is additive and optional for direct exporter integrations that do not supply
detector metadata.

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
./ghidra-report.sh --search <term>           Search indexed metadata, APIs, IOCs, and indicators
./ghidra-report.sh --dashboard [port]        Web UI over the report history
./ghidra-report.sh --rules [report|binary]   Evaluate the YAML capability rules
./ghidra-report.sh --trace <trace.json>      Correlate a sandbox trace with static imports
./ghidra-report.sh --carve <binary> [dir]    Carve embedded firmware containers
./ghidra-report.sh --svd <file.svd>          Inspect / inject CMSIS-SVD peripherals
./ghidra-report.sh --detect-type <file>      Print the detected format and exit
./ghidra-report.sh --list-projects           Show cached Ghidra projects
./ghidra-report.sh --purge-projects          Delete cached .gpr / .rep databases
```

File types are validated against header signatures and structural fields before loader dispatch; an unknown `.bin`/`.rom` stays a raw binary rather than being guessed to be SNES. Supported ELF language IDs are selected from class, byte order, and `e_machine`. If the header does not justify a safe language choice (including ambiguous MIPS64 ISA/ABI variants), `--detect-type` reports the format while import defers processor selection to Ghidra.

### Options

| Flag | Effect |
|:--|:--|
| `--format <txt\|json\|md\|html\|sarif\|yar\|misp\|all>` | Which artifacts to write (default `all`) |
| `--parallel`, `-j [N]` | Analyze ingress files across N worker processes; identical output identities are serialized |
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

The history index preserves separate reports by canonical JSON report path. Search combines case-insensitive SQLite `LIKE` matching for metadata, hashes, suspicious APIs, IOCs, and threat indicators with an FTS5 index over extracted/recovered strings, function names/symbols, exports, rules, capabilities, and findings found in selected JSON fields. Re-indexing the same JSON path refreshes its free-text index without duplicating the history row. Existing rows are migrated in place; older reports only gain recovered-string/function search content after their JSON is re-indexed (the migration cannot reconstruct fields that were never stored in SQLite):

```bash
./ghidra-report.sh --search "CreateRemoteThread"
./ghidra-report.sh --search "Themida"
./ghidra-report.sh --search 10bce0b1
./ghidra-report.sh --dashboard 8080
```

The dashboard binds to `127.0.0.1` by default and remains unauthenticated
on loopback. Every non-loopback bind requires `GHIDRA_DASHBOARD_TOKEN`, a
random token of at least 32 UTF-8 bytes. The browser prompts for HTTP Basic
credentials (username `ghidra-report`, password the token); the same
authentication protects the UI, APIs, and report artifacts.

```bash
export GHIDRA_DASHBOARD_TOKEN="$(openssl rand -hex 32)"
GHIDRA_DASHBOARD_HOST=0.0.0.0 ./ghidra-report.sh --dashboard 8080
```

The built-in server does not provide TLS. **Never expose its HTTP connection
directly to an untrusted network.** Put remote access behind an HTTPS reverse
proxy, VPN, or SSH tunnel; ensure the proxy preserves the `Authorization`
header. Tokens are read from the environment and are never accepted as command
line arguments. Unknown hostnames are treated as remote and also require a
token. Docker Compose binds inside the container but publishes the port on host
loopback only (`127.0.0.1:8080`); because the container listens on
`0.0.0.0`, Compose also requires `GHIDRA_DASHBOARD_TOKEN` to be set.

#### HTTPS deployment with Docker Compose and Caddy

For a public HTTPS endpoint, create a DNS A/AAAA record for the server and allow
inbound TCP ports 80 and 443 (plus UDP 443 for HTTP/3). Then start the optional
Caddy profile:

```bash
export DASHBOARD_DOMAIN="dashboard.example.com"
export GHIDRA_DASHBOARD_TOKEN="$(openssl rand -hex 32)"
docker compose --profile https up -d --build
```

Open `https://$DASHBOARD_DOMAIN/`; the browser's HTTP Basic prompt uses
username `ghidra-report` and the token as its password. Caddy obtains and
renews the public certificate automatically. Keep the named `caddy_data` and
`caddy_config` volumes so certificate and ACME state persist. The dashboard's
direct host mapping remains loopback-only at `127.0.0.1:8080`; only Caddy
publishes ports 80/443.

The proxy configuration preserves `Authorization` for the dashboard's Basic
authentication, removes client-supplied `Forwarded` and `X-Forwarded-*`
overrides, and adds HTTPS response headers. The dashboard does not use forwarded
headers for authentication, host selection, or URL generation. Do not add a
broad `trusted_proxies` range or an authentication-header rewrite. When another
load balancer sits in front of Caddy, review and configure its trust boundary
separately rather than trusting arbitrary client forwarding headers.

The live proxy regression is `python3 tests/test_dashboard_proxy.py` (Docker
Engine required). It runs Caddy with a local test CA and verifies TLS termination,
the Basic-auth challenge/credential pass-through, and response headers. It does
not validate public ACME issuance or renewal against your deployment's DNS.

Report HTML is served with a restrictive CSP sandbox, all dashboard responses
use `Cache-Control: no-store`, and artifact routes are confined to the
canonical `output/` directory.

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
        │                  │      │   DecompilerExporter  │     │  (SQLite LIKE)       │
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
│  projects/         │     Side pipelines (Python stdlib; PyYAML for rules)
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
| `capability_engine.py` | `--rules` | Evaluates strict v1.0.0 YAML rules with file-aggregate and API-only function scopes, AND/OR/NOT and N-of-M logic; exact API matching, not capa-compatible. |
| `trace_correlator.py` | `--trace` | Correlates a CAPE/DRAKVUF sandbox trace against the static import set using a sliding call window, so multi-step behaviours (alloc → write → create thread) match as one capability. |
| `index_report.py` | *(automatic)* | Indexes each completed JSON report path into `output/reports.db`; separate runs and same-basename inputs remain distinct. Search combines SQLite `LIKE` matches on metadata/APIs/IOCs/indicators with FTS5 search across recovered text, symbols/functions, exports, rules, capabilities, and findings. |
| `dashboard.py` | `--dashboard` | Standalone `http.server` UI + REST API. Loopback by default; `GHIDRA_DASHBOARD_HOST` opts into another bind address. |

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

The YAML rule engine requires PyYAML; without it, rule evaluation now exits with
an actionable error instead of silently loading zero rules. Install the optional
dependency with:

```bash
python3 -m pip install -r requirements-rules.txt
```

The core report pipeline, dashboard, carver, indexer, and trace correlator continue
to use Python's standard library. The Docker image installs the OS-provided
PyYAML package so `--rules` works there as well.

The capability DSL is versioned and validated against
[`schemas/capability-rule-v1.schema.json`](schemas/capability-rule-v1.schema.json);
stable IDs, rationales, and HTTPS references are required. Every shipped rule has
a positive and a negative fixture. `scope: "file"` evaluates aggregate report fields;
`scope: "function"` evaluates API-only expressions independently against each
function's resolved suspicious call sites. Instruction and basic-block scopes are
rejected until the report contains the required features. API primitives use
case-insensitive exact function names, or exact `library!function` names in file
scope; substring matches are not used.

The exporter adds an optional `function_api_evidence` array containing each caller
function's address and the suspicious API target/call-site addresses. Function-scope
rule matches include that caller identity, call-site evidence, and
`evidence_quality: "function_callsite"`; file-scope matches retain
`evidence_quality: "file_aggregate"`. Neither quality label is a probability or
calibrated confidence score. Read [`docs/CAPABILITY_RULES.md`](docs/CAPABILITY_RULES.md)
for the DSL contract and remaining limitations.

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

Host installs must use a Java runtime supported by the installed Ghidra release. The pinned container uses Ghidra 12.2 and JDK 25; `GHIDRA_ROOT` overrides autodetection, and the launcher prints its detected runtime versions.

### Docker

```bash
docker compose run --rm ghidra-report --batch
```

The image pins Ghidra 12.2 and Eclipse Temurin JDK 25, verifies the official release archive checksum, and preconfigures the headless analyzer. `ingress/` and `output/` are bind-mounted. GitHub Actions builds this image, runs a real synthetic PE analysis, checks all seven artifacts and JSON/SARIF/MISP envelopes, then runs the broader synthetic suite. SNES header detection is covered independently; raw 65816 Ghidra analysis is skipped unless a compatible optional processor language is installed.

### Packages

```bash
APP_VERSION="$(cat VERSION)"
./scripts/package_release.sh          # dist/ghidra-report-v${APP_VERSION}-linux-x86_64.tar.gz + .sha256
```

Homebrew formula and AUR `PKGBUILD` live in `packaging/`; both use a launcher wrapper so read-only runtime assets remain co-located and writable data stays in the user's data directory. A man page is at
`ghidra-report.1`.

For Homebrew/AUR installs, runtime assets stay together under the package's private app root, while writable inputs, projects, reports, and history default to `${XDG_DATA_HOME:-$HOME/.local/share}/ghidra-report`. Set `GHIDRA_REPORT_DATA_DIR` to choose another data root, or override `GHIDRA_REPORT_INGRESS_DIR`, `GHIDRA_REPORT_OUTPUT_DIR`, `GHIDRA_REPORT_PROJECTS_DIR`, and `GHIDRA_REPORT_DB_PATH` individually. A source checkout continues to default its writable directories beside `ghidra-report.sh`.

**Release status:** `VERSION` is the canonical app version source. The Homebrew/AUR metadata is aligned to this repository and version, but release tags/assets have not been published and their source checksums remain explicit placeholders. Do not submit or install those package definitions as a release until a tagged release archive exists, its checksum is verified, and clean-install tests pass.

### CI

`.github/workflows/binary-analysis.yml` has a fast no-Ghidra lane for Python,
CLI, launcher, parser, and dashboard-security regressions. Its separate pinned
Ghidra 12.2/JDK 25 container job executes a real synthetic PE analysis and checks
all seven artifacts plus JSON/SARIF/MISP envelopes, then runs the broader
`tests/run_tests.sh` suite using generated fixtures. SNES header detection runs
without extensions; Ghidra raw 65816 analysis and dependent semantic diff tests
are skipped unless the optional `65816:LE:24:snes` language definition is
installed. That skip does not validate optional community loaders.
SARIF publishing remains disabled until a complete generated-artifact upload path
is implemented and tested.

---

## Testing

### Fast checks (no Ghidra required)

These checks run in the default GitHub Actions workflow. To run the Python checks locally, install `requirements-rules.txt` and `requirements-test.txt`; the Java escaping regression also needs `javac` and `java` on `PATH`, and the live Caddy HTTPS proxy regression needs Docker Engine. Ghidra is not required for this lane.

```bash
python3 -m compileall -q scripts tests
python3 tests/test_report_schema.py
python3 tests/test_report_format.py
python3 tests/test_version_consistency.py
python3 tests/test_package_layout.py
python3 tests/test_architecture_detector.py
bash tests/test_architecture_dispatch.sh
python3 tests/test_project_identity.py
./ghidra-report.sh --help >/dev/null
bash tests/test_run_headless.sh
bash tests/test_headless_log.sh
bash tests/test_ghidra_language.sh
bash tests/test_snes_fallback.sh
bash tests/test_report_generation.sh
bash tests/test_batch_runner.sh
python3 tests/test_dashboard_security.py
python3 tests/test_dashboard_proxy.py  # requires Docker Engine
python3 tests/test_firmware_carver.py
python3 tests/test_trace_correlator.py
python3 tests/test_history_indexer.py
python3 tests/test_capability_engine.py
```

The launcher regression test mocks the Ghidra commands and checks standard and
Flatpak invocation plus invalid `JAVA_HOME`. The dashboard security tests start a
local HTTP server and cover path traversal, symlink escapes, escaped HTML values,
security headers/CSP, loopback binding, and bounded responses.
The trace-correlation tests exercise list-shaped generic traces, CAPE process events,
case-insensitive API matching, malformed event entries, and process-isolated attack chains.
The history-indexer tests verify current/legacy report-field mapping, JSON-path idempotence, migration preservation, FTS5 matches for recovered strings and function names, and removal of stale text hits when a JSON path is re-indexed. The dashboard security suite also verifies FTS snippets retain separate same-basename output identities.

### Full Ghidra-backed integration suite

```bash
./tests/run_tests.sh
```

This suite generates synthetic PE, SNES, GBA, N64, and PS1 fixtures and
requires a compatible Ghidra installation and Java for analysis tests. The
default GitHub Actions container runs it with pinned Ghidra 12.2 and JDK 25.
SNES header detection always runs, but raw 65816 analysis and its semantic-diff
dependency run only when the optional `65816:LE:24:snes` language definition is
installed in Ghidra or under `GHIDRA_EXTENSION_ROOT`. Other community-loader
inventory is reported separately as skipped when seven extensions are not
available; that skip does not verify extension-backed loaders.

The suite covers the seven report artifacts, scoring, MISP/SARIF output, firmware
carving, history search, capability and trace engines, SVD injection, file-type
detection, packaging, and Java compilation. It also imports 15 synthetic ELF
executables through the real Ghidra loader (including ARM BE8) and verifies that
each JSON report records the expected opened language ID. SNES cartridge header
detection runs on the base image; SNES MMIO/DMA analysis and the semantic diff
require the optional 65816 language. The focused container smoke validates the
real PE JSON against the checked-in schema and checks the SARIF/MISP envelopes.
No job installs or validates optional community loaders.

No test reads samples from `ingress/`; fixtures are generated in temporary
locations, and real analysis samples should remain git-ignored.

---

## Project layout

```
ghidra-report.sh          Main CLI
run-headless.sh           Portable Ghidra headless launcher (GHIDRA_ROOT/JAVA_HOME aware)
scripts/
  ExportFullReport.java   Orchestrator
  lib/*.java              Analyzers and renderers
  *.py                    Side pipelines
rules/*.yaml              Capability detection rules
ingress/                  Drop binaries here
output/<output_key>/      Reports for one canonical path + content identity, plus reports.db
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
