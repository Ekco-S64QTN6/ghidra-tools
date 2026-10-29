# Roadmap — ghidra-report

**Status:** Proposed engineering backlog, based on a static review of the repository's `main` branch on 2026-10-27.  
**Purpose:** Turn the current collection of useful analysis prototypes into a safer, reproducible, verifiable binary-triage pipeline.  
**Planning rule:** Fix security and correctness before adding more detection features. This roadmap is ordered by risk and dependencies, not a promise of calendar dates.

## Executive summary

The project already has a broad prototype: a Bash CLI, a Ghidra Java analysis pipeline, seven report formats, heuristic threat scoring, YAML rules, firmware carving, a trace correlator, an SVD helper, a small HTTP dashboard, and packaging scripts. The biggest opportunity is not adding more checkboxes; it is making those features safe, testable, portable, and accurately documented.

The following issues should be addressed before describing the project as feature-complete or using its outputs as an automated containment signal:

1. **Dashboard exposure:** `scripts/dashboard.py` binds to all interfaces, serves paths beneath `/output/` without a canonical-path containment check, and interpolates sample/report-derived strings into `innerHTML`. Taken together, these create serious file-disclosure and stored-XSS risks when the dashboard is reachable by untrusted clients or displays hostile samples.
2. **Headless launch portability:** `run-headless.sh` hard-codes a Flatpak install path, while the CLI claims to autodetect `/opt/ghidra` and `/usr/share/ghidra`. The Docker image installs Ghidra 11.1.2 while README and plan claim Ghidra 12.x.
3. **CI does not run the advertised suite:** `.github/workflows/binary-analysis.yml` does not execute `tests/run_tests.sh`; it runs a small dashboard check and a firmware-carver command with `|| true`. Its SARIF step targets an output path that this workflow does not generate.
4. **History and search disagree with documentation:** `scripts/index_report.py` uses ordinary `LIKE` searches rather than FTS5, uses a filename as the unique key (so a rerun for the same filename overwrites the previous record), reads a timestamp key that the report writer does not emit, and looks for `ioc_findings` while the JSON writer emits `iocs`.
5. **The feature claims exceed the verified implementation:** ELF architecture detection logs a guessed language ID but does not pass it to Ghidra; the capability engine is aggregate-report matching rather than true instruction/basic-block/function-scope analysis; firmware extraction is not recursive and has unbounded decompression paths; trace correlation and deobfuscation are best-effort heuristics that need stronger fixtures and calibration.

These findings come from source inspection, not a successful execution of the project. The repository could not be cloned in the review environment because direct Git network access failed, and no local Ghidra installation was available to run integration tests. Re-run the test suite in a controlled environment after the P0 setup and security work below.

## Priority definitions

- **P0 — Must fix before recommending network exposure, trusting CI status, or advertising a verified install path.**
- **P1 — Correctness and verification work required for reliable analysis output and maintainable releases.**
- **P2 — Product and analyst workflow improvements after the foundations are dependable.**

---

## P0 — Security, execution, and delivery fundamentals

### 0.1 Harden the dashboard before exposing it

**Relevant files:** `scripts/dashboard.py`, `docker-compose.yml`, README deployment guidance.

- Resolve every requested output path to a canonical path and reject it unless it remains under the canonical `output/` directory. Handle URL-encoded and path-normalization edge cases and test traversal attempts.
- Bind to `127.0.0.1` by default, not the wildcard address. Add an explicit opt-in bind-address setting for trusted LAN/service deployment; document that exposing it requires authentication and a protected network. Prefer adding authentication rather than suggesting that an arbitrary interface binding is safe.
- Replace untrusted `innerHTML` interpolation with DOM APIs and `textContent`, or a small, reviewed escaping layer. Sample names, symbols, URLs, extracted strings, and IOCs must be treated as hostile input.
- Add response security headers (including an appropriate Content Security Policy), limit search input and response size, and avoid exposing filesystem error text or stack detail to clients.
- Ensure reports and uploaded samples are not accessible outside their intended root. Add regression tests for traversal, encoded traversal, markup/script-shaped IOCs, and dashboard bind configuration.

**Acceptance criteria**
- Requests cannot read files outside `output/`, even using encoded or normalized traversal variants.
- A generated report containing HTML/JavaScript-shaped strings renders them as text.
- The default listener is loopback-only; remote binding is explicit and documented.
- Security tests run in CI and fail the build on regression.

**Incremental progress — 2026-10-29:** Report artifact routes now repeatedly URL-decode and canonicalize paths, reject traversal and symlink escapes, cap file/search responses, and return generic filesystem/database errors. Dashboard values are HTML-escaped before template insertion; exported report HTML receives a restrictive CSP sandbox. The server binds to loopback by default, with an explicit `GHIDRA_DASHBOARD_HOST` override; Docker Compose limits host publication to loopback. Dedicated HTTP/security regressions are wired into CI. This is incremental progress, not a full security sign-off: remote binds remain unauthenticated and require a trusted access boundary, and the complete suite/runtime threat review is still outstanding.

### 0.2 Make the Ghidra launcher honor configuration

**Relevant files:** `run-headless.sh`, `ghidra-report.sh`, `Dockerfile`, `docker-compose.yml`.

- Remove the Flatpak-only paths hard-coded in `run-headless.sh`. Derive the launcher/JVM from `GHIDRA_ROOT` (and an explicit `JAVA_HOME` when provided), or invoke Ghidra's supported `support/analyzeHeadless` launcher where it works in the target environment.
- Keep discovery and execution consistent: if the CLI finds `/opt/ghidra` or `/usr/share/ghidra`, the launcher must actually use that installation.
- Pin one tested Ghidra build for the default CI/container path and publish the supported versions explicitly. The repository currently claims Ghidra 12.x but the Dockerfile downloads Ghidra 11.1.2. Upstream Ghidra has since published 12.2; choose a version deliberately and test it rather than relying on an unverified range.
- Add clear dependency checks for Java, Ghidra, and required extensions, with actionable errors and an actual version printout.
- Avoid piping the headless process through `tee | while` in a way that lets `set -e -o pipefail` bypass the intended loader-fallback/error handling. Capture its exit status explicitly before deciding whether to retry or emit reports.

**Acceptance criteria**
- Clean-container smoke tests prove the same launcher works with the documented Docker install and a non-Flatpak `GHIDRA_ROOT`.
- Unsupported Ghidra/Java combinations fail early with a useful error.
- Loader fallback is tested against both a successful import and an expected failure.

**Incremental progress — 2026-10-29:** The launcher now honors an explicit or discovered `GHIDRA_ROOT`, validates `JAVA_HOME`, calls `support/analyzeHeadless` for standard installs, and derives the Flatpak JDK for the existing direct-JVM workaround. A mock-based regression test covers both launcher paths and invalid Java configuration. The previously added log helper is now used by both the primary import and SNES fallback; each command's nonzero exit is preserved through `tee`/filtering, and an unrecognized failure status can no longer be reported as successful import merely because expected error text was absent. Synthetic tests cover command exit propagation and invalid filter mode. This does **not** close the gate: the Docker/Ghidra version mismatch, clean-container runtime smoke test, dependency/version diagnostics, and real Ghidra loader-fallback acceptance tests remain open.

### 0.3 Turn CI into real, deterministic verification

**Relevant files:** `.github/workflows/binary-analysis.yml`, `tests/run_tests.sh`, `tests/make_fixtures.py`.

- Run actual tests instead of a smoke command followed by `|| true`. Split tests into clearly named groups:
  - fast Python/CLI/helper unit tests that do not need Ghidra or optional loaders;
  - Java compile/schema checks against the pinned Ghidra distribution;
  - end-to-end analysis tests with synthetic PE and SNES fixtures;
  - optional extension-based tests, explicitly skipped only when the relevant extension is not installed.
- Remove the test's assumption that every developer/CI runner has seven extensions in `~/.config/ghidra/ghidra_12.1.3_FLATPAK/Extensions`. Provide a documented extension fixture/install step or test the extension-free paths separately.
- Fix the Java compile assertion so it checks `javac`'s exit code directly, not whether the output happens to contain the word `error:`.
- Exercise the same release/container path that users run. Make the workflow fail if the expected artifacts are missing or malformed.
- Set the minimum workflow permissions needed for SARIF upload (including `security-events: write`), upload only after an analysis has actually produced SARIF, and do not use `continue-on-error: true` to hide a broken promised integration.
- Pin Actions to reviewed major versions (or immutable SHAs per project policy) and test the Docker build, CLI help, one fixture analysis, all expected output artifacts, and output schemas.
- Use a small, redistributable synthetic corpus in CI; keep licensed/vendor loaders and any non-redistributable binaries out of CI unless permission is explicit.

**Acceptance criteria**
- A clean checkout on the documented environment can run the default test command without relying on a developer's home directory.
- A failing test, failed headless analysis, missing SARIF file, or schema error fails the job.
- The workflow report accurately states which test groups ran and which optional groups were skipped.

**Incremental progress — 2026-10-29:** The fast CI lane now runs Python compilation, CLI help, the mocked portable-launcher regressions, and the dashboard HTTP/security regressions as explicit failing checks. Removed the `firmware_carver.py ... || true` command because it did not validate behavior and could not fail CI. Removed the manual SARIF upload-only job because it never generated the referenced `output/dsetup.dll/report_latest.sarif` artifact and hid upload failures. The full Ghidra-backed suite, extension-independent fixtures, Java/schema validation, Docker smoke analysis, and real SARIF generation/upload remain open; this does not close P0.3.

---

## P1 — Correctness and evidence quality

### 1.1 Make architecture detection actually select an architecture

**Relevant files:** `ghidra-report.sh`, `docs/PROCESSOR_PROFILES.md`, loader dispatch tests.

- Treat file extension as a hint, then validate magic/header fields; do not classify every unknown `.bin` as an SNES ROM without saying that is a guess.
- For ELF, use class, byte order, `e_machine`, and relevant flags together. Do not map all RISC-V executables to one 64-bit language spec.
- Pass the chosen language/processor to Ghidra's import invocation, or state accurately that the CLI only reports a suggestion when it cannot force a loader.
- Cover every format accepted in direct mode in `--batch` extension filtering (including supported GBA/PSX formats), and test uppercase extensions, mislabeled files, truncated headers, and unknown architectures.
- Track format detection separately from successful loader selection and the architecture Ghidra actually opened.

**Acceptance criteria**
- Tests verify both detected format and the processor spec passed to Ghidra for x86, x86-64, ARM, AArch64, MIPS, RISC-V 32/64-bit, PowerPC, and unknown inputs.
- The report records detection evidence and final Ghidra language ID so incorrect guesses are explainable.

**Incremental progress — 2026-10-29:** Added `scripts/architecture_detector.py` to validate PE signatures/optional headers, ELF identity fields, N64 byte-order magics, PS-X EXE headers, GBA logo/checksum fields, and plausible checksum/reset-vector SNES headers before classifying those formats. Unknown `.bin`/`.rom` files now stay raw instead of being guessed as SNES. ELF processor selection uses ELF class, byte order, and `e_machine`, passes supported Ghidra language IDs through `-processor`, and logs the evidence used; unsupported combinations defer to Ghidra. RISC-V uses the declared `RISCV:LE:{32,64}:default` IDs; MIPS64 is intentionally not forced because Ghidra's current MIPS64 `default` definitions identify MIPS16e mode, so ELF ABI/ISA flags need interpretation before a safe selection can be made. Batch filtering now includes `.gba`, `.psx`, and N64 ROM suffixes. Synthetic architecture/header fixtures run in fast CI. The detector still reports format suggestion separately from the actual loader result, and the full integration suite must confirm language/loader IDs on real Ghidra imports.

### 1.2 Upgrade the YAML capability engine from prototype to a real rule system

**Relevant files:** `scripts/capability_engine.py`, `rules/*.yaml`.

- Decide explicitly whether to integrate or interoperate with Mandiant's capa engine/rule corpus, or to maintain a smaller, documented ghidra-report-specific DSL. Do not imply equivalent scope unless it is implemented and tested.
- The current evaluator runs rules against aggregate report fields. It does not extract instruction/basic-block features and it does not genuinely evaluate rules against individual functions despite rule metadata such as `scope: function`.
- Fix the no-PyYAML fallback: the current fallback parses only top-level labels and does not parse the `features` tree, so it cannot load the actual rules. Either make PyYAML a required, installed dependency for this feature or implement/test a real parser.
- Define and version a rule schema; validate operators, primitive types, unknown keys, weights, and metadata at load time. Give every rule a stable ID, rationale, references, and fixtures.
- Keep evidence attached to every hit (matched API, indicator, block/function address, and rule expression) and expose a confidence/quality label. Add negative examples to measure false positives.
- Validate MITRE ATT&CK and MBC references against current canonical identifiers; do not derive classifications from loose substring matching alone.

**Acceptance criteria**
- Every shipped rule has a positive and a negative fixture.
- Tests prove each advertised operator and scope, including malformed YAML and missing dependencies.
- Output states which exact evidence matched and the relevant address/scope.

**Incremental progress — 2026-10-29:** Added `requirements-rules.txt` for the optional PyYAML runtime dependency and installed the system PyYAML package in the Docker image. The rule engine no longer uses an incomplete top-level-only YAML fallback: missing PyYAML and malformed/incomplete rules now fail with a path-specific diagnostic rather than silently producing zero rule matches. Synthetic tests cover shipped rule loading, missing dependency behavior, malformed YAML, supported operator/primitive shape validation, weights/unknown keys/count thresholds, AND/OR/NOT/count evaluation, and a positive/negative process-injection rule example. True per-function/basic-block scope, a separately versioned formal rule schema, stable rule IDs/references, and coverage fixtures for all shipped rules remain open.

### 1.3 Make string recovery and emulation evidence-driven

**Relevant files:** `scripts/lib/EmulatorDeobfuscator.java`, `scripts/lib/StackStringDetector.java`, `scripts/lib/IocExtractor.java`, `scripts/ExportFullReport.java`.

- Expand string scanning beyond strings Ghidra has already defined as data; support bounded raw-region scanning and UTF-16LE with address provenance.
- The current stack-string detector concatenates printable immediate bytes from consecutive `MOV*`/`STR*` instructions without confirming that they target the same stack buffer. Verify stores, offsets, data flow, termination, and architecture before calling a result a reconstructed string.
- The XOR scanner selects an immediate and memory reference heuristically; the P-code pass uses a very small step budget and does not robustly initialize a realistic stack/call state. Treat these as candidate-producing heuristics, not proof of runtime decryption.
- Add emulation time, instruction, memory, recursion, and output limits; record stop reasons; do not swallow every `Throwable` without diagnostic evidence.
- Compare behavior and output quality with FLOSS on a documented, legally usable corpus. Integrate FLOSS as an optional backend only after evaluating licensing, dependencies, performance, and offline behavior.

**Acceptance criteria**
- Each extracted/recovered string includes method, address, function/context, and a confidence or evidence explanation.
- Fixtures cover immediate-built stack strings, encoded static strings, UTF-16LE, false-positive patterns, unsupported architectures, and bounded emulation failures.
- A regression report documents precision/recall on a sample corpus; no “emulated” result is emitted without actual execution evidence.

### 1.4 Make firmware carving bounded, recursive, and verifiable

**Relevant files:** `scripts/firmware_carver.py`, CLI `--carve`, tests and docs.

- Implement actual recursive extraction with depth, file-count, total-output-size, per-file-size, decompression-ratio, and wall-time budgets. Make the limits configurable with safe defaults.
- Avoid loading and copying an entire large firmware image multiple times; use bounded reads, memory mapping, or chunked scanning where practical.
- Validate container bounds, header checksums/CRCs, lengths, offsets, and supported compression types before extraction. Never trust declared sizes from the binary.
- Add fixture files for each claimed format and for truncated, corrupt, overlapping, nested, and adversarially compressed inputs. Current tests mostly cover GZIP and a U-Boot header rather than the advertised breadth.
- Either implement UBI/zlib and recursive cases, or remove them from the feature claims until supported.
- Compare detections/extraction against Binwalk v3 and/or unblob. Prefer delegating to a mature extractor for broad format coverage over maintaining a growing, weakly tested signature parser. Keep external tools optional and make their availability explicit.

**Acceptance criteria**
- A nested fixture is extracted recursively, with every child offset and size recorded.
- Corrupt/oversized inputs stop within resource limits and never write outside the chosen output directory.
- Every advertised format has a known-positive fixture and a malformed-input regression case.

**Incremental progress — 2026-10-29:** The uImage parser now rejects negative offsets and headers whose declared payload size exceeds the bytes remaining in the input, and the scanner emits a diagnostic instead of reporting a truncated container. A synthetic standard-library test covers valid payloads, truncated payloads, invalid offsets, and ensures truncated headers produce no carve output; this test runs in the fast CI lane. Header CRC validation, recursion, resource budgets, and broader per-format negative fixtures remain open.

### 1.5 Correct dynamic trace correlation

**Relevant files:** `scripts/trace_correlator.py`, `--trace`, `docs/SOAR_INTEGRATION.md`.

- Normalize generic and CAPE/Cuckoo/DRAKVUF-like formats with explicit adapters and schema tests. The current list input path later assumes a dictionary and calls `.get()`; nested process behavior is not consistently read from its actual location.
- Correlate dynamic calls against all relevant static imports or statically resolved calls, not only the subset already tagged suspicious. Separate “not in import table” from “evidence of dynamic resolution.”
- Normalize API names/case and preserve process, thread, time, arguments, and call ordering. Keep attack-chain sequence matches tied to the actual event slice.
- State clearly that a trace is an external observation and may not correspond to the same sample/build unless the hash and run metadata match.

**Acceptance criteria**
- Fixtures include each supported input schema, list-shaped input, multiple processes, case variations, absent fields, and common injection chains.
- Output differentiates confirmed, statically imported but unobserved, and unresolved dynamic APIs without treating any one category as a verdict by itself.

**Incremental progress — 2026-10-29:** The trace loader now accepts top-level array traces without calling mapping methods on the list, normalizes generic and CAPE/Cuckoo process call records, retains process/thread/time/argument metadata on normalized calls, matches API names case-insensitively, and prevents an attack chain from being stitched together across different process IDs. Dedicated synthetic fixtures run in fast CI. Additional schema adapters, explicit provenance/hash matching between sample and trace, and broader sandbox-specific fixtures remain open.

### 1.6 Calibrate risk scoring and preserve evidence

**Relevant files:** `scripts/lib/HeuristicScorer.java`, `ApiTagger.java`, `EntropyAnalyzer.java`, `ShellcodeDetector.java`, all report writers.

- Treat risk scores as triage prioritization, not a calibrated probability. Document that score interpretation depends on file type and available evidence.
- Validate weights against a labeled benign/malicious/packed corpus; test false positives such as benign high entropy, embedded data, and raw byte patterns inside non-executable sections.
- Give each finding a stable identifier, evidence address/region, confidence, source, weight, and explanation. Avoid using an import alone to imply a complete ATT&CK behavior.
- Gate architecture-specific shellcode signatures by architecture and executable permissions where appropriate. Comments mention detection categories (such as egg hunters) that should be implemented or removed from the claims.
- Distinguish “not observed” from “absent,” particularly for stripped, packed, or partially decoded binaries.

**Acceptance criteria**
- Every score contribution is traceable to a finding with evidence and rationale.
- A versioned benchmark includes benign controls and reports false-positive/false-negative trade-offs before weights change.
- Reports label unsupported or low-coverage analyses rather than silently producing a reassuring low score.

---

## P1 — Data model, report integrity, and history

### 1.7 Version the JSON report contract and fix serialization

**Relevant files:** `scripts/lib/ReportModel.java`, `JsonReportWriter.java`, `ReportFormat.java`, `SarifExporter.java`, `MispExporter.java`, `YaraGenerator.java`.

- Add a `schema_version` and maintain JSON schemas plus migration fixtures. Consumers should not rely on undocumented key names.
- Use a standard JSON serializer or ensure every control character below U+0020 is escaped. The current hand-written escaping covers common escapes but does not handle all JSON control characters.
- Validate SARIF against the official 2.1.0 schema and MISP event JSON against supported MISP conventions in CI. The SARIF writer currently represents an address as `region.message`, which is not a substitute for a valid source region/offset; map offsets correctly or omit the region when exact mapping is not possible.
- Add stable SARIF rule IDs and result fingerprints; attach accurate evidence locations where available. Use real finding addresses rather than hard-coded `0x0`.
- Escape YARA strings/metadata comprehensively and compile generated rules with YARA in an optional test job. Keep generated byte patterns conservative and explain that a generated rule may be sample-specific.
- Ensure exports carry the complete intended IOC set and preserve provenance; distinguish values suitable for IDS matching from contextual host paths or decoded candidate strings.

**Acceptance criteria**
- All report formats are validated using real parsers/schema validators in CI.
- Adversarial strings containing control characters, quotes, backslashes, Unicode, and markup round-trip safely.
- SARIF finding locations and fingerprints are stable and meaningful; YARA output compiles for the fixture corpus.

### 1.8 Make history actually historical and searchable

**Relevant files:** `scripts/index_report.py`, `scripts/dashboard.py`, report paths and CLI search.

- Use an analysis-run ID keyed by sample SHA-256 plus run metadata rather than using filename as a unique key. Preserve multiple builds with the same filename and repeated analysis of the same sample.
- Align database field names with the JSON schema. The JSON writer emits `generated` and `iocs`, while the indexer currently reads `timestamp` and `ioc_findings`; those fields are lost today.
- Either implement actual SQLite FTS5 tables and indexes or stop claiming that searches use FTS5. Include extracted strings, recovered strings, symbols/functions, rules, and findings in the agreed searchable set.
- Add schema migrations, transactions, useful indexes, query pagination/limits, deterministic sorting, retention/export, and clear behavior when a JSON report is re-indexed.
- Keep the report paths stored in the DB relative to a known data root or validate them before serving artifacts from the dashboard.

**Acceptance criteria**
- Two different binaries with the same basename and two runs of one binary both remain queryable as separate records.
- Search returns fixture IOCs and findings; tests verify the timestamps and IOCs survive indexing.
- A migration test upgrades an older database without losing saved reports.

**Incremental progress — 2026-10-29:** The indexer now reads the report writer's `generated` timestamp and `iocs` array, while retaining fallbacks for older `timestamp` and `ioc_findings` reports. Indicator ATT&CK metadata is read from the current `mitre_id` field with a legacy `mitre` fallback. Synthetic SQLite tests cover both current and legacy report shapes in fast CI. The filename-unique run model, true FTS5 implementation, migrations, and search coverage expansion remain open.

**Documentation correction — 2026-10-29:** README, man page, and project-plan search claims now describe the implementation actually present: ordinary SQLite `LIKE` queries over report filename/hash metadata, suspicious APIs, IOCs, and indicators. The docs no longer claim that FTS5, extracted-string/symbol search, or immutable per-run history exists. This narrows the claims without closing the 1.8 implementation gate.

### 1.9 Make parallel and batch execution reliable

**Relevant files:** `ghidra-report.sh`, project naming, output path creation.

- Give projects stable collision-resistant names derived from sample hash and analysis settings, not sanitized basename alone.
- Do not let parallel workers operate on the same Ghidra project or the same `report_latest.*` outputs. Isolate per-run temporary paths and publish final artifacts atomically.
- Collect individual exit statuses, propagate failure counts, and report successful, failed, and skipped samples separately. Current parallel waits suppress errors and batch can report success after failures.
- Add per-file timeouts, cancellation, retry policy for known transient failures, and clear logs per sample. Do not delete or replace a project until its ownership and active workers are known.

**Acceptance criteria**
- Concurrent files with identical basenames do not collide or corrupt reports.
- One failed input makes the batch exit non-zero while the remaining files still receive a clear status.
- Repeated runs produce complete artifacts, never partially written `report_latest.*` files.

**Incremental progress — 2026-10-29:** Batch execution now uses a shared, tested worker scheduler that waits for every child exactly once, records per-item success/failure counts, attempts remaining items after a failure, rejects non-positive worker counts, and returns nonzero when any item fails. A synthetic shell regression covers mixed results, all-success results, and invalid worker counts. Collision-resistant project identity, atomic output publication, timeouts/cancellation, and retry policy remain open.

---

## P1 — Packaging, deployment, and documentation consistency

### 1.10 Repair reproducible packaging and versioning

**Relevant files:** `Dockerfile`, `docker-compose.yml`, `scripts/package_release.sh`, `packaging/PKGBUILD`, `packaging/ghidra-report.rb`, `ghidra-report.1`, `SarifExporter.java`.

- Fix the Homebrew/AUR repository URLs to the actual project origin.
- Replace `sha256 "SKIP"` and `sha256sums=('SKIP')` with real release checksums; these are not acceptable as reproducible release metadata.
- Ensure the package install layout matches how `ghidra-report.sh` finds sibling scripts, rules, the headless launcher, and writable data directories. Test installation into a clean package/container rather than only running from the checkout.
- Use one version source for CLI banner, report metadata, SARIF driver version, man page, release archive names, Homebrew/AUR manifests, and docs. Add a CI consistency check.
- Review generated maintainer/author metadata for accuracy, and remove placeholder or attribution strings that do not identify an actual maintainer.
- Publish artifacts and checksums through a tested GitHub Release workflow after the acceptance checks pass. Do not treat building a tarball locally as proof that a package is installable.

**Acceptance criteria**
- A clean install from each maintained package route can show help, locate its analysis files, and run the documented smoke test.
- Checksums are computed and verified, all URLs point to the real repository/releases, and versions match across outputs.
- Release CI produces an installable archive and a machine-readable test summary.

### 1.11 Make docs mirror behavior, not intentions

**Relevant files:** `README.md`, `PROJECT_PLAN.md`, `docs/PROCESSOR_PROFILES.md`, `docs/SOAR_INTEGRATION.md`, `ghidra-report.1`.

Currentness assessment at the audit point:

| Document | Status | Required correction |
|---|---|---|
| `README.md` | **Partially stale** | Its Ghidra 12.x requirement conflicts with the Ghidra 11.1.2 Docker image; FTS5/history and fresh-clone test claims do not match the current indexer/CI; custom config options listed in prose are not all loaded by the CLI; several loader and auto-processor claims need verified support-matrix entries. |
| `PROJECT_PLAN.md` | **Overstates completion** | The introduction says “feature-complete” and “no open backlog,” but the dashboard, CI, data indexing, loader selection, and test requirements below are not yet verified/correct. Retain it as development history or clearly separate completed implementation work from validated/release-ready behavior; link to this roadmap. |
| `docs/PROCESSOR_PROFILES.md` | **Partially stale** | It hard-codes a Ghidra Flatpak extension directory, and its processor mapping example differs from the CLI mapping. The CLI logs detected ELF architecture but does not pass it as the processor selection. Make extension availability and detection-vs-selection explicit. |
| `docs/SOAR_INTEGRATION.md` | **Payload example is stale** | The documented webhook example includes `risk_score`, `risk_level`, `sha256`, and `high_priority_findings`; the current CLI sends `text`, `binary`, `score`, and `level`. Verify integration endpoints and use a captured/tested payload before describing end-to-end ingestion as supported. |
| `ghidra-report.1` | **Needs alignment** | Reconcile flags, supported behavior, release version, and maintainer metadata with tested CLI/package behavior. |
| `Dockerfile` and package formulas | **Inconsistent** | The Docker Ghidra build, documented requirement, install paths, repository URLs, and checksum placeholders do not form one verified release story. |

- Keep a single concise support matrix with columns for detection, loader availability, analysis-tested status, and optional dependencies.
- Document exactly which tests run by default, which require Ghidra, and which require community extensions.
- Document dashboard security/bind address, the static-analysis threat model, sample-handling limits, and whether a feature is experimental.
- Add copy-pasteable docs smoke tests for the advertised quickstart, Docker run, CLI options, config, SOAR webhook, and packaging routes.

**Acceptance criteria**
- Every command example is exercised by CI or clearly labeled illustrative.
- Every format, extension, architecture, config property, and integration is labeled implemented/tested/experimental/not supported.
- A documentation consistency check detects Ghidra/version/CLI flags and artifact-name drift.

---

## P2 — Capability expansion after foundations are fixed

### 2.1 Better analyst workflow

- Add a stable machine-readable finding catalog (JSON and optional JSONL), including finding ID, rule version, severity, confidence, evidence, address, and false-positive context.
- Improve semantic diffing to compare the same sample across versions and compare different samples without implying that unmatched file names alone imply code change. Use hashes, section identity, architecture, and per-finding fingerprints.
- Add baseline/allowlist management with reviewable, versioned suppressions (for example signed or hash-scoped suppressions), not global silent suppression.
- Add explainable triage summaries with “why this scored,” coverage/limitations, and next analyst steps. Keep any automated containment actions outside the core analyzer until false-positive rates are measured.

### 2.2 More useful integrations

- Provide documented adapters for capa rules/results, FLOSS string outputs, Binwalk/unblob carve metadata, and supported sandbox traces. Make optional tooling explicit and record its version in every report.
- Add import/export contracts and integration tests for MISP and generic webhooks; use minimal least-privilege credentials and never log secrets.
- Let CI consumers upload SARIF when analysis yields findings and a suitable source/artifact mapping exists. Binary offsets must be represented honestly; do not make an artifact look like a source-code line finding when it is not.

### 2.3 Performance and operator ergonomics

- Add progress reporting, a machine-readable exit status, per-file logs, cancellation, and resource-budget summaries.
- Add configurable report/database retention and clean-up commands that never delete source samples without explicit user intent.
- Add benchmark fixtures for large PE/ELF images, packed inputs, and firmware images; track wall time and peak memory to catch regressions.
- Consider a job queue or service mode only when the local CLI, database, and dashboard are secure and race-free.

---

## Suggested implementation sequence

1. **Security gate:** dashboard path containment, loopback default, DOM-safe rendering, regression tests.
2. **Build/run gate:** one supported Ghidra version, portable launcher, Docker smoke test, explicit dependency checks.
3. **CI gate:** split fast and Ghidra-backed tests; run real tests; make failures and SARIF upload behavior honest.
4. **Data correctness:** JSON contract/schema, escaped serialization, indexing field alignment, true historical run model and search.
5. **Analysis correctness:** processor selection, capability rule scope/dependencies, trace normalization, bounded recursive carving, explainable scores.
6. **Evidence quality:** real fixtures, corpus benchmarks, schema validation, YARA tests, and explicit false-positive/coverage reporting.
7. **Release and docs gate:** packaging fixes, versions/checksums, tested install routes, support matrix, update README/PROJECT_PLAN/docs/man page.
8. **Feature expansion:** optional upstream integrations and analyst workflow improvements guided by measured gaps.

## Definition of “ready to call it feature-complete”

Before removing the backlog or describing the project as production-ready, require all of the following:

- [ ] Dashboard is safe by default and has regression tests for path traversal and stored XSS.
- [ ] A clean documented install can run headless Ghidra without relying on a specific user's Flatpak directory.
- [ ] CI runs actual tests, fails on failures, and generates/validates every promised artifact.
- [ ] Report schemas, SARIF, MISP, and YARA outputs are validated using independent parsers or validators.
- [ ] History preserves separate analysis runs, indexes all documented fields, and implements the advertised search semantics.
- [ ] Architecture/loader claims are backed by tests that verify the processor actually selected by Ghidra.
- [ ] Rules, string recovery, trace correlation, and firmware-carving claims have positive/negative fixtures and documented limits.
- [ ] Release artifacts are checksummed and install-tested; version and repository metadata is consistent.
- [ ] README, PROJECT_PLAN, processor docs, SOAR docs, and man page have no known contradictions with implementation.

## Comparable projects and research references

The goal is to borrow proven ideas and validation practices, not copy full projects or expand scope indiscriminately.

| Project/reference | Relevant strengths | Recommended takeaway for ghidra-report |
|---|---|---|
| [Ghidra headless analyzer documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md) and [upstream releases](https://github.com/NationalSecurityAgency/ghidra/releases) | Supported headless project/import/script execution and versioned releases | Use the supported launcher, pin/test versions, and explicitly separate Ghidra core support from community-loader support. |
| [Mandiant capa](https://github.com/mandiant/capa) and [capa documentation](https://mandiant.github.io/capa/) | Rule-based capability detection with structured features, scope, and ATT&CK/MBC annotations | Integrate or deliberately interoperate with a mature rule system, or specify the limits of the smaller rule DSL. Test rule metadata and evidence, not just the happy-path match. |
| [Mandiant FLOSS](https://github.com/mandiant/flare-floss) and [usage guide](https://github.com/mandiant/flare-floss/blob/master/doc/usage.md) | Static, stack, tight, and decoded string extraction workflows | Use it as a benchmark or optional backend for obfuscated-string recovery; compare output and false positives on the same corpus. |
| [Binwalk v3](https://github.com/ReFirmLabs/binwalk) | Firmware signature identification, entropy analysis, embedded-file detection and extraction; the current rewrite emphasizes speed and accuracy | Benchmark carving against it and add recursion, offset-accurate extraction, corruption handling, and resource budgets. |
| [unblob](https://unblob.org/) and [source repository](https://github.com/onekey-sec/unblob) | Modular extraction, recursive parsing, format-specific handlers, handling of unknown regions | Prefer mature format extractors or adapters to an under-tested collection of custom parsers; fuzz and resource-limit every parser. |
| [GitHub SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file) and [SARIF support reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) | Requires valid SARIF and correct workflow permissions/categories; supports third-party analysis results | Validate the output against SARIF 2.1.0, set least-privilege workflow permissions, upload only real results, and provide stable result fingerprints and truthful locations. |
| [YARA rule-writing documentation](https://yara.readthedocs.io/en/stable/writingrules.html) | Defined rule syntax and conditions with a proper compiler/runtime | Compile generated rules in tests, escape all input values, and measure rule usefulness rather than equating “generated” with “high-quality.” |

## Review notes and limitations

- This document reflects static inspection of the current `main` branch and external project documentation accessed on 2026-10-27. It is not a penetration test, malware-lab assessment, or verified runtime test report.
- Direct `git clone` failed in the review environment because GitHub DNS resolution was unavailable. Repository files were inspected through the connected GitHub integration instead.
- No local Ghidra install or full test run was available in this environment. Findings that depend on runtime behavior should be confirmed by CI and the acceptance tests above.
- Prioritize fixes by the stated acceptance criteria. Do not mark a roadmap item complete solely because a command, class, or documentation section exists.
