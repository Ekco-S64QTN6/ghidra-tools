# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- Add mmap-backed firmware scanning and bounded recursive GZIP extraction with configurable depth, file-count, file-size, aggregate-size, expansion-ratio, and wall-time limits; retain source/parent provenance and stream output through temporary files.
- Add an opt-in Caddy HTTPS reverse-proxy profile for Docker Compose, with automatic certificate management, unchanged Basic-auth forwarding, defensive forwarding-header handling, and a live TLS integration test.
- Require a 32-byte environment token and HTTP Basic authentication for non-loopback dashboard binds; protect the UI, APIs, and report artifacts while keeping loopback use simple.
- Recover stack strings only from contiguous immediate P-code stores to verified stack-frame write references; expose method and offset provenance in JSON, with a real-Ghidra positive fixture plus register-immediate, register-derived, and non-contiguous stack-store false-positive controls.
- Define the capability-rule DSL as strict schema version 1.0.0; assign stable IDs, rationale, and HTTPS ATT&CK references to every shipped rule, and add positive/negative fixtures for all 11 rules.
- Add function-scoped process-injection detection backed by per-function suspicious API call sites; preserve caller and call-site addresses in an additive `function_api_evidence` JSON field and prevent cross-function evidence aggregation. Instruction/block scopes remain rejected.
- Add shell-level synthetic ELF dispatch tests that assert the exact processor ID passed to Ghidra for supported architecture mappings and no forced processor for unsupported/malformed inputs; include the ARM BE8 mapping.
- Add a shared Ghidra language-definition probe and test SNES raw-analysis fallback only when the optional 65816 language is installed; keep SNES header detection active in the base image.
- Run the broader synthetic Ghidra-backed integration suite in the pinned Ghidra 12.2/JDK 25 CI container, and use structurally valid synthetic GBA/N64/PSX headers in file-detection regressions.

- Add a real Ghidra 12.2 ELF import matrix with synthetic executables that validate the opened language ID in generated JSON reports.
- Preserve detector evidence, recommended and explicitly requested processor IDs, requested loaders, import strategy, and ELF flags in an additive optional JSON `detection` object; assert the provenance against real PE/ELF reports.

### Fixed
- Validate SquashFS v3/v4 superblock endianness, block geometry, version, root metadata offset, and declared filesystem bounds; validate CRAMFS v2 superblock size, flags, signature policy, root inode type, and root-data bounds.
- Validate JFFS2 INODE/DIRENT header and node CRCs plus compressed-data/name CRCs using Linux crc32_le(seed=0); reject malformed node lengths and corrupted records.
- Reject legacy U-Boot uImages with invalid header or payload CRC-32 values; compute payload checksums in bounded chunks before carving.
- Reject corrupt/truncated GZIP members and remove partial decompression outputs; correct firmware-carving claims to exclude unimplemented UBI and zlib-stream extraction.
- Document and test the dashboard's real TLS-terminated deployment path; keep the application from trusting client-supplied proxy identity headers.
- Reject unauthenticated remote dashboard binds, classify unknown hostnames conservatively as remote, and disable browser caching of report/dashboard responses.
- Match a Ghidra stack STORE input to its defining output in the same instruction's P-code array (rather than relying on the unpopulated `Varnode.getDef()` link), and accept only one direct `COPY` from a same-sized constant; register-derived stack stores remain rejected.
- Use exact case-insensitive API-name matching in capability rules instead of potentially overbroad substring matching.
- Select Ghidra's mixed-endian ARM language for ELF32 big-endian files carrying `EF_ARM_BE8`, rather than forcing the pure big-endian instruction language.
- Update FindCrypt's cancellation polling to Ghidra 12.2's `TaskMonitor.checkCancelled()` API so the full Java pipeline compiles against the pinned runtime.
- Attach stdin to the container smoke's heredoc so the PE analysis assertions actually execute; remove the unsupported assumption that vanilla Ghidra 12.2 contains the optional 65816 language.
- Print the last 80 lines of the raw Ghidra fallback log when SNES fallback fails, and assert that bounded diagnostic output is retained in the mocked failure regression.
- Trigger SNES raw fallback when the optional loader exits nonzero even if its diagnostic text changes; test status-based fallback and missing-language diagnostics. Raw SNES execution remains conditional on an installed `65816:LE:24:snes` language definition.
- Add root `VERSION` as the canonical app-version source for the CLI banner, headless child environment, SARIF driver metadata, and release archive naming; add a CI consistency check and align formula repository/JDK metadata without pretending unpublished release checksums are available.
- Keep Homebrew/AUR runtime assets together under private app roots, add package launchers that route writable state to XDG user data, vendor a pinned pure-Python PyYAML copy for Homebrew, and test wrapper argument/data-path behavior.
- Add migration-tracked SQLite FTS5 search for recovered strings, functions/symbols, exports, rules, capabilities, and findings; keep the index synchronized on report re-index, expose snippets in CLI/dashboard search, and add legacy migration/update regression tests.
- Add `schema_version: 1.0.0` and a Draft 7 JSON Schema for primary report output; escape every U+0000–U+001F character and round-trip adversarial strings through a real JSON parser in CI.
- Make the headless launcher honor `GHIDRA_ROOT` and `JAVA_HOME`, use Ghidra's supported launcher for standard installs, and retain the Flatpak direct-JVM workaround with paths derived from the detected installation.
- Pin the container to Ghidra 12.2 with JDK 25, verify the official release SHA-256 before extraction, report detected Ghidra/Java versions, and add an actual core-PE analysis/report integration smoke job.
- Add mocked regression coverage for standard and Flatpak launcher selection and invalid Java configuration.
- Restrict dashboard artifact access to canonical paths under `output/`, sandbox exported HTML, escape sample-derived UI values, apply defensive response headers and response limits, and bind to loopback unless explicitly configured.
- Replace the CI's ignored firmware scan with compile, CLI, launcher, and dashboard security checks; remove the upload-only SARIF job until CI generates and validates a real artifact.
- Keep `--help` and offline CLI utilities available without Ghidra by checking Ghidra prerequisites only when binary analysis starts.
- Reject truncated U-Boot uImage payloads whose declared length exceeds the available input and add synthetic bounds regression tests.
- Normalize top-level array and CAPE-style dynamic traces, preserve event metadata, compare API names case-insensitively, and prevent cross-process attack-chain matches.
- Index current report timestamps, IOCs, and indicator ATT&CK IDs correctly while preserving compatibility with older field names.
- Backfill a migration-tracked FTS5 index from report JSON text fields, synchronize it on re-index, and expose ranked snippets in CLI/dashboard search alongside existing metadata/API/IOC `LIKE` searches.
- Require an actual YAML parser for capability rules, validate supported operators, primitive types, rule metadata, weights and unknown keys at load time, fail visibly on invalid rules, and add rule-loading/operator regression tests.
- Correct README, man-page, and project-plan claims about history search: the current indexer uses SQLite `LIKE`, searches only metadata/APIs/IOCs/indicators, and overwrites a row when the filename repeats.
- Make batch execution report per-item success/failure counts and return nonzero when any sample fails, while continuing the remaining items.
- Validate file headers before format classification, select ELF processors from class/endianness/e_machine, log detection evidence, and include GBA/PSX/N64 ROMs in batch discovery. Use declared RISC-V language IDs and defer MIPS64 selection until ISA/ABI flags can be interpreted safely.
- Use the status-preserving headless log helper for loader imports and SNES fallback, and add regression coverage for nonzero analyzer exit statuses.
- Preserve Ghidra report-export exit statuses through log filtering, clean partial failed-export artifacts without replacing prior latest symlinks, and support HTML-only successful output.
- Serialize import, analysis, report export, and `report_latest.*` updates across concurrent runs of the same output identity with cross-process advisory locks; different identities remain concurrent, with a configurable fail-closed wait timeout and regression tests.
- Write report exports in a private staging directory, discard staged files on exporter failure, and atomically replace each `report_latest.*` symlink only after successful export; document that multiple formats are not published as one transaction.
- Derive Ghidra project names from canonical source path, sample content, and project-affecting settings so same-basename inputs or changed content do not reuse the wrong project.
- Key report-output directories by sanitized filename, canonical path hash, and content hash; migrate history away from unique basenames and retain distinct reports by JSON path, including dashboard search links for each output identity.
