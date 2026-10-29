# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Fixed
- Make the headless launcher honor `GHIDRA_ROOT` and `JAVA_HOME`, use Ghidra's supported launcher for standard installs, and retain the Flatpak direct-JVM workaround with paths derived from the detected installation.
- Pin the container to Ghidra 12.2 with JDK 25, verify the official release SHA-256 before extraction, report detected Ghidra/Java versions, and add an actual core-PE analysis/report integration smoke job.
- Add mocked regression coverage for standard and Flatpak launcher selection and invalid Java configuration.
- Restrict dashboard artifact access to canonical paths under `output/`, sandbox exported HTML, escape sample-derived UI values, apply defensive response headers and response limits, and bind to loopback unless explicitly configured.
- Replace the CI's ignored firmware scan with compile, CLI, launcher, and dashboard security checks; remove the upload-only SARIF job until CI generates the referenced artifact, and document the full-suite limitation.
- Keep `--help` and offline CLI utilities available without Ghidra by checking Ghidra prerequisites only when binary analysis starts.
- Reject truncated U-Boot uImage payloads whose declared length exceeds the available input and add synthetic bounds regression tests.
- Normalize top-level array and CAPE-style dynamic traces, preserve event metadata, compare API names case-insensitively, and prevent cross-process attack-chain matches.
- Index current report timestamps, IOCs, and indicator ATT&CK IDs correctly while preserving compatibility with older field names.
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
