# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Fixed
- Make the headless launcher honor `GHIDRA_ROOT` and `JAVA_HOME`, use Ghidra's supported launcher for standard installs, and retain the Flatpak direct-JVM workaround with paths derived from the detected installation.
- Add mocked regression coverage for standard and Flatpak launcher selection and invalid Java configuration.
- Restrict dashboard artifact access to canonical paths under `output/`, sandbox exported HTML, escape sample-derived UI values, apply defensive response headers and response limits, and bind to loopback unless explicitly configured.
- Replace the CI's ignored firmware scan with compile, CLI, launcher, and dashboard security checks; remove the upload-only SARIF job until CI generates the referenced artifact, and document the full-suite limitation.
- Keep `--help` and offline CLI utilities available without Ghidra by checking Ghidra prerequisites only when binary analysis starts.
- Reject truncated U-Boot uImage payloads whose declared length exceeds the available input and add synthetic bounds regression tests.
- Normalize top-level array and CAPE-style dynamic traces, preserve event metadata, compare API names case-insensitively, and prevent cross-process attack-chain matches.
- Index current report timestamps, IOCs, and indicator ATT&CK IDs correctly while preserving compatibility with older field names.
- Require an actual YAML parser for capability rules, validate supported operators, primitive types, rule metadata, weights and unknown keys at load time, fail visibly on invalid rules, and add rule-loading/operator regression tests.
