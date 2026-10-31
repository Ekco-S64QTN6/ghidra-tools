# CLAUDE.md

Repository-specific guidance for contributors and coding agents.

## Runtime and compatibility

- `VERSION` is the canonical app release version for the CLI banner, SARIF driver metadata, and local release archive naming. `tests/test_version_consistency.py` guards duplicate version references in docs, formulas, and CI.
- Package formulas should keep `ghidra-report.sh`, `run-headless.sh`, `VERSION`, `scripts/`, `rules/`, and `schemas/` together under a private app root. Their generated wrapper must route writable ingress/projects/reports/history to `GHIDRA_REPORT_DATA_DIR` (defaulting to XDG user storage); never write generated data into the read-only application tree.
- Homebrew/AUR definitions are not release-ready while their SHA-256 fields say `SKIP`; never invent a digest. Only replace those placeholders after a real tag/release asset exists and the clean package install path has been tested.

- The dashboard binds to loopback without authentication. Any non-loopback bind must fail closed unless `GHIDRA_DASHBOARD_TOKEN` is set to at least 32 UTF-8 bytes; credentials use HTTP Basic auth and remote traffic must be protected by TLS. The optional Compose `https` profile uses `deploy/caddy/Caddyfile`; preserve `Authorization`, do not configure broad `trusted_proxies`, and keep forwarded identity headers out of dashboard authorization/routing decisions. `python3 tests/test_dashboard_proxy.py` exercises the real Caddy TLS/auth path and requires Docker. Never pass dashboard tokens on the command line.
- Firmware carving uses a read-only mmap for scanning, chunked artifact copies, and streamed GZIP decompression. Require valid U-Boot legacy header and payload CRC-32 values before carving a uImage; the 64-byte header checksum is computed with its own field zeroed, and the payload checksum covers exactly the declared data. Keep the `GHIDRA_CARVE_*` depth/file/per-file/aggregate/ratio/time budgets fail-closed; validate JFFS2 INODE and DIRENT common-header, raw-node, and compressed-data/name CRCs before carving; do not report unverified XATTR/XREF/SUMMARY nodes as supported. Preserve `.part` cleanup/atomic publication and do not imply UBI, zlib streams, or recursive SquashFS/CRAMFS extraction. `tests/test_firmware_carver.py` is part of the fast CI lane; its uImage and JFFS2 fixtures must generate valid CRCs.
- The default container target is **Ghidra 12.2 + JDK 25**. Ghidra 12.2 requires at least JDK 25. The Docker build must verify the official release archive SHA-256 before extraction; do not update the version/date without refreshing the checksum from the upstream release and getting the container CI smoke test to pass.
- `run-headless.sh` honors `GHIDRA_ROOT` and `JAVA_HOME`, uses `support/analyzeHeadless` for standard installs, and retains a derived-JDK workaround for Flatpak. Its Ghidra-root/version and Java-runtime messages are diagnostic; they do not certify compatibility of every Ghidra/Java pair.
- Community console/firmware loaders and the 65816 language definition are not bundled in the base Docker image. Claims about extension-backed behavior need an extension-equipped integration test. Default CI runs PE analysis and SNES header detection; SNES raw-analysis checks are skipped unless `65816:LE:24:snes` is installed.

## Test lanes

- The fast no-Ghidra lane in `.github/workflows/binary-analysis.yml` runs Python/CLI/helper/security regressions.
- The Ghidra-container job builds the pinned image, executes a real synthetic PE analysis with Ghidra, checks all seven non-empty report formats, validates the primary JSON report against `schemas/report-v1.schema.json`, and checks SARIF 2.1.0/MISP structure. It then runs `tests/run_tests.sh` in the same pinned Ghidra 12.2/JDK 25 image. SNES detection is covered, but raw 65816 analysis and dependent semantic diff are skipped unless the optional language ID is installed. SARIF/MISP checks are envelope checks, not full official schema validation.
- `tests/run_tests.sh` generates its own fixtures and runs the broader Ghidra-backed integration checks. It checks SNES header detection even without 65816, and skips only the 65816-dependent Ghidra analysis/diff when that language ID is absent. Optional community-extension inventory is separately skipped when fewer than seven extensions are present.
- Do not claim a test group passed unless the relevant command or GitHub job actually ran successfully. A fast no-Ghidra pass is not a replacement for container/runtime verification.

## Output identity, concurrency, and publication

- The primary JSON report uses `schema_version: "1.0.0"` and is described by `schemas/report-v1.schema.json`. When changing serialized fields, update the schema and fixtures, test control characters through the production `ReportFormat.escapeJson()` helper, and validate real PE/SNES container reports against the schema. Do not claim official SARIF/MISP schema validation when CI only checks their structural envelopes.
- `scripts/project_identity.py` provides stable project and report-output identities. Project identity includes project-affecting settings; report-output identity intentionally excludes those settings. Use the same output key for all paths that address a report identity.
- `process_binary()` locks a report identity before touching its Ghidra project and holds the lock through analysis, export, and latest-link updates. The OS advisory lock is implemented in `scripts/output_lock.py` and `scripts/output_lock.sh`. **Do not unlink or routinely clean files in `output/.locks/`**: a waiter could hold the old inode while a later process locks a newly created inode.
- Reports are generated in a private `.stage.*` directory. Failed exports should not replace a previous `report_latest.*` target; abandoned staging directories are cleaned by the next run for that identity.
- `scripts/atomic_publish.py` replaces each latest symlink atomically, one format at a time. The set of links for multiple formats is **not** a single transaction; document this limitation rather than implying all formats switch together.
- The SQLite index treats canonical JSON report paths as idempotent identities, preserving same-basename runs. Search combines `LIKE` over metadata/APIs/IOCs/indicators with migration-tracked external-content FTS5 over selected text fields (recovered strings, functions/symbols, exports, rules/capabilities/findings). Re-indexing a JSON path refreshes FTS text via triggers. Old rows can be schema-migrated but need their source JSON re-indexed to populate text that was never stored in SQLite.

## Documentation and review discipline

- Keep `README.md`, `ROADMAP.md`, `PROJECT_PLAN.md`, `CHANGELOG.md`, `ghidra-report.1`, and relevant `docs/` pages aligned with implementation and actual test evidence.
- Prefer synthetic, redistributable fixtures. Never require local samples from `ingress/` in tests.
- Before merging a PR, inspect its diff and obtain a green GitHub Actions result for the exact PR head SHA. Re-check the head SHA before merge, and do not merge a failed, pending, or stale check run.
