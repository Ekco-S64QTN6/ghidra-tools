# CLAUDE.md

Repository-specific guidance for contributors and coding agents.

## Runtime and compatibility

- `VERSION` is the canonical app release version for the CLI banner, SARIF driver metadata, and local release archive naming. `tests/test_version_consistency.py` guards duplicate version references in docs, formulas, and CI.
- Package formulas should keep `ghidra-report.sh`, `run-headless.sh`, `VERSION`, `scripts/`, `rules/`, and `schemas/` together under a private app root. Their generated wrapper must route writable ingress/projects/reports/history to `GHIDRA_REPORT_DATA_DIR` (defaulting to XDG user storage); never write generated data into the read-only application tree.
- Homebrew/AUR definitions are not release-ready while their SHA-256 fields say `SKIP`; never invent a digest. Only replace those placeholders after a real tag/release asset exists and the clean package install path has been tested.

- The default container target is **Ghidra 12.2 + JDK 25**. Ghidra 12.2 requires at least JDK 25. The Docker build must verify the official release archive SHA-256 before extraction; do not update the version/date without refreshing the checksum from the upstream release and getting the container CI smoke test to pass.
- `run-headless.sh` honors `GHIDRA_ROOT` and `JAVA_HOME`, uses `support/analyzeHeadless` for standard installs, and retains a derived-JDK workaround for Flatpak. Its Ghidra-root/version and Java-runtime messages are diagnostic; they do not certify compatibility of every Ghidra/Java pair.
- Community console/firmware loaders are not bundled in the base Docker image. Claims about extension-backed loader behavior need an extension-equipped integration test. The container test covers PE analysis plus a synthetic SNES ROM through the raw 65816 fallback; this does not validate optional community loader extensions or all retail ROM variants.

## Test lanes

- The fast no-Ghidra lane in `.github/workflows/binary-analysis.yml` runs Python/CLI/helper/security regressions.
- The Ghidra-container job builds the pinned image, analyzes generated synthetic PE and SNES fixtures with real Ghidra, checks all seven non-empty report formats, validates both primary JSON reports against `schemas/report-v1.schema.json`, and checks SARIF 2.1.0/MISP structure. Those last two are envelope checks, not full official schema validation.
- `tests/run_tests.sh` is a broader suite for a configured Ghidra installation. It reports optional community-extension inventory as skipped when fewer than seven extensions are present; that skip is not evidence of extension-backed loader correctness.
- Do not claim a test group passed unless the relevant command or GitHub job actually ran successfully. A fast no-Ghidra pass is not a replacement for container/runtime verification.

## Output identity, concurrency, and publication

- The primary JSON report uses `schema_version: "1.0.0"` and is described by `schemas/report-v1.schema.json`. When changing serialized fields, update the schema and fixtures, test control characters through the production `ReportFormat.escapeJson()` helper, and validate real PE/SNES container reports against the schema. Do not claim official SARIF/MISP schema validation when CI only checks their structural envelopes.
- `scripts/project_identity.py` provides stable project and report-output identities. Project identity includes project-affecting settings; report-output identity intentionally excludes those settings. Use the same output key for all paths that address a report identity.
- `process_binary()` locks a report identity before touching its Ghidra project and holds the lock through analysis, export, and latest-link updates. The OS advisory lock is implemented in `scripts/output_lock.py` and `scripts/output_lock.sh`. **Do not unlink or routinely clean files in `output/.locks/`**: a waiter could hold the old inode while a later process locks a newly created inode.
- Reports are generated in a private `.stage.*` directory. Failed exports should not replace a previous `report_latest.*` target; abandoned staging directories are cleaned by the next run for that identity.
- `scripts/atomic_publish.py` replaces each latest symlink atomically, one format at a time. The set of links for multiple formats is **not** a single transaction; document this limitation rather than implying all formats switch together.
- The SQLite index treats canonical JSON report paths as idempotent identities, preserving same-basename runs. Search is currently SQLite `LIKE` over selected metadata rather than FTS5, and extracted strings/symbols are not fully indexed.

## Documentation and review discipline

- Keep `README.md`, `ROADMAP.md`, `PROJECT_PLAN.md`, `CHANGELOG.md`, `ghidra-report.1`, and relevant `docs/` pages aligned with implementation and actual test evidence.
- Prefer synthetic, redistributable fixtures. Never require local samples from `ingress/` in tests.
- Before merging a PR, inspect its diff and obtain a green GitHub Actions result for the exact PR head SHA. Re-check the head SHA before merge, and do not merge a failed, pending, or stale check run.
