# Changelog

## 1.2.0
- **Sidebar tree view** — activity bar icon, findings grouped by severity. Click any finding to open the file. Header buttons for scan and refresh.
- **Status bar item** — live summary of findings: green when clean, red when HIGH findings exist, amber for warnings. Click to re-scan.
- **PyPI ecosystem support** — OSV check now covers both npm and PyPI. Parses `requirements.txt`, `Pipfile.lock`, and `poetry.lock`. Scans Python manifests for IOC patterns, custom pip indexes, and build-system risks.
- Hook detection aligned with miasma-audit.js: `Notification` now treated as a sensitive event (HIGH); non-dangerous hooks flagged as WARN instead of being silently dropped. Empty hook arrays are no longer flagged.
- Skip the extension being developed from self-integrity checks (no more false tamper alert when editing Thumper's own source under F5).
- Hardening check re-runs automatically after `hardenWorkspace()` succeeds, clearing the stale finding from the tree.
- Proper extension icon (Dune thumper device silhouette) for the activity bar.

## 1.1.0
- Detection patterns extracted to patterns.js (single shared module). The extension no longer bundles the miasma-audit script; it ships separately as a dated forensic tool.
- OSV.dev integration: lockfile dependencies are batch-checked against Google's OSV malicious-package database (no API key, cached 24h). MAL-* malware advisories alert; ordinary CVEs are logged only. This is the evergreen detector that replaces hand-maintained denylists.
- Bundled miasma-audit.js relabeled as a dated June-2026-campaign artifact.

## 1.0.0
Initial public release.
- Config integrity baselines (Claude Code settings, .vscode/tasks.json + settings.json + launch.json, .npmrc, package.json) — alerts on any unexpected change.
- Installed-extension integrity: hash baseline of every extension's entry files; changed code WITHOUT a version bump = tamper alert (the Nx Console attack shape). Re-checks every 10 minutes and on extension-set changes.
- npm registry / .npmrc tamper detection (hijacked registry=, removed ignore-scripts floor).
- Dependency cooldown: flags lockfile-resolved versions published within the last N days (default 7).
- Dangerous install-script detection in package.json (fetch-and-execute, credential paths).
- Terminal hygiene nudges toward `npm ci --ignore-scripts`; one-click .npmrc hardening.
- Bundled read-only Miasma/Shai-Hulud audit script for full-system scans (also runs standalone).
