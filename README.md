<p align="center"><img src="resources/thumper.png" width="256" alt="Thumper the Dune-inspired supply-chain watchdog"></p>

# Thumper

**Brings the worm to the surface.**

In Dune, a thumper draws Shai-Hulud out of the sand. The npm worm that named
itself after that sandworm hides in the places your editor trusts most: your
config files, your dependencies, your installed extensions. Thumper watches
exactly those places and forces anything that moves into the open.

Local, zero dependencies, no account, no telemetry. Read the source before you
trust it.

## What it watches

**Known-malicious packages, via OSV.dev.** Resolved versions from your lockfiles
(`package-lock.json`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`) are
batch-checked against Google's OSV database for both **npm** and **PyPI**
ecosystems. OSV aggregates the OSSF malicious-packages feed (the `MAL-`
advisories covering Shai-Hulud, Miasma, PhantomRaven, and whatever comes next).
This is the evergreen detector: the denylist maintenance is OSV's job, not a
hand-edited list that goes stale. Malicious hits alert loudly; ordinary CVE
advisories are logged quietly to the output channel (Thumper is a malware
watchdog, not a CVE auditor). One batched POST to `api.osv.dev`, no API key,
results cached 24h.

**Config integrity baselines.** On first run Thumper records a SHA-256 of every
config file an attacker abuses for execution: Claude Code settings (global and
per-project), `.vscode/tasks.json` / `settings.json` / `launch.json`, `.npmrc`,
`package.json`. After that, *any* unexpected change is flagged, whether or not
the content looks malicious "a file I execute changed and I didn't change it"
is the real signal, and it needs no knowledge of the malware. Accept legitimate
edits with **Thumper: Accept current configs as baseline**.

**Installed-extension integrity (the Nx Console lesson).** The Nx Console
compromise shipped a credential stealer as a marketplace auto-update: ~2.7KB
injected into the extension's minified `main.js`, live for 11 minutes, and it
specifically harvested Claude Code configs. The one local signal that existed:
the extension's entry file changed. Thumper baselines every installed extension
as `{version, hash(entry files)}` and re-checks on startup, every 10 minutes
(auto-updates land mid-session), and whenever the extension set changes.
The distinction that keeps it useful instead of noisy:
- files changed **+ version bumped** → normal update: noted once, re-baselined.
- files changed **+ version UNCHANGED** → tamper: HIGH modal, baseline kept so
 the alert repeats until you investigate.
Thumper deliberately does not pattern-scan extension code minified legit
bundles match everything the integrity diff is the honest signal.

**Registry / `.npmrc` tampering.** Flags a `registry=` line pointing anywhere
that isn't a known-good host (the silent-mirror redirect move) and flags
`ignore-scripts=false` (someone removing your safety floor).

**Dependency cooldown.** Flags lockfile-resolved versions published within the
last N days (default 7, via the npm registry). Brand-new versions are the
highest-risk window for supply-chain poisoning; a few days' quarantine is when
poisoned versions get caught and yanked.

**Dangerous install scripts & Python manifests.** Any `preinstall`/`install`/
`postinstall` script in a `package.json` matching fetch-and-execute or
credential-touching patterns. Also scans `requirements.txt`, `pyproject.toml`,
`Pipfile`, `setup.py`, and `setup.cfg` for the same IOC patterns `pip install`
with custom indexes, `setup.py` network calls, and build-system configuration
that runs code at install time.

**Terminal hygiene + hardening.** Best-effort warnings when a risky
`npm install` runs (suggesting `npm ci --ignore-scripts`), a hardening check on
open, and a one-click `.npmrc` floor (`ignore-scripts=true`).

## What it cannot do (read this)

- It cannot block a terminal command or stop an install-time payload
 (`preinstall` / `binding.gyp` / `pip install` / `setup.py`) those run
 before the editor is involved. Prevention lives in `.npmrc`, lockfiles, and
 CI gates; Thumper is the watchdog for what gets past them and what gets left
 behind.
- Extension tampering is detected *after* it lands, not blocked.
- A clean result means no known indicators and no unexpected changes strong
 evidence, not a guarantee.
- If something flags: **clean the persistence first, isolate, then rotate
 credentials from a different machine.** Never revoke before cleaning.

## Commands

| Command | What it does |
| --- | --- |
| **Thumper: Scan workspace now** | Full sweep: IOC scan + config integrity + extension integrity + OSV check. |
| **Thumper: Check dependencies against OSV** | Batch-check lockfile deps against the OSV malware database. |
| **Thumper: Check dependency ages** | Flag lockfile-resolved versions newer than the cooldown window. |
| **Thumper: Harden this workspace** | Write `ignore-scripts=true` to the workspace `.npmrc`. |
| **Thumper: Accept current configs as baseline** | Record the current state of protected config files as known-good. |

The sidebar tree view header also has **Scan** (▶) and **Refresh** (↻) buttons.

Detection patterns live in `patterns.js`, the single shared module.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `thumper.osvCheck` | `true` | Batch-check npm + PyPI lockfile deps against OSV on open. |
| `thumper.configIntegrity` | `true` | Baseline + diff protected config files. |
| `thumper.extensionIntegrity` | `true` | Baseline + diff installed extensions. |
| `thumper.extensionRecheckMinutes` | `10` | Periodic extension re-check (0 disables). |
| `thumper.minDependencyAgeDays` | `7` | Cooldown window (0 disables). |
| `thumper.maxAgeChecks` | `40` | Cap on registry age lookups per run. |
| `thumper.ageCheckOnStartup` | `false` | Run the age check automatically on open. |
| `thumper.scanOnStartup` / `watchTerminal` / `checkHardening` | `true` | v0.x behaviors. |
| `thumper.suspectScopes` / `suspectPackages` | `[]` | Extra IOCs on top of the bundled baseline. |

## Install

### From a pre-built `.vsix` (recommended)

Download `thumper-*.vsix` from the [latest GitHub release](https://github.com/hijaz/thumper/releases), then:

```bash
code --install-extension thumper-*.vsix
```

Or in VS Code: `Ctrl+Shift+P` → **Extensions: Install from VSIX…** → pick the file.

### From source (no build step)

```bash
git clone https://github.com/hijaz/thumper.git
cd thumper
# Open this directory in VS Code, press F5
code .
```

Press **F5** a second VS Code window opens with Thumper loaded. Open a real
project there to test it.

### Build the `.vsix` yourself

```bash
npm install -g @vscode/vsce
vsce package
# produces thumper-*.vsix
```

## Network access, in full

Thumper makes exactly two kinds of outbound requests, both read-only, both
optional via settings: `api.osv.dev` (batch malware lookup) and
`registry.npmjs.org` (publish dates for the cooldown check). Nothing else. No
telemetry, no remote config, no auto-updating rules a security tool that
pulls live behavior from the internet is the exact pattern Thumper exists to
flag.
