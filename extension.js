// Thumper v0.3 — generic supply-chain watchdog for VS Code
//
// v0.1/0.2 were Miasma/Shai-Hulud specific. v0.3 generalizes to the MECHANISMS
// every future supply-chain wave reuses, so it keeps protecting after the
// current campaign's package names are stale:
//
//   A) CONFIG INTEGRITY BASELINES  — snapshot a hash of each protected config
//      file and alert on ANY unexpected change, regardless of payload shape.
//      This is the future-proof core: it does not need to know the malware.
//   B) REGISTRY / .npmrc TAMPER     — detect a hijacked `registry=` line or a
//      silently-removed `ignore-scripts=true` floor.
//   C) DEPENDENCY AGE (COOLDOWN)    — flag lockfile-resolved versions published
//      within the last N days (worm waves push brand-new versions; a few days'
//      quarantine is when poisoned versions get caught and yanked).
//   D) KNOWN-IOC SCAN + HYGIENE     — the v0.1/0.2 behavior, still here.
//
// Everything is detection/alerting. The only writes are: the .npmrc harden
// action and the integrity baseline file, both under your control.
//
// HONEST LIMITS (unchanged): cannot block a terminal command or stop an
// install-time payload; those are prevented by .npmrc + CI, not the editor.

const vscode = require('vscode');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const https = require('https');
const crypto = require('crypto');
const ioc = require('./patterns.js'); // single source of truth for IOC patterns

let output;
let ctx; // extension context, for storage
function log(m) { if (!output) output = vscode.window.createOutputChannel('Thumper'); output.appendLine(`[${new Date().toLocaleTimeString()}] ${m}`); }

// ---- unified findings store (feeds sidebar tree + status bar) ------------
let scanFindings = [];
let findingsProvider;
let statusBarItem;

function replaceFindings(source, findings) {
  scanFindings = scanFindings.filter(f => f.source !== source);
  scanFindings.push(...findings.map(f => ({ severity: f.severity, message: f.message, file: f.file || null, detail: f.detail || null, source, time: Date.now() })));
  updateStatusBar();
  if (findingsProvider) findingsProvider.refresh();
}

function updateStatusBar() {
  if (!statusBarItem) return;
  const high = scanFindings.filter(f => f.severity === 'high').length;
  const warn = scanFindings.filter(f => f.severity === 'warn').length;
  const total = high + warn;
  if (total === 0) {
    statusBarItem.text = '$(shield) Thumper';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = 'Thumper: no findings. Click to scan.';
  } else if (high > 0) {
    statusBarItem.text = `$(error) Thumper: ${high} HIGH`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    statusBarItem.tooltip = `HIGH: ${high}\nWarnings: ${warn}\nInfo: ${scanFindings.filter(f => f.severity === 'info').length}\nClick to re-scan`;
  } else {
    statusBarItem.text = `$(warning) Thumper: ${warn} issue${warn > 1 ? 's' : ''}`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.tooltip = `Warnings: ${warn}\nInfo: ${scanFindings.filter(f => f.severity === 'info').length}\nClick to re-scan`;
  }
  statusBarItem.show();
}

// ---- tree data provider for sidebar -------------------------------------
class FindingsProvider {
  constructor() {
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
  }
  refresh() { this._onDidChangeTreeData.fire(); }
  getTreeItem(element) {
    if (element.type === 'group') {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.Expanded);
      item.iconPath = new vscode.ThemeIcon(element.severity === 'high' ? 'error' : element.severity === 'warn' ? 'warning' : element.severity === 'remediation' ? 'lightbulb' : 'info');
      return item;
    }
    if (element.type === 'step') {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(element.icon || 'wrench');
      item.command = { command: element.command, title: element.label };
      item.tooltip = element.tooltip || '';
      return item;
    }
    const label = element.message.length > 100 ? element.message.slice(0, 97) + '...' : element.message;
    const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
    item.description = element.file ? path.basename(element.file) : '';
    item.tooltip = `${element.message}\n\nFile: ${element.file || 'n/a'}\n${element.detail ? 'Detail: ' + element.detail : ''}`;
    item.iconPath = new vscode.ThemeIcon(element.severity === 'high' ? 'error' : element.severity === 'warn' ? 'warning' : 'info');
    if (element.file) {
      try {
        item.resourceUri = vscode.Uri.file(element.file);
        item.command = { command: 'vscode.open', title: 'Open File', arguments: [vscode.Uri.file(element.file)] };
      } catch (_) { /* invalid path, skip */ }
    }
    return item;
  }
  getChildren(element) {
    if (!element) {
      const groups = [];
      for (const sev of ['high', 'warn', 'info']) {
        const count = scanFindings.filter(f => f.severity === sev).length;
        if (count > 0) groups.push({ type: 'group', severity: sev, label: sev === 'high' ? `HIGH (${count})` : sev === 'warn' ? `Warnings (${count})` : `Info (${count})` });
      }
      const steps = buildRemediationSteps();
      if (steps.length) groups.push({ type: 'group', severity: 'remediation', label: `Remediation (${steps.length})` });
      if (groups.length === 0) return [new vscode.TreeItem('No findings — run a scan', vscode.TreeItemCollapsibleState.None)];
      return groups;
    }
    if (element.type === 'group') {
      if (element.severity === 'remediation') return buildRemediationSteps();
      return scanFindings.filter(f => f.severity === element.severity).sort((a, b) => b.time - a.time);
    }
    return [];
  }
}

// Derives a list of clickable remediation steps from current findings.
// Each step maps to a command that either fixes the issue automatically or
// opens the output channel for manual investigation.
function buildRemediationSteps() {
  const steps = [];
  const hasSource = (src) => scanFindings.some(f => f.source === src);
  const hasMsg = (text) => scanFindings.some(f => f.message.includes(text));

  if (hasMsg('.npmrc')) {
    steps.push({ type: 'step', label: 'Harden .npmrc (add ignore-scripts=true)', command: 'thumper.hardenWorkspace', icon: 'shield', tooltip: 'Write ignore-scripts=true to workspace .npmrc' });
  }
  if (hasMsg('lockfile')) {
    steps.push({ type: 'step', label: 'Generate lockfile', command: 'thumper.generateLockfile', icon: 'refresh', tooltip: 'Run npm install --package-lock-only --ignore-scripts' });
  }
  if (hasSource('integrity')) {
    steps.push({ type: 'step', label: 'Accept current configs as baseline', command: 'thumper.acceptBaselines', icon: 'check', tooltip: 'Mark current config files as the trusted baseline' });
  }
  if (hasSource('persistence')) {
    steps.push({ type: 'step', label: 'Review IOC findings in output', command: 'thumper.showOutput', icon: 'output', tooltip: 'Review persistence / IOC findings in the output channel' });
  }
  if (hasSource('osv')) {
    steps.push({ type: 'step', label: 'Review OSV malware matches', command: 'thumper.showOutput', icon: 'output', tooltip: 'Review malicious package findings from OSV in the output channel' });
  }
  if (hasSource('extensions')) {
    steps.push({ type: 'step', label: 'Review extension tampering', command: 'thumper.showOutput', icon: 'output', tooltip: 'Review extension integrity findings in the output channel' });
  }
  if (hasSource('deps')) {
    steps.push({ type: 'step', label: 'Review dependency ages', command: 'thumper.showOutput', icon: 'output', tooltip: 'Review young dependency findings in the output channel' });
  }
  return steps;
}

const parseJsonc = ioc.parseJsonc;
function patternHits(t) { return ioc.patternHits(t); }

function cfg() {
  const c = vscode.workspace.getConfiguration('thumper');
  return {
    scopes: c.get('suspectScopes', []),
    packages: c.get('suspectPackages', []),
    scanOnStartup: c.get('scanOnStartup', true),
    watchTerminal: c.get('watchTerminal', true),
    checkHardening: c.get('checkHardening', true),
    osvCheck: c.get('osvCheck', true),
    configIntegrity: c.get('configIntegrity', true),
    extIntegrity: c.get('extensionIntegrity', true),
    extRecheckMin: c.get('extensionRecheckMinutes', 10),
    minAgeDays: c.get('minDependencyAgeDays', 7),
    maxAgeChecks: c.get('maxAgeChecks', 40),
    ageOnStartup: c.get('ageCheckOnStartup', false),
  };
}
function depMatches(name, conf) {
  const scopes = [...new Set([...(ioc.SUSPECT_SCOPES || []), ...conf.scopes])];
  const pkgs = [...new Set([...(ioc.SUSPECT_PACKAGES || []), ...conf.packages])];
  if (pkgs.includes(name)) return true;
  return scopes.some((s) => name === s || name.startsWith(s + '/'));
}
function folders() { return vscode.workspace.workspaceFolders || []; }
function read(f) { try { return fs.readFileSync(f, 'utf8'); } catch { return null; } }

// ============================================================================
// A) CONFIG INTEGRITY BASELINES  (generic, payload-agnostic)
// ============================================================================
//
// The set of files an attacker abuses to gain execution or redirect installs.
// We hash each one. First run records a baseline; later runs diff against it.
// Any unexpected change is surfaced even if its content looks innocent, because
// "a file I execute changed and I didn't change it" is the real signal.

function protectedConfigPaths() {
  const list = [];
  const home = os.homedir();
  // Global, machine-wide
  list.push(path.join(home, '.claude', 'settings.json'));
  list.push(path.join(home, '.claude', 'settings.local.json'));
  list.push(path.join(home, '.npmrc'));
  // Per workspace
  for (const f of folders()) {
    const r = f.uri.fsPath;
    list.push(path.join(r, '.npmrc'));
    list.push(path.join(r, 'package.json'));
    list.push(path.join(r, '.vscode', 'tasks.json'));
    list.push(path.join(r, '.vscode', 'settings.json'));
    list.push(path.join(r, '.vscode', 'launch.json'));
    list.push(path.join(r, '.claude', 'settings.json'));
    list.push(path.join(r, '.claude', 'settings.local.json'));
  }
  return [...new Set(list)];
}

function hashFile(f) {
  const t = read(f);
  if (t === null) return null;
  return crypto.createHash('sha256').update(t).digest('hex');
}

function loadBaselines() {
  try { return ctx.globalState.get('configBaselines', {}); } catch { return {}; }
}
async function saveBaselines(b) { try { await ctx.globalState.update('configBaselines', b); } catch (e) { log('baseline save failed: ' + e.message); } }

// Returns { changed:[], appeared:[], removed:[] } vs stored baseline.
function diffIntegrity() {
  const base = loadBaselines();
  const changed = [], appeared = [], removed = [];
  const seen = new Set();
  for (const f of protectedConfigPaths()) {
    seen.add(f);
    const h = hashFile(f);
    const prior = base[f];
    if (h === null) { if (prior) removed.push(f); continue; }
    if (!prior) { appeared.push(f); }
    else if (prior !== h) { changed.push(f); }
  }
  // files that were baselined but are no longer in the protected set are ignored
  return { changed, appeared, removed };
}

async function acceptBaselines(silent) {
  const base = {};
  for (const f of protectedConfigPaths()) {
    const h = hashFile(f);
    if (h !== null) base[f] = h;
  }
  await saveBaselines(base);
  log(`Baseline recorded for ${Object.keys(base).length} config file(s).`);
  if (!silent) vscode.window.showInformationMessage(`Thumper: baseline recorded for ${Object.keys(base).length} config file(s). Future unexpected changes will be flagged.`);
}

function reportIntegrity(diff, interactive) {
  const total = diff.changed.length + diff.appeared.length + diff.removed.length;
  if (!total) { replaceFindings('integrity', []); return; }
  diff.changed.forEach((f) => log(`[INTEGRITY] changed: ${f}`));
  diff.appeared.forEach((f) => log(`[INTEGRITY] new file appeared: ${f}`));
  diff.removed.forEach((f) => log(`[INTEGRITY] removed: ${f}`));
  // For new/changed config, also run the content patterns to escalate severity.
  let suspicious = false;
  for (const f of [...diff.changed, ...diff.appeared]) {
    const t = read(f); if (t && patternHits(t).length) suspicious = true;
  }
  const detail =
    (diff.changed.length ? 'Changed:\n' + diff.changed.map((f) => '  • ' + f).join('\n') + '\n' : '') +
    (diff.appeared.length ? 'New:\n' + diff.appeared.map((f) => '  • ' + f).join('\n') + '\n' : '') +
    (diff.removed.length ? 'Removed:\n' + diff.removed.map((f) => '  • ' + f).join('\n') : '');
  const head = suspicious
    ? `Thumper: ${total} protected config change(s), and at least one contains suspicious content. Review before trusting.`
    : `Thumper: ${total} protected config file(s) changed since your baseline. If you did not make these changes, investigate.`;
  // Pipe to sidebar store
  const findings = [];
  diff.changed.forEach(f => findings.push({ severity: suspicious ? 'high' : 'warn', message: `Config changed: ${f}`, file: f, detail: 'Hash changed since baseline' }));
  diff.appeared.forEach(f => findings.push({ severity: 'info', message: `New tracked file: ${f}`, file: f }));
  diff.removed.forEach(f => findings.push({ severity: 'warn', message: `Tracked file missing: ${f}`, file: f, detail: 'Was baselined, now gone' }));
  replaceFindings('integrity', findings);
  const fn = suspicious ? vscode.window.showErrorMessage : vscode.window.showWarningMessage;
  if (!interactive) { log(head); return; }
  fn(head, { modal: suspicious, detail }, 'Open details', 'Accept as baseline').then((c) => {
    if (c === 'Open details' && output) output.show(true);
    if (c === 'Accept as baseline') acceptBaselines(false);
  });
}

// ============================================================================
// A2) INSTALLED-EXTENSION INTEGRITY  (the Nx Console lesson)
// ============================================================================
//
// The Nx Console compromise (May 2026) shipped a credential stealer as a
// marketplace auto-update: ~2.7KB injected into the extension's minified
// main.js, live for 11 minutes, run on workspace open. EDR missed it; the
// marketplace's malware scan missed it. The local signal that WAS available:
// the extension's entry file changed.
//
// We baseline every installed extension as { version, hash(main), hash(pkg) }
// and diff. The key distinction that keeps this useful instead of noisy:
//   • version bumped + files changed  -> normal update: note it, re-baseline.
//   • version SAME  + files changed   -> tampering: HIGH, modal, do not accept.
// We deliberately do NOT pattern-scan extension code — minified legit bundles
// match everything — integrity diff is the honest signal here.

// Built-in extensions ship with VS Code itself and get updated when VS Code
// updates — their files change but version numbers often stay the same because
// they're tied to the VS Code build, not the marketplace.  We skip them here
// so we don't flag normal editor updates as tampering.
function isBuiltinExtension(ext) {
  if (!ext.id) return false;
  // Fast path: known built-in publisher prefixes shipped with VS Code.
  const id = ext.id.toLowerCase();
  if (id.startsWith('vscode.') || id.startsWith('ms-vscode.')) return true;
  // Path-based: built-in extensions live under <appRoot>/extensions/,
  // user-installed extensions live under ~/.vscode*/extensions/.
  try {
    const appRoot = vscode.env.appRoot;
    if (appRoot && ext.extensionPath) {
      const builtinDir = path.join(appRoot, 'extensions') + path.sep;
      if (ext.extensionPath.startsWith(builtinDir)) return true;
    }
  } catch (_) { /* env.appRoot unavailable in some contexts */ }
  return false;
}

function extensionEntryFiles(ext) {
  const files = [];
  const root = ext.extensionPath;
  const pj = ext.packageJSON || {};
  files.push(path.join(root, 'package.json'));
  for (const key of ['main', 'browser']) {
    if (typeof pj[key] === 'string') {
      let p = path.join(root, pj[key]);
      if (!fs.existsSync(p) && fs.existsSync(p + '.js')) p = p + '.js';
      if (fs.existsSync(p)) files.push(p);
    }
  }
  return files;
}

function snapshotExtensions() {
  const snap = {};
  for (const ext of vscode.extensions.all || []) {
    try {
      if (isBuiltinExtension(ext)) continue; // skip built-ins
      if (ctx && ctx.extension && ext.id === ctx.extension.id) continue; // skip self during dev
      const pj = ext.packageJSON || {};
      const h = crypto.createHash('sha256');
      let hashed = 0;
      for (const f of extensionEntryFiles(ext)) {
        const t = read(f);
        if (t !== null) { h.update(f).update('\u0000').update(t); hashed++; }
      }
      snap[ext.id] = { version: pj.version || '0.0.0', hash: hashed ? h.digest('hex') : null };
    } catch (e) { log('ext snapshot failed for ' + (ext && ext.id) + ': ' + e.message); }
  }
  return snap;
}

function diffExtensions(baseline, current) {
  const tampered = [], updated = [], added = [], removed = [];
  for (const [id, cur] of Object.entries(current)) {
    const prior = baseline[id];
    if (!prior) { added.push({ id, version: cur.version }); continue; }
    if (prior.hash && cur.hash && prior.hash !== cur.hash) {
      if (prior.version === cur.version) tampered.push({ id, version: cur.version });
      else updated.push({ id, from: prior.version, to: cur.version });
    } else if (prior.version !== cur.version) {
      updated.push({ id, from: prior.version, to: cur.version });
    }
  }
  for (const id of Object.keys(baseline)) if (!current[id]) removed.push({ id });
  return { tampered, updated, added, removed };
}

async function checkExtensionIntegrity(interactive) {
  const baseline = ctx.globalState.get('extBaselines', null);
  const current = snapshotExtensions();
  if (!baseline) {
    await ctx.globalState.update('extBaselines', current);
    log(`Extension baseline recorded for ${Object.keys(current).length} extension(s).`);
    replaceFindings('extensions', []);
    return;
  }
  const d = diffExtensions(baseline, current);

  d.tampered.forEach((t) => log(`[EXT-TAMPER] ${t.id} files changed WITHOUT a version bump (still v${t.version})`));
  d.updated.forEach((u) => log(`[EXT-UPDATE] ${u.id} ${u.from} -> ${u.to}`));
  d.added.forEach((a) => log(`[EXT-NEW] ${a.id}@${a.version}`));
  d.removed.forEach((r) => log(`[EXT-REMOVED] ${r.id}`));

  // Pipe to sidebar store
  const findings = [];
  d.tampered.forEach(t => findings.push({ severity: 'high', message: `Tampered: ${t.id} (v${t.version})`, file: null, detail: 'Files changed without version bump — may be Nx-Console-style attack' }));
  d.updated.forEach(u => findings.push({ severity: 'info', message: `Updated: ${u.id} ${u.from} → ${u.to}`, file: null }));
  d.added.forEach(a => findings.push({ severity: 'info', message: `Installed: ${a.id}@${a.version}`, file: null }));
  d.removed.forEach(r => findings.push({ severity: 'info', message: `Removed: ${r.id}`, file: null }));
  replaceFindings('extensions', findings);

  if (d.tampered.length) {
    // Tampering: alert hard, do NOT auto-accept the new state.
    vscode.window.showErrorMessage(
      `Thumper: ${d.tampered.length} installed extension(s) changed on disk WITHOUT a version change. This is the Nx-Console-style tamper signal. Disable them and investigate before continuing.`,
      { modal: true, detail: d.tampered.map((t) => `• ${t.id} (v${t.version})`).join('\n') },
      'Open details'
    ).then((c) => { if (c && output) output.show(true); });
    return; // keep old baseline so the alert repeats until resolved or explicitly accepted
  }

  if (d.updated.length || d.added.length || d.removed.length) {
    // Normal churn: surface it once, then re-baseline so we don't nag.
    const bits = [];
    if (d.updated.length) bits.push(`${d.updated.length} updated`);
    if (d.added.length) bits.push(`${d.added.length} new`);
    if (d.removed.length) bits.push(`${d.removed.length} removed`);
    if (interactive || d.updated.length) {
      vscode.window.showInformationMessage(`Thumper: extension changes since last check (${bits.join(', ')}). Logged to output.`, 'Open details')
        .then((c) => { if (c && output) output.show(true); });
    }
    await ctx.globalState.update('extBaselines', current);
  } else if (interactive) {
    vscode.window.showInformationMessage('Thumper: installed extensions match their baseline.');
  }
}



// ============================================================================
// B) REGISTRY / .npmrc TAMPER DETECTION
// ============================================================================

function npmrcPaths() {
  const list = [path.join(os.homedir(), '.npmrc')];
  for (const f of folders()) list.push(path.join(f.uri.fsPath, '.npmrc'));
  return list;
}

const TRUSTED_REGISTRY = /^https?:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|.*\.pkg\.dev|.*\.jfrog\.io|.*\.azure(?:devops)?\.com|.*\.visualstudio\.com|npm\.pkg\.github\.com)\b/i;

function checkNpmrcTamper() {
  const findings = [];
  for (const f of npmrcPaths()) {
    const t = read(f); if (t === null) continue;
    for (const raw of t.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith(';') || line.startsWith('#')) continue;
      const m = line.match(/^(?:.*:)?registry\s*=\s*(.+)$/i);
      if (m) {
        const url = m[1].trim().replace(/^["']|["']$/g, '');
        if (!TRUSTED_REGISTRY.test(url)) findings.push({ sev: 'high', msg: `Custom npm registry configured: ${url}`, file: f, why: 'Could redirect installs to a malicious mirror. Confirm this is your org registry.' });
      }
      if (/^ignore-scripts\s*=\s*false/i.test(line)) findings.push({ sev: 'warn', msg: 'ignore-scripts is explicitly set to false', file: f, why: 'Re-enables install-time script execution. Confirm this was intentional.' });
      if (/(^|:)_auth(Token)?\s*=/.test(line) && /^[^:]*registry\s*=/.test('') === false) {
        // auth token present is normal; only note if alongside an untrusted registry (handled above)
      }
    }
  }
  return findings;
}

// ============================================================================
// C0) OSV.dev MALICIOUS-PACKAGE CHECK  (the evergreen detector)
// ============================================================================
//
// Batch-checks the lockfile's resolved name@version against Google's OSV
// database via POST https://api.osv.dev/v1/querybatch (no API key). OSV
// aggregates the OSSF malicious-packages feed, whose MAL-* advisories cover
// Shai-Hulud / Miasma / PhantomRaven and future campaigns. We alert ONLY on
// MAL-* (malware); ordinary CVE advisories are logged, not modal'd, because
// Thumper is a malware watchdog, not a CVE auditor.
//
// querybatch returns, per query (order matches input): { vulns: [{id, modified}] }
// with IDs only. We classify by ID prefix; MAL- => malicious.

function osvBatchQuery(queries) {
  // queries: [{package:{name,ecosystem:'npm'}, version}]
  return new Promise((resolve) => {
    const body = JSON.stringify({ queries });
    const req = https.request('https://api.osv.dev/v1/querybatch', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        if (res.statusCode !== 200) { log(`OSV: HTTP ${res.statusCode}`); return resolve(null); }
        try { resolve(JSON.parse(d).results || []); } catch { resolve(null); }
      });
    });
    req.on('error', (e) => { log('OSV request failed: ' + e.message); resolve(null); });
    req.setTimeout(15000, () => { req.destroy(); log('OSV request timed out'); resolve(null); });
    req.write(body); req.end();
  });
}

function isMalwareId(id) { return typeof id === 'string' && /^MAL-/i.test(id); }

async function checkOsv(interactive) {
  // Collect deps from all ecosystems
  const deps = [];
  for (const f of folders()) {
    const root = f.uri.fsPath;
    // npm
    for (const n of ['package-lock.json', 'npm-shrinkwrap.json']) {
      const p = path.join(root, n);
      if (fs.existsSync(p)) for (const d of readLockResolvedVersions(p)) deps.push({ ...d, ecosystem: 'npm' });
    }
    // PyPI
    const reqTxt = path.join(root, 'requirements.txt');
    if (fs.existsSync(reqTxt)) for (const d of readRequirementsTxt(reqTxt)) deps.push(d);
    const pipfile = path.join(root, 'Pipfile.lock');
    if (fs.existsSync(pipfile)) for (const d of readPipfileLock(pipfile)) deps.push(d);
    const poetry = path.join(root, 'poetry.lock');
    if (fs.existsSync(poetry)) for (const d of readPoetryLock(poetry)) deps.push(d);
  }
  if (!deps.length) { if (interactive) vscode.window.showInformationMessage('Thumper: no lockfile to check against OSV.'); return; }
  // de-dupe by ecosystem:name@version
  const seen = new Set(); const uniq = deps.filter((d) => { const k = d.ecosystem + ':' + d.name + '@' + d.version; if (seen.has(k)) return false; seen.add(k); return true; });

  // 24h cache — keyed by ecosystem:name@version
  const cache = ctx.globalState.get('osvCache', {});
  const now = Date.now();
  const toQuery = [];
  for (const d of uniq) {
    const ckey = d.ecosystem + ':' + d.name + '@' + d.version;
    const c = cache[ckey];
    if (!c || now - c.at > 86400000) toQuery.push(d);
  }

  if (toQuery.length) {
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Thumper: checking packages against OSV' }, async () => {
      for (let i = 0; i < toQuery.length; i += 500) {
        const chunk = toQuery.slice(i, i + 500);
        const results = await osvBatchQuery(chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })));
        if (!results) return;
        chunk.forEach((d, idx) => {
          const ids = ((results[idx] && results[idx].vulns) || []).map((v) => v.id);
          cache[d.ecosystem + ':' + d.name + '@' + d.version] = { ids, at: now };
        });
      }
    });
    await ctx.globalState.update('osvCache', cache);
  }

  const malicious = [], cves = [];
  for (const d of uniq) {
    const c = cache[d.ecosystem + ':' + d.name + '@' + d.version];
    if (!c || !c.ids || !c.ids.length) continue;
    const mal = c.ids.filter(isMalwareId);
    if (mal.length) malicious.push({ ...d, ids: mal });
    else cves.push({ ...d, ids: c.ids });
  }

  cves.forEach((c) => log(`[OSV-CVE] ${c.ecosystem}:${c.name}@${c.version}: ${c.ids.join(', ')}`));
  malicious.forEach((m) => log(`[OSV-MALWARE] ${m.ecosystem}:${m.name}@${m.version}: ${m.ids.join(', ')}`));

  // Pipe to sidebar store
  const osvFindings = [];
  malicious.forEach(m => osvFindings.push({ severity: 'high', message: `MALICIOUS [${m.ecosystem}]: ${m.name}@${m.version}`, file: null, detail: m.ids.join(', ') }));
  cves.forEach(c => osvFindings.push({ severity: 'info', message: `CVE [${c.ecosystem}]: ${c.name}@${c.version}`, file: null, detail: c.ids.join(', ') }));
  replaceFindings('osv', osvFindings);

  if (malicious.length) {
    vscode.window.showErrorMessage(
      `Thumper: ${malicious.length} installed package version(s) are flagged as MALICIOUS by OSV. Treat secrets reachable from this machine as exposed. CLEAN before rotating.`,
      { modal: true, detail: malicious.map((m) => `• [${m.ecosystem}] ${m.name}@${m.version}\n  ${m.ids.join(', ')} — osv.dev/vulnerability/${m.ids[0]}`).join('\n\n') },
      'Open details', 'Remediation steps'
    ).then((c) => { if (c === 'Open details' && output) output.show(true); if (c === 'Remediation steps') showSteps(); });
  } else if (interactive) {
    const npmCount = uniq.filter(d => d.ecosystem === 'npm').length;
    const pyCount = uniq.filter(d => d.ecosystem === 'PyPI').length;
    const parts = [];
    if (npmCount) parts.push(`${npmCount} npm`);
    if (pyCount) parts.push(`${pyCount} PyPI`);
    const note = cves.length ? ` (${cves.length} non-malware advisory match(es) logged to output)` : '';
    vscode.window.showInformationMessage(`Thumper: no known-malicious packages found in ${parts.join(' + ')} checked.${note}`);
  }
}

// ============================================================================
// C) DEPENDENCY AGE (COOLDOWN)
// ============================================================================
//
// Reads resolved versions from the lockfile, asks the registry when each was
// published, flags any newer than minAgeDays. Capped + cached (24h) because
// full packuments are large.

function readLockResolvedVersions(lockPath) {
  const t = read(lockPath); if (t === null) return [];
  let lock; try { lock = JSON.parse(t); } catch { return []; }
  const out = [];
  for (const [key, meta] of Object.entries(lock.packages || {})) {
    if (!key.startsWith('node_modules/')) continue;
    const name = key.slice('node_modules/'.length).replace(/.*node_modules\//, '');
    if (meta && meta.version && name) out.push({ name, version: meta.version });
  }
  // de-dupe name@version
  const seen = new Set(); const uniq = [];
  for (const d of out) { const k = d.name + '@' + d.version; if (!seen.has(k)) { seen.add(k); uniq.push(d); } }
  return uniq;
}

// ---- PyPI lockfile parsers -----------------------------------------------
function readRequirementsTxt(file) {
  const t = read(file); if (t === null) return [];
  const deps = [];
  for (const raw of t.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9_.-]+)\s*==\s*([^;\s]+)/);
    if (m) deps.push({ name: m[1].toLowerCase(), version: m[2], ecosystem: 'PyPI' });
  }
  return deps;
}

function readPipfileLock(file) {
  let j; try { j = JSON.parse(read(file) || ''); } catch { return []; }
  const deps = [];
  for (const section of ['default', 'develop']) {
    for (const [name, meta] of Object.entries(j[section] || {})) {
      const v = (meta && meta.version || '').replace(/^==/, '');
      if (v) deps.push({ name: name.toLowerCase(), version: v, ecosystem: 'PyPI' });
    }
  }
  return deps;
}

function readPoetryLock(file) {
  const t = read(file); if (t === null) return [];
  const deps = [];
  let name = null;
  for (const raw of t.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('[[package]]')) { name = null; continue; }
    const nm = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nm) name = nm[1].toLowerCase();
    const vm = line.match(/^version\s*=\s*"([^"]+)"/);
    if (vm && name) { deps.push({ name, version: vm[1], ecosystem: 'PyPI' }); name = null; }
  }
  return deps;
}

function getPublishTime(name, version) {
  return new Promise((resolve) => {
    const cache = ctx.globalState.get('ageCache', {});
    const ckey = name + '@' + version;
    const hit = cache[ckey];
    if (hit && (Date.now() - hit.at < 24 * 3600 * 1000)) return resolve(hit.time);
    const url = 'https://registry.npmjs.org/' + name.replace('/', '%2f');
    https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        let time = null;
        try { const j = JSON.parse(d); time = j.time && j.time[version] ? j.time[version] : null; } catch {}
        cache[ckey] = { time, at: Date.now() };
        ctx.globalState.update('ageCache', cache);
        resolve(time);
      });
    }).on('error', () => resolve(null));
  });
}

async function checkDependencyAges(interactive) {
  const conf = cfg();
  if (conf.minAgeDays <= 0) { if (interactive) vscode.window.showInformationMessage('Thumper: age check disabled (minDependencyAgeDays = 0).'); return; }
  const locks = [];
  for (const f of folders()) {
    for (const n of ['package-lock.json', 'npm-shrinkwrap.json']) {
      const p = path.join(f.uri.fsPath, n);
      if (fs.existsSync(p)) locks.push(p);
    }
  }
  if (!locks.length) { if (interactive) vscode.window.showInformationMessage('Thumper: no lockfile found to age-check.'); return; }

  let deps = [];
  for (const l of locks) deps = deps.concat(readLockResolvedVersions(l));
  // de-dupe across lockfiles, then cap
  const seen = new Set(); deps = deps.filter((d) => { const k = d.name + '@' + d.version; if (seen.has(k)) return false; seen.add(k); return true; });
  const capped = deps.slice(0, conf.maxAgeChecks);

  const cutoff = Date.now() - conf.minAgeDays * 86400 * 1000;
  const young = [];
  await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Thumper: checking dependency ages' }, async () => {
    for (const d of capped) {
      const t = await getPublishTime(d.name, d.version);
      if (t && new Date(t).getTime() > cutoff) {
        const days = Math.floor((Date.now() - new Date(t).getTime()) / 86400000);
        young.push({ ...d, days, published: t });
      }
    }
  });

  if (!young.length) {
    log(`Age check: none of ${capped.length} checked deps are newer than ${conf.minAgeDays}d.`);
    replaceFindings('deps', []);
    if (interactive) vscode.window.showInformationMessage(`Thumper: no dependencies newer than ${conf.minAgeDays} days (checked ${capped.length}${deps.length > capped.length ? ' of ' + deps.length : ''}).`);
    return;
  }
  young.sort((a, b) => a.days - b.days);
  young.forEach((y) => log(`[AGE] ${y.name}@${y.version} published ${y.days}d ago (${y.published})`));
  // Pipe to sidebar store
  const ageFindings = young.map(y => ({ severity: 'warn', message: `${y.name}@${y.version} — ${y.days}d old`, file: null, detail: `Published ${y.published}, cooldown is ${conf.minAgeDays}d` }));
  replaceFindings('deps', ageFindings);
  const detail = young.slice(0, 20).map((y) => `  • ${y.name}@${y.version} — ${y.days}d old`).join('\n');
  vscode.window.showWarningMessage(
    `Thumper: ${young.length} dependency version(s) are newer than your ${conf.minAgeDays}-day cooldown. Brand-new versions are the highest-risk window for supply-chain poisoning.`,
    { modal: false, detail }, 'Open details'
  ).then((c) => { if (c && output) output.show(true); });
}

// ============================================================================
// D) KNOWN-IOC PERSISTENCE SCAN + HYGIENE  (from v0.1/0.2)
// ============================================================================

function scanTasksFile(file, findings) {
  let text = read(file); if (text === null) return;
  let parsed = null; try { parsed = parseJsonc(text); } catch {}
  const tasks = parsed && Array.isArray(parsed.tasks) ? parsed.tasks : [];
  for (const t of tasks) {
    const runOn = t && t.runOptions && t.runOptions.runOn;
    const cmd = [t && t.command, ...(Array.isArray(t && t.args) ? t.args : [])].filter(Boolean).join(' ');
    if (runOn === 'folderOpen') findings.push({ sev: 'high', msg: `Auto-run-on-open task "${t.label || '(unlabeled)'}"`, file, detail: cmd });
    if (cmd) { const h = patternHits(cmd); if (h.length) findings.push({ sev: 'high', msg: `Suspicious task "${t.label || '(unlabeled)'}": ${h.join(', ')}`, file, detail: cmd }); }
  }
  if (!tasks.length) { const h = patternHits(text); if (h.length) findings.push({ sev: 'high', msg: `Suspicious content in tasks.json: ${h.join(', ')}`, file }); }
}
function scanClaudeFile(file, findings) {
  let text = read(file); if (text === null) return;
  let parsed = null; try { parsed = parseJsonc(text); } catch {}
  const hooks = parsed && parsed.hooks;
  if (hooks && typeof hooks === 'object') {
    const active = Object.entries(hooks).filter(([, v]) => Array.isArray(v) && v.length);
    if (active.length) {
      const events = active.map(([k]) => k).join(', ');
      const sev = /SessionStart|PreToolUse|UserPromptSubmit|Notification/.test(events) ? 'high' : 'warn';
      findings.push({ sev, msg: `Claude hook(s) defined: ${events}`, file, detail: 'Hooks run shell commands automatically. If you did not add these, remove them by hand.\n' + JSON.stringify(Object.fromEntries(active)).slice(0, 400) });
    }
  }
  const h = patternHits(text); if (h.length) findings.push({ sev: 'high', msg: `Suspicious content in Claude settings: ${h.join(', ')}`, file });
}
function scanManifest(file, findings, conf) {
  let pkg; try { pkg = JSON.parse(read(file) || ''); } catch { return; }
  for (const b of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const dep of Object.keys(pkg[b] || {})) if (depMatches(dep, conf)) findings.push({ sev: 'high', msg: `Denylisted dependency "${dep}" (${b})`, file });
  }
  // Generic: lifecycle scripts that fetch+execute
  const scripts = pkg.scripts || {};
  for (const [k, v] of Object.entries(scripts)) {
    if (/^(pre|post)?install$/.test(k) && typeof v === 'string') {
      const h = patternHits(v); if (h.length) findings.push({ sev: 'high', msg: `Install script "${k}" looks dangerous: ${h.join(', ')}`, file, detail: v });
    }
  }
}

function scanPythonFile(file, findings) {
  const text = read(file); if (text === null) return;
  const base = path.basename(file);
  const hits = patternHits(text);
  if (hits.length) findings.push({ sev: 'high', msg: `Suspicious content in ${base}: ${hits.join(', ')}`, file, detail: text.slice(0, 400) });
  // Check for direct pip install commands (often used in supply-chain attacks)
  if (/pip\s+install\b/i.test(text) && /--index-url|--extra-index-url|--trusted-host/i.test(text)) {
    findings.push({ sev: 'high', msg: `${base} references pip install with custom index`, file, why: 'Custom package indexes can serve malicious packages.' });
  }
  // pyproject.toml build-system check
  if (base === 'pyproject.toml') {
    const bsMatch = text.match(/\[build-system\]/i);
    if (bsMatch) findings.push({ sev: 'info', msg: 'pyproject.toml has [build-system] — build-time code execution surface', file });
  }
  // setup.py with network calls
  if (base === 'setup.py' && /\b(urlopen|urlretrieve|requests\.|urllib)\b/i.test(text)) {
    findings.push({ sev: 'high', msg: 'setup.py makes network calls', file, detail: text.slice(0, 400) });
  }
}

async function fullScan(reason) {
  const conf = cfg();
  const findings = [];
  log(`Scan (${reason})...`);
  // npm
  for (const u of await vscode.workspace.findFiles('**/package.json', '**/node_modules/**', 2000)) scanManifest(u.fsPath, findings, conf);
  // VS Code / Claude
  for (const u of await vscode.workspace.findFiles('**/.vscode/tasks.json', '**/node_modules/**', 500)) scanTasksFile(u.fsPath, findings);
  for (const u of await vscode.workspace.findFiles('**/.claude/settings*.json', '**/node_modules/**', 500)) scanClaudeFile(u.fsPath, findings);
  for (const f of ['settings.json', 'settings.local.json']) { const p = path.join(os.homedir(), '.claude', f); if (fs.existsSync(p)) scanClaudeFile(p, findings); }
  // PyPI
  for (const u of await vscode.workspace.findFiles('**/requirements*.txt', '**/{node_modules,.venv,venv,__pycache__}/**', 500)) scanPythonFile(u.fsPath, findings);
  for (const u of await vscode.workspace.findFiles('**/{pyproject.toml,Pipfile,setup.py,setup.cfg}', '**/{node_modules,.venv,venv,__pycache__}/**', 500)) scanPythonFile(u.fsPath, findings);
  // Registry / .npmrc
  for (const t of checkNpmrcTamper()) findings.push(t);
  reportPersistence(findings, reason !== 'startup');
  return findings;
}
function reportPersistence(findings, interactive) {
  const high = findings.filter((f) => f.sev === 'high');
  const warn = findings.filter((f) => f.sev === 'warn');
  findings.forEach((f) => log(`  [${f.sev.toUpperCase()}] ${f.msg} :: ${f.file}${f.why ? ' :: ' + f.why : ''}${f.detail ? ' :: ' + f.detail : ''}`));
  // Pipe to sidebar store
  const normalized = findings.map(f => ({ severity: f.sev === 'high' ? 'high' : 'warn', message: f.msg, file: f.file || null, detail: f.detail || f.why || null }));
  replaceFindings('persistence', normalized);
  if (!interactive) return;
  if (high.length) {
    vscode.window.showErrorMessage(
      `Thumper: ${high.length} HIGH finding(s). CLEAN before rotating any credentials.`,
      { modal: true, detail: high.slice(0, 6).map((f) => `• ${f.msg}\n  ${f.file}`).join('\n\n') }, 'Open details', 'Remediation steps'
    ).then((c) => { if (c === 'Open details' && output) output.show(true); if (c === 'Remediation steps') showSteps(); });
  } else if (warn.length) {
    vscode.window.showWarningMessage(`Thumper: ${warn.length} item(s) to review.`, 'Open output').then((c) => { if (c && output) output.show(true); });
  } else {
    vscode.window.showInformationMessage('Thumper: no persistence/IOC indicators found.');
  }
}

// ---- hygiene nudge + hardening (from v0.2, condensed) ----------------------

function scriptsDisabled() {
  for (const f of npmrcPaths()) { const t = read(f); if (t && /^\s*ignore-scripts\s*=\s*true\s*$/im.test(t)) return true; }
  return false;
}
function lockfilePresent() {
  for (const f of folders()) if (fs.existsSync(path.join(f.uri.fsPath, 'package-lock.json')) || fs.existsSync(path.join(f.uri.fsPath, 'npm-shrinkwrap.json'))) return true;
  return false;
}
function analyzeCommand(line) {
  if (scriptsDisabled()) return null;
  const hasIgnore = /--ignore-scripts\b/.test(line);
  for (const s of line.split(/&&|;|\|\|/).map((x) => x.trim())) {
    const isNpm = /\bnpm\s+(i|install|add|update|up)\b/i.test(s) && !/\bnpm\s+ci\b/.test(s);
    const isPnpm = /\bpnpm\s+(i|install|add|update|up)\b/i.test(s);
    const isYarn = /\byarn(\s+(add|install))?\s*$/i.test(s) || /\byarn\s+(add|install)\b/i.test(s);
    if ((isNpm || isPnpm || isYarn) && !hasIgnore) {
      const bare = isNpm && lockfilePresent() && !/\bnpm\s+(i|install|add)\b\s+[^-\s]/i.test(s);
      return { bare };
    }
  }
  return null;
}
let warnedAt = 0;
function onCommand(line) {
  if (!line) return; const r = analyzeCommand(line); if (!r) return;
  if (Date.now() - warnedAt < 4000) return; warnedAt = Date.now();
  const msg = r.bare ? 'Thumper: prefer `npm ci --ignore-scripts` (you have a lockfile), or set the .npmrc floor.' : 'Thumper: that install ran lifecycle scripts. Prefer `--ignore-scripts`, or set the .npmrc floor.';
  vscode.window.showWarningMessage(msg, 'Harden workspace', 'Why?').then((c) => { if (c === 'Harden workspace') hardenWorkspace(true); if (c === 'Why?') showSteps(); });
}
async function checkHardening() {
  const issues = [];
  const hFindings = [];
  if (!scriptsDisabled()) {
    issues.push('`.npmrc` does not set `ignore-scripts=true`.');
    hFindings.push({ severity: 'warn', message: '`.npmrc` does not set `ignore-scripts=true`.', file: null });
  }
  if (folders().length && !lockfilePresent()) {
    issues.push('No committed lockfile found.');
    hFindings.push({ severity: 'warn', message: 'No committed lockfile found.', file: null });
  }
  // Pipe to sidebar store
  replaceFindings('hardening', hFindings);
  return issues;
}
async function hardenWorkspace(skipConfirm) {
  if (!folders().length) { vscode.window.showErrorMessage('Thumper: open a folder first.'); return; }
  const root = folders()[0].uri.fsPath; const npmrc = path.join(root, '.npmrc');
  let cur = read(npmrc) || ''; const already = /^\s*ignore-scripts\s*=\s*true\s*$/im.test(cur);

  // When called from the "Harden it" button, skip the redundant second modal.
  // When called standalone (command palette / terminal nudge), still confirm.
  if (!skipConfirm) {
    const ok = await vscode.window.showWarningMessage(already ? '.npmrc already disables scripts. Show the full checklist?' : `Add "ignore-scripts=true" to ${npmrc}?`, { modal: true }, 'Yes');
    if (ok !== 'Yes') return;
  }

  let didWrite = false;
  if (!already) {
    try {
      fs.writeFileSync(npmrc, (cur.trim() ? cur.trim() + '\n' : '') + 'ignore-scripts=true\n');
      log('wrote .npmrc floor');
      didWrite = true;
    } catch (e) { vscode.window.showErrorMessage('write failed: ' + e.message); return; }
  }

  // Re-check to update sidebar.
  const issues = await checkHardening();

  showSteps();
  const noLockfile = issues.includes('No committed lockfile found.');
  if (didWrite) {
    vscode.window.showInformationMessage(noLockfile
      ? 'Thumper: .npmrc floor set. Reminder: commit a lockfile (package-lock.json) for reproducible installs.'
      : 'Thumper: .npmrc floor set. Checklist in the output channel.');
  } else if (already) {
    vscode.window.showInformationMessage(noLockfile
      ? 'Thumper: .npmrc already has ignore-scripts=true. Reminder: commit a lockfile.'
      : 'Thumper: .npmrc already has ignore-scripts=true.');
  }
}
async function generateLockfile() {
  if (!folders().length) { vscode.window.showErrorMessage('Thumper: open a folder first.'); return; }
  const root = folders()[0].uri.fsPath;
  if (lockfilePresent()) {
    vscode.window.showInformationMessage('Thumper: a lockfile already exists.');
    await checkHardening();
    return;
  }
  await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Thumper: generating lockfile...' }, () => new Promise((resolve) => {
    cp.exec('npm install --package-lock-only --ignore-scripts', { cwd: root }, async (err) => {
      if (err) {
        log('lockfile generation failed: ' + err.message);
        vscode.window.showErrorMessage('Thumper: lockfile generation failed. Check the output channel for details.');
      } else {
        log('generated package-lock.json');
        vscode.window.showInformationMessage('Thumper: package-lock.json generated. Commit it for reproducible installs.');
      }
      await checkHardening();
      resolve();
    });
  }));
}
function showSteps() {
  if (!output) output = vscode.window.createOutputChannel('Thumper');
  output.appendLine('\n--- Hardening / why ---');
  ['npm ci = exactly-what-I-locked + hash verify, but STILL runs scripts.',
   '--ignore-scripts = no install-time code runs at all (set ignore-scripts=true in .npmrc as the floor).',
   'Commit the lockfile; npm ci --ignore-scripts in CI; npm audit signatures to verify provenance.',
   'Cooldown: avoid installing versions published in the last few days.',
   'If compromised: CLEAN persistence first, ISOLATE, then ROTATE from a clean machine. Never revoke before cleaning.'
  ].forEach((s) => output.appendLine('  • ' + s));
  output.show();
}

// ============================================================================
// ACTIVATION
// ============================================================================

function activate(context) {
  ctx = context;
  log('Thumper v0.3 active.');
  const conf = cfg();

  // ---- status bar item -------------------------------------------------
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'thumper.scanNow';
  statusBarItem.text = '$(shield) Thumper';
  statusBarItem.tooltip = 'Thumper: click to scan workspace';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // ---- sidebar tree view -----------------------------------------------
  findingsProvider = new FindingsProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('thumper.findings', findingsProvider)
  );
  context.subscriptions.push(
    vscode.commands.registerCommand('thumper.refreshFindings', () => findingsProvider.refresh())
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('thumper.scanNow', async () => { await fullScan('manual'); if (cfg().configIntegrity) reportIntegrity(diffIntegrity(), true); if (cfg().extIntegrity) await checkExtensionIntegrity(true); if (cfg().osvCheck) await checkOsv(true); }),
    vscode.commands.registerCommand('thumper.checkOsv', () => checkOsv(true)),
    vscode.commands.registerCommand('thumper.hardenWorkspace', () => hardenWorkspace(true)),
    vscode.commands.registerCommand('thumper.checkDependencyAges', () => checkDependencyAges(true)),
    vscode.commands.registerCommand('thumper.acceptBaselines', async () => { await acceptBaselines(false); await ctx.globalState.update('extBaselines', snapshotExtensions()); log('Extension baseline re-recorded.'); }),
    vscode.commands.registerCommand('thumper.showOutput', () => { if (!output) output = vscode.window.createOutputChannel('Thumper'); output.show(); }),
    vscode.commands.registerCommand('thumper.generateLockfile', () => generateLockfile())
  );

  // First run: if no baseline exists yet, record one silently so future changes diff against a known-good point.
  if (conf.configIntegrity) {
    const base = loadBaselines();
    if (!Object.keys(base).length) setTimeout(() => acceptBaselines(true), 1000);
    else setTimeout(() => reportIntegrity(diffIntegrity(), false), 2000);
  }
  if (conf.scanOnStartup) setTimeout(() => fullScan('startup'), 1500);
  if (conf.checkHardening) setTimeout(() => checkHardening(), 2500);
  if (conf.ageOnStartup) setTimeout(() => checkDependencyAges(false), 3500);
  if (conf.osvCheck) setTimeout(() => checkOsv(false), 4000);
  if (conf.extIntegrity) {
    setTimeout(() => checkExtensionIntegrity(false), 3000);
    if (conf.extRecheckMin > 0) {
      const iv = setInterval(() => checkExtensionIntegrity(false), conf.extRecheckMin * 60 * 1000);
      context.subscriptions.push({ dispose: () => clearInterval(iv) });
    }
    // Re-check immediately when the extension set changes (install/uninstall/update).
    if (vscode.extensions.onDidChange) {
      context.subscriptions.push(vscode.extensions.onDidChange(() => checkExtensionIntegrity(false)));
    }
  }

  // Live watchers: persistence files + integrity re-check on any protected change.
  const watch = (glob) => vscode.workspace.createFileSystemWatcher(glob);
  const tasksW = watch('**/.vscode/tasks.json');
  const claudeW = watch('**/.claude/settings*.json');
  const onTask = (u) => { const f = []; scanTasksFile(u.fsPath, f); if (f.some((x) => x.sev === 'high')) reportPersistence(f, 'tasks.json changed'); if (cfg().configIntegrity) reportIntegrity(diffIntegrity(), true); };
  const onClaude = (u) => { const f = []; scanClaudeFile(u.fsPath, f); if (f.some((x) => x.sev === 'high')) reportPersistence(f, 'Claude settings changed'); if (cfg().configIntegrity) reportIntegrity(diffIntegrity(), true); };
  tasksW.onDidChange(onTask); tasksW.onDidCreate(onTask);
  claudeW.onDidChange(onClaude); claudeW.onDidCreate(onClaude);
  context.subscriptions.push(tasksW, claudeW);
  // Watch .npmrc for registry/floor tampering specifically.
  const npmrcW = watch('**/.npmrc');
  const onNpmrc = () => { const t = checkNpmrcTamper(); if (t.length) reportPersistence(t, '.npmrc changed'); if (cfg().configIntegrity) reportIntegrity(diffIntegrity(), true); };
  npmrcW.onDidChange(onNpmrc); npmrcW.onDidCreate(onNpmrc);
  context.subscriptions.push(npmrcW);
  try {
    const homeClaudeW = watch(new vscode.RelativePattern(vscode.Uri.file(path.join(os.homedir(), '.claude')), 'settings*.json'));
    homeClaudeW.onDidChange(onClaude); homeClaudeW.onDidCreate(onClaude); context.subscriptions.push(homeClaudeW);
  } catch (e) { log('cannot watch ~/.claude: ' + e.message); }

  if (conf.watchTerminal && typeof vscode.window.onDidStartTerminalShellExecution === 'function') {
    context.subscriptions.push(vscode.window.onDidStartTerminalShellExecution((e) => {
      try { onCommand(e && e.execution && e.execution.commandLine && e.execution.commandLine.value); } catch (err) { log('term watch err: ' + err.message); }
    }));
    log('Terminal hygiene watch enabled.');
  }
}
function deactivate() {}
module.exports = { activate, deactivate, readLockResolvedVersions, readRequirementsTxt, readPipfileLock, readPoetryLock, isMalwareId, hashFile, TRUSTED_REGISTRY };
