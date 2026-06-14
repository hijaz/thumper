// patterns.js — shared detection patterns and IOCs for Thumper.
//
// Single source of truth, imported by both the extension and the standalone
// audit script. The behavioral SUSPICIOUS_PATTERNS are evergreen (they describe
// what malicious config content does, not which campaign did it). The
// SUSPECT_SCOPES / SUSPECT_PACKAGES / FINGERPRINT_STRINGS are campaign-specific
// IOCs for the June 2026 Miasma / Shai-Hulud outbreak and will age out; the
// extension's OSV.dev check is the living malicious-package detector.

'use strict';

// --- Campaign-specific IOCs (dated; OSV is the evergreen source) ------------
const SUSPECT_SCOPES = ['@redhat-cloud-services'];
const SUSPECT_PACKAGES = ['@vapi-ai/server-sdk', 'ai-sdk-ollama'];
const FINGERPRINT_STRINGS = [
  'Miasma: The Spreading Blight',
  'Miasma - The Spreading Blight',
  'Shai-Hulud',
  'Shai Hulud',
];

// --- Evergreen behavioral patterns (bash + PowerShell payloads) -------------
const SUSPICIOUS_PATTERNS = [
  { re: /\b(curl|wget|fetch)\b[^\n|]*\|\s*(sh|bash|node|python3?)/i, why: 'downloads and pipes into a shell/interpreter' },
  { re: /Invoke-WebRequest|iwr\b|irm\b|DownloadString/i, why: 'PowerShell remote download' },
  { re: /\|\s*(iex|Invoke-Expression)/i, why: 'pipes into Invoke-Expression' },
  { re: /base64\s+(-d|--decode)|atob\(|FromBase64String/i, why: 'base64 decode of a payload' },
  { re: /\beval\s*\(|\bFunction\s*\(\s*['"]/i, why: 'dynamic code execution (eval/Function)' },
  { re: /child_process|spawn(Sync)?|execSync|\bexec\s*\(/i, why: 'spawns child processes' },
  { re: /\.aws|\.ssh|id_rsa|id_ed25519|\.npmrc|gcloud|\.kube|\.azure|credentials/i, why: 'touches credential/secret locations' },
  { re: /AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|GOOGLE_APPLICATION_CREDENTIALS/i, why: 'reads sensitive environment variables' },
  { re: /rm\s+-rf\s+(~|\$HOME|\/)|Remove-Item[^\n]*-Recurse/i, why: 'destructive file removal' },
  { re: /\bnpm\s+publish\b|npm\s+token\b/i, why: 'interacts with npm publishing/tokens (worm propagation)' },
  { re: /\bnc\b\s+-|netcat|\/dev\/tcp\//i, why: 'raw network connection (possible C2)' },
  { re: /https?:\/\/(?!localhost|127\.0\.0\.1)\d{1,3}(\.\d{1,3}){3}/i, why: 'connects to a raw IP address' },
  { re: /binding\.gyp/i, why: 'binding.gyp build hook (second-wave technique)' },
];

// --- Shared helpers ---------------------------------------------------------

// Tolerant JSONC parse (tasks.json / Claude settings allow comments + trailing
// commas). Throws on truly malformed input; callers fall back to raw scan.
function parseJsonc(text) {
  const stripped = text
    .replace(/("(?:\\.|[^"\\])*")|\/\/[^\n\r]*|\/\*[\s\S]*?\*\//g, (m, str) => (str ? str : ''))
    .replace(/,(\s*[}\]])/g, '$1');
  return JSON.parse(stripped);
}

function patternHits(text) {
  const hits = [];
  for (const p of SUSPICIOUS_PATTERNS) if (p.re.test(text)) hits.push(p.why);
  for (const fp of FINGERPRINT_STRINGS) if (text.includes(fp)) hits.push(`contains worm fingerprint "${fp}"`);
  return hits;
}

function depMatches(name) {
  if (SUSPECT_PACKAGES.includes(name)) return true;
  return SUSPECT_SCOPES.some((scope) => name === scope || name.startsWith(scope + '/'));
}

module.exports = {
  SUSPECT_SCOPES, SUSPECT_PACKAGES, FINGERPRINT_STRINGS, SUSPICIOUS_PATTERNS,
  parseJsonc, patternHits, depMatches,
};
