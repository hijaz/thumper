// tests for extension.js — pure functions (lockfile parsing, PyPI parsers,
// hashing, registry checks).  Uses a Module._load hook to mock 'vscode'.
'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

// ── mock vscode before the extension module is loaded ────────────────────
// Intercept require('vscode') via Module._load so extension.js doesn't
// crash when trying to import VS Code APIs during unit tests.
const Module = require('module');
const _load = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'vscode') {
    return require('./vscode-mock.js');
  }
  return _load.apply(this, arguments);
};

const ext = require('../extension.js');

// ── helpers ──────────────────────────────────────────────────────────────
const fixtures = (name) => path.join(__dirname, 'fixtures', name);

// ── tests ────────────────────────────────────────────────────────────────

describe('extension.js — lockfile parsing', () => {
  describe('readLockResolvedVersions', () => {
    it('returns deps from a package-lock.json v2', () => {
      const deps = ext.readLockResolvedVersions(fixtures('package-lock.json'));
      assert.ok(deps.length >= 4, `expected >=4 deps, got ${deps.length}`);

      const names = deps.map(d => d.name);
      assert.ok(names.includes('express'));
      assert.ok(names.includes('lodash'));
      assert.ok(names.includes('@redhat-cloud-services/frontend-components'));
      assert.ok(names.includes('accepts'));
    });

    it('extracts correct versions', () => {
      const deps = ext.readLockResolvedVersions(fixtures('package-lock.json'));
      const express = deps.find(d => d.name === 'express');
      assert.ok(express);
      assert.strictEqual(express.version, '4.18.2');
    });

    it('de-duplicates name@version pairs', () => {
      const deps = ext.readLockResolvedVersions(fixtures('package-lock.json'));
      const lodashEntries = deps.filter(d => d.name === 'lodash');
      // package-lock has lodash at root (4.17.21) and nested (4.17.20)
      const versions = lodashEntries.map(d => d.version).sort();
      assert.deepStrictEqual(versions, ['4.17.20', '4.17.21']);
    });

    it('returns empty array for non-existent file', () => {
      const deps = ext.readLockResolvedVersions(fixtures('nonexistent.json'));
      assert.deepStrictEqual(deps, []);
    });

    it('returns empty array for malformed JSON', () => {
      const tmp = fixtures('bad-lock.json');
      fs.writeFileSync(tmp, '{ this is not valid json }');
      try {
        const deps = ext.readLockResolvedVersions(tmp);
        assert.deepStrictEqual(deps, []);
      } finally {
        fs.rmSync(tmp);
      }
    });
  });
});

describe('extension.js — PyPI parsers', () => {
  describe('readRequirementsTxt', () => {
    it('parses pinned requirements', () => {
      const deps = ext.readRequirementsTxt(fixtures('requirements.txt'));
      assert.ok(deps.length >= 4, `expected >=4 deps, got ${deps.length}`);

      const names = deps.map(d => d.name);
      assert.ok(names.includes('flask'));
      assert.ok(names.includes('requests'));
      assert.ok(names.includes('numpy'));
      assert.ok(names.includes('pandas'));
    });

    it('extracts correct version strings', () => {
      const deps = ext.readRequirementsTxt(fixtures('requirements.txt'));
      const flask = deps.find(d => d.name === 'flask');
      assert.ok(flask);
      assert.strictEqual(flask.version, '2.3.2');
      assert.strictEqual(flask.ecosystem, 'PyPI');
    });

    it('skips unpinned packages', () => {
      const deps = ext.readRequirementsTxt(fixtures('requirements.txt'));
      const pipTools = deps.filter(d => d.name === 'pip-tools');
      assert.strictEqual(pipTools.length, 0);
    });

    it('skips comment lines and options', () => {
      const deps = ext.readRequirementsTxt(fixtures('requirements.txt'));
      // --extra-index-url and -r lines should not appear as deps
      const flags = deps.filter(d => d.name.startsWith('-'));
      assert.strictEqual(flags.length, 0);
    });

    it('returns empty array for non-existent file', () => {
      const deps = ext.readRequirementsTxt(fixtures('nonexistent.txt'));
      assert.deepStrictEqual(deps, []);
    });
  });

  describe('readPipfileLock', () => {
    it('parses default and develop dependencies', () => {
      const deps = ext.readPipfileLock(fixtures('Pipfile.lock'));
      assert.ok(deps.length >= 3, `expected >=3 deps, got ${deps.length}`);

      const names = deps.map(d => d.name);
      assert.ok(names.includes('django'));
      assert.ok(names.includes('requests'));
      assert.ok(names.includes('pytest'));   // develop dep
    });

    it('strips == prefix from versions', () => {
      const deps = ext.readPipfileLock(fixtures('Pipfile.lock'));
      const django = deps.find(d => d.name === 'django');
      assert.ok(django);
      assert.strictEqual(django.version, '3.2.19');
    });

    it('tags all deps as PyPI ecosystem', () => {
      const deps = ext.readPipfileLock(fixtures('Pipfile.lock'));
      assert.ok(deps.every(d => d.ecosystem === 'PyPI'));
    });

    it('returns empty array for non-existent file', () => {
      const deps = ext.readPipfileLock(fixtures('nonexistent.lock'));
      assert.deepStrictEqual(deps, []);
    });
  });

  describe('readPoetryLock', () => {
    it('parses all [[package]] entries', () => {
      const deps = ext.readPoetryLock(fixtures('poetry.lock'));
      assert.strictEqual(deps.length, 3);

      const names = deps.map(d => d.name);
      assert.ok(names.includes('flask'));
      assert.ok(names.includes('click'));
      assert.ok(names.includes('requests'));
    });

    it('extracts version strings without quotes', () => {
      const deps = ext.readPoetryLock(fixtures('poetry.lock'));
      const flask = deps.find(d => d.name === 'flask');
      assert.ok(flask);
      assert.strictEqual(flask.version, '2.3.2');
    });

    it('tags all deps as PyPI ecosystem', () => {
      const deps = ext.readPoetryLock(fixtures('poetry.lock'));
      assert.ok(deps.every(d => d.ecosystem === 'PyPI'));
    });

    it('returns empty array for non-existent file', () => {
      const deps = ext.readPoetryLock(fixtures('nonexistent.lock'));
      assert.deepStrictEqual(deps, []);
    });
  });
});

describe('extension.js — utilities', () => {
  describe('hashFile', () => {
    it('produces a 64-character hex SHA-256', () => {
      const tmp = fixtures('temp.txt');
      fs.writeFileSync(tmp, 'hello world');
      try {
        const h = ext.hashFile(tmp);
        assert.ok(typeof h === 'string');
        assert.strictEqual(h.length, 64);
        assert.ok(/^[0-9a-f]{64}$/.test(h));
      } finally {
        fs.rmSync(tmp);
      }
    });

    it('returns null for non-existent file', () => {
      assert.strictEqual(ext.hashFile(fixtures('nonexistent.txt')), null);
    });

    it('is deterministic (same content → same hash)', () => {
      const tmp = fixtures('hash-test.txt');
      fs.writeFileSync(tmp, 'deterministic');
      try {
        const h1 = ext.hashFile(tmp);
        const h2 = ext.hashFile(tmp);
        assert.strictEqual(h1, h2);
      } finally {
        fs.rmSync(tmp);
      }
    });

    it('different content produces different hashes', () => {
      const tmp = fixtures('hash-diff.txt');
      fs.writeFileSync(tmp, 'content A');
      const h1 = ext.hashFile(tmp);
      fs.writeFileSync(tmp, 'content B');
      const h2 = ext.hashFile(tmp);
      fs.rmSync(tmp);
      assert.notStrictEqual(h1, h2);
    });
  });

  describe('isMalwareId', () => {
    it('returns true for MAL- prefixed IDs', () => {
      assert.strictEqual(ext.isMalwareId('MAL-2024-1234'), true);
      assert.strictEqual(ext.isMalwareId('MAL-2025-9999'), true);
      assert.strictEqual(ext.isMalwareId('mal-0001'), true); // case-insensitive
    });

    it('returns false for CVE IDs', () => {
      assert.strictEqual(ext.isMalwareId('CVE-2024-1234'), false);
      assert.strictEqual(ext.isMalwareId('GHSA-xxxx-xxxx'), false);
    });

    it('returns false for non-string or empty values', () => {
      assert.strictEqual(ext.isMalwareId(null), false);
      assert.strictEqual(ext.isMalwareId(undefined), false);
      assert.strictEqual(ext.isMalwareId(''), false);
      assert.strictEqual(ext.isMalwareId(123), false);
    });
  });

  describe('TRUSTED_REGISTRY', () => {
    it('matches registry.npmjs.org', () => {
      assert.ok(ext.TRUSTED_REGISTRY.test('https://registry.npmjs.org/'));
      assert.ok(ext.TRUSTED_REGISTRY.test('http://registry.npmjs.org/'));
    });

    it('matches registry.yarnpkg.com', () => {
      assert.ok(ext.TRUSTED_REGISTRY.test('https://registry.yarnpkg.com/'));
    });

    it('matches GitHub Packages npm registry', () => {
      assert.ok(ext.TRUSTED_REGISTRY.test('https://npm.pkg.github.com/'));
    });

    it('matches JFrog Artifactory', () => {
      assert.ok(ext.TRUSTED_REGISTRY.test('https://myorg.jfrog.io/artifactory/npm/'));
    });

    it('matches Azure DevOps artifacts', () => {
      assert.ok(ext.TRUSTED_REGISTRY.test('https://pkgs.dev.azure.com/myorg/_packaging/npm/'));
    });

    it('rejects bare IP address registries', () => {
      assert.strictEqual(ext.TRUSTED_REGISTRY.test('https://192.168.1.1:4873/'), false);
    });

    it('rejects obviously malicious registries', () => {
      assert.strictEqual(ext.TRUSTED_REGISTRY.test('https://evil-mirror.com/'), false);
      assert.strictEqual(ext.TRUSTED_REGISTRY.test('https://npm.malware.example.com/'), false);
    });
  });

  describe('readRequirementsTxt — edge cases', () => {
    it('handles CRLF line endings', () => {
      // read handles any line ending via split(/\r?\n/)
      const tmp = fixtures('crlf.txt');
      fs.writeFileSync(tmp, 'flask==2.3.2\r\nrequests==2.31.0\r\n');
      try {
        const deps = ext.readRequirementsTxt(tmp);
        assert.strictEqual(deps.length, 2);
        assert.strictEqual(deps[0].name, 'flask');
        assert.strictEqual(deps[1].name, 'requests');
      } finally {
        fs.rmSync(tmp);
      }
    });

    it('handles package names with dots and hyphens', () => {
      const tmp = fixtures('names.txt');
      fs.writeFileSync(tmp, 'google-cloud-storage==2.10.0\nruamel.yaml==0.17.32\n');
      try {
        const deps = ext.readRequirementsTxt(tmp);
        assert.strictEqual(deps.length, 2);
        assert.ok(deps.some(d => d.name === 'google-cloud-storage'));
        assert.ok(deps.some(d => d.name === 'ruamel.yaml'));
      } finally {
        fs.rmSync(tmp);
      }
    });
  });
});
