// Minimal vscode mock — just enough so extension.js can be require()'d for
// unit-testing its pure functions.  None of the mock methods do anything;
// they exist only to prevent crashes at import time.
'use strict';

const { EventEmitter } = require('events');

class TreeItem {
  constructor(label, collapsibleState) {
    this.label = label;
    this.collapsibleState = collapsibleState;
    this.iconPath = undefined;
    this.description = undefined;
    this.tooltip = undefined;
    this.command = undefined;
    this.resourceUri = undefined;
    this.contextValue = undefined;
  }
}

const TreeItemCollapsibleState = { None: 0, Expanded: 1, Collapsed: 2 };

class ThemeIcon {
  constructor(id) { this.id = id; }
}

class ThemeColor {
  constructor(id) { this.id = id; }
}

const Uri = {
  file: (p) => ({ fsPath: p, scheme: 'file', path: p }),
  parse: (s) => ({ toString: () => s }),
};

const StatusBarAlignment = { Left: 1, Right: 2 };
const ProgressLocation = { Window: 1, Notification: 2 };

// Mutable state so tests can set up workspace folders etc.
let workspaceFolders = [];
let extensionsAll = [];

const mockWindow = {
  createOutputChannel: () => ({ appendLine: () => {}, append: () => {}, show: () => {}, dispose: () => {} }),
  showInformationMessage: () => Promise.resolve(undefined),
  showWarningMessage: () => Promise.resolve(undefined),
  showErrorMessage: () => Promise.resolve(undefined),
  withProgress: (_opts, fn) => fn(),
  onDidStartTerminalShellExecution: undefined,
  createStatusBarItem: () => ({ show: () => {}, dispose: () => {}, text: '', tooltip: '' }),
};

const mockWorkspace = {
  getConfiguration: () => ({
    get: (key, defaultValue) => {
      const defaults = {
        suspectScopes: [],
        suspectPackages: [],
        scanOnStartup: false,
        watchTerminal: false,
        checkHardening: false,
        osvCheck: false,
        configIntegrity: false,
        extIntegrity: false,
        extensionRecheckMinutes: 0,
        minDependencyAgeDays: 7,
        maxAgeChecks: 40,
        ageCheckOnStartup: false,
      };
      return key in defaults ? defaults[key] : defaultValue;
    },
  }),
  get workspaceFolders() { return workspaceFolders; },
  createFileSystemWatcher: () => new EventEmitter(),
  findFiles: () => Promise.resolve([]),
};

const mockExtensions = {
  get all() { return extensionsAll; },
  get onDidChange() { return undefined; },
};

const mockGlobalState = {
  _store: {},
  get: function (key, defaultValue) {
    try { return key in this._store ? JSON.parse(JSON.stringify(this._store[key])) : defaultValue; }
    catch { return defaultValue; }
  },
  update: function (key, value) { this._store[key] = value; return Promise.resolve(); },
};

let _ctx = {
  globalState: mockGlobalState,
  extension: { id: 'thumper' },
  subscriptions: [],
};

const vscode = {
  window: mockWindow,
  workspace: mockWorkspace,
  extensions: mockExtensions,
  TreeItem,
  TreeItemCollapsibleState,
  EventEmitter,
  ThemeIcon,
  ThemeColor,
  Uri,
  StatusBarAlignment,
  ProgressLocation,
  RelativePattern: function (base, pattern) { this.base = base; this.pattern = pattern; },
  // expose test hooks
  __setWorkspaceFolders: (f) => { workspaceFolders = f; },
  __setExtensions: (e) => { extensionsAll = e; },
  __setCtx: (c) => { _ctx = Object.assign(_ctx, c); },
  __reset: () => {
    workspaceFolders = [];
    extensionsAll = [];
    mockGlobalState._store = {};
  },
};

module.exports = vscode;
