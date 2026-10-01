#!/usr/bin/env node
'use strict';

// Thin shim: resolve the banbo binary and exec it, passing through argv, stdio,
// and the exit code. All CLI behaviour lives in the Go binary itself.

const { spawn } = require('child_process');
const { resolveBinary } = require('../scripts/platform');

let binary;
try {
  binary = resolveBinary();
} catch (err) {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
}

const child = spawn(binary, process.argv.slice(2), {
  stdio: 'inherit',
  // Propagate the current environment (incl. ANTHROPIC_API_KEY / OPENAI_API_KEY).
  env: process.env,
});

child.on('error', (err) => {
  process.stderr.write(`banbo: failed to start binary: ${err.message}\n`);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (signal) {
    // Mirror the conventional 128 + signal exit for killed children.
    const signals = { SIGINT: 2, SIGTERM: 15, SIGKILL: 9, SIGHUP: 1 };
    process.exit(128 + (signals[signal] || 0));
  }
  process.exit(code == null ? 1 : code);
});
