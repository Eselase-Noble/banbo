'use strict';

// Programmatic API for banbo.
//
//   const { run, scan, code } = require('banbo');
//   const result = await scan('example.com', { authorized: true });
//
// `run` is the low-level primitive (capture stdout/stderr/exit). `scan` and
// `code` are convenience wrappers that request `-o json` and parse the result.

const { spawn } = require('child_process');
const { resolveBinary } = require('./scripts/platform');

// banbo exit codes 0/1/2 all mean "the scan ran"; anything else is an error.
const OK_EXIT_CODES = new Set([0, 1, 2]);

/**
 * Build the child-process environment, forwarding AI API keys when provided.
 * @param {import('./index').RunOptions} [opts]
 */
function buildEnv(opts = {}) {
  const env = { ...process.env, ...(opts.env || {}) };
  if (opts.anthropicApiKey) env.ANTHROPIC_API_KEY = opts.anthropicApiKey;
  if (opts.openaiApiKey) env.OPENAI_API_KEY = opts.openaiApiKey;
  return env;
}

/**
 * Run the banbo binary with raw arguments.
 * @param {string[]} args
 * @param {import('./index').RunOptions} [opts]
 * @returns {Promise<{exitCode: number, stdout: string, stderr: string}>}
 */
function run(args, opts = {}) {
  return new Promise((resolve, reject) => {
    if (!Array.isArray(args)) {
      reject(new TypeError('banbo.run: args must be an array of strings'));
      return;
    }

    let binary;
    try {
      binary = resolveBinary();
    } catch (err) {
      reject(err);
      return;
    }

    const child = spawn(binary, args, {
      cwd: opts.cwd,
      env: buildEnv(opts),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let timer;

    if (opts.timeoutMs && opts.timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, opts.timeoutMs);
    }

    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      reject(new Error(`banbo: failed to start binary: ${err.message}`));
    });

    child.on('close', (codeOrNull) => {
      if (timer) clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`banbo: timed out after ${opts.timeoutMs}ms`));
        return;
      }
      resolve({ exitCode: codeOrNull == null ? 1 : codeOrNull, stdout, stderr });
    });
  });
}

/**
 * Convert scan options into CLI flags.
 * @param {import('./index').ScanOptions} [opts]
 */
function scanFlags(opts = {}) {
  const flags = [];
  // Authorization is required for active scanning; default to passing the flag
  // only when the caller explicitly opts in.
  if (opts.authorized) flags.push('--i-am-authorized');
  if (opts.ports) {
    const ports = Array.isArray(opts.ports) ? opts.ports.join(',') : String(opts.ports);
    flags.push('--ports', ports);
  }
  if (opts.timeout) flags.push('--timeout', String(opts.timeout));
  if (opts.active) flags.push('--active');
  if (opts.noAi) flags.push('--no-ai');
  // JSON parsing is confused by ANSI colour codes; always disable in library mode.
  flags.push('--no-color');
  return flags;
}

/**
 * Parse banbo JSON stdout, raising a descriptive error on malformed output.
 * @param {{exitCode: number, stdout: string, stderr: string}} res
 * @param {string} command
 */
function parseResult(res, command) {
  if (!OK_EXIT_CODES.has(res.exitCode)) {
    const detail = (res.stderr || res.stdout || '').trim();
    throw new Error(
      `banbo ${command} failed (exit ${res.exitCode})${detail ? `: ${detail}` : ''}`
    );
  }
  const text = res.stdout.trim();
  if (!text) {
    throw new Error(`banbo ${command} produced no JSON output on stdout.`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`banbo ${command} returned invalid JSON: ${err.message}`);
  }
}

/**
 * Run `banbo scan <target> -o json` and return the parsed ScanResult.
 * @param {string} target
 * @param {import('./index').ScanOptions} [opts]
 * @returns {Promise<import('./index').ScanResult>}
 */
async function scan(target, opts = {}) {
  if (!target || typeof target !== 'string') {
    throw new TypeError('banbo.scan: target must be a non-empty string');
  }
  const args = ['scan', target, '-o', 'json', ...scanFlags(opts)];
  const res = await run(args, opts);
  return parseResult(res, 'scan');
}

/**
 * Run `banbo code [path] -o json` and return the parsed ScanResult.
 * @param {string} [path] defaults to "." (current directory)
 * @param {import('./index').CodeOptions} [opts]
 * @returns {Promise<import('./index').ScanResult>}
 */
async function code(path = '.', opts = {}) {
  const args = ['code', path, '-o', 'json'];
  if (opts.full) args.push('--full');
  if (opts.noAi) args.push('--no-ai');
  const res = await run(args, opts);
  return parseResult(res, 'code');
}

/**
 * Run `banbo version` and return the trimmed version string.
 * @param {import('./index').RunOptions} [opts]
 * @returns {Promise<string>}
 */
async function version(opts = {}) {
  const res = await run(['version'], opts);
  if (!OK_EXIT_CODES.has(res.exitCode)) {
    throw new Error(`banbo version failed (exit ${res.exitCode})`);
  }
  return res.stdout.trim();
}

module.exports = { run, scan, code, version, OK_EXIT_CODES };
