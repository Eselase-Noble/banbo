'use strict';

// Shared platform/arch mapping and path resolution for the banbo npm wrapper.
// Used by scripts/download.js (install time) and index.js / bin/banbo.js (run time).

const path = require('path');
const fs = require('fs');

const OWNER = 'Eselase-Noble';
const REPO = 'banbo';

// The release version this package pins to. Kept in lock-step with package.json
// so `npm install banbo@x.y.z` always fetches the matching binary.
const VERSION = require('../package.json').version;

// Map Node's process.platform -> release <os> token.
const OS_MAP = {
  linux: 'linux',
  darwin: 'darwin',
  win32: 'windows',
};

// Map Node's process.arch -> release <arch> token.
const ARCH_MAP = {
  x64: 'amd64',
  arm64: 'arm64',
};

/**
 * Resolve the current host to the banbo release tokens, or throw a clear error
 * if the platform/arch is unsupported.
 * @returns {{os: string, arch: string, ext: string, exe: string}}
 */
function detectTarget() {
  const os = OS_MAP[process.platform];
  const arch = ARCH_MAP[process.arch];

  if (!os || !arch) {
    const supported =
      'linux/x64, linux/arm64, darwin/x64, darwin/arm64, win32/x64, win32/arm64';
    throw new Error(
      `banbo: unsupported platform "${process.platform}/${process.arch}". ` +
        `Prebuilt binaries are available for: ${supported}. ` +
        `You can point banbo at a locally built binary with the BANBO_BINARY environment variable.`
    );
  }

  const ext = os === 'windows' ? 'zip' : 'tar.gz';
  const exe = os === 'windows' ? 'banbo.exe' : 'banbo';

  return { os, arch, ext, exe };
}

/** Directory where the downloaded binary is cached inside the package. */
function vendorDir() {
  return path.join(__dirname, '..', 'vendor');
}

/** Absolute path to the executable inside the vendor dir for the given target. */
function vendoredBinaryPath(target) {
  return path.join(vendorDir(), target.exe);
}

/** Base name of the release archive, e.g. "banbo_darwin_arm64". */
function archiveBaseName(target) {
  return `${REPO}_${target.os}_${target.arch}`;
}

/** Full download URL for the release archive. */
function archiveUrl(target, version = VERSION) {
  return `https://github.com/${OWNER}/${REPO}/releases/download/v${version}/${archiveBaseName(
    target
  )}.${target.ext}`;
}

/** Full download URL for the checksums file. */
function checksumsUrl(version = VERSION) {
  return `https://github.com/${OWNER}/${REPO}/releases/download/v${version}/checksums.txt`;
}

/**
 * Resolve the banbo executable to invoke at runtime.
 * Precedence: BANBO_BINARY env var -> vendored binary. Throws if neither exists.
 * @returns {string} absolute path to an existing executable
 */
function resolveBinary() {
  const override = process.env.BANBO_BINARY;
  if (override && override.trim() !== '') {
    if (!fs.existsSync(override)) {
      throw new Error(
        `banbo: BANBO_BINARY is set to "${override}" but that file does not exist.`
      );
    }
    return override;
  }

  const target = detectTarget();
  const vendored = vendoredBinaryPath(target);
  if (fs.existsSync(vendored)) {
    return vendored;
  }

  throw new Error(
    `banbo: binary not found at "${vendored}". ` +
      `The postinstall download may have failed. Re-run "npm rebuild banbo", ` +
      `reinstall the package, or set BANBO_BINARY to a locally built binary.`
  );
}

module.exports = {
  OWNER,
  REPO,
  VERSION,
  OS_MAP,
  ARCH_MAP,
  detectTarget,
  vendorDir,
  vendoredBinaryPath,
  archiveBaseName,
  archiveUrl,
  checksumsUrl,
  resolveBinary,
};
