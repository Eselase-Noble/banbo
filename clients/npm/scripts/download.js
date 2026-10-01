'use strict';

// Postinstall script: download + extract the correct prebuilt banbo binary for
// the host platform into ./vendor/banbo (or banbo.exe on Windows).
//
// Behaviour:
//   - If BANBO_BINARY is set, skip the download entirely (the user supplies it).
//   - If the binary is already vendored, skip (idempotent reinstalls).
//   - Download the release archive + checksums.txt, verify sha256 when available,
//     extract the executable, chmod +x, and exit quietly on success.
//   - Retry the download once on transient failure.
//   - On unsupported platforms, print a clear message and exit 0 so that `npm
//     install` does not hard-fail for users who intend to supply BANBO_BINARY.

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const {
  detectTarget,
  vendorDir,
  vendoredBinaryPath,
  archiveBaseName,
  archiveUrl,
  checksumsUrl,
  VERSION,
} = require('./platform');

function log(msg) {
  // Keep success output minimal; npm already shows the package name.
  process.stdout.write(`banbo: ${msg}\n`);
}

function warn(msg) {
  process.stderr.write(`banbo: ${msg}\n`);
}

/**
 * Fetch a URL into a Buffer, following redirects (GitHub release assets 302 to
 * a CDN). Uses the global fetch available in Node >= 18.
 */
async function fetchBuffer(url) {
  const res = await fetch(url, {
    redirect: 'follow',
    headers: { 'User-Agent': `banbo-npm/${VERSION}` },
  });
  if (!res.ok) {
    throw new Error(`GET ${url} -> HTTP ${res.status} ${res.statusText}`);
  }
  const arrayBuf = await res.arrayBuffer();
  return Buffer.from(arrayBuf);
}

async function withRetry(fn, attempts = 2) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) {
        warn(`download attempt ${i + 1} failed (${err.message}); retrying...`);
      }
    }
  }
  throw lastErr;
}

/**
 * Parse a goreleaser-style checksums.txt ("<sha256>  <filename>") and return the
 * expected hex digest for the given archive file name, or null if absent.
 */
function expectedSha(checksumsText, fileName) {
  const lines = checksumsText.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      const [sha, name] = [parts[0], parts[parts.length - 1]];
      if (name === fileName || name === `*${fileName}`) {
        return sha.toLowerCase();
      }
    }
  }
  return null;
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Minimal gzip + tar extractor that pulls a single named file out of a .tar.gz
 * buffer. Avoids a native/third-party tar dependency. Returns the file bytes or
 * null if not found.
 */
function extractFromTarGz(buf, wantedName) {
  const tar = zlib.gunzipSync(buf);
  const BLOCK = 512;
  let offset = 0;

  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK);
    // A full block of zeros marks the end of the archive.
    if (header.every((b) => b === 0)) break;

    const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const name = prefix ? `${prefix}/${rawName}` : rawName;

    const sizeField = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeField, 8) || 0;
    const typeFlag = String.fromCharCode(header[156]);

    const dataStart = offset + BLOCK;

    // Regular files: typeFlag '0' or '\0'.
    if (typeFlag === '0' || typeFlag === '\0') {
      const base = name.split('/').pop();
      if (base === wantedName || name === wantedName) {
        return tar.subarray(dataStart, dataStart + size);
      }
    }

    // Advance past this entry's data, rounded up to the next 512 block.
    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
  }
  return null;
}

/**
 * Extract a single named file from a .zip buffer. Supports stored (0) and
 * deflate (8) compression, which is what goreleaser produces. Returns bytes or
 * null if not found.
 */
function extractFromZip(buf, wantedName) {
  // Walk local file headers. Signature 0x04034b50.
  let offset = 0;
  while (offset + 30 <= buf.length) {
    const sig = buf.readUInt32LE(offset);
    if (sig !== 0x04034b50) break;

    const method = buf.readUInt16LE(offset + 8);
    const compSize = buf.readUInt32LE(offset + 18);
    const nameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);

    const nameStart = offset + 30;
    const name = buf.subarray(nameStart, nameStart + nameLen).toString('utf8');
    const dataStart = nameStart + nameLen + extraLen;
    const compData = buf.subarray(dataStart, dataStart + compSize);

    const base = name.split('/').pop();
    if (base === wantedName || name === wantedName) {
      if (method === 0) return Buffer.from(compData);
      if (method === 8) return zlib.inflateRawSync(compData);
      throw new Error(`unsupported zip compression method ${method}`);
    }

    offset = dataStart + compSize;
  }
  return null;
}

async function main() {
  // The user supplies their own binary; nothing to download.
  if (process.env.BANBO_BINARY && process.env.BANBO_BINARY.trim() !== '') {
    log(`BANBO_BINARY is set; skipping download.`);
    return;
  }

  let target;
  try {
    target = detectTarget();
  } catch (err) {
    // Do not fail the whole install; the user can still set BANBO_BINARY.
    warn(err.message);
    warn('skipping binary download.');
    return;
  }

  const dest = vendoredBinaryPath(target);
  if (fs.existsSync(dest)) {
    // Already installed (e.g. cached install, repeated postinstall).
    return;
  }

  const fileName = `${archiveBaseName(target)}.${target.ext}`;
  const url = archiveUrl(target);

  log(`downloading v${VERSION} binary for ${target.os}/${target.arch}...`);

  const archive = await withRetry(() => fetchBuffer(url));

  // Verify sha256 against checksums.txt when it is reachable. A missing or
  // unreachable checksums file is a warning, not a fatal error.
  try {
    const checksums = await withRetry(() => fetchBuffer(checksumsUrl()));
    const expected = expectedSha(checksums.toString('utf8'), fileName);
    if (expected) {
      const actual = sha256(archive);
      if (actual !== expected) {
        throw new Error(
          `checksum mismatch for ${fileName}: expected ${expected}, got ${actual}`
        );
      }
    } else {
      warn(`checksums.txt had no entry for ${fileName}; skipping verification.`);
    }
  } catch (err) {
    // A genuine mismatch must abort; a fetch/parse problem is tolerated.
    if (/checksum mismatch/.test(err.message)) throw err;
    warn(`could not verify checksum (${err.message}); continuing.`);
  }

  const exeBytes =
    target.ext === 'zip'
      ? extractFromZip(archive, target.exe)
      : extractFromTarGz(archive, target.exe);

  if (!exeBytes) {
    throw new Error(
      `could not find "${target.exe}" inside ${fileName}. The release layout may have changed.`
    );
  }

  // Write atomically: temp file then rename into place.
  fs.mkdirSync(vendorDir(), { recursive: true });
  const tmp = path.join(vendorDir(), `.${target.exe}.${process.pid}.tmp`);
  fs.writeFileSync(tmp, exeBytes);
  if (process.platform !== 'win32') {
    fs.chmodSync(tmp, 0o755);
  }
  fs.renameSync(tmp, dest);

  // Smoke-test the binary so a corrupt download surfaces now, not at first use.
  try {
    execFileSync(dest, ['version'], { stdio: 'ignore', timeout: 15000 });
  } catch (err) {
    warn(`installed binary failed a "version" smoke test (${err.message}).`);
  }
}

main().catch((err) => {
  warn(err && err.message ? err.message : String(err));
  warn(
    'binary download failed. You can retry with "npm rebuild banbo" or set ' +
      'BANBO_BINARY to a locally built banbo executable.'
  );
  // Fail the install so the problem is visible rather than silently broken.
  process.exit(1);
});
