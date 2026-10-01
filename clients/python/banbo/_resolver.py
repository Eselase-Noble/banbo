"""Locate (and if necessary download) the banbo Go binary.

The wrapper never reimplements scanning; it execs the prebuilt banbo binary that
is published as a GitHub release asset. This module is responsible for turning a
version string into an absolute path to an executable binary:

  * If ``BANBO_BINARY`` is set in the environment, that path is used verbatim.
  * Otherwise the correct release archive for the host OS/arch is downloaded once
    into a per-user cache directory, verified against ``checksums.txt`` (when the
    checksum file is available), extracted, made executable, and reused on every
    subsequent call.

Only the Python standard library is used (urllib, tarfile, zipfile, hashlib,
shutil) so that the package stays pure-Python with no runtime dependencies.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Optional

# Version of the banbo CLI this wrapper targets. Kept in sync with the package
# version declared in pyproject.toml and the upstream git tag ``v<VERSION>``.
BANBO_VERSION = "0.1.3"

# GitHub coordinates for the release assets.
_GITHUB_OWNER = "Eselase-Noble"
_GITHUB_REPO = "banbo"
_RELEASE_BASE = (
    "https://github.com/{owner}/{repo}/releases/download/v{version}".format
)

# Environment variable that, when set, short-circuits the download and points at
# an existing banbo binary (useful for development, air-gapped hosts, or tests).
ENV_BINARY = "BANBO_BINARY"

# Environment variable to override the cache root (otherwise a platform default).
ENV_CACHE_DIR = "BANBO_CACHE_DIR"


class ResolverError(RuntimeError):
    """Raised when the banbo binary cannot be located, downloaded, or verified."""


def detect_os() -> str:
    """Return the banbo ``<os>`` token for the current host."""
    system = platform.system()
    mapping = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}
    try:
        return mapping[system]
    except KeyError:
        raise ResolverError(
            "unsupported operating system {!r}; banbo publishes binaries for "
            "linux, darwin, and windows only".format(system)
        )


def detect_arch() -> str:
    """Return the banbo ``<arch>`` token for the current host."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    raise ResolverError(
        "unsupported CPU architecture {!r}; banbo publishes amd64 and arm64 "
        "binaries only".format(platform.machine())
    )


def _archive_ext(os_token: str) -> str:
    return "zip" if os_token == "windows" else "tar.gz"


def _binary_name(os_token: str) -> str:
    return "banbo.exe" if os_token == "windows" else "banbo"


def _asset_name(os_token: str, arch_token: str) -> str:
    return "banbo_{os}_{arch}.{ext}".format(
        os=os_token, arch=arch_token, ext=_archive_ext(os_token)
    )


def _release_url(version: str, asset: str) -> str:
    base = _RELEASE_BASE(owner=_GITHUB_OWNER, repo=_GITHUB_REPO, version=version)
    return "{base}/{asset}".format(base=base, asset=asset)


def cache_dir(version: str = BANBO_VERSION) -> Path:
    """Return the per-user cache directory for the given banbo version.

    Follows platformdirs-style conventions without taking a dependency:

      * Windows: ``%LOCALAPPDATA%\\banbo\\<version>``
      * macOS:   ``~/Library/Caches/banbo/<version>``
      * Linux:   ``$XDG_CACHE_HOME/banbo/<version>`` or ``~/.cache/banbo/<version>``

    An explicit ``BANBO_CACHE_DIR`` override wins over all of the above.
    """
    override = os.environ.get(ENV_CACHE_DIR)
    if override:
        root = Path(override).expanduser()
    elif sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA") or os.path.expanduser(
            "~\\AppData\\Local"
        )
        root = Path(local) / "banbo"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Caches" / "banbo"
    else:
        xdg = os.environ.get("XDG_CACHE_HOME")
        base = Path(xdg) if xdg else (Path.home() / ".cache")
        root = base / "banbo"
    return root / version


def _parse_checksums(text: str) -> Dict[str, str]:
    """Parse a ``checksums.txt`` (``<sha256>␣␣<filename>`` per line)."""
    sums: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0], parts[-1]
        # Filenames in checksums.txt may be prefixed with '*' (binary mode).
        sums[name.lstrip("*")] = digest.lower()
    return sums


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, *, timeout: float = 120.0) -> None:
    """Download ``url`` to ``dest`` atomically (download to a temp file, rename)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "banbo-python/{}".format(BANBO_VERSION)}
    )
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), suffix=".part")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as out:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                shutil.copyfileobj(resp, out)
        tmp_path.replace(dest)
    except urllib.error.HTTPError as exc:
        _safe_unlink(tmp_path)
        raise ResolverError(
            "failed to download {url}: HTTP {code} {reason}".format(
                url=url, code=exc.code, reason=exc.reason
            )
        ) from exc
    except (urllib.error.URLError, OSError) as exc:
        _safe_unlink(tmp_path)
        raise ResolverError(
            "failed to download {url}: {err}".format(url=url, err=exc)
        ) from exc
    except BaseException:
        _safe_unlink(tmp_path)
        raise


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _try_fetch_checksums(version: str, timeout: float) -> Optional[Dict[str, str]]:
    """Fetch and parse ``checksums.txt`` for the release, or ``None`` on failure.

    Checksum verification is best-effort: a release might not ship the file, or
    the network might block the extra request. In that case we skip verification
    rather than failing the whole install.
    """
    url = _release_url(version, "checksums.txt")
    req = urllib.request.Request(
        url, headers={"User-Agent": "banbo-python/{}".format(BANBO_VERSION)}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            text = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return None
    sums = _parse_checksums(text)
    return sums or None


def _extract(archive: Path, os_token: str, dest_dir: Path) -> Path:
    """Extract the banbo executable from ``archive`` into ``dest_dir``.

    Returns the path to the extracted executable. Entries are extracted
    defensively so that a malicious/malformed archive cannot write outside
    ``dest_dir`` (path traversal via ``..`` or absolute members).
    """
    binary_name = _binary_name(os_token)
    dest_dir = dest_dir.resolve()

    if _archive_ext(os_token) == "zip":
        with zipfile.ZipFile(archive) as zf:
            members = zf.namelist()
            _guard_members(members, dest_dir)
            zf.extractall(dest_dir)
    else:
        with tarfile.open(archive, "r:gz") as tf:
            members = [m.name for m in tf.getmembers()]
            _guard_members(members, dest_dir)
            tf.extractall(dest_dir)  # noqa: S202 - members validated above

    found = _find_binary(dest_dir, binary_name)
    if found is None:
        raise ResolverError(
            "archive {name} did not contain an executable named {bin!r}".format(
                name=archive.name, bin=binary_name
            )
        )
    return found


def _guard_members(members, dest_dir: Path) -> None:
    for name in members:
        if not name:
            continue
        target = (dest_dir / name).resolve()
        if dest_dir != target and dest_dir not in target.parents:
            raise ResolverError(
                "refusing to extract unsafe archive member {!r}".format(name)
            )


def _find_binary(root: Path, binary_name: str) -> Optional[Path]:
    direct = root / binary_name
    if direct.is_file():
        return direct
    for path in root.rglob(binary_name):
        if path.is_file():
            return path
    return None


def _make_executable(path: Path) -> None:
    if os.name == "nt":
        return
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def resolve(version: str = BANBO_VERSION, *, timeout: float = 120.0) -> Path:
    """Return an absolute path to an executable banbo binary.

    The binary is resolved in this order:

      1. ``$BANBO_BINARY`` if set (used verbatim, must exist and be executable).
      2. A previously cached binary for ``version`` under the user cache dir.
      3. A freshly downloaded, verified, and extracted binary (cached for reuse).

    :raises ResolverError: if no usable binary can be produced.
    """
    override = os.environ.get(ENV_BINARY)
    if override:
        p = Path(override).expanduser()
        if not p.is_file():
            raise ResolverError(
                "{env}={path!r} does not point to an existing file".format(
                    env=ENV_BINARY, path=override
                )
            )
        return p.resolve()

    os_token = detect_os()
    arch_token = detect_arch()
    binary_name = _binary_name(os_token)

    version_dir = cache_dir(version)
    cached = version_dir / binary_name
    if cached.is_file():
        return cached.resolve()

    version_dir.mkdir(parents=True, exist_ok=True)

    asset = _asset_name(os_token, arch_token)
    url = _release_url(version, asset)
    archive_path = version_dir / asset

    _download(url, archive_path, timeout=timeout)

    # Best-effort integrity check against the release checksums.txt.
    checksums = _try_fetch_checksums(version, timeout)
    if checksums is not None and asset in checksums:
        actual = _sha256(archive_path)
        expected = checksums[asset]
        if actual != expected:
            _safe_unlink(archive_path)
            raise ResolverError(
                "checksum mismatch for {asset}: expected {exp}, got {act}".format(
                    asset=asset, exp=expected, act=actual
                )
            )

    extracted = _extract(archive_path, os_token, version_dir)

    # Normalize: make sure the executable lives at <version_dir>/<binary_name>
    # so the cache-hit fast path above finds it next time.
    if extracted.resolve() != cached.resolve():
        shutil.move(str(extracted), str(cached))

    _make_executable(cached)
    _safe_unlink(archive_path)
    return cached.resolve()
