"""banbo — Python client for the banbo layered security scanner.

This package is a thin, pure-Python wrapper around the prebuilt ``banbo`` Go CLI.
It does **not** reimplement any scanning logic; it downloads the correct release
binary for your platform on first use and execs it, parsing the JSON it emits
into typed dataclasses.

Quick start (library)::

    import banbo

    result = banbo.scan("example.com", i_am_authorized=True)
    print(result.summary.total, "findings")
    for f in result.findings:
        print(f.severity, f.title, f.asset)

    code_result = banbo.code("./src")

Quick start (raw passthrough)::

    cp = banbo.run(["version"])
    print(cp.stdout)

Environment:
    ``BANBO_BINARY``     path to an existing banbo binary (skips the download).
    ``BANBO_CACHE_DIR``  override the per-user cache directory.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from ._resolver import BANBO_VERSION, ResolverError, resolve

__all__ = [
    "run",
    "scan",
    "code",
    "version",
    "ScanResult",
    "Finding",
    "Severity",
    "Counts",
    "ModuleError",
    "CompletedProcess",
    "BanboError",
    "ResolverError",
    "BANBO_VERSION",
    "__version__",
]

__version__ = BANBO_VERSION

# Exit codes 0 (clean/info), 1 (low/medium), and 2 (high/critical) all mean the
# scan "ran OK" and produced findings. Any other code is a genuine error.
_OK_EXIT_CODES = frozenset({0, 1, 2})


class BanboError(RuntimeError):
    """Raised when the banbo CLI fails to run or returns an error exit code."""

    def __init__(self, message: str, *, returncode: Optional[int] = None,
                 stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Severity(str, Enum):
    """Finding severity, ordered from least to most serious.

    Subclasses ``str`` so values compare and serialize as their JSON tokens,
    e.g. ``Severity.HIGH == "high"``.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_json(cls, value: Optional[str]) -> Optional["Severity"]:
        if value is None:
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            raise ValueError("unknown severity {!r}".format(value))

    @property
    def rank(self) -> int:
        """Numeric rank (info=0 .. critical=4) for ordering/comparisons."""
        order = (
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        )
        return order.index(self)


@dataclass
class Finding:
    """A single security finding reported by banbo."""

    id: str
    title: str
    layer: str
    severity: Severity
    asset: str
    evidence: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cvss: Optional[float] = None
    compliance: List[str] = field(default_factory=list)
    ai_explanation: Optional[str] = None
    ai_remediation: Optional[str] = None
    business_impact: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Finding":
        return cls(
            id=d.get("id", ""),
            title=d.get("title", ""),
            layer=d.get("layer", ""),
            severity=Severity.from_json(d.get("severity")) or Severity.INFO,
            asset=d.get("asset", ""),
            evidence=d.get("evidence"),
            description=d.get("description"),
            remediation=d.get("remediation"),
            references=list(d.get("references") or []),
            cvss=d.get("cvss"),
            compliance=list(d.get("compliance") or []),
            ai_explanation=d.get("ai_explanation"),
            ai_remediation=d.get("ai_remediation"),
            business_impact=d.get("business_impact"),
        )


@dataclass
class Counts:
    """Per-severity finding counts plus the overall total."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    @classmethod
    def from_dict(cls, d: Optional[Mapping[str, Any]]) -> "Counts":
        d = d or {}
        return cls(
            critical=int(d.get("critical", 0)),
            high=int(d.get("high", 0)),
            medium=int(d.get("medium", 0)),
            low=int(d.get("low", 0)),
            info=int(d.get("info", 0)),
            total=int(d.get("total", 0)),
        )


@dataclass
class ModuleError:
    """A non-fatal error reported by an individual scanning module."""

    module: str
    error: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ModuleError":
        return cls(module=d.get("module", ""), error=d.get("error", ""))


@dataclass
class ScanResult:
    """Parsed result of a ``banbo scan`` or ``banbo code`` run."""

    target: str
    host: str
    started_at: str
    duration_ms: int
    findings: List[Finding] = field(default_factory=list)
    summary: Counts = field(default_factory=Counts)
    errors: List[ModuleError] = field(default_factory=list)
    exit_code: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any], *, exit_code: int = 0) -> "ScanResult":
        return cls(
            target=d.get("target", ""),
            host=d.get("host", ""),
            started_at=d.get("started_at", ""),
            duration_ms=int(d.get("duration_ms", 0)),
            findings=[Finding.from_dict(f) for f in (d.get("findings") or [])],
            summary=Counts.from_dict(d.get("summary")),
            errors=[ModuleError.from_dict(e) for e in (d.get("errors") or [])],
            exit_code=exit_code,
            raw=dict(d),
        )

    @property
    def ok(self) -> bool:
        """True if the scan ran successfully (exit code 0, 1, or 2)."""
        return self.exit_code in _OK_EXIT_CODES

    def findings_at_least(self, severity: Severity) -> List[Finding]:
        """Return findings with severity >= ``severity``."""
        return [f for f in self.findings if f.severity.rank >= severity.rank]


class CompletedProcess:
    """Result of :func:`run`: a lightweight, ``subprocess``-like container."""

    __slots__ = ("args", "returncode", "stdout", "stderr")

    def __init__(self, args: Sequence[str], returncode: int,
                 stdout: str, stderr: str) -> None:
        self.args = list(args)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ran_ok(self) -> bool:
        """True if banbo ran and produced results (exit code 0, 1, or 2)."""
        return self.returncode in _OK_EXIT_CODES

    def __repr__(self) -> str:
        return (
            "CompletedProcess(args={args!r}, returncode={rc})".format(
                args=self.args, rc=self.returncode
            )
        )


def run(
    args: Sequence[str],
    *,
    env: Optional[Mapping[str, str]] = None,
    check: bool = False,
    timeout: Optional[float] = None,
) -> CompletedProcess:
    """Run the banbo binary with ``args`` and capture its output.

    :param args: arguments passed after the binary name, e.g.
        ``["scan", "example.com", "-o", "json"]``.
    :param env: optional environment mapping; when ``None`` the current
        process environment is inherited.
    :param check: when True, raise :class:`BanboError` on *any* non-"ran OK"
        exit code (anything other than 0, 1, or 2).
    :param timeout: optional timeout in seconds forwarded to ``subprocess``.
    :returns: a :class:`CompletedProcess` with captured stdout/stderr.
    :raises BanboError: if the binary cannot be run, or (with ``check``) on error.
    :raises ResolverError: if the binary cannot be resolved/downloaded.
    """
    binary = resolve()
    cmd = [str(binary)] + [str(a) for a in args]
    try:
        proc = subprocess.run(
            cmd,
            env=dict(env) if env is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,  # text mode; 3.8-compatible alias for text=True
        )
    except FileNotFoundError as exc:
        raise BanboError(
            "banbo binary not found at {path}".format(path=binary)
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise BanboError(
            "banbo timed out after {t}s".format(t=timeout),
            returncode=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        ) from exc

    result = CompletedProcess(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
    if check and not result.ran_ok:
        raise BanboError(
            "banbo exited with error code {rc}".format(rc=result.returncode),
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    return result


def _bool_flags(opts: Mapping[str, Any], mapping: Mapping[str, str]) -> List[str]:
    flags: List[str] = []
    for key, flag in mapping.items():
        if opts.get(key):
            flags.append(flag)
    return flags


def _parse_json_result(cp: CompletedProcess) -> ScanResult:
    if not cp.ran_ok:
        raise BanboError(
            "banbo exited with error code {rc}: {err}".format(
                rc=cp.returncode, err=(cp.stderr or "").strip()
            ),
            returncode=cp.returncode,
            stdout=cp.stdout,
            stderr=cp.stderr,
        )
    try:
        data = json.loads(cp.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        raise BanboError(
            "could not parse banbo JSON output: {err}".format(err=exc),
            returncode=cp.returncode,
            stdout=cp.stdout,
            stderr=cp.stderr,
        ) from exc
    return ScanResult.from_dict(data, exit_code=cp.returncode)


def scan(
    target: str,
    *,
    i_am_authorized: bool = False,
    ports: Optional[Union[str, Sequence[Union[str, int]]]] = None,
    timeout: Optional[str] = None,
    active: bool = False,
    no_ai: bool = False,
    no_color: bool = True,
    env: Optional[Mapping[str, str]] = None,
    run_timeout: Optional[float] = None,
) -> ScanResult:
    """Run ``banbo scan <target> -o json`` and return a parsed :class:`ScanResult`.

    :param target: the host/URL/IP to scan.
    :param i_am_authorized: pass ``-y/--i-am-authorized`` to confirm authorization
        for active probing. Required by banbo for anything beyond passive checks.
    :param ports: ports to scan, as a comma string (``"80,443"``) or a sequence
        (``[80, 443]``); forwarded as ``--ports``.
    :param timeout: per-operation timeout understood by banbo, e.g. ``"5s"``;
        forwarded as ``--timeout``.
    :param active: enable active probing (``--active``).
    :param no_ai: disable AI enrichment (``--no-ai``).
    :param no_color: pass ``--no-color`` (default True so captured output is clean).
    :param env: optional environment for the child process.
    :param run_timeout: wall-clock timeout in seconds for the subprocess.
    :returns: the parsed :class:`ScanResult`.
    """
    args: List[str] = ["scan", str(target), "-o", "json"]
    args += _bool_flags(
        {
            "i_am_authorized": i_am_authorized,
            "active": active,
            "no_ai": no_ai,
            "no_color": no_color,
        },
        {
            "i_am_authorized": "--i-am-authorized",
            "active": "--active",
            "no_ai": "--no-ai",
            "no_color": "--no-color",
        },
    )
    if ports is not None:
        if isinstance(ports, (str, bytes)):
            ports_str = ports if isinstance(ports, str) else ports.decode()
        else:
            ports_str = ",".join(str(p) for p in ports)
        args += ["--ports", ports_str]
    if timeout is not None:
        args += ["--timeout", str(timeout)]

    cp = run(args, env=env, timeout=run_timeout)
    return _parse_json_result(cp)


def code(
    path: str = ".",
    *,
    full: bool = False,
    no_ai: bool = False,
    no_color: bool = True,
    env: Optional[Mapping[str, str]] = None,
    run_timeout: Optional[float] = None,
) -> ScanResult:
    """Run ``banbo code [path] -o json`` and return a parsed :class:`ScanResult`.

    :param path: source directory (or file) to review; defaults to ``.``.
    :param full: pass ``--full`` for a deeper/complete review.
    :param no_ai: disable AI enrichment (``--no-ai``).
    :param no_color: pass ``--no-color`` (default True).
    :param env: optional environment for the child process.
    :param run_timeout: wall-clock timeout in seconds for the subprocess.
    :returns: the parsed :class:`ScanResult`.
    """
    args: List[str] = ["code", str(path), "-o", "json"]
    args += _bool_flags(
        {"full": full, "no_ai": no_ai, "no_color": no_color},
        {"full": "--full", "no_ai": "--no-ai", "no_color": "--no-color"},
    )
    cp = run(args, env=env, timeout=run_timeout)
    return _parse_json_result(cp)


def version() -> str:
    """Return the version string reported by ``banbo version``."""
    cp = run(["version"], check=True)
    return cp.stdout.strip()
