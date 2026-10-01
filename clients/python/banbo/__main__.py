"""CLI shim: exec the banbo binary, passing through argv and the exit code.

This makes both entry points behave identically to invoking the native binary:

    banbo scan example.com -o json -y        # console_scripts entry point
    python -m banbo scan example.com -o json # module execution

We resolve (downloading on first use) and then run the binary as a subprocess,
streaming its stdout/stderr through unchanged and propagating its exit code.
"""

from __future__ import annotations

import subprocess
import sys
from typing import List, Optional

from ._resolver import ResolverError, resolve


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns the banbo exit code (also used by console_scripts)."""
    args = list(sys.argv[1:] if argv is None else argv)

    try:
        binary = resolve()
    except ResolverError as exc:
        print("banbo: {}".format(exc), file=sys.stderr)
        return 70  # EX_SOFTWARE: internal/setup failure

    cmd = [str(binary)] + args
    try:
        # Inherit stdin/stdout/stderr so interactive prompts, colour, and
        # streaming output all behave exactly like the native binary.
        proc = subprocess.run(cmd)
    except FileNotFoundError:
        print("banbo: binary not found at {}".format(binary), file=sys.stderr)
        return 70
    except KeyboardInterrupt:
        return 130  # 128 + SIGINT
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
