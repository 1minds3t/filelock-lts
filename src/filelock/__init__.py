"""
A platform independent file lock that supports the with-statement.

.. autodata:: filelock.__version__
   :no-value:

"""

from __future__ import annotations

import sys
import warnings
from typing import TYPE_CHECKING





def _check_clobber():
    """
    Verify that CVE-patched files have not been silently overwritten after
    install, and detect co-installation of upstream filelock.

    Two detection layers:

    1. RECORD-based integrity check (primary):
       Reads our own dist-info RECORD (written by pip at install time) and
       verifies that _unix.py, _windows.py, and _soft.py on disk still match
       the recorded SHA256 hashes. A mismatch means a subsequent install
       overwrote our files — the CVEs may be reintroduced regardless of
       whether upstream dist-info is present.

    2. Co-install detection (secondary):
       Scans installed distributions for a bare 'filelock' dist that is not
       one of our LTS packages. Presence indicates a likely clobber, even if
       the RECORD check passed (e.g. if the upstream install happened to write
       identical bytes, which is unlikely but possible in edge cases).

    Detection is non-fatal — failures in this check will not interrupt imports.
    """
    try:
        try:
            import importlib.metadata as _md
        except ImportError:
            import importlib_metadata as _md  # type: ignore[no-redef]

        import hashlib
        import base64
        from pathlib import Path

        # Files whose integrity we guarantee. __init__.py intentionally
        # excluded — it contains this function and changes across versions.
        PATCHED_FILES = {"_unix.py", "_windows.py", "_soft.py"}

        LTS_NAMES = {
            "filelock-lts",
            "filelock-lts-py38",
            "filelock_lts",
            "filelock_lts_py38",
        }

        import csv

        _lts_normalized = {n.lower().replace("-", "_") for n in LTS_NAMES}

        # ── Single pass: find our dist + upstream in one loop ─────────────────
        compromised = []
        our_dist = None
        upstream_version = None
        for dist in _md.distributions():
            raw = (dist.metadata.get("Name", "") or "").lower().replace("-", "_")
            if raw in _lts_normalized:
                our_dist = dist
            elif raw == "filelock":
                upstream_version = dist.metadata.get("Version", "unknown")
            if our_dist is not None and upstream_version is not None:
                break

        # ── Layer 1: RECORD-based integrity ──────────────────────────────────
        if our_dist is not None:
            record_text = our_dist.read_text("RECORD")
            if not record_text:
                # Missing RECORD = editable install, broken install, or tampering.
                # We can't verify integrity, so flag it.
                compromised.append("RECORD missing or unreadable (editable install or tampered package)")
            else:
                site_root = Path(our_dist.locate_file(""))
                for row in csv.reader(record_text.splitlines()):
                    if len(row) < 2:
                        continue
                    rel_path, recorded_hash = row[0].strip(), row[1].strip()
                    filename = Path(rel_path).name
                    if filename not in PATCHED_FILES:
                        continue
                    if not recorded_hash.startswith("sha256:"):
                        continue

                    actual = site_root / rel_path
                    if not actual.exists():
                        compromised.append(f"{filename} (missing at {actual})")
                        continue

                    digest = base64.urlsafe_b64encode(
                        hashlib.sha256(actual.read_bytes()).digest()
                    ).rstrip(b"=").decode()

                    expected = recorded_hash[len("sha256:"):]
                    if digest != expected:
                        compromised.append(
                            f"{filename} (hash mismatch — expected {expected[:12]}…, got {digest[:12]}…)"
                        )

        # ── Emit warning if either layer fires ───────────────────────────────
        if compromised or upstream_version:
            import warnings
            lines = [
                "\n\n  *** SECURITY WARNING: filelock-lts-py38 integrity check failed ***\n",
            ]
            if compromised:
                lines += [
                    "  Patched files have been modified since install:",
                    *[f"    • {f}" for f in compromised],
                    "  CVE-2025-68146 and CVE-2026-22701 patches may no longer be active.",
                ]
            if upstream_version:
                if compromised:
                    lines.append("")
                lines.append(
                    f"  Upstream filelock=={upstream_version} is co-installed alongside this package."
                )
                if not compromised:
                    lines.append(
                        "  If installed after filelock-lts-py38, pip may have overwritten the patched files."
                    )
            lines += [
                "",
                "  To restore protection (Python 3.8 env):",
                "    pip uninstall filelock -y",
                "    pip install --force-reinstall filelock-lts-py38",
                "",
                "  To verify patch integrity after reinstall:",
                "    python -c \"",
                "      import importlib.metadata as m, hashlib, base64, pathlib",
                "      d = next(x for x in m.distributions()",
                "               if (x.metadata.get('Name','') or '').lower().replace('-','_')",
                "               in {'filelock_lts_py38', 'filelock_lts'})",
                "      rec = d.read_text('RECORD')",
                "      print('RECORD found — run full integrity check via filelock-lts-py38')",
                "    \"",
                "    # Or simply: pip show filelock-lts-py38",
                "    # Confirm dist is 'filelock-lts-py38', not bare 'filelock'",
                "",
            ]
            warnings.warn("\n".join(lines), RuntimeWarning, stacklevel=2)

    except Exception:
        # Never crash the import over a metadata check.
        pass


_check_clobber()




from ._api import AcquireReturnProxy, BaseFileLock
from ._error import Timeout
from ._soft import SoftFileLock
from ._unix import UnixFileLock, has_fcntl
from ._windows import WindowsFileLock
from .asyncio import (
    AsyncAcquireReturnProxy,
    AsyncSoftFileLock,
    AsyncUnixFileLock,
    AsyncWindowsFileLock,
    BaseAsyncFileLock,
)
from .version import version

#: version of the project as a string
__version__: str = version


if sys.platform == "win32":  # pragma: win32 cover
    _FileLock: type[BaseFileLock] = WindowsFileLock
    _AsyncFileLock: type[BaseAsyncFileLock] = AsyncWindowsFileLock
else:  # pragma: win32 no cover # noqa: PLR5501
    if has_fcntl:
        _FileLock: type[BaseFileLock] = UnixFileLock
        _AsyncFileLock: type[BaseAsyncFileLock] = AsyncUnixFileLock
    else:
        _FileLock = SoftFileLock
        _AsyncFileLock = AsyncSoftFileLock
        if warnings is not None:
            warnings.warn("only soft file lock is available", stacklevel=2)

if TYPE_CHECKING:
    FileLock = SoftFileLock
    AsyncFileLock = AsyncSoftFileLock
else:
    #: Alias for the lock, which should be used for the current platform.
    FileLock = _FileLock
    AsyncFileLock = _AsyncFileLock


__all__ = [
    "AcquireReturnProxy",
    "AsyncAcquireReturnProxy",
    "AsyncFileLock",
    "AsyncSoftFileLock",
    "AsyncUnixFileLock",
    "AsyncWindowsFileLock",
    "BaseAsyncFileLock",
    "BaseFileLock",
    "FileLock",
    "SoftFileLock",
    "Timeout",
    "UnixFileLock",
    "WindowsFileLock",
    "__version__",
]
