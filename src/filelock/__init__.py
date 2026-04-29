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
    Detect whether upstream 'filelock' has been installed alongside this
    package and clobbered our patched files.

    This can happen silently when any tool with ``Requires: filelock`` is
    installed after filelock-lts-py38, causing pip to overwrite _unix.py/_windows.py
    with unpatched upstream versions and reintroducing CVEs.

    Detection strategy: iterate importlib.metadata distributions looking for
    a dist named 'filelock' that is NOT one of our lts packages.
    """
    try:
        try:
            import importlib.metadata as _md
        except ImportError:
            import importlib_metadata as _md  # type: ignore[no-redef]

        LTS_NAMES = {
            "filelock-lts",
            "filelock-lts-py38",
            "filelock_lts",
            "filelock_lts_py38",
        }

        for dist in _md.distributions():
            raw_name = dist.metadata.get("Name", "") or ""
            if raw_name.lower() == "filelock" and raw_name not in LTS_NAMES:
                version = dist.metadata.get("Version", "unknown")
                import warnings
                warnings.warn(
                    f"\n\n"
                    f"  *** SECURITY WARNING: filelock-lts-py38 may be compromised ***\n"
                    f"\n"
                    f"  Upstream 'filelock=={version}' is installed alongside this package.\n"
                    f"  If installed AFTER filelock-lts-py38, pip overwrote the patched\n"
                    f"  _unix.py/_windows.py with unpatched versions, reintroducing:\n"
                    f"\n"
                    f"    CVE-2025-68146 (HIGH)     — TOCTOU symlink attack\n"
                    f"    CVE-2026-22701 (MODERATE) — TOCTOU in SoftFileLock\n"
                    f"\n"
                    f"  To restore protection (Python 3.8 env):\n"
                    f"    pip uninstall filelock\n"
                    f"    pip install --force-reinstall filelock-lts-py38\n"
                    f"\n"
                    f"  Verify patch is active:\n"
                    f"    python -c \"import filelock; print(filelock.__version__)\"\n"
                    f"    # confirm dist is 'filelock-lts-py38', not 'filelock'\n",
                    stacklevel=2,
                    category=RuntimeWarning,
                )
                break

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
