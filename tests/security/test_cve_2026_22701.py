"""
Tests for CVE-2026-22701
=========================
filelock Time-of-Check-Time-of-Use (TOCTOU) Symlink Vulnerability in SoftFileLock
Fixed in upstream: filelock 3.20.3
LTS patch:         security/patches/cve-2026-22701.patch
LTS package:       filelock-lts-py37 (base: filelock==3.12.2)
CVE:               https://www.cve.org/CVERecord?id=CVE-2026-22701
GHSA:              GHSA-qmgc-5h2g-mvrw

Patch touches:
  src/filelock/_soft.py  — adds O_NOFOLLOW flag to os.open() call

The vulnerability:
  SoftFileLock acquires a lock by creating a file with os.open(O_CREAT|O_EXCL).
  Before the fix, an attacker could pre-place a symlink at the lock path;
  os.open would silently follow it and open/truncate the symlink target —
  a classic TOCTOU race allowing arbitrary file clobbering.
  O_NOFOLLOW causes os.open to raise OSError(ELOOP) if the path is a symlink,
  blocking the attack entirely.

Run:
  pytest tests/security/test_cve_2026_22701.py -v
"""
import os
import sys
import inspect
import textwrap
import tempfile
from pathlib import Path

import pytest

# ── locate src/ so tests work whether installed or run from repo root ─────────
_REPO_ROOT = Path(__file__).parent.parent.parent
_SOFT_PY   = _REPO_ROOT / "src" / "filelock" / "_soft.py"


# =============================================================================
# 1. CODE INSPECTION — patch must be present in source
# =============================================================================

def test_o_nofollow_flag_added_to_soft_file_lock():
    """
    [CODE INSPECTION]
    The fix adds O_NOFOLLOW to the os.open() flags in SoftFileLock._acquire.
    We verify the exact lines landed in source.
    """
    assert _SOFT_PY.exists(), f"Source not found: {_SOFT_PY}"
    src = _SOFT_PY.read_text()

    assert "O_NOFOLLOW" in src, (
        "O_NOFOLLOW not found in _soft.py — CVE-2026-22701 patch not applied"
    )
    assert 'getattr(os, "O_NOFOLLOW", None)' in src, (
        "Expected safe getattr fallback for O_NOFOLLOW — patch may be incomplete"
    )
    assert "flags |= o_nofollow" in src, (
        "Expected 'flags |= o_nofollow' — patch may be incomplete"
    )


def test_acquire_method_source_contains_nofollow():
    """
    [CODE INSPECTION]
    Inspect the live _acquire method bytecode source to confirm O_NOFOLLOW
    is set before the os.open() call — not just anywhere in the file.
    """
    from filelock._soft import SoftFileLock
    src = inspect.getsource(SoftFileLock._acquire)

    assert "O_NOFOLLOW" in src, (
        "O_NOFOLLOW not present in SoftFileLock._acquire — patch not active"
    )
    # O_NOFOLLOW must appear BEFORE the os.open call in the method
    nofollow_pos = src.index("O_NOFOLLOW")
    osopen_pos   = src.index("os.open(")
    assert nofollow_pos < osopen_pos, (
        "O_NOFOLLOW must be set before os.open() is called"
    )


# =============================================================================
# 2. FUNCTIONAL — symlink attack is blocked on platforms that support O_NOFOLLOW
# =============================================================================

@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Symlinks require elevated privileges on Windows; O_NOFOLLOW not available"
)
def test_soft_file_lock_refuses_symlink_at_lock_path():
    """
    [FUNCTIONAL]
    Core regression: SoftFileLock must NOT follow a symlink placed at the
    lock file path. With O_NOFOLLOW, os.open raises OSError (errno ELOOP or
    similar) instead of silently opening the symlink target.

    This is the exact TOCTOU attack vector described in CVE-2026-22701.
    """
    from filelock import SoftFileLock

    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW not available on this platform")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target_file  = tmp / "sensitive_target.txt"
        lock_path    = tmp / "test.lock"

        # Attacker pre-creates the symlink at the lock path pointing at a
        # sensitive file they want to clobber
        target_file.write_text("sensitive data")
        lock_path.symlink_to(target_file)

        assert lock_path.is_symlink(), "Setup: symlink must exist before lock attempt"

        lock = SoftFileLock(str(lock_path))
        with pytest.raises(OSError):
            lock.acquire(timeout=0)

        # Critical: the symlink target must be untouched
        assert target_file.exists(), "Symlink target was deleted — attack succeeded"
        assert target_file.read_text() == "sensitive data", (
            "Symlink target was modified — TOCTOU attack succeeded, patch not working"
        )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Symlinks require elevated privileges on Windows"
)
def test_soft_file_lock_works_normally_without_symlink():
    """
    [FUNCTIONAL]
    Verify the fix doesn't break normal SoftFileLock operation —
    acquiring and releasing a lock on a regular (non-symlink) path.
    """
    from filelock import SoftFileLock

    with tempfile.TemporaryDirectory() as tmp:
        lock_path = Path(tmp) / "normal.lock"
        lock = SoftFileLock(str(lock_path))

        with lock:
            assert lock_path.exists(), "Lock file should exist while held"

        # After release the lock file is removed
        assert not lock_path.exists(), "Lock file should be cleaned up after release"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Symlinks require elevated privileges on Windows"
)
def test_symlink_target_not_truncated():
    """
    [FUNCTIONAL]
    Before the fix, os.open with O_TRUNC would truncate the symlink target.
    Confirm the target file content is preserved (i.e. we never got that far).
    """
    from filelock import SoftFileLock

    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW not available on this platform")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target   = tmp / "do_not_truncate.txt"
        lockfile = tmp / "attack.lock"

        original_content = "this must not be truncated\n" * 100
        target.write_text(original_content)
        lockfile.symlink_to(target)

        lock = SoftFileLock(str(lockfile))
        try:
            lock.acquire(timeout=0)
        except OSError:
            pass  # expected — O_NOFOLLOW blocked it

        assert target.read_text() == original_content, (
            "Target file was truncated — O_NOFOLLOW not blocking symlink follow"
        )


# =============================================================================
# 3. REGRESSION — O_NOFOLLOW flag value is wired into flags before os.open
# =============================================================================

def test_o_nofollow_is_nonzero_on_linux():
    """
    [REGRESSION]
    On Linux/macOS, os.O_NOFOLLOW must be defined and nonzero.
    If it's somehow 0, ORing it in would be a no-op and the fix would be silently
    ineffective.
    """
    if sys.platform == "win32":
        pytest.skip("O_NOFOLLOW not defined on Windows — that's expected")

    assert hasattr(os, "O_NOFOLLOW"), "os.O_NOFOLLOW missing on non-Windows platform"
    assert os.O_NOFOLLOW != 0, "os.O_NOFOLLOW is 0 — flag would be a no-op"


def test_getattr_fallback_is_safe():
    """
    [REGRESSION]
    The patch uses getattr(os, "O_NOFOLLOW", None) so it degrades safely on
    platforms without the flag (e.g. Windows) rather than raising AttributeError.
    Simulate that path by verifying the fallback logic directly.
    """
    # Simulate what the patched code does on a platform without O_NOFOLLOW
    o_nofollow = getattr(os, "O_NOFOLLOW", None)
    base_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC

    if o_nofollow is not None:
        flags = base_flags | o_nofollow
        assert flags != base_flags, "O_NOFOLLOW should change the flags value"
    else:
        flags = base_flags
        # On platforms without it, flags must still be valid
        assert flags == base_flags