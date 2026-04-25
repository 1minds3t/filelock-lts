import os
import pytest
import tempfile
from pathlib import Path

_SRC = Path(__file__).parent.parent.parent / "src" / "filelock" / "_soft.py"

# ─────────────────────────────────────────────────────────────────────────────
# 1. CODE INSPECTION
# ─────────────────────────────────────────────────────────────────────────────

def test_cve_2026_22701_fix_present_in_source():
    """Verify O_NOFOLLOW guard landed in _soft.py"""
    src = _SRC.read_text()
    assert "O_NOFOLLOW" in src, "CVE-2026-22701 patch not applied — O_NOFOLLOW missing"
    assert "getattr(os" in src, "Expected getattr(os, 'O_NOFOLLOW', None) pattern missing"

# ─────────────────────────────────────────────────────────────────────────────
# 2. FUNCTIONAL
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW not available on this platform (Windows)")
def test_cve_2026_22701_symlink_rejected():
    """SoftFileLock must refuse to acquire a lock through a symlink."""
    from filelock import SoftFileLock

    with tempfile.TemporaryDirectory() as tmp:
        real_lock = Path(tmp) / "real.lock"
        symlink_lock = Path(tmp) / "attack.lock"

        real_lock.touch()
        symlink_lock.symlink_to(real_lock)

        with pytest.raises(OSError):
            lock = SoftFileLock(str(symlink_lock))
            lock.acquire(timeout=0)

# ─────────────────────────────────────────────────────────────────────────────
# 3. REGRESSION
# ─────────────────────────────────────────────────────────────────────────────

def test_cve_2026_22701_normal_lock_still_works():
    """Normal lock acquisition must still work after the patch."""
    from filelock import SoftFileLock

    with tempfile.TemporaryDirectory() as tmp:
        lock_path = Path(tmp) / "normal.lock"
        lock = SoftFileLock(str(lock_path))
        with lock:
            assert lock_path.exists()