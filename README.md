# filelock-lts-py37 🛡️

> **Disclaimer:** This project is not affiliated with, endorsed by, or associated with the official `filelock` maintainers. All patches are independently maintained and provided on a best-effort basis to support legacy Python environments.

Security-patched backport of [`filelock`](https://github.com/tox-dev/filelock) for **Python 3.7**, maintained as a drop-in replacement for installations that cannot upgrade to modern Python.

---

## Why This Exists

The upstream `filelock` project ships security fixes only for currently-supported Python versions. When a vulnerability is patched in `filelock 3.20+`, the fix is unavailable to the millions of production systems still running Python 3.7.

This package backports those fixes — with full test coverage and transparent diffs — so legacy environments get the same security guarantees as modern ones.

---

## Installation

```bash
pip install filelock-lts-py37
```

It exposes the same public API as `filelock`. No code changes required:

```python
from filelock import FileLock, SoftFileLock, Timeout

lock = FileLock("my.lock")
with lock:
    # safe
```

---

## Security Coverage

| CVE | Severity | Base Package Fixed | Our Backport | Patch |
|:----|:---------|:------------------|:-------------|:------|
| [CVE-2025-68146](https://nvd.nist.gov/vuln/detail/CVE-2025-68146) | HIGH | filelock 3.20.1 | `2025.68146.2` | [patch](security/patches/cve-2025-68146.patch) |
| [CVE-2026-22701](https://www.cve.org/CVERecord?id=CVE-2026-22701) | MODERATE | filelock 3.20.3 | `2026.22701` | [patch](security/patches/cve-2026-22701.patch) |

### CVE-2025-68146 — Symlink TOCTOU in UnixFileLock and WindowsFileLock

Local attackers could pre-place a symlink (Linux/macOS) or reparse point/junction (Windows) at a lock file path, causing `filelock` to follow it and open or truncate an arbitrary target file.

**Unix/Linux/macOS fix:** `O_NOFOLLOW` flag added to `os.open()` in `_unix.py` and `_soft.py`. The kernel now refuses to follow symlinks at the lock path.

**Windows fix:** Explicit reparse point detection via `kernel32.GetFileAttributesW` in `_windows.py`. Lock acquisition is refused if the target path is a symbolic link or directory junction.

### CVE-2026-22701 — Symlink TOCTOU in SoftFileLock

Same class of vulnerability affecting `SoftFileLock` specifically. The `O_NOFOLLOW` guard was not applied to the soft lock path.

**Fix:** `getattr(os, "O_NOFOLLOW", None)` pattern applied in `_soft.py`, with a safe no-op fallback on platforms that do not expose the flag.

---

## Base Package

| Property | Value |
|:---------|:------|
| Base | `filelock 3.12.2` |
| Released | 2023-06-12 |
| Python | `>=3.7, <3.8` |
| License | MIT |

The source tree is `filelock 3.12.2` with only the security patches applied. You can verify this yourself:

```bash
# Compare local source against upstream 3.12.2
python check_local_vs_upstream.py
```

Diffs are strictly limited to `_unix.py`, `_soft.py`, and `_windows.py`. All other files are identical to the upstream release.

---

## Versioning

Versions follow the pattern `YEAR.CVEID[.PATCH]`:

- `2025.68146.2` — CVE-2025-68146 backport, second revision
- `2026.22701` — CVE-2026-22701 backport

---

## Security Audit Trail

All patch work is documented in [`security/`](security/):

```
security/
├── analysis/          # Pre- and post-patch analysis for each CVE
├── patches/           # The actual .patch files applied to this repo
└── upstream/          # Original upstream patch source and metadata
```

See [`security/PATCHES.md`](security/PATCHES.md) for a full narrative of what was changed and why.

---

## Tests

```bash
pytest tests/security/ -v
```

Each CVE has dedicated tests covering code inspection, functional behaviour, and regression prevention. Tests are skipped gracefully on platforms where the fix is not applicable (e.g. Windows-specific tests on Linux).

---

## License

The Unlicense (Public Domain) — same as filelock 3.12.2