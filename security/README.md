# Security Patches — filelock-lts-py37

This document explains every security patch applied to this repository, what was changed, why, and how to verify it.

Base package: **filelock 3.12.2** (released 2023-06-12, last release supporting Python 3.7)

---

## CVE-2025-68146 — TOCTOU Symlink Attack (HIGH)

**Published:** 2025-12-16
**Upstream fix:** filelock 3.20.1
**Our backport:** filelock-lts-py37 `2025.68146.2`
**NVD:** https://nvd.nist.gov/vuln/detail/CVE-2025-68146

### Vulnerability

`filelock` acquires locks by opening files with `os.open()`. Before this fix, none of the lock backends checked whether the target path was a symlink before opening it. An attacker with write access to the directory could:

1. Observe that a process is about to acquire a lock at a known path (e.g. `/tmp/app.lock`)
2. Pre-place a symlink at that path pointing at an arbitrary target (e.g. `/etc/passwd`)
3. When the victim process calls `lock.acquire()`, `os.open()` follows the symlink
4. The victim opens — and potentially truncates — the attacker's chosen target file

This is a classic Time-of-Check to Time-of-Use (TOCTOU) race. It affects all three lock backends: `UnixFileLock`, `SoftFileLock`, and `WindowsFileLock`.

### Files Changed

**`src/filelock/_unix.py`** — added `os.O_NOFOLLOW` to the `os.open()` flags in `UnixFileLock._acquire()`:

```python
# Before
open_flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC

# After
open_flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
```

`O_NOFOLLOW` causes the kernel to return `ELOOP` immediately if the final path component is a symlink, blocking the attack at the syscall level.

**`src/filelock/_soft.py`** — added `O_NOFOLLOW` via a safe `getattr` fallback:

```python
o_nofollow = getattr(os, "O_NOFOLLOW", None)
if o_nofollow is not None:
    flags |= o_nofollow
```

Using `getattr` rather than a direct reference means the code degrades safely on platforms where `O_NOFOLLOW` is not defined without raising `AttributeError`.

**`src/filelock/_windows.py`** — Windows does not have `O_NOFOLLOW`. Instead, explicit reparse point detection was added using the Windows API before the lock is acquired:

```python
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

def _is_reparse_point(path: str) -> bool:
    attrs = _kernel32.GetFileAttributesW(path)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
```

`WindowsFileLock._acquire()` calls `_is_reparse_point()` before opening the file and raises `OSError` if the path is a symbolic link or directory junction.

### Patch Files

- `security/patches/cve-2025-68146.patch` — primary patch
- `security/patches/cve-2025-68146-missing-hunk-applied.patch` — supplementary hunk applied separately
- `security/upstream/cve-2025-68146-upstream-src.patch` — original upstream diff (3.20.0 → 3.20.1)
- `security/upstream/cve-2025-68146-upstream-src.json` — OSV metadata snapshot

### Verification

```bash
grep -n "O_NOFOLLOW" src/filelock/_unix.py src/filelock/_soft.py
grep -n "_is_reparse_point\|GetFileAttributesW" src/filelock/_windows.py
pytest tests/security/test_cve_2025_68146.py -v
```

---

## CVE-2026-22701 — TOCTOU Symlink Attack in SoftFileLock (MODERATE)

**Published:** 2026-01-13
**Upstream fix:** filelock 3.20.3
**Our backport:** filelock-lts-py37 `2026.22701`
**GHSA:** GHSA-qmgc-5h2g-mvrw
**CVE:** https://www.cve.org/CVERecord?id=CVE-2026-22701

### Vulnerability

A follow-on to CVE-2025-68146 specifically targeting `SoftFileLock`. The upstream fix for CVE-2025-68146 applied `O_NOFOLLOW` to `UnixFileLock` and `WindowsFileLock` but the same gap in `SoftFileLock._acquire()` was not addressed until 3.20.3. The attack vector is identical: an attacker pre-places a symlink at the lock path and `SoftFileLock` follows it when creating the lock file.

### Files Changed

**`src/filelock/_soft.py`** — no additional change was required. The `O_NOFOLLOW` guard introduced during our CVE-2025-68146 backport was already identical to the upstream 3.20.3 fix. Our backport covered `SoftFileLock` in the same release as `UnixFileLock`, whereas upstream shipped it as a separate point release.

The patcher confirmed this automatically:

```
✓ Patch is already applied — all changes present in local source.
  ✓ src/filelock/_soft.py: all additions already present
```

### Patch Files

- `security/patches/cve-2026-22701.patch` — documents the upstream change (already applied)
- `security/upstream/cve-2026-22701-upstream-src.patch` — original upstream diff (3.20.2 → 3.20.3)
- `security/upstream/cve-2026-22701-upstream-src.json` — OSV metadata snapshot

### Verification

```bash
grep -n "O_NOFOLLOW\|o_nofollow" src/filelock/_soft.py
pytest tests/security/test_cve_2026_22701.py -v
```

---

## Full Diff vs Upstream Baseline

To verify the complete set of changes relative to vanilla `filelock 3.12.2`:

```bash
python check_local_vs_upstream.py
```

Expected: 3 files differ (`_unix.py`, `_soft.py`, `_windows.py`), 5 files identical (`__init__.py`, `_api.py`, `_error.py`, `_util.py`, `py.typed`).