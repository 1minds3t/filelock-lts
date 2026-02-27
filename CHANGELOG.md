# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2026.22701] — 2026-02-26

### Security

- **CVE-2026-22701** (MODERATE) — TOCTOU symlink attack in `SoftFileLock`
  ([GHSA-qmgc-5h2g-mvrw](https://github.com/advisories/GHSA-qmgc-5h2g-mvrw),
  [CVE](https://www.cve.org/CVERecord?id=CVE-2026-22701))
  Upstream fixed in filelock 3.20.3. Our CVE-2025-68146 backport had already
  applied the identical fix to `_soft.py`, so no additional code change was
  required. This release formally tracks coverage of the CVE and updates the
  version accordingly.

### Maintenance

- Removed ghost `src/filelock_lts_py37/` directory that had re-appeared from
  a patcher restore operation
- Cleaned up `patched/` staging directory left by failed patch attempt
- Fixed duplicate `# SECURITY PATCH` comment in `_unix.py`
- Added `patched/` and `licenses/` to `.gitignore`
- Added comprehensive security regression tests for CVE-2026-22701
  (`tests/security/test_cve_2026_22701.py`)

---

## [2025.68146.2] — 2025-12-25

### Security

- **CVE-2025-68146** (HIGH) — TOCTOU symlink attack in `UnixFileLock`,
  `SoftFileLock`, and `WindowsFileLock`
  ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68146))
  Upstream fixed in filelock 3.20.1. Full dual-platform backport to
  filelock 3.12.2.

  **Unix/Linux/macOS (`_unix.py`):** Added `os.O_NOFOLLOW` to `os.open()`
  flags in `UnixFileLock._acquire()`. The kernel now refuses to follow a
  symlink at the lock path, returning `ELOOP` instead.

  **All platforms (`_soft.py`):** Added `O_NOFOLLOW` via
  `getattr(os, "O_NOFOLLOW", None)` in `SoftFileLock._acquire()`. Degrades
  safely to a no-op on platforms that do not expose the flag.

  **Windows (`_windows.py`):** Added explicit reparse point detection using
  `kernel32.GetFileAttributesW` via ctypes. `WindowsFileLock._acquire()` now
  raises `OSError` if the lock path is a symbolic link or directory junction,
  before any file is opened.

### Maintenance

- Added security regression tests (`tests/security/test_cve_2025_68146.py`)
- Added patch documentation in `security/patches/` and `security/upstream/`
- Added pre/post patch analysis in `security/analysis/`

---

## [2025.68146] — 2025-12-16

### Security

- Initial backport release of CVE-2025-68146 fix for Python 3.7.
  Partial fix — `_windows.py` reparse point detection not yet included.

---

*Base package: [filelock 3.12.2](https://pypi.org/project/filelock/3.12.2/)
— last upstream release supporting Python 3.7 (released 2023-06-12).*