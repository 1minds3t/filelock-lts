# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2026.22701.1] — 2026-04-29

runtime integrity hardening

Adds runtime clobber detection to guard against pip dependency resolution
silently overwriting CVE-patched files after install.

## What's new

_check_clobber() now runs two detection layers on every import:

1. RECORD-based integrity (primary): verifies _unix.py, _windows.py, and
   _soft.py against the SHA256 hashes pip recorded at install time. Catches
   silent overwrites regardless of whether upstream dist-info is present.

2. Co-install detection (secondary): warns if a bare `filelock` dist is found
   alongside this package — belt-and-suspenders signal for environments where
   the hash check alone may not surface the issue.

Additional hardening:
- Guard against repeated execution across daemon reexec, hot-reload, and
  re-import paths (_check_clobber_done flag)
- Surfaces missing dist as a compromised entry rather than silently skipping
  the integrity check (relevant in bubble-isolated environments)
- pyproject.toml: requires pip>=24.1, conflicts upstream filelock to prevent
  co-installation at resolve time

## Affected CVEs

CVE-2025-68146, CVE-2026-22701

## Upgrade

pip install --force-reinstall filelock_lts_py37

---

**Updates:**
- Update publish workflow for Python 3.12 support

**Other Changes:**
- security(lts-py37): updated RECORD-based integrity check + co-install detection
- docs: defense-in-depth framing, RECORD-based integrity verification section
- security(lts-py37): inject _check_clobber, add build-scripts to .gitignore
- docs: clear install order warning and clobber protection guidance
- fix(pyproject): underscore name, require pip>=24.1, conflict upstream filelock
- ...and 2 more changes

_6 files changed, 411 insertions(+), 95 deletions(-)_

## [2026.22701] — 2026-02-26

Security Update (CVE-2025-68146 & CVE-2026-22701)

## 🛡️ Security Fixes

This release addresses two Time-of-Check-Time-of-Use (TOCTOU) vulnerabilities involving symlink attacks, ensuring Python 3.7 environments remain secure.

*   **Unix/Linux/macOS:** Added `os.O_NOFOLLOW` to `os.open` flags in `UnixFileLock`. The kernel will now refuse to open the lock file if it is a symbolic link, preventing attackers from redirecting the lock creation to arbitrary files.
*   **Windows:** Added explicit reparse point detection in `WindowsFileLock`. Uses `GetFileAttributesW` to verify the target is not a symbolic link or junction before acquisition.

*   **All Platforms:** Added `os.O_NOFOLLOW` (via `getattr` for compatibility) to `SoftFileLock`. This prevents similar race conditions where the soft lock file could be replaced with a symlink.

## 🧹 Maintenance
*   Added comprehensive security regression tests in `tests/security/`.
*   Cleaned up redundant source directories and build artifacts.
*   Updated project metadata and documentation.

---

## [2025.68146.2] — 2025-12-25

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

- Added security regression tests (`tests/security/test_cve_2025_68146.py`)
- Added patch documentation in `security/patches/` and `security/upstream/`
- Added pre/post patch analysis in `security/analysis/`

---

## [2025.68146] — 2025-12-16

- Initial backport release of CVE-2025-68146 fix for Python 3.7.
  Partial fix — `_windows.py` reparse point detection not yet included.

---

*Base package: [filelock 3.12.2](https://pypi.org/project/filelock/3.12.2/)
— last upstream release supporting Python 3.7 (released 2023-06-12).*

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
