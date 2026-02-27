# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2026.22701] — 2026-02-26

Security Update (CVE-2025-68146 & CVE-2026-22701)

## 🛡️ Security Fixes

This release addresses two Time-of-Check-Time-of-Use (TOCTOU) vulnerabilities involving symlink attacks.

- **Unix:** Added `os.O_NOFOLLOW` to the `os.open` flags in `UnixFileLock`. This prevents the kernel from following a symlink if the lock file is replaced with a link to a sensitive file between the existence check and the open call.
- **Windows:** Added a check for reparse points (symlinks/junctions) in `WindowsFileLock` using `GetFileAttributesW`. The lock acquisition now fails if the lock file is a reparse point.

- **All Platforms:** Added `os.O_NOFOLLOW` (where available) to the `os.open` flags in `SoftFileLock` to prevent similar race conditions in the soft locking mechanism.

## 🧹 Maintenance
- Removed redundant source directory `src/filelock_lts_py37` to reduce package size.
- Added comprehensive security regression tests in `tests/security/`.

---

