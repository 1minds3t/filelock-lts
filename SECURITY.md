# Security Policy

## CVE-2025-68146: Symlink Attack via TOCTOU Race Condition

### Vulnerability Details
**Severity**: Medium/High (Local Privilege Escalation context)
**Affected Versions**: filelock < 3.20.1
**Description**: 
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists in `filelock` versions prior to 3.20.1. The library checked if a lock file existed before opening it with `O_TRUNC`. A local attacker could create a symlink to a sensitive file (e.g., `/etc/passwd`) in the window between the check and the open. 

### The Fix
This LTS ecosystem ensures security across all Python versions:

1. **Modern Python (3.10+)**: Redirects to the official `filelock >= 3.20.1` which includes the fix.
2. **Legacy Python (3.7-3.9)**: Includes a custom backport of the `O_NOFOLLOW` flag in `os.open()`, preventing the kernel from following attacker-controlled symlinks.

### Ecosystem Status
| Python | Package Name | Status |
|:---:|:---|:---|
| **3.7** | `filelock-lts-py37` | ✅ **Patched (Backport)** |
| **3.8** | `filelock-lts-py38` | ✅ **Patched (Backport)** |
| **3.9** | `filelock-lts-py39` | ✅ **Patched (Backport)** |
| **3.10+** | `filelock-lts-py3*` | ➡️ **Redirects to Upstream** |
