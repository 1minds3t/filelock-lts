# Filelock LTS (py3.9) - 🛡️ PATCHED (Backport)


> **⚠️ Disclaimer:** This project is **not affiliated with, endorsed by, or associated with** the official `filelock` maintainers. All patches and releases are independently maintained and provided on a best-effort basis to support legacy environments.


| **Metric** | **Details** |
|:---|:---|
| **CVE** | [CVE-2025-68146](https://nvd.nist.gov/vuln/detail/CVE-2025-68146) |
| **Version** | `2025.68146` |
| **Base Core** | `filelock 3.19.1` |
| **Python** | `Python 3.9` |
| **License** | Unlicense (Public Domain) |

---

## 🛡️ Security Patch Overview
**This release backports the complete upstream security fix for CVE-2025-68146 to Python 3.9.**

While upstream `filelock` patched this issue in versions requiring Python 3.10+, millions of installations on older Python versions remain vulnerable. This package restores full security parity for legacy environments.

### The Problem
*   **Vulnerability:** CVE-2025-68146 (Symlink/Junction TOCTOU Attack)
*   **Impact:** Local attackers can truncate or corrupt arbitrary files via race conditions involving symlinks (Linux/Unix) or Junctions (Windows).
*   **Context:** Official upstream patches are not available for Python 3.9.

### The Solution
This package is a **drop-in replacement**. It contains the original source code of `filelock 3.19.1` but applies the specific security patches manually to both Unix and Windows drivers.

```bash
pip install filelock-lts-py3.9==2025.68146
```

## ⚙️ Technical Details
This release includes the full dual-platform fix:

**Unix / Linux / macOS:**
- Enforces `os.O_NOFOLLOW` flag during lock file creation.
- Prevents the kernel from following attacker-controlled symlinks.

**Windows:**
- Implements explicit Reparse Point detection using `kernel32.GetFileAttributesW` via ctypes.
- Refuses to acquire locks if the target is a Symbolic Link or Directory Junction.
- Mitigates specific Windows-based TOCTOU attacks.

**Verification:** You can compare the source tree of this branch against the official filelock 3.19.1 tag. The changes are strictly limited to `_unix.py` and `_windows.py` security logic.


## 🔮 The Future: Proactive Dependency Security
The Filelock LTS ecosystem is evolving to provide earlier visibility and stronger controls around dependency risk:

1.  **Early Warning Releases**: Placeholder LTS releases may be published when a potential upstream security issue is under investigation, allowing users to prepare before official advisories are issued.
2.  **Runtime Policy Enforcement (Optional)**: An opt-in runtime module that detects vulnerable dependency versions at runtime and enforces user-configured policies (warn, block, or isolate).
3.  **Configurable Security Policies**: Teams can choose how unpatched dependencies are handled based on their risk tolerance and operational needs.

