# Filelock LTS (py3.8) - 🛡️ PATCHED (Backport)

| **Metric** | **Details** |
|:---|:---|
| **CVE** | [CVE-2025-68146](https://nvd.nist.gov/vuln/detail/CVE-2025-68146) |
| **Version** | `2025.68146` |
| **Base Core** | `filelock 3.16.1` |
| **Python** | `Python 3.8` |
| **License** | Unlicense (Public Domain) |

---

## 🛡️ Security Patch Overview
**This release backports the critical security fix for CVE-2025-68146 to Python 3.8.**

While upstream `filelock` patched this issue in versions requiring Python 3.10+, millions of installations on older Python versions remain vulnerable. This package restores security parity for legacy environments.

### The Problem
*   **Vulnerability:** CVE-2025-68146 (Symlink TOCTOU Attack)
*   **Impact:** Attackers can truncate arbitrary files via symlink race conditions.
*   **Context:** Official upstream patches are not available for Python 3.8.

### The Solution
This package is a **drop-in replacement**. It contains the original source code of `filelock 3.16.1` but applies the specific security patch manually.

```bash
pip install filelock-lts-py3.8==2025.68146
```

### ⚙️ Technical Details
*   **Fix Implementation:** We force `os.O_NOFOLLOW` in the `UnixFileLock` handler.
*   **Verification:** You can compare the source tree of this branch against the official `filelock 3.16.1` tag. The only difference is the security patch in `_unix.py`.


## 🔮 The Future: Proactive Security
We are building the **Filelock LTS Runtime Ecosystem**. In future releases, this package will support:

1.  **Pre-Patch Protocols (Alpha)**: We will release "Pre-Patch" versions (e.g., `0.2026.1234`) immediately upon vulnerability discovery, allowing you to patch **before** upstream maintainers release official fixes.
2.  **Runtime Protection**: A `filelock-lts-runtime` module that scans your environment and hot-patches vulnerable libraries in memory without requiring a restart.
3.  **Configurable Policies**: Choose between `warn`, `block`, or `sandbox` modes for file operations.

