# Filelock LTS (py3.12) - ➡️ REDIRECT

| **Metric** | **Details** |
|:---|:---|
| **CVE** | [CVE-2025-68146](https://nvd.nist.gov/vuln/detail/CVE-2025-68146) |
| **Version** | `2025.68146` |
| **Base Core** | `filelock Upstream >= 3.20.1` |
| **Python** | `Python 3.12` |
| **License** | Unlicense (Public Domain) |

---

## ➡️ Modern Python Redirect
**This package ensures you are using a secure version of `filelock` on Python 3.12.**

Since Python 3.12 is supported by the official upstream maintainers, this LTS package acts as a **Meta-Package** / **Proxy**.

### How it works
Installing this package automatically installs the official `filelock >= 3.20.1`, which contains the official fix for CVE-2025-68146.

```bash
pip install filelock-lts-py3.12
```

### Why use this?
*   **Consistency:** Use `filelock-lts` across your entire fleet (legacy and modern) without changing requirements files.
*   **Future Proofing:** If a new vulnerability appears and upstream is slow to react, we will deploy a "Pre-Patch" here first.


## 🔮 The Future: Proactive Security
We are building the **Filelock LTS Runtime Ecosystem**. In future releases, this package will support:

1.  **Pre-Patch Protocols (Alpha)**: We will release "Pre-Patch" versions (e.g., `0.2026.1234`) immediately upon vulnerability discovery, allowing you to patch **before** upstream maintainers release official fixes.
2.  **Runtime Protection**: A `filelock-lts-runtime` module that scans your environment and hot-patches vulnerable libraries in memory without requiring a restart.
3.  **Configurable Policies**: Choose between `warn`, `block`, or `sandbox` modes for file operations.

