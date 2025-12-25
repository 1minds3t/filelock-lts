# Filelock LTS (py3.13) - ➡️ REDIRECT


> **⚠️ Disclaimer:** This project is **not affiliated with, endorsed by, or associated with** the official `filelock` maintainers. All patches and releases are independently maintained and provided on a best-effort basis to support legacy environments.


| **Metric** | **Details** |
|:---|:---|
| **CVE** | [CVE-2025-68146](https://nvd.nist.gov/vuln/detail/CVE-2025-68146) |
| **Version** | `2025.68146` |
| **Base Core** | `filelock Upstream >= 3.20.1` |
| **Python** | `Python 3.13` |
| **License** | Unlicense (Public Domain) |

---

## ➡️ Modern Python Redirect
This package ensures you are using a secure version of filelock on Python 3.13.

Since Python 3.13 is supported by the official upstream maintainers, this LTS package acts as a **Meta-Package / Proxy**.

### How it works
Installing this package automatically installs the official `filelock >= 3.20.1`, which contains the official fix for CVE-2025-68146.

```bash
pip install filelock-lts-py3.13
```

### Why use this?
- **Consistency**: Use `filelock-lts` across your entire fleet (legacy and modern) without changing requirements files.
- **Continuity**: Ensures automated security redirect logic remains active even if upstream release patterns change.


## 🔮 The Future: Proactive Dependency Security
The Filelock LTS ecosystem is evolving to provide earlier visibility and stronger controls around dependency risk:

1.  **Early Warning Releases**: Placeholder LTS releases may be published when a potential upstream security issue is under investigation, allowing users to prepare before official advisories are issued.
2.  **Runtime Policy Enforcement (Optional)**: An opt-in runtime module that detects vulnerable dependency versions at runtime and enforces user-configured policies (warn, block, or isolate).
3.  **Configurable Security Policies**: Teams can choose how unpatched dependencies are handled based on their risk tolerance and operational needs.

