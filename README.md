# Filelock LTS: The CVE-Aware Ecosystem 🛡️

![Security Status](https://img.shields.io/badge/Security-Patched-success) ![CVE](https://img.shields.io/badge/CVE-2025--68146-Fixed-blue)

**A unified security ecosystem ensuring `filelock` safety across ALL Python versions (3.7 - 3.14).**

## 🚨 The Vulnerability: CVE-2025-68146
A critical **Time-of-Check-Time-of-Use (TOCTOU)** race condition allows local attackers to truncate or corrupt sensitive files via symlink attacks. 

## 🛡️ The Solution
This repository acts as a smart dispatcher. Installing `filelock-lts` automatically delivers the correct security strategy for your Python runtime:

| Python Version | Strategy | Base Version | Status |
|:---:|:---|:---|:---:|
| **3.7** | **Custom Backport** | `3.12.2` | 🛡️ **SECURED** |
| **3.8** | **Custom Backport** | `3.16.1` | 🛡️ **SECURED** |
| **3.9** | **Custom Backport** | `3.19.1` | 🛡️ **SECURED** |
| **3.10+** | **Upstream Proxy** | `Official >= 3.20.1` | ✅ **REDIRECTED** |

## 📦 Installation

**Standard Installation (Recommended):**
```bash
pip install filelock-lts
```
*This automatically selects the correct package for your environment.*

**Specific Version Targeting:**
```bash
pip install filelock-lts-py38  # For Python 3.8 specifically
```


## 🔮 The Future: Proactive Security
We are building the **Filelock LTS Runtime Ecosystem**. In future releases, this package will support:

1.  **Pre-Patch Protocols (Alpha)**: We will release "Pre-Patch" versions (e.g., `0.2026.1234`) immediately upon vulnerability discovery, allowing you to patch **before** upstream maintainers release official fixes.
2.  **Runtime Protection**: A `filelock-lts-runtime` module that scans your environment and hot-patches vulnerable libraries in memory without requiring a restart.
3.  **Configurable Policies**: Choose between `warn`, `block`, or `sandbox` modes for file operations.


## 🏗️ Architecture
*   **`main`**: The metadata dispatcher (this branch).
*   **`py3.X`**: Isolated branches containing specific source code or dependency definitions for that Python version.

## 🤝 License
Unlicense (Public Domain). Security belongs to everyone.
