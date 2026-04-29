# Filelock LTS: The CVE-Aware Ecosystem 🛡️

> **⚠️ Disclaimer:** This project is **not affiliated with, endorsed by, or associated with** the official `filelock` maintainers. All patches and releases are independently maintained and provided on a best-effort basis to support legacy environments.

A unified security ecosystem ensuring filelock safety across ALL Python versions (3.7 - 3.14).

## 🚨 The Vulnerabilities: CVE-2025-68146 & CVE-2026-22701
A critical Time-of-Check-Time-of-Use (TOCTOU) race condition allows local attackers to truncate or corrupt sensitive files via symlink or junction attacks. 

## 🛡️ The Solution
This repository acts as a smart dispatcher. Installing `filelock-lts` automatically delivers the correct security strategy for your Python runtime:

| Python Version | Strategy | Base Version | Status |
|:---|:---|:---|:---|
| **3.7** | Custom Backport | `3.12.2` | 🛡️ SECURED (Unix + Win32) |
| **3.8** | Custom Backport | `3.16.1` | 🛡️ SECURED (Unix + Win32) |
| **3.9** | Custom Backport | `3.19.1` | 🛡️ SECURED (Unix + Win32) |
| **3.10+** | Upstream Proxy | Official `>= 3.20.1` | ✅ REDIRECTED |

## 📦 Installation
**Standard Installation (Recommended):**
```bash
pip install filelock-lts
```
This automatically selects the correct package for your environment.

**Specific Version Targeting:**
```bash
pip install filelock-lts-py38  # For Python 3.8 specifically
```

## 🔮 The Future: Proactive Dependency Security
The Filelock LTS ecosystem is evolving to provide earlier visibility and stronger controls around dependency risk:

- **Early Warning Releases:** Placeholder LTS releases may be published when a potential upstream security issue is under investigation, allowing users to prepare before official advisories are issued.
- **Runtime Policy Enforcement (Optional):** An opt-in runtime module that detects vulnerable dependency versions at runtime and enforces user-configured policies (warn, block, or isolate).
- **Configurable Security Policies:** Teams can choose how unpatched dependencies are handled based on their risk tolerance and operational needs.

## 🏗️ Architecture
- `lts-dispatcher`: The metadata dispatcher (this branch).
- `lts-py3.X`: Isolated branches containing specific source code or dependency definitions for that Python version.

## 🤝 License
Unlicense (Public Domain). Security belongs to everyone.
