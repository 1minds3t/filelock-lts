import subprocess
import os

CALVER = "2026.22701.1"

README_CONTENT = """# Filelock LTS: The CVE-Aware Ecosystem 🛡️

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
"""

PYPROJECT_CONTENT = f"""[build-system]
requires =["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "filelock-lts"
version = "{CALVER}"
description = "LTS Security release for filelock (CVE-2025-68146 & CVE-2026-22701 Patch) - Meta-package"
requires-python = ">=3.7"
license = {{text = "Unlicense"}}
readme = "README.md"
classifiers =[
    "Topic :: Security",
    "Intended Audience :: Developers"
]
dependencies =[
    "filelock-lts-py37=={CALVER} ; python_version >= '3.7' and python_version < '3.8'",
    "filelock-lts-py38=={CALVER} ; python_version >= '3.8' and python_version < '3.9'",
    "filelock-lts-py39=={CALVER} ; python_version >= '3.9' and python_version < '3.10'",
    "filelock>=3.20.1 ; python_version >= '3.10'"
]

[project.urls]
Homepage = "https://github.com/1minds3t/filelock-lts"
"Security" = "https://github.com/1minds3t/filelock-lts/blob/main/SECURITY.md"
"""

def git(args):
    subprocess.check_call(["git"] + args)

def main():
    target_branch = "lts-dispatcher"
    current_branch = subprocess.check_output(["git", "branch", "--show-current"]).decode().strip()
    
    print(f"🚀 Updating dispatcher branch: '{target_branch}'...")

    try:
        if current_branch != target_branch:
            git(["switch", target_branch])
        
        try:
            git(["pull", "origin", target_branch])
        except subprocess.CalledProcessError:
            print("  ⚠️  Could not pull, or branch does not exist on origin. Continuing...")

        print("  📝 Writing README.md...")
        with open("README.md", "w", encoding="utf-8") as f:
            f.write(README_CONTENT)

        print("  📝 Writing pyproject.toml...")
        with open("pyproject.toml", "w", encoding="utf-8") as f:
            f.write(PYPROJECT_CONTENT)

        git(["add", "README.md", "pyproject.toml"])
        
        try:
            commit_msg = (
                f"chore: release {CALVER} for CVE-2025-68146 and CVE-2026-22701\n\n"
                "- Bumped legacy dependencies to 2026.22701.1\n"
                "- Dropped redundant 3.10+ proxy dependencies in favor of native upstream redirection\n"
                "- Updated README to feature dual-CVE architecture"
            )
            git(["commit", "-m", commit_msg])
            git(["push", "origin", target_branch])
            print(f"  ✅ Committed and pushed to {target_branch}.")
        except subprocess.CalledProcessError:
            print(f"  ⚠️  No changes to commit.")

    except Exception as e:
        print(f"  ❌ Error: {e}")
    finally:
        if current_branch != target_branch:
            git(["switch", current_branch])
        print(f"\n✅ Done. Back on '{current_branch}'.")

if __name__ == "__main__":
    main()