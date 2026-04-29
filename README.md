# filelock-lts (lts-py39) — 🛡️ PATCHED (Backport)

> **⚠️ Disclaimer:** This project is **not affiliated with, endorsed by, or associated
> with** the official `filelock` maintainers. All patches and releases are independently
> maintained and provided on a best-effort basis to support legacy environments.


| **Metric**     | **Details**                                                              |
|:---------------|:-------------------------------------------------------------------------|
| **CVEs Fixed** | CVE-2025-68146 (HIGH) · CVE-2026-22701 (MODERATE)                       |
| **Version**    | `2026.22701`                                                               |
| **Base**       | `filelock 3.19.1` (upstream tag for Python 3.9)                     |
| **Python**     | `3.9` only (`>=3.9, <3.10`) |
| **License**    | Unlicense (Public Domain)                                                |

---

## 🚨 The Problem

`filelock >= 3.20.1` contains the official fix for CVE-2025-68146 and CVE-2026-22701, but upstream
**requires Python >= 3.10**. Python 3.9 users are permanently excluded from
official security patches.

This package backports the complete fix to Python 3.9.

---

## 📦 Installation

### Fresh install (no existing `filelock`)

```bash
pip install filelock-lts-py39==2026.22701
```

### If `filelock` is already installed — do this in order

```bash
# 1. Remove upstream filelock first
pip uninstall filelock -y

# 2. Install the patched version
pip install filelock-lts-py39==2026.22701

# 3. Verify the patch is active
python -c "import filelock; print(filelock.__version__)"
pip show filelock filelock-lts-py39
```

> **Why the order matters:** Both packages install into the `filelock/` namespace
> in `site-packages`. Whichever is installed **last** owns the files. If upstream
> `filelock` is installed after this package, it silently overwrites the patched
> `_unix.py` and `_windows.py`, reintroducing the CVEs.

---

## ⚠️ Staying Protected After Initial Install

### The clobber risk

Any tool that declares `Requires: filelock` (without a version pin) will cause pip
to install upstream `filelock` when that tool is installed, **overwriting your
patched files**.

This package emits a `RuntimeWarning` at import time if it detects upstream
`filelock` is present alongside it — but detection happens after the damage is done.

### Safe workflow

```bash
# After installing ANY new package, verify protection is intact:
pip show filelock
# Should show NO result, or only show filelock-lts / filelock-lts-py39

# If upstream filelock crept back in:
pip uninstall filelock -y
pip install --force-reinstall filelock-lts-py39
```

### Pinning in requirements files

```
# requirements.txt — pin explicitly to block pip from pulling upstream
filelock-lts-py39==2026.22701
# Do NOT also list 'filelock' — that will pull in upstream
```

### Pinning in pyproject.toml

```toml
[project]
dependencies = [
    "filelock-lts-py39==2026.22701",
    # Do NOT add 'filelock' here — it will clobber the patched version
]
```

---

## ✅ Verifying the Patch Is Active

```bash
# Check which dist owns the filelock namespace
python -c "
import importlib.metadata as m
for d in m.distributions():
    name = d.metadata.get('Name','')
    if 'filelock' in name.lower():
        print(name, d.metadata.get('Version',''))
"
# Expected output:
#   filelock-lts             2026.22701
#   filelock-lts-py39  2026.22701
#
# If you see bare 'filelock  3.x.x' — upstream has clobbered your install.
```

---

## ⚙️ What Was Patched

**CVE-2025-68146** — `_unix.py`, `_windows.py`
- Unix: `os.O_NOFOLLOW` flag enforced during lock file creation, blocking symlink
  traversal at the kernel level.
- Windows: Explicit reparse point detection via `kernel32.GetFileAttributesW` (ctypes),
  refusing lock acquisition if the target is a symlink or directory junction.

**CVE-2026-22701** — `_soft.py`
- `O_NOFOLLOW` guard applied to `SoftFileLock` via `getattr` fallback for
  cross-platform safety.

Patch files and upstream diff analysis:
- `security/patches/` — the exact diffs applied
- `security/analysis/` — justification for each change

---

## 🔗 Links

| Resource | URL |
|:---------|:----|
| Source (this branch) | https://github.com/1minds3t/filelock-lts/tree/lts-py39 |
| Patch files | https://github.com/1minds3t/filelock-lts/tree/lts-py39/security/patches |
| CVE-2025-68146 | https://nvd.nist.gov/vuln/detail/CVE-2025-68146 |
| CVE-2026-22701 | https://www.cve.org/CVERecord?id=CVE-2026-22701 |
| Upstream filelock | https://github.com/tox-dev/py-filelock |

---

> **Note for package maintainers:** If your package targets Python 3.9 and
> currently lists `filelock` as a dependency, consider switching to
> `filelock-lts-py39>=2026.22701` to ensure your users receive the patched version.
> The import API is 100% compatible — no code changes required.
