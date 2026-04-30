import subprocess

# Configuration — only legacy branches get patched READMEs
# Modern branches (py310+) redirect to upstream and don't need this treatment
ECOSYSTEM = {
    "lts-py37": {"type": "legacy", "base": "3.12.2",  "pyver": "3.7", "status": "🛡️ PATCHED (Backport)"},
    "lts-py38": {"type": "legacy", "base": "3.16.1",  "pyver": "3.8", "status": "🛡️ PATCHED (Backport)"},
    "lts-py39": {"type": "legacy", "base": "3.19.1",  "pyver": "3.9", "status": "🛡️ PATCHED (Backport)"},
}

CVE_ID   = "CVE-2025-68146 and CVE-2026-22701"
CALVER   = "2026.22701.1"
GH_BASE  = "https://github.com/1minds3t/filelock-lts"

DISCLAIMER = """> **⚠️ Disclaimer:** This project is **not affiliated with, endorsed by, or associated
> with** the official `filelock` maintainers. All patches and releases are independently
> maintained and provided on a best-effort basis to support legacy environments.
"""

def git(args):
    subprocess.check_call(["git"] + args)

def content_legacy(branch, info):
    pkg      = f"filelock-lts-py{info['pyver'].replace('.', '')}"
    pyver    = info["pyver"]
    base     = info["base"]
    status   = info["status"]
    pyshort  = pyver.replace(".", "")
    next_minor = f"{pyver.split('.')[0]}.{int(pyver.split('.')[1]) + 1}"

    return f"""# filelock-lts ({branch}) — {status}

{DISCLAIMER}

| **Metric**     | **Details**                                                              |
|:---------------|:-------------------------------------------------------------------------|
| **CVEs Fixed** | CVE-2025-68146 (HIGH) · CVE-2026-22701 (MODERATE)                       |
| **Version**    | `{CALVER}`                                                               |
| **Base**       | `filelock {base}` (upstream tag for Python {pyver})                     |
| **Python**     | `{pyver}` only (`>={pyver}, <{next_minor}`)                              |
| **License**    | Unlicense (Public Domain)                                                |

---

## 🚨 The Problem

`filelock >= 3.20.1` contains the official fix for {CVE_ID}, but upstream
**requires Python >= 3.10**. Python {pyver} users are permanently excluded from
official security patches.

This package backports the complete fix to Python {pyver}.

---

## 🔒 Defense-in-Depth

This package uses three hardening layers to protect patched files from being
silently overwritten by pip's flat install model:

1. **Install-time prevention** — `[conflicts]` table in `pyproject.toml` signals
   incompatibility with upstream `filelock` to resolvers that support it.
   Enforced by pip ≥ 24.1 during dependency resolution; older pip versions
   will ignore this field silently.

2. **Runtime integrity check** — `_check_clobber()` runs at import time using
   two detection layers:
   - **RECORD-based SHA256 verification** (primary): reads pip's own
     `dist-info/RECORD` and verifies `_unix.py`, `_windows.py`, and `_soft.py`
     on disk still match the hashes recorded at install time. Catches silent
     overwrites even when no upstream dist-info is present.
   - **Co-install detection** (secondary): scans installed distributions for a
     bare `filelock` dist alongside this package.
   Detection is non-fatal — failures in the check will not interrupt imports.

3. **Documentation** — install-order warnings, safe workflow guidance, and
   verification steps below.

> **Note:** These layers reduce risk but cannot fully prevent file overwrites
> within pip's install model. Always verify patch integrity after installing
> new packages in the same environment. See [Verifying Patch Integrity](#-verifying-patch-integrity) below.

---

## 📦 Installation

### Fresh install (no existing `filelock`)

```bash
pip install {pkg}=={CALVER}
```

### If `filelock` is already installed — do this in order

```bash
# 1. Remove upstream filelock first
pip uninstall filelock -y

# 2. Install the patched version
pip install {pkg}=={CALVER}

# 3. Verify patch integrity (see section below)
```

> **Why the order matters:** Both packages install into the `filelock/` namespace
> in `site-packages`. Whichever is installed **last** owns the files. If upstream
> `filelock` is installed after this package, it silently overwrites the patched
> `_unix.py`, `_windows.py`, and `_soft.py`, reintroducing the CVEs with no
> error or warning from pip.

---

## ⚠️ Staying Protected After Initial Install

### The clobber risk

Any tool that declares `Requires: filelock` (without a version pin) may cause pip
to install upstream `filelock` when that tool is installed, **overwriting your
patched files**. This happens silently — pip does not warn when one package's
files are overwritten by another.

### Safe workflow

```bash
# After installing ANY new package into this environment, verify protection:
python -c "import filelock"
# If patched files were overwritten, you will see a RuntimeWarning.

# Or check which dist owns the filelock namespace:
pip show filelock
# Should show NO result, or only show {pkg}

# If upstream filelock crept back in:
pip uninstall filelock -y
pip install --force-reinstall {pkg}
```

### Pinning in requirements files

```
# requirements.txt — pin explicitly to block pip from pulling upstream
{pkg}=={CALVER}
# Do NOT also list 'filelock' — that will pull in the unpatched upstream
```

### Pinning in pyproject.toml

```toml
[project]
dependencies = [
    "{pkg}=={CALVER}",
    # Do NOT add 'filelock' here — it will clobber the patched version
]
```

---

## ✅ Verifying Patch Integrity

### Quick check — dist ownership

```bash
python -c "
import importlib.metadata as m
for d in m.distributions():
    name = d.metadata.get('Name', '')
    if 'filelock' in name.lower():
        print(name, d.metadata.get('Version', ''))
"
# Expected: only '{pkg}  {CALVER}'
# If you see bare 'filelock  3.x.x' — upstream has been installed and may
# have overwritten the patched files.
```

### Full integrity check — SHA256 against RECORD

This verifies the actual patched files on disk match the hashes pip recorded
at install time. This is the same check `_check_clobber()` performs at import.

```bash
python -c "
import importlib.metadata as m, hashlib, base64, pathlib

LTS_NAMES = {{
    'filelock_lts_py{pyshort}', 'filelock_lts',
    'filelock-lts-py{pyshort}', 'filelock-lts',
}}
PATCHED = {{'_unix.py', '_windows.py', '_soft.py'}}

our_dist = None
for d in m.distributions():
    norm = (d.metadata.get('Name', '') or '').lower().replace('-', '_')
    if norm in LTS_NAMES:
        our_dist = d
        break

if our_dist is None:
    print('ERROR: {pkg} dist-info not found')
    raise SystemExit(1)

import filelock as fl
pkg_dir = pathlib.Path(fl.__file__).parent
record = our_dist.read_text('RECORD')
ok, failed = [], []

for line in record.splitlines():
    parts = line.split(',')
    if len(parts) < 2:
        continue
    filename = pathlib.Path(parts[0].strip()).name
    recorded = parts[1].strip()
    if filename not in PATCHED or not recorded.startswith('sha256:'):
        continue
    actual = pkg_dir / filename
    if not actual.exists():
        failed.append(f'{{filename}}: MISSING')
        continue
    digest = base64.urlsafe_b64encode(
        hashlib.sha256(actual.read_bytes()).digest()
    ).rstrip(b'=').decode()
    if digest == recorded[7:]:
        ok.append(filename)
    else:
        failed.append(f'{{filename}}: HASH MISMATCH')

for f in ok:
    print(f'  ✅ {{f}}')
for f in failed:
    print(f'  ❌ {{f}}')

if failed:
    print('\\nPatch integrity FAILED — reinstall {pkg}')
    raise SystemExit(1)
else:
    print('\\nAll patched files verified against RECORD.')
"
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
| Source (this branch) | {GH_BASE}/tree/{branch} |
| Patch files | {GH_BASE}/tree/{branch}/security/patches |
| CVE-2025-68146 | https://nvd.nist.gov/vuln/detail/CVE-2025-68146 |
| CVE-2026-22701 | https://www.cve.org/CVERecord?id=CVE-2026-22701 |
| Upstream filelock | https://github.com/tox-dev/py-filelock |

---

> **Note for package maintainers:** If your package targets Python {pyver} and
> currently lists `filelock` as a dependency, consider switching to
> `{pkg}>={CALVER}` to ensure your users receive the patched version.
> The import API is 100% compatible — no code changes required.
"""

def main():
    current_branch = subprocess.check_output(["git", "branch", "--show-current"]).decode().strip()
    print("🚀 Updating READMEs for legacy branches...")

    for branch, info in ECOSYSTEM.items():
        print(f"📄 {branch}...")
        try:
            git(["checkout", branch])
            try:
                git(["pull", "origin", branch])
            except subprocess.CalledProcessError:
                print(f"  ⚠️  Could not pull, continuing...")

            with open("README.md", "w") as f:
                f.write(content_legacy(branch, info))

            git(["add", "README.md"])
            try:
                git(["commit", "-m",
                     "docs: defense-in-depth framing, RECORD-based integrity verification section\n\n"
                     "- Corrected [conflicts] framing: enforced by pip ≥ 24.1, silently\n"
                     "  ignored by older versions — not guaranteed by build-system.requires\n"
                     "- Added defense-in-depth section describing all three hardening layers\n"
                     "- Added full RECORD-based SHA256 integrity check script matching\n"
                     "  the logic in _check_clobber()\n"
                     "- Note added: these layers reduce risk but cannot fully prevent\n"
                     "  overwrites within pip's install model"])
                git(["push", "origin", branch])
                print(f"  ✅ Pushed.")
            except subprocess.CalledProcessError:
                print(f"  ⚠️  No changes.")

        except Exception as e:
            print(f"  ❌ Error: {e}")

    git(["checkout", current_branch])
    print(f"\n✅ Done. Back on '{current_branch}'.")

if __name__ == "__main__":
    main()