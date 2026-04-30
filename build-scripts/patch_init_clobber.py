#!/usr/bin/env python3
"""
Patch src/filelock/__init__.py on legacy LTS branches (py37, py38, py39):
  - Injects _check_clobber() immediately after stdlib imports, before the
    first from ._xxx import line.
  - Skips branches where _check_clobber is already present.
  - Adapts the LTS package name and Python version in the warning text
    per branch.

Detection strategy (two layers):
  1. RECORD-based integrity: verifies patched files on disk still match the
     SHA256 hashes recorded by pip at install time in the dist-info RECORD.
     Catches silent overwrites even when no upstream dist-info is present.
  2. Co-install detection: warns if upstream 'filelock' dist-info is found
     alongside ours (belt-and-suspenders secondary signal).

Store in build-scripts/ (already in .gitignore).
Usage:
    cd ~/filelock-lts
    python build-scripts/patch_init_clobber.py
"""
import subprocess
import re

# lts-py37 is already patched manually — skip it here, or include and let
# the idempotency check handle it. Set to True to re-verify py37 as well.
INCLUDE_PY37 = True

LEGACY_BRANCHES = ["lts-py38", "lts-py39"]
if INCLUDE_PY37:
    LEGACY_BRANCHES = ["lts-py37"] + LEGACY_BRANCHES

INIT_PATH = "src/filelock/__init__.py"

# Per-branch metadata used to customise the warning text
BRANCH_META = {
    "lts-py37": {
        "pkg_name": "filelock-lts-py37",
        "py_ver":   "3.7",
        "lts_names": """\
            "filelock-lts",
            "filelock-lts-py37",
            "filelock_lts",
            "filelock_lts_py37",""",
    },
    "lts-py38": {
        "pkg_name": "filelock-lts-py38",
        "py_ver":   "3.8",
        "lts_names": """\
            "filelock-lts",
            "filelock-lts-py38",
            "filelock_lts",
            "filelock_lts_py38",""",
    },
    "lts-py39": {
        "pkg_name": "filelock-lts-py39",
        "py_ver":   "3.9",
        "lts_names": """\
            "filelock-lts",
            "filelock-lts-py39",
            "filelock_lts",
            "filelock_lts_py39",""",
    },
}


def git(*args):
    subprocess.check_call(["git"] + list(args))


def git_out(*args):
    return subprocess.check_output(["git"] + list(args)).decode().strip()


def build_clobber_block(meta: dict) -> str:
    pkg   = meta["pkg_name"]
    py    = meta["py_ver"]
    names = meta["lts_names"]
    return f'''\

_check_clobber_done = False


def _check_clobber():
    """
    Verify that CVE-patched files have not been silently overwritten after
    install, and detect co-installation of upstream filelock.

    Two detection layers:

    1. RECORD-based integrity check (primary):
       Reads our own dist-info RECORD (written by pip at install time) and
       verifies that _unix.py, _windows.py, and _soft.py on disk still match
       the recorded SHA256 hashes. A mismatch means a subsequent install
       overwrote our files — the CVEs may be reintroduced regardless of
       whether upstream dist-info is present.

    2. Co-install detection (secondary):
       Scans installed distributions for a bare 'filelock' dist that is not
       one of our LTS packages. Presence indicates a likely clobber, even if
       the RECORD check passed (e.g. if the upstream install happened to write
       identical bytes, which is unlikely but possible in edge cases).

    Detection is non-fatal — failures in this check will not interrupt imports.
    Guard against repeated execution (daemon reexec, hot-reload, re-import).
    """
    global _check_clobber_done
    if _check_clobber_done:
        return
    _check_clobber_done = True
    try:
        try:
            import importlib.metadata as _md
        except ImportError:
            import importlib_metadata as _md  # type: ignore[no-redef]

        import hashlib
        import base64
        from pathlib import Path

        # Files whose integrity we guarantee. __init__.py intentionally
        # excluded — it contains this function and changes across versions.
        PATCHED_FILES = {{"_unix.py", "_windows.py", "_soft.py"}}

        LTS_NAMES = {{
{names}
        }}

        import csv

        _lts_normalized = {{n.lower().replace("-", "_") for n in LTS_NAMES}}

        # ── Single pass: find our dist + upstream in one loop ─────────────────
        compromised = []
        our_dist = None
        upstream_version = None
        for dist in _md.distributions():
            raw = (dist.metadata.get("Name", "") or "").lower().replace("-", "_")
            if raw in _lts_normalized and our_dist is None:
                our_dist = dist
            elif raw == "filelock":
                upstream_version = dist.metadata.get("Version", "unknown")
            if our_dist is not None and upstream_version is not None:
                break

        # ── Layer 1: RECORD-based integrity ──────────────────────────────────
        if our_dist is None:
            compromised.append("filelock-lts distribution not found (environment inconsistency — bubble isolation may be hiding it)")

        if our_dist is not None:
            record_text = our_dist.read_text("RECORD")
            if not record_text:
                # Missing RECORD = editable install, broken install, or tampering.
                # We can't verify integrity, so flag it.
                compromised.append("RECORD missing or unreadable (editable install or tampered package)")
            else:
                site_root = Path(our_dist.locate_file(""))
                for row in csv.reader(record_text.splitlines()):
                    if len(row) < 2:
                        continue
                    rel_path, recorded_hash = row[0].strip(), row[1].strip()
                    filename = Path(rel_path).name
                    if filename not in PATCHED_FILES:
                        continue
                    if not recorded_hash.startswith("sha256:"):
                        continue

                    actual = site_root / rel_path
                    if not actual.exists():
                        compromised.append(f"{{filename}} (missing at {{actual}})")
                        continue

                    digest = base64.urlsafe_b64encode(
                        hashlib.sha256(actual.read_bytes()).digest()
                    ).rstrip(b"=").decode()

                    expected = recorded_hash[len("sha256:"):]
                    if digest != expected:
                        compromised.append(
                            f"{{filename}} (hash mismatch — expected {{expected[:12]}}…, got {{digest[:12]}}…)"
                        )

        # ── Emit warning if either layer fires ───────────────────────────────
        if compromised or upstream_version:
            import warnings
            lines = [
                "\\n\\n  *** SECURITY WARNING: {pkg} integrity check failed ***\\n",
            ]
            if compromised:
                lines += [
                    "  Patched files have been modified since install:",
                    *[f"    • {{f}}" for f in compromised],
                    "  CVE-2025-68146 and CVE-2026-22701 patches may no longer be active.",
                ]
            if upstream_version:
                if compromised:
                    lines.append("")
                lines.append(
                    f"  Upstream filelock=={{upstream_version}} is co-installed alongside this package."
                )
                if not compromised:
                    lines.append(
                        "  If installed after {pkg}, pip may have overwritten the patched files."
                    )
            lines += [
                "",
                "  To restore protection (Python {py} env):",
                "    pip uninstall filelock -y",
                "    pip install --force-reinstall {pkg}",
                "",
                "  To verify patch integrity after reinstall:",
                "    python -c \\"",
                "      import importlib.metadata as m, hashlib, base64, pathlib",
                "      d = next(x for x in m.distributions()",
                "               if (x.metadata.get('Name','') or '').lower().replace('-','_')",
                "               in {{'filelock_lts_py{py.replace('.', '')}', 'filelock_lts'}})",
                "      rec = d.read_text('RECORD')",
                "      print('RECORD found — run full integrity check via {pkg}')",
                "    \\"",
                "    # Or simply: pip show {pkg}",
                "    # Confirm dist is '{pkg}', not bare 'filelock'",
                "",
            ]
            warnings.warn("\\n".join(lines), RuntimeWarning, stacklevel=2)

    except Exception:
        # Never crash the import over a metadata check.
        pass


_check_clobber()

'''


# Regex: first "from ._xxx import" line (the real package imports)
INJECT_BEFORE = re.compile(r'^from \._', re.MULTILINE)

# Matches the entire _check_clobber block including the module-level
# _check_clobber_done flag that precedes it, plus any surrounding blank lines,
# so re-runs excise the whole unit and don't accumulate duplicate flag lines.
EXISTING_BLOCK = re.compile(
    r'\n*_check_clobber_done\s*=\s*False\s*\n+def _check_clobber\(\):.*?^_check_clobber\(\)\n*',
    re.MULTILINE | re.DOTALL,
)

# Canonical blank-line separator written around the block on every apply.
# Two blank lines before + two blank lines after = PEP 8 top-level spacing.
_SEP = "\n\n\n"


def _canonical(text: str) -> str:
    """Return content stripped of surrounding whitespace for diffing."""
    return text.strip()


def patch_init(content: str, meta: dict):
    block = build_clobber_block(meta)

    existing = EXISTING_BLOCK.search(content)
    if existing:
        if _canonical(existing.group(0)) == _canonical(block):
            return content, False  # identical content — nothing to do

        # Stale block — excise everything the regex consumed (including all
        # accumulated blank lines) and splice in with exact whitespace.
        before = content[:existing.start()].rstrip("\n")
        after  = content[existing.end():].lstrip("\n")
        new_content = before + _SEP + block.strip() + _SEP + after
        return new_content, True

    # No existing block — inject before first "from ._" import.
    m = INJECT_BEFORE.search(content)
    if not m:
        raise ValueError("Could not find injection point (first 'from ._' import)")

    before = content[:m.start()].rstrip("\n")
    after  = content[m.start():].lstrip("\n")
    new_content = before + _SEP + block.strip() + _SEP + after
    return new_content, True


def main():
    original = git_out("branch", "--show-current")
    print(f"Starting on: {original}\n")

    for branch in LEGACY_BRANCHES:
        print(f"--- {branch} ---")
        meta = BRANCH_META.get(branch)
        if not meta:
            print(f"  No metadata defined for {branch}, skipping.")
            continue

        try:
            git("checkout", branch)
            git("pull", "origin", branch)
        except subprocess.CalledProcessError as e:
            print(f"  ERROR: {e}")
            continue

        try:
            with open(INIT_PATH, "r") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"  {INIT_PATH} not found on this branch, skipping.")
            continue

        try:
            new_content, changed = patch_init(content, meta)
        except ValueError as e:
            print(f"  PATCH ERROR: {e}")
            continue

        if not changed:
            print(f"  _check_clobber already up-to-date — nothing to do.")
            continue

        action = "updated" if EXISTING_BLOCK.search(content) else "injected"

        with open(INIT_PATH, "w") as f:
            f.write(new_content)

        git("add", INIT_PATH)
        try:
            git(
                "commit", "-m",
                f"security({branch}): {action} RECORD-based integrity check + co-install detection\n\n"
                f"_check_clobber() now uses two detection layers:\n"
                f"  1. RECORD-based SHA256 integrity: verifies _unix.py, _windows.py,\n"
                f"     _soft.py against pip's own dist-info RECORD. Catches silent\n"
                f"     overwrites without relying on dist-info presence.\n"
                f"  2. Co-install detection: warns if bare 'filelock' dist is found\n"
                f"     alongside this package (secondary signal).\n\n"
                f"Covers CVE-2025-68146 and CVE-2026-22701.",
            )
            git("push", "origin", branch)
            print(f"  Block {action} and pushed.")
        except subprocess.CalledProcessError:
            print(f"  Nothing committed (already clean after write — unexpected).")

    git("checkout", original)
    print(f"\nDone. Back on '{original}'.")


if __name__ == "__main__":
    main()