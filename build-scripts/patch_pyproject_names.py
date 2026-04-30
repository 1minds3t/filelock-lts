#!/usr/bin/env python3
"""
Patch pyproject.toml on legacy LTS branches (py37, py38, py39):
  1. Normalize name to underscores (PyPI sdist requirement)
  2. Add pip >= 24.1 to build requires (needed for conflicts table support)
  3. Add [conflicts] table to evict upstream filelock before install

Only touches legacy branches. Modern redirect branches (py310+) are skipped.

Store in build-scripts/ which is in .gitignore.
"""
import subprocess
import re

LEGACY_BRANCHES = ["lts-py37", "lts-py38", "lts-py39"]

def git(*args):
    subprocess.check_call(["git"] + list(args))

def git_out(*args):
    return subprocess.check_output(["git"] + list(args)).decode().strip()

CONFLICTS_BLOCK = """
[conflicts]
filelock = "*"
"""

def patch_toml(content):
    changed = False

    # 1. Normalize name hyphens -> underscores
    def normalize_name(m):
        old = m.group(1)
        new = old.replace("-", "_")
        return f'name = "{new}"'
    new_content, n = re.subn(r'^name = "([^"]+)"', normalize_name, content, flags=re.MULTILINE)
    if n and new_content != content:
        print(f"  Normalized name")
        content = new_content
        changed = True

    # 2. Add pip>=24.1 to build requires if not present
    def patch_build_requires(m):
        val = m.group(1)
        if "pip>=24.1" in val:
            return m.group(0)
        val = val.rstrip().rstrip(']').rstrip()
        new_val = val + ',\n    "pip>=24.1"\n]'
        return f'requires = {new_val}'
    new_content, n = re.subn(r'requires = (\[.*?\])', patch_build_requires, content, flags=re.DOTALL)
    if n and new_content != content:
        print(f"  Added pip>=24.1 to build requires")
        content = new_content
        changed = True

    # 3. Add [conflicts] block if not present
    if "[conflicts]" not in content:
        content = content.rstrip() + "\n" + CONFLICTS_BLOCK
        print(f"  Added [conflicts] table")
        changed = True

    return content, changed

def main():
    original = git_out("branch", "--show-current")
    print(f"Starting on: {original}\n")

    for branch in LEGACY_BRANCHES:
        print(f"--- {branch} ---")
        try:
            git("checkout", branch)
            git("pull", "origin", branch)
        except subprocess.CalledProcessError as e:
            print(f"  ERROR: {e}")
            continue

        with open("pyproject.toml", "r") as f:
            content = f.read()

        new_content, changed = patch_toml(content)

        if not changed:
            print(f"  Nothing to do.")
            continue

        with open("pyproject.toml", "w") as f:
            f.write(new_content)

        git("add", "pyproject.toml")
        try:
            git("commit", "-m", "fix(pyproject): underscore name, require pip>=24.1, conflict upstream filelock")
            git("push", "origin", branch)
            print(f"  Pushed.")
        except subprocess.CalledProcessError:
            print(f"  Nothing committed (already clean).")

    git("checkout", original)
    print(f"\nDone. Back on '{original}'.")

if __name__ == "__main__":
    main()