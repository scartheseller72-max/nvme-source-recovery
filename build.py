#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build.py  --  Build a standalone NVMe Source Recovery executable with PyInstaller.

The single binary doubles as the GUI, the recovery engine, and the TRIM tool
(the GUI re-invokes its own executable with --engine / --trim), so there are no
loose .py files to ship. Output lands in ./dist/.

    python3 -m pip install pyinstaller
    python3 build.py

Run it once per OS (Windows / macOS / Linux) — PyInstaller does not
cross-compile. CI does exactly this in .github/workflows/build.yml.
"""

import os
import sys
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "nvme-recovery"
ENTRY = os.path.join(HERE, "nvme_recover_gui.py")
SEP = ";" if os.name == "nt" else ":"          # PyInstaller --add-data separator


def main():
    try:
        import PyInstaller                      # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run:  python3 -m pip install pyinstaller")
        return 1

    for d in ("build", "dist"):
        shutil.rmtree(os.path.join(HERE, d), ignore_errors=True)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", NAME,
        "--add-data", "%s%sassets" % (os.path.join(HERE, "assets"), SEP),
        # bundle the engine + trim modules so --engine / --trim work when frozen
        "--hidden-import", "nvme_recover",
        "--hidden-import", "trim_control",
        "--paths", HERE,
    ]
    icon = _icon_path()
    if icon:
        args += ["--icon", icon]
    args.append(ENTRY)

    print("[build] " + " ".join(args))
    rc = subprocess.call(args)
    if rc != 0:
        return rc

    out = os.path.join(HERE, "dist")
    print("\n[build] DONE. Artifacts in: %s" % out)
    for f in sorted(os.listdir(out)):
        full = os.path.join(out, f)
        print("   %s  (%.1f MiB)" % (f, os.path.getsize(full) / (1024 * 1024)))
    return 0


def _icon_path():
    """Use a platform-native icon if one is present in assets/."""
    cand = "icon.ico" if os.name == "nt" else ("icon.icns" if sys.platform == "darwin" else None)
    if cand:
        p = os.path.join(HERE, "assets", cand)
        if os.path.isfile(p):
            return p
    return None


if __name__ == "__main__":
    sys.exit(main())
