#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trim_control.py  --  Safely query / disable / enable SSD TRIM (system-wide).

WHY THIS MATTERS FOR RECOVERY
-----------------------------
TRIM / DEALLOCATE is exactly what makes deleted data on an SSD unrecoverable:
it tells the drive to physically erase the freed clusters. Before you attempt a
recovery, DISABLE TRIM so that connecting or touching drives can't erase any
more. After recovery, ENABLE it again to keep the SSD healthy and fast.

IMPORTANT
  * This changes OPERATING-SYSTEM settings, NOT any drive's contents.
  * It is SYSTEM-WIDE -- it affects every SSD on this machine.
  * It only prevents FUTURE erasure. Data already TRIMed is gone.
  * For best protection, disable TRIM BEFORE connecting the damaged drive.
  * Needs Administrator (Windows) or root / sudo (Linux, macOS).

USAGE
  python3 trim_control.py status      # show current TRIM state
  python3 trim_control.py disable     # turn TRIM OFF (protect data)
  python3 trim_control.py enable      # turn TRIM ON  (restore after recovery)

The last line of output is always machine-readable:  "TRIM_STATE: <X>"
where X is ENABLED / DISABLED / MIXED / UNKNOWN.
"""

import os
import re
import sys
import subprocess

IS_WINDOWS = (os.name == "nt")
IS_MAC = (sys.platform == "darwin")


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as exc:
        class R:                                        # minimal stand-in
            returncode = 1
            stdout = ""
            stderr = str(exc)
        return R()


def emit_state(state):
    print("TRIM_STATE: %s" % state)


def need_priv_msg():
    return ("Administrator" if IS_WINDOWS else "root (re-run with sudo)")


# --------------------------------------------------------------------------- #
#  Windows  (fsutil behavior ... DisableDeleteNotify)                          #
# --------------------------------------------------------------------------- #

def win_status():
    r = run(["fsutil", "behavior", "query", "DisableDeleteNotify"])
    out = (r.stdout + r.stderr).strip()
    if out:
        print(out)
    vals = re.findall(r"=\s*(\d)", out)
    if not vals:
        print("[!] Could not read TRIM state (need %s?)." % need_priv_msg())
        emit_state("UNKNOWN")
        return 0
    # DisableDeleteNotify == 1 means TRIM is OFF.
    if all(v == "1" for v in vals):
        emit_state("DISABLED")
    elif all(v == "0" for v in vals):
        emit_state("ENABLED")
    else:
        emit_state("MIXED")
    return 0


def win_set(disable):
    val = "1" if disable else "0"
    r = run(["fsutil", "behavior", "set", "DisableDeleteNotify", val])
    out = (r.stdout + r.stderr).strip()
    if out:
        print(out)
    if r.returncode != 0:
        print("[!] Failed to change TRIM. Run this as Administrator.")
        emit_state("UNKNOWN")
        return 1
    print("[ok] TRIM %s system-wide." % ("DISABLED" if disable else "ENABLED"))
    return win_status()


# --------------------------------------------------------------------------- #
#  Linux  (fstrim.timer + continuous 'discard' mounts)                         #
# --------------------------------------------------------------------------- #

def _discard_mounts():
    found = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and "discard" in parts[3].split(","):
                    found.append(parts[1])
    except Exception:
        pass
    return found


def linux_status():
    t = run(["systemctl", "is-enabled", "fstrim.timer"])
    timer = (t.stdout or t.stderr).strip() or "unknown"
    print("periodic fstrim.timer : %s" % timer)
    disc = _discard_mounts()
    if disc:
        print("continuous 'discard'  : ON for %s" % ", ".join(disc))
    else:
        print("continuous 'discard'  : none")
    enabled = (timer == "enabled") or bool(disc)
    emit_state("ENABLED" if enabled else "DISABLED")
    return 0


def linux_set(disable):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Need root. Re-run with sudo.")
        emit_state("UNKNOWN")
        return 1
    if disable:
        r = run(["systemctl", "disable", "--now", "fstrim.timer"])
    else:
        r = run(["systemctl", "enable", "--now", "fstrim.timer"])
    out = (r.stdout + r.stderr).strip()
    if out:
        print(out)
    disc = _discard_mounts()
    if disable and disc:
        print("[!] Note: these mounts still TRIM continuously via the 'discard'")
        print("    option: %s" % ", ".join(disc))
        print("    Remove 'discard' from /etc/fstab and remount to fully stop TRIM.")
    print("[ok] periodic TRIM %s." % ("DISABLED" if disable else "ENABLED"))
    return linux_status()


# --------------------------------------------------------------------------- #
#  macOS  (trimforce -- reboots; we only guide, never auto-reboot)            #
# --------------------------------------------------------------------------- #

def mac_status():
    out = ""
    for dt in ("SPNVMeDataType", "SPSerialATADataType"):
        r = run(["system_profiler", dt])
        out += r.stdout
    states = set(re.findall(r"TRIM Support:\s*(\w+)", out))
    if states:
        print("TRIM Support reported: %s" % ", ".join(sorted(states)))
        if states == {"Yes"}:
            emit_state("ENABLED")
        elif states == {"No"}:
            emit_state("DISABLED")
        else:
            emit_state("MIXED")
    else:
        print("[!] Could not read TRIM state from system_profiler.")
        emit_state("UNKNOWN")
    return 0


def mac_set(disable):
    print("macOS toggles TRIM with `trimforce`, which forces a REBOOT and only")
    print("affects third-party SSDs (Apple internal SSDs always have TRIM on).")
    print("Run this yourself when ready:")
    print("    sudo trimforce %s" % ("disable" if disable else "enable"))
    emit_state("UNKNOWN")
    return 0


# --------------------------------------------------------------------------- #

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    action = argv[0] if argv else "status"
    if action not in ("status", "disable", "enable"):
        print(__doc__)
        return 2

    osname = "Windows" if IS_WINDOWS else ("macOS" if IS_MAC else "Linux")
    print("[trim] platform: %s   action: %s" % (osname, action))

    if action == "status":
        return win_status() if IS_WINDOWS else mac_status() if IS_MAC else linux_status()

    disable = (action == "disable")
    if disable:
        print("[trim] Disabling TRIM protects deleted data from further erasure.")
    else:
        print("[trim] Enabling TRIM restores normal SSD maintenance.")

    if IS_WINDOWS:
        return win_set(disable)
    if IS_MAC:
        return mac_set(disable)
    return linux_set(disable)


if __name__ == "__main__":
    sys.exit(main())
