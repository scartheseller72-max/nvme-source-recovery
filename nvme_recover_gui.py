#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nvme_recover_gui.py  --  Desktop GUI front-end for the NVMe / NTFS source-code
                         recovery engine (nvme_recover.py).

Goals
-----
  * Stdlib-only (tkinter) so it runs on a Linux live USB with no pip installs.
  * 100% READ-ONLY against the source -- it only ever drives nvme_recover.py,
    which never writes to the image/device.
  * Live, colourised log streaming + progress, device picker, phase selection,
    and a results browser that lets you read recovered files without leaving
    the app.

It runs the engine as a subprocess (sys.executable nvme_recover.py <cmd> ...)
so a long scan never freezes the UI and the engine stays untouched.

    python3 nvme_recover_gui.py
"""

import os
import re
import sys
import csv
import glob
import json
import time
import queue
import shlex
import shutil
import threading
import subprocess

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, font as tkfont
except Exception as exc:                                    # pragma: no cover
    sys.stderr.write(
        "tkinter is required for the GUI but is not available.\n"
        "  Debian/Ubuntu : sudo apt install -y python3-tk\n"
        "  Fedora        : sudo dnf install -y python3-tkinter\n"
        "  Arch          : sudo pacman -S tk\n"
        "Original error: %s\n" % exc)
    sys.exit(1)


HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "nvme_recover.py")
TRIM_SCRIPT = os.path.join(HERE, "trim_control.py")
IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
FROZEN = getattr(sys, "frozen", False)
SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".nvme_recover_gui.json")


def resource_dir():
    """Where bundled data (assets/) lives — the PyInstaller temp dir when frozen."""
    return getattr(sys, "_MEIPASS", HERE)


def engine_argv(*args):
    """argv to run the recovery engine, working both as a .py and as a frozen exe.
    When frozen, the GUI re-invokes its own executable with a --engine switch."""
    if FROZEN:
        return [sys.executable, "--engine", *args]
    return [sys.executable, ENGINE, *args]


def trim_argv(*args):
    if FROZEN:
        return [sys.executable, "--trim", *args]
    return [sys.executable, TRIM_SCRIPT, *args]


# Phase id -> (label, engine subcommand, tooltip)
PHASES = [
    ("analyze",  "Analyze",  "analyze",
     "Zero/0xFF/entropy map: how much did TRIM wipe, and where is live data."),
    ("mft",      "MFT mine", "mft",
     "Recover deleted files from $MFT. Resident files come back 100% intact."),
    ("usn",      "USN log",  "usn",
     "Parse $UsnJrnl into a timestamped delete log by filename."),
    ("archives", "Archives", "archives",
     "Carve & rebuild ZIP / 7z / gzip with CRC validation."),
    ("media",    "Media",    "media",
     "Carve photos (jpg/png/gif/bmp/webp/heic) & videos (mp4/mov/avi/mkv/webm/wmv)."),
    ("source",   "Source",   "source",
     "Language-aware carving of raw .rs/.kt/.py/.sol/... text."),
]

CMD_LABEL = {cmd: label for _pid, label, cmd, _t in PHASES}

# Theme ---------------------------------------------------------------------- #
BG       = "#0f1620"
BG_PANEL = "#16202c"
BG_INPUT = "#0b1118"
FG       = "#d7e0ea"
FG_MUTE  = "#7d8da0"
ACCENT   = "#3b8ee0"
OK       = "#2ea44f"
WARN     = "#e0a13b"
ERR      = "#e0533b"
BORDER   = "#26323f"


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #

def human(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f PiB" % n


def open_path(path):
    """Open a file or folder with the OS default handler. Cross-platform."""
    try:
        if IS_WINDOWS:
            os.startfile(path)                          # noqa: type checker
        elif IS_MAC:
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


def base_disk(dev):
    """Whole-disk node for a partition path: /dev/sdc2 -> /dev/sdc,
    /dev/nvme0n1p2 -> /dev/nvme0n1."""
    if not dev:
        return dev
    m = re.match(r"^(/dev/(?:nvme\d+n\d+|mmcblk\d+))p\d+$", dev)
    if m:
        return m.group(1)
    m = re.match(r"^(/dev/[a-z]+)\d+$", dev)
    if m:
        return m.group(1)
    return dev


def _detect_windows():
    out = []
    try:
        ps = ("Get-CimInstance Win32_DiskDrive | ForEach-Object "
              "{ \"$($_.DeviceID)|$($_.Size)|$($_.Model)|$($_.SerialNumber)|"
              "$($_.InterfaceType)\" }")
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            parts = line.split("|")
            if len(parts) < 2 or not parts[0].strip():
                continue
            dev = parts[0].strip()                      # \\.\PHYSICALDRIVE0
            size = parts[1].strip()
            model = parts[2].strip() if len(parts) > 2 else ""
            serial = parts[3].strip() if len(parts) > 3 else ""
            tran = parts[4].strip() if len(parts) > 4 else ""
            hs = human(int(size)) if size.isdigit() else size
            label = "%s  ·  %s" % (dev, hs)
            if model:
                label += "  ·  " + model
            if tran:
                label += "  [%s]" % tran
            if serial:
                label += "  SN:" + serial[:16]
            out.append((dev, label))
    except Exception:
        pass
    return out


def _detect_macos():
    out = []
    try:
        res = subprocess.run(["diskutil", "list"], capture_output=True,
                             text=True, timeout=8)
        for line in res.stdout.splitlines():
            m = re.match(r"^(/dev/disk\d+)\b", line)
            if m:
                out.append((m.group(1), line.strip()))
    except Exception:
        pass
    if not out:
        for dev in sorted(glob.glob("/dev/disk[0-9]")):
            out.append((dev, dev))
    return out


def _detect_linux():
    out = []
    try:
        # -P (key="value") survives spaces in model/vendor names.
        res = subprocess.run(
            ["lsblk", "-dpP", "-o", "NAME,SIZE,TYPE,TRAN,VENDOR,MODEL,SERIAL"],
            capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                kv = dict(re.findall(r'(\w+)="([^"]*)"', line))
                if kv.get("TYPE") != "disk":
                    continue
                name = kv.get("NAME", "")
                if not name:
                    continue
                ident = (kv.get("VENDOR", "").strip() + " " +
                         kv.get("MODEL", "").strip()).strip()
                label = "%s  ·  %s" % (name, kv.get("SIZE", "?"))
                if ident:
                    label += "  ·  " + ident
                if kv.get("TRAN"):
                    label += "  [%s]" % kv["TRAN"]
                if kv.get("SERIAL", "").strip():
                    label += "  SN:" + kv["SERIAL"].strip()[:16]
                out.append((name, label))
            if out:
                return out
    except Exception:
        pass
    for pat in ("/dev/nvme*n[0-9]", "/dev/sd[a-z]"):
        for dev in sorted(glob.glob(pat)):
            out.append((dev, dev))
    return out


def detect_block_devices():
    """Return [(path, label)] for likely source devices. Best-effort, read-only."""
    if IS_WINDOWS:
        return _detect_windows()
    if IS_MAC:
        return _detect_macos()
    return _detect_linux()


def device_size_bytes(dev):
    """Best-effort byte size of a block device (Linux/macOS)."""
    try:
        if IS_WINDOWS:
            return None
        r = subprocess.run(["lsblk", "-bdno", "SIZE", dev],
                           capture_output=True, text=True, timeout=8)
        return int(r.stdout.strip().splitlines()[0])
    except Exception:
        return None


def dest_backing_disk(path):
    """Whole disk that backs a destination directory/file (Linux), or None."""
    try:
        r = subprocess.run(["df", "--output=source", path],
                           capture_output=True, text=True, timeout=8)
        lines = r.stdout.strip().splitlines()
        if len(lines) >= 2 and lines[1].startswith("/dev/"):
            return base_disk(lines[1].strip())
    except Exception:
        pass
    return None


def detect_writable_mounts(exclude_disk=None):
    """Best-effort list of plausible DESTINATION drives (where a rescue image
    can be saved): mounted, writable, real filesystems on a different disk than
    the one being imaged. Returns [(mountpoint, label, free_bytes, disk)]."""
    if IS_WINDOWS:
        return _writable_mounts_windows(exclude_disk)
    if IS_MAC:
        return _writable_mounts_macos(exclude_disk)
    return _writable_mounts_linux(exclude_disk)


def _mount_entry(mp, free, total, extra, disk):
    label = "%s  ·  free %s / %s" % (mp, human(free), human(total))
    if extra:
        label += "  ·  " + extra
    return (mp, label, free, disk)


def _writable_mounts_linux(exclude_disk):
    out = []
    try:
        res = subprocess.run(
            ["lsblk", "-pP", "-o",
             "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,RO,RM,MODEL,VENDOR,LABEL"],
            capture_output=True, text=True, timeout=6)
        for line in res.stdout.splitlines():
            kv = dict(re.findall(r'(\w+)="([^"]*)"', line))
            mp = kv.get("MOUNTPOINT", "").strip()
            if not mp or kv.get("RO") == "1":
                continue
            fst = kv.get("FSTYPE", "").strip()
            if not fst or fst == "swap":
                continue
            # skip the live OS / system mounts; we want data drives only
            if mp == "/" or mp.startswith(("/boot", "/proc", "/sys",
                                           "/run", "/dev", "/var", "/snap")):
                continue
            disk = base_disk(kv.get("NAME", ""))
            if exclude_disk and disk == exclude_disk:
                continue
            if not os.access(mp, os.W_OK):
                continue
            try:
                du = shutil.disk_usage(mp)
            except Exception:
                continue
            ident = (kv.get("VENDOR", "").strip() + " " +
                     kv.get("MODEL", "").strip()).strip()
            extra = ident
            if kv.get("LABEL", "").strip():
                extra = (extra + "  “%s”" % kv["LABEL"].strip()).strip()
            out.append(_mount_entry(mp, du.free, du.total, extra or fst, disk))
    except Exception:
        pass
    # Fallback: probe the usual removable-media roots directly.
    if not out:
        for root in ("/media", "/mnt", "/run/media"):
            for sub in sorted(glob.glob(os.path.join(root, "*")) +
                              glob.glob(os.path.join(root, "*", "*"))):
                if os.path.ismount(sub) and os.access(sub, os.W_OK):
                    try:
                        du = shutil.disk_usage(sub)
                    except Exception:
                        continue
                    out.append(_mount_entry(sub, du.free, du.total, "", None))
    return out


def _writable_mounts_macos(exclude_disk):
    out = []
    for sub in sorted(glob.glob("/Volumes/*")):
        if not os.path.isdir(sub) or not os.access(sub, os.W_OK):
            continue
        try:
            du = shutil.disk_usage(sub)
        except Exception:
            continue
        out.append(_mount_entry(sub, du.free, du.total,
                                os.path.basename(sub), None))
    return out


def _writable_mounts_windows(exclude_disk):
    out = []
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        root = "%s:\\" % letter
        if not os.path.isdir(root):
            continue
        try:
            du = shutil.disk_usage(root)
        except Exception:
            continue
        out.append(_mount_entry(root, du.free, du.total, "", None))
    return out



def load_settings():
    try:
        with open(SETTINGS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(data):
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def count_csv_rows(path):
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, newline="") as f:
            return max(0, sum(1 for _ in f) - 1)
    except Exception:
        return 0


# --------------------------------------------------------------------------- #
#  Worker: runs engine phases sequentially, streams output via a queue         #
# --------------------------------------------------------------------------- #

class Runner(object):
    def __init__(self, out_q):
        self.q = out_q
        self.proc = None
        self.thread = None
        self.cancelled = False

    def is_running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, jobs):
        """jobs: list of (title, argv-list)."""
        self.cancelled = False
        self.thread = threading.Thread(target=self._run, args=(jobs,), daemon=True)
        self.thread.start()

    def cancel(self):
        self.cancelled = True
        p = self.proc
        if p and p.poll() is None:
            try:
                p.terminate()                           # cross-platform
            except Exception:
                pass

    def _emit(self, kind, text):
        self.q.put((kind, text))

    def _run(self, jobs):
        ok = True
        for title, argv in jobs:
            if self.cancelled:
                break
            self._emit("phase", title)
            self._emit("cmd", " ".join(shlex.quote(a) for a in argv))
            try:
                self.proc = subprocess.Popen(
                    argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    bufsize=1, universal_newlines=True)
            except Exception as exc:
                self._emit("err", "failed to launch: %s" % exc)
                ok = False
                break
            for line in iter(self.proc.stdout.readline, ""):
                self._emit("log", line.rstrip("\n"))
            self.proc.stdout.close()
            rc = self.proc.wait()
            if self.cancelled:
                self._emit("warn", "%s cancelled." % title)
                ok = False
                break
            if rc != 0:
                self._emit("err", "%s exited with code %d" % (title, rc))
                ok = False
            else:
                self._emit("done", title)
        self.proc = None
        self._emit("finished", "ok" if ok else "fail")


# --------------------------------------------------------------------------- #
#  Main application                                                            #
# --------------------------------------------------------------------------- #

class App(object):
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.runner = Runner(self.q)
        self.phase_vars = {}
        self.last_out = None
        self.settings = load_settings()
        self._after_image_dest = None
        self._start_ts = None
        self._phase_idx = 0
        self._phase_total = 0
        self._cur_phase = ""

        root.title("NVMe Source Recovery")
        root.configure(bg=BG)
        root.geometry("1180x760")
        root.minsize(940, 620)

        self._init_fonts()
        self._init_style()
        self._set_icon()
        self._build_menu()
        self._build()
        self._apply_settings()
        self._refresh_devices()
        self._bind_keys()
        self._tick()
        self.root.after(80, self._pump)
        self.root.after(300, lambda: self._trim("status"))
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_icon(self):
        for name in ("mark.png", "logo.png"):
            p = os.path.join(resource_dir(), "assets", name)
            if os.path.isfile(p):
                try:
                    self._icon = tk.PhotoImage(file=p)
                    self.root.iconphoto(True, self._icon)
                    return
                except Exception:
                    continue

    def _build_menu(self):
        bar = tk.Menu(self.root)
        filem = tk.Menu(bar, tearoff=0)
        filem.add_command(label="Open output folder", command=self._open_output,
                          accelerator="Ctrl+O")
        filem.add_command(label="Save log…", command=self._save_log,
                          accelerator="Ctrl+S")
        filem.add_separator()
        filem.add_command(label="Quit", command=self._on_close, accelerator="Ctrl+Q")
        bar.add_cascade(label="File", menu=filem)
        runm = tk.Menu(bar, tearoff=0)
        runm.add_command(label="Image drive… (create .img)", command=self._image_drive)
        runm.add_command(label="Verify image… (check .sha256)", command=self._verify_image)
        runm.add_separator()
        runm.add_command(label="Run selected", command=self._run_selected,
                         accelerator="Ctrl+R")
        runm.add_command(label="Stop", command=self._stop, accelerator="Esc")
        runm.add_command(label="Self-test", command=self._run_selftest)
        runm.add_separator()
        runm.add_command(label="Refresh results", command=self._load_results,
                         accelerator="F5")
        bar.add_cascade(label="Run", menu=runm)
        toolsm = tk.Menu(bar, tearoff=0)
        toolsm.add_command(label="TRIM status", command=lambda: self._trim("status"))
        toolsm.add_command(label="Disable TRIM (protect data)",
                           command=lambda: self._trim("disable"))
        toolsm.add_command(label="Enable TRIM (restore)",
                           command=lambda: self._trim("enable"))
        bar.add_cascade(label="Tools", menu=toolsm)
        helpm = tk.Menu(bar, tearoff=0)
        helpm.add_command(label="About", command=self._about)
        bar.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=bar)

    def _bind_keys(self):
        self.root.bind("<Control-r>", lambda e: self._run_selected())
        self.root.bind("<Control-o>", lambda e: self._open_output())
        self.root.bind("<Control-s>", lambda e: self._save_log())
        self.root.bind("<Control-q>", lambda e: self._on_close())
        self.root.bind("<F5>", lambda e: self._load_results())
        self.root.bind("<Escape>", lambda e: self._stop())

    # -- styling ----------------------------------------------------------- #
    def _init_fonts(self):
        self.f_ui = tkfont.Font(family="DejaVu Sans", size=10)
        self.f_h1 = tkfont.Font(family="DejaVu Sans", size=16, weight="bold")
        self.f_h2 = tkfont.Font(family="DejaVu Sans", size=11, weight="bold")
        self.f_mono = tkfont.Font(family="DejaVu Sans Mono", size=10)
        self.f_small = tkfont.Font(family="DejaVu Sans", size=9)

    def _init_style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=BG_INPUT,
                     bordercolor=BORDER, font=self.f_ui)
        st.configure("TFrame", background=BG)
        st.configure("Panel.TFrame", background=BG_PANEL)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Panel.TLabel", background=BG_PANEL, foreground=FG)
        st.configure("Mute.TLabel", background=BG, foreground=FG_MUTE, font=self.f_small)
        st.configure("PanelMute.TLabel", background=BG_PANEL, foreground=FG_MUTE,
                     font=self.f_small)
        st.configure("H1.TLabel", background=BG, foreground=FG, font=self.f_h1)
        st.configure("H2.TLabel", background=BG_PANEL, foreground=ACCENT, font=self.f_h2)
        st.configure("TButton", background=BG_PANEL, foreground=FG, borderwidth=1,
                     focusthickness=0, padding=6)
        st.map("TButton",
               background=[("active", BORDER), ("disabled", BG_PANEL)],
               foreground=[("disabled", FG_MUTE)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#06121f",
                     font=self.f_h2, padding=8)
        st.map("Accent.TButton",
               background=[("active", "#5aa0ea"), ("disabled", BORDER)],
               foreground=[("disabled", FG_MUTE)])
        # Checkbuttons: make the tick state unmistakable on a dark theme.
        # Unchecked = dark box with a visible border; checked = filled accent box.
        for cb_style in ("TCheckbutton", "Phase.TCheckbutton"):
            st.configure(cb_style, background=BG_PANEL, foreground=FG,
                         focuscolor=BG_PANEL, indicatorbackground=BG_INPUT,
                         indicatorforeground=ACCENT, indicatorcolor=BG_INPUT,
                         bordercolor=BORDER, indicatormargin=4)
            st.map(cb_style,
                   background=[("active", BG_PANEL)],
                   foreground=[("disabled", FG_MUTE)],
                   indicatorbackground=[("selected", ACCENT),
                                        ("active", "#1b2937")],
                   indicatorforeground=[("selected", "#06121f")],
                   indicatorcolor=[("selected", ACCENT), ("active", "#1b2937")],
                   bordercolor=[("selected", ACCENT), ("active", ACCENT)])
        st.configure("Phase.TCheckbutton", font=self.f_h2)
        st.configure("Footer.TFrame", background=BG_INPUT)
        st.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG,
                     insertcolor=FG, bordercolor=BORDER)
        st.configure("TCombobox", fieldbackground=BG_INPUT, foreground=FG,
                     background=BG_PANEL, arrowcolor=FG)
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_MUTE,
                     padding=(16, 7))
        st.map("TNotebook.Tab",
               background=[("selected", BG)],
               foreground=[("selected", ACCENT)])
        st.configure("Horizontal.TProgressbar", background=ACCENT,
                     troughcolor=BG_INPUT, bordercolor=BORDER)
        st.configure("Treeview", background=BG_INPUT, fieldbackground=BG_INPUT,
                     foreground=FG, borderwidth=0, rowheight=22)
        st.map("Treeview", background=[("selected", ACCENT)],
               foreground=[("selected", "#06121f")])

    # -- layout ------------------------------------------------------------ #
    def _build(self):
        # Header ---------------------------------------------------------- #
        head = ttk.Frame(self.root, padding=(16, 12, 16, 8))
        head.pack(fill="x")
        ttk.Label(head, text="NVMe Source Recovery", style="H1.TLabel").pack(side="left")
        badge = tk.Label(head, text="  READ-ONLY  ", bg=OK, fg="#06121f",
                         font=self.f_small)
        badge.pack(side="left", padx=12)
        ttk.Label(head, text="forensic recovery of deleted source & archives "
                  "from NTFS / NVMe", style="Mute.TLabel").pack(side="left", padx=4)

        body = ttk.Frame(self.root, padding=(16, 0, 16, 8))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=0, minsize=340)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_left(body)
        self._build_right(body)
        self._build_statusbar()

    def _build_left(self, parent):
        # Outer panel: row 0 = scrollable config, row 1 = sticky action footer.
        left = ttk.Frame(parent, style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        canvas = tk.Canvas(left, bg=BG_PANEL, highlightthickness=0, borderwidth=0)
        vsb = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        inner = ttk.Frame(canvas, style="Panel.TFrame", padding=(14, 14, 8, 14))
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(win, width=e.width))
        self._bind_wheel(canvas)

        # --- Source ---
        ttk.Label(inner, text="SOURCE  (image or device)", style="H2.TLabel").pack(anchor="w")
        srow = ttk.Frame(inner, style="Panel.TFrame")
        srow.pack(fill="x", pady=(4, 2))
        self.src_var = tk.StringVar()
        self.src_combo = ttk.Combobox(srow, textvariable=self.src_var)
        self.src_combo.pack(side="left", fill="x", expand=True)
        ttk.Button(srow, text="↻", width=3, command=self._refresh_devices).pack(side="left", padx=(4, 0))
        brow = ttk.Frame(inner, style="Panel.TFrame")
        brow.pack(fill="x")
        ttk.Button(brow, text="Browse image…", command=self._pick_image).pack(side="left")
        ttk.Button(brow, text="Identify disk", command=self._identify_disk).pack(side="left", padx=(6, 0))
        brow2 = ttk.Frame(inner, style="Panel.TFrame")
        brow2.pack(fill="x", pady=(4, 0))
        ttk.Button(brow2, text="① Image drive → .img",
                   command=self._image_drive).pack(side="left")
        ttk.Button(brow2, text="Verify image",
                   command=self._verify_image).pack(side="left", padx=(6, 0))
        dev_hint = ("Pick a forensic .img, or a detected disk "
                    "(\\\\.\\PhysicalDriveN — run as Administrator).\n"
                    "Tip: image the drive first, then recover from the safe copy." if IS_WINDOWS
                    else "Pick a forensic .img, or a detected device (opened read-only).\n"
                    "Tip: image the drive first, then recover from the safe copy.")
        ttk.Label(inner, text=dev_hint, style="PanelMute.TLabel",
                  wraplength=300, justify="left").pack(anchor="w", pady=(2, 12))

        # --- Output ---
        ttk.Label(inner, text="OUTPUT DIRECTORY", style="H2.TLabel").pack(anchor="w")
        orow = ttk.Frame(inner, style="Panel.TFrame")
        orow.pack(fill="x", pady=(4, 2))
        self.out_var = tk.StringVar()
        ttk.Entry(orow, textvariable=self.out_var).pack(side="left", fill="x", expand=True)
        ttk.Button(orow, text="Browse…", command=self._pick_out).pack(side="left", padx=(4, 0))
        ttk.Label(inner, text="Recovered files & manifests are written here.",
                  style="PanelMute.TLabel").pack(anchor="w", pady=(2, 12))

        # --- Phases ---
        phdr = ttk.Frame(inner, style="Panel.TFrame")
        phdr.pack(fill="x")
        ttk.Label(phdr, text="PHASES", style="H2.TLabel").pack(side="left")
        ttk.Button(phdr, text="none", width=5,
                   command=lambda: self._set_all_phases(False)).pack(side="right")
        ttk.Button(phdr, text="all", width=4,
                   command=lambda: self._set_all_phases(True)).pack(side="right", padx=(0, 4))
        for pid, label, _cmd, tip in PHASES:
            v = tk.BooleanVar(value=True)
            self.phase_vars[pid] = v
            cb = ttk.Checkbutton(inner, text=label, variable=v, style="Phase.TCheckbutton")
            cb.pack(anchor="w", pady=(5, 0))
            ttk.Label(inner, text=tip, style="PanelMute.TLabel",
                      wraplength=296, justify="left").pack(anchor="w", padx=(24, 0))

        # --- Options ---
        ttk.Label(inner, text="OPTIONS", style="H2.TLabel").pack(anchor="w", pady=(12, 0))
        self.opt_carve = tk.BooleanVar(value=False)
        ttk.Checkbutton(inner, text="Carve non-resident file bodies",
                        variable=self.opt_carve).pack(anchor="w", pady=(5, 0))
        ttk.Label(inner, text="Pull data from cluster runs (may be zeros if TRIMed).",
                  style="PanelMute.TLabel", wraplength=296,
                  justify="left").pack(anchor="w", padx=(24, 0))
        self.opt_unclass = tk.BooleanVar(value=False)
        ttk.Checkbutton(inner, text="Keep unclassified text blobs",
                        variable=self.opt_unclass).pack(anchor="w", pady=(5, 0))

        # --- TRIM protection ---
        ttk.Label(inner, text="TRIM PROTECTION", style="H2.TLabel").pack(anchor="w", pady=(12, 0))
        self.trim_status = ttk.Label(inner, text="TRIM: checking…",
                                     style="PanelMute.TLabel")
        self.trim_status.pack(anchor="w", pady=(2, 4))
        trow = ttk.Frame(inner, style="Panel.TFrame")
        trow.pack(fill="x")
        ttk.Button(trow, text="Check",
                   command=lambda: self._trim("status")).pack(side="left")
        ttk.Button(trow, text="Disable (protect)",
                   command=lambda: self._trim("disable")).pack(side="left", padx=(6, 0))
        ttk.Button(trow, text="Enable (restore)",
                   command=lambda: self._trim("enable")).pack(side="left", padx=(6, 0))
        ttk.Label(inner, text="System-wide; affects all SSDs and needs admin/root. "
                  "Disable BEFORE connecting the damaged drive. Only stops FUTURE "
                  "erasure — already-TRIMed data is gone.",
                  style="PanelMute.TLabel", wraplength=296,
                  justify="left").pack(anchor="w", pady=(2, 0))

        # --- Sticky action footer (always visible, never scrolls) ---
        footer = ttk.Frame(left, style="Footer.TFrame", padding=(12, 10))
        footer.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.run_btn = ttk.Button(footer, text="▶  RUN RECOVERY", style="Accent.TButton",
                                  command=self._run_selected)
        self.run_btn.pack(fill="x")
        row2 = ttk.Frame(footer, style="Footer.TFrame")
        row2.pack(fill="x", pady=(6, 0))
        self.stop_btn = ttk.Button(row2, text="■ Stop", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", fill="x", expand=True)
        ttk.Button(row2, text="Self-test", command=self._run_selftest).pack(side="left", padx=(6, 0), fill="x", expand=True)
        ttk.Button(row2, text="Open output", command=self._open_output).pack(side="left", padx=(6, 0), fill="x", expand=True)

    def _bind_wheel(self, canvas):
        def _on_wheel(event):
            if event.num == 4:                          # Linux scroll up
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:                        # Linux scroll down
                canvas.yview_scroll(1, "units")
            else:                                       # Windows / macOS
                canvas.yview_scroll(int(-event.delta / 120) or
                                    (-1 if event.delta > 0 else 1), "units")

        def _enter(_e):
            canvas.bind_all("<MouseWheel>", _on_wheel)
            canvas.bind_all("<Button-4>", _on_wheel)
            canvas.bind_all("<Button-5>", _on_wheel)

        def _leave(_e):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _enter)
        canvas.bind("<Leave>", _leave)

    def _build_right(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.grid(row=0, column=1, sticky="nsew")

        # Log tab
        logtab = ttk.Frame(self.nb)
        self.nb.add(logtab, text="Live log")
        self.log = tk.Text(logtab, bg=BG_INPUT, fg=FG, insertbackground=FG,
                           font=self.f_mono, wrap="none", borderwidth=0,
                           padx=10, pady=8)
        ysb = ttk.Scrollbar(logtab, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=ysb.set, state="disabled")
        ysb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)
        self.log.tag_configure("muted", foreground=FG_MUTE)
        self.log.tag_configure("phase", foreground=ACCENT, font=self.f_h2)
        self.log.tag_configure("cmd", foreground=FG_MUTE, font=self.f_small)
        self.log.tag_configure("ok", foreground=OK)
        self.log.tag_configure("warn", foreground=WARN)
        self.log.tag_configure("err", foreground=ERR)

        # Results tab
        self._build_results_tab()

    def _build_results_tab(self):
        res = ttk.Frame(self.nb, padding=8)
        self.nb.add(res, text="Results")

        # Summary cards row
        self.cards = ttk.Frame(res)
        self.cards.pack(fill="x", pady=(0, 8))
        self.card_labels = {}
        for key, title in [("resident", "Resident files\n(intact)"),
                           ("listed", "Files listed\nin $MFT"),
                           ("deletes", "USN delete\nevents"),
                           ("photos", "Photos\ncarved"),
                           ("videos", "Videos\ncarved"),
                           ("source", "Source\nfragments"),
                           ("archives", "Archives\ncarved")]:
            card = ttk.Frame(self.cards, style="Panel.TFrame", padding=10)
            card.pack(side="left", fill="x", expand=True, padx=3)
            val = tk.Label(card, text="–", bg=BG_PANEL, fg=ACCENT,
                           font=self.f_h1)
            val.pack()
            tk.Label(card, text=title, bg=BG_PANEL, fg=FG_MUTE,
                     font=self.f_small, justify="center").pack()
            self.card_labels[key] = val

        # Split: file tree | preview
        split = ttk.Panedwindow(res, orient="horizontal")
        split.pack(fill="both", expand=True)

        treebox = ttk.Frame(split)
        frow = ttk.Frame(treebox)
        frow.pack(fill="x", pady=(0, 4))
        ttk.Label(frow, text="Filter:", style="Mute.TLabel").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(frow, textvariable=self.filter_var).pack(side="left", fill="x",
                                                           expand=True, padx=(4, 6))
        self.tree_count = ttk.Label(frow, text="", style="Mute.TLabel")
        self.tree_count.pack(side="right")
        treerow = ttk.Frame(treebox)
        treerow.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(treerow, show="tree", selectmode="browse")
        tsb = ttk.Scrollbar(treerow, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_open)
        split.add(treebox, weight=1)

        prevbox = ttk.Frame(split)
        ttk.Label(prevbox, text="PREVIEW", style="H2.TLabel").pack(anchor="w")
        self.preview = tk.Text(prevbox, bg=BG_INPUT, fg=FG, font=self.f_mono,
                               wrap="none", borderwidth=0, padx=8, pady=6,
                               state="disabled")
        psb = ttk.Scrollbar(prevbox, orient="vertical", command=self.preview.yview)
        self.preview.configure(yscrollcommand=psb.set)
        psb.pack(side="right", fill="y")
        self.preview.pack(side="left", fill="both", expand=True)
        split.add(prevbox, weight=2)

        bar = ttk.Frame(res)
        bar.pack(fill="x", pady=(6, 0))
        ttk.Button(bar, text="↻ Refresh", command=self._load_results).pack(side="left")
        ttk.Button(bar, text="Open in file manager", command=self._open_output).pack(side="left", padx=6)
        self._tree_paths = {}

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(16, 4, 16, 8))
        bar.pack(fill="x")
        self.pbar = ttk.Progressbar(bar, mode="determinate", maximum=100)
        self.pbar.pack(side="left", fill="x", expand=True)
        self.timing = ttk.Label(bar, text="", style="Mute.TLabel")
        self.timing.pack(side="left", padx=(10, 0))
        self.status = ttk.Label(bar, text="Ready.", style="Mute.TLabel")
        self.status.pack(side="left", padx=10)

    # -- actions ----------------------------------------------------------- #
    def _refresh_devices(self):
        devs = detect_block_devices()
        # Show the rich label (path · size · model · [bus] · serial) in the list,
        # but keep a label->path map so we run against the real device node.
        self._dev_by_label = {label: path for path, label in devs}
        self.src_combo["values"] = [label for _path, label in devs]
        self._set_status("Found %d disk(s). Pick yours by size/model." % len(devs)
                         if devs else "No disks detected — browse for an image, "
                         "or run as root/Administrator.")

    def _source_path(self):
        """Resolve whatever is shown in the source box to a real path/device node."""
        raw = self.src_var.get().strip()
        return getattr(self, "_dev_by_label", {}).get(raw, raw)

    def _identify_disk(self):
        dev = self._source_path()
        if not dev or not self._is_device(dev):
            messagebox.showinfo("Identify disk",
                                "Pick a disk from the list first (not an image file), "
                                "then Identify shows its partitions so you can confirm "
                                "it's the right drive.")
            return
        self._set_status("Identifying %s…" % dev)
        threading.Thread(target=self._identify_worker, args=(dev,), daemon=True).start()

    def _identify_worker(self, dev):
        if IS_WINDOWS:
            cmd = ["powershell", "-NoProfile", "-Command",
                   "Get-CimInstance Win32_DiskDrive | Where-Object DeviceID -eq "
                   "'%s' | Format-List Model,SerialNumber,Size,InterfaceType,Partitions"
                   % dev]
        elif IS_MAC:
            cmd = ["diskutil", "info", dev]
        else:
            cmd = ["lsblk", "-o",
                   "NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL,TRAN", dev]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out = (r.stdout or "") + (r.stderr or "")
        except Exception as exc:
            out = str(exc)
        self.q.put(("identify", (dev, out.strip())))

    def _pick_image(self):
        path = filedialog.askopenfilename(
            title="Select forensic image",
            filetypes=[("Disk images", "*.img *.dd *.raw *.bin"), ("All files", "*")])
        if path:
            self.src_var.set(path)
            if not self.out_var.get():
                self.out_var.set(os.path.join(os.path.dirname(path), "recovered"))

    def _pick_out(self):
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self.out_var.set(path)

    def _selected_phase_cmds(self):
        return [cmd for pid, _l, cmd, _t in PHASES if self.phase_vars[pid].get()]

    def _is_device(self, src):
        return src.startswith(("/dev/", "\\\\.\\", "\\\\?\\"))

    def _validate(self):
        src = self._source_path()
        out = self.out_var.get().strip()
        is_dev = self._is_device(src)
        if not src or (not is_dev and not os.path.exists(src)):
            messagebox.showerror("Source missing",
                                 "Select a valid image file or device first.")
            return None
        if not out:
            messagebox.showerror("Output missing", "Choose an output directory.")
            return None
        if not FROZEN and not os.path.isfile(ENGINE):
            messagebox.showerror("Engine missing",
                                 "Cannot find nvme_recover.py next to this GUI:\n%s" % ENGINE)
            return None
        if is_dev:
            note = ("\n\nWindows: this GUI must be started as Administrator to read it."
                    if IS_WINDOWS else "")
            if not messagebox.askyesno(
                    "Run against a live device?",
                    "%s is a physical device.\n\nThe engine opens it READ-ONLY, but the "
                    "recommended workflow is to image it first.%s\n\nContinue read-only?"
                    % (src, note)):
                return None
        return src, out

    def _run_selected(self):
        cmds = self._selected_phase_cmds()
        if not cmds:
            messagebox.showinfo("No phases", "Select at least one phase to run.")
            return
        self._launch(cmds)

    def _launch(self, cmds):
        v = self._validate()
        if not v:
            return
        src, out = v
        try:
            os.makedirs(out, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("Output error", "Cannot create output dir:\n%s" % exc)
            return
        self.last_out = out
        regions = os.path.join(out, "00_analysis", "regions.json")

        jobs = []
        for cmd in cmds:
            argv = engine_argv(cmd, "--image", src, "--out", out)
            if cmd in ("mft",) and self.opt_carve.get():
                argv.append("--carve-nonresident")
            if cmd == "source" and self.opt_unclass.get():
                argv.append("--include-unclassified")
            # Restrict only the bulk-data carvers to live extents (faster). mft
            # and usn must scan the WHOLE image: their records survive in regions
            # analyze marks as dead, so region-limiting would miss them.
            if cmd in ("archives", "media", "source") and \
                    ("analyze" in cmds or os.path.isfile(regions)):
                argv += ["--regions", regions]
            jobs.append((CMD_LABEL.get(cmd, cmd), argv))
        self._start_jobs(jobs)

    def _run_selftest(self):
        out = self.out_var.get().strip() or os.path.join(HERE, "_selftest")
        out = os.path.join(out, "_selftest") if os.path.basename(out) != "_selftest" else out
        argv = engine_argv("selftest", "--out", out)
        self.last_out = os.path.join(out, "out")
        self._start_jobs([("Self-test", argv)])

    def _choose_dest_dir(self, src_disk, min_bytes, initial):
        """Modal picker that lists mounted, writable destination drives so the
        user can save the rescue image to a SEPARATE drive without hunting
        through the file dialog. Returns a directory path, or None if cancelled."""
        win = tk.Toplevel(self.root)
        win.title("Choose destination drive")
        win.configure(bg=BG)
        win.transient(self.root)
        win.resizable(False, False)
        result = {"dir": None}

        ttk.Label(win, text="Where should the rescue image be saved?",
                  style="H2.TLabel").pack(anchor="w", padx=14, pady=(12, 2))
        ttk.Label(win, wraplength=520, style="Mute.TLabel",
                  text=("Pick a SEPARATE drive with enough free space — NOT the drive "
                        "you're imaging, and ideally not the live-USB you booted from.\n"
                        "Don't see your drive? Plug it in and mount it (Files app, or: "
                        "sudo mount /dev/sdX1 /mnt), then press Refresh.")
                  ).pack(anchor="w", padx=14, pady=(0, 8))

        lb = tk.Listbox(win, width=72, height=7, activestyle="none",
                        bg=BG_INPUT, fg=FG, selectbackground=ACCENT,
                        selectforeground="#06121f", highlightthickness=1,
                        highlightbackground=BORDER, relief="flat",
                        font=self.f_mono)
        lb.pack(fill="x", padx=14)
        rows = []

        def refill():
            lb.delete(0, "end")
            del rows[:]
            mounts = detect_writable_mounts(exclude_disk=src_disk)
            if not mounts:
                lb.insert("end", "  (no extra drives detected — use Browse… below)")
                rows.append(None)
            for mp, label, free, _disk in mounts:
                tag = "   ⚠ may not fit" if (min_bytes and free < min_bytes) else ""
                lb.insert("end", "  " + label + tag)
                rows.append(mp)
            if rows and rows[0]:
                lb.selection_set(0)

        def use_selected():
            sel = lb.curselection()
            if sel and rows[sel[0]]:
                result["dir"] = rows[sel[0]]
                win.destroy()

        def browse():
            d = filedialog.askdirectory(
                parent=win, title="Choose destination folder",
                initialdir=initial if os.path.isdir(initial) else "/")
            if d:
                result["dir"] = d
                win.destroy()

        lb.bind("<Double-Button-1>", lambda _e: use_selected())
        refill()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=14, pady=12)
        ttk.Button(btns, text="Refresh", command=refill).pack(side="left")
        ttk.Button(btns, text="Browse…", command=browse).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel",
                   command=win.destroy).pack(side="right")
        ttk.Button(btns, text="Use this drive", style="Accent.TButton",
                   command=use_selected).pack(side="right", padx=6)

        win.update_idletasks()
        win.grab_set()
        win.wait_window()
        return result["dir"]

    def _image_drive(self):
        """Create a read-only raw image of the selected disk/partition first."""
        src = self._source_path()
        if not src or (not self._is_device(src) and not os.path.exists(src)):
            messagebox.showerror("Source missing",
                                 "Select the disk / device (or an image) to copy first.")
            return
        if not FROZEN and not os.path.isfile(ENGINE):
            messagebox.showerror("Engine missing",
                                 "Cannot find nvme_recover.py next to this GUI:\n%s" % ENGINE)
            return

        src_disk = base_disk(src) if (self._is_device(src) and not IS_WINDOWS) else None
        src_bytes = (device_size_bytes(src) if self._is_device(src)
                     else (os.path.getsize(src) if os.path.isfile(src) else None))
        initial = (self.out_var.get().strip() or os.path.expanduser("~"))

        # For a live device, lead with the drive picker so the destination is
        # always a real, mounted, SEPARATE drive (the live-USB pain point).
        if self._is_device(src):
            destdir0 = self._choose_dest_dir(src_disk, src_bytes, initial)
            if not destdir0:
                return
        else:
            destdir0 = initial

        dest = filedialog.asksaveasfilename(
            title="Save disk image as…  (choose a SEPARATE drive)",
            defaultextension=".img",
            initialdir=destdir0 if os.path.isdir(destdir0) else os.path.expanduser("~"),
            initialfile="rescue.img",
            filetypes=[("Raw disk image", "*.img"), ("All files", "*")])
        if not dest:
            return
        destdir = os.path.dirname(os.path.abspath(dest)) or "."

        # Safety: never write the image onto the very disk we're imaging.
        if src_disk:
            dest_disk = dest_backing_disk(destdir)
            if dest_disk and dest_disk == src_disk:
                messagebox.showerror(
                    "Unsafe destination",
                    "That destination lives on the SAME disk you're imaging (%s).\n\n"
                    "Writing the image there would overwrite the data you're trying "
                    "to recover. Choose a different drive." % src_disk)
                return

        # Capacity check: does the image fit?
        try:
            free = shutil.disk_usage(destdir).free
        except Exception:
            free = None
        if src_bytes and free is not None and free < src_bytes:
            if not messagebox.askyesno(
                    "Not enough free space?",
                    "The source is %s but the destination only has %s free.\n\n"
                    "The image likely won't fit. Continue anyway?"
                    % (human(src_bytes), human(free))):
                return

        if self._is_device(src):
            note = ("\n\nWindows: the GUI must be running as Administrator to read it."
                    if IS_WINDOWS else "")
            sz = "  (%s)" % human(src_bytes) if src_bytes else ""
            if not messagebox.askyesno(
                    "Create read-only image?",
                    "Read %s%s and write a full image to:\n%s\n\n"
                    "The source is opened READ-ONLY and never modified.%s\n\nProceed?"
                    % (src, sz, dest, note)):
                return
        argv = engine_argv("image", "--image", src, "--dest", dest)
        self._after_image_dest = dest
        self.last_out = os.path.dirname(dest) or None
        self._start_jobs([("Image drive", argv)])

    def _verify_image(self):
        """Re-hash an .img and compare it to its .sha256 sidecar so you can
        confirm a rescue image is complete and uncorrupted before trusting it."""
        if not FROZEN and not os.path.isfile(ENGINE):
            messagebox.showerror("Engine missing",
                                 "Cannot find nvme_recover.py next to this GUI:\n%s" % ENGINE)
            return
        src = self._source_path()
        initial = src if (src and os.path.isfile(src)) else \
            (self.out_var.get().strip() or os.path.expanduser("~"))
        img = filedialog.askopenfilename(
            title="Select image to verify",
            initialdir=os.path.dirname(initial) if os.path.isfile(initial) else initial,
            filetypes=[("Disk images", "*.img *.dd *.raw *.bin"), ("All files", "*")])
        if not img:
            return
        if not os.path.isfile(img + ".sha256"):
            if not messagebox.askyesno(
                    "No checksum sidecar",
                    "No %s.sha256 was found, so there's nothing to compare against.\n\n"
                    "Compute and print the image's hash anyway?" % os.path.basename(img)):
                return
        self.last_out = os.path.dirname(img) or None
        self._start_jobs([("Verify image", engine_argv("verify", "--image", img))])

    # -- TRIM control ------------------------------------------------------ #
    def _trim(self, action):
        if not FROZEN and not os.path.isfile(TRIM_SCRIPT):
            messagebox.showerror("Missing", "trim_control.py not found next to the GUI.")
            return
        if action == "disable":
            if not messagebox.askyesno(
                    "Disable TRIM?",
                    "Turn TRIM OFF system-wide to protect deleted data from further "
                    "erasure?\n\n• Affects ALL SSDs on this machine.\n"
                    "• Changes an OS setting, not any drive's contents.\n"
                    "• Only prevents FUTURE erasure — already-TRIMed data is gone.\n"
                    "• Needs %s.\n\nProceed?" % ("Administrator" if IS_WINDOWS else "root/sudo")):
                return
        elif action == "enable":
            if not messagebox.askyesno(
                    "Enable TRIM?",
                    "Turn TRIM back ON system-wide?\n\nDo this only AFTER you have "
                    "finished recovering — it lets the SSD erase freed blocks again "
                    "(good for performance/longevity).\n\nProceed?"):
                return
        self._set_status("TRIM: running %s…" % action)
        threading.Thread(target=self._trim_worker, args=(action,), daemon=True).start()

    def _trim_worker(self, action):
        try:
            r = subprocess.run(trim_argv(action),
                               capture_output=True, text=True, timeout=90)
            out = (r.stdout or "") + (r.stderr or "")
            rc = r.returncode
        except Exception as exc:
            out, rc = str(exc), 1
        state = "UNKNOWN"
        for line in out.splitlines():
            if line.startswith("TRIM_STATE:"):
                state = line.split(":", 1)[1].strip()
        self.q.put(("trim_result", (action, rc, out, state)))

    def _update_trim_label(self, state):
        text = {
            "DISABLED": "TRIM: OFF — safe for recovery",
            "ENABLED": "TRIM: ON — disable before recovery",
            "MIXED": "TRIM: MIXED — some volumes still trimming",
            "UNKNOWN": "TRIM: unknown (need admin/root to read?)",
        }.get(state, "TRIM: " + state)
        color = {"DISABLED": OK, "ENABLED": WARN, "MIXED": WARN}.get(state, FG_MUTE)
        self.trim_status.configure(text=text, foreground=color)

    def _start_jobs(self, jobs):
        if self.runner.is_running():
            messagebox.showinfo("Busy", "A recovery is already running.")
            return
        self._save_state()
        self._clear_log()
        self._append("phase", "Starting %d phase(s)…\n" % len(jobs))
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.pbar.configure(mode="indeterminate")
        self.pbar.start(12)
        self._start_ts = time.time()
        self._phase_idx = 0
        self._phase_total = len(jobs)
        self.nb.select(0)
        self.runner.start(jobs)

    def _stop(self):
        if self.runner.is_running():
            self.runner.cancel()
            self._set_status("Stopping…")

    def _open_output(self):
        path = self.last_out or self.out_var.get().strip()
        if not path or not os.path.isdir(path):
            messagebox.showinfo("Nothing yet", "No output directory to open.")
            return
        if not open_path(path):
            messagebox.showinfo("Output", path)

    # -- settings, phases, timing, filter, log save ------------------------ #
    def _apply_settings(self):
        s = self.settings
        if s.get("source"):
            self.src_var.set(s["source"])
        if s.get("out"):
            self.out_var.set(s["out"])
        for pid, var in self.phase_vars.items():
            if pid in s.get("phases", {}):
                var.set(bool(s["phases"][pid]))
        self.opt_carve.set(bool(s.get("carve", False)))
        self.opt_unclass.set(bool(s.get("unclassified", False)))

    def _save_state(self):
        save_settings({
            "source": self.src_var.get().strip(),
            "out": self.out_var.get().strip(),
            "phases": {pid: var.get() for pid, var in self.phase_vars.items()},
            "carve": self.opt_carve.get(),
            "unclassified": self.opt_unclass.get(),
        })

    def _set_all_phases(self, value):
        for var in self.phase_vars.values():
            var.set(value)

    def _tick(self):
        if self._start_ts is not None:
            el = int(time.time() - self._start_ts)
            phase = "%d/%d" % (self._phase_idx, self._phase_total) \
                if self._phase_total else ""
            self.timing.configure(text="⏱ %02d:%02d   phase %s%s" % (
                el // 60, el % 60, phase,
                "  ·  " + self._cur_phase if self._cur_phase else ""))
        self.root.after(500, self._tick)

    def _apply_filter(self):
        needle = self.filter_var.get().strip().lower()
        if not needle:
            self._populate_tree()
            return
        out = self.last_out or self.out_var.get().strip() or ""
        self.tree.delete(*self.tree.get_children())
        self._tree_paths = {}
        shown = 0
        for path in getattr(self, "_all_files", []):
            if needle in os.path.basename(path).lower():
                n = self.tree.insert("", "end", text=os.path.relpath(path, out)
                                     if out else path)
                self._tree_paths[n] = path
                shown += 1
        self.tree_count.configure(text="%d match%s" % (shown, "" if shown == 1 else "es"))

    def _save_log(self):
        path = filedialog.asksaveasfilename(
            title="Save log", defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*")])
        if not path:
            return
        try:
            with open(path, "w") as f:
                f.write(self.log.get("1.0", "end"))
            self._set_status("Log saved: %s" % path)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def _about(self):
        messagebox.showinfo(
            "About",
            "NVMe Source Recovery\n\n"
            "Read-only forensic recovery of deleted source code, archives,\n"
            "photos and videos from NTFS / NVMe.\n\n"
            "Cross-platform (Linux / macOS / Windows), stdlib-only.\n"
            "The engine issues read commands only — it never writes to the source.")

    # -- queue pump -------------------------------------------------------- #
    def _pump(self):
        try:
            while True:
                kind, text = self.q.get_nowait()
                self._handle(kind, text)
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _handle(self, kind, text):
        if kind == "phase":
            self._phase_idx += 1
            self._cur_phase = text
            self._append("phase", "\n▸ %s\n" % text)
            self._set_status("Running: %s" % text)
        elif kind == "cmd":
            self._append("cmd", "  $ %s\n" % text)
        elif kind == "log":
            tag = "log"
            low = text.lower()
            if "fail" in low or "error" in low or "[!]" in text:
                tag = "err"
            elif "pass" in low or "done" in low or "complete" in low:
                tag = "ok"
            elif "warn" in low or "note" in low:
                tag = "warn"
            self._append(tag, text + "\n")
            self._maybe_progress(text)
        elif kind == "done":
            self._append("ok", "  ✓ %s done\n" % text)
        elif kind == "warn":
            self._append("warn", "  %s\n" % text)
        elif kind == "err":
            self._append("err", "  %s\n" % text)
        elif kind == "identify":
            dev, out = text
            self.nb.select(0)
            self._append("phase", "\n▸ Identify %s\n" % dev)
            self._append("log", out + "\n")
            self._set_status("Identified %s — see the log to confirm it's your drive." % dev)
            messagebox.showinfo("Disk: %s" % dev, out or "No details available.")
        elif kind == "trim_result":
            action, rc, out, state = text
            self.nb.select(0)
            self._append("phase", "\n▸ TRIM %s\n" % action)
            self._append("ok" if rc == 0 else "err", out.strip() + "\n")
            self._update_trim_label(state)
            if rc == 0:
                self._set_status("TRIM %s done — state: %s" % (action, state))
            elif action != "status":
                self._set_status("TRIM %s failed — see log." % action)
                messagebox.showerror(
                    "TRIM", "Could not change TRIM. You likely need to run the GUI "
                    "as %s.\n\nSee the log for details." %
                    ("Administrator" if IS_WINDOWS else "root (sudo)"))
        elif kind == "finished":
            self._on_finished(text == "ok")

    def _maybe_progress(self, text):
        # analyze prints "[analyze]   xx.x%  ..."
        m = re.search(r"(\d{1,3}\.\d)%", text)
        if m:
            try:
                pct = float(m.group(1))
                if self.pbar["mode"] != "determinate":
                    self.pbar.stop()
                    self.pbar.configure(mode="determinate")
                self.pbar["value"] = pct
            except Exception:
                pass

    def _on_finished(self, ok):
        self.pbar.stop()
        self.pbar.configure(mode="determinate")
        self.pbar["value"] = 100 if ok else self.pbar["value"]
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        el = int(time.time() - self._start_ts) if self._start_ts else 0
        self._start_ts = None
        self._cur_phase = ""
        self.timing.configure(text="⏱ %02d:%02d total" % (el // 60, el % 60))
        # Imaging finished: point the source at the new image and stop here.
        dest = self._after_image_dest
        self._after_image_dest = None
        if dest is not None:
            if ok and os.path.isfile(dest):
                self.src_var.set(dest)
                self._save_state()
                self._set_status("Image created — Source is now the .img. Pick phases and Run.")
                self._append("ok", "\n✔ Image saved: %s\n" % dest)
                messagebox.showinfo(
                    "Image ready",
                    "Saved a read-only image:\n%s\n\n"
                    "The Source field now points at this image. Pick your phases "
                    "and click RUN RECOVERY." % dest)
            else:
                self._set_status("Imaging failed — see log.")
            return

        self._set_status("Finished." if ok else "Finished with errors — see log.")
        self._append("ok" if ok else "err",
                     "\n%s  (%dm %02ds)\n" % ("✔ All phases complete." if ok
                                              else "✘ Completed with errors.",
                                              el // 60, el % 60))
        self._load_results()
        if ok:
            self.nb.select(1)

    # -- results browser --------------------------------------------------- #
    def _load_results(self):
        out = self.last_out or self.out_var.get().strip()
        if not out or not os.path.isdir(out):
            return
        # cards
        mft_csv = os.path.join(out, "10_mft", "mft_manifest.csv")
        usn_csv = os.path.join(out, "10_mft", "usn_journal.csv")
        src_csv = os.path.join(out, "30_source", "source_manifest.csv")
        resident = listed = deletes = 0
        if os.path.isfile(mft_csv):
            try:
                with open(mft_csv, newline="") as f:
                    for row in csv.DictReader(f):
                        listed += 1
                        if (row.get("recovered") or "").startswith(("yes", "partial")):
                            resident += 1
            except Exception:
                pass
        if os.path.isfile(usn_csv):
            try:
                with open(usn_csv, newline="") as f:
                    for row in csv.DictReader(f):
                        if "FILE_DELETE" in (row.get("reason") or ""):
                            deletes += 1
            except Exception:
                pass
        src_count = count_csv_rows(src_csv)
        arch = 0
        for sub in ("zip", "7z", "gzip", "zip_members"):
            d = os.path.join(out, "20_archives", sub)
            if os.path.isdir(d):
                arch += sum(len(fs) for _r, _d, fs in os.walk(d))
        photos = videos = 0
        pdir = os.path.join(out, "40_media", "photos")
        vdir = os.path.join(out, "40_media", "videos")
        if os.path.isdir(pdir):
            photos = sum(len(fs) for _r, _d, fs in os.walk(pdir))
        if os.path.isdir(vdir):
            videos = sum(len(fs) for _r, _d, fs in os.walk(vdir))
        self.card_labels["resident"].configure(text=str(resident))
        self.card_labels["listed"].configure(text=str(listed))
        self.card_labels["deletes"].configure(text=str(deletes))
        self.card_labels["photos"].configure(text=str(photos))
        self.card_labels["videos"].configure(text=str(videos))
        self.card_labels["source"].configure(text=str(src_count))
        self.card_labels["archives"].configure(text=str(arch))

        # tree
        self._populate_tree()

    TREE_CAP = 20000          # don't try to render millions of recovered files

    def _populate_tree(self):
        out = self.last_out or self.out_var.get().strip()
        self.tree.delete(*self.tree.get_children())
        self._tree_paths = {}
        self._all_files = []
        self._tree_truncated = False
        if out and os.path.isdir(out):
            try:
                self._add_tree_dir("", out, depth=0)
            except Exception:
                pass
        n = len(self._all_files)
        suffix = "+ (showing first %d — use Open output)" % self.TREE_CAP \
            if self._tree_truncated else ""
        self.tree_count.configure(
            text="%d file%s %s" % (n, "" if n == 1 else "s", suffix))

    def _add_tree_dir(self, parent, path, depth):
        if depth > 6 or len(self._all_files) >= self.TREE_CAP:
            if len(self._all_files) >= self.TREE_CAP:
                self._tree_truncated = True
            return
        try:
            entries = sorted(os.listdir(path))
        except Exception:
            return
        for name in entries:
            if len(self._all_files) >= self.TREE_CAP:
                self._tree_truncated = True
                return
            full = os.path.join(path, name)
            try:
                isdir = os.path.isdir(full)
                sz = "  (%s)" % human(os.path.getsize(full)) \
                    if (not isdir and os.path.isfile(full)) else ""
            except Exception:
                continue
            label = name + ("/" if isdir else sz)
            node = self.tree.insert(parent, "end", text=label, open=(depth == 0))
            self._tree_paths[node] = full
            if isdir:
                self._add_tree_dir(node, full, depth + 1)
            elif os.path.isfile(full):
                self._all_files.append(full)

    def _on_tree_select(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        path = self._tree_paths.get(sel[0])
        if not path or not os.path.isfile(path):
            self._set_preview("")
            return
        try:
            with open(path, "rb") as f:
                data = f.read(64 * 1024)
            text = data.decode("utf-8", "replace")
        except Exception as exc:
            text = "<cannot read: %s>" % exc
        more = "\n\n… (truncated; open the file for the rest)" \
            if os.path.getsize(path) > 64 * 1024 else ""
        self._set_preview("# %s\n\n%s%s" % (path, text, more))

    def _on_tree_open(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        path = self._tree_paths.get(sel[0])
        if path and os.path.isfile(path):
            open_path(path)

    def _set_preview(self, text):
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text)
        self.preview.configure(state="disabled")

    # -- log helpers ------------------------------------------------------- #
    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _append(self, tag, text):
        self.log.configure(state="normal")
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_status(self, text):
        self.status.configure(text=text)

    def _on_close(self):
        if self.runner.is_running():
            if not messagebox.askyesno("Quit", "A recovery is running. Stop and quit?"):
                return
            self.runner.cancel()
        self._save_state()
        self.root.destroy()


def main():
    # When frozen, the single executable doubles as the engine and trim tool so
    # the GUI can re-invoke itself (no separate .py files ship with the binary).
    if len(sys.argv) >= 2 and sys.argv[1] == "--engine":
        import nvme_recover
        sys.exit(nvme_recover.main(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] == "--trim":
        import trim_control
        sys.exit(trim_control.main(sys.argv[2:]))
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
