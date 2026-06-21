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
IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".nvme_recover_gui.json")

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


def _detect_windows():
    out = []
    try:
        ps = ("Get-CimInstance Win32_DiskDrive | ForEach-Object "
              "{ \"$($_.DeviceID)|$($_.Size)|$($_.Model)\" }")
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=10)
        for line in res.stdout.splitlines():
            parts = line.split("|")
            if len(parts) < 2 or not parts[0].strip():
                continue
            dev = parts[0].strip()                      # \\.\PHYSICALDRIVE0
            size = parts[1].strip()
            model = parts[2].strip() if len(parts) > 2 else ""
            hs = human(int(size)) if size.isdigit() else size
            out.append((dev, "%s  (%s%s)" % (dev, hs, "  " + model if model else "")))
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
        res = subprocess.run(["lsblk", "-dpno", "NAME,SIZE,MODEL,TYPE"],
                             capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.split(None, 3)
                if len(parts) < 2:
                    continue
                name, size = parts[0], parts[1]
                typ = parts[3] if len(parts) > 3 else ""
                model = parts[2] if len(parts) > 2 else ""
                if "disk" in (typ.lower() if typ else "") or "disk" in line.lower():
                    out.append((name, "%s  (%s%s)" % (name, size,
                                "  " + model if model else "")))
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
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_icon(self):
        for name in ("mark.png", "logo.png"):
            p = os.path.join(HERE, "assets", name)
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
        runm.add_command(label="Run selected", command=self._run_selected,
                         accelerator="Ctrl+R")
        runm.add_command(label="Stop", command=self._stop, accelerator="Esc")
        runm.add_command(label="Self-test", command=self._run_selftest)
        runm.add_separator()
        runm.add_command(label="Refresh results", command=self._load_results,
                         accelerator="F5")
        bar.add_cascade(label="Run", menu=runm)
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
        dev_hint = ("Pick a forensic .img, or a detected disk "
                    "(\\\\.\\PhysicalDriveN — run as Administrator)." if IS_WINDOWS
                    else "Pick a forensic .img, or a detected device (opened read-only).")
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
        self.src_combo["values"] = [d[0] for d in devs]
        self._set_status("Found %d block device(s)." % len(devs) if devs
                         else "No block devices detected — browse for an image.")

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
        src = self.src_var.get().strip()
        out = self.out_var.get().strip()
        is_dev = self._is_device(src)
        if not src or (not is_dev and not os.path.exists(src)):
            messagebox.showerror("Source missing",
                                 "Select a valid image file or device first.")
            return None
        if not out:
            messagebox.showerror("Output missing", "Choose an output directory.")
            return None
        if not os.path.isfile(ENGINE):
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
            argv = [sys.executable, ENGINE, cmd, "--image", src, "--out", out]
            if cmd in ("mft",) and self.opt_carve.get():
                argv.append("--carve-nonresident")
            if cmd == "source" and self.opt_unclass.get():
                argv.append("--include-unclassified")
            # use regions.json to speed later phases if analyze will have produced it
            if cmd in ("usn", "archives", "media", "source") and \
                    ("analyze" in cmds or os.path.isfile(regions)):
                argv += ["--regions", regions]
            jobs.append((CMD_LABEL.get(cmd, cmd), argv))
        self._start_jobs(jobs)

    def _run_selftest(self):
        out = self.out_var.get().strip() or os.path.join(HERE, "_selftest")
        out = os.path.join(out, "_selftest") if os.path.basename(out) != "_selftest" else out
        argv = [sys.executable, ENGINE, "selftest", "--out", out]
        self.last_out = os.path.join(out, "out")
        self._start_jobs([("Self-test", argv)])

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

    def _populate_tree(self):
        out = self.last_out or self.out_var.get().strip()
        self.tree.delete(*self.tree.get_children())
        self._tree_paths = {}
        self._all_files = []
        if out and os.path.isdir(out):
            self._add_tree_dir("", out, depth=0)
        n = len(self._all_files)
        self.tree_count.configure(text="%d file%s" % (n, "" if n == 1 else "s"))

    def _add_tree_dir(self, parent, path, depth):
        if depth > 6:
            return
        try:
            entries = sorted(os.listdir(path))
        except Exception:
            return
        for name in entries:
            full = os.path.join(path, name)
            isdir = os.path.isdir(full)
            label = name + ("/" if isdir else "  (%s)" % human(os.path.getsize(full))
                            if os.path.isfile(full) else "")
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
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
