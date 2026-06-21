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
import sys
import csv
import glob
import json
import queue
import shlex
import signal
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


def detect_block_devices():
    """Return [(path, label)] for likely source devices. Best-effort, read-only."""
    out = []
    try:
        res = subprocess.run(
            ["lsblk", "-dpno", "NAME,SIZE,MODEL,TYPE"],
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
                    label = "%s  (%s%s)" % (name, size, "  " + model if model else "")
                    out.append((name, label))
            if out:
                return out
    except Exception:
        pass
    # Fallback: glob common device nodes
    for pat in ("/dev/nvme*n[0-9]", "/dev/sd[a-z]"):
        for dev in sorted(glob.glob(pat)):
            out.append((dev, dev))
    return out


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
                p.send_signal(signal.SIGTERM)
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

        root.title("NVMe Source Recovery")
        root.configure(bg=BG)
        root.geometry("1100x720")
        root.minsize(900, 600)

        self._init_fonts()
        self._init_style()
        self._build()
        self._refresh_devices()
        self.root.after(80, self._pump)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

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
        st.configure("TCheckbutton", background=BG_PANEL, foreground=FG)
        st.map("TCheckbutton", background=[("active", BG_PANEL)])
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
        left = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        # Source
        ttk.Label(left, text="SOURCE  (image or device)", style="H2.TLabel").pack(anchor="w")
        srow = ttk.Frame(left, style="Panel.TFrame")
        srow.pack(fill="x", pady=(4, 2))
        self.src_var = tk.StringVar()
        self.src_combo = ttk.Combobox(srow, textvariable=self.src_var)
        self.src_combo.pack(side="left", fill="x", expand=True)
        ttk.Button(srow, text="↻", width=3, command=self._refresh_devices).pack(side="left", padx=(4, 0))
        brow = ttk.Frame(left, style="Panel.TFrame")
        brow.pack(fill="x")
        ttk.Button(brow, text="Browse image…", command=self._pick_image).pack(side="left")
        ttk.Label(left, text="Pick a forensic .img, or a /dev node (opened read-only).",
                  style="PanelMute.TLabel", wraplength=300, justify="left").pack(anchor="w", pady=(2, 10))

        # Output
        ttk.Label(left, text="OUTPUT DIRECTORY", style="H2.TLabel").pack(anchor="w")
        orow = ttk.Frame(left, style="Panel.TFrame")
        orow.pack(fill="x", pady=(4, 2))
        self.out_var = tk.StringVar()
        ttk.Entry(orow, textvariable=self.out_var).pack(side="left", fill="x", expand=True)
        ttk.Button(orow, text="Browse…", command=self._pick_out).pack(side="left", padx=(4, 0))
        ttk.Label(left, text="Recovered files & manifests are written here.",
                  style="PanelMute.TLabel").pack(anchor="w", pady=(2, 10))

        # Phases
        ttk.Label(left, text="PHASES", style="H2.TLabel").pack(anchor="w")
        for pid, label, _cmd, tip in PHASES:
            v = tk.BooleanVar(value=True)
            self.phase_vars[pid] = v
            cb = ttk.Checkbutton(left, text=label, variable=v)
            cb.pack(anchor="w", pady=(3, 0))
            ttk.Label(left, text=tip, style="PanelMute.TLabel",
                      wraplength=300, justify="left").pack(anchor="w", padx=(22, 0))

        # Options
        ttk.Label(left, text="OPTIONS", style="H2.TLabel").pack(anchor="w", pady=(10, 0))
        self.opt_carve = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Carve non-resident file bodies",
                        variable=self.opt_carve).pack(anchor="w", pady=(3, 0))
        ttk.Label(left, text="Pull data from cluster runs (may be zeros if TRIMed).",
                  style="PanelMute.TLabel", wraplength=300,
                  justify="left").pack(anchor="w", padx=(22, 0))
        self.opt_unclass = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Keep unclassified text blobs",
                        variable=self.opt_unclass).pack(anchor="w", pady=(3, 0))

        # Run buttons
        btns = ttk.Frame(left, style="Panel.TFrame")
        btns.pack(fill="x", pady=(14, 0))
        self.run_btn = ttk.Button(btns, text="▶  Run", style="Accent.TButton",
                                  command=self._run_selected)
        self.run_btn.pack(side="left", fill="x", expand=True)
        self.stop_btn = ttk.Button(btns, text="■ Stop", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(6, 0))

        extra = ttk.Frame(left, style="Panel.TFrame")
        extra.pack(fill="x", pady=(6, 0))
        ttk.Button(extra, text="Self-test", command=self._run_selftest).pack(side="left", fill="x", expand=True)
        ttk.Button(extra, text="Open output", command=self._open_output).pack(side="left", padx=(6, 0), fill="x", expand=True)

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
        self.tree = ttk.Treeview(treebox, show="tree", selectmode="browse")
        tsb = ttk.Scrollbar(treebox, orient="vertical", command=self.tree.yview)
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

    def _validate(self):
        src = self.src_var.get().strip()
        out = self.out_var.get().strip()
        if not src or not os.path.exists(src):
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
        if src.startswith("/dev/"):
            if not messagebox.askyesno(
                    "Run against a live device?",
                    "%s is a block device.\n\nThe engine opens it READ-ONLY, but the "
                    "recommended workflow is to image it first.\n\nContinue read-only?" % src):
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
            if cmd in ("usn", "archives", "source") and \
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
        self._clear_log()
        self._append("phase", "Starting %d phase(s)…\n" % len(jobs))
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.pbar.configure(mode="indeterminate")
        self.pbar.start(12)
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
        for opener in ("xdg-open", "open"):
            try:
                subprocess.Popen([opener, path])
                return
            except Exception:
                continue
        messagebox.showinfo("Output", path)

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
        import re
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
        self._set_status("Finished." if ok else "Finished with errors — see log.")
        self._append("ok" if ok else "err",
                     "\n%s\n" % ("✔ All phases complete." if ok
                                 else "✘ Completed with errors."))
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
        self.card_labels["resident"].configure(text=str(resident))
        self.card_labels["listed"].configure(text=str(listed))
        self.card_labels["deletes"].configure(text=str(deletes))
        self.card_labels["source"].configure(text=str(src_count))
        self.card_labels["archives"].configure(text=str(arch))

        # tree
        self.tree.delete(*self.tree.get_children())
        self._tree_paths = {}
        self._add_tree_dir("", out, depth=0)

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
            for opener in ("xdg-open", "open"):
                try:
                    subprocess.Popen([opener, path])
                    return
                except Exception:
                    continue

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
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
