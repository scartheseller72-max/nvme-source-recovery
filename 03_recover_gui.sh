#!/usr/bin/env bash
###############################################################################
#  03_recover_gui.sh — launch the desktop GUI front-end for nvme_recover.py
#
#  Usage:
#     ./03_recover_gui.sh
#
#  The GUI is stdlib-only (tkinter). If tkinter is missing it will tell you
#  exactly what to install. Everything it does is READ-ONLY against the source.
###############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GUI="$HERE/nvme_recover_gui.py"

command -v python3 >/dev/null || { echo "[FAIL] python3 required (sudo apt install -y python3)"; exit 1; }
[[ -f "$GUI" ]] || { echo "[FAIL] GUI not found: $GUI"; exit 1; }

if ! python3 -c "import tkinter" 2>/dev/null; then
  echo "[note] tkinter not installed — the GUI needs it:"
  echo "       Debian/Ubuntu : sudo apt install -y python3-tk"
  echo "       Fedora        : sudo dnf install -y python3-tkinter"
  echo "       Arch          : sudo pacman -S tk"
fi

exec python3 "$GUI"
