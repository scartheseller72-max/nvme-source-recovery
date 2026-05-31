#!/usr/bin/env bash
###############################################################################
#  02_run_recovery.sh — one-command recovery pipeline (runs on the IMAGE only)
#
#  Usage:
#     ./02_run_recovery.sh <IMAGE_OR_DEVICE> <OUTPUT_DIR> [--carve-nonresident]
#
#  Example:
#     ./02_run_recovery.sh /mnt/dest/rescue-nvme0n1.img /mnt/dest/recovered
#
#  Order of operations (highest-yield first):
#     1) analyze   — zero/entropy map: how much did TRIM wipe, and where is data
#     2) mft       — recover deleted files from $MFT (resident = INTACT)
#     3) usn       — timestamped delete log by filename ($UsnJrnl)
#     4) archives  — ZIP / 7z / gzip carving with validation
#     5) source    — language-aware .rs/.kt/.py/.sol carving
#
#  Everything is READ-ONLY against the input.
###############################################################################
set -uo pipefail

IMG="${1:-}"; OUT="${2:-}"; EXTRA="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="$HERE/nvme_recover.py"

if [[ -z "$IMG" || -z "$OUT" ]]; then
  echo "Usage: $0 <IMAGE_OR_DEVICE> <OUTPUT_DIR> [--carve-nonresident]"
  echo "Example: $0 /mnt/dest/rescue-nvme0n1.img /mnt/dest/recovered"
  exit 1
fi
[[ -e "$IMG" ]]     || { echo "[FAIL] input not found: $IMG"; exit 1; }
[[ -f "$ENGINE" ]]  || { echo "[FAIL] engine not found next to this script: $ENGINE"; exit 1; }
command -v python3 >/dev/null || { echo "[FAIL] python3 required (sudo apt install -y python3)"; exit 1; }
command -v 7z >/dev/null || echo "[note] '7z' (p7zip-full) not installed — carved .7z will still be saved; install to extract."

mkdir -p "$OUT"
echo "[*] input : $IMG"
echo "[*] output: $OUT"
echo

# 1) analyze  -> writes $OUT/00_analysis/regions.json (limits later scans to live data)
python3 "$ENGINE" analyze --image "$IMG" --out "$OUT"
REGIONS="$OUT/00_analysis/regions.json"

# 2) MFT — resident files recovered intact; add --carve-nonresident to also pull
#    file data from the original cluster offsets (may be zeros if TRIM completed).
if [[ "$EXTRA" == "--carve-nonresident" ]]; then
  python3 "$ENGINE" mft --image "$IMG" --out "$OUT" --carve-nonresident
else
  python3 "$ENGINE" mft --image "$IMG" --out "$OUT"
fi

# 3) USN journal
python3 "$ENGINE" usn --image "$IMG" --out "$OUT" --regions "$REGIONS"

# 4) Archives (ZIP / 7z / gzip), scanning only live extents for speed
python3 "$ENGINE" archives --image "$IMG" --out "$OUT" --regions "$REGIONS"

# 5) Source-code carving
python3 "$ENGINE" source --image "$IMG" --out "$OUT" --regions "$REGIONS"

echo
echo "============================================================"
echo " RECOVERY COMPLETE — look here:"
echo "   $OUT/10_mft/files/           recovered deleted files (original names)"
echo "   $OUT/10_mft/mft_manifest.csv  full list of every deleted file found"
echo "   $OUT/10_mft/usn_journal.csv   timestamped delete log"
echo "   $OUT/20_archives/             rebuilt zip/7z + salvaged members"
echo "   $OUT/30_source/<lang>/        carved source by language"
echo
echo " Find a specific file fast (use a string you KNOW was in your code):"
echo "   grep -rIl 'mySpecialFunctionName' \"$OUT\""
echo "============================================================"
