#!/usr/bin/env bash
###############################################################################
#  01_image_drive.sh — hardened, READ-ONLY forensic imaging of an NVMe SSD
#
#  Run from a Linux LIVE USB (SystemRescue / Ubuntu / Mint). Do NOT boot the
#  affected Windows install. Do NOT mount the damaged drive.
#
#  This is the MANDATORY first step. All recovery happens on the IMAGE, never
#  on the original drive. The source is force-set read-only at the kernel level
#  (blockdev --setro) so even an accidental write is rejected.
#
#  It also captures the controller state (SMART, id-ctrl, error/fw logs,
#  partition table) so you have forensic evidence of what TRIM/GC did.
#
#  Phases:
#     ./01_image_drive.sh devices
#     ./01_image_drive.sh state   /dev/nvme0n1 /mnt/dest
#     ./01_image_drive.sh image   /dev/nvme0n1 /mnt/dest
###############################################################################
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'
say(){ printf '%s\n' "$*"; }
ok(){  printf '%s[ OK ]%s %s\n' "$GRN" "$RST" "$*"; }
warn(){ printf '%s[WARN]%s %s\n' "$YEL" "$RST" "$*"; }
err(){ printf '%s[FAIL]%s %s\n' "$RED" "$RST" "$*" >&2; }
hr(){ printf '%s\n' "------------------------------------------------------------"; }
need(){ command -v "$1" >/dev/null 2>&1; }

ensure_tools(){
  local miss=()
  for t in ddrescue lsblk blockdev sha256sum; do need "$t" || miss+=("$t"); done
  if ((${#miss[@]})); then
    warn "Missing: ${miss[*]}"
    say  "Install (Debian/Ubuntu live):"
    say  "  ${BLD}sudo apt update && sudo apt install -y gddrescue nvme-cli gdisk coreutils util-linux${RST}"
    exit 1
  fi
  need nvme  || warn "nvme-cli not found — controller state capture will be skipped."
  need sgdisk|| warn "gdisk/sgdisk not found — GPT backup will be skipped."
}

phase_devices(){
  hr; say "${BLD}Block devices — identify SOURCE (damaged) and DEST (separate, larger):${RST}"; hr
  lsblk -dpo NAME,SIZE,MODEL,TRAN,SERIAL,MOUNTPOINT 2>/dev/null || lsblk
  hr
  if need nvme; then say "${BLD}NVMe namespaces:${RST}"; sudo nvme list 2>/dev/null || true; hr; fi
  say "${CYN}SOURCE${RST} = damaged disk, image the WHOLE namespace e.g. ${BLD}/dev/nvme0n1${RST}"
  say "${CYN}DEST${RST}   = a DIFFERENT writable disk with free space >= source size,"
  say "         mounted somewhere writable e.g. ${BLD}/mnt/dest${RST}"
}

check_distinct(){
  local src="$1" dst="$2"
  [[ -b "$src" ]] || { err "Source '$src' is not a block device."; exit 1; }
  [[ -d "$dst" ]] || { err "Dest dir '$dst' does not exist / not mounted."; exit 1; }
  # refuse if source (or any of its partitions) is mounted
  if lsblk -no MOUNTPOINT "$src" 2>/dev/null | grep -q '[^[:space:]]'; then
    err "Source $src has a MOUNTED partition. Unmount it (umount) before imaging."
    exit 1
  fi
  local dstdev srcbase
  dstdev="$(df --output=source "$dst" 2>/dev/null | tail -1)"
  srcbase="${src%%p[0-9]*}"; srcbase="${srcbase%[0-9]}"
  if [[ "$dstdev" == "$src"* || "$dstdev" == "$srcbase"* ]]; then
    err "Destination ($dstdev) lives on the SOURCE disk. Choose a separate disk."
    exit 1
  fi
  ok "Source and destination are on different disks; source not mounted."
}

phase_state(){
  ensure_tools
  local src="${1:-}" dst="${2:-}"
  [[ -n "$src" && -n "$dst" ]] || { err "Usage: $0 state <SRC> <DEST_DIR>"; exit 1; }
  check_distinct "$src" "$dst"
  local sdir="$dst/forensic-state"; mkdir -p "$sdir"
  hr; say "${BLD}Capturing controller state (proves what TRIM/GC did) -> $sdir${RST}"; hr
  lsblk -O "$src" > "$sdir/lsblk.txt" 2>/dev/null || true
  if need nvme; then
    local ctrl="${src%n[0-9]*}"   # /dev/nvme0n1 -> /dev/nvme0
    sudo nvme smart-log "$src"      > "$sdir/smart-log.txt"  2>&1 || true
    sudo nvme id-ctrl  "$ctrl"      > "$sdir/id-ctrl.txt"    2>&1 || true
    sudo nvme id-ns    "$src"       > "$sdir/id-ns.txt"      2>&1 || true
    sudo nvme error-log "$ctrl"     > "$sdir/error-log.txt"  2>&1 || true
    sudo nvme fw-log   "$ctrl"      > "$sdir/fw-log.txt"     2>&1 || true
    # key indicators
    say "${CYN}Unsafe shutdowns (your hard power-cut should have incremented this):${RST}"
    grep -i "unsafe_shutdowns" "$sdir/smart-log.txt" || true
    say "${CYN}DLFEAT / deterministic-read-after-trim (id-ns 'dlfeat'):${RST}"
    grep -i "dlfeat" "$sdir/id-ns.txt" || true
    say "${CYN}ONCS (Dataset-Mgmt/DEALLOCATE support, id-ctrl 'oncs'):${RST}"
    grep -i "oncs" "$sdir/id-ctrl.txt" || true
  fi
  if need sgdisk; then sudo sgdisk --backup="$sdir/gpt-backup.bin" "$src" >/dev/null 2>&1 || true; fi
  if need sfdisk; then sudo sfdisk -d "$src" > "$sdir/partition-table.txt" 2>/dev/null || true; fi
  ok "State captured. Review $sdir/ before imaging."
}

phase_image(){
  ensure_tools
  local src="${1:-}" dst="${2:-}"
  [[ -n "$src" && -n "$dst" ]] || { err "Usage: $0 image <SRC> <DEST_DIR>"; exit 1; }
  check_distinct "$src" "$dst"

  local model size img map
  model="$(lsblk -dno MODEL "$src" 2>/dev/null | xargs || true)"
  size="$(lsblk -dno SIZE "$src" 2>/dev/null | xargs || true)"
  img="$dst/rescue-$(basename "$src").img"
  map="$dst/rescue-$(basename "$src").map"

  hr
  warn "About to image (READ-ONLY):"
  say  "   SOURCE : $src   ($model, $size)"
  say  "   IMAGE  : $img"
  say  "   MAPFILE: $map   (resume-safe)"
  hr
  read -rp "Type ${BLD}YES${RST} to begin: " a; [[ "$a" == "YES" ]] || { say "Aborted."; exit 0; }

  # Kernel-level write protection on the SOURCE (belt and suspenders).
  if sudo blockdev --setro "$src" 2>/dev/null; then
    ok "Source set READ-ONLY at kernel level (blockdev --setro)."
  else
    warn "Could not set read-only flag; ddrescue still only READS the source."
  fi

  say ""
  ok "Pass 1: fast linear copy of all readable blocks (no scraping)..."
  #  -n / --no-scrape : skip the slow scraping phase on pass 1
  #  -d / --idirect   : O_DIRECT reads, bypass page cache (cleaner, fewer artifacts)
  #  -b 4096          : 4 KiB sector alignment (NVMe)
  #  reads only — NEVER issues TRIM/DISCARD
  sudo ddrescue -n -d -b 4096 "$src" "$img" "$map"

  ok "Pass 2: retry only the bad/slow spots (3 tries)..."
  sudo ddrescue -d -b 4096 -r3 "$src" "$img" "$map"

  hr
  ok "Imaging complete."
  say "${CYN}Computing SHA-256 (evidence integrity)...${RST}"
  ( cd "$dst" && sha256sum "$(basename "$img")" | tee "$(basename "$img").sha256" )
  hr
  say "${BLD}Now POWER OFF / unplug the SOURCE drive and leave it untouched.${RST}"
  say "All further work happens on the IMAGE only:"
  say "   ${BLD}./02_run_recovery.sh \"$img\" \"$dst/recovered\"${RST}"
}

case "${1:-}" in
  devices) phase_devices ;;
  state)   shift; phase_state "$@" ;;
  image)   shift; phase_image "$@" ;;
  *)
    say "${BLD}01_image_drive.sh — read-only forensic imaging (run from Linux LIVE USB)${RST}"
    say ""
    say "  $0 devices                          # 1. list disks"
    say "  $0 state  /dev/nvme0n1 /mnt/dest     # 2. capture SMART/TRIM state (optional but smart)"
    say "  $0 image  /dev/nvme0n1 /mnt/dest     # 3. read-only clone -> image file"
    say ""
    say "Then run:  ./02_run_recovery.sh /mnt/dest/rescue-nvme0n1.img /mnt/dest/recovered"
    ;;
esac
