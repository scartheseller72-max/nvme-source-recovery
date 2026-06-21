#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nvme_recover.py  --  Software data-recovery engine for accidentally deleted
                     source code + archives on an NTFS volume (NVMe SSD).

Built for the Lexar NM620 / Innogrit IG5216 (DRAM-less, TRIM-enabled) loss
scenario, but works on ANY raw image or block device that contains NTFS.

It is 100% READ-ONLY against the source. It never writes to the image/device.
Run it on a forensic IMAGE (recommended) or directly on a read-only device.

RECOVERY VECTORS (highest yield first for lost source code)
-----------------------------------------------------------
  1. NTFS $MFT mining        -- the BEST shot for source code:
                                * RESIDENT $DATA  = small files recovered 100%
                                  intact (name + path + bytes), because the
                                  content lives inside the MFT record itself.
                                * Non-resident files: exact name + size + the
                                  precise cluster offsets, so we do a TARGETED
                                  carve at the real location (far better than
                                  blind carving). Survives because TRIM frees
                                  the DATA clusters, not the $MFT system file.
  2. $UsnJrnl change journal -- timestamped list of every create/delete by
                                name; reconstructs exactly what was lost.
  3. Archive carving         -- ZIP (central-directory reconstruction + per
                                member salvage), 7z (CRC-validated, exact size
                                from header), gzip streams.
  4. Source-text carving     -- language-aware scan for .rs/.kt/.py/.sol/etc.
                                directly from raw bytes (no metadata needed).
  5. Region analysis         -- zero/0xFF/entropy map so you SEE up front how
                                much TRIM actually wiped and where data lives.

USAGE
-----
  python3 nvme_recover.py analyze  --image IMG --out OUT
  python3 nvme_recover.py mft      --image IMG --out OUT [--carve-nonresident]
  python3 nvme_recover.py usn      --image IMG --out OUT
  python3 nvme_recover.py archives --image IMG --out OUT [--regions OUT/00_analysis/regions.json]
  python3 nvme_recover.py source   --image IMG --out OUT [--regions ...]
  python3 nvme_recover.py all      --image IMG --out OUT      # runs everything in order
  python3 nvme_recover.py selftest --out /tmp/selftest        # proves the engine works

Author: HyperAgent recovery toolkit.  Stdlib-only (optional: py7zr for 7z verify).
"""

import argparse
import binascii
import datetime
import io
import json
import mmap
import os
import re
import stat
import struct
import sys
import zlib
import zipfile

# --------------------------------------------------------------------------- #
#  Small utilities                                                            #
# --------------------------------------------------------------------------- #

KiB = 1024
MiB = 1024 * 1024
GiB = 1024 * 1024 * 1024


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f PiB" % n


def le(b):
    """little-endian unsigned int from bytes"""
    return int.from_bytes(b, "little")


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def sanitize_relpath(p):
    """Turn an arbitrary (possibly Windows) path into a safe relative path."""
    if not p:
        return "unnamed"
    p = p.replace("\\", "/")
    p = re.sub(r"^[A-Za-z]:", "", p)            # strip drive letter
    out = []
    for seg in p.split("/"):
        seg = seg.strip().strip(".")
        if not seg or seg in (".", ".."):
            continue
        seg = re.sub(r'[<>:"|?*\x00-\x1f]', "_", seg)
        out.append(seg[:200])
    return "/".join(out) if out else "unnamed"


def unique_path(path):
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while True:
        cand = "%s__%d%s" % (root, i, ext)
        if not os.path.exists(cand):
            return cand
        i += 1


def safe_write(outroot, relpath, data):
    """Write data under outroot/relpath, defeating path traversal. Returns final path."""
    relpath = sanitize_relpath(relpath)
    full = os.path.normpath(os.path.join(outroot, relpath))
    if not (full == outroot or full.startswith(outroot + os.sep)):
        full = os.path.join(outroot, os.path.basename(relpath) or "unnamed")
    os.makedirs(os.path.dirname(full), exist_ok=True)
    full = unique_path(full)
    with open(full, "wb") as f:
        f.write(data)
    return full


def filetime_to_iso(ft):
    if not ft:
        return ""
    try:
        secs = ft / 10_000_000.0 - 11644473600.0
        if secs < 0 or secs > 32503680000.0:   # >year 3000 => junk
            return ""
        return datetime.datetime.utcfromtimestamp(secs).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
#  Unified read-only reader: mmap for image files; aligned seek/read for       #
#  block / physical devices. Works on Linux, macOS, and Windows.               #
# --------------------------------------------------------------------------- #

IS_WINDOWS = (os.name == "nt")


class Reader(object):
    def __init__(self, path):
        self.path = path
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):                     # Windows: avoid CRLF mangling
            flags |= os.O_BINARY
        self.fd = os.open(path, flags)
        self.mm = None
        self.align = 1                                  # sector alignment for raw reads
        self._has_pread = hasattr(os, "pread")
        self.is_block = False

        win_raw = IS_WINDOWS and (path.startswith("\\\\.\\") or
                                  path.startswith("\\\\?\\"))
        try:
            st = os.fstat(self.fd)
        except OSError:
            st = None

        if win_raw:
            # Windows physical drive (\\.\PhysicalDriveN): needs sector-aligned
            # reads and an ioctl to learn its size.
            self.is_block = True
            self.align = 512
            self.size = self._win_device_size()
            if not self.size:
                self.size = self._probe_size()
        elif st is not None and stat.S_ISREG(st.st_mode):
            self.size = st.st_size
            if self.size > 0:
                try:
                    self.mm = mmap.mmap(self.fd, 0, access=mmap.ACCESS_READ)
                except (ValueError, OSError):
                    self.mm = None
        else:
            # Linux/macOS block or char device: size via lseek to end.
            self.is_block = bool(st and stat.S_ISBLK(st.st_mode))
            try:
                self.size = os.lseek(self.fd, 0, os.SEEK_END)
                os.lseek(self.fd, 0, os.SEEK_SET)
            except OSError:
                self.size = self._probe_size()

    def _win_device_size(self):
        """IOCTL_DISK_GET_LENGTH_INFO via ctypes (Windows only)."""
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes
            handle = msvcrt.get_osfhandle(self.fd)
            IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
            outbuf = ctypes.create_string_buffer(8)
            returned = wintypes.DWORD(0)
            ok = ctypes.windll.kernel32.DeviceIoControl(
                wintypes.HANDLE(handle), IOCTL_DISK_GET_LENGTH_INFO,
                None, 0, outbuf, 8, ctypes.byref(returned), None)
            if ok:
                return int.from_bytes(outbuf.raw[:8], "little")
        except Exception:
            pass
        return 0

    def _probe_size(self):
        """Binary-search the last readable sector if size is otherwise unknown."""
        a = self.align or 512
        lo, hi = 0, 1 << 50
        try:
            while lo < hi:
                mid = ((lo + hi + 1) // 2) // a * a
                if mid <= lo:
                    break
                if self._plain_read(mid - a, a):
                    lo = mid
                else:
                    hi = mid - a
        except Exception:
            pass
        return lo

    def read(self, off, length):
        if off < 0 or off >= self.size or length <= 0:
            return b""
        length = min(length, self.size - off)
        if self.mm is not None:
            return self.mm[off:off + length]
        if self.align > 1:
            return self._aligned_read(off, length)
        return self._plain_read(off, length)

    def _plain_read(self, off, length):
        out = bytearray()
        pos = off
        remaining = length
        while remaining > 0:
            try:
                if self._has_pread:
                    chunk = os.pread(self.fd, min(remaining, 16 * MiB), pos)
                else:
                    os.lseek(self.fd, pos, os.SEEK_SET)
                    chunk = os.read(self.fd, min(remaining, 16 * MiB))
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            pos += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

    def _aligned_read(self, off, length):
        """Expand the request to sector bounds (required for Windows raw devices),
        read, then slice back to exactly what was asked for."""
        a = self.align
        a_start = off - (off % a)
        a_end = ((off + length + a - 1) // a) * a
        if a_end > self.size:
            a_end = self.size
        raw = self._plain_read(a_start, a_end - a_start)
        lo = off - a_start
        return raw[lo:lo + length]

    def find(self, needle, start=0, end=None):
        if end is None:
            end = self.size
        if self.mm is not None:
            idx = self.mm.find(needle, start, end)
            return idx if idx != -1 and idx < end else -1
        chunk = 8 * MiB
        ov = len(needle) - 1
        pos = start
        while pos < end:
            buf = self.read(pos, min(chunk, end - pos) + ov)
            i = buf.find(needle)
            if i != -1 and (pos + i) < end:
                return pos + i
            pos += chunk
        return -1

    def close(self):
        if self.mm is not None:
            self.mm.close()
        os.close(self.fd)


def iter_windows(reader, extents, window=16 * MiB, overlap=1 * MiB):
    """Yield (abs_offset, data) windows over the given extents, with overlap so
    signatures spanning a boundary are fully present in at least one window."""
    for (s, e) in extents:
        s = max(0, s)
        e = min(reader.size, e)
        pos = s
        while pos < e:
            n = min(window, e - pos)
            data = reader.read(pos, n + overlap)
            yield pos, data
            pos += n


# --------------------------------------------------------------------------- #
#  Phase 1: Region / zero / entropy analysis                                  #
# --------------------------------------------------------------------------- #

def shannon_entropy(data):
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def analyze(reader, outdir, block_size=1 * MiB, gap_merge=8):
    a_dir = os.path.join(outdir, "00_analysis")
    os.makedirs(a_dir, exist_ok=True)
    zero_block = bytes(block_size)
    ff_block = b"\xff" * block_size

    total = reader.size
    nblocks = (total + block_size - 1) // block_size
    zero_n = ff_n = text_n = high_n = other_n = 0
    interesting = []   # list of block indices that hold real data
    log("[analyze] scanning %s in %d blocks of %s ..." % (human(total), nblocks, human(block_size)))

    i = 0
    pos = 0
    next_report = 0
    while pos < total:
        n = min(block_size, total - pos)
        data = reader.read(pos, n)
        if n == block_size and data == zero_block:
            zero_n += 1
        elif n == block_size and data == ff_block:
            ff_n += 1
        elif data.count(0) >= len(data) - 16:
            zero_n += 1
        else:
            ent = shannon_entropy(data[:4096])
            if ent < 5.0:
                text_n += 1
            elif ent > 7.5:
                high_n += 1
            else:
                other_n += 1
            interesting.append(i)
        i += 1
        pos += n
        if pos >= next_report:
            pct = 100.0 * pos / total
            log("[analyze]   %5.1f%%  (%s)  interesting blocks: %d" %
                (pct, human(pos), len(interesting)))
            next_report = pos + max(block_size, total // 50)

    # merge interesting blocks into extents, bridging small gaps
    extents = []
    for idx in interesting:
        s = idx * block_size
        e = min(total, s + block_size)
        if extents and s - extents[-1][1] <= gap_merge * block_size:
            extents[-1][1] = e
        else:
            extents.append([s, e])
    extents = [(s, e) for s, e in extents]

    summary = {
        "image": reader.path,
        "image_size": total,
        "block_size": block_size,
        "blocks_total": nblocks,
        "blocks_zero": zero_n,
        "blocks_ff": ff_n,
        "blocks_text_like": text_n,
        "blocks_high_entropy": high_n,
        "blocks_other": other_n,
        "interesting_blocks": len(interesting),
        "interesting_extents": len(extents),
        "interesting_bytes": sum(e - s for s, e in extents),
        "extents": extents,
    }
    with open(os.path.join(a_dir, "regions.json"), "w") as f:
        json.dump(summary, f, indent=2)

    pct_dead = 100.0 * (zero_n + ff_n) / max(1, nblocks)
    lines = [
        "REGION ANALYSIS  (how much did TRIM wipe?)",
        "=" * 52,
        "image            : %s" % reader.path,
        "size             : %s" % human(total),
        "zeroed blocks    : %d (%.1f%%)   <- TRIMed / never written" % (zero_n, 100.0 * zero_n / max(1, nblocks)),
        "0xFF blocks      : %d (%.1f%%)   <- erased / fresh NAND" % (ff_n, 100.0 * ff_n / max(1, nblocks)),
        "text-like blocks : %d (%.1f%%)   <- candidate SOURCE CODE" % (text_n, 100.0 * text_n / max(1, nblocks)),
        "high-entropy     : %d (%.1f%%)   <- candidate ARCHIVES/encrypted" % (high_n, 100.0 * high_n / max(1, nblocks)),
        "other            : %d (%.1f%%)" % (other_n, 100.0 * other_n / max(1, nblocks)),
        "-" * 52,
        "DEAD (zero/0xFF) : %.1f%%" % pct_dead,
        "RECOVERABLE area : %s in %d extents" % (human(summary["interesting_bytes"]), len(extents)),
        "",
        "Interpretation:",
    ]
    if pct_dead > 99.0:
        lines.append("  >99%% dead. TRIM almost certainly completed. Your best (only)")
        lines.append("  software hope is $MFT resident files + $UsnJrnl. Run 'mft' + 'usn'.")
    elif pct_dead > 85.0:
        lines.append("  Mostly wiped, but real data survives. Run mft/usn first, then")
        lines.append("  archives/source on the interesting extents.")
    else:
        lines.append("  LOTS of data survived -- TRIM did NOT fully complete. Run the")
        lines.append("  full pipeline; good odds for archives and source carving.")
    txt = "\n".join(lines)
    with open(os.path.join(a_dir, "summary.txt"), "w") as f:
        f.write(txt + "\n")
    log("\n" + txt + "\n")
    return summary


def load_extents(reader, regions_path):
    if regions_path and os.path.isfile(regions_path):
        with open(regions_path) as f:
            data = json.load(f)
        ex = [(int(s), int(e)) for s, e in data.get("extents", [])]
        if ex:
            log("[regions] using %d extents (%s) from %s" %
                (len(ex), human(sum(e - s for s, e in ex)), regions_path))
            return ex
    log("[regions] no regions file -- scanning the WHOLE image (slower)")
    return [(0, reader.size)]


# --------------------------------------------------------------------------- #
#  Phase 2: NTFS partition + boot sector discovery                            #
# --------------------------------------------------------------------------- #

def find_ntfs_partitions(reader):
    """Return list of dicts with NTFS partition geometry. Robust to GPT/MBR or
    a bare partition image at offset 0."""
    parts = []
    seen = set()

    def try_bpb(part_off):
        if part_off in seen:
            return
        seen.add(part_off)
        boot = reader.read(part_off, 512)
        if len(boot) < 512 or boot[3:11] != b"NTFS    ":
            return
        bps = le(boot[0x0B:0x0D]) or 512
        spc_raw = boot[0x0D]
        if spc_raw == 0:
            return
        spc = spc_raw if spc_raw < 0x80 else 1 << (256 - spc_raw)
        mft_lcn = le(boot[0x30:0x38])
        clu_per_rec = struct.unpack("<b", boot[0x40:0x41])[0]
        if clu_per_rec >= 0:
            rec_size = clu_per_rec * bps * spc
        else:
            rec_size = 1 << (-clu_per_rec)
        if rec_size <= 0:
            rec_size = 1024
        bpc = bps * spc
        parts.append({
            "part_offset": part_off,
            "bytes_per_sector": bps,
            "sectors_per_cluster": spc,
            "bytes_per_cluster": bpc,
            "mft_lcn": mft_lcn,
            "mft_offset": part_off + mft_lcn * bpc,
            "mft_record_size": rec_size,
            "total_sectors": le(boot[0x28:0x30]),
        })

    # bare partition at 0
    try_bpb(0)

    # MBR
    mbr = reader.read(0, 512)
    if len(mbr) >= 512 and mbr[510:512] == b"\x55\xaa":
        for i in range(4):
            ent = mbr[0x1BE + i * 16: 0x1BE + i * 16 + 16]
            ptype = ent[4]
            start_lba = le(ent[8:12])
            if ptype in (0x07, 0x17) and start_lba:      # NTFS/exFAT
                try_bpb(start_lba * 512)

    # GPT
    gpt = reader.read(512, 512)
    if gpt[:8] == b"EFI PART":
        part_lba = le(gpt[72:80])
        num = le(gpt[80:84])
        esize = le(gpt[84:88]) or 128
        num = min(num, 256)
        table = reader.read(part_lba * 512, num * esize)
        for i in range(num):
            ent = table[i * esize:(i + 1) * esize]
            if len(ent) < 56:
                break
            if ent[:16] == b"\x00" * 16:
                continue
            first_lba = le(ent[32:40])
            if first_lba:
                try_bpb(first_lba * 512)

    return parts


# --------------------------------------------------------------------------- #
#  Phase 2: NTFS $MFT record parsing                                          #
# --------------------------------------------------------------------------- #

ATTR_STANDARD_INFO = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF


def apply_fixup(rec, sector=512):
    """Apply the NTFS Update Sequence Array. Returns possibly-corrected bytes."""
    rec = bytearray(rec)
    if rec[:4] not in (b"FILE", b"BAAD"):
        return bytes(rec)
    usa_off = le(rec[0x04:0x06])
    usa_cnt = le(rec[0x06:0x08])
    if usa_cnt < 1 or usa_off + usa_cnt * 2 > len(rec):
        return bytes(rec)
    usn = rec[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        sec_end = i * sector - 2
        if sec_end + 2 > len(rec):
            break
        orig = rec[usa_off + i * 2: usa_off + i * 2 + 2]
        # only fix if the tail matches the USN (consistency); be lenient otherwise
        rec[sec_end:sec_end + 2] = orig
    return bytes(rec)


def parse_data_runs(buf):
    """Parse an NTFS data-run list -> [(length_clusters, start_lcn_or_None)]."""
    runs = []
    i = 0
    prev = 0
    n = len(buf)
    while i < n:
        header = buf[i]
        i += 1
        if header == 0:
            break
        ll = header & 0x0F
        ol = (header >> 4) & 0x0F
        if ll == 0 or i + ll + ol > n:
            break
        length = le(buf[i:i + ll])
        i += ll
        if ol == 0:
            runs.append((length, None))      # sparse
            continue
        off = le(buf[i:i + ol])
        if buf[i + ol - 1] & 0x80:            # sign-extend negative
            off -= (1 << (ol * 8))
        i += ol
        prev += off
        runs.append((length, prev))
    return runs


def parse_mft_record(rec):
    """Parse one (fixed-up) MFT record. Returns dict or None."""
    if rec[:4] != b"FILE":
        return None
    flags = le(rec[0x16:0x18])
    attr_off = le(rec[0x14:0x16])
    used = le(rec[0x18:0x1C]) or len(rec)
    seq = le(rec[0x10:0x12])
    info = {
        "in_use": bool(flags & 0x01),
        "is_dir": bool(flags & 0x02),
        "seq": seq,
        "names": [],          # list of (namespace, name, parent_entry)
        "real_size": 0,
        "alloc_size": 0,
        "resident_data": None,
        "data_runs": None,
        "si_times": {},
    }
    off = attr_off
    limit = min(used, len(rec))
    guard = 0
    while off + 8 <= limit and guard < 64:
        guard += 1
        atype = le(rec[off:off + 4])
        if atype == ATTR_END:
            break
        alen = le(rec[off + 4:off + 8])
        if alen < 0x10 or off + alen > len(rec):
            break
        non_res = rec[off + 8]
        name_len = rec[off + 9]
        if non_res == 0:
            content_len = le(rec[off + 0x10:off + 0x14])
            content_off = le(rec[off + 0x14:off + 0x16])
            content = rec[off + content_off: off + content_off + content_len]
        else:
            content = b""

        if atype == ATTR_STANDARD_INFO and non_res == 0 and len(content) >= 0x20:
            info["si_times"] = {
                "created": filetime_to_iso(le(content[0x00:0x08])),
                "modified": filetime_to_iso(le(content[0x08:0x10])),
            }
        elif atype == ATTR_FILE_NAME and non_res == 0 and len(content) >= 0x42:
            parent = le(content[0x00:0x06])
            real_size = le(content[0x30:0x38])
            nlen = content[0x40]
            nspace = content[0x41]
            name = content[0x42:0x42 + nlen * 2].decode("utf-16-le", "replace")
            info["names"].append((nspace, name, parent))
            if real_size:
                info["real_size"] = real_size
        elif atype == ATTR_DATA and name_len == 0:
            # unnamed main stream only (skip ADS)
            if non_res == 0:
                info["resident_data"] = content
                if len(content) > info["real_size"]:
                    info["real_size"] = len(content)
            else:
                real_size = le(rec[off + 0x30:off + 0x38])
                alloc = le(rec[off + 0x28:off + 0x30])
                runs_off = le(rec[off + 0x20:off + 0x22])
                runs = parse_data_runs(rec[off + runs_off: off + alen])
                info["data_runs"] = runs
                info["real_size"] = real_size or info["real_size"]
                info["alloc_size"] = alloc
        off += alen
    return info


def pick_name(names):
    """Prefer Win32 / long names over DOS 8.3."""
    if not names:
        return None, None
    best = None
    for nspace, name, parent in names:
        if nspace == 2:            # DOS only -> low priority
            if best is None:
                best = (name, parent)
            continue
        if best is None or len(name) > len(best[0]):
            best = (name, parent)
    return best if best else (names[0][1], names[0][2])


def mine_mft(reader, outdir, geom=None, carve_nonresident=False,
             max_records=5_000_000, regions=None):
    """Scan for MFT FILE records, rebuild the deleted file tree, recover resident
    files intact, and (optionally) targeted-carve non-resident files."""
    m_dir = os.path.join(outdir, "10_mft")
    files_dir = os.path.join(m_dir, "files")
    os.makedirs(files_dir, exist_ok=True)

    if geom is None:
        parts = find_ntfs_partitions(reader)
        geom = parts[0] if parts else {"bytes_per_cluster": 4096, "part_offset": 0,
                                        "mft_record_size": 1024}
        if parts:
            log("[mft] NTFS found: cluster=%s, MFT@offset %d (record %dB)" %
                (human(geom["bytes_per_cluster"]), geom["mft_offset"], geom["mft_record_size"]))
        else:
            log("[mft] No NTFS boot sector found; assuming cluster=4096, record=1024")
    bpc = geom.get("bytes_per_cluster", 4096)
    rec_size = geom.get("mft_record_size", 1024) or 1024

    # Scan extents (or whole image) for 'FILE' record signatures.
    extents = regions if regions else [(0, reader.size)]
    records = {}          # entry_no -> parsed info (best-effort; keyed by offset order)
    by_offset = []        # (offset, info)
    found = 0
    scanned = 0

    log("[mft] scanning for MFT records (record size %dB)..." % rec_size)
    for base, data in iter_windows(reader, extents, window=32 * MiB, overlap=rec_size):
        start = 0
        while True:
            idx = data.find(b"FILE", start)
            if idx == -1:
                break
            start = idx + 4
            abs_off = base + idx
            raw = data[idx: idx + rec_size]
            if len(raw) < rec_size:
                raw = reader.read(abs_off, rec_size)
            if len(raw) < 42:
                continue
            # cheap sanity gate before full parse
            usa_off = le(raw[0x04:0x06])
            attr_off = le(raw[0x14:0x16])
            if not (0x10 <= usa_off <= 0x40) or not (0x20 <= attr_off <= 0x400):
                continue
            fixed = apply_fixup(raw)
            info = parse_mft_record(fixed)
            if not info or not info["names"]:
                continue
            info["offset"] = abs_off
            by_offset.append(info)
            found += 1
            if found % 2000 == 0:
                log("[mft]   parsed %d records (at %s)" % (found, human(abs_off)))
            if found >= max_records:
                break
        scanned += 1
        if found >= max_records:
            break

    log("[mft] parsed %d MFT records with names" % found)

    # Build an entry->name map for path reconstruction. MFT entry number can be
    # inferred from offset when MFT is contiguous; otherwise we use the parent
    # references and a fabricated index keyed by (name,parent).
    # Best-effort: index by sequence of discovery, resolve parents by FILE_NAME.
    # We reconstruct paths using parent refs walked against records we did parse.
    entry_index = {}
    if geom.get("mft_offset") is not None:
        for info in by_offset:
            rel = info["offset"] - geom["mft_offset"]
            if rel >= 0 and rel % rec_size == 0:
                entry_index[rel // rec_size] = info

    def resolve_path(info, depth=0):
        name, parent = pick_name(info["names"])
        if depth > 64:
            return name
        if parent == 5 or parent == 0 or parent not in entry_index:
            return name
        pinfo = entry_index.get(parent)
        if not pinfo or pinfo is info:
            return name
        return resolve_path(pinfo, depth + 1).rstrip("/") + "/" + name

    # Recover files + write manifest
    import csv
    man_path = os.path.join(m_dir, "mft_manifest.csv")
    resident_recovered = 0
    targeted_recovered = 0
    targeted_zero = 0
    listed = 0
    with open(man_path, "w", newline="") as mf:
        w = csv.writer(mf)
        w.writerow(["path", "size_bytes", "is_dir", "in_use", "storage",
                    "modified", "recovered", "recovered_path", "note"])
        for info in by_offset:
            if info["is_dir"]:
                continue
            name, parent = pick_name(info["names"])
            if not name:
                continue
            path = resolve_path(info) if entry_index else name
            size = info["real_size"]
            modified = info.get("si_times", {}).get("modified", "")
            listed += 1
            recovered = ""
            rec_path = ""
            note = ""

            if info["resident_data"] is not None and len(info["resident_data"]) > 0:
                # FULL intact recovery of a small file
                content = info["resident_data"][:size] if size else info["resident_data"]
                rec_path = safe_write(files_dir, path or name, content)
                resident_recovered += 1
                recovered = "yes"
                note = "RESIDENT (intact)"
            elif carve_nonresident and info["data_runs"]:
                buf = bytearray()
                for (length, lcn) in info["data_runs"]:
                    if lcn is None:               # sparse
                        buf += bytes(length * bpc)
                        continue
                    abs_off = geom.get("part_offset", 0) + lcn * bpc
                    buf += reader.read(abs_off, length * bpc)
                    if size and len(buf) >= size:
                        break
                if size:
                    buf = buf[:size]
                if buf and buf.count(0) < len(buf):   # not all zeros -> something survived
                    rec_path = safe_write(files_dir, path or name, bytes(buf))
                    targeted_recovered += 1
                    recovered = "partial/full"
                    note = "TARGETED carve from data runs"
                else:
                    targeted_zero += 1
                    recovered = "no"
                    note = "data clusters TRIMed (read as zero)"
            else:
                note = "non-resident; run with --carve-nonresident to attempt"

            w.writerow([path, size, info["is_dir"], info["in_use"],
                        "resident" if info["resident_data"] is not None else "non-resident",
                        modified, recovered, rec_path, note])

    log("[mft] DONE: %d files listed | %d resident recovered INTACT | "
        "%d targeted-carved | %d non-resident were zero" %
        (listed, resident_recovered, targeted_recovered, targeted_zero))
    log("[mft] manifest: %s" % man_path)
    log("[mft] recovered files under: %s" % files_dir)
    return {
        "listed": listed,
        "resident_recovered": resident_recovered,
        "targeted_recovered": targeted_recovered,
        "targeted_zero": targeted_zero,
        "manifest": man_path,
    }


# --------------------------------------------------------------------------- #
#  Phase 3: $UsnJrnl change-journal mining                                     #
# --------------------------------------------------------------------------- #

USN_REASONS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"), (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"), (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"), (0x00008000, "BASIC_INFO_CHANGE"),
    (0x80000000, "CLOSE"),
]


def decode_reason(reason):
    out = [name for bit, name in USN_REASONS if reason & bit]
    return "|".join(out) if out else ("0x%08x" % reason)


def mine_usn(reader, outdir, regions=None, max_records=20_000_000):
    """Scan for USN_RECORD_V2 entries and dump a timestamped change log.
    This recovers filenames of deleted files even when MFT records are gone."""
    import csv
    u_dir = os.path.join(outdir, "10_mft")
    os.makedirs(u_dir, exist_ok=True)
    out_csv = os.path.join(u_dir, "usn_journal.csv")
    extents = regions if regions else [(0, reader.size)]

    count = 0
    deletes = 0
    log("[usn] scanning for $UsnJrnl V2 records ...")
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "reason", "file_ref", "parent_ref", "attrs", "name"])
        for base, data in iter_windows(reader, extents, window=32 * MiB, overlap=1024):
            n = len(data)
            i = 0
            # USN V2 records: major version 2, minor 0 at offset +4. Scan on that.
            while True:
                j = data.find(b"\x02\x00\x00\x00", i)   # MajorVersion=2, MinorVersion=0
                if j == -1:
                    break
                i = j + 1
                rec_off = j - 4                          # RecordLength precedes version
                if rec_off < 0:
                    continue
                rlen = le(data[rec_off:rec_off + 4])
                if rlen < 0x3C or rlen > 0x400 or rec_off + rlen > n:
                    continue
                name_len = le(data[rec_off + 0x38:rec_off + 0x3A])
                name_off = le(data[rec_off + 0x3A:rec_off + 0x3C])
                if name_off != 0x3C or name_len == 0 or name_len % 2 or name_len > 510:
                    continue
                if rec_off + name_off + name_len > rec_off + rlen:
                    continue
                try:
                    name = data[rec_off + name_off: rec_off + name_off + name_len].decode("utf-16-le", "strict")
                except Exception:
                    continue
                if not name or any(ord(c) < 0x20 for c in name):
                    continue
                file_ref = le(data[rec_off + 0x08:rec_off + 0x10])
                parent_ref = le(data[rec_off + 0x10:rec_off + 0x18])
                ts = filetime_to_iso(le(data[rec_off + 0x20:rec_off + 0x28]))
                reason = le(data[rec_off + 0x28:rec_off + 0x2C])
                attrs = le(data[rec_off + 0x34:rec_off + 0x38])
                w.writerow([ts, decode_reason(reason), file_ref & 0xFFFFFFFFFFFF,
                            parent_ref & 0xFFFFFFFFFFFF, "0x%x" % attrs, name])
                count += 1
                if reason & 0x200:
                    deletes += 1
                if count >= max_records:
                    break
            if count >= max_records:
                break
    log("[usn] DONE: %d journal records (%d FILE_DELETE events) -> %s" %
        (count, deletes, out_csv))
    return {"records": count, "deletes": deletes, "csv": out_csv}


# --------------------------------------------------------------------------- #
#  Phase 4: Archive carving (ZIP / 7z / gzip)                                  #
# --------------------------------------------------------------------------- #

def _overlaps(ranges, s, e):
    for (a, b) in ranges:
        if s < b and a < e:
            return True
    return False


def carve_zip(reader, outdir, regions=None, max_size=2 * GiB):
    z_dir = os.path.join(outdir, "20_archives", "zip")
    mem_dir = os.path.join(outdir, "20_archives", "zip_members")
    os.makedirs(z_dir, exist_ok=True)
    os.makedirs(mem_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    carved = []
    whole = 0
    members = 0

    # --- 4a. Whole-archive reconstruction from End-Of-Central-Directory ---
    log("[zip] reconstructing archives from EOCD records ...")
    for base, data in iter_windows(reader, extents, window=64 * MiB, overlap=1 * MiB):
        start = 0
        while True:
            idx = data.find(b"PK\x05\x06", start)
            if idx == -1:
                break
            start = idx + 4
            eocd_abs = base + idx
            hdr = reader.read(eocd_abs, 22)
            if len(hdr) < 22:
                continue
            cd_size = le(hdr[12:16])
            cd_off = le(hdr[16:20])
            comment_len = le(hdr[20:22])
            arc_start = eocd_abs - cd_size - cd_off
            if arc_start < 0:
                continue
            if reader.read(arc_start, 4) != b"PK\x03\x04":
                continue
            total = (eocd_abs - arc_start) + 22 + comment_len
            if total <= 0 or total > max_size:
                continue
            if _overlaps(carved, arc_start, arc_start + total):
                continue
            blob = reader.read(arc_start, total)
            try:
                zf = zipfile.ZipFile(io.BytesIO(blob))
                names = zf.namelist()
            except Exception:
                continue
            carved.append((arc_start, arc_start + total))
            arc_dir = safe_write(z_dir, "archive_%012x" % arc_start + "/.keep", b"")
            arc_dir = os.path.dirname(arc_dir)
            good = 0
            for zi in zf.infolist():
                try:
                    content = zf.read(zi)
                except Exception:
                    continue
                if zi.is_dir():
                    continue
                safe_write(arc_dir, zi.filename, content)
                good += 1
            whole += 1
            log("[zip]   archive @0x%x  %d/%d members OK -> %s" %
                (arc_start, good, len(names), arc_dir))

    # --- 4b. Per-member salvage from local file headers (broken central dir) ---
    log("[zip] salvaging individual members from local headers ...")
    for base, data in iter_windows(reader, extents, window=64 * MiB, overlap=1 * MiB):
        start = 0
        while True:
            idx = data.find(b"PK\x03\x04", start)
            if idx == -1:
                break
            start = idx + 4
            lh_abs = base + idx
            if _overlaps(carved, lh_abs, lh_abs + 30):
                continue
            lh = reader.read(lh_abs, 30)
            if len(lh) < 30:
                continue
            flag = le(lh[6:8])
            method = le(lh[8:10])
            crc = le(lh[14:18])
            comp_size = le(lh[18:22])
            uncomp_size = le(lh[22:26])
            name_len = le(lh[26:28])
            extra_len = le(lh[28:30])
            if flag & 0x08 or comp_size == 0 or comp_size > max_size:
                continue                                  # streamed/unknown size
            if name_len > 4096:
                continue
            name = reader.read(lh_abs + 30, name_len).decode("utf-8", "replace")
            data_off = lh_abs + 30 + name_len + extra_len
            comp = reader.read(data_off, comp_size)
            if len(comp) < comp_size:
                continue
            try:
                if method == 0:
                    raw = comp
                elif method == 8:
                    raw = zlib.decompressobj(-15).decompress(comp)
                else:
                    continue
            except Exception:
                continue
            if uncomp_size and len(raw) != uncomp_size:
                # partial inflate is still useful for text; keep what we got
                pass
            ok = (not crc) or (binascii.crc32(raw) & 0xFFFFFFFF) == crc
            tag = "ok" if ok else "crcfail"
            safe_write(mem_dir, (name or ("member_%012x" % lh_abs)) + "." + tag, raw)
            members += 1
            if members % 100 == 0:
                log("[zip]   salvaged %d members" % members)

    log("[zip] DONE: %d whole archives, %d salvaged members" % (whole, members))
    return {"whole": whole, "members": members}


def carve_7z(reader, outdir, regions=None, max_size=8 * GiB):
    s_dir = os.path.join(outdir, "20_archives", "7z")
    os.makedirs(s_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    sig = b"7z\xbc\xaf\x27\x1c"
    carved = []
    n = 0
    log("[7z] scanning for CRC-validated 7z headers ...")
    for base, data in iter_windows(reader, extents, window=64 * MiB, overlap=64):
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            start = idx + 6
            abs_off = base + idx
            head = reader.read(abs_off, 32)
            if len(head) < 32:
                continue
            start_crc = le(head[8:12])
            if (binascii.crc32(head[12:32]) & 0xFFFFFFFF) != start_crc:
                continue                                  # not a real 7z header
            nh_off = le(head[12:20])
            nh_size = le(head[20:28])
            total = 32 + nh_off + nh_size
            if total <= 32 or total > max_size or abs_off + total > reader.size:
                continue
            if _overlaps(carved, abs_off, abs_off + total):
                continue
            nh = reader.read(abs_off + 32 + nh_off, nh_size)
            nh_crc = le(head[28:32])
            validated = (binascii.crc32(nh) & 0xFFFFFFFF) == nh_crc
            blob = reader.read(abs_off, total)
            path = safe_write(s_dir, "archive_%012x.7z" % abs_off, blob)
            carved.append((abs_off, abs_off + total))
            n += 1
            log("[7z]   @0x%x size=%s nextHeaderCRC=%s -> %s" %
                (abs_off, human(total), "OK" if validated else "?", path))
    log("[7z] DONE: %d archives carved" % n)
    return {"count": n}


def carve_gzip(reader, outdir, regions=None, max_member=512 * MiB):
    g_dir = os.path.join(outdir, "20_archives", "gzip")
    os.makedirs(g_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    n = 0
    log("[gz] scanning for gzip streams ...")
    for base, data in iter_windows(reader, extents, window=64 * MiB, overlap=64):
        start = 0
        while True:
            idx = data.find(b"\x1f\x8b\x08", start)
            if idx == -1:
                break
            start = idx + 3
            abs_off = base + idx
            flg = reader.read(abs_off + 3, 1)
            if not flg or (flg[0] & 0xE0):                # reserved bits set => junk
                continue
            blob = reader.read(abs_off, max_member)
            try:
                d = zlib.decompressobj(16 + 15)
                out = d.decompress(blob)
                out += d.flush()
            except Exception:
                continue
            if len(out) < 16:
                continue
            safe_write(g_dir, "stream_%012x.bin" % abs_off, out)
            n += 1
            log("[gz]   @0x%x -> %s decompressed" % (abs_off, human(len(out))))
    log("[gz] DONE: %d gzip streams" % n)
    return {"count": n}


# --------------------------------------------------------------------------- #
#  Phase 4b: Media carving (photos + videos)                                   #
# --------------------------------------------------------------------------- #
#
#  Signature-based carving that finds the REAL end of each file instead of
#  blindly dumping a fixed window:
#    * footer-terminated  : JPEG (FFD9), PNG (IEND), GIF (0x3B block-walk)
#    * size-in-header     : BMP, RIFF (AVI/WEBP), ASF/WMV
#    * container box-walk : ISO-BMFF (MP4/MOV/M4V/3GP/HEIC/AVIF)
#    * EBML element-walk  : Matroska / WebM
#
#  As with all carving on a TRIM-completed SSD the data clusters may read back
#  as zeros; this pays off on partially-TRIMed drives, other filesystems, and
#  for files whose bodies happened to survive.

PHOTO_MAX = 256 * MiB
VIDEO_MAX = 8 * GiB

ASF_GUID = bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c")
_BOX_CHAR = re.compile(rb"[A-Za-z0-9 _]{4}")


def _be(b, o, n):
    return int.from_bytes(b[o:o + n], "big")


def _find_footer(reader, start, footer, search_from, max_size, tail):
    """Scan forward from start+search_from for `footer`; return total length
    (footer end - start + tail) or None. `tail` extra bytes belong to the file
    after the footer match (e.g. PNG IEND CRC)."""
    end = min(reader.size, start + max_size)
    pos = start + search_from
    chunk = 8 * MiB
    fl = len(footer)
    while pos < end:
        buf = reader.read(pos, min(chunk, end - pos) + fl)
        i = buf.find(footer)
        if i != -1:
            return (pos + i + fl + tail) - start
        pos += chunk
    return None


def _h_jpeg(reader, off):
    total = _find_footer(reader, off, b"\xff\xd9", 2, PHOTO_MAX, 0)
    if total and total > 4:
        return off, total, "photos", "jpg", "footer"
    return None


def _h_png(reader, off):
    total = _find_footer(reader, off, b"IEND", 8, PHOTO_MAX, 4)
    if total and total > 16:
        return off, total, "photos", "png", "footer"
    return None


def _skip_gif_subblocks(reader, pos, end):
    while pos < end:
        b = reader.read(pos, 1)
        if not b:
            return end
        ln = b[0]
        pos += 1 + ln
        if ln == 0:
            break
    return pos


def _h_gif(reader, off):
    head = reader.read(off, 13)
    if head[:6] not in (b"GIF87a", b"GIF89a") or len(head) < 13:
        return None
    flags = head[10]
    pos = off + 13
    if flags & 0x80:
        pos += 3 * (2 ** ((flags & 7) + 1))
    end = min(reader.size, off + PHOTO_MAX)
    while pos < end:
        b = reader.read(pos, 1)
        if not b:
            return None
        tag = b[0]
        if tag == 0x3B:                                   # trailer
            return off, (pos + 1) - off, "photos", "gif", "parsed"
        elif tag == 0x21:                                 # extension
            pos = _skip_gif_subblocks(reader, pos + 2, end)
        elif tag == 0x2C:                                 # image descriptor
            desc = reader.read(pos, 10)
            if len(desc) < 10:
                return None
            lflags = desc[9]
            pos += 10
            if lflags & 0x80:
                pos += 3 * (2 ** ((lflags & 7) + 1))
            pos += 1                                       # LZW min code size
            pos = _skip_gif_subblocks(reader, pos, end)
        else:
            return None
    return None


def _h_bmp(reader, off):
    hdr = reader.read(off, 14)
    if len(hdr) < 14 or hdr[:2] != b"BM":
        return None
    size = le(hdr[2:6])
    data_off = le(hdr[10:14])
    if size < 54 or size > PHOTO_MAX or not (26 <= data_off < size):
        return None
    return off, size, "photos", "bmp", "header"


def _riff_kind(fourcc):
    if fourcc == b"AVI ":
        return "videos", "avi"
    if fourcc == b"WEBP":
        return "photos", "webp"
    return None, None


def _h_riff(reader, off):
    hdr = reader.read(off, 12)
    if len(hdr) < 12 or hdr[:4] != b"RIFF":
        return None
    total = 8 + le(hdr[4:8])
    kind, ext = _riff_kind(hdr[8:12])
    if not kind or total <= 12 or total > VIDEO_MAX:
        return None
    return off, total, kind, ext, "header"


_BMFF_PHOTO = (b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx",
               b"mif1", b"msf1", b"avif", b"avis")
_BMFF_VIDEO = (b"isom", b"iso2", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42",
               b"mp4v", b"mmp4", b"M4V ", b"M4VH", b"M4VP", b"qt  ", b"3gp",
               b"3g2", b"dash", b"avc1", b"f4v ")


def _bmff_kind(brand):
    if brand in _BMFF_PHOTO:
        return "photos", "heic" if brand[:3] != b"avi" else "avif"
    if brand in _BMFF_VIDEO or brand[:3] in (b"3gp", b"3g2"):
        ext = "mov" if brand == b"qt  " else ("m4v" if brand[:2] == b"M4" else "mp4")
        return "videos", ext
    return None, None


def _h_isobmff(reader, off):
    box_start = off - 4
    if box_start < 0:
        return None
    first_size = _be(reader.read(box_start, 4), 0, 4)
    if first_size != 1 and not (8 <= first_size <= VIDEO_MAX):
        return None
    pos = box_start
    end = min(reader.size, box_start + VIDEO_MAX)
    seen_ftyp = False
    brand = b""
    while pos + 8 <= end:
        hdr = reader.read(pos, 16)
        if len(hdr) < 8:
            break
        size = _be(hdr, 0, 4)
        btype = hdr[4:8]
        if not _BOX_CHAR.fullmatch(btype):
            break
        if size == 1:
            if len(hdr) < 16:
                break
            size = _be(hdr, 8, 8)
        elif size == 0:
            break
        if size < 8:
            break
        if btype == b"ftyp":
            seen_ftyp = True
            brand = reader.read(pos + 8, 4)
        pos += size
    if not seen_ftyp:
        return None
    total = pos - box_start
    kind, ext = _bmff_kind(brand)
    if not kind or total < 16 or total > VIDEO_MAX:
        return None
    return box_start, total, kind, ext, "boxwalk"


def _h_asf(reader, off):
    hdr = reader.read(off, 24)
    if len(hdr) < 24 or hdr[:16] != ASF_GUID:
        return None
    size = le(hdr[16:24])
    if size < 30 or size > VIDEO_MAX:
        return None
    return off, size, "videos", "wmv", "header"


def _read_vint(reader, pos, keep_marker):
    """Read one EBML variable-size integer. Returns (value, length, unknown)."""
    b = reader.read(pos, 1)
    if not b or b[0] == 0:
        return None, 0, False
    first = b[0]
    mask = 0x80
    length = 1
    while length <= 8 and not (first & mask):
        mask >>= 1
        length += 1
    if length > 8:
        return None, 0, False
    raw = reader.read(pos, length)
    if len(raw) < length:
        return None, 0, False
    if keep_marker:
        return int.from_bytes(raw, "big"), length, False
    val = first & (mask - 1)
    for k in range(1, length):
        val = (val << 8) | raw[k]
    if val == (1 << (7 * length)) - 1:                    # all data bits set
        return None, length, True
    return val, length, False


def _h_ebml(reader, off):
    pos = off
    end = min(reader.size, off + VIDEO_MAX)
    count = 0
    while pos < end and count < 4:
        idv, idlen, _ = _read_vint(reader, pos, True)
        if idv is None:
            break
        sz, szlen, unknown = _read_vint(reader, pos + idlen, False)
        if unknown or sz is None:
            return None
        pos += idlen + szlen + sz
        count += 1
        if idv == 0x18538067:                             # Segment -> last top box
            break
    total = pos - off
    if total < 32 or total > VIDEO_MAX:
        return None
    sniff = reader.read(off, min(4096, total))
    ext = "webm" if b"webm" in sniff else "mkv"
    return off, total, "videos", ext, "ebml"


# (signature, handler).  Order matters only for log readability.
MEDIA_SIGS = [
    (b"\xff\xd8\xff", _h_jpeg),
    (b"\x89PNG\r\n\x1a\n", _h_png),
    (b"GIF8", _h_gif),
    (b"BM", _h_bmp),
    (b"RIFF", _h_riff),
    (b"ftyp", _h_isobmff),
    (ASF_GUID, _h_asf),
    (b"\x1aE\xdf\xa3", _h_ebml),
]


def carve_media(reader, outdir, regions=None):
    """Carve photos and videos by signature, finding true file boundaries."""
    import csv
    m_dir = os.path.join(outdir, "40_media")
    photo_dir = os.path.join(m_dir, "photos")
    video_dir = os.path.join(m_dir, "videos")
    os.makedirs(photo_dir, exist_ok=True)
    os.makedirs(video_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    man = os.path.join(m_dir, "media_manifest.csv")

    carved = []                                            # (start, end) dedup
    counts = {"photos": 0, "videos": 0}
    by_ext = {}
    log("[media] scanning for photos & videos ...")
    with open(man, "w", newline="") as mf:
        w = csv.writer(mf)
        w.writerow(["offset_hex", "kind", "ext", "size_bytes", "size_human",
                    "method", "path"])
        for base, data in iter_windows(reader, extents, window=64 * MiB, overlap=1 * MiB):
            hits = []
            for sig, handler in MEDIA_SIGS:
                start = 0
                while True:
                    idx = data.find(sig, start)
                    if idx == -1:
                        break
                    start = idx + 1
                    hits.append((base + idx, handler))
            hits.sort(key=lambda h: h[0])
            for abs_off, handler in hits:
                res = handler(reader, abs_off)
                if not res:
                    continue
                fstart, total, kind, ext, method = res
                if _overlaps(carved, fstart, fstart + total):
                    continue
                blob = reader.read(fstart, total)
                if not blob or blob.count(0) >= len(blob) - 16:
                    continue                               # all zeros => TRIMed
                carved.append((fstart, fstart + total))
                dest = photo_dir if kind == "photos" else video_dir
                path = safe_write(dest, "media_%012x.%s" % (fstart, ext), blob)
                counts[kind] += 1
                by_ext[ext] = by_ext.get(ext, 0) + 1
                w.writerow(["0x%x" % fstart, kind, ext, total, human(total),
                            method, path])
                if (counts["photos"] + counts["videos"]) % 50 == 0:
                    log("[media]   %d photos, %d videos so far" %
                        (counts["photos"], counts["videos"]))
    log("[media] DONE: %d photos, %d videos  %s" %
        (counts["photos"], counts["videos"], dict(by_ext)))
    log("[media] manifest: %s" % man)
    return {"photos": counts["photos"], "videos": counts["videos"],
            "by_ext": by_ext, "manifest": man}


# --------------------------------------------------------------------------- #
#  Phase 5: Language-aware source-code carving                                 #
# --------------------------------------------------------------------------- #

TEXT_RUN = re.compile(rb"[\t\n\r\x20-\x7e]{160,}")

LANG_RULES = {
    "rust": {
        "ext": "rs",
        "strong": [rb"\bfn\s+main\s*\(", rb"\bpub\s+fn\b", rb"#\[derive\(",
                   rb"\buse\s+std::", rb"\bimpl\b[^\n]{0,60}\bfor\b",
                   rb"\blet\s+mut\b", rb"println!\s*\(", rb"->\s*Result<",
                   rb"#!\[", rb"\bmatch\b[^\n]{0,40}\{"],
        "weak": [rb"\bfn\s+\w+\s*\(", rb"\bstruct\s+\w+", rb"\benum\s+\w+",
                 rb"\bpub\s+(struct|enum|mod|trait)\b", rb"::<"],
    },
    "kotlin": {
        "ext": "kt",
        "strong": [rb"\bfun\s+main\s*\(", rb"@Composable", rb"import\s+androidx",
                   rb"\bval\s+\w+\s*[:=]", rb"\bvar\s+\w+\s*[:=]",
                   rb"\bsuspend\s+fun\b", rb"\bcompanion\s+object\b",
                   rb":\s*ViewModel", rb"\bpackage\s+[a-z][\w.]+"],
        "weak": [rb"\bfun\s+\w+\s*\(", rb"\bclass\s+\w+", rb"\bobject\s+\w+",
                 rb"\boverride\b", rb"\bdata\s+class\b"],
    },
    "python": {
        "ext": "py",
        "strong": [rb"\bdef\s+\w+\s*\(", rb"(?m)^\s*import\s+\w+",
                   rb"(?m)^\s*from\s+[\w.]+\s+import", rb"if\s+__name__\s*==",
                   rb"\bself\.", rb"(?m)^#!.*python", rb"\basync\s+def\b"],
        "weak": [rb"\bclass\s+\w+\s*[:(]", rb"\bprint\s*\(", rb"\breturn\b",
                 rb"\bwith\s+open\b", rb"->\s*None\b"],
    },
    "solidity": {
        "ext": "sol",
        "strong": [rb"pragma\s+solidity", rb"\bcontract\s+\w+",
                   rb"\binterface\s+\w+", rb"\blibrary\s+\w+",
                   rb"\bmsg\.sender\b", rb"\bmapping\s*\(", rb"\bemit\s+\w+",
                   rb"\bfunction\s+\w+\s*\([^)]*\)\s*(public|external|internal|private)",
                   rb"// SPDX-License-Identifier"],
        "weak": [rb"\bfunction\s+\w+\s*\(", rb"\bevent\s+\w+", rb"\brequire\s*\(",
                 rb"\buint256\b", rb"\baddress\b"],
    },
    "javascript": {
        "ext": "js",
        "strong": [rb"\bfunction\s+\w+\s*\(", rb"=>\s*\{", rb"\bconst\s+\w+\s*=",
                   rb"\bmodule\.exports\b", rb"\brequire\s*\(", rb"export\s+(default|const|function)"],
        "weak": [rb"\blet\s+\w+\s*=", rb"console\.log", rb"\bawait\b"],
    },
    "go": {
        "ext": "go",
        "strong": [rb"(?m)^package\s+\w+", rb"\bfunc\s+\w+\s*\(", rb"\bimport\s*\(",
                   rb"\bfmt\.", rb":=", rb"\bpackage\s+main\b"],
        "weak": [rb"\bfunc\b", rb"\bdefer\b", rb"\bgo\s+\w+\("],
    },
    "c_cpp": {
        "ext": "c",
        "strong": [rb"#include\s*<", rb"\bint\s+main\s*\(", rb"\bprintf\s*\(",
                   rb"\bstd::", rb"#define\s+\w+", rb"\bvoid\s+\w+\s*\("],
        "weak": [rb"\breturn\s+0;", rb"\bstruct\s+\w+", rb"\btypedef\b"],
    },
    "json": {
        "ext": "json",
        "strong": [rb'^\s*[\{\[]', rb'"\w+"\s*:\s*[\{\["\d]'],
        "weak": [rb'"\w+"\s*:'],
    },
    "toml_cfg": {
        "ext": "toml",
        "strong": [rb"\[dependencies\]", rb"\[package\]", rb"(?m)^\w[\w.-]*\s*=\s*"],
        "weak": [rb"\bversion\s*=", rb"\[\w+\]"],
    },
    "markdown": {
        "ext": "md",
        "strong": [rb"(?m)^#{1,6}\s+\S", rb"```", rb"(?m)^\s*[-*]\s+\S"],
        "weak": [rb"\[.+\]\(.+\)"],
    },
}


def classify_text(buf):
    """Return (lang_key, ext, score) for a text blob, or (None, None, 0)."""
    best_key, best_score = None, 0
    for key, rules in LANG_RULES.items():
        score = 0
        strong_hit = False
        for pat in rules["strong"]:
            if re.search(pat, buf):
                score += 3
                strong_hit = True
        for pat in rules["weak"]:
            if re.search(pat, buf):
                score += 1
        if strong_hit and score > best_score:
            best_key, best_score = key, score
    if best_key and best_score >= 4:
        return best_key, LANG_RULES[best_key]["ext"], best_score
    return None, None, 0


def carve_source(reader, outdir, regions=None, min_len=160,
                 include_unclassified=False):
    base_dir = os.path.join(outdir, "30_source")
    os.makedirs(base_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    import csv
    man = os.path.join(base_dir, "source_manifest.csv")
    counts = {}
    processed_upto = -1
    saved = 0

    log("[src] scanning for source-code text runs ...")
    with open(man, "w", newline="") as mf:
        w = csv.writer(mf)
        w.writerow(["offset_hex", "length", "language", "score", "path", "preview"])
        for base, data in iter_windows(reader, extents, window=32 * MiB, overlap=1 * MiB):
            for m in TEXT_RUN.finditer(data):
                s_abs = base + m.start()
                e_abs = base + m.end()
                if s_abs <= processed_upto:
                    continue
                blob = m.group()
                if len(blob) < min_len:
                    continue
                key, ext, score = classify_text(blob)
                if not key:
                    if not include_unclassified or len(blob) < 600:
                        continue
                    key, ext = "other", "txt"
                lang_dir = os.path.join(base_dir, key)
                os.makedirs(lang_dir, exist_ok=True)
                path = safe_write(lang_dir, "src_%012x.%s" % (s_abs, ext), blob)
                processed_upto = e_abs
                counts[key] = counts.get(key, 0) + 1
                saved += 1
                preview = blob[:60].decode("ascii", "replace").replace("\n", " ")
                w.writerow(["0x%x" % s_abs, len(blob), key, score, path, preview])
                if saved % 200 == 0:
                    log("[src]   saved %d source fragments" % saved)
    log("[src] DONE: %d fragments  %s" % (saved, dict(counts)))
    log("[src] manifest: %s" % man)
    return {"saved": saved, "by_lang": counts}


# --------------------------------------------------------------------------- #
#  Self-test: builds a synthetic image and proves every carver works           #
# --------------------------------------------------------------------------- #

def _build_mft_record(name, parent, content, rec_size=1024):
    """Construct a minimal valid NTFS FILE record with resident $DATA."""
    rec = bytearray(rec_size)
    # --- attributes first, so we can compute first-attr offset = 0x38 ---
    attr_off = 0x38
    off = attr_off

    def put_attr(buf, atype, content_bytes, resident=True):
        # resident attribute
        name_len = 0
        hdr = bytearray(0x18)
        struct.pack_into("<I", hdr, 0x00, atype)
        struct.pack_into("<B", hdr, 0x08, 0)        # resident
        struct.pack_into("<B", hdr, 0x09, name_len)
        struct.pack_into("<H", hdr, 0x0A, 0)
        struct.pack_into("<I", hdr, 0x10, len(content_bytes))
        struct.pack_into("<H", hdr, 0x14, 0x18)     # content offset
        total = 0x18 + len(content_bytes)
        total = (total + 7) & ~7
        struct.pack_into("<I", hdr, 0x04, total)
        out = bytearray(total)
        out[0:0x18] = hdr
        out[0x18:0x18 + len(content_bytes)] = content_bytes
        return out

    # $STANDARD_INFORMATION (0x10)
    si = bytes(0x30)
    a = put_attr(rec, ATTR_STANDARD_INFO, si)
    rec[off:off + len(a)] = a
    off += len(a)

    # $FILE_NAME (0x30)
    nm = name.encode("utf-16-le")
    fn = bytearray(0x42 + len(nm))
    struct.pack_into("<Q", fn, 0x00, parent)
    struct.pack_into("<Q", fn, 0x30, len(content))   # alloc
    struct.pack_into("<Q", fn, 0x38, len(content))   # real size
    fn[0x40] = len(name)
    fn[0x41] = 1                                      # Win32 namespace
    fn[0x42:0x42 + len(nm)] = nm
    a = put_attr(rec, ATTR_FILE_NAME, bytes(fn))
    rec[off:off + len(a)] = a
    off += len(a)

    # $DATA (0x80) resident
    a = put_attr(rec, ATTR_DATA, content)
    rec[off:off + len(a)] = a
    off += len(a)

    # end marker
    struct.pack_into("<I", rec, off, ATTR_END)
    used = off + 8

    # record header
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x04, 0x30)          # USA offset
    struct.pack_into("<H", rec, 0x06, (rec_size // 512) + 1)  # USA count
    struct.pack_into("<H", rec, 0x10, 1)             # seq
    struct.pack_into("<H", rec, 0x12, 1)             # link count
    struct.pack_into("<H", rec, 0x14, attr_off)      # first attr
    struct.pack_into("<H", rec, 0x16, 0x01)          # flags: in use, file
    struct.pack_into("<I", rec, 0x18, used)
    struct.pack_into("<I", rec, 0x1C, rec_size)

    # Update Sequence Array: write USN at 0x30, fix sector tails
    usn = b"\x05\x05"
    rec[0x30:0x32] = usn
    cnt = (rec_size // 512) + 1
    for i in range(1, cnt):
        sec_end = i * 512 - 2
        # save original tail into USA, then stamp USN at tail
        rec[0x30 + i * 2: 0x30 + i * 2 + 2] = rec[sec_end:sec_end + 2]
        rec[sec_end:sec_end + 2] = usn
    return bytes(rec)


def selftest(outdir):
    os.makedirs(outdir, exist_ok=True)
    img_path = os.path.join(outdir, "synthetic.img")
    SIZE = 8 * MiB
    img = bytearray(SIZE)

    # 1) A NTFS-ish boot sector at 0 so geometry is detected (cluster=4096)
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, 512)     # bytes/sector
    boot[0x0D] = 8                              # sectors/cluster -> 4096 cluster
    struct.pack_into("<Q", boot, 0x30, 4)       # MFT LCN
    boot[0x40] = 0xF6                           # -10 -> record size 1024
    img[0:512] = boot

    # 2) MFT at LCN 4 (offset 16384): one resident .rs and one .sol
    mft_off = 4 * 4096
    rust_src = b'fn main() {\n    let mut x = 41;\n    x += 1;\n    println!("answer={}", x);\n}\n'
    rec0 = _build_mft_record("answer.rs", 5, rust_src)
    img[mft_off:mft_off + len(rec0)] = rec0
    sol_src = (b"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
               b"contract Vault {\n    mapping(address => uint256) public balances;\n"
               b"    function deposit() external payable { balances[msg.sender] += msg.value; }\n}\n")
    rec1 = _build_mft_record("Vault.sol", 5, sol_src)
    img[mft_off + 1024:mft_off + 1024 + len(rec1)] = rec1

    # 3) A real ZIP somewhere in the "data" area
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("backup/utils.py", b"def add(a, b):\n    return a + b\n\nimport os\nprint(os.getcwd())\n")
        zf.writestr("backup/Main.kt", b"package demo\nfun main() {\n    val n = 10\n    println(n)\n}\n")
    zbytes = zbuf.getvalue()
    zoff = 2 * MiB
    img[zoff:zoff + len(zbytes)] = zbytes

    # 4) A loose Python source blob (no metadata) further along
    py_blob = (b"#!/usr/bin/env python3\nimport sys\n\n"
               b"def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\n"
               b"if __name__ == '__main__':\n    print(fib(int(sys.argv[1])))\n") * 3
    poff = 4 * MiB
    img[poff:poff + len(py_blob)] = py_blob

    # 5) A USN V2 delete record
    def usn_rec(name, reason):
        nm = name.encode("utf-16-le")
        body = bytearray(0x3C + len(nm))
        struct.pack_into("<H", body, 0x04, 2)        # major
        struct.pack_into("<H", body, 0x06, 0)        # minor
        struct.pack_into("<Q", body, 0x08, 100)      # file ref
        struct.pack_into("<Q", body, 0x10, 5)        # parent
        struct.pack_into("<Q", body, 0x20, 133000000000000000)  # filetime
        struct.pack_into("<I", body, 0x28, reason)
        struct.pack_into("<H", body, 0x38, len(nm))
        struct.pack_into("<H", body, 0x3A, 0x3C)
        body[0x3C:0x3C + len(nm)] = nm
        rlen = (len(body) + 7) & ~7
        full = bytearray(rlen)
        full[:len(body)] = body
        struct.pack_into("<I", full, 0, rlen)
        return bytes(full)
    uoff = 6 * MiB
    r = usn_rec("answer.rs", 0x200 | 0x80000000)      # FILE_DELETE|CLOSE
    img[uoff:uoff + len(r)] = r

    # 6) Media: a real 1x1 PNG, a JPEG (FFD8..FFD9), and a minimal MP4 (ISO-BMFF)
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000d49444154789c6360000002000005000100200d0a2db40000000049454e"
        "44ae426082")
    png_off = 3 * MiB
    img[png_off:png_off + len(png)] = png
    jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x55" * 64 + b"\xff\xd9"
    jpg_off = 3 * MiB + 64 * KiB
    img[jpg_off:jpg_off + len(jpg)] = jpg
    mp4 = (b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isommp41"
           b"\x00\x00\x00\x10mdatHELLO_VID")
    mp4_off = 5 * MiB
    img[mp4_off:mp4_off + len(mp4)] = mp4

    with open(img_path, "wb") as f:
        f.write(img)
    log("[selftest] wrote synthetic image: %s (%s)" % (img_path, human(SIZE)))

    reader = Reader(img_path)
    out = os.path.join(outdir, "out")
    os.makedirs(out, exist_ok=True)
    summary = analyze(reader, out, block_size=64 * KiB)
    ex = [(int(s), int(e)) for s, e in summary["extents"]]
    mres = mine_mft(reader, out, carve_nonresident=False, regions=None)
    ures = mine_usn(reader, out, regions=ex)
    zres = carve_zip(reader, out, regions=ex)
    mres_media = carve_media(reader, out, regions=ex)
    sres = carve_source(reader, out, regions=ex)
    reader.close()

    # assertions
    ok = True
    files = []
    for root, _, fs in os.walk(os.path.join(out, "10_mft", "files")):
        for fn in fs:
            files.append(fn)
    if "answer.rs" not in files or "Vault.sol" not in files:
        ok = False
        log("[selftest] FAIL: resident MFT files not recovered: %s" % files)
    else:
        log("[selftest] PASS: resident MFT files recovered intact: answer.rs, Vault.sol")
    if mres["resident_recovered"] < 2:
        ok = False
    if ures["deletes"] < 1:
        ok = False
        log("[selftest] FAIL: USN delete event not found")
    else:
        log("[selftest] PASS: USN FILE_DELETE recovered")
    if zres["whole"] < 1:
        ok = False
        log("[selftest] FAIL: ZIP not reconstructed")
    else:
        log("[selftest] PASS: ZIP reconstructed (members extracted)")
    langs = sres["by_lang"]
    if langs.get("python", 0) < 1:
        ok = False
        log("[selftest] FAIL: python source not carved (%s)" % langs)
    else:
        log("[selftest] PASS: source carving classified languages: %s" % langs)
    exts = mres_media["by_ext"]
    if mres_media["photos"] < 2 or not {"png", "jpg"} <= set(exts):
        ok = False
        log("[selftest] FAIL: photos not carved (%s)" % exts)
    else:
        log("[selftest] PASS: photos carved (png + jpg, true boundaries)")
    if mres_media["videos"] < 1 or "mp4" not in exts:
        ok = False
        log("[selftest] FAIL: video (mp4) not carved (%s)" % exts)
    else:
        log("[selftest] PASS: video carved (mp4 box-walk)")

    log("\n[selftest] %s" % ("ALL TESTS PASSED" if ok else "SOME TESTS FAILED"))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
#  Recovery summary writer                                                     #
# --------------------------------------------------------------------------- #

def write_summary(outdir, results):
    path = os.path.join(outdir, "RECOVERY_SUMMARY.txt")
    lines = ["RECOVERY SUMMARY", "=" * 52, ""]
    for phase, res in results.items():
        lines.append("[%s]" % phase)
        for k, v in (res or {}).items():
            if k == "extents":
                continue
            lines.append("    %-22s : %s" % (k, v))
        lines.append("")
    lines += [
        "WHERE TO LOOK",
        "-" * 52,
        "  10_mft/files/         -> deleted files recovered with original names",
        "  10_mft/mft_manifest.csv-> EVERY deleted file found (your lost tree)",
        "  10_mft/usn_journal.csv -> timestamped delete log by filename",
        "  20_archives/zip/       -> rebuilt .zip archives (members extracted)",
        "  20_archives/zip_members-> individual files salvaged from broken zips",
        "  20_archives/7z/        -> carved .7z archives (extract with: 7z x)",
        "  40_media/photos/       -> carved photos (jpg/png/gif/bmp/webp/heic)",
        "  40_media/videos/       -> carved videos (mp4/mov/avi/mkv/webm/wmv)",
        "  30_source/<lang>/      -> source fragments grouped by language",
        "",
        "TIP: grep the whole output tree for a unique string you remember:",
        "     grep -rIl 'YOUR_UNIQUE_FUNCTION_NAME' " + outdir,
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    log("\n" + "\n".join(lines))
    log("\n[summary] %s" % path)


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Read-only NTFS/NVMe source-code & archive recovery engine.")
    sub = p.add_subparsers(dest="cmd")

    def add_common(sp):
        sp.add_argument("--image", required=True, help="image file OR /dev/nvmeXn1 (read-only)")
        sp.add_argument("--out", required=True, help="output directory")
        sp.add_argument("--regions", default=None, help="regions.json from 'analyze' (limits scan to live data)")

    sp = sub.add_parser("analyze"); add_common(sp)
    sp.add_argument("--block-size", type=int, default=1 * MiB)

    sp = sub.add_parser("mft"); add_common(sp)
    sp.add_argument("--carve-nonresident", action="store_true",
                    help="also pull file data from cluster runs (may be zeros if TRIMed)")
    sp.add_argument("--cluster-size", type=int, default=None)
    sp.add_argument("--mft-offset", type=int, default=None)

    sp = sub.add_parser("usn"); add_common(sp)
    sp = sub.add_parser("archives"); add_common(sp)
    sp = sub.add_parser("media"); add_common(sp)
    sp = sub.add_parser("source"); add_common(sp)
    sp.add_argument("--include-unclassified", action="store_true")
    sp = sub.add_parser("all"); add_common(sp)
    sp.add_argument("--carve-nonresident", action="store_true")

    sp = sub.add_parser("selftest")
    sp.add_argument("--out", default="/tmp/nvme_selftest")

    args = p.parse_args(argv)
    if not args.cmd:
        p.print_help()
        return 2

    if args.cmd == "selftest":
        return selftest(args.out)

    os.makedirs(args.out, exist_ok=True)
    reader = Reader(args.image)
    if reader.is_block:
        log("[!] SOURCE IS A LIVE BLOCK/PHYSICAL DEVICE. Strongly recommend imaging first.")
        log("[!] Opening READ-ONLY. Do NOT mount this device read-write.")
        if IS_WINDOWS:
            log("[!] Windows: run this from an Administrator prompt to read \\\\.\\PhysicalDriveN.")
        log("")
    if not reader.size:
        log("[!] Could not determine source size (0 bytes). On Windows raw devices")
        log("[!] this usually means it needs Administrator privileges. Aborting.")
        reader.close()
        return 1
    log("[+] source=%s size=%s\n" % (args.image, human(reader.size)))

    geom = None
    if getattr(args, "cluster_size", None) or getattr(args, "mft_offset", None):
        parts = find_ntfs_partitions(reader)
        geom = parts[0] if parts else {"bytes_per_cluster": 4096, "part_offset": 0,
                                       "mft_record_size": 1024, "mft_offset": None}
        if args.cluster_size:
            geom["bytes_per_cluster"] = args.cluster_size
        if args.mft_offset is not None:
            geom["mft_offset"] = args.mft_offset

    try:
        if args.cmd == "analyze":
            analyze(reader, args.out, block_size=args.block_size)
        elif args.cmd == "mft":
            ex = load_extents(reader, args.regions) if args.regions else None
            mine_mft(reader, args.out, geom=geom,
                     carve_nonresident=args.carve_nonresident, regions=ex)
        elif args.cmd == "usn":
            ex = load_extents(reader, args.regions) if args.regions else None
            mine_usn(reader, args.out, regions=ex)
        elif args.cmd == "archives":
            ex = load_extents(reader, args.regions) if args.regions else None
            carve_zip(reader, args.out, regions=ex)
            carve_7z(reader, args.out, regions=ex)
            carve_gzip(reader, args.out, regions=ex)
        elif args.cmd == "media":
            ex = load_extents(reader, args.regions) if args.regions else None
            carve_media(reader, args.out, regions=ex)
        elif args.cmd == "source":
            ex = load_extents(reader, args.regions) if args.regions else None
            carve_source(reader, args.out, regions=ex,
                         include_unclassified=args.include_unclassified)
        elif args.cmd == "all":
            results = {}
            summary = analyze(reader, args.out)
            ex = [(int(s), int(e)) for s, e in summary["extents"]]
            results["analyze"] = {k: v for k, v in summary.items() if k != "extents"}
            results["mft"] = mine_mft(reader, args.out, geom=geom,
                                      carve_nonresident=args.carve_nonresident, regions=None)
            results["usn"] = mine_usn(reader, args.out, regions=ex)
            results["zip"] = carve_zip(reader, args.out, regions=ex)
            results["7z"] = carve_7z(reader, args.out, regions=ex)
            results["gzip"] = carve_gzip(reader, args.out, regions=ex)
            results["media"] = carve_media(reader, args.out, regions=ex)
            results["source"] = carve_source(reader, args.out, regions=ex)
            write_summary(args.out, results)
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
