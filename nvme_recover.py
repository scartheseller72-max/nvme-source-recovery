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
                                name (USN_RECORD V2 and V3); reconstructs
                                exactly what was lost.
  3. Archive carving         -- ZIP (central-directory reconstruction + per
                                member salvage, including streamed members via
                                data descriptors), 7z (CRC-validated, exact
                                size from header), tar (checksum-validated,
                                original member names), and gzip / xz / bzip2
                                streams.
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
import bz2
import csv
import datetime
import hashlib
import io
import json
import math
import mmap
import os
import re
import stat
import struct
import sys
import zlib
import zipfile

try:
    import lzma
except ImportError:        # Python built without liblzma
    lzma = None

__version__ = "2.0.0"

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
#  Unified read-only reader: mmap for files, pread for block devices          #
# --------------------------------------------------------------------------- #

class Reader(object):
    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY)
        st = os.fstat(self.fd)
        self.is_block = stat.S_ISBLK(st.st_mode)
        self.mm = None
        if stat.S_ISREG(st.st_mode):
            self.size = st.st_size
            if self.size > 0:
                try:
                    self.mm = mmap.mmap(self.fd, 0, access=mmap.ACCESS_READ)
                except (ValueError, OSError):
                    self.mm = None
        else:
            # block / char device -- size via lseek to end
            self.size = os.lseek(self.fd, 0, os.SEEK_END)
            os.lseek(self.fd, 0, os.SEEK_SET)

    def read(self, off, length):
        if off < 0 or off >= self.size or length <= 0:
            return b""
        length = min(length, self.size - off)
        if self.mm is not None:
            return self.mm[off:off + length]
        out = bytearray()
        pos = off
        remaining = length
        while remaining > 0:
            try:
                chunk = os.pread(self.fd, min(remaining, 16 * MiB), pos)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            pos += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

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
    """Yield (abs_offset, data, span) windows over the given extents. `data`
    covers span+overlap bytes so signatures spanning a window boundary are fully
    present in at least one window; matches that START at or beyond `span`
    belong to the next window and must be skipped (avoids duplicates)."""
    for (s, e) in extents:
        s = max(0, s)
        e = min(reader.size, e)
        pos = s
        while pos < e:
            n = min(window, e - pos)
            data = reader.read(pos, n + overlap)
            yield pos, data, n
            pos += n


# --------------------------------------------------------------------------- #
#  Phase 1: Region / zero / entropy analysis                                  #
# --------------------------------------------------------------------------- #

def shannon_entropy(data):
    if not data:
        return 0.0
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
    usa_off = le(rec[0x04:0x06])
    # NTFS 3.1+ stores the MFT record number in the header; older layouts
    # (USA offset < 0x30) do not have the field.
    record_no = le(rec[0x2C:0x30]) if usa_off >= 0x30 else None
    info = {
        "in_use": bool(flags & 0x01),
        "is_dir": bool(flags & 0x02),
        "seq": seq,
        "record_no": record_no,
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
    for base, data, span in iter_windows(reader, extents, window=32 * MiB, overlap=rec_size):
        start = 0
        while True:
            idx = data.find(b"FILE", start)
            if idx == -1 or idx >= span:
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

    # Build an entry->record map for path reconstruction. Preferred key is the
    # MFT record number stored in the record header (NTFS 3.1+), which works
    # even for records found OUTSIDE the contiguous MFT (e.g. $MFT fragments or
    # mirror copies). Fallback: infer the entry number from the record's offset
    # relative to the MFT start.
    entry_index = {}
    mft_off = geom.get("mft_offset")
    for info in by_offset:
        rno = info.get("record_no")
        if rno is None and mft_off is not None:
            rel = info["offset"] - mft_off
            if rel >= 0 and rel % rec_size == 0:
                rno = rel // rec_size
        if rno is not None and rno not in entry_index:
            entry_index[rno] = info

    path_cache = {}

    def resolve_path(info, depth=0):
        key = id(info)
        if key in path_cache:
            return path_cache[key]
        name, parent = pick_name(info["names"])
        out = name
        if depth <= 64 and parent not in (0, 5):
            pinfo = entry_index.get(parent)
            if pinfo is not None and pinfo is not info:
                out = resolve_path(pinfo, depth + 1).rstrip("/") + "/" + name
        path_cache[key] = out
        return out

    # Recover files + write manifest
    man_path = os.path.join(m_dir, "mft_manifest.csv")
    resident_recovered = 0
    targeted_recovered = 0
    targeted_zero = 0
    listed = 0
    with open(man_path, "w", newline="") as mf:
        w = csv.writer(mf)
        w.writerow(["path", "size_bytes", "is_dir", "in_use", "storage",
                    "created", "modified", "recovered", "recovered_path", "note"])
        for info in by_offset:
            if info["is_dir"]:
                continue
            name, parent = pick_name(info["names"])
            if not name:
                continue
            path = resolve_path(info) if entry_index else name
            size = info["real_size"]
            created = info.get("si_times", {}).get("created", "")
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
                        created, modified, recovered, rec_path, note])

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


# USN_RECORD field layouts. V2 (Windows XP+) uses 64-bit file references;
# V3 (Windows 8 / Server 2012+, ReFS-capable volumes) uses 128-bit FILE_ID_128.
USN_LAYOUTS = {
    2: {"sig": b"\x02\x00\x00\x00", "min_len": 0x3C,
        "file_ref": (0x08, 8), "parent_ref": (0x10, 8),
        "ts": 0x20, "reason": 0x28, "attrs": 0x34,
        "name_len": 0x38, "name_off_field": 0x3A, "name_at": 0x3C},
    3: {"sig": b"\x03\x00\x00\x00", "min_len": 0x4C,
        "file_ref": (0x08, 16), "parent_ref": (0x18, 16),
        "ts": 0x30, "reason": 0x38, "attrs": 0x44,
        "name_len": 0x48, "name_off_field": 0x4A, "name_at": 0x4C},
}


def _scan_usn_window(data, span, version):
    """Yield (version, ts, reason, file_ref, parent_ref, attrs, name) tuples
    for every valid USN record of the given version in this window."""
    L = USN_LAYOUTS[version]
    n = len(data)
    i = 0
    while True:
        j = data.find(L["sig"], i)      # MajorVersion, MinorVersion=0
        if j == -1:
            break
        i = j + 1
        rec_off = j - 4                  # RecordLength precedes the version
        if rec_off < 0 or rec_off >= span:
            continue
        rlen = le(data[rec_off:rec_off + 4])
        if rlen < L["min_len"] or rlen > 0x400 or rec_off + rlen > n:
            continue
        name_len = le(data[rec_off + L["name_len"]:rec_off + L["name_len"] + 2])
        name_off = le(data[rec_off + L["name_off_field"]:rec_off + L["name_off_field"] + 2])
        if name_off != L["name_at"] or name_len == 0 or name_len % 2 or name_len > 510:
            continue
        if name_off + name_len > rlen:
            continue
        try:
            name = data[rec_off + name_off: rec_off + name_off + name_len].decode("utf-16-le", "strict")
        except Exception:
            continue
        if not name or any(ord(c) < 0x20 for c in name):
            continue
        fo, fl = L["file_ref"]
        po, pl = L["parent_ref"]
        # mask to the 48-bit MFT record number (drops the sequence counter)
        file_ref = le(data[rec_off + fo:rec_off + fo + fl]) & 0xFFFFFFFFFFFF
        parent_ref = le(data[rec_off + po:rec_off + po + pl]) & 0xFFFFFFFFFFFF
        ts = filetime_to_iso(le(data[rec_off + L["ts"]:rec_off + L["ts"] + 8]))
        reason = le(data[rec_off + L["reason"]:rec_off + L["reason"] + 4])
        attrs = le(data[rec_off + L["attrs"]:rec_off + L["attrs"] + 4])
        yield version, ts, reason, file_ref, parent_ref, attrs, name


def mine_usn(reader, outdir, regions=None, max_records=20_000_000):
    """Scan for USN_RECORD V2 and V3 entries and dump a timestamped change log.
    This recovers filenames of deleted files even when MFT records are gone."""
    u_dir = os.path.join(outdir, "10_mft")
    os.makedirs(u_dir, exist_ok=True)
    out_csv = os.path.join(u_dir, "usn_journal.csv")
    extents = regions if regions else [(0, reader.size)]

    count = 0
    deletes = 0
    log("[usn] scanning for $UsnJrnl V2/V3 records ...")
    with open(out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "usn_version", "reason", "file_ref",
                    "parent_ref", "attrs", "name"])
        for base, data, span in iter_windows(reader, extents, window=32 * MiB, overlap=1024):
            for version in (2, 3):
                for (ver, ts, reason, file_ref, parent_ref, attrs, name) in \
                        _scan_usn_window(data, span, version):
                    w.writerow([ts, ver, decode_reason(reason), file_ref,
                                parent_ref, "0x%x" % attrs, name])
                    count += 1
                    if reason & 0x200:
                        deletes += 1
                    if count >= max_records:
                        break
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
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=1 * MiB):
        start = 0
        while True:
            idx = data.find(b"PK\x05\x06", start)
            if idx == -1 or idx >= span:
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
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=1 * MiB):
        start = 0
        while True:
            idx = data.find(b"PK\x03\x04", start)
            if idx == -1 or idx >= span:
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
            if name_len > 4096 or comp_size > max_size:
                continue
            name = reader.read(lh_abs + 30, name_len).decode("utf-8", "replace")
            data_off = lh_abs + 30 + name_len + extra_len

            if flag & 0x08 or comp_size == 0:
                # Streamed member: sizes live in a trailing data descriptor.
                # Find the PK\x07\x08 descriptor whose comp_size matches the
                # distance from the data start, then CRC-validate the inflate.
                raw = None
                probe = reader.read(data_off, 8 * MiB)
                dpos = 0
                while True:
                    k = probe.find(b"PK\x07\x08", dpos)
                    if k == -1 or k + 16 > len(probe):
                        break
                    dpos = k + 1
                    dcrc, dcsize, dusize = struct.unpack("<III", probe[k + 4:k + 16])
                    if dcsize != k:
                        continue
                    comp = probe[:k]
                    try:
                        cand = comp if method == 0 else zlib.decompressobj(-15).decompress(comp)
                    except Exception:
                        continue
                    if (binascii.crc32(cand) & 0xFFFFFFFF) == dcrc and \
                            (not dusize or len(cand) == dusize):
                        raw, crc = cand, dcrc
                        break
                if raw is None:
                    continue
            else:
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
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=64):
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1 or idx >= span:
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
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=64):
        start = 0
        while True:
            idx = data.find(b"\x1f\x8b\x08", start)
            if idx == -1 or idx >= span:
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


def carve_xz(reader, outdir, regions=None, max_member=512 * MiB):
    x_dir = os.path.join(outdir, "20_archives", "xz")
    os.makedirs(x_dir, exist_ok=True)
    if lzma is None:
        log("[xz] python lzma module unavailable -- skipping xz carving")
        return {"count": 0}
    extents = regions if regions else [(0, reader.size)]
    n = 0
    log("[xz] scanning for xz streams ...")
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=64):
        start = 0
        while True:
            idx = data.find(b"\xfd7zXZ\x00", start)
            if idx == -1 or idx >= span:
                break
            start = idx + 6
            abs_off = base + idx
            blob = reader.read(abs_off, max_member)
            try:
                d = lzma.LZMADecompressor(lzma.FORMAT_XZ)
                out = d.decompress(blob, max_member)
            except Exception:
                continue
            if len(out) < 16:
                continue
            safe_write(x_dir, "stream_%012x.bin" % abs_off, out)
            n += 1
            log("[xz]   @0x%x -> %s decompressed" % (abs_off, human(len(out))))
    log("[xz] DONE: %d xz streams" % n)
    return {"count": n}


def carve_bzip2(reader, outdir, regions=None, max_member=512 * MiB):
    b_dir = os.path.join(outdir, "20_archives", "bzip2")
    os.makedirs(b_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    n = 0
    log("[bz2] scanning for bzip2 streams ...")
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=64):
        start = 0
        while True:
            idx = data.find(b"BZh", start)
            if idx == -1 or idx >= span:
                break
            start = idx + 3
            # "BZh" + level 1-9 + compressed-block magic (pi)
            if not (b"1" <= data[idx + 3:idx + 4] <= b"9"):
                continue
            if data[idx + 4:idx + 10] != b"\x31\x41\x59\x26\x53\x59":
                continue
            abs_off = base + idx
            blob = reader.read(abs_off, max_member)
            try:
                d = bz2.BZ2Decompressor()
                out = d.decompress(blob, max_member)
            except Exception:
                continue
            if len(out) < 16:
                continue
            safe_write(b_dir, "stream_%012x.bin" % abs_off, out)
            n += 1
            log("[bz2]   @0x%x -> %s decompressed" % (abs_off, human(len(out))))
    log("[bz2] DONE: %d bzip2 streams" % n)
    return {"count": n}


def _tar_checksum_ok(hdr):
    """Validate a 512-byte tar header via its checksum field (kills false hits)."""
    if len(hdr) < 512:
        return False
    try:
        stored = int(hdr[148:156].split(b"\x00")[0].strip() or b"", 8)
    except ValueError:
        return False
    calc = sum(hdr[:148]) + 8 * 0x20 + sum(hdr[156:512])
    return calc == stored


def carve_tar(reader, outdir, regions=None, max_members=100_000, max_file=2 * GiB):
    """Carve tar archives via the 'ustar' magic + header checksum, walking the
    member chain to recover every file WITH its original name and path."""
    t_dir = os.path.join(outdir, "20_archives", "tar")
    os.makedirs(t_dir, exist_ok=True)
    extents = regions if regions else [(0, reader.size)]
    carved = []
    archives = 0
    members = 0
    log("[tar] scanning for checksum-validated tar headers ...")
    for base, data, span in iter_windows(reader, extents, window=64 * MiB, overlap=1024):
        start = 0
        while True:
            idx = data.find(b"ustar", start)
            if idx == -1 or idx >= span:
                break
            start = idx + 5
            hdr_off = base + idx - 257            # magic sits at +257 in the header
            if hdr_off < 0 or _overlaps(carved, hdr_off, hdr_off + 512):
                continue
            # walk the member chain from this header
            pos = hdr_off
            found = []
            while len(found) < max_members:
                hdr = reader.read(pos, 512)
                if len(hdr) < 512 or hdr[257:262] != b"ustar" or not _tar_checksum_ok(hdr):
                    break
                name = hdr[0:100].split(b"\x00")[0].decode("utf-8", "replace")
                prefix = hdr[345:500].split(b"\x00")[0].decode("utf-8", "replace")
                try:
                    size = int(hdr[124:136].split(b"\x00")[0].strip() or b"0", 8)
                except ValueError:
                    break
                if size < 0 or size > max_file:
                    break
                typeflag = hdr[156:157]
                full_name = (prefix + "/" + name) if prefix else name
                if typeflag in (b"0", b"\x00") and name:
                    found.append((pos + 512, size, full_name))
                pos += 512 + ((size + 511) // 512) * 512
            if not found:
                continue
            arc_dir = os.path.join(t_dir, "archive_%012x" % hdr_off)
            for (doff, size, nm) in found:
                safe_write(arc_dir, nm, reader.read(doff, size))
                members += 1
            carved.append((hdr_off, pos))
            archives += 1
            log("[tar]   @0x%x  %d members -> %s" % (hdr_off, len(found), arc_dir))
    log("[tar] DONE: %d tar archives, %d members" % (archives, members))
    return {"archives": archives, "members": members}


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
    "typescript": {
        "ext": "ts",
        "strong": [rb"\bexport\s+(interface|type)\s+\w+", rb"\binterface\s+\w+\s*\{",
                   rb"\btype\s+\w+\s*=", rb":\s*(string|number|boolean)\b",
                   rb"\bimplements\s+\w+", rb"\breadonly\s+\w+\s*:"],
        "weak": [rb"\benum\s+\w+", rb"\bprivate\s+\w+\s*:", rb"<\w+>\s*\(",
                 rb"\bas\s+const\b"],
    },
    "java": {
        "ext": "java",
        "strong": [rb"\bpublic\s+(final\s+)?class\s+\w+", rb"\bpublic\s+static\s+void\s+main\b",
                   rb"\bSystem\.out\.print", rb"\bimport\s+java[x]?\.",
                   rb"@Override\b", rb"\bprivate\s+(static\s+)?final\b"],
        "weak": [rb"\bnew\s+\w+\s*\(", rb"\bextends\s+\w+", rb"\bthrows\s+\w+",
                 rb"\bvoid\s+\w+\s*\("],
    },
    "shell": {
        "ext": "sh",
        "strong": [rb"(?m)^#!.*\b(ba|z|da)?sh\b", rb"(?m)^\s*fi\s*$", rb"(?m)^\s*esac\s*$",
                   rb"\[\[\s[^\n]+\s\]\]", rb"\$\{\w+[:#%/-]"],
        "weak": [rb"(?m)^\s*if\s+\[", rb"\blocal\s+\w+=", rb"\becho\s+",
                 rb"(?m)^\s*done\s*$"],
    },
    "sql": {
        "ext": "sql",
        "strong": [rb"(?i)\bCREATE\s+TABLE\b", rb"(?i)\bSELECT\b[^\n;]{0,200}\bFROM\b",
                   rb"(?i)\bINSERT\s+INTO\b", rb"(?i)\bALTER\s+TABLE\b",
                   rb"(?i)\bPRIMARY\s+KEY\b"],
        "weak": [rb"(?i)\bWHERE\b", rb"(?i)\bVARCHAR\b", rb"(?i)\bJOIN\b"],
    },
    "html": {
        "ext": "html",
        "strong": [rb"(?i)<!DOCTYPE\s+html", rb"(?i)<html\b", rb"(?i)<div\b[^>]*>",
                   rb"(?i)<body\b"],
        "weak": [rb"(?i)</\w+>", rb"(?i)<a\s+href=", rb"(?i)<script\b"],
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
    man = os.path.join(base_dir, "source_manifest.csv")
    counts = {}
    processed_upto = -1
    saved = 0
    dupes = 0
    seen_hashes = set()

    log("[src] scanning for source-code text runs ...")
    with open(man, "w", newline="") as mf:
        w = csv.writer(mf)
        w.writerow(["offset_hex", "length", "language", "score", "path", "preview"])
        for base, data, span in iter_windows(reader, extents, window=32 * MiB, overlap=1 * MiB):
            for m in TEXT_RUN.finditer(data):
                if m.start() >= span:
                    break
                s_abs = base + m.start()
                e_abs = base + m.end()
                if s_abs <= processed_upto:
                    continue
                blob = m.group()
                if len(blob) < min_len:
                    continue
                digest = hashlib.sha1(blob).digest()
                if digest in seen_hashes:
                    dupes += 1
                    processed_upto = e_abs
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
                seen_hashes.add(digest)
                counts[key] = counts.get(key, 0) + 1
                saved += 1
                preview = blob[:60].decode("ascii", "replace").replace("\n", " ")
                w.writerow(["0x%x" % s_abs, len(blob), key, score, path, preview])
                if saved % 200 == 0:
                    log("[src]   saved %d source fragments" % saved)
    log("[src] DONE: %d fragments (%d duplicates skipped)  %s" % (saved, dupes, dict(counts)))
    log("[src] manifest: %s" % man)
    return {"saved": saved, "duplicates_skipped": dupes, "by_lang": counts}


# --------------------------------------------------------------------------- #
#  Self-test: builds a synthetic image and proves every carver works           #
# --------------------------------------------------------------------------- #

def _build_mft_record(name, parent, content, rec_size=1024,
                      record_no=0, flags=0x01):
    """Construct a minimal valid NTFS FILE record with resident $DATA.
    flags: 0x01 = file in use, 0x00 = deleted file, 0x03 = directory in use."""
    rec = bytearray(rec_size)
    is_dir = bool(flags & 0x02)
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

    # $DATA (0x80) resident -- directories have no unnamed data stream
    if not is_dir:
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
    struct.pack_into("<H", rec, 0x16, flags)         # in-use / dir flags
    struct.pack_into("<I", rec, 0x18, used)
    struct.pack_into("<I", rec, 0x1C, rec_size)
    struct.pack_into("<I", rec, 0x2C, record_no)     # MFT record number (3.1+)

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
    import tarfile

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

    # 2) MFT at LCN 4 (offset 16384): resident files, a directory tree
    #    (src/main.rs -- exercises record-number path reconstruction), and a
    #    DELETED file (in_use=0 -- the actual recovery scenario).
    mft_off = 4 * 4096
    rust_src = b'fn main() {\n    let mut x = 41;\n    x += 1;\n    println!("answer={}", x);\n}\n'
    sol_src = (b"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
               b"contract Vault {\n    mapping(address => uint256) public balances;\n"
               b"    function deposit() external payable { balances[msg.sender] += msg.value; }\n}\n")
    recs = [
        _build_mft_record("answer.rs", 5, rust_src, record_no=16),
        _build_mft_record("Vault.sol", 5, sol_src, record_no=17),
        _build_mft_record("src", 5, b"", record_no=20, flags=0x03),       # directory
        _build_mft_record("main.rs", 20, rust_src, record_no=21),        # inside src/
        _build_mft_record("lost.py", 5, b"print('deleted but resident')\n",
                          record_no=22, flags=0x00),                     # deleted
    ]
    for i, rec in enumerate(recs):
        img[mft_off + i * 1024: mft_off + i * 1024 + len(rec)] = rec

    # 3) A real ZIP somewhere in the "data" area
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("backup/utils.py", b"def add(a, b):\n    return a + b\n\nimport os\nprint(os.getcwd())\n")
        zf.writestr("backup/Main.kt", b"package demo\nfun main() {\n    val n = 10\n    println(n)\n}\n")
    zbytes = zbuf.getvalue()
    zoff = 2 * MiB
    img[zoff:zoff + len(zbytes)] = zbytes

    # 3b) A streamed ZIP member (flag bit 3, sizes only in the data descriptor)
    sm_name = b"stream/notes.md"
    sm_raw = b"# Recovered notes\n\n- streamed zip member salvage works\n"
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    sm_data = co.compress(sm_raw) + co.flush()
    lfh = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0x08, 8, 0, 0,
                      0, 0, 0, len(sm_name), 0)
    desc = struct.pack("<IIII", 0x08074b50, binascii.crc32(sm_raw) & 0xFFFFFFFF,
                       len(sm_data), len(sm_raw))
    streamed = lfh + sm_name + sm_data + desc
    soff = 2 * MiB + 256 * KiB
    img[soff:soff + len(streamed)] = streamed

    # 3c) gzip / xz / bzip2 streams
    payload = b"compressed recovery payload: " + b"0123456789abcdef" * 16
    co = zlib.compressobj(9, zlib.DEFLATED, 31)        # gzip container
    gz_blob = co.compress(payload) + co.flush()
    goff = 2 * MiB + 512 * KiB
    img[goff:goff + len(gz_blob)] = gz_blob
    if lzma is not None:
        xz_blob = lzma.compress(payload, format=lzma.FORMAT_XZ)
        xoff = 2 * MiB + 768 * KiB
        img[xoff:xoff + len(xz_blob)] = xz_blob
    bz_blob = bz2.compress(payload)
    boff = 3 * MiB
    img[boff:boff + len(bz_blob)] = bz_blob

    # 3d) A tar archive (member names + paths must survive)
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for nm, data_ in (("proj/lib.rs", b"pub fn add(a: i32, b: i32) -> i32 { a + b }\n"),
                          ("proj/app.py", b"def run():\n    return 42\n")):
            ti = tarfile.TarInfo(nm)
            ti.size = len(data_)
            tf.addfile(ti, io.BytesIO(data_))
    tar_blob = tbuf.getvalue()
    toff = 3 * MiB + 256 * KiB
    img[toff:toff + len(tar_blob)] = tar_blob

    # 3e) A minimal 7z (valid signature header + CRC-checked next header)
    nh = b"\x17\x06\x8d\x9b\xd5\x0f" + b"\x00" * 18
    head = bytearray(32)
    head[0:6] = b"7z\xbc\xaf\x27\x1c"
    head[6:8] = b"\x00\x04"
    struct.pack_into("<Q", head, 12, 0)               # next header right after
    struct.pack_into("<Q", head, 20, len(nh))
    struct.pack_into("<I", head, 28, binascii.crc32(nh) & 0xFFFFFFFF)
    struct.pack_into("<I", head, 8, binascii.crc32(head[12:32]) & 0xFFFFFFFF)
    z7off = 3 * MiB + 512 * KiB
    img[z7off:z7off + 32 + len(nh)] = bytes(head) + nh

    # 4) Loose source blobs (no metadata): python, java, typescript
    py_blob = (b"#!/usr/bin/env python3\nimport sys\n\n"
               b"def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\n"
               b"if __name__ == '__main__':\n    print(fib(int(sys.argv[1])))\n") * 3
    poff = 4 * MiB
    img[poff:poff + len(py_blob)] = py_blob
    java_blob = (b"import java.util.List;\n\npublic class Main {\n"
                 b"    @Override\n    public String toString() { return \"demo\"; }\n"
                 b"    public static void main(String[] args) {\n"
                 b"        System.out.println(\"recovered\");\n    }\n}\n") * 2
    joff = 4 * MiB + 512 * KiB
    img[joff:joff + len(java_blob)] = java_blob
    ts_blob = (b"export interface Config {\n    name: string;\n    retries: number;\n"
               b"    readonly verbose: boolean;\n}\n\n"
               b"export type Outcome = { ok: boolean };\n"
               b"const defaults: Config = { name: 'x', retries: 3, verbose: false };\n") * 2
    tsoff = 4 * MiB + 768 * KiB
    img[tsoff:tsoff + len(ts_blob)] = ts_blob

    # 5) USN delete records: one V2 and one V3
    def usn_rec_v2(name, reason):
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

    def usn_rec_v3(name, reason):
        nm = name.encode("utf-16-le")
        body = bytearray(0x4C + len(nm))
        struct.pack_into("<H", body, 0x04, 3)        # major
        struct.pack_into("<H", body, 0x06, 0)        # minor
        struct.pack_into("<Q", body, 0x08, 200)      # file ref (low 8 of 16)
        struct.pack_into("<Q", body, 0x18, 5)        # parent (low 8 of 16)
        struct.pack_into("<Q", body, 0x30, 133000000000000000)  # filetime
        struct.pack_into("<I", body, 0x38, reason)
        struct.pack_into("<H", body, 0x48, len(nm))
        struct.pack_into("<H", body, 0x4A, 0x4C)
        body[0x4C:0x4C + len(nm)] = nm
        rlen = (len(body) + 7) & ~7
        full = bytearray(rlen)
        full[:len(body)] = body
        struct.pack_into("<I", full, 0, rlen)
        return bytes(full)

    uoff = 6 * MiB
    r = usn_rec_v2("answer.rs", 0x200 | 0x80000000)   # FILE_DELETE|CLOSE
    img[uoff:uoff + len(r)] = r
    r3 = usn_rec_v3("Vault.sol", 0x200 | 0x80000000)
    img[uoff + 1024:uoff + 1024 + len(r3)] = r3

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
    z7res = carve_7z(reader, out, regions=ex)
    tres = carve_tar(reader, out, regions=ex)
    gres = carve_gzip(reader, out, regions=ex)
    xres = carve_xz(reader, out, regions=ex)
    bres = carve_bzip2(reader, out, regions=ex)
    sres = carve_source(reader, out, regions=ex)
    reader.close()

    # assertions
    ok = True

    def check(cond, what):
        nonlocal ok
        if cond:
            log("[selftest] PASS: %s" % what)
        else:
            ok = False
            log("[selftest] FAIL: %s" % what)

    files_root = os.path.join(out, "10_mft", "files")
    files = []
    for root, _, fs in os.walk(files_root):
        for fn in fs:
            files.append(fn)
    check("answer.rs" in files and "Vault.sol" in files,
          "resident MFT files recovered intact (answer.rs, Vault.sol)")
    check("lost.py" in files, "DELETED resident file recovered (lost.py)")
    check(os.path.isfile(os.path.join(files_root, "src", "main.rs")),
          "directory path reconstructed from MFT record numbers (src/main.rs)")
    check(mres["resident_recovered"] >= 4, "resident recovery count >= 4")
    check(ures["deletes"] >= 2, "USN FILE_DELETE events found (V2 + V3)")
    check(zres["whole"] >= 1, "ZIP reconstructed from EOCD (members extracted)")
    check(zres["members"] >= 1, "streamed ZIP member salvaged via data descriptor")
    check(z7res["count"] >= 1, "7z carved (CRC-validated header)")
    check(tres["members"] >= 2, "tar members carved with original paths")
    check(gres["count"] >= 1, "gzip stream decompressed")
    if lzma is not None:
        check(xres["count"] >= 1, "xz stream decompressed")
    check(bres["count"] >= 1, "bzip2 stream decompressed")
    langs = sres["by_lang"]
    check(langs.get("python", 0) >= 1, "python source carved (%s)" % langs)
    check(langs.get("java", 0) >= 1, "java source carved")
    check(langs.get("typescript", 0) >= 1, "typescript source carved")

    log("\n[selftest] %s" % ("ALL TESTS PASSED" if ok else "SOME TESTS FAILED"))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
#  Recovery summary writer                                                     #
# --------------------------------------------------------------------------- #

def write_summary(outdir, results):
    jpath = os.path.join(outdir, "RECOVERY_SUMMARY.json")
    with open(jpath, "w") as f:
        json.dump({"version": __version__, "results": results}, f,
                  indent=2, default=str)
    path = os.path.join(outdir, "RECOVERY_SUMMARY.txt")
    lines = ["RECOVERY SUMMARY  (engine v%s)" % __version__, "=" * 52, ""]
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
        "  20_archives/tar/       -> carved tar archives (members extracted)",
        "  20_archives/{gzip,xz,bzip2}/ -> decompressed streams",
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
    p.add_argument("--version", action="version",
                   version="nvme_recover %s" % __version__)
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
        log("[!] SOURCE IS A LIVE BLOCK DEVICE. Strongly recommend imaging first.")
        log("[!] Opening READ-ONLY. Do NOT mount this device read-write.\n")
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
            carve_tar(reader, args.out, regions=ex)
            carve_gzip(reader, args.out, regions=ex)
            carve_xz(reader, args.out, regions=ex)
            carve_bzip2(reader, args.out, regions=ex)
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
            results["tar"] = carve_tar(reader, args.out, regions=ex)
            results["gzip"] = carve_gzip(reader, args.out, regions=ex)
            results["xz"] = carve_xz(reader, args.out, regions=ex)
            results["bzip2"] = carve_bzip2(reader, args.out, regions=ex)
            results["source"] = carve_source(reader, args.out, regions=ex)
            write_summary(args.out, results)
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
