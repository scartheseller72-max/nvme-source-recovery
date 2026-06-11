<p align="center">
  <img src="assets/logo.png" alt="NVMe Recovery Toolkit" width="720">
</p>

<p align="center">
  <strong>Read-only forensic recovery of accidentally deleted source code and archives
  from an NTFS volume on an NVMe SSD.</strong><br>
  Built for the Lexar NM620 / Innogrit IG5216 (DRAM-less, TRIM-enabled) mass-deletion scenario.
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-2.0.0-8a5cf5">
  <img alt="self-test" src="https://img.shields.io/badge/self--test-ALL_PASSED-2ea44f">
  <img alt="source mode" src="https://img.shields.io/badge/source-READ--ONLY-3b6ea8">
  <img alt="python" src="https://img.shields.io/badge/python-3.6%2B_stdlib-f2a33c">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-555555">
</p>

---

## Overview

You deleted roughly 100 GB of `.rs / .kt / .py / .sol` source and `.zip / .7z`
backups on a TRIM-enabled NVMe drive, rebooted once, then hard-powered-off. This
toolkit provides the highest realistic chance of recovering that source code using
software alone, by attacking the recovery vectors that generic carvers
(PhotoRec, EaseUS, Disk Drill) miss.

The workflow is two steps and never touches the original drive after imaging:

```
   Power off the drive  ->  Image it read-only  ->  Recover from the image
        (done)                01_image_drive.sh        02_run_recovery.sh
```

New here? The [Backstory](BACKSTORY.md) explains the incident that led to this
toolkit — and the one insight that turned a near-hopeless case into a solvable one.

---

## Why this works — the $MFT vector

Most guides stop at *"TRIM means the data is gone, send it to a lab."* That is only
half the story. The critical fact:

> TRIM / DEALLOCATE frees the deleted files' **data clusters** — it does **not**
> deallocate the `$MFT` system file itself.

So even when the data area reads back as zeros:

| Frequently survives TRIM | Usually wiped by TRIM |
| --- | --- |
| `$MFT` records of deleted files (names, paths, sizes) | the bulk file **data clusters** |
| **Resident** small files — content stored *inside* the MFT record | large non-resident file bodies |
| `$UsnJrnl` change journal (timestamped delete log) | |

Many source files are small enough to be stored **resident** inside their MFT
record, which means they are recovered **fully intact, with their original
filename and path**, even on a drive where the data area has been zeroed. That is
the realistic win this toolkit is engineered around.

---

## Pipeline

```
        +---------------------------------------------------------------+
        |            DAMAGED Lexar NM620 512GB  (keep powered OFF)       |
        +-------------------------------+-------------------------------+
                                        |  connect to Linux, do NOT mount
                                        v
        +---------------------------------------------------------------+
        |  STEP 1   01_image_drive.sh                 [ READ-ONLY ]      |
        |  devices  ->  state  ->  image                                |
        |  blockdev --setro -> SMART/TRIM capture -> ddrescue -> sha256 |
        +-------------------------------+-------------------------------+
                                        |  rescue-nvme0n1.img  (work on THIS)
                                        v
        +---------------------------------------------------------------+
        |  STEP 2   02_run_recovery.sh   ->   nvme_recover.py           |
        |                                                               |
        |  analyze  ->  mft  ->  usn  ->  archives  ->  source          |
        |  (where's    (intact  (delete   (zip/7z/     (.rs/.kt/        |
        |   the data?)  files)   log)      gzip)        .py/.sol)       |
        +-------------------------------+-------------------------------+
                                        v
                          recovered/  (your files + manifests)
```

---

## Recovery vectors

<table>
  <thead>
    <tr><th width="64">&nbsp;</th><th>Command</th><th>What it does</th></tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><img src="assets/icon-analyze.png" width="44" alt="analyze"></td>
      <td><code>analyze</code></td>
      <td>Zero / <code>0xFF</code> / entropy map of the image: shows how much TRIM
      wiped and <em>where</em> live data sits. Writes <code>regions.json</code> to
      fast-path every later phase.</td>
    </tr>
    <tr>
      <td align="center"><img src="assets/icon-mft.png" width="44" alt="mft"></td>
      <td><code>mft</code></td>
      <td>Scans <code>$MFT</code>: recovers <strong>resident files intact</strong>
      with full directory paths rebuilt from the MFT record numbers (works even
      for scattered record fragments); for non-resident files it lists the exact
      clusters and can targeted-carve them with <code>--carve-nonresident</code>.</td>
    </tr>
    <tr>
      <td align="center"><img src="assets/icon-usn.png" width="44" alt="usn"></td>
      <td><code>usn</code></td>
      <td>Parses the <code>$UsnJrnl</code> change journal (<strong>V2 and V3</strong>
      records) into a timestamped <strong>delete log by filename</strong>.</td>
    </tr>
    <tr>
      <td align="center"><img src="assets/icon-archives.png" width="44" alt="archives"></td>
      <td><code>archives</code></td>
      <td><strong>ZIP</strong> (central-directory reconstruction + per-member
      salvage, including <em>streamed</em> members via data descriptors),
      <strong>7z</strong> (CRC-validated, exact size from header),
      <strong>tar</strong> (checksum-validated, original member names), and
      <strong>gzip / xz / bzip2</strong> stream recovery.</td>
    </tr>
    <tr>
      <td align="center"><img src="assets/icon-source.png" width="44" alt="source"></td>
      <td><code>source</code></td>
      <td>Language-aware carving of raw bytes into buckets:
      <code>.rs / .kt / .py / .sol / .go / .js / .ts / .java / .c / .sh / .sql /
      .html / .json / .toml / .md</code> — with automatic duplicate-fragment
      de-duplication.</td>
    </tr>
  </tbody>
</table>

Two convenience commands tie these together:

- `all` — runs every phase in the optimal order and writes `RECOVERY_SUMMARY.txt`.
- `selftest` — builds a synthetic image and proves every vector works (no drive needed).

---

## Requirements

Run from a **Linux live USB** (SystemRescue / Ubuntu / Mint). Do not boot the
affected Windows installation.

```bash
sudo apt update && sudo apt install -y gddrescue nvme-cli gdisk python3 p7zip-full
```

| Package | Purpose |
| --- | --- |
| `gddrescue` | provides `ddrescue` (the imager) |
| `nvme-cli` | SMART / id-ctrl / TRIM-state capture |
| `gdisk` | GPT partition-table backup (`sgdisk`) |
| `python3` | the recovery engine (3.6+, **standard library only**) |
| `p7zip-full` | optional — to *extract* carved `.7z` (carving works without it) |

---

## Usage

### Step 1 — Image the drive (read-only)

```bash
chmod +x 01_image_drive.sh 02_run_recovery.sh

./01_image_drive.sh devices                       # identify your /dev/nvmeXn1
./01_image_drive.sh state /dev/nvme0n1 /mnt/dest   # capture SMART/TRIM evidence (optional)
./01_image_drive.sh image /dev/nvme0n1 /mnt/dest   # -> /mnt/dest/rescue-nvme0n1.img (+ .sha256)
./01_image_drive.sh verify /mnt/dest               # re-check image SHA-256 any time later
```

Safety is enforced: the script refuses if the source is mounted or if the
destination lives on the source disk, force-sets the source read-only
(`blockdev --setro`), and only ever issues READ commands — never TRIM/discard.
The destination must be a separate, larger disk you can write to.

### Step 2 — Recover (operates on the image only)

```bash
./02_run_recovery.sh /mnt/dest/rescue-nvme0n1.img /mnt/dest/recovered
```

Optional extra pass — also pull non-resident file bodies from their exact
clusters (may be zeros if TRIM completed, but worth one attempt):

```bash
python3 nvme_recover.py mft \
    --image /mnt/dest/rescue-nvme0n1.img \
    --out   /mnt/dest/recovered \
    --carve-nonresident
```

### Step 3 — Find your files

```bash
# grep the whole recovery tree for a string you know was in your code
grep -rIl 'someUniqueFunctionName' /mnt/dest/recovered
```

---

## Output layout

```
recovered/
+-- 00_analysis/
|   +-- regions.json          <- live-data map (speeds up later phases)
|   +-- summary.txt           <- "how much did TRIM wipe?" verdict
+-- 10_mft/
|   +-- files/                <- deleted files recovered WITH original names
|   +-- mft_manifest.csv      <- every deleted file found (your lost tree)
|   +-- usn_journal.csv       <- timestamped delete log
+-- 20_archives/
|   +-- zip/                  <- rebuilt .zip (members extracted)
|   +-- zip_members/          <- individual files salvaged from broken zips
|   |                            (including streamed members via data descriptors)
|   +-- 7z/                   <- carved .7z (extract with: 7z x)
|   +-- tar/                  <- carved tar archives (members + original paths)
|   +-- gzip/ xz/ bzip2/      <- decompressed compression streams
+-- 30_source/
|   +-- rust/ kotlin/ python/ solidity/ go/ javascript/ typescript/ java/ ...
|   +-- source_manifest.csv   <- offset, language, confidence, preview
+-- RECOVERY_SUMMARY.txt
+-- RECOVERY_SUMMARY.json     <- same summary, machine-readable
```

---

## Verify it works (no drive needed)

```bash
python3 nvme_recover.py selftest --out /tmp/nvme_selftest
```

Builds a synthetic NTFS-style image and asserts every vector end-to-end:
resident MFT files recovered byte-for-byte (including a **deleted** file and a
file inside a subdirectory, proving path reconstruction), USN V2 **and** V3
delete events parsed, ZIP reconstructed with members extracted, a streamed ZIP
member salvaged via its data descriptor, 7z / tar / gzip / xz / bzip2 carved
and decompressed, and source fragments correctly language-classified
(python / java / typescript / solidity). Prints `ALL TESTS PASSED`.

---

## Command reference

```text
python3 nvme_recover.py <command> --image <IMG|/dev/nvmeXn1> --out <DIR> [options]

  analyze   --block-size N             zero/entropy region map
  mft       [--carve-nonresident]      $MFT mining (+ optional cluster carve)
            [--cluster-size N] [--mft-offset N]
  usn                                  $UsnJrnl delete log (V2 + V3 records)
  archives                             ZIP / 7z / tar / gzip / xz / bzip2 carving
  source    [--include-unclassified]   language-aware source carving
  all       [--carve-nonresident]      full pipeline + summary (.txt + .json)
  selftest                             self-validate the engine

  common:   --regions <regions.json>   restrict scan to live extents (faster)
            --version                  print engine version
```

---

## What's new in v2.0.0

- **MFT path reconstruction via record numbers** — full `dir/sub/file.ext`
  paths are now rebuilt from the record number stored in each FILE record
  header (NTFS 3.1+), so even MFT fragments found *outside* the contiguous
  table resolve correctly. Created timestamps added to the manifest.
- **USN V3 support** — journals from Windows 8 / Server 2012+ volumes
  (128-bit file references) are parsed alongside V2.
- **Streamed-ZIP salvage** — members written with flag bit 3 (sizes only in
  the trailing data descriptor) are now recovered and CRC-validated.
- **Three new carvers** — `tar` (header-checksum validated, original member
  names and paths), `xz`, and `bzip2` streams (both decompressed in-engine,
  still stdlib-only).
- **Five new source languages** — TypeScript, Java, Shell, SQL, and HTML,
  plus SHA-1 de-duplication of identical fragments.
- **Correctness & ops** — window-overlap duplicate hits eliminated across all
  scanners, machine-readable `RECOVERY_SUMMARY.json`, `--version` flag,
  `01_image_drive.sh verify` phase, and a selftest that now asserts 15 checks
  end-to-end (deleted-file recovery and subdirectory paths included).

---

## Realism assessment

- **Bulk data area.** On a TRIM-completed NVMe, deleted data clusters most likely
  read back as zeros (deterministic read after TRIM). Raw `source` carving and
  `--carve-nonresident` may find little there. The pessimistic write-ups are
  correct about this part.
- **Where the hope is.** The `$MFT` resident files and the `$UsnJrnl` routinely
  survive, and they are exactly where small source files come back intact.
- **What to do.** Run `analyze` first. If the dead (zero/`0xFF`) percentage is
  below 99 percent, the odds climb sharply. The cost of trying is one image plus a
  few CPU hours.
- **If software comes up empty.** The only remaining path is a lab with PC-3000
  SSD tooling and an Innogrit IG5216 controller-bypass profile for a raw-NAND read.
  Keep the drive unpowered until then.

---

## Safety rules

1. Never work on the original drive — image first, recover from the image.
2. Never mount the damaged drive read-write; do not run `fstrim` or `ntfsfix` on it.
3. Keep the source powered off between attempts.
4. The destination disk must be separate and at least as large as the source.

---

## Project layout

```
nvme-source-recovery/
+-- README.md
+-- BACKSTORY.md           how the incident happened and why this toolkit exists
+-- LICENSE
+-- nvme_recover.py        recovery engine (MFT + USN + archives + source)
+-- 01_image_drive.sh      read-only ddrescue imaging + controller-state capture
+-- 02_run_recovery.sh     one-command pipeline runner
+-- assets/                logo, mark, and vector icons used by this README
```

---

## License

MIT — provided as-is, for recovering data you are authorized to access
(for example, your own accidentally deleted files). No warranty.
