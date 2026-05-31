# Backstory

How a single automated command erased about 100 GB of source code in a few
seconds — and why this toolkit exists.

---

## The incident

It started, as these things usually do, with an automation that did exactly
what it was told to do.

An IDE agent running with full administrator rights executed a recursive clear
on the root of the `D:` partition. In a handful of seconds it unlinked roughly
**100 GB** of working data: Rust, Kotlin, Python, and Solidity source trees, and
the `.zip` / `.7z` backups that were supposed to be the safety net.

The deletion happened on screen, in real time. The reaction was fast and, as it
turns out, correct: an immediate system restart. The machine reached the Windows
desktop, and the partition came back **empty**. A hard power-cut followed within
minutes, the network was disconnected, and the drive was physically removed and
left unpowered.

Total post-incident uptime: **under five minutes**.

That five minutes is the entire story.

---

## The hardware that makes this hard

| Component | Detail |
| --- | --- |
| Drive | Lexar NM620 512 GB, M.2 NVMe 1.4 |
| Controller | Innogrit IG5216 — **DRAM-less**, uses Host Memory Buffer (HMB) |
| NAND | 3D TLC |
| Filesystem | NTFS on `D:` |
| TRIM | Enabled globally (Windows default) |

On a TRIM-enabled NVMe, deleting a file does more than unlink it. NTFS issues a
**DEALLOCATE** (TRIM) for the freed clusters. The controller updates its
Logical-to-Physical (L2P) mapping to mark those ranges as unmapped, and — because
modern NVMe enforces *deterministic read after TRIM* — any later read of those
logical blocks returns **zeros**, regardless of whether the NAND cells have
physically been erased yet.

In other words: the data may still be sitting in the flash, but the normal read
path is contractually obligated to hand you nothing but zeros.

---

## The first diagnosis: near-zero

The initial research was blunt and discouraging, and it was not wrong about the
hardest part. The industry consensus for TRIM-enabled NVMe is that **logical
recovery is effectively a myth** — once DEALLOCATE is processed, the controller
returns zeros, and the only path to the raw NAND is proprietary controller-bypass
tooling (PC-3000 SSD, chip-off) used by hardware labs.

A second-by-second reconstruction of the drive's internal state explains why:

| Time | What happened inside the drive |
| --- | --- |
| T+0 | NTFS marks MFT records unallocated; clusters freed |
| T+0 – 5s | Windows issues NVMe DEALLOCATE for the freed ranges |
| T+5 – 60s | IG5216 invalidates L2P mappings; trimmed LBAs now read as zero |
| T+1 – 5 min | Desktop idle — prime window for background garbage collection |
| T+5 min | Hard power-cut — GC and any pending erase cycles halt |

Read against that timeline, the prognosis for the bulk data area was honest and
grim: most of those 100 GB of clusters would read back as zeros.

---

## The turning point

But the doom-laden version of the story missed something important.

> TRIM frees the deleted files' **data clusters**. It does **not** deallocate
> the `$MFT` system file itself.

That single distinction reframes the entire problem. The `$MFT` — the Master File
Table that records every file's name, path, size, timestamps, and location — is
not part of the freed data region. Its records for just-deleted files are simply
marked "not in use," not zeroed. Which means:

- **Resident small files survive intact.** NTFS stores the content of small files
  *inside* their MFT record. A large fraction of source files are small enough to
  qualify, so they come back **byte-for-byte, with their original filename and
  path**, even when the data area is all zeros.
- **The `$UsnJrnl` change journal survives.** It holds a timestamped log of every
  create and delete — a name-by-name record of exactly what was lost.
- **Non-resident files leave a map.** Even when a file's body is gone, its MFT
  record still lists the exact clusters it occupied, enabling a *targeted* carve
  instead of a blind one.

The problem stopped being "read raw NAND past the controller" and became "mine the
filesystem metadata that TRIM never touched." That is a software problem — and a
solvable one.

---

## What we built

The insight became an engine. `nvme_recover.py` is read-only and attacks the loss
along five vectors, highest-yield first:

1. **Region analysis** — a zero/entropy map that shows, up front, how much TRIM
   actually wiped and where live data still sits.
2. **`$MFT` mining** — recovers resident files intact; targeted-carves
   non-resident files from their recorded clusters.
3. **`$UsnJrnl` journal** — reconstructs the timestamped delete log by filename.
4. **Archive carving** — ZIP via central-directory reconstruction and per-member
   salvage, 7z via CRC-validated headers, plus gzip streams.
5. **Source carving** — language-aware recovery of raw text into per-language
   buckets, with no filesystem metadata required.

Two read-only shell scripts wrap it: one images the drive safely with `ddrescue`
(kernel write-lock, controller-state capture, checksum), and one runs the whole
recovery pipeline over the image in a single command.

Everything ships with a `selftest` that builds a synthetic NTFS image and proves
each vector end-to-end. It passes.

---

## Lessons

- **On a TRIM-enabled SSD, the moment you see a wrong delete, cut power.** It is
  the single highest-impact action available, because it freezes garbage
  collection. In this case it was done correctly, and it preserved whatever chance
  remained.
- **Never give an automated agent administrator rights and a recursive delete over
  a directory you have not backed up elsewhere.**
- **A backup on the same volume is not a backup.** The `.zip`/`.7z` archives died
  with the source.
- **Metadata outlives data.** When the bytes are gone, the filesystem's own
  bookkeeping is often the last — and best — witness.

---

*This toolkit is the answer to a question nobody wants to ask at 2 a.m.: "the
drive says it's empty — is anything still there?" Sometimes, in the metadata, the
answer is yes.*
