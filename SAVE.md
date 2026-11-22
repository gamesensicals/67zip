# SAVE: 67zip (gamesensicals/67zip)

Saved work for the 67zip project. The project repository `gamesensicals/67zip`
was empty when this started; nothing is published there yet. When the work is
finished **and the user approves**, it moves to `gamesensicals/67zip` branch
`claude/67zip-gui-linux-k401kq` (delete this `SAVE.md` in that final commit).

Scheduled continuations the user asked for: **03:40** and **08:55** Vienna time
(2026-11-22).

## The request

A 7-Zip-like archiver **with a GUI for Linux**, named **67zip**. Decisions made
with the user:

- **Rust**, with **as much of our own code as possible**, **as secure as
  possible**, speed **at least 85% of 7-Zip** (measured, see below).
- GUI toolkit **iced** (pure Rust, draws its own UI) so it looks **the same and
  as nice as possible on every distro**: bundled Inter font, own icon set,
  follows system dark/light mode and accent colour (XDG portal), HiDPI.
- License: MIT OR Apache-2.0 (user may change).

## Speed check done before starting (4-core VM, 7-Zip 23.01, ~100-130 MB corpora)

Safe Rust (no `unsafe` in our code, lzma-rust2 without its `optimization`
feature) vs 7-Zip, same threads and same output size:
7z LZMA2 compress 86% / 95%; 7z extract 105-114% (single block), ~170% (our
multi-block files); zip compress 2.3-2.9x faster (files ~3% larger); zip
extract ~190%; bzip2 compress 175-215%; **bzip2 extract 57%** -> plan: own
multi-core safe bzip2 decoder.

## Plan (stages)

1. Engine `crates/zip67-core`: own zip (read/write, Zip64, UTF-8, AES-256
   WinZip AE-2, ZipCrypto read only), own tar (+gz/bz2/xz/zst/lz), single-file
   streams, safe extraction (cap-std, no escapes, bomb limits), create/update.
2. Own 7z reader/writer: LZMA2 (multi-threaded), LZMA, PPMd, BZip2, Deflate,
   Copy, BCJ filters, AES-256 + encrypted headers.
3. CLI `67z` (7-Zip style commands) + sandboxed worker process (Landlock +
   seccomp); the GUI never parses archives itself.
4. GUI `67zip` (iced): 7-Zip-style file manager, dialogs, theming, icons.
5. Own parallel safe bzip2 decoder, ISO reader, hashes, split volumes, bench.
6. Fuzzing, CI, packaging (desktop entry/MIME, file-manager menus, Flatpak,
   AppImage), README.

## Done

- **Stage 1 engine done** (`crates/zip67-core`, `#![forbid(unsafe_code)]`):
  own zip reader/writer (Zip64, UTF-8, Unix modes, symlinks, AES-256 AE-2
  with HMAC check, ZipCrypto read-only, Deflate/Store/BZip2/LZMA/XZ/Zstd/PPMd
  read), own tar (ustar/PAX/GNU) + gz/bz2/xz/zst/lzma/lz, single-file
  streams, detection, safe extraction via cap-std (no `..`/absolute paths,
  no escaping symlinks, no setuid/devices, bomb limits, overlap-bomb check),
  create/update (atomic temp file + rename), hashes, split/combine.
- Tests: 34 pass (`cargo test -p zip67-core`), incl. real 7-Zip accepting our
  zip/zip-AES/tar.*/gz/bz2/xz/lzma, us reading 7-Zip-made zip (Deflate,
  BZip2, LZMA, PPMd, AES-256, ZipCrypto, Store), tar.gz/bz2/xz, and attack
  tests (zip slip, symlink escape, overlap bomb, fuzzed garbage).
- **Stage 2 (7z) done**: own 7z container reader/writer
  (`formats/sevenz/{header,coders,reader,writer}.rs`): signature + encoded +
  AES-encrypted headers, coder graphs incl. BCJ2, LZMA2 (multi-threaded
  encode and decode), LZMA, PPMd, BZip2, Deflate, Copy, BCJ/ARM64/Delta
  filters, 7zAES (key derivation capped at 2^24 rounds), solid/non-solid,
  updates. 14 tests in `tests/sevenz.rs` pass, both directions against 7-Zip.
- **Stage 3 done**: `crates/zip67-worker` (Landlock + seccomp sandbox,
  JSON-lines protocol, worker loop, client) and `crates/zip67-cli` (binary
  `67z`, 7-Zip style commands a/x/e/l/t/d/rn/u/h/b/i, hidden
  `--worker` and `--sandbox-selftest`). Self-test passes here (kernel 6.18).
- Speed after tuning (LZMA level params = 7-Zip's: nice_len 32 at level 5;
  multi-thread blocks = total/threads clamped to 2-4x dict): 7z compress
  95-100% of 7-Zip speed (text files 2.3% larger, binaries 0.7% larger);
  7z extract ~100%; zip 2-3x faster. Script: `tools/speedcheck.sh`.
- ISO is a stub (`formats/iso.rs`) -> stage 5.

- **Stage 4 (GUI) mostly done**: `crates/zip67-gui` (binary `67zip`, iced
  0.14): toolbar, address bar, places/favourites sidebar, virtual file list
  (sort, multi-select, keyboard), browse into archives (nested read-only),
  open file from archive + "save changes back", context menu, dialogs (add,
  extract, password, overwrite, properties, checksums, benchmark, settings,
  about), progress with pause/cancel/background, toasts, drag-and-drop in,
  Trash support, light/dark + accent (follows system via mundy), bundled
  Inter font, own SVG icons + logo (`resources/67zip.svg`). Tested under
  Xvfb + xdotool (needs `xdotool windowfocus` there: no window manager).

- **Stage 6 done**: README (with screenshots in `docs/screenshots`), MIT +
  Apache licences, `install.sh` (user or --system, --uninstall), desktop
  entry + AppStream + icons (`data/`), Dolphin/Nemo/Nautilus menus, Flatpak
  manifest (`packaging/flatpak`, needs cargo-sources.json), cargo-deb
  metadata (gui crate), GitHub Actions CI (`.github/workflows/ci.yml`),
  fuzz targets (`fuzz/`, cargo +nightly fuzz; corpora in `fuzz/corpus`).
- **Fuzzing found a crash** in the `libbz2-rs-sys` 0.2.7 bzip2 decoder
  (integer underflow in decompress.rs:710, panics with overflow checks).
  Fixed by stage 5's **own bzip2 decoder** (`codecs/bz2.rs`): safe,
  multi-core (scans for block magics, decodes blocks in parallel, strict
  sequential fallback), fast 10-bit Huffman tables. Used for .bz2,
  .tar.bz2, zip and 7z. Speed: ~170% of 7-Zip (4 threads), 1 thread ~65%.
  The bzip2 crate is now only used for compressing (trusted input).
  zip and streams fuzzers: ~1.4M runs each, no crash.

- **ISO 9660 reader done** (Rock Ridge, Joliet, multi-extent, cycle-safe),
  tested against genisoimage images.
- **Second fuzz finding fixed**: endless loop in lzma-rust2 0.25's
  `Lzma2Reader` on LZMA chunks sent before properties. LZMA2 input now goes
  through our `codecs/lzma2.rs` guard (chunk structure validation) and the
  single-thread path uses `Lzma2Stream` with a no-progress check.
- Clean fuzz round after fixes (10 min each): 7z 278k, tar 4.6M, streams
  102k, open_any 62k runs; earlier zip 1.4M. Seeds in `fuzz/seeds/`.
- GUI: dialogs focus their text field; password retry flow verified;
  settings/about verified. `install.sh` verified (install + uninstall).

## Next

Ask the user to approve moving the work to `gamesensicals/67zip`.
Possible polish: nested archive write-back (now read-only), AppImage script,
drag files *out* of the window (iced does not support it yet).

## How to resume

```
git clone https://github.com/gamesensicals/savedata && cd savedata
git checkout claude/67zip-gui-linux-k401kq
cargo test --workspace
```
