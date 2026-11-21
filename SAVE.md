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

## Next

Stage 4: GUI crate `crates/zip67-gui` (binary `67zip`, iced 0.14). It must
run archive work only through `zip67_worker::client::WorkerHandle` spawning
`current_exe --worker`.

## How to resume

```
git clone https://github.com/gamesensicals/savedata && cd savedata
git checkout claude/67zip-gui-linux-k401kq
cargo test --workspace
```
