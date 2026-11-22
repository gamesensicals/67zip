# 67zip

A fast, secure archive manager for Linux, in the spirit of 7-Zip, with a
modern interface that looks the same on every distribution.

![67zip browsing a 7z archive](docs/screenshots/archive-light.png)

- **Own archive engine in safe Rust.** The 7z, zip and tar formats, gzip
  framing, the multi-core bzip2 decoder, safe extraction and the sandbox
  are written for 67zip. `unsafe`
  code is forbidden in every 67zip crate. Compression algorithms and
  encryption come from small, widely used pure-Rust libraries; encryption
  is never home-made.
- **Sandboxed.** Archives are opened in a separate worker process that locks
  itself down with Landlock (it can reach only the files of the current
  operation) and seccomp (no network, cannot start programs). The window
  you see never parses archive data.
- **About as fast as 7-Zip.** Multi-threaded LZMA2, measured against 7-Zip
  23.01 on the same machine. See [Speed](#speed).
- **Looks right everywhere.** Its own icon set and bundled Inter font.
  Light and dark themes follow your desktop, including its accent colour.

## Formats

| Format | Open / extract | Create / change | Notes |
|---|---|---|---|
| 7z | yes | yes | LZMA2 (multi-threaded), LZMA, PPMd, BZip2, Deflate, Copy; BCJ, BCJ2, ARM64, Delta filters; AES-256, encrypted file names |
| zip | yes | yes | Deflate, BZip2, LZMA, XZ, Zstd, Store, PPMd (read); Zip64; UTF-8 names; AES-256 (read and write); old ZipCrypto (read only) |
| tar | yes | yes | ustar, PAX, GNU long names; plain or with gz, bz2, xz, zst, lz, lzma |
| gz, bz2, xz, zst, lzma, lz | yes | yes | single files |
| `.001` split archives | yes | yes | any format; create with "Split into" or `-v100m` |
| iso | planned | no | |

## Install

Building needs [Rust](https://rustup.rs) 1.88 or newer.

```sh
git clone https://github.com/gamesensicals/67zip
cd 67zip
./install.sh            # installs for your user into ~/.local
./install.sh --system   # or for everyone into /usr/local (run as root)
```

The script installs:
- `67zip` (the app) and `67z` (the command line tool);
- a menu entry, the icon, and "Open with" for archive files;
- "Extract here" and "Add to archive" menus for Dolphin, Nemo and Nautilus.

Remove everything with `./install.sh --uninstall`.

Packaging files are included for a `.deb` (`cargo deb -p zip67-gui`) and for
Flatpak (`packaging/flatpak/`).

On distributions without a desktop, the app needs `libxkbcommon-x11` (or
Wayland) and working OpenGL or Vulkan drivers, as any desktop provides.

## Using the app

![Add to archive dialog in dark mode](docs/screenshots/add-dark.png)

- **Moving around:** double-click a folder or archive to open it. Backspace
  goes up a level. An archive opens like a folder. Opening a file inside it
  starts your usual app for that file. If you change and save the file,
  67zip offers to put the new version back into the archive.
- **Toolbar:** Add, Extract, Test, Copy, Move, Delete, Info, New folder,
  Checksum, Benchmark.
- **Right-click** for Extract here, Extract to "name/", Add to "name.7z",
  and more.
- **Drag files onto the window.** In a folder, this opens or compresses
  them; inside an archive, it adds them.
- **Keys:**
  - Enter opens; Alt+Enter shows properties.
  - F2 renames, F5 copies, F6 moves, F7 creates a folder.
  - Del deletes; Ctrl+A selects all.
  - Ctrl+H shows hidden files; Ctrl+L jumps to the address bar.
  - F9 toggles the sidebar.
- **Deleting** on disk moves items to the desktop Trash, which you can turn
  off in Settings.

## Command line: `67z`

`67z` follows 7-Zip's `7z` syntax:

```sh
67z a photos.7z ~/Pictures            # create or add (7z by default)
67z a -tzip -p backup.zip docs/       # zip with AES-256, asks for the password
67z a -mx9 -mhe=on -psecret x.7z dir  # ultra, encrypted file names
67z a -ttar.zst code.tar.zst src/
67z l archive.7z                      # list (-slt for details)
67z t archive.zip                     # test
67z x archive.7z -o/tmp/out           # extract with folders
67z e archive.7z -o/tmp/flat          # extract without folders
67z d archive.7z old/file.txt         # delete inside an archive
67z rn archive.7z a.txt b.txt         # rename inside an archive
67z h -scrcSHA256 file.iso            # checksums (CRC32, CRC64, SHA-1/256/512, BLAKE3, MD5)
67z b                                 # benchmark
```

Run `67z --help` for all switches. Exit codes match 7-Zip: 0 means OK,
1 a warning, 2 an error, 7 a bad command line, and 255 that you stopped it.

## Security

What a malicious archive cannot do in 67zip:

- **Write outside the destination folder.** `../` paths and absolute paths
  are refused. All writes go through a directory handle
  ([cap-std](https://github.com/bytecodealliance/cap-std)) that resolves
  paths only beneath the destination, so even symlink races cannot redirect
  them.
- **Plant escaping links.** Symlinks whose target would leave the
  destination are not created. Device files, FIFOs and setuid/setgid bits
  are never created.
- **Exhaust disk or memory.** Decompression-bomb limits cover total size,
  expansion ratio, dictionary and model memory, header size and entry
  count. Overlapping zip entries (the "non-recursive zip bomb") are
  rejected.
- **Pass tampered data off as fine.** Every CRC is checked. Zip AES data is
  checked with its HMAC before extraction counts as successful. Partly
  written files are removed when a check fails.
- **Disguise a file name.** Control characters and invisible text-direction
  characters are shown as `\u{…}` codes and flagged, because names like
  `invoice\u{202e}fdp.exe` are used to fake file types.
- **Escape the worker.** Archive parsing runs in a process restricted by
  Landlock and seccomp. Try `67z --sandbox-selftest /tmp/somedir` to see
  the checks pass on your kernel (Landlock needs Linux 5.13 or newer).

Other protections:

- Passwords are wiped from memory after use and are never stored.
- Archives are changed by writing a new temporary file and renaming it
  over the original in one step, so a failure never leaves half an archive.
- Release builds check every integer operation for overflow.
- `fuzz/` holds fuzz targets for every parser, run in CI.

Limits of the formats, not of 67zip:

- 7z encryption (AES-256-CBC) cannot detect deliberate modification of the
  encrypted data; zip AES can.
- Old ZipCrypto zip encryption is broken, so 67zip only reads it.

## Speed

These numbers were measured on a 4-core cloud VM against 7-Zip 23.01, with
the same threads and default level, on about 100–130 MB of text and
binaries. Above 100% means 67zip was faster. Repeat the check on your own
files with `tools/speedcheck.sh`.

| Task | 67zip vs 7-Zip |
|---|---|
| 7z compress (text, binaries) | 95–100% speed, files 0.7–2.3% larger |
| 7z extract (any 7z file) | about 100% |
| 7z extract (files made by 67zip) | about 170% |
| zip compress | 2–3× faster, files ~3% larger |
| zip extract | about 190% |
| bzip2 compress | about 200% |
| bzip2 extract | about 170% (own multi-core decoder) |

## Project layout

| Path | What it is |
|---|---|
| `crates/zip67-core` | the archive engine (formats, extraction, hashing) |
| `crates/zip67-worker` | the sandbox, the worker process and its protocol |
| `crates/zip67-cli` | the `67z` command line tool |
| `crates/zip67-gui` | the `67zip` app (built with [iced](https://iced.rs)) |
| `fuzz/` | fuzz targets (`cargo +nightly fuzz run sevenz`) |
| `data/`, `packaging/` | desktop integration and packages |

Run the tests with `cargo test --workspace`. Installing `7zip` makes the
compatibility tests run against real 7-Zip as well.

## License

67zip is licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. The bundled Inter font is
under the SIL Open Font License (`crates/zip67-gui/resources/fonts`).
