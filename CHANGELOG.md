# Changelog

## 0.1.1 — 2026-11-22

### New

- **UDF disc images** (ISO/IEC 13346, the file system of DVDs, Blu-rays and
  many `.iso` files), revisions 1.02 to 2.60. This includes Blu-ray's
  metadata partition, sparable DVD-RW volumes, long Unicode names, files
  over 4 GB, sparse files, links, times and permissions. Images that hold
  both UDF and ISO 9660 open with UDF; if their UDF part is damaged, the
  ISO 9660 part is shown with a note. Not supported: packet-written
  CD-R/DVD-R discs with a virtual allocation table.
- **RAR archives** (reading): RAR5 and RAR 2.0–4.x, solid, multi-volume
  and self-extracting archives, AES-256 / AES-128 encryption including
  encrypted names, BLAKE2sp checksums, links, comments and file versions.
- **ISO 9660 images** with Rock Ridge and Joliet.
- **Split archives** open from any part in all common naming schemes, and
  "Split into" creates `.001` parts.
- **Optional secure deletion**: "Securely" (or `67z a -sshred`) overwrites
  the original files with random data before deleting them, and decrypted
  temporary copies of files opened from an archive are wiped when 67zip
  closes. A notice (with "Don't warn me again") says when those copies
  had to go to a disk instead of memory.
- Archives inside archives can be changed; the outer archive is updated.
- Our own multi-core bzip2 decoder.
- An AppImage build in CI.
- **Update checks**, once a day (can be turned off) and on demand in the
  About box or with `67z update --check`. Releases are signed with the
  67zip release key (minisign, key ID 269FF0C6C87BEF0F); an update is used
  only if its signature and SHA-256 hash match, never for an older
  version. AppImages update themselves after asking; `.deb` and
  source installs get the verified package in Downloads; Flatpak is left
  to Flathub. The check sends nothing but the version number.
- Releases are built, signed and published by a GitHub workflow.

### Changed

- **Passwords are easy to find.** The Add dialog has an "Encryption:
  Protect with a password" checkbox for 7z and zip (AES-256), shown greyed
  out with the reason for formats without encryption. Ticking it shows the
  password fields with the cursor already in place.
- New "Add to zip with a password…" in the right-click menu, and "Compress
  to .zip with a password…" in Dolphin, Nemo and Nautilus
  (`67zip --add-with-password FILES...`).
- `67z a -mem=ZipCrypto` now says that AES-256 is used instead (ZipCrypto
  is easily broken and 67zip never creates it); an unknown `-mem` value is
  an error.
- Relicensed under the MIT license.
- New screenshots.

### Security

- Hardening after a review and a penetration test: stricter sandbox rules
  (no `TIOCSTI`, no signals to other processes, no namespaces, no x32
  system calls), a staging folder for everything the worker writes,
  escaped control characters in names and messages, permissions limited by
  the umask, a free-space check against archives that lie about their
  size, overflow checks for archive sizes, and files opened from archives
  lose their execute permission.
- The RAR, UDF and other parsers were fuzzed; every crash found was fixed
  and kept as a regression test.

## 0.1.0 — 2026-11-22

First version: the 67zip app and the `67z` command line tool, with our own
7z, zip, tar and gz/bz2/xz/zst/lzma/lz engine in safe Rust, a sandboxed
worker process (Landlock and seccomp), multi-threaded LZMA2, AES-256
encryption, a benchmark, checksums, desktop integration and packaging.
