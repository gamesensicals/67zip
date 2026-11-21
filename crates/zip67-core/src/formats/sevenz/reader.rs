//! 7z reader: signature header, (encoded / encrypted) headers, solid
//! folders decoded once in order, CRC checks for every file.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use super::coders::{folder_methods, folder_reader, DecodeCtx, SharedSrc};
use super::header::{read_encoded_header_info, read_header, Header, StreamsInfo, SIGNATURE};
use crate::archive::{ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::detect::ArchiveType;
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::io::{CrcCheck, Progressed, ReadSeek, TakeExact};
use crate::limits::Limits;
use crate::password::Password;
use crate::progress::Progress;
use crate::util::{filetime_to_unix, normalize_path};

type Keys = Mutex<HashMap<(Vec<u8>, u8), zeroize::Zeroizing<[u8; 32]>>>;

pub struct SevenZReader {
    src: SharedSrc,
    size: u64,
    streams: StreamsInfo,
    pack_offsets: Vec<u64>,
    entries: Vec<Entry>,
    /// Per entry: (folder, substream) when the entry has data.
    places: Vec<Option<(usize, usize)>>,
    password: Option<Password>,
    limits: Limits,
    threads: usize,
    keys: Keys,
    info: ArchiveInfo,
}

fn pack_offsets(s: &StreamsInfo, size: u64) -> Result<Vec<u64>> {
    let mut off = 32u64.checked_add(s.pack_pos).ok_or_else(|| Error::corrupt("7z pack position"))?;
    let mut v = Vec::with_capacity(s.pack_sizes.len());
    for &p in &s.pack_sizes {
        v.push(off);
        off = off.checked_add(p).ok_or_else(|| Error::corrupt("7z pack sizes"))?;
        if off > size {
            return Err(Error::corrupt("7z data runs past the end of the file (incomplete download?)"));
        }
    }
    Ok(v)
}

fn wrong_password_if_encrypted(e: Error, encrypted: bool) -> Error {
    if encrypted && matches!(e, Error::Corrupt(_) | Error::Checksum(_) | Error::Io(_)) {
        Error::WrongPassword
    } else {
        e
    }
}

impl SevenZReader {
    pub fn open(mut src: Box<dyn ReadSeek>, size: u64, opts: &OpenOptions) -> Result<Self> {
        let limits = opts.limits.clone();
        src.seek(SeekFrom::Start(0))?;
        let mut sig = [0u8; 32];
        src.read_exact(&mut sig)?;
        if sig[..6] != SIGNATURE {
            return Err(Error::UnsupportedFormat);
        }
        if sig[6] != 0 {
            return Err(Error::unsupported(format!("7z format version {}.{}", sig[6], sig[7])));
        }
        let start_crc = u32::from_le_bytes(sig[8..12].try_into().unwrap_or([0; 4]));
        if crate::crc::crc32(&sig[12..32]) != start_crc {
            return Err(Error::corrupt("7z start header checksum mismatch"));
        }
        let next_off = u64::from_le_bytes(sig[12..20].try_into().unwrap_or([0; 8]));
        let next_size = u64::from_le_bytes(sig[20..28].try_into().unwrap_or([0; 8]));
        let next_crc = u32::from_le_bytes(sig[28..32].try_into().unwrap_or([0; 4]));
        let threads = if opts.threads == 0 { crate::util::default_threads() } else { opts.threads };
        let shared: SharedSrc = Arc::new(Mutex::new(src));
        let keys: Keys = Mutex::new(HashMap::new());

        let mut info = ArchiveInfo { format: "7z".into(), physical_size: size, volumes: 1, headers_size: Some(next_size), ..Default::default() };
        if next_size == 0 {
            return Ok(SevenZReader {
                src: shared,
                size,
                streams: StreamsInfo::default(),
                pack_offsets: Vec::new(),
                entries: Vec::new(),
                places: Vec::new(),
                password: opts.password.clone(),
                limits,
                threads,
                keys,
                info,
            });
        }
        let hpos = 32u64.checked_add(next_off).ok_or_else(|| Error::corrupt("7z header offset"))?;
        if next_size > limits.max_header_size || hpos.checked_add(next_size).is_none_or(|e| e > size) {
            return Err(Error::corrupt("7z header lies outside the file (incomplete download?)"));
        }
        let mut data = vec![0u8; next_size as usize];
        {
            let mut s = shared.lock().map_err(|_| Error::invalid("lock"))?;
            s.seek(SeekFrom::Start(hpos))?;
            s.read_exact(&mut data)?;
        }
        if crate::crc::crc32(&data) != next_crc {
            return Err(Error::corrupt("7z header checksum mismatch"));
        }

        let mut header: Option<Header> = None;
        for _ in 0..4 {
            match data.first() {
                Some(&super::header::id::HEADER) => {
                    header = Some(read_header(&data, limits.max_entries)?);
                    break;
                }
                Some(&super::header::id::ENCODED_HEADER) => {
                    let si = read_encoded_header_info(&data)?;
                    let folder = si.folders.first().ok_or_else(|| Error::corrupt("7z encoded header without data"))?;
                    let encrypted = folder.is_encrypted();
                    if encrypted {
                        info.encrypted_headers = true;
                        if opts.password.is_none() {
                            return Err(Error::PasswordRequired);
                        }
                    }
                    let unpack = folder.unpack_size();
                    if unpack > limits.max_header_size {
                        return Err(Error::limit("7z header too large"));
                    }
                    let offsets = pack_offsets(&si, size)?;
                    let ctx = DecodeCtx {
                        src: &shared,
                        pack_offsets: &offsets,
                        pack_sizes: &si.pack_sizes,
                        password: opts.password.as_ref(),
                        limits: &limits,
                        threads: 1,
                        keys: &keys,
                    };
                    let decoded = (|| -> Result<Vec<u8>> {
                        let mut r = folder_reader(folder, &ctx)?;
                        let mut out = Vec::with_capacity(unpack as usize);
                        r.read_to_end(&mut out)?;
                        if let Some(c) = folder.crc {
                            if crate::crc::crc32(&out) != c {
                                return Err(Error::Checksum("7z header".into()));
                            }
                        }
                        Ok(out)
                    })()
                    .map_err(|e| wrong_password_if_encrypted(e, encrypted))?;
                    if encrypted && decoded.first() != Some(&super::header::id::HEADER) && decoded.first() != Some(&super::header::id::ENCODED_HEADER) {
                        return Err(Error::WrongPassword);
                    }
                    data = decoded;
                }
                _ => return Err(Error::corrupt("7z header has an unknown type")),
            }
        }
        let header = header.ok_or_else(|| Error::corrupt("7z header nesting too deep"))?;
        let streams = header.streams;
        let offsets = pack_offsets(&streams, size)?;

        // Assign files with data to folder substreams in order.
        let mut slots: Vec<(usize, usize)> = Vec::new();
        for (fi, f) in streams.folders.iter().enumerate() {
            let n = streams.sub_sizes.get(fi).map(|v| v.len()).unwrap_or(0);
            if f.num_substreams as usize != n {
                return Err(Error::corrupt("7z substream count mismatch"));
            }
            for si in 0..n {
                slots.push((fi, si));
            }
        }
        let mut slot_iter = slots.into_iter();
        let mut entries = Vec::with_capacity(header.files.len());
        let mut places = Vec::with_capacity(header.files.len());
        for rec in &header.files {
            let place = if rec.has_stream { Some(slot_iter.next().ok_or_else(|| Error::corrupt("7z: more files than data streams"))?) } else { None };
            if rec.is_anti {
                continue;
            }
            let unix = rec.attrib.filter(|a| a & 0x8000 != 0).map(|a| a >> 16);
            let mut name = rec.name.clone();
            if unix.is_none() {
                name = name.replace('\\', "/");
            }
            if name.len() > limits.max_path_len {
                return Err(Error::limit("entry name too long"));
            }
            let (path, unsafe_path) = normalize_path(&name);
            let kind = if rec.is_dir {
                EntryKind::Dir
            } else if unix.is_some_and(|m| m & 0o170000 == 0o120000) {
                EntryKind::Symlink
            } else if unix.is_some_and(|m| m & 0o170000 == 0o040000) && !rec.has_stream {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let mut e = Entry::new(entries.len(), path, kind);
            e.unsafe_path = unsafe_path;
            if let Some(ft) = rec.mtime {
                let (s, n) = filetime_to_unix(ft);
                e.mtime = Some(s);
                e.mtime_nanos = n;
            }
            e.mode = unix.map(|m| m & 0o7777).or_else(|| rec.attrib.map(|a| if a & 1 != 0 { 0o444 } else if kind == EntryKind::Dir { 0o755 } else { 0o644 }));
            if let Some((fi, si)) = place {
                let f = &streams.folders[fi];
                e.size = streams.sub_sizes[fi][si];
                e.crc32 = streams.sub_crcs.get(fi).and_then(|v| v.get(si)).copied().flatten();
                e.encrypted = f.is_encrypted();
                e.method = Some(folder_methods(f));
                e.block = Some(fi as u32);
                if f.num_substreams == 1 {
                    e.packed_size = Some((0..f.packed.len()).map(|k| streams.pack_sizes.get(f.first_pack + k).copied().unwrap_or(0)).sum());
                }
            }
            entries.push(e);
            places.push(place);
        }

        let mut methods: Vec<String> = streams.folders.iter().map(folder_methods).collect();
        methods.sort();
        methods.dedup();
        info.methods = methods;
        info.solid = streams.folders.iter().any(|f| f.num_substreams > 1);
        info.blocks = streams.folders.len() as u64;
        info.encrypted_data = streams.folders.iter().any(|f| f.is_encrypted());

        Ok(SevenZReader {
            src: shared,
            size,
            streams,
            pack_offsets: offsets,
            entries,
            places,
            password: opts.password.clone(),
            limits,
            threads,
            keys,
            info,
        })
    }
}

impl ArchiveReader for SevenZReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::SEVEN_Z
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        self.info.clone()
    }

    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let _ = self.size;
        // Entries without data first (folders, empty files).
        for (i, e) in self.entries.iter().enumerate() {
            if self.places[i].is_some() || !selected(e) {
                continue;
            }
            progress.check()?;
            match e.kind {
                EntryKind::Dir => visitor.dir(e)?,
                EntryKind::Symlink => {}
                _ => {
                    let mut empty: &[u8] = &[];
                    if let Err(err) = visitor.file(e, &mut empty) {
                        if matches!(err, Error::Cancelled) {
                            return Err(err);
                        }
                        visitor.entry_error(e, err)?;
                    }
                }
            }
            progress.file_done();
        }
        // Then folder by folder, each decoded once from its start.
        let mut by_folder: Vec<Vec<(usize, usize)>> = vec![Vec::new(); self.streams.folders.len()];
        for (i, p) in self.places.iter().enumerate() {
            if let Some((fi, si)) = *p {
                by_folder[fi].push((si, i));
            }
        }
        for (fi, mut members) in by_folder.into_iter().enumerate() {
            if !members.iter().any(|&(_, i)| selected(&self.entries[i])) {
                continue;
            }
            members.sort();
            let folder = &self.streams.folders[fi];
            let encrypted = folder.is_encrypted();
            if encrypted && self.password.is_none() {
                for &(_, i) in &members {
                    if selected(&self.entries[i]) {
                        visitor.entry_error(&self.entries[i], Error::PasswordRequired)?;
                    }
                }
                continue;
            }
            let ctx = DecodeCtx {
                src: &self.src,
                pack_offsets: &self.pack_offsets,
                pack_sizes: &self.streams.pack_sizes,
                password: self.password.as_ref(),
                limits: &self.limits,
                threads: self.threads,
                keys: &self.keys,
            };
            let mut stream = match folder_reader(folder, &ctx) {
                Ok(s) => s,
                Err(e) => {
                    let e = wrong_password_if_encrypted(e, encrypted);
                    for &(_, i) in &members {
                        if selected(&self.entries[i]) {
                            visitor.entry_error(&self.entries[i], clone_err(&e))?;
                        }
                    }
                    continue;
                }
            };
            let mut broken: Option<Error> = None;
            let mut next_sub = 0usize;
            for &(si, i) in &members {
                progress.check()?;
                let entry = &self.entries[i];
                if let Some(e) = &broken {
                    if selected(entry) {
                        visitor.entry_error(entry, clone_err(e))?;
                    }
                    continue;
                }
                // Substreams always appear in order; skip any without an entry (anti items).
                while next_sub < si {
                    let sz = self.streams.sub_sizes[fi][next_sub];
                    if let Err(e) = crate::io::drain(&mut (&mut stream).take(sz)) {
                        broken = Some(wrong_password_if_encrypted(e.into(), encrypted));
                        break;
                    }
                    next_sub += 1;
                }
                if broken.is_some() {
                    if selected(entry) {
                        visitor.entry_error(entry, clone_err(broken.as_ref().unwrap_or(&Error::Cancelled)))?;
                    }
                    continue;
                }
                next_sub = si + 1;
                let size = self.streams.sub_sizes[fi][si];
                let part = TakeExact::new(&mut stream, size);
                let mut checked = CrcCheck::new(part, entry.crc32, &entry.path);
                let res: Result<()> = if !selected(entry) {
                    crate::io::drain(&mut checked).map(|_| ()).map_err(Error::from)
                } else {
                    progress.set_current(&entry.path);
                    let r = if entry.kind == EntryKind::Symlink {
                        let mut t = Vec::new();
                        match (&mut checked).take(4097).read_to_end(&mut t) {
                            Ok(_) if t.len() > 4096 => Err(Error::corrupt("symlink target too long")),
                            Ok(_) => visitor.symlink(entry, &String::from_utf8_lossy(&t)),
                            Err(e) => Err(e.into()),
                        }
                    } else {
                        let mut p = Progressed::new(&mut checked, progress);
                        visitor.file(entry, &mut p)
                    };
                    // Keep the solid stream aligned whatever the visitor did.
                    let drained = crate::io::drain(&mut checked).map(|_| ()).map_err(Error::from);
                    r.and(drained)
                };
                match res {
                    Ok(()) => {
                        if selected(entry) {
                            progress.file_done();
                        }
                    }
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(e @ Error::Checksum(_)) => {
                        let e = wrong_password_if_encrypted(e, encrypted);
                        if selected(entry) {
                            visitor.entry_error(entry, e)?;
                        }
                    }
                    Err(e @ (Error::UnsafePath(_) | Error::InvalidInput(_))) => visitor.entry_error(entry, e)?,
                    Err(e @ Error::LimitExceeded(_)) => return Err(e),
                    Err(e) => {
                        // Decoder failure: the rest of this folder is lost.
                        let e = wrong_password_if_encrypted(e, encrypted);
                        if selected(entry) {
                            visitor.entry_error(entry, clone_err(&e))?;
                        }
                        broken = Some(e);
                    }
                }
            }
        }
        Ok(())
    }
}

fn clone_err(e: &Error) -> Error {
    match e {
        Error::WrongPassword => Error::WrongPassword,
        Error::PasswordRequired => Error::PasswordRequired,
        Error::Checksum(s) => Error::Checksum(s.clone()),
        Error::Unsupported(s) => Error::Unsupported(s.clone()),
        Error::LimitExceeded(s) => Error::LimitExceeded(s.clone()),
        other => Error::Corrupt(other.to_string()),
    }
}
