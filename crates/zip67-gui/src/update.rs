//! Update checks and downloads in the app. The network work runs on
//! background threads; the app polls their channels on its timer. All the
//! checking (signature, hashes, hosts) is in the `zip67-update` crate.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;

use zip67_update::{Check, Client, Install, Manifest, UpdateError, Version};

pub enum UpdateState {
    Idle,
    Checking { manual: bool, rx: Receiver<Result<Check, String>> },
    /// The answer to a check started by hand (shown in the About box).
    Status(String),
    /// A newer, verified release.
    Available { manifest: Manifest },
    Downloading { version: Version, rx: Receiver<Event>, cancel: Arc<AtomicBool>, done: u64, total: u64 },
    /// The AppImage was replaced: restart to use the new version.
    Installed { version: Version, appimage: PathBuf },
    /// A verified package was saved for an installation that can't replace itself.
    Saved { version: Version, file: PathBuf, how: String },
    /// Nothing to download for this installation; how to update instead.
    Manual { version: Version, how: String },
    Failed(String),
}

pub enum Event {
    Progress(u64, u64),
    Installed(PathBuf),
    Saved(PathBuf, String),
    Manual(String),
    Failed(String),
}

pub fn start_check(manual: bool) -> UpdateState {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(Client::new().check(Version::current()).map_err(|e| e.to_string()));
    });
    UpdateState::Checking { manual, rx }
}

pub fn start_download(install: &Install, manifest: &Manifest) -> UpdateState {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let (install, m, stop) = (install.clone(), manifest.clone(), cancel.clone());
    let total = install.package_kind().and_then(|k| manifest.package(&k)).map(|p| p.size).unwrap_or(0);
    std::thread::spawn(move || {
        let ev = download(&install, &m, &tx, &stop);
        let _ = tx.send(ev);
    });
    UpdateState::Downloading { version: manifest.version, rx, cancel, done: 0, total }
}

fn download(install: &Install, m: &Manifest, tx: &Sender<Event>, cancel: &AtomicBool) -> Event {
    let Some(pkg) = install.package_kind().and_then(|k| m.package(&k).cloned()) else {
        return Event::Manual(format!("{} Releases: {}", install.how_to_update(None), zip67_update::RELEASES_PAGE));
    };
    let client = Client::new();
    let progress = |done, total| {
        let _ = tx.send(Event::Progress(done, total));
    };
    // An AppImage downloads next to itself so the new file can be renamed
    // over it. If that folder isn't writable, the file goes to Downloads.
    if let Install::AppImage(target) = install {
        match client.download(&pkg, &zip67_update::download_folder(install), &progress, cancel) {
            Ok(tmp) => {
                return match zip67_update::install_appimage(&tmp, target) {
                    Ok(()) => Event::Installed(target.clone()),
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp);
                        Event::Failed(format!("couldn't replace the AppImage: {e}"))
                    }
                };
            }
            Err(UpdateError::Io(_)) => {}
            Err(e) => return Event::Failed(e.to_string()),
        }
    }
    let dir = zip67_update::downloads_dir();
    let kept = client.download(&pkg, &dir, &progress, cancel).and_then(|tmp| {
        zip67_update::keep_download(&tmp, &dir, pkg.file_name()).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    });
    match kept {
        Ok(path) => {
            let how = install.how_to_update(Some(&path));
            Event::Saved(path, how)
        }
        Err(e) => Event::Failed(e.to_string()),
    }
}

impl UpdateState {
    pub fn busy(&self) -> bool {
        matches!(self, UpdateState::Checking { .. } | UpdateState::Downloading { .. })
    }

    pub fn cancel(&self) {
        if let UpdateState::Downloading { cancel, .. } = self {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Takes what the background threads sent. `skipped` hides a version
    /// the user chose to skip, unless they checked by hand.
    pub fn poll(&mut self, skipped: Option<&str>) {
        match self {
            UpdateState::Checking { manual, rx } => {
                let manual = *manual;
                let next = match rx.try_recv() {
                    Err(TryRecvError::Empty) => return,
                    Err(TryRecvError::Disconnected) => UpdateState::Idle,
                    Ok(Ok(Check::UpToDate(_))) if manual => UpdateState::Status(format!("67zip {} is up to date.", Version::current())),
                    Ok(Ok(Check::Available(m))) if manual || skipped != Some(m.version.to_string().as_str()) => UpdateState::Available { manifest: m },
                    Ok(Err(e)) if manual => UpdateState::Status(format!("Couldn't check for updates: {e}")),
                    Ok(_) => UpdateState::Idle,
                };
                *self = next;
            }
            UpdateState::Downloading { version, rx, done, total, .. } => loop {
                let version = *version;
                match rx.try_recv() {
                    Ok(Event::Progress(d, t)) => {
                        *done = d;
                        *total = t;
                    }
                    Ok(Event::Installed(appimage)) => return *self = UpdateState::Installed { version, appimage },
                    Ok(Event::Saved(file, how)) => return *self = UpdateState::Saved { version, file, how },
                    Ok(Event::Manual(how)) => return *self = UpdateState::Manual { version, how },
                    Ok(Event::Failed(e)) => return *self = UpdateState::Failed(e),
                    Err(TryRecvError::Empty) => return,
                    Err(TryRecvError::Disconnected) => return *self = UpdateState::Failed("the download stopped".into()),
                }
            },
            _ => {}
        }
    }
}

/// Debug builds only: `ZIP67_UPDATE_DEMO=available|downloading|installed|saved`
/// shows that state with made-up data, for screenshots. No network.
#[cfg(debug_assertions)]
pub fn demo(stage: &str) -> UpdateState {
    let v = Version::current();
    let version = Version(v.0, v.1, v.2 + 1);
    let manifest = Manifest {
        version,
        date: "2026-11-30".into(),
        notes: "Faster RAR extraction.\nFixes a crash with some damaged zip files.".into(),
        packages: Vec::new(),
    };
    match stage {
        "downloading" => {
            let (tx, rx) = channel();
            let _ = tx.send(Event::Progress(27 << 20, 41 << 20));
            std::mem::forget(tx);
            UpdateState::Downloading { version, rx, cancel: Arc::default(), done: 0, total: 41 << 20 }
        }
        "installed" => UpdateState::Installed { version, appimage: PathBuf::from("/home/user/Applications/67zip-x86_64.AppImage") },
        "saved" => {
            let file = PathBuf::from(format!("/home/user/Downloads/67zip-{version}-x86_64.AppImage"));
            let how = Install::Source.how_to_update(Some(&file));
            UpdateState::Saved { version, file, how }
        }
        _ => UpdateState::Available { manifest },
    }
}
