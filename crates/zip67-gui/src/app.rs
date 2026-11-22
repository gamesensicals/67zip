//! Application state and behaviour. All archive work happens in sandboxed
//! worker processes; this process only lists folders on disk and draws.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::keyboard::{self, Key, Modifiers, key::Named};
use iced::widget::scrollable::{AbsoluteOffset, Viewport};
use iced::{Color, Event, Point, Subscription, Task, Theme, event, window};

use zip67_core::Entry;
use zip67_core::archive::ArchiveInfo;
use zip67_core::extract::{Answer, ExtractOptions, Overwrite, PathMode, Selection};
use zip67_core::hash::HashKind;
use zip67_core::progress::Snapshot;
use zip67_worker::client::WorkerHandle;
use zip67_worker::protocol::{
    ChangesSpec, CreateSpec, Event as WEvent, FailKind, Question, Reply, Request,
};
use zip67_worker::sandbox::SandboxStatus;

use crate::forms::*;
use crate::listing::{self, Row, SortKey, Tree};
use crate::platform;
use crate::settings::{Settings, ThemeChoice};
use crate::style;

pub const ROW_H: f32 = 30.0;
pub const LIST_ID: &str = "file-list";
/// The password field of the Add dialog.
pub const ADD_PASSWORD_ID: &str = "add-password";

/// What to do right after start (from the command line / file manager).
#[derive(Clone, Debug, Default)]
pub struct Launch {
    pub path: Option<PathBuf>,
    pub add: Vec<PathBuf>,
    /// `--add-with-password`: the Add dialog opens set to zip with a password.
    pub add_protected: bool,
    pub extract: Option<(PathBuf, ExtractHow)>,
}

#[derive(Clone, Copy, Debug)]
pub enum ExtractHow {
    Ask,
    Here,
    ToFolder,
}

impl Launch {
    pub fn from_args(args: &[String]) -> Launch {
        let mut l = Launch::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--add" => l.add.extend(it.by_ref().map(PathBuf::from)),
                "--add-with-password" => {
                    l.add_protected = true;
                    l.add.extend(it.by_ref().map(PathBuf::from));
                }
                "--extract" => l.extract = it.next().map(|p| (PathBuf::from(p), ExtractHow::Ask)),
                "--extract-here" => {
                    l.extract = it.next().map(|p| (PathBuf::from(p), ExtractHow::Here))
                }
                "--extract-to-folder" => {
                    l.extract = it.next().map(|p| (PathBuf::from(p), ExtractHow::ToFolder))
                }
                p if !p.starts_with("--") => l.path = Some(PathBuf::from(p)),
                _ => {}
            }
        }
        l
    }
}

#[derive(Debug)]
pub struct OpenArchive {
    /// Real file given to workers (a temp copy for nested archives).
    pub file: PathBuf,
    /// Shown in the address bar, e.g. `/home/me/a.zip/inner.7z`.
    pub display: String,
    pub archive_type: String,
    pub entries: Vec<Entry>,
    pub info: ArchiveInfo,
    pub tree: Tree,
    pub password: Option<String>,
    /// Folder on disk that holds the outermost archive.
    pub host_dir: PathBuf,
    pub nested: bool,
    /// For a nested archive: the folder inside its parent archive.
    pub inner_dir: String,
}

#[derive(Debug)]
pub enum Location {
    Dir(PathBuf),
    Archive {
        stack: Vec<OpenArchive>,
        folder: String,
    },
}

#[derive(Clone, Debug)]
pub enum Purpose {
    Open {
        file: PathBuf,
        display: String,
        host_dir: PathBuf,
        nested: bool,
        folder: String,
        password: Option<String>,
        inner_dir: String,
    },
    /// Re-read an archive that is already open, keeping the view.
    Refresh {
        file: PathBuf,
    },
    Extract {
        dest: PathBuf,
        then: After,
    },
    Test,
    Changed {
        archive: PathBuf,
        folder: String,
    },
    Hash(Vec<HashKind>),
    Bench,
}

#[derive(Clone, Debug)]
pub enum After {
    Report,
    OpenFile {
        path: PathBuf,
        folder: String,
        archive: PathBuf,
        password: Option<String>,
        nested_display: String,
        host_dir: PathBuf,
    },
}

pub struct Job {
    pub handle: WorkerHandle,
    pub request: Request,
    pub purpose: Purpose,
    pub title: String,
    pub snap: Snapshot,
    pub started: Instant,
    pub paused: bool,
    pub background: bool,
    pub question: Option<Question>,
}

#[derive(Clone, Debug)]
pub struct Watch {
    pub temp: PathBuf,
    pub mtime: Option<std::time::SystemTime>,
    pub archive: PathBuf,
    pub folder: String,
    pub password: Option<String>,
}

pub struct ContextMenu {
    pub at: Point,
    pub items: Vec<(String, Message, bool)>,
}

pub struct App {
    pub settings: Settings,
    pub system_dark: bool,
    pub system_accent: Option<Color>,
    pub location: Location,
    pub rows: Vec<Row>,
    pub selected: BTreeSet<usize>,
    pub anchor: Option<usize>,
    pub focus: Option<usize>,
    pub sort: (SortKey, bool),
    pub address: String,
    pub scroll_y: f32,
    pub view_h: f32,
    pub modifiers: Modifiers,
    pub cursor: Point,
    pub menu: Option<ContextMenu>,
    pub modal: Option<Modal>,
    pub job: Option<Job>,
    pub fs_job: Option<(String, std::sync::mpsc::Receiver<Result<(), String>>)>,
    pub queue: Vec<(Request, Purpose, String)>,
    pub toast: Option<(String, Instant, bool)>,
    pub temp_base: PathBuf,
    /// Told the user once that decrypted temporary copies are on a disk.
    pub warned_temp_on_disk: bool,
    pub watches: Vec<Watch>,
    pub sandbox: Option<SandboxStatus>,
    pub exe: PathBuf,
    pub places: Vec<(String, PathBuf, crate::icons::Icon)>,
    pub hover_drop: bool,
}

#[derive(Clone, Debug)]
pub enum Message {
    // navigation
    Up,
    Refresh,
    GoTo(PathBuf),
    AddressChanged(String),
    AddressSubmit,
    RowClick(usize),
    RowDouble(usize),
    RowRight(usize),
    BackgroundRight,
    Sort(SortKey),
    Scrolled(Viewport),
    Key(Key, Modifiers),
    Modifiers(Modifiers),
    Cursor(Point),
    Dropped(PathBuf),
    DropHover(bool),
    ToggleSidebar,
    AddFavorite,
    RemoveFavorite(PathBuf),
    // actions
    Add,
    AddTo(&'static str),
    /// Opens the Add dialog set to zip with "Protect with a password" ticked.
    AddWithPassword,
    Extract,
    ExtractHere,
    ExtractToFolder,
    Test,
    CopyTo,
    MoveTo,
    Delete,
    Rename,
    NewFolder,
    Info,
    OpenSelected,
    OpenInside,
    OpenOutside,
    Hash(Option<HashKind>),
    Benchmark,
    RunBenchmark,
    OpenSettings,
    About,
    CloseMenu,
    ShowMenu,
    CloseModal,
    CopyText(String),
    // forms
    AddArchive(String),
    AddFormat(Format),
    AddLevel(Level),
    AddMethod(MethodChoice),
    AddProtect(bool),
    AddPassword(String),
    AddPassword2(String),
    AddShowPassword(bool),
    AddEncryptNames(bool),
    AddSolid(bool),
    AddVolume(Volume),
    AddDeleteAfter(bool),
    AddShred(bool),
    AddExclude(String),
    AddBrowse,
    AddBrowsed(Option<PathBuf>),
    AddPicked(Option<Vec<PathBuf>>),
    AddOk,
    ExDest(String),
    ExSubfolder(bool),
    ExPathMode(PathChoice),
    ExOverwrite(OverwriteChoice),
    ExPassword(String),
    ExShowPassword(bool),
    ExBrowse,
    ExBrowsed(Option<PathBuf>),
    ExOk,
    PwInput(String),
    PwShow(bool),
    PwOk,
    Answer(Answer),
    ConfirmOk,
    InputChanged(String),
    InputOk,
    // settings
    SetTheme(ThemeChoice),
    SetAccent(Option<String>),
    SetShowHidden(bool),
    SetConfirmDelete(bool),
    SetUseTrash(bool),
    SetWarnTempOnDisk(bool),
    TempNoticeDontWarn(bool),
    TempNoticeOk,
    SetDefaultFormat(Format),
    SetDefaultLevel(Level),
    SetScale(Choice<u32>),
    // jobs and system
    Tick,
    WatchTick,
    JobPause,
    JobCancel,
    JobBackground(bool),
    SystemDark(bool),
    SystemAccent(Option<Color>),
    Nothing,
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string_lossy().into_owned())
}

/// Archive name without its archive extension: `photos.tar.gz` -> `photos`.
/// Never `.`, `..` or empty (a file named `...zip` must not extract into
/// the parent folder).
pub fn stem_of(name: &str) -> String {
    let s = stem_raw(name);
    let t = s.trim_matches('.');
    if t.is_empty() || s.contains('/') {
        format!("{} files", name.replace('/', "_"))
    } else {
        s
    }
}

fn stem_raw(name: &str) -> String {
    // A part of a split archive is named after the whole archive.
    let logical = zip67_core::source::logical_name_str(name);
    let name = logical.as_str();
    if let Some(t) = zip67_core::ArchiveType::from_file_name(name) {
        let lower = name.to_ascii_lowercase();
        for ext in [
            t.extension(),
            ".tgz".into(),
            ".tbz2".into(),
            ".txz".into(),
            ".tzst".into(),
            ".tbz".into(),
        ] {
            if lower.ends_with(&ext) {
                return name[..lower.len() - ext.len()].to_string();
            }
        }
    }
    match name.rsplit_once('.') {
        Some((s, _)) if !s.is_empty() => s.to_string(),
        _ => format!("{name} files"),
    }
}

pub fn set_password(req: &mut Request, pw: Option<String>) {
    match req {
        Request::List { password, .. }
        | Request::Extract { password, .. }
        | Request::Test { password, .. }
        | Request::Update { password, .. } => *password = pw,
        _ => {}
    }
}

impl App {
    pub fn new(launch: Launch) -> (App, Task<Message>) {
        let settings = Settings::load();
        let start = launch
            .path
            .clone()
            .filter(|p| p.is_dir())
            .or_else(|| std::env::current_dir().ok().filter(|d| d != Path::new("/")))
            .or_else(|| settings.last_dir.clone())
            .unwrap_or_else(platform::home);
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("67zip"));
        let mut app = App {
            settings,
            system_dark: false,
            system_accent: None,
            location: Location::Dir(start.clone()),
            rows: Vec::new(),
            selected: BTreeSet::new(),
            anchor: None,
            focus: None,
            sort: (SortKey::Name, true),
            address: String::new(),
            scroll_y: 0.0,
            view_h: 0.0,
            modifiers: Modifiers::default(),
            cursor: Point::ORIGIN,
            menu: None,
            modal: None,
            job: None,
            fs_job: None,
            queue: Vec::new(),
            toast: None,
            temp_base: platform::temp_base(),
            warned_temp_on_disk: false,
            watches: Vec::new(),
            sandbox: None,
            exe,
            places: platform::places(),
            hover_drop: false,
        };
        let _ = app.load_dir(&start);
        let mut tasks =
            vec![iced::system::theme().map(|m| Message::SystemDark(m == iced::theme::Mode::Dark))];
        if let Some(p) = launch.path.filter(|p| p.is_file()) {
            app.open_archive_file(&p, None);
        }
        if !launch.add.is_empty() {
            app.open_add_dialog(launch.add.clone(), None);
            if launch.add_protected {
                app.protect_add_as_zip();
                tasks.push(iced::widget::operation::focus(ADD_PASSWORD_ID));
            }
        }
        if let Some((p, how)) = launch.extract {
            match how {
                ExtractHow::Ask => app.open_extract_dialog(vec![p], None),
                ExtractHow::Here => app.extract_fs_archives(vec![p], false),
                ExtractHow::ToFolder => app.extract_fs_archives(vec![p], true),
            }
        }
        tasks.push(Task::none());
        (app, Task::batch(tasks))
    }

    pub fn title(&self) -> String {
        match &self.location {
            Location::Dir(d) => format!("{} — 67zip", file_name(d)),
            Location::Archive { stack, .. } => format!(
                "{} — 67zip",
                stack
                    .last()
                    .map(|a| file_name(Path::new(&a.display)))
                    .unwrap_or_default()
            ),
        }
    }

    pub fn theme(&self) -> Theme {
        let dark = match self.settings.theme {
            ThemeChoice::System => self.system_dark,
            ThemeChoice::Light => false,
            ThemeChoice::Dark => true,
        };
        let accent = match &self.settings.accent {
            Some(name) => style::ACCENTS
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, c)| *c)
                .unwrap_or(style::ACCENTS[0].1),
            None => self.system_accent.unwrap_or(style::ACCENTS[0].1),
        };
        style::make_theme(dark, accent)
    }

    pub fn scale(&self) -> f32 {
        self.settings.scale.clamp(0.8, 1.6)
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![
            event::listen_with(|e, status, _id| match e {
                Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. })
                    if status == event::Status::Ignored =>
                {
                    Some(Message::Key(key, modifiers))
                }
                Event::Keyboard(keyboard::Event::ModifiersChanged(m)) => {
                    Some(Message::Modifiers(m))
                }
                Event::Mouse(iced::mouse::Event::CursorMoved { position }) => {
                    Some(Message::Cursor(position))
                }
                Event::Window(window::Event::FileDropped(p)) => Some(Message::Dropped(p)),
                Event::Window(window::Event::FileHovered(_)) => Some(Message::DropHover(true)),
                Event::Window(window::Event::FilesHoveredLeft) => Some(Message::DropHover(false)),
                _ => None,
            }),
            iced::system::theme_changes()
                .map(|m| Message::SystemDark(m == iced::theme::Mode::Dark)),
            Subscription::run(accent_stream),
        ];
        if self.job.is_some() || self.fs_job.is_some() || self.toast.is_some() {
            subs.push(iced::time::every(Duration::from_millis(60)).map(|_| Message::Tick));
        }
        if !self.watches.is_empty() {
            subs.push(iced::time::every(Duration::from_secs(2)).map(|_| Message::WatchTick));
        }
        Subscription::batch(subs)
    }

    // ----- listing ----------------------------------------------------------

    pub fn current_archive(&self) -> Option<&OpenArchive> {
        match &self.location {
            Location::Archive { stack, .. } => stack.last(),
            _ => None,
        }
    }

    pub fn current_folder(&self) -> &str {
        match &self.location {
            Location::Archive { folder, .. } => folder,
            _ => "",
        }
    }

    pub fn current_dir(&self) -> PathBuf {
        match &self.location {
            Location::Dir(d) => d.clone(),
            Location::Archive { stack, .. } => stack
                .first()
                .map(|a| a.host_dir.clone())
                .unwrap_or_else(platform::home),
        }
    }

    fn reset_view(&mut self) -> Task<Message> {
        self.selected.clear();
        self.anchor = None;
        self.focus = if self.rows.is_empty() { None } else { Some(0) };
        self.scroll_y = 0.0;
        iced::widget::operation::scroll_to(LIST_ID, AbsoluteOffset { x: 0.0, y: 0.0 })
    }

    fn refresh_rows(&mut self) {
        let (key, asc) = self.sort;
        match &self.location {
            Location::Dir(d) => {
                self.rows = listing::list_dir(d, self.settings.show_hidden).unwrap_or_else(|e| {
                    self.toast = Some((
                        format!("Cannot open {}: {e}", d.display()),
                        Instant::now(),
                        true,
                    ));
                    Vec::new()
                });
                self.address = d.to_string_lossy().into_owned();
            }
            Location::Archive { stack, folder } => {
                if let Some(a) = stack.last() {
                    self.rows = a.tree.rows(&a.entries, folder);
                    self.address = if folder.is_empty() {
                        a.display.clone()
                    } else {
                        format!("{}/{}", a.display, folder)
                    };
                }
            }
        }
        listing::sort(&mut self.rows, key, asc);
        self.selected.retain(|&i| i < self.rows.len());
    }

    pub fn load_dir(&mut self, d: &Path) -> Task<Message> {
        self.location = Location::Dir(d.to_path_buf());
        self.settings.last_dir = Some(d.to_path_buf());
        self.refresh_rows();
        self.reset_view()
    }

    fn selected_rows(&self) -> Vec<&Row> {
        let v: Vec<&Row> = self
            .selected
            .iter()
            .filter_map(|&i| self.rows.get(i))
            .collect();
        if v.is_empty() {
            self.focus
                .and_then(|i| self.rows.get(i))
                .into_iter()
                .collect()
        } else {
            v
        }
    }

    fn selected_paths(&self) -> Vec<PathBuf> {
        self.selected_rows()
            .into_iter()
            .map(|r| r.path.clone())
            .collect()
    }

    fn selected_arc_paths(&self) -> Vec<String> {
        self.selected_rows()
            .into_iter()
            .map(|r| r.arc_path.clone())
            .collect()
    }

    fn toast(&mut self, msg: impl Into<String>, error: bool) {
        self.toast = Some((msg.into(), Instant::now(), error));
    }

    // ----- jobs -------------------------------------------------------------

    pub fn start_job(&mut self, request: Request, purpose: Purpose, title: String) {
        if self.job.is_some() {
            self.queue.push((request, purpose, title));
            return;
        }
        match WorkerHandle::spawn(&self.exe, &request) {
            Ok(handle) => {
                let quiet = matches!(purpose, Purpose::Open { .. } | Purpose::Refresh { .. });
                self.job = Some(Job {
                    handle,
                    request,
                    purpose,
                    title,
                    snap: Snapshot::default(),
                    started: Instant::now(),
                    paused: false,
                    background: quiet,
                    question: None,
                });
            }
            Err(e) => self.toast(format!("Could not start the worker process: {e}"), true),
        }
    }

    fn poll_job(&mut self) -> Task<Message> {
        let mut finished = None;
        if let Some(job) = self.job.as_mut() {
            // A short Open job only shows its dialog if it takes a while.
            if matches!(job.purpose, Purpose::Open { .. } | Purpose::Refresh { .. })
                && job.started.elapsed() > Duration::from_millis(600)
            {
                job.background = false;
            }
            for _ in 0..200 {
                let Some(ev) = job.handle.try_next() else {
                    break;
                };
                match ev {
                    WEvent::Hello { sandbox, .. } => self.sandbox = Some(sandbox),
                    WEvent::Progress(s) => job.snap = s,
                    WEvent::Ask(q) => {
                        job.question = Some(q.clone());
                        self.modal = Some(Modal::Overwrite(q));
                    }
                    WEvent::Done(reply) => {
                        finished = Some(Ok(reply));
                        break;
                    }
                    WEvent::Failed(f) => {
                        finished = Some(Err(f));
                        break;
                    }
                }
            }
        }
        let Some(result) = finished else {
            return Task::none();
        };
        let job = self.job.take().expect("job present");
        if matches!(self.modal, Some(Modal::Overwrite(_))) {
            self.modal = None;
        }
        let task = self.finish_job(job, result);
        if self.job.is_none() && !self.queue.is_empty() {
            let (r, p, t) = self.queue.remove(0);
            self.start_job(r, p, t);
        }
        task
    }

    fn ask_password(&mut self, job: Job, wrong: bool) {
        self.modal = Some(Modal::Password {
            prompt: if wrong {
                "The password is wrong. Try again:".into()
            } else {
                "This archive is protected. Enter its password:".into()
            },
            value: String::new(),
            show: false,
            retry: Box::new(job.request),
            purpose: Box::new(job.purpose),
            title: job.title,
        });
    }

    fn finish_job(
        &mut self,
        job: Job,
        result: Result<Reply, zip67_worker::protocol::Failure>,
    ) -> Task<Message> {
        let had_password = match &job.request {
            Request::List { password, .. }
            | Request::Extract { password, .. }
            | Request::Test { password, .. }
            | Request::Update { password, .. } => password.is_some(),
            _ => false,
        };
        match result {
            Err(f) => match f.kind {
                FailKind::PasswordRequired => {
                    self.ask_password(job, false);
                    Task::none()
                }
                FailKind::WrongPassword => {
                    self.ask_password(job, true);
                    Task::none()
                }
                FailKind::Cancelled => {
                    self.toast("Cancelled.", false);
                    self.refresh_after_change();
                    Task::none()
                }
                _ => {
                    self.modal = Some(Modal::Report(ReportView {
                        title: format!("{} failed", job.title),
                        summary: zip67_core::util::safe_display(&f.message),
                        lines: Vec::new(),
                        ok: false,
                    }));
                    Task::none()
                }
            },
            Ok(reply) => self.handle_reply(job, reply, had_password),
        }
    }

    fn handle_reply(&mut self, job: Job, reply: Reply, had_password: bool) -> Task<Message> {
        match (job.purpose.clone(), reply) {
            (
                Purpose::Refresh { file },
                Reply::Listing {
                    archive_type,
                    entries,
                    info,
                },
            ) => {
                if let Location::Archive { stack, folder } = &mut self.location {
                    let top = stack.last().is_some_and(|a| a.file == file);
                    if let Some(a) = stack.iter_mut().find(|a| a.file == file) {
                        a.tree = Tree::build(&entries);
                        a.entries = entries;
                        a.info = info;
                        a.archive_type = archive_type;
                        // If the folder on screen is gone (renamed, deleted),
                        // show the nearest one that still exists.
                        while top && !folder.is_empty() && !a.tree.has_dir(folder) {
                            *folder = folder
                                .rsplit_once('/')
                                .map(|(p, _)| p.to_string())
                                .unwrap_or_default();
                        }
                    }
                }
                self.refresh_rows();
                Task::none()
            }
            (
                Purpose::Open {
                    file,
                    display,
                    host_dir,
                    nested,
                    folder,
                    password,
                    inner_dir,
                },
                Reply::Listing {
                    archive_type,
                    entries,
                    info,
                },
            ) => {
                let pw = password.or_else(|| match &job.request {
                    Request::List { password, .. } => password.clone(),
                    _ => None,
                });
                let tree = Tree::build(&entries);
                let arch = OpenArchive {
                    file,
                    display,
                    archive_type,
                    entries,
                    info,
                    tree,
                    password: pw,
                    host_dir,
                    nested,
                    inner_dir,
                };
                let folder = if arch.tree.has_dir(&folder) {
                    folder
                } else {
                    String::new()
                };
                match &mut self.location {
                    Location::Archive { stack, folder: f }
                        if nested || stack.last().is_some_and(|a| a.file == arch.file) =>
                    {
                        if stack.last().is_some_and(|a| a.file == arch.file) {
                            stack.pop();
                        }
                        stack.push(arch);
                        *f = folder;
                    }
                    _ => {
                        self.location = Location::Archive {
                            stack: vec![arch],
                            folder,
                        }
                    }
                }
                self.refresh_rows();
                self.reset_view()
            }
            (Purpose::Extract { dest, then }, Reply::Extracted(rep)) => {
                let needs_pw = !had_password
                    && rep
                        .errors
                        .iter()
                        .any(|(_, e)| e.contains("password is required"));
                let wrong_pw = had_password
                    && !rep.errors.is_empty()
                    && rep.errors.iter().all(|(_, e)| e.contains("wrong password"));
                if needs_pw || wrong_pw {
                    self.ask_password(job, wrong_pw);
                    return Task::none();
                }
                match then {
                    After::Report => {
                        let ok = rep.errors.is_empty();
                        if ok && rep.warnings.is_empty() {
                            self.toast(
                                format!("Extracted {} files to {}", rep.files, dest.display()),
                                false,
                            );
                        } else {
                            self.modal = Some(Modal::Report(ReportView {
                                title: "Extraction finished".into(),
                                summary: format!(
                                    "{} files and {} folders extracted to {}. {} problems.",
                                    rep.files,
                                    rep.dirs,
                                    dest.display(),
                                    rep.errors.len() + rep.warnings.len()
                                ),
                                lines: rep
                                    .errors
                                    .iter()
                                    .map(|(p, e)| {
                                        format!(
                                            "{}: {}",
                                            zip67_core::util::safe_display(p),
                                            zip67_core::util::safe_display(e)
                                        )
                                    })
                                    .chain(
                                        rep.warnings
                                            .iter()
                                            .map(|w| zip67_core::util::safe_display(w)),
                                    )
                                    .collect(),
                                ok,
                            }));
                        }
                        self.refresh_after_change();
                    }
                    After::OpenFile {
                        path,
                        folder,
                        archive,
                        password,
                        nested_display,
                        host_dir,
                    } => {
                        if !rep.errors.is_empty() {
                            self.modal = Some(Modal::Report(ReportView {
                                title: "Could not open the file".into(),
                                summary: rep
                                    .errors
                                    .iter()
                                    .map(|(_, e)| zip67_core::util::safe_display(e))
                                    .collect::<Vec<_>>()
                                    .join("; "),
                                lines: vec![],
                                ok: false,
                            }));
                        } else if zip67_core::ArchiveType::from_file_name(&file_name(&path))
                            .is_some()
                        {
                            // An archive inside the archive: browse it too (read-only).
                            let req = Request::List {
                                archive: path.clone(),
                                password: None,
                            };
                            let purpose = Purpose::Open {
                                file: path,
                                display: nested_display,
                                host_dir,
                                nested: true,
                                folder: String::new(),
                                password: None,
                                inner_dir: folder,
                            };
                            self.start_job(req, purpose, "Opening".into());
                        } else if platform::is_launcher(&path) {
                            // A desktop launcher runs a command when opened; one from
                            // an archive could pose as a document.
                            self.toast("Launcher files (.desktop) are not opened from archives. Extract it and check it first.".to_string(), true);
                        } else if let Err(e) = platform::open_with_default(&path) {
                            self.toast(e.to_string(), true);
                        } else {
                            if password.is_some()
                                && self.settings.warn_temp_on_disk
                                && !self.warned_temp_on_disk
                                && !platform::temp_in_memory()
                            {
                                // Once per session, until "Don't warn me again".
                                self.warned_temp_on_disk = true;
                                if self.modal.is_none() {
                                    self.modal = Some(Modal::TempOnDisk {
                                        folder: self.temp_base.display().to_string(),
                                        dont_warn: false,
                                    });
                                }
                            }
                            let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                            self.watches.push(Watch {
                                temp: path,
                                mtime,
                                archive,
                                folder,
                                password,
                            });
                        }
                    }
                }
                Task::none()
            }
            (Purpose::Test, Reply::Tested(rep)) => {
                let needs_pw = !had_password
                    && rep
                        .errors
                        .iter()
                        .any(|(_, e)| e.contains("password is required"));
                let wrong_pw = had_password
                    && !rep.errors.is_empty()
                    && rep.errors.iter().all(|(_, e)| e.contains("wrong password"));
                if needs_pw || wrong_pw {
                    self.ask_password(job, wrong_pw);
                    return Task::none();
                }
                let ok = rep.errors.is_empty();
                self.modal = Some(Modal::Report(ReportView {
                    title: if ok {
                        "No errors found".into()
                    } else {
                        "Errors found".into()
                    },
                    summary: format!(
                        "Tested {} files ({}).",
                        rep.files,
                        zip67_core::util::human_size(rep.bytes)
                    ),
                    lines: rep
                        .errors
                        .iter()
                        .map(|(p, e)| {
                            format!(
                                "{}: {}",
                                zip67_core::util::safe_display(p),
                                zip67_core::util::safe_display(e)
                            )
                        })
                        .collect(),
                    ok,
                }));
                Task::none()
            }
            (Purpose::Changed { archive, folder }, Reply::Created(rep)) => {
                if !rep.warnings.is_empty() {
                    self.modal = Some(Modal::Report(ReportView {
                        title: "Done, with warnings".into(),
                        summary: format!("{} files added.", rep.files),
                        lines: rep
                            .warnings
                            .iter()
                            .map(|w| zip67_core::util::safe_display(w))
                            .collect(),
                        ok: true,
                    }));
                } else {
                    let what = rep
                        .outputs
                        .first()
                        .map(|p| file_name(p))
                        .unwrap_or_default();
                    self.toast(
                        format!(
                            "Saved {what} ({})",
                            zip67_core::util::human_size(rep.bytes_out)
                        ),
                        false,
                    );
                }
                let _ = folder;
                // Re-read the archive if it is open, and if it lives inside
                // another archive, put the new version back into that one
                // (which in turn updates its own parent, and so on).
                let found = match &self.location {
                    Location::Archive { stack, .. } => {
                        stack.iter().position(|a| a.file == archive).map(|k| {
                            let me = &stack[k];
                            let parent = k.checked_sub(1).map(|p| &stack[p]);
                            (
                                me.password.clone(),
                                parent.map(|p| {
                                    (
                                        p.file.clone(),
                                        p.password.clone(),
                                        p.display.clone(),
                                        me.file.clone(),
                                        me.inner_dir.clone(),
                                    )
                                }),
                            )
                        })
                    }
                    _ => None,
                };
                match found {
                    Some((password, parent)) => {
                        self.start_job(
                            Request::List {
                                archive: archive.clone(),
                                password,
                            },
                            Purpose::Refresh { file: archive },
                            "Reading".into(),
                        );
                        if let Some((pfile, ppw, pdisplay, me, inner_dir)) = parent {
                            let req = Request::Update {
                                archive: pfile.clone(),
                                password: ppw,
                                changes: ChangesSpec {
                                    add: vec![(me, inner_dir.clone())],
                                    ..Default::default()
                                },
                                level: None,
                                threads: 0,
                            };
                            let title = format!("Saving into {}", file_name(Path::new(&pdisplay)));
                            self.start_job(
                                req,
                                Purpose::Changed {
                                    archive: pfile,
                                    folder: inner_dir,
                                },
                                title,
                            );
                        }
                    }
                    None => self.refresh_after_change(),
                }
                Task::none()
            }
            (Purpose::Hash(kinds), Reply::Hashes(v)) => {
                self.modal = Some(Modal::Hashes(v, kinds));
                Task::none()
            }
            (Purpose::Bench, Reply::Benchmark(v)) => {
                self.modal = Some(Modal::Bench(Some(v)));
                Task::none()
            }
            _ => Task::none(),
        }
    }

    fn refresh_after_change(&mut self) {
        if matches!(self.location, Location::Dir(_)) {
            self.refresh_rows();
        }
    }

    // ----- opening ----------------------------------------------------------

    pub fn open_archive_file(&mut self, p: &Path, password: Option<String>) {
        let host_dir = p
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(platform::home);
        // Parts of a split archive are shown under the archive's own name.
        let display = host_dir
            .join(zip67_core::source::logical_name(p))
            .to_string_lossy()
            .into_owned();
        let req = Request::List {
            archive: p.to_path_buf(),
            password: password.clone(),
        };
        self.start_job(
            req,
            Purpose::Open {
                file: p.to_path_buf(),
                display,
                host_dir,
                nested: false,
                folder: String::new(),
                password,
                inner_dir: String::new(),
            },
            "Opening".into(),
        );
    }

    fn open_row(&mut self, i: usize, force_inside: bool, force_outside: bool) -> Task<Message> {
        let Some(r) = self.rows.get(i).cloned() else {
            return Task::none();
        };
        match &mut self.location {
            Location::Dir(_) => {
                if r.is_dir {
                    return self.load_dir(&r.path);
                }
                let is_archive =
                    force_inside || (!force_outside && r.kind == listing::Kind::Archive);
                if is_archive {
                    self.open_archive_file(&r.path, None);
                } else if let Err(e) = platform::open_with_default(&r.path) {
                    self.toast(e.to_string(), true);
                }
                Task::none()
            }
            Location::Archive { folder, .. } => {
                if r.is_dir {
                    *folder = r.arc_path.clone();
                    self.refresh_rows();
                    return self.reset_view();
                }
                let Some(idx) = r.entry else {
                    return Task::none();
                };
                let Some(a) = self.current_archive() else {
                    return Task::none();
                };
                let dir = platform::new_temp_dir(&self.temp_base);
                let target = dir.join(&r.name);
                // Opened files never keep execute permissions from the archive.
                let options = ExtractOptions {
                    path_mode: PathMode::Flat,
                    overwrite: Overwrite::Always,
                    preserve_permissions: false,
                    ..Default::default()
                };
                let parent = r
                    .arc_path
                    .rsplit_once('/')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_default();
                let req = Request::Extract {
                    archive: a.file.clone(),
                    password: a.password.clone(),
                    dest: dir,
                    selection: Selection::Indices(vec![idx]),
                    options,
                };
                let nested_display = format!("{}/{}", a.display, r.arc_path);
                let then = After::OpenFile {
                    path: target,
                    folder: parent,
                    archive: a.file.clone(),
                    password: a.password.clone(),
                    nested_display,
                    host_dir: a.host_dir.clone(),
                };
                let dest = PathBuf::new();
                self.start_job(
                    req,
                    Purpose::Extract { dest, then },
                    format!("Opening {}", r.display),
                );
                Task::none()
            }
        }
    }

    fn go_up(&mut self) -> Task<Message> {
        match &mut self.location {
            Location::Dir(d) => {
                if let Some(p) = d.parent().map(Path::to_path_buf) {
                    let old = d.clone();
                    let t = self.load_dir(&p);
                    if let Some(i) = self.rows.iter().position(|r| r.path == old) {
                        self.selected.insert(i);
                        self.focus = Some(i);
                    }
                    return t;
                }
                Task::none()
            }
            Location::Archive { stack, folder } => {
                if !folder.is_empty() {
                    let old = folder.clone();
                    *folder = folder
                        .rsplit_once('/')
                        .map(|(p, _)| p.to_string())
                        .unwrap_or_default();
                    self.refresh_rows();
                    let t = self.reset_view();
                    if let Some(i) = self.rows.iter().position(|r| r.arc_path == old) {
                        self.selected.insert(i);
                        self.focus = Some(i);
                    }
                    return t;
                }
                if stack.len() > 1 {
                    let inner = stack.pop().expect("nested archive");
                    if let Some(Location::Archive { folder, .. }) = Some(&mut self.location) {
                        *folder = inner
                            .display
                            .rsplit_once('/')
                            .map(|(p, _)| p.to_string())
                            .unwrap_or_default();
                        let outer = self
                            .current_archive()
                            .map(|a| a.display.clone())
                            .unwrap_or_default();
                        if let Location::Archive { folder, .. } = &mut self.location {
                            *folder = folder
                                .strip_prefix(&outer)
                                .map(|s| s.trim_start_matches('/').to_string())
                                .unwrap_or_default();
                        }
                    }
                    self.refresh_rows();
                    return self.reset_view();
                }
                let file = stack
                    .first()
                    .map(|a| PathBuf::from(&a.display))
                    .unwrap_or_default();
                let dir = stack
                    .first()
                    .map(|a| a.host_dir.clone())
                    .unwrap_or_else(platform::home);
                let t = self.load_dir(&dir);
                if let Some(i) = self.rows.iter().position(|r| r.path == file) {
                    self.selected.insert(i);
                    self.focus = Some(i);
                }
                t
            }
        }
    }

    // ----- dialogs ------------------------------------------------------------

    pub fn open_add_dialog(&mut self, sources: Vec<PathBuf>, into: Option<AddInto>) {
        let dir = self.current_dir();
        let fmt = FORMATS
            .iter()
            .copied()
            .find(|f| f.0 == self.settings.default_format)
            .unwrap_or(FORMATS[0]);
        let base = match sources.as_slice() {
            [one] => file_name(one),
            _ => file_name(&dir),
        };
        let base = if base.is_empty() || base == "/" {
            "archive".to_string()
        } else {
            base
        };
        let archive = dir
            .join(format!("{base}.{}", fmt.0))
            .to_string_lossy()
            .into_owned();
        let level = LEVELS
            .iter()
            .copied()
            .find(|l| l.0 == self.settings.default_level)
            .unwrap_or(Level(5));
        self.modal = Some(Modal::Add(AddForm {
            sources,
            into,
            archive,
            format: fmt,
            level,
            method: MethodChoice(None),
            protect: false,
            password: String::new(),
            password2: String::new(),
            show_password: false,
            encrypt_names: true,
            solid: true,
            volume: VOLUMES[0],
            delete_after: false,
            shred: false,
            exclude: String::new(),
            error: None,
        }));
    }

    /// Switches the open Add dialog to zip with "Protect with a password" ticked.
    pub fn protect_add_as_zip(&mut self) {
        let zip = FORMATS
            .iter()
            .copied()
            .find(|f| f.0 == "zip")
            .unwrap_or(FORMATS[1]);
        if let Some(Modal::Add(f)) = self.modal.as_mut() {
            if f.into.is_none() {
                let old = zip67_core::ArchiveType::from_id(f.format.0)
                    .map(|t| t.extension())
                    .unwrap_or_default();
                if let Some(stem) = f.archive.strip_suffix(&old) {
                    f.archive = format!("{stem}.zip");
                }
                f.format = zip;
                f.method = MethodChoice(None);
                f.protect = true;
            }
        }
    }

    pub fn open_extract_dialog(
        &mut self,
        archives: Vec<PathBuf>,
        selection: Option<(PathBuf, Selection, String)>,
    ) {
        let dir = match archives.first() {
            Some(a) => a
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.current_dir()),
            None => self.current_dir(),
        };
        let password = self
            .current_archive()
            .and_then(|a| a.password.clone())
            .unwrap_or_default();
        self.modal = Some(Modal::Extract(ExtractForm {
            subfolder: archives.len() == 1 || selection.is_none(),
            archives,
            selection,
            dest: dir.to_string_lossy().into_owned(),
            path_mode: PATH_MODES[0],
            overwrite: OVERWRITES[0],
            password,
            show_password: false,
            error: None,
        }));
    }

    fn extract_fs_archives(&mut self, archives: Vec<PathBuf>, into_folder: bool) {
        for a in one_per_archive(archives) {
            let parent = a
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.current_dir());
            let dest = if into_folder {
                parent.join(stem_of(&file_name(&a)))
            } else {
                parent
            };
            let options = ExtractOptions {
                overwrite: Overwrite::Ask,
                ..Default::default()
            };
            let req = Request::Extract {
                archive: a.clone(),
                password: None,
                dest: dest.clone(),
                selection: Selection::All,
                options,
            };
            self.start_job(
                req,
                Purpose::Extract {
                    dest,
                    then: After::Report,
                },
                format!("Extracting {}", file_name(&a)),
            );
        }
    }

    fn submit_add(&mut self) {
        let cwd = self.current_dir();
        let Some(Modal::Add(f)) = self.modal.as_mut() else {
            return;
        };
        let protect = f.protect && f.into.is_none();
        if protect && !f.encryptable() {
            f.error = Some("Only 7z and zip archives can have a password.".into());
            return;
        }
        if protect && f.password.is_empty() {
            f.error = Some("Type a password, or untick \"Protect with a password\".".into());
            return;
        }
        if protect && f.password != f.password2 && !f.show_password {
            f.error = Some("The two passwords do not match.".into());
            return;
        }
        let spec = CreateSpec {
            archive_type: f.format.0.to_string(),
            level: f.level.0,
            method: f.method.0,
            password: if protect {
                Some(f.password.clone())
            } else {
                None
            },
            encrypt_names: f.encrypt_names && f.format.0 == "7z",
            solid: f.solid,
            volume_size: f.volume.0,
            delete_after: f.delete_after,
            shred: f.delete_after && f.shred,
            exclude: f
                .exclude
                .split([',', ';'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            ..Default::default()
        };
        let (req, purpose, title) = if let Some(into) = &f.into {
            let changes = ChangesSpec {
                add: f
                    .sources
                    .iter()
                    .map(|s| (s.clone(), into.folder.clone()))
                    .collect(),
                ..Default::default()
            };
            (
                Request::Update {
                    archive: into.archive.clone(),
                    password: into.password.clone(),
                    changes,
                    level: Some(f.level.0),
                    threads: 0,
                },
                Purpose::Changed {
                    archive: into.archive.clone(),
                    folder: into.folder.clone(),
                },
                "Adding files".to_string(),
            )
        } else {
            let mut archive = PathBuf::from(f.archive.trim());
            if archive.is_relative() {
                archive = cwd.join(archive);
            }
            let req = Request::AddFiles {
                archive: archive.clone(),
                inputs: f.sources.clone(),
                arc_dir: String::new(),
                spec,
            };
            (
                req,
                Purpose::Changed {
                    archive: archive.clone(),
                    folder: String::new(),
                },
                format!("Creating {}", file_name(&archive)),
            )
        };
        self.settings.default_format = f.format.0.to_string();
        self.settings.default_level = f.level.0;
        self.settings.save();
        self.modal = None;
        self.start_job(req, purpose, title);
    }

    fn submit_extract(&mut self) {
        let Some(Modal::Extract(f)) = self.modal.clone() else {
            return;
        };
        let mut dest = PathBuf::from(f.dest.trim());
        if dest.as_os_str().is_empty() {
            if let Some(Modal::Extract(m)) = self.modal.as_mut() {
                m.error = Some("Choose a destination folder.".into());
            }
            return;
        }
        if dest.is_relative() {
            dest = self.current_dir().join(dest);
        }
        let password = if f.password.is_empty() {
            None
        } else {
            Some(f.password.clone())
        };
        self.modal = None;
        if let Some((archive, selection, base)) = f.selection {
            let path_mode = if f.path_mode.0 == PathMode::Flat {
                PathMode::Flat
            } else {
                PathMode::Relative
            };
            let name = self
                .current_archive()
                .map(|a| stem_of(&file_name(Path::new(&a.display))))
                .unwrap_or_default();
            let dest = if f.subfolder { dest.join(name) } else { dest };
            let options = ExtractOptions {
                path_mode,
                base,
                overwrite: f.overwrite.0,
                ..Default::default()
            };
            if let Some(a) = self.current_archive_mut() {
                if password.is_some() {
                    a.password = password.clone();
                }
            }
            let req = Request::Extract {
                archive,
                password,
                dest: dest.clone(),
                selection,
                options,
            };
            self.start_job(
                req,
                Purpose::Extract {
                    dest,
                    then: After::Report,
                },
                "Extracting".into(),
            );
        } else {
            for a in one_per_archive(f.archives) {
                let d = if f.subfolder {
                    dest.join(stem_of(&file_name(&a)))
                } else {
                    dest.clone()
                };
                let options = ExtractOptions {
                    path_mode: f.path_mode.0,
                    overwrite: f.overwrite.0,
                    ..Default::default()
                };
                let req = Request::Extract {
                    archive: a.clone(),
                    password: password.clone(),
                    dest: d.clone(),
                    selection: Selection::All,
                    options,
                };
                self.start_job(
                    req,
                    Purpose::Extract {
                        dest: d,
                        then: After::Report,
                    },
                    format!("Extracting {}", file_name(&a)),
                );
            }
        }
    }

    fn current_archive_mut(&mut self) -> Option<&mut OpenArchive> {
        match &mut self.location {
            Location::Archive { stack, .. } => stack.last_mut(),
            _ => None,
        }
    }

    fn archive_selection(&self) -> (Selection, String) {
        let folder = self.current_folder().to_string();
        let explicit = !self.selected.is_empty();
        if !explicit {
            let base = folder.clone();
            return (
                if folder.is_empty() {
                    Selection::All
                } else {
                    Selection::Paths(vec![folder])
                },
                base,
            );
        }
        (Selection::Paths(self.selected_arc_paths()), folder)
    }

    fn can_modify(&mut self) -> bool {
        let Location::Archive { stack, .. } = &self.location else {
            return true;
        };
        // Every archive from the file on disk down to the one on screen
        // gets rewritten, so all of them must be changeable.
        let blocked = stack.iter().find(|a| {
            !zip67_core::ArchiveType::from_id(&a.archive_type).is_some_and(|t| t.can_update())
                || a.info.volumes > 1
        });
        if let Some(a) = blocked {
            let why = if a.info.volumes > 1 {
                "split archives cannot be changed"
            } else {
                "this kind of archive cannot be changed"
            };
            let name = file_name(Path::new(&a.display));
            self.toast(
                format!("{}: {why}.", zip67_core::util::safe_display(&name)),
                true,
            );
            return false;
        }
        true
    }

    fn context_menu(&mut self) {
        let mut items: Vec<(String, Message, bool)> = Vec::new();
        let one = self.selected_rows().len() == 1;
        let any = !self.selected_rows().is_empty();
        match &self.location {
            Location::Dir(_) => {
                let rows = self.selected_rows();
                let archives = rows.iter().all(|r| r.kind == listing::Kind::Archive) && any;
                let name = rows.first().map(|r| r.name.clone()).unwrap_or_default();
                items.push(("Open".into(), Message::OpenSelected, one));
                if one && !rows[0].is_dir {
                    items.push(("Open inside 67zip".into(), Message::OpenInside, true));
                }
                if archives {
                    items.push((String::new(), Message::Nothing, false));
                    items.push(("Extract here".into(), Message::ExtractHere, true));
                    let label = if one {
                        format!(
                            "Extract to \"{}/\"",
                            zip67_core::util::safe_display(&stem_of(&name))
                        )
                    } else {
                        "Extract each to its own folder".into()
                    };
                    items.push((label, Message::ExtractToFolder, true));
                    items.push(("Extract…".into(), Message::Extract, true));
                    items.push(("Test archive".into(), Message::Test, true));
                }
                items.push((String::new(), Message::Nothing, false));
                items.push(("Add to archive…".into(), Message::Add, any));
                if any {
                    let base = if one {
                        zip67_core::util::safe_display(&name)
                    } else {
                        file_name(&self.current_dir())
                    };
                    items.push((format!("Add to \"{base}.7z\""), Message::AddTo("7z"), true));
                    items.push((
                        format!("Add to \"{base}.zip\""),
                        Message::AddTo("zip"),
                        true,
                    ));
                    items.push((
                        "Add to zip with a password…".into(),
                        Message::AddWithPassword,
                        true,
                    ));
                }
                items.push((
                    "Checksums (CRC32, SHA-256…)".into(),
                    Message::Hash(None),
                    any,
                ));
                items.push((String::new(), Message::Nothing, false));
                items.push(("Copy to…".into(), Message::CopyTo, any));
                items.push(("Move to…".into(), Message::MoveTo, any));
                items.push(("Rename".into(), Message::Rename, one));
                items.push(("Move to Trash".into(), Message::Delete, any));
                items.push((String::new(), Message::Nothing, false));
                items.push(("New folder".into(), Message::NewFolder, true));
                items.push(("Properties".into(), Message::Info, true));
            }
            Location::Archive { .. } => {
                items.push(("Open".into(), Message::OpenSelected, one));
                items.push(("Open with another app".into(), Message::OpenOutside, one));
                items.push((String::new(), Message::Nothing, false));
                items.push(("Extract…".into(), Message::Extract, true));
                items.push(("Copy to…".into(), Message::CopyTo, true));
                items.push(("Test".into(), Message::Test, true));
                items.push((String::new(), Message::Nothing, false));
                items.push(("Rename".into(), Message::Rename, one));
                items.push(("Delete from archive".into(), Message::Delete, any));
                items.push(("New folder".into(), Message::NewFolder, true));
                items.push((String::new(), Message::Nothing, false));
                items.push(("Properties".into(), Message::Info, true));
            }
        }
        self.menu = Some(ContextMenu {
            at: self.cursor,
            items,
        });
    }

    fn properties(&mut self) {
        let rows: Vec<Row> = self.selected_rows().into_iter().cloned().collect();
        let mut lines = Vec::new();
        let mut warning = None;
        match &self.location {
            Location::Archive { stack, .. } => {
                let Some(a) = stack.last() else { return };
                let i = &a.info;
                lines.push(("Archive".into(), zip67_core::util::safe_display(&a.display)));
                lines.push((
                    "Type".into(),
                    zip67_core::ArchiveType::from_id(&a.archive_type)
                        .map(|t| t.display_name())
                        .unwrap_or(a.archive_type.clone()),
                ));
                lines.push((
                    "Size on disk".into(),
                    zip67_core::util::human_size(i.physical_size),
                ));
                let total: u64 = zip67_core::util::total_size(a.entries.iter().map(|e| e.size));
                lines.push(("Unpacked size".into(), zip67_core::util::human_size(total)));
                if i.physical_size > 0 && total > 0 {
                    lines.push((
                        "Ratio".into(),
                        format!("{:.1}%", 100.0 * i.physical_size as f64 / total as f64),
                    ));
                }
                lines.push((
                    "Files".into(),
                    a.entries.iter().filter(|e| !e.is_dir()).count().to_string(),
                ));
                lines.push((
                    "Folders".into(),
                    a.tree.dirs.len().saturating_sub(1).to_string(),
                ));
                if !i.methods.is_empty() {
                    lines.push(("Method".into(), i.methods.join(", ")));
                }
                if a.archive_type == "7z" {
                    lines.push((
                        "Solid".into(),
                        if i.solid {
                            format!("yes, {} blocks", i.blocks)
                        } else {
                            "no".into()
                        },
                    ));
                }
                lines.push((
                    "Encrypted".into(),
                    match (i.encrypted_headers, i.encrypted_data) {
                        (true, _) => "data and file names".into(),
                        (false, true) => "data (file names visible)".into(),
                        _ => "no".into(),
                    },
                ));
                if i.volumes > 1 {
                    lines.push(("Volumes".into(), i.volumes.to_string()));
                }
                if let Some(c) = &i.comment {
                    lines.push(("Comment".into(), zip67_core::util::safe_display(c)));
                }
                if a.archive_type == "7z" && i.encrypted_data {
                    warning = Some("7z encryption hides your data, but the format cannot detect if someone modified the encrypted file. Zip AES archives made by 67zip can.".into());
                }
                if let [r] = rows.as_slice() {
                    lines.push((String::new(), String::new()));
                    lines.push(("Selected".into(), r.display.clone()));
                    if let Some(s) = r.size {
                        lines.push((
                            "Size".into(),
                            format!("{} ({s} bytes)", zip67_core::util::human_size(s)),
                        ));
                    }
                    if let Some(p) = r.packed {
                        lines.push(("Packed".into(), zip67_core::util::human_size(p)));
                    }
                    if let Some(m) = r.mtime {
                        lines.push(("Modified".into(), zip67_core::util::format_local_time(m)));
                    }
                    if let Some(m) = &r.method {
                        lines.push(("Method".into(), m.clone()));
                    }
                    if let Some(c) = r.crc {
                        lines.push(("CRC32".into(), format!("{c:08X}")));
                    }
                    if let Some(m) = r.mode {
                        lines.push(("Permissions".into(), format!("{m:04o}")));
                    }
                    if let Some(l) = &r.link_target {
                        lines.push(("Link to".into(), zip67_core::util::safe_display(l)));
                    }
                }
                for w in &i.warnings {
                    lines.push(("Warning".into(), w.clone()));
                }
            }
            Location::Dir(d) => {
                if rows.is_empty() {
                    lines.push(("Folder".into(), d.to_string_lossy().into_owned()));
                    if let Some(free) = zip67_core::extract::free_space(d) {
                        lines.push(("Free space".into(), zip67_core::util::human_size(free)));
                    }
                }
                for r in rows.iter().take(1) {
                    lines.push(("Name".into(), r.display.clone()));
                    lines.push((
                        "Location".into(),
                        r.path
                            .parent()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    ));
                    lines.push(("Type".into(), listing::type_label(r)));
                    if let Some(s) = r.size {
                        lines.push((
                            "Size".into(),
                            format!("{} ({s} bytes)", zip67_core::util::human_size(s)),
                        ));
                    }
                    if let Some(m) = r.mtime {
                        lines.push(("Modified".into(), zip67_core::util::format_local_time(m)));
                    }
                    if let Some(m) = r.mode {
                        lines.push(("Permissions".into(), format!("{m:04o}")));
                    }
                    if let Some(l) = &r.link_target {
                        lines.push(("Link to".into(), zip67_core::util::safe_display(l)));
                    }
                }
                if rows.len() > 1 {
                    let total: u64 =
                        zip67_core::util::total_size(rows.iter().filter_map(|r| r.size));
                    lines.push((
                        "Selected".into(),
                        format!(
                            "{} items, {}",
                            rows.len(),
                            zip67_core::util::human_size(total)
                        ),
                    ));
                }
            }
        }
        if rows.iter().any(|r| r.suspicious) {
            warning = Some("A name contains hidden control or text-direction characters. They are shown as \\u{…} codes because they are often used to disguise a file's real type.".into());
        }
        self.modal = Some(Modal::Properties {
            title: "Properties".into(),
            lines,
            warning,
        });
    }

    fn apply_pending(&mut self, action: PendingAction) {
        match action {
            PendingAction::DeleteFs(paths, trash) => {
                let mut failed = Vec::new();
                for p in &paths {
                    let res = if trash {
                        platform::move_to_trash(p)
                    } else if std::fs::symlink_metadata(p)
                        .map(|m| m.is_dir())
                        .unwrap_or(false)
                    {
                        std::fs::remove_dir_all(p)
                    } else {
                        std::fs::remove_file(p)
                    };
                    if let Err(e) = res {
                        failed.push(format!("{}: {e}", p.display()));
                    }
                }
                if !failed.is_empty() {
                    self.modal = Some(Modal::Report(ReportView {
                        title: "Some items were not deleted".into(),
                        summary: String::new(),
                        lines: failed,
                        ok: false,
                    }));
                }
                self.refresh_rows();
            }
            PendingAction::DeleteInArchive(paths) => {
                if let Some(a) = self.current_archive() {
                    let req = Request::Update {
                        archive: a.file.clone(),
                        password: a.password.clone(),
                        changes: ChangesSpec {
                            delete: paths,
                            ..Default::default()
                        },
                        level: None,
                        threads: 0,
                    };
                    let p = Purpose::Changed {
                        archive: a.file.clone(),
                        folder: self.current_folder().to_string(),
                    };
                    self.start_job(req, p, "Deleting".into());
                }
            }
            PendingAction::UpdateModified {
                temp,
                archive,
                folder,
            } => {
                let pw = self
                    .watches
                    .iter()
                    .find(|w| w.temp == temp)
                    .and_then(|w| w.password.clone());
                let req = Request::Update {
                    archive: archive.clone(),
                    password: pw,
                    changes: ChangesSpec {
                        add: vec![(temp, folder.clone())],
                        ..Default::default()
                    },
                    level: None,
                    threads: 0,
                };
                self.start_job(
                    req,
                    Purpose::Changed { archive, folder },
                    "Updating the archive".into(),
                );
            }
            PendingAction::AddDropped(paths) => {
                if let Some(a) = self.current_archive() {
                    let into = AddInto {
                        archive: a.file.clone(),
                        folder: self.current_folder().to_string(),
                        password: a.password.clone(),
                    };
                    let changes = ChangesSpec {
                        add: paths
                            .iter()
                            .map(|p| (p.clone(), into.folder.clone()))
                            .collect(),
                        ..Default::default()
                    };
                    let req = Request::Update {
                        archive: into.archive.clone(),
                        password: into.password.clone(),
                        changes,
                        level: None,
                        threads: 0,
                    };
                    self.start_job(
                        req,
                        Purpose::Changed {
                            archive: into.archive,
                            folder: into.folder,
                        },
                        "Adding files".into(),
                    );
                }
            }
        }
    }

    fn apply_input(&mut self, action: InputAction, value: String) -> Result<(), String> {
        let v = value.trim().to_string();
        if v.is_empty() {
            return Err("Please enter a name.".into());
        }
        let bad_name = |s: &str| s.contains('/') || s == "." || s == "..";
        match action {
            InputAction::RenameFs(p) => {
                if bad_name(&v) {
                    return Err("A name cannot contain '/'.".into());
                }
                let to = p.with_file_name(&v);
                if to.exists() {
                    return Err("An item with that name already exists.".into());
                }
                std::fs::rename(&p, &to).map_err(|e| e.to_string())?;
                self.refresh_rows();
                self.select_path(&to);
            }
            InputAction::NewFolderFs => {
                if bad_name(&v) {
                    return Err("A name cannot contain '/'.".into());
                }
                let dir = self.current_dir().join(&v);
                std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
                self.refresh_rows();
                self.select_path(&dir);
            }
            InputAction::RenameInArchive(old) => {
                if bad_name(&v) {
                    return Err("A name cannot contain '/'.".into());
                }
                let new = match old.rsplit_once('/') {
                    Some((d, _)) => format!("{d}/{v}"),
                    None => v,
                };
                if let Some(a) = self.current_archive() {
                    let req = Request::Update {
                        archive: a.file.clone(),
                        password: a.password.clone(),
                        changes: ChangesSpec {
                            rename: vec![(old, new)],
                            ..Default::default()
                        },
                        level: None,
                        threads: 0,
                    };
                    let p = Purpose::Changed {
                        archive: a.file.clone(),
                        folder: self.current_folder().to_string(),
                    };
                    self.start_job(req, p, "Renaming".into());
                }
            }
            InputAction::NewFolderInArchive => {
                if bad_name(&v) {
                    return Err("A name cannot contain '/'.".into());
                }
                let folder = self.current_folder().to_string();
                let path = if folder.is_empty() {
                    v
                } else {
                    format!("{folder}/{v}")
                };
                if let Some(a) = self.current_archive() {
                    let req = Request::Update {
                        archive: a.file.clone(),
                        password: a.password.clone(),
                        changes: ChangesSpec {
                            new_dirs: vec![path],
                            ..Default::default()
                        },
                        level: None,
                        threads: 0,
                    };
                    let p = Purpose::Changed {
                        archive: a.file.clone(),
                        folder,
                    };
                    self.start_job(req, p, "Creating folder".into());
                }
            }
            InputAction::ArchiveCopyTo => {
                let dest = PathBuf::from(&v);
                let (selection, base) = self.archive_selection();
                if let Some(a) = self.current_archive() {
                    let options = ExtractOptions {
                        path_mode: PathMode::Relative,
                        base,
                        overwrite: Overwrite::Ask,
                        ..Default::default()
                    };
                    let req = Request::Extract {
                        archive: a.file.clone(),
                        password: a.password.clone(),
                        dest: dest.clone(),
                        selection,
                        options,
                    };
                    self.start_job(
                        req,
                        Purpose::Extract {
                            dest,
                            then: After::Report,
                        },
                        "Copying out of the archive".into(),
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Selects the row showing `path` (after rename / new folder).
    fn select_path(&mut self, path: &Path) {
        if let Some(i) = self.rows.iter().position(|r| r.path == path) {
            self.selected = [i].into_iter().collect();
            self.anchor = Some(i);
            self.focus = Some(i);
        }
    }

    fn fs_copy_move(
        &mut self,
        paths: Vec<PathBuf>,
        dest: PathBuf,
        moving: bool,
    ) -> Result<(), String> {
        if !dest.is_dir() {
            return Err("That folder does not exist.".into());
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut errors = Vec::new();
            for p in &paths {
                let to = dest.join(p.file_name().unwrap_or_default());
                if to.exists() {
                    errors.push(format!("{} already exists", to.display()));
                    continue;
                }
                let res = if moving {
                    std::fs::rename(p, &to)
                        .or_else(|_| copy_tree(p, &to).and_then(|_| remove_tree(p)))
                } else {
                    copy_tree(p, &to)
                };
                if let Err(e) = res {
                    errors.push(format!("{}: {e}", p.display()));
                }
            }
            let _ = tx.send(if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("\n"))
            });
        });
        self.fs_job = Some((
            if moving {
                "Moving".into()
            } else {
                "Copying".into()
            },
            rx,
        ));
        Ok(())
    }

    // ----- update -------------------------------------------------------------

    /// Handles a message; dialogs with a text field get keyboard focus.
    pub fn update(&mut self, msg: Message) -> Task<Message> {
        let before = self.modal_kind();
        let task = self.update_inner(msg);
        let after = self.modal_kind();
        if after != before {
            match after {
                Some("password") => {
                    return Task::batch([task, iced::widget::operation::focus("password")]);
                }
                Some("input") => {
                    return Task::batch([task, iced::widget::operation::focus("modal-input")]);
                }
                _ => {}
            }
        }
        task
    }

    fn modal_kind(&self) -> Option<&'static str> {
        match &self.modal {
            Some(Modal::Password { .. }) => Some("password"),
            Some(Modal::Input { .. }) => Some("input"),
            Some(_) => Some("other"),
            None => None,
        }
    }

    fn update_inner(&mut self, msg: Message) -> Task<Message> {
        if !matches!(
            msg,
            Message::Cursor(_)
                | Message::Tick
                | Message::WatchTick
                | Message::Modifiers(_)
                | Message::Scrolled(_)
                | Message::ShowMenu
        ) && self.menu.is_some()
        {
            let keep = matches!(msg, Message::Nothing);
            if !keep {
                self.menu = None;
            }
        }
        match msg {
            Message::Nothing => {}
            Message::Up => return self.go_up(),
            Message::Refresh => self.refresh_rows(),
            Message::GoTo(p) => {
                self.location = Location::Dir(p.clone());
                return self.load_dir(&p);
            }
            Message::AddressChanged(s) => self.address = s,
            Message::AddressSubmit => {
                let p = PathBuf::from(self.address.trim());
                if p.is_dir() {
                    return self.load_dir(&p);
                } else if p.is_file() {
                    self.open_archive_file(&p, None);
                } else if let Location::Archive { stack, folder } = &mut self.location {
                    if let Some(a) = stack.last() {
                        if let Some(rest) = self.address.trim().strip_prefix(&a.display) {
                            let rest = rest.trim_matches('/').to_string();
                            if a.tree.has_dir(&rest) {
                                *folder = rest;
                                self.refresh_rows();
                                return self.reset_view();
                            }
                        }
                    }
                    self.toast("No such folder.", true);
                } else {
                    self.toast("No such folder.", true);
                }
            }
            Message::RowClick(i) => {
                if self.modifiers.control() {
                    if !self.selected.remove(&i) {
                        self.selected.insert(i);
                    }
                    self.anchor = Some(i);
                } else if self.modifiers.shift() {
                    let a = self.anchor.unwrap_or(i);
                    self.selected = (a.min(i)..=a.max(i)).collect();
                } else {
                    self.selected = [i].into_iter().collect();
                    self.anchor = Some(i);
                }
                self.focus = Some(i);
            }
            Message::RowDouble(i) => return self.open_row(i, false, false),
            Message::RowRight(i) => {
                if !self.selected.contains(&i) {
                    self.selected = [i].into_iter().collect();
                    self.anchor = Some(i);
                }
                self.focus = Some(i);
                // Open on the next update, after the cursor position of this
                // same input batch has been seen.
                return Task::done(Message::ShowMenu);
            }
            Message::BackgroundRight => {
                if self.menu.is_none() {
                    self.selected.clear();
                    return Task::done(Message::ShowMenu);
                }
            }
            Message::ShowMenu => self.context_menu(),
            Message::Sort(k) => {
                self.sort = if self.sort.0 == k {
                    (k, !self.sort.1)
                } else {
                    (k, true)
                };
                self.refresh_rows();
                self.selected.clear();
            }
            Message::Scrolled(v) => {
                self.scroll_y = v.absolute_offset().y;
                self.view_h = v.bounds().height;
            }
            Message::Modifiers(m) => self.modifiers = m,
            Message::Cursor(p) => self.cursor = p,
            Message::DropHover(h) => self.hover_drop = h,
            Message::Dropped(p) => {
                self.hover_drop = false;
                if matches!(self.location, Location::Archive { .. }) {
                    if !self.can_modify() {
                        return Task::none();
                    }
                    let mut paths = vec![p];
                    if let Some(Modal::Confirm {
                        action: PendingAction::AddDropped(v),
                        text,
                        ..
                    }) = self.modal.as_mut()
                    {
                        v.append(&mut paths);
                        *text = format!("Add {} dropped items to this archive folder?", v.len());
                        return Task::none();
                    }
                    self.modal = Some(Modal::Confirm {
                        title: "Add to archive".into(),
                        text: format!(
                            "Add \"{}\" to this archive folder?",
                            zip67_core::util::safe_display(&file_name(&paths[0]))
                        ),
                        ok: "Add".into(),
                        danger: false,
                        action: PendingAction::AddDropped(paths),
                    });
                } else if p.is_file()
                    && zip67_core::ArchiveType::from_file_name(&file_name(&p)).is_some()
                    && self.modal.is_none()
                {
                    self.open_archive_file(&p, None);
                } else if let Some(Modal::Add(f)) = self.modal.as_mut() {
                    f.sources.push(p);
                } else {
                    self.open_add_dialog(vec![p], None);
                }
            }
            Message::Key(key, m) => return self.on_key(key, m),
            Message::ToggleSidebar => {
                self.settings.sidebar = !self.settings.sidebar;
                self.settings.save();
            }
            Message::AddFavorite => {
                let d = self.current_dir();
                if !self.settings.favorites.contains(&d) {
                    self.settings.favorites.push(d);
                    self.settings.save();
                }
            }
            Message::RemoveFavorite(p) => {
                self.settings.favorites.retain(|f| f != &p);
                self.settings.save();
            }
            Message::Add => match &self.location {
                Location::Dir(_) => {
                    let paths = self.selected_paths();
                    if paths.is_empty() {
                        self.toast("Select the files and folders to add first.", false);
                    } else {
                        self.open_add_dialog(paths, None);
                    }
                }
                Location::Archive { .. } => {
                    if self.can_modify() {
                        return Task::perform(pick_files(self.current_dir()), Message::AddPicked);
                    }
                }
            },
            Message::AddWithPassword => {
                let paths = self.selected_paths();
                if paths.is_empty() {
                    self.toast("Select the files and folders to add first.", false);
                    return Task::none();
                }
                self.open_add_dialog(paths, None);
                self.protect_add_as_zip();
                return iced::widget::operation::focus(ADD_PASSWORD_ID);
            }
            Message::AddTo(ext) => {
                let paths = self.selected_paths();
                if paths.is_empty() {
                    return Task::none();
                }
                let base = match paths.as_slice() {
                    [one] => file_name(one),
                    _ => file_name(&self.current_dir()),
                };
                let archive = self.current_dir().join(format!("{base}.{ext}"));
                let spec = CreateSpec {
                    archive_type: ext.into(),
                    level: self.settings.default_level,
                    ..Default::default()
                };
                let req = Request::AddFiles {
                    archive: archive.clone(),
                    inputs: paths,
                    arc_dir: String::new(),
                    spec,
                };
                self.start_job(
                    req,
                    Purpose::Changed {
                        archive: archive.clone(),
                        folder: String::new(),
                    },
                    format!("Creating {}", file_name(&archive)),
                );
            }
            Message::Extract => match &self.location {
                Location::Dir(_) => {
                    let archives: Vec<PathBuf> = self
                        .selected_rows()
                        .iter()
                        .filter(|r| !r.is_dir)
                        .map(|r| r.path.clone())
                        .collect();
                    if archives.is_empty() {
                        self.toast("Select an archive to extract.", false);
                    } else {
                        self.open_extract_dialog(archives, None);
                    }
                }
                Location::Archive { .. } => {
                    let (sel, base) = self.archive_selection();
                    let file = self
                        .current_archive()
                        .map(|a| a.file.clone())
                        .unwrap_or_default();
                    self.open_extract_dialog(vec![], Some((file, sel, base)));
                }
            },
            Message::ExtractHere => {
                let a: Vec<PathBuf> = self.selected_paths();
                self.extract_fs_archives(a, false);
            }
            Message::ExtractToFolder => {
                let a: Vec<PathBuf> = self.selected_paths();
                self.extract_fs_archives(a, true);
            }
            Message::Test => match &self.location {
                Location::Dir(_) => {
                    for p in one_per_archive(self.selected_paths()) {
                        let req = Request::Test {
                            archive: p.clone(),
                            password: None,
                            selection: Selection::All,
                        };
                        self.start_job(req, Purpose::Test, format!("Testing {}", file_name(&p)));
                    }
                }
                Location::Archive { .. } => {
                    let (sel, _) = self.archive_selection();
                    if let Some(a) = self.current_archive() {
                        let req = Request::Test {
                            archive: a.file.clone(),
                            password: a.password.clone(),
                            selection: sel,
                        };
                        self.start_job(req, Purpose::Test, "Testing".into());
                    }
                }
            },
            Message::CopyTo | Message::MoveTo => {
                let moving = matches!(msg, Message::MoveTo);
                let action = match &self.location {
                    Location::Dir(_) => {
                        let p = self.selected_paths();
                        if moving {
                            InputAction::MoveTo(p)
                        } else {
                            InputAction::CopyTo(p)
                        }
                    }
                    Location::Archive { .. } => InputAction::ArchiveCopyTo,
                };
                self.modal = Some(Modal::Input {
                    title: if moving {
                        "Move to".into()
                    } else {
                        "Copy to".into()
                    },
                    label: "Destination folder".into(),
                    value: self.current_dir().to_string_lossy().into_owned(),
                    action,
                    error: None,
                });
            }
            Message::Delete => match &self.location {
                Location::Dir(_) => {
                    let paths = self.selected_paths();
                    if paths.is_empty() {
                        return Task::none();
                    }
                    let trash = self.settings.use_trash;
                    let what = if paths.len() == 1 {
                        format!(
                            "\"{}\"",
                            zip67_core::util::safe_display(&file_name(&paths[0]))
                        )
                    } else {
                        format!("{} items", paths.len())
                    };
                    if self.settings.confirm_delete || !trash {
                        self.modal = Some(Modal::Confirm {
                            title: if trash {
                                "Move to Trash".into()
                            } else {
                                "Delete permanently".into()
                            },
                            text: if trash {
                                format!("Move {what} to the Trash?")
                            } else {
                                format!("Delete {what} permanently? This cannot be undone.")
                            },
                            ok: if trash {
                                "Move to Trash".into()
                            } else {
                                "Delete".into()
                            },
                            danger: !trash,
                            action: PendingAction::DeleteFs(paths, trash),
                        });
                    } else {
                        self.apply_pending(PendingAction::DeleteFs(paths, trash));
                    }
                }
                Location::Archive { .. } => {
                    if !self.can_modify() || self.selected.is_empty() {
                        return Task::none();
                    }
                    let paths = self.selected_arc_paths();
                    self.modal = Some(Modal::Confirm {
                        title: "Delete from archive".into(),
                        text: format!(
                            "Remove {} item(s) from the archive? The archive is rewritten; this cannot be undone.",
                            paths.len()
                        ),
                        ok: "Delete".into(),
                        danger: true,
                        action: PendingAction::DeleteInArchive(paths),
                    });
                }
            },
            Message::Rename => {
                let Some(r) = self.selected_rows().first().map(|r| (*r).clone()) else {
                    return Task::none();
                };
                let action = match &self.location {
                    Location::Dir(_) => InputAction::RenameFs(r.path.clone()),
                    Location::Archive { .. } => {
                        if !self.can_modify() {
                            return Task::none();
                        }
                        InputAction::RenameInArchive(r.arc_path.clone())
                    }
                };
                self.modal = Some(Modal::Input {
                    title: "Rename".into(),
                    label: "New name".into(),
                    value: r.name.clone(),
                    action,
                    error: None,
                });
            }
            Message::NewFolder => {
                let action = match &self.location {
                    Location::Dir(_) => InputAction::NewFolderFs,
                    Location::Archive { .. } => {
                        if !self.can_modify() {
                            return Task::none();
                        }
                        InputAction::NewFolderInArchive
                    }
                };
                self.modal = Some(Modal::Input {
                    title: "New folder".into(),
                    label: "Folder name".into(),
                    value: "New folder".into(),
                    action,
                    error: None,
                });
            }
            Message::Info => self.properties(),
            Message::OpenSelected => {
                if let Some(i) = self.focus.or_else(|| self.selected.first().copied()) {
                    return self.open_row(i, false, false);
                }
            }
            Message::OpenInside => {
                if let Some(i) = self.focus {
                    return self.open_row(i, true, false);
                }
            }
            Message::OpenOutside => {
                if let Some(i) = self.focus {
                    return self.open_row(i, false, true);
                }
            }
            Message::Hash(kind) => {
                let paths: Vec<PathBuf> = match &self.location {
                    Location::Dir(_) => collect_files(&self.selected_paths()),
                    Location::Archive { .. } => {
                        self.toast(
                            "Checksums are calculated for files on disk. Extract the files first.",
                            false,
                        );
                        return Task::none();
                    }
                };
                if paths.is_empty() {
                    self.toast("Select files to calculate checksums for.", false);
                    return Task::none();
                }
                let kinds = match kind {
                    Some(k) => vec![k],
                    None => vec![HashKind::Crc32, HashKind::Sha256, HashKind::Blake3],
                };
                self.start_job(
                    Request::Hash {
                        paths,
                        kinds: kinds.clone(),
                    },
                    Purpose::Hash(kinds),
                    "Calculating checksums".into(),
                );
            }
            Message::Benchmark => self.modal = Some(Modal::Bench(None)),
            Message::RunBenchmark => {
                self.modal = None;
                let threads = zip67_core::util::default_threads();
                self.start_job(
                    Request::Benchmark {
                        seconds: 4,
                        threads,
                        dict_size: 0,
                    },
                    Purpose::Bench,
                    "Benchmark".into(),
                );
            }
            Message::OpenSettings => self.modal = Some(Modal::Settings),
            Message::About => self.modal = Some(Modal::About),
            Message::CloseMenu => self.menu = None,
            Message::CloseModal => {
                if let Some(Modal::Overwrite(_)) = self.modal {
                    if let Some(j) = self.job.as_mut() {
                        j.handle.answer(Answer::Cancel);
                        j.question = None;
                    }
                }
                self.modal = None;
            }
            Message::CopyText(t) => return iced::clipboard::write(t),
            // ---- add form
            Message::AddArchive(s) => self.with_add(|f| f.archive = s),
            Message::AddFormat(fmt) => self.with_add(|f| {
                let old = zip67_core::ArchiveType::from_id(f.format.0)
                    .map(|t| t.extension())
                    .unwrap_or_default();
                if let Some(stem) = f.archive.strip_suffix(&old) {
                    f.archive = format!("{stem}.{}", fmt.0);
                }
                f.format = fmt;
                f.method = MethodChoice(None);
                if !f.encryptable() {
                    f.protect = false;
                }
            }),
            Message::AddLevel(l) => self.with_add(|f| f.level = l),
            Message::AddMethod(m) => self.with_add(|f| f.method = m),
            Message::AddProtect(b) => {
                self.with_add(|f| f.protect = b && f.encryptable());
                if b {
                    return iced::widget::operation::focus(ADD_PASSWORD_ID);
                }
            }
            Message::AddPassword(s) => self.with_add(|f| f.password = s),
            Message::AddPassword2(s) => self.with_add(|f| f.password2 = s),
            Message::AddShowPassword(b) => self.with_add(|f| f.show_password = b),
            Message::AddEncryptNames(b) => self.with_add(|f| f.encrypt_names = b),
            Message::AddSolid(b) => self.with_add(|f| f.solid = b),
            Message::AddVolume(v) => self.with_add(|f| f.volume = v),
            Message::AddDeleteAfter(b) => self.with_add(|f| f.delete_after = b),
            Message::AddShred(b) => self.with_add(|f| f.shred = b),
            Message::AddExclude(s) => self.with_add(|f| f.exclude = s),
            Message::AddBrowse => {
                let start = self.current_dir();
                return Task::perform(save_file(start), Message::AddBrowsed);
            }
            Message::AddBrowsed(p) => {
                if let Some(p) = p {
                    self.with_add(|f| f.archive = p.to_string_lossy().into_owned());
                }
            }
            Message::AddPicked(files) => {
                if let (Some(files), Some(a)) =
                    (files.filter(|v| !v.is_empty()), self.current_archive())
                {
                    let into = AddInto {
                        archive: a.file.clone(),
                        folder: self.current_folder().to_string(),
                        password: a.password.clone(),
                    };
                    self.open_add_dialog(files, Some(into));
                }
            }
            Message::AddOk => self.submit_add(),
            // ---- extract form
            Message::ExDest(s) => self.with_ex(|f| f.dest = s),
            Message::ExSubfolder(b) => self.with_ex(|f| f.subfolder = b),
            Message::ExPathMode(p) => self.with_ex(|f| f.path_mode = p),
            Message::ExOverwrite(o) => self.with_ex(|f| f.overwrite = o),
            Message::ExPassword(s) => self.with_ex(|f| f.password = s),
            Message::ExShowPassword(b) => self.with_ex(|f| f.show_password = b),
            Message::ExBrowse => {
                let start = self.current_dir();
                return Task::perform(pick_folder(start), Message::ExBrowsed);
            }
            Message::ExBrowsed(p) => {
                if let Some(p) = p {
                    self.with_ex(|f| f.dest = p.to_string_lossy().into_owned());
                }
            }
            Message::ExOk => self.submit_extract(),
            // ---- password
            Message::PwInput(s) => {
                if let Some(Modal::Password { value, .. }) = self.modal.as_mut() {
                    *value = s;
                }
            }
            Message::PwShow(b) => {
                if let Some(Modal::Password { show, .. }) = self.modal.as_mut() {
                    *show = b;
                }
            }
            Message::PwOk => {
                if let Some(Modal::Password {
                    value,
                    retry,
                    purpose,
                    title,
                    ..
                }) = self.modal.take()
                {
                    let mut req = *retry;
                    set_password(&mut req, Some(value.clone()));
                    let mut purpose = *purpose;
                    if let Purpose::Open { password, .. } = &mut purpose {
                        *password = Some(value.clone());
                    }
                    if let Some(a) = self.current_archive_mut() {
                        a.password = Some(value);
                    }
                    self.start_job(req, purpose, title);
                }
            }
            Message::Answer(a) => {
                if let Some(j) = self.job.as_mut() {
                    j.handle.answer(a);
                    j.question = None;
                }
                self.modal = None;
            }
            Message::ConfirmOk => {
                if let Some(Modal::Confirm { action, .. }) = self.modal.take() {
                    self.apply_pending(action);
                }
            }
            Message::InputChanged(s) => {
                if let Some(Modal::Input { value, error, .. }) = self.modal.as_mut() {
                    *value = s;
                    *error = None;
                }
            }
            Message::InputOk => {
                if let Some(Modal::Input {
                    value,
                    action,
                    title,
                    label,
                    ..
                }) = self.modal.take()
                {
                    let res = match &action {
                        InputAction::CopyTo(p) => {
                            self.fs_copy_move(p.clone(), PathBuf::from(value.trim()), false)
                        }
                        InputAction::MoveTo(p) => {
                            self.fs_copy_move(p.clone(), PathBuf::from(value.trim()), true)
                        }
                        _ => self.apply_input(action.clone(), value.clone()),
                    };
                    if let Err(e) = res {
                        self.modal = Some(Modal::Input {
                            title,
                            label,
                            value,
                            action,
                            error: Some(e),
                        });
                    }
                }
            }
            // ---- settings
            Message::SetTheme(t) => self.with_settings(|s| s.theme = t),
            Message::SetAccent(a) => self.with_settings(|s| s.accent = a),
            Message::SetShowHidden(b) => {
                self.with_settings(|s| s.show_hidden = b);
                self.refresh_rows();
            }
            Message::SetConfirmDelete(b) => self.with_settings(|s| s.confirm_delete = b),
            Message::SetUseTrash(b) => self.with_settings(|s| s.use_trash = b),
            Message::SetWarnTempOnDisk(b) => self.with_settings(|s| s.warn_temp_on_disk = b),
            Message::TempNoticeDontWarn(b) => {
                if let Some(Modal::TempOnDisk { dont_warn, .. }) = self.modal.as_mut() {
                    *dont_warn = b;
                }
            }
            Message::TempNoticeOk => {
                if let Some(Modal::TempOnDisk {
                    dont_warn: true, ..
                }) = self.modal.take()
                {
                    self.with_settings(|s| s.warn_temp_on_disk = false);
                }
            }
            Message::SetDefaultFormat(f) => self.with_settings(|s| s.default_format = f.0.into()),
            Message::SetDefaultLevel(l) => self.with_settings(|s| s.default_level = l.0),
            Message::SetScale(c) => self.with_settings(|s| s.scale = c.0 as f32 / 100.0),
            // ---- jobs
            Message::Tick => {
                if let Some((_, at, _)) = &self.toast {
                    if at.elapsed() > Duration::from_secs(5) {
                        self.toast = None;
                    }
                }
                if let Some((title, rx)) = &self.fs_job {
                    if let Ok(res) = rx.try_recv() {
                        let title = title.clone();
                        self.fs_job = None;
                        match res {
                            Ok(()) => self.toast(format!("{title} finished."), false),
                            Err(e) => {
                                self.modal = Some(Modal::Report(ReportView {
                                    title: format!("{title} finished with problems"),
                                    summary: String::new(),
                                    lines: e.lines().map(String::from).collect(),
                                    ok: false,
                                }))
                            }
                        }
                        self.refresh_rows();
                    }
                }
                return self.poll_job();
            }
            Message::WatchTick => {
                if self.modal.is_some() || self.job.is_some() {
                    return Task::none();
                }
                for w in &mut self.watches {
                    let now = std::fs::metadata(&w.temp).and_then(|m| m.modified()).ok();
                    if now.is_some() && now != w.mtime {
                        w.mtime = now;
                        let name = file_name(&w.temp);
                        self.modal = Some(Modal::Confirm {
                            title: "File changed".into(),
                            text: format!(
                                "\"{}\" was changed in another program. Save the changes into the archive?",
                                zip67_core::util::safe_display(&name)
                            ),
                            ok: "Update archive".into(),
                            danger: false,
                            action: PendingAction::UpdateModified {
                                temp: w.temp.clone(),
                                archive: w.archive.clone(),
                                folder: w.folder.clone(),
                            },
                        });
                        break;
                    }
                }
            }
            Message::JobPause => {
                if let Some(j) = self.job.as_mut() {
                    if j.paused {
                        j.handle.resume()
                    } else {
                        j.handle.pause()
                    }
                    j.paused = !j.paused;
                }
            }
            Message::JobCancel => {
                if let Some(j) = self.job.as_mut() {
                    j.handle.cancel();
                    if j.paused {
                        j.handle.resume();
                    }
                }
                self.queue.clear();
            }
            Message::JobBackground(b) => {
                if let Some(j) = self.job.as_mut() {
                    j.background = b;
                }
            }
            Message::SystemDark(d) => self.system_dark = d,
            Message::SystemAccent(c) => self.system_accent = c,
        }
        Task::none()
    }

    fn with_add(&mut self, f: impl FnOnce(&mut AddForm)) {
        if let Some(Modal::Add(form)) = self.modal.as_mut() {
            form.error = None;
            f(form);
        }
    }
    fn with_ex(&mut self, f: impl FnOnce(&mut ExtractForm)) {
        if let Some(Modal::Extract(form)) = self.modal.as_mut() {
            form.error = None;
            f(form);
        }
    }
    fn with_settings(&mut self, f: impl FnOnce(&mut Settings)) {
        f(&mut self.settings);
        self.settings.save();
    }

    fn on_key(&mut self, key: Key, m: Modifiers) -> Task<Message> {
        if self.modal.is_some() {
            if let Key::Named(Named::Escape) = key {
                return self.update(Message::CloseModal);
            }
            if let Key::Named(Named::Enter) = key {
                return match self.modal {
                    Some(Modal::Add(_)) => self.update(Message::AddOk),
                    Some(Modal::TempOnDisk { .. }) => self.update(Message::TempNoticeOk),
                    Some(Modal::Extract(_)) => self.update(Message::ExOk),
                    Some(Modal::Password { .. }) => self.update(Message::PwOk),
                    Some(Modal::Confirm { .. }) => self.update(Message::ConfirmOk),
                    Some(Modal::Input { .. }) => self.update(Message::InputOk),
                    Some(
                        Modal::Report(_)
                        | Modal::Properties { .. }
                        | Modal::About
                        | Modal::Hashes(..),
                    ) => self.update(Message::CloseModal),
                    _ => Task::none(),
                };
            }
            return Task::none();
        }
        if self.menu.is_some() {
            if let Key::Named(Named::Escape) = key {
                self.menu = None;
            }
            return Task::none();
        }
        let n = self.rows.len();
        let move_to = |app: &mut App, i: usize| -> Task<Message> {
            if m.shift() {
                let a = app.anchor.unwrap_or(app.focus.unwrap_or(0));
                app.selected = (a.min(i)..=a.max(i)).collect();
            } else {
                app.selected = [i].into_iter().collect();
                app.anchor = Some(i);
            }
            app.focus = Some(i);
            let top = i as f32 * ROW_H;
            let h = if app.view_h > 0.0 { app.view_h } else { 400.0 };
            if top < app.scroll_y {
                return iced::widget::operation::scroll_to(
                    LIST_ID,
                    AbsoluteOffset { x: 0.0, y: top },
                );
            } else if top + ROW_H > app.scroll_y + h {
                return iced::widget::operation::scroll_to(
                    LIST_ID,
                    AbsoluteOffset {
                        x: 0.0,
                        y: top + ROW_H - h,
                    },
                );
            }
            Task::none()
        };
        match key.as_ref() {
            Key::Named(Named::ArrowDown) if n > 0 => {
                let i = self.focus.map(|f| (f + 1).min(n - 1)).unwrap_or(0);
                return move_to(self, i);
            }
            Key::Named(Named::ArrowUp) if n > 0 => {
                let i = self.focus.map(|f| f.saturating_sub(1)).unwrap_or(0);
                return move_to(self, i);
            }
            Key::Named(Named::Home) if n > 0 => return move_to(self, 0),
            Key::Named(Named::End) if n > 0 => return move_to(self, n - 1),
            Key::Named(Named::PageDown) if n > 0 => {
                let step = ((self.view_h / ROW_H) as usize).max(1);
                let i = self.focus.map(|f| (f + step).min(n - 1)).unwrap_or(0);
                return move_to(self, i);
            }
            Key::Named(Named::PageUp) if n > 0 => {
                let step = ((self.view_h / ROW_H) as usize).max(1);
                let i = self.focus.map(|f| f.saturating_sub(step)).unwrap_or(0);
                return move_to(self, i);
            }
            Key::Named(Named::Enter) if m.alt() => return self.update(Message::Info),
            Key::Named(Named::Enter) => return self.update(Message::OpenSelected),
            Key::Named(Named::Backspace) => return self.update(Message::Up),
            Key::Named(Named::ArrowLeft) if m.alt() => return self.update(Message::Up),
            Key::Named(Named::Delete) => return self.update(Message::Delete),
            Key::Named(Named::F2) => return self.update(Message::Rename),
            Key::Named(Named::F5) => return self.update(Message::CopyTo),
            Key::Named(Named::F6) => return self.update(Message::MoveTo),
            Key::Named(Named::F7) => return self.update(Message::NewFolder),
            Key::Named(Named::F9) => return self.update(Message::ToggleSidebar),
            Key::Named(Named::Escape) => self.selected.clear(),
            Key::Character("a") if m.control() => {
                self.selected = (0..n).collect();
            }
            Key::Character("r") if m.control() => return self.update(Message::Refresh),
            Key::Character("q") if m.control() => return iced::exit(),
            Key::Character("h") if m.control() => {
                return self.update(Message::SetShowHidden(!self.settings.show_hidden));
            }
            Key::Character("l") if m.control() => {
                return iced::widget::operation::focus("address");
            }
            Key::Character(",") if m.control() => return self.update(Message::OpenSettings),
            _ => {}
        }
        Task::none()
    }
}

/// Keeps one entry per split archive when several of its parts are selected.
fn one_per_archive(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    paths
        .into_iter()
        .filter(|p| {
            let key = match zip67_core::source::volume_set(p) {
                Ok(Some(set)) => set.parts.first().cloned().unwrap_or_else(|| p.clone()),
                _ => p.clone(),
            };
            seen.insert(key)
        })
        .collect()
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    let md = std::fs::symlink_metadata(from)?;
    if md.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(from)?, to)
    } else if md.is_dir() {
        std::fs::create_dir(to)?;
        for e in std::fs::read_dir(from)? {
            let e = e?;
            copy_tree(&e.path(), &to.join(e.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(from, to).map(|_| ())
    }
}

fn remove_tree(p: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(p)?.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    }
}

fn collect_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(p: &Path, out: &mut Vec<PathBuf>, depth: usize) {
        if depth > 64 || out.len() > 100_000 {
            return;
        }
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => {
                if let Ok(rd) = std::fs::read_dir(p) {
                    let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                    v.sort();
                    for c in v {
                        walk(&c, out, depth + 1);
                    }
                }
            }
            Ok(m) if m.is_file() => out.push(p.to_path_buf()),
            _ => {}
        }
    }
    for p in paths {
        walk(p, &mut out, 0);
    }
    out
}

async fn pick_folder(start: PathBuf) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .set_directory(start)
        .pick_folder()
        .await
        .map(|h| h.path().to_path_buf())
}

async fn save_file(start: PathBuf) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .set_directory(start)
        .save_file()
        .await
        .map(|h| h.path().to_path_buf())
}

async fn pick_files(start: PathBuf) -> Option<Vec<PathBuf>> {
    rfd::AsyncFileDialog::new()
        .set_directory(start)
        .pick_files()
        .await
        .map(|v| v.into_iter().map(|h| h.path().to_path_buf()).collect())
}

fn accent_stream() -> impl iced::futures::Stream<Item = Message> {
    use iced::futures::StreamExt;
    mundy::Preferences::stream(mundy::Interest::AccentColor | mundy::Interest::ColorScheme).map(
        |p| {
            let c = p
                .accent_color
                .0
                .map(|c| Color::from_rgba(c.red as f32, c.green as f32, c.blue as f32, 1.0));
            Message::SystemAccent(c)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{Launch, stem_of};
    use std::path::PathBuf;

    #[test]
    fn add_with_password_from_the_file_manager() {
        let args: Vec<String> = ["--add-with-password", "a.txt", "--b.txt"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let l = Launch::from_args(&args);
        assert!(l.add_protected);
        // Everything after the flag is a file, even if it starts with "--".
        assert_eq!(
            l.add,
            vec![PathBuf::from("a.txt"), PathBuf::from("--b.txt")]
        );
        let plain = Launch::from_args(&["--add".to_string(), "a.txt".to_string()]);
        assert!(!plain.add_protected && plain.add.len() == 1);
    }

    #[test]
    fn extract_folder_names_stay_below_the_folder() {
        assert_eq!(stem_of("photos.tar.gz"), "photos");
        assert_eq!(stem_of("a.part2.rar"), "a");
        for evil in ["...zip", "..zip", ".7z", "....tar.gz"] {
            let s = stem_of(evil);
            assert!(
                !s.trim_matches('.').is_empty() && !s.contains('/'),
                "{evil} -> {s}"
            );
        }
    }
}
