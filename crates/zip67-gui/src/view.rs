//! Drawing the window.

use iced::alignment::{Horizontal, Vertical};
use iced::widget::{
    button, center, checkbox, column, container, mouse_area, opaque, pick_list, pin, progress_bar, row, rule, scrollable, space, stack, text,
    text_input, tooltip, Column, Row as WRow,
};
use iced::{Alignment, Element, Font, Length, Padding};

use zip67_core::util::{format_local_time, human_size, safe_display};

use crate::app::{App, Location, Message, ADD_PASSWORD_ID, ROW_H};
use crate::forms::*;
use crate::icons::{icon, Icon};
use crate::listing::{self, SortKey};
use crate::settings::ThemeChoice;
use crate::style;

pub const INTER: Font = Font::with_name("Inter");
pub const INTER_SEMI: Font = Font { weight: iced::font::Weight::Semibold, ..INTER };
pub const INTER_MEDIUM: Font = Font { weight: iced::font::Weight::Medium, ..INTER };

fn label<'a>(s: impl text::IntoFragment<'a>) -> text::Text<'a> {
    text(s).size(14)
}

fn muted<'a>(s: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    text(s).size(13).style(|t: &iced::Theme| text::Style { color: Some(style::muted_text(t)) }).into()
}

fn tool<'a>(ic: Icon, name: &'a str, tip: &'a str, msg: Option<Message>) -> Element<'a, Message> {
    let b = button(column![icon(ic, 26.0), text(name).size(12).font(INTER_MEDIUM)].spacing(3).align_x(Alignment::Center).width(62))
        .padding(Padding::from([6, 4]))
        .style(style::tool_button)
        .on_press_maybe(msg);
    tooltip(b, container(text(tip).size(12)).padding(6).style(style::menu), tooltip::Position::Bottom).gap(4).into()
}

fn small_tool<'a>(ic: Icon, tip: &'a str, msg: Message) -> Element<'a, Message> {
    tooltip(button(icon(ic, 18.0)).padding(7).style(style::tool_button).on_press(msg), container(text(tip).size(12)).padding(6).style(style::menu), tooltip::Position::Bottom)
        .gap(4)
        .into()
}

fn primary<'a>(s: &'a str, msg: Option<Message>) -> Element<'a, Message> {
    button(text(s).size(14).font(INTER_SEMI)).padding(Padding::from([8, 18])).style(style::primary_button).on_press_maybe(msg).into()
}

fn secondary<'a>(s: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(s).size(14)).padding(Padding::from([8, 18])).style(style::secondary_button).on_press(msg).into()
}

fn danger<'a>(s: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(s).size(14).font(INTER_SEMI)).padding(Padding::from([8, 18])).style(style::danger_button).on_press(msg).into()
}

fn field<'a>(name: &'a str, content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    row![container(text(name).size(13).style(|t: &iced::Theme| text::Style { color: Some(style::muted_text(t)) })).width(140), content.into()]
        .spacing(12)
        .align_y(Alignment::Center)
        .into()
}

fn input<'a>(placeholder: &'a str, value: &'a str, on: impl Fn(String) -> Message + 'a) -> text_input::TextInput<'a, Message> {
    text_input(placeholder, value).on_input(on).padding(Padding::from([7, 10])).size(14).style(style::input)
}

impl App {
    pub fn view(&self) -> Element<'_, Message> {
        let main = column![self.view_toolbar(), self.view_address(), row![self.view_sidebar(), self.view_list()].height(Length::Fill), self.view_status()];
        let mut layers: Vec<Element<Message>> = vec![main.into()];
        if self.hover_drop {
            let msg = match self.location {
                Location::Archive { .. } => "Drop to add to this archive",
                Location::Dir(_) => "Drop to open or compress",
            };
            layers.push(
                container(container(text(msg).size(20).font(INTER_SEMI)).padding(24).style(style::card))
                    .center(Length::Fill)
                    .style(style::backdrop)
                    .into(),
            );
        }
        if let Some(m) = &self.menu {
            layers.push(mouse_area(container(space()).width(Length::Fill).height(Length::Fill)).on_press(Message::CloseMenu).on_right_press(Message::CloseMenu).into());
            let mut col = Column::new().spacing(1).width(250);
            for (name, msg, enabled) in &m.items {
                if name.is_empty() {
                    col = col.push(container(rule::horizontal(1).style(style::rule)).padding(Padding::from([3, 6])));
                } else {
                    col = col.push(
                        button(text(name.clone()).size(13))
                            .width(Length::Fill)
                            .padding(Padding::from([6, 10]))
                            .style(style::menu_item)
                            .on_press_maybe(enabled.then(|| msg.clone())),
                    );
                }
            }
            let h = m.items.iter().map(|(n, ..)| if n.is_empty() { 7.0 } else { 29.0 }).sum::<f32>() + 12.0;
            let y = if m.at.y + h > 760.0 { (m.at.y - h).max(4.0) } else { m.at.y };
            layers.push(pin(container(col).padding(6).style(style::menu)).x(m.at.x.min(2000.0)).y(y).into());
        }
        if let Some(job) = &self.job {
            if !job.background && job.question.is_none() && self.modal.is_none() {
                layers.push(self.modal_frame(self.view_progress(job), 520.0));
            }
        }
        if let Some(modal) = &self.modal {
            let (content, width) = self.view_modal(modal);
            layers.push(self.modal_frame(content, width));
        }
        stack(layers).into()
    }

    fn modal_frame<'a>(&'a self, content: Element<'a, Message>, width: f32) -> Element<'a, Message> {
        opaque(mouse_area(center(opaque(container(content).width(width).padding(22).style(style::card))).style(style::backdrop)).on_press(Message::Nothing))
    }

    fn view_toolbar(&self) -> Element<'_, Message> {
        let in_archive = matches!(self.location, Location::Archive { .. });
        let busy = self.job.is_some();
        let has_sel = !self.selected.is_empty() || self.focus.is_some();
        let some = |m: Message, ok: bool| if ok && !busy { Some(m) } else { None };
        let bar = row![
            tool(Icon::Add, "Add", "Add the selected items to an archive", some(Message::Add, true)),
            tool(Icon::Extract, "Extract", "Extract files", some(Message::Extract, has_sel || in_archive)),
            tool(Icon::Test, "Test", "Check the archive for errors", some(Message::Test, has_sel || in_archive)),
            rule::vertical(1).style(style::rule),
            tool(Icon::Copy, "Copy", "Copy to another folder (F5)", some(Message::CopyTo, has_sel || in_archive)),
            tool(Icon::Move, "Move", "Move to another folder (F6)", some(Message::MoveTo, has_sel && !in_archive)),
            tool(Icon::Delete, "Delete", "Delete (Del)", some(Message::Delete, has_sel)),
            tool(Icon::Info, "Info", "Properties (Alt+Enter)", Some(Message::Info)),
            tool(Icon::NewFolder, "Folder", "New folder (F7)", some(Message::NewFolder, true)),
            rule::vertical(1).style(style::rule),
            tool(Icon::Hash, "Checksum", "CRC32, SHA-256 and BLAKE3 of the selected files", some(Message::Hash(None), has_sel && !in_archive)),
            tool(Icon::Bench, "Benchmark", "Measure compression speed", some(Message::Benchmark, true)),
            space().width(Length::Fill),
            small_tool(Icon::Settings, "Settings (Ctrl+,)", Message::OpenSettings),
            small_tool(Icon::Logo, "About 67zip", Message::About),
        ]
        .spacing(4)
        .align_y(Alignment::Center)
        .height(64);
        container(bar).padding(Padding::from([4, 10])).width(Length::Fill).style(style::toolbar).into()
    }

    fn view_address(&self) -> Element<'_, Message> {
        let lock: Element<Message> = match self.current_archive() {
            Some(a) if a.info.encrypted_data || a.info.encrypted_headers => {
                tooltip(icon(Icon::Lock, 18.0), container(text("Encrypted archive").size(12)).padding(6).style(style::menu), tooltip::Position::Bottom).into()
            }
            _ => space().width(0).into(),
        };
        let kind: Element<Message> = match self.current_archive() {
            Some(a) => container(text(zip67_core::ArchiveType::from_id(&a.archive_type).map(|t| t.display_name()).unwrap_or(a.archive_type.clone())).size(12).font(INTER_SEMI))
                .padding(Padding::from([3, 9]))
                .style(|t: &iced::Theme| style::badge(t, t.palette().primary))
                .into(),
            None => space().width(0).into(),
        };
        let addr = container(
            row![
                icon(if matches!(self.location, Location::Archive { .. }) { Icon::Archive } else { Icon::Folder }, 18.0),
                text_input("Path", &self.address).id("address").on_input(Message::AddressChanged).on_submit(Message::AddressSubmit).size(14).padding(Padding::from([6, 6])).style(style::address_input),
                kind,
                lock
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        )
        .padding(Padding::from([1, 10]))
        .style(style::address);
        container(
            row![
                small_tool(Icon::Sidebar, "Show or hide places (F9)", Message::ToggleSidebar),
                small_tool(Icon::Up, "Up one level (Backspace)", Message::Up),
                small_tool(Icon::Refresh, "Refresh (Ctrl+R)", Message::Refresh),
                addr,
                small_tool(Icon::Star, "Add this folder to favourites", Message::AddFavorite),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        )
        .padding(Padding::from([8, 10]))
        .style(style::panel)
        .into()
    }

    fn view_sidebar(&self) -> Element<'_, Message> {
        if !self.settings.sidebar {
            return space().width(0).into();
        }
        let current = self.current_dir();
        let mut col = Column::new().spacing(2).padding(Padding::from([10, 8]));
        col = col.push(container(text("PLACES").size(11).font(INTER_SEMI).style(|t: &iced::Theme| text::Style { color: Some(style::muted_text(t)) })).padding(Padding::from([4, 8])));
        for (name, path, ic) in &self.places {
            let active = matches!(self.location, Location::Dir(_)) && current == *path;
            col = col.push(
                button(row![icon(*ic, 18.0), text(name.clone()).size(14)].spacing(10).align_y(Alignment::Center))
                    .width(Length::Fill)
                    .padding(Padding::from([6, 8]))
                    .style(style::place_button(active))
                    .on_press(Message::GoTo(path.clone())),
            );
        }
        if !self.settings.favorites.is_empty() {
            col = col.push(container(text("FAVOURITES").size(11).font(INTER_SEMI).style(|t: &iced::Theme| text::Style { color: Some(style::muted_text(t)) })).padding(Padding { top: 12.0, right: 8.0, bottom: 4.0, left: 8.0 }));
            for f in &self.settings.favorites {
                let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.to_string_lossy().into_owned());
                let active = matches!(self.location, Location::Dir(_)) && current == *f;
                col = col.push(
                    mouse_area(
                        button(row![icon(Icon::Folder, 18.0), text(safe_display(&name)).size(14)].spacing(10).align_y(Alignment::Center))
                            .width(Length::Fill)
                            .padding(Padding::from([6, 8]))
                            .style(style::place_button(active))
                            .on_press(Message::GoTo(f.clone())),
                    )
                    .on_middle_press(Message::RemoveFavorite(f.clone())),
                );
            }
        }
        col = col.push(space().height(Length::Fill));
        let shield: Element<Message> = match &self.sandbox {
            Some(s) => {
                let (ic, txt) = if s.is_strong() { (Icon::Shield, "Sandbox active") } else { (Icon::ShieldOff, "Sandbox limited") };
                tooltip(
                    row![icon(ic, 16.0), text(txt).size(12)].spacing(6).align_y(Alignment::Center),
                    container(text(s.describe()).size(12)).padding(8).max_width(280).style(style::menu),
                    tooltip::Position::Top,
                )
                .into()
            }
            None => row![icon(Icon::Shield, 16.0), muted("Sandboxed")].spacing(6).align_y(Alignment::Center).into(),
        };
        col = col.push(container(shield).padding(Padding::from([6, 8])));
        container(col).width(210).height(Length::Fill).style(style::sidebar).into()
    }

    fn view_list(&self) -> Element<'_, Message> {
        let in_archive = matches!(self.location, Location::Archive { .. });
        let show_packed = in_archive && self.rows.iter().any(|r| r.packed.is_some());
        let (key, asc) = self.sort;
        let head = |name: &'static str, k: SortKey, w: Length, right: bool| -> Element<Message> {
            let arrow = if key == k { if asc { " ▲" } else { " ▼" } } else { "" };
            button(text(format!("{name}{arrow}")).size(12).font(INTER_SEMI).width(Length::Fill).align_x(if right { Horizontal::Right } else { Horizontal::Left }))
                .width(w)
                .padding(Padding::from([5, 6]))
                .style(style::header_button)
                .on_press(Message::Sort(k))
                .into()
        };
        let mut header = WRow::new().spacing(0).padding(Padding::from([0, 12]));
        header = header.push(space().width(30));
        header = header.push(head("Name", SortKey::Name, Length::Fill, false));
        header = header.push(head("Size", SortKey::Size, Length::Fixed(100.0), true));
        if show_packed {
            header = header.push(head("Packed", SortKey::Packed, Length::Fixed(100.0), true));
        }
        header = header.push(head("Modified", SortKey::Modified, Length::Fixed(160.0), false));
        header = header.push(head(if in_archive { "Method" } else { "Type" }, SortKey::Type, Length::Fixed(if in_archive { 150.0 } else { 120.0 }), false));
        let header = container(header).width(Length::Fill).style(style::list_header);

        let n = self.rows.len();
        let body: Element<Message> = if n == 0 {
            let msg = if in_archive { "This folder of the archive is empty." } else { "This folder is empty. Drop files here to compress them." };
            mouse_area(container(muted(msg)).center(Length::Fill)).on_right_press(Message::BackgroundRight).into()
        } else {
            let h = if self.view_h > 0.0 { self.view_h } else { 1200.0 };
            let first = ((self.scroll_y / ROW_H).floor() as usize).saturating_sub(4).min(n);
            let last = (((self.scroll_y + h) / ROW_H).ceil() as usize + 4).min(n);
            let mut col = Column::new().padding(Padding::from([4, 8]));
            col = col.push(space().height(first as f32 * ROW_H));
            for i in first..last {
                col = col.push(self.view_row(i, in_archive, show_packed));
            }
            col = col.push(space().height((n - last) as f32 * ROW_H));
            let list = scrollable(col).id(crate::app::LIST_ID).on_scroll(Message::Scrolled).height(Length::Fill).width(Length::Fill).style(style::scroll);
            mouse_area(list).on_right_press(Message::BackgroundRight).into()
        };
        let mut col = column![header, body].height(Length::Fill);
        if let Some((msg, _, err)) = &self.toast {
            let err = *err;
            col = col.push(
                container(
                    container(row![icon(if err { Icon::Warning } else { Icon::Test }, 18.0), text(msg.clone()).size(13)].spacing(10).align_y(Alignment::Center))
                        .padding(Padding::from([10, 14]))
                        .style(style::menu),
                )
                .width(Length::Fill)
                .align_x(Horizontal::Center)
                .padding(10),
            );
        }
        container(col).width(Length::Fill).height(Length::Fill).style(style::list_area).into()
    }

    fn view_row(&self, i: usize, in_archive: bool, show_packed: bool) -> Element<'_, Message> {
        let r = &self.rows[i];
        let selected = self.selected.contains(&i);
        let focused = self.focus == Some(i);
        let size = r.size.map(human_size).unwrap_or_default();
        let mut name_row = WRow::new().spacing(6).align_y(Alignment::Center);
        let name_txt = text(r.display.clone()).size(14).wrapping(text::Wrapping::None);
        name_row = name_row.push(if r.hidden { name_txt.style(|t: &iced::Theme| text::Style { color: Some(style::muted_text(t)) }) } else { name_txt });
        if r.encrypted {
            name_row = name_row.push(icon(Icon::Lock, 13.0));
        }
        if r.suspicious {
            name_row = name_row.push(tooltip(icon(Icon::Warning, 14.0), container(text("This name contains hidden characters that can disguise the real file type.").size(12)).padding(6).max_width(260).style(style::menu), tooltip::Position::Right));
        }
        let mut cells = WRow::new().spacing(0).align_y(Alignment::Center).height(ROW_H);
        cells = cells.push(container(icon(r.kind.icon(), 20.0)).width(30).align_x(Horizontal::Center));
        cells = cells.push(container(name_row).width(Length::Fill).padding(Padding::from([0, 6])).clip(true));
        cells = cells.push(container(text(size).size(13)).width(100).align_x(Horizontal::Right).padding(Padding::from([0, 6])));
        if show_packed {
            cells = cells.push(container(text(r.packed.map(human_size).unwrap_or_default()).size(13)).width(100).align_x(Horizontal::Right).padding(Padding::from([0, 6])));
        }
        cells = cells.push(container(text(r.mtime.map(format_local_time).unwrap_or_default()).size(13)).width(160).padding(Padding::from([0, 6])));
        let typ = if in_archive { if r.is_dir { String::new() } else { r.method.clone().unwrap_or_default() } } else { listing::type_label(r) };
        cells = cells.push(container(text(typ).size(13).wrapping(text::Wrapping::None)).width(if in_archive { 150 } else { 120 }).padding(Padding::from([0, 6])).clip(true));
        let odd = i % 2 == 1;
        let styled = container(cells).padding(Padding::from([0, 4])).style(move |t: &iced::Theme| {
            let mut s = style::row(t, selected, odd);
            if focused && !selected {
                s.border = iced::Border { color: style::with_alpha(t.palette().primary, 0.5), width: 1.0, radius: 6.0.into() };
            }
            s
        });
        mouse_area(styled).on_press(Message::RowClick(i)).on_double_click(Message::RowDouble(i)).on_right_press(Message::RowRight(i)).into()
    }

    fn view_status(&self) -> Element<'_, Message> {
        let n = self.rows.len();
        let sel: Vec<&listing::Row> = self.selected.iter().filter_map(|&i| self.rows.get(i)).collect();
        let left = if sel.is_empty() {
            format!("{n} {}", if n == 1 { "item" } else { "items" })
        } else {
            let total: u64 = zip67_core::util::total_size(sel.iter().filter_map(|r| r.size));
            format!("{} of {n} selected · {}", sel.len(), human_size(total))
        };
        let right = match &self.location {
            Location::Dir(d) => zip67_core::extract::free_space(d).map(|f| format!("{} free", human_size(f))).unwrap_or_default(),
            Location::Archive { stack, .. } => stack
                .last()
                .map(|a| {
                    let mut parts = vec![human_size(a.info.physical_size)];
                    if let Some(m) = a.info.methods.first() {
                        parts.push(m.clone());
                    }
                    if a.info.solid {
                        parts.push("solid".into());
                    }
                    if a.info.volumes > 1 {
                        parts.push(format!("{} parts", a.info.volumes));
                    }
                    if a.nested {
                        parts.push("inside another archive".into());
                    }
                    parts.join(" · ")
                })
                .unwrap_or_default(),
        };
        let mut r = row![text(left).size(12), space().width(Length::Fill)].spacing(12).align_y(Alignment::Center);
        if let Some(job) = &self.job {
            if job.background {
                let pct = if job.snap.total > 0 { job.snap.done as f32 / job.snap.total as f32 } else { 0.0 };
                r = r.push(text(job.title.clone()).size(12));
                r = r.push(container(progress_bar(0.0..=1.0, pct).girth(6)).width(140));
                if !matches!(job.purpose, crate::app::Purpose::Open { .. }) {
                    r = r.push(button(text("Show").size(12)).padding(Padding::from([2, 8])).style(style::secondary_button).on_press(Message::JobBackground(false)));
                }
            }
        }
        if let Some((t, _)) = &self.fs_job {
            r = r.push(text(format!("{t}…")).size(12));
        }
        r = r.push(text(right).size(12));
        container(r).padding(Padding::from([5, 14])).width(Length::Fill).style(style::status_bar).into()
    }

    fn view_progress<'a>(&'a self, job: &'a crate::app::Job) -> Element<'a, Message> {
        let s = &job.snap;
        let pct = if s.total > 0 { (s.done as f64 / s.total as f64).min(1.0) } else { 0.0 };
        let secs = job.started.elapsed().as_secs_f64().max(0.001);
        let speed = s.done as f64 / secs;
        let finishing = s.total > 0 && s.done >= s.total;
        let left = if pct > 0.01 && speed > 0.0 && !finishing { Some(((s.total.saturating_sub(s.done)) as f64 / speed) as u64) } else { None };
        let fmt_t = |t: u64| format!("{:02}:{:02}:{:02}", t / 3600, (t / 60) % 60, t % 60);
        let stat = |k: &'a str, v: String| -> Element<'a, Message> { row![container(muted(k)).width(110), text(v).size(13)].into() };
        let current = if finishing && secs > 1.0 { "Compressing the last blocks…".to_string() } else { safe_display(&s.current) };
        column![
            row![icon(Icon::Archive, 28.0), text(job.title.clone()).size(18).font(INTER_SEMI)].spacing(12).align_y(Alignment::Center),
            container(text(current).size(13).wrapping(text::Wrapping::None)).clip(true).width(Length::Fill),
            progress_bar(0.0..=1.0, pct as f32).girth(10),
            row![
                column![
                    stat("Elapsed", fmt_t(secs as u64)),
                    stat("Remaining", left.map(fmt_t).unwrap_or_else(|| if finishing { "finishing…".into() } else { "—".into() })),
                    stat("Speed", format!("{}/s", human_size(speed as u64))),
                ]
                .spacing(4)
                .width(Length::Fill),
                column![
                    stat("Processed", format!("{} / {}", human_size(s.done), human_size(s.total))),
                    stat("Files", format!("{} / {}", s.files_done, s.files_total)),
                    stat("Progress", format!("{:.0}%", pct * 100.0)),
                ]
                .spacing(4)
                .width(Length::Fill),
            ],
            row![
                space().width(Length::Fill),
                secondary("Background", Message::JobBackground(true)),
                secondary(if job.paused { "Resume" } else { "Pause" }, Message::JobPause),
                danger("Cancel", Message::JobCancel),
            ]
            .spacing(8),
        ]
        .spacing(14)
        .into()
    }

    fn title_row<'a>(ic: Icon, title: impl text::IntoFragment<'a>) -> Element<'a, Message> {
        row![icon(ic, 26.0), text(title).size(18).font(INTER_SEMI), space().width(Length::Fill), button(icon(Icon::Close, 14.0)).padding(6).style(style::tool_button).on_press(Message::CloseModal)]
            .spacing(12)
            .align_y(Alignment::Center)
            .into()
    }

    fn view_modal<'a>(&'a self, modal: &'a Modal) -> (Element<'a, Message>, f32) {
        match modal {
            Modal::Add(f) => (self.view_add(f), 620.0),
            Modal::Extract(f) => (self.view_extract(f), 600.0),
            Modal::Password { prompt, value, show, .. } => (
                column![
                    Self::title_row(Icon::Lock, "Password"),
                    label(prompt.clone()),
                    row![
                        input("Password", value, Message::PwInput).secure(!*show).on_submit(Message::PwOk).id("password"),
                        button(icon(Icon::Eye, 18.0)).padding(7).style(style::tool_button).on_press(Message::PwShow(!*show))
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                    row![space().width(Length::Fill), secondary("Cancel", Message::CloseModal), primary("OK", Some(Message::PwOk))].spacing(8),
                ]
                .spacing(14)
                .into(),
                440.0,
            ),
            Modal::Overwrite(q) => (
                column![
                    Self::title_row(Icon::Warning, "File already exists"),
                    text(safe_display(&q.path)).size(14).font(INTER_SEMI),
                    row![
                        column![muted("Existing file"), text(human_size(q.existing_size)).size(13), text(q.existing_mtime.map(format_local_time).unwrap_or_default()).size(13)].spacing(2).width(Length::Fill),
                        column![muted("New file from the archive"), text(human_size(q.new_size)).size(13), text(q.new_mtime.map(format_local_time).unwrap_or_default()).size(13)].spacing(2).width(Length::Fill),
                    ],
                    row![
                        primary("Replace", Some(Message::Answer(zip67_core::extract::Answer::Yes))),
                        secondary("Replace all", Message::Answer(zip67_core::extract::Answer::YesToAll)),
                        secondary("Skip", Message::Answer(zip67_core::extract::Answer::No)),
                        secondary("Skip all", Message::Answer(zip67_core::extract::Answer::NoToAll)),
                    ]
                    .spacing(8),
                    row![
                        secondary("Keep both", Message::Answer(zip67_core::extract::Answer::Rename)),
                        secondary("Keep both for all", Message::Answer(zip67_core::extract::Answer::RenameAll)),
                        space().width(Length::Fill),
                        danger("Stop", Message::Answer(zip67_core::extract::Answer::Cancel)),
                    ]
                    .spacing(8),
                ]
                .spacing(14)
                .into(),
                580.0,
            ),
            Modal::TempOnDisk { folder, dont_warn } => (
                column![
                    Self::title_row(Icon::Info, "Decrypted file stored on disk".to_string()),
                    label(format!(
                        "The file you opened from an encrypted archive was decrypted into a temporary folder on the disk ({}), because this system has no temporary folder in memory.\n\n67zip overwrites and deletes it when it closes. SSDs and some file systems (btrfs, ZFS) may still keep old copies; full-disk encryption protects against that.",
                        zip67_core::util::safe_display(folder)
                    )),
                    checkbox(*dont_warn).label("Don't warn me again").on_toggle(Message::TempNoticeDontWarn).text_size(13),
                    row![space().width(Length::Fill), primary("OK", Some(Message::TempNoticeOk))].spacing(8),
                ]
                .spacing(16)
                .into(),
                520.0,
            ),
            Modal::Confirm { title, text: t, ok, danger: d, .. } => (
                column![
                    Self::title_row(if *d { Icon::Delete } else { Icon::Info }, title.clone()),
                    label(t.clone()),
                    row![space().width(Length::Fill), secondary("Cancel", Message::CloseModal), if *d { danger(ok, Message::ConfirmOk) } else { primary(ok, Some(Message::ConfirmOk)) }].spacing(8),
                ]
                .spacing(16)
                .into(),
                460.0,
            ),
            Modal::Input { title, label: l, value, error, .. } => {
                let mut c = column![Self::title_row(Icon::Rename, title.clone()), field(l, input("", value, Message::InputChanged).on_submit(Message::InputOk).id("modal-input"))].spacing(14);
                if let Some(e) = error {
                    if !e.is_empty() {
                        c = c.push(text(e.clone()).size(13).style(|t: &iced::Theme| text::Style { color: Some(t.palette().danger) }));
                    }
                }
                c = c.push(row![space().width(Length::Fill), secondary("Cancel", Message::CloseModal), primary("OK", Some(Message::InputOk))].spacing(8));
                (c.into(), 500.0)
            }
            Modal::Report(r) => {
                let mut lines = Column::new().spacing(4);
                for l in r.lines.iter().take(500) {
                    lines = lines.push(text(l.clone()).size(12));
                }
                let mut c = column![Self::title_row(if r.ok { Icon::Test } else { Icon::Warning }, r.title.clone())].spacing(12);
                if !r.summary.is_empty() {
                    c = c.push(label(r.summary.clone()));
                }
                if !r.lines.is_empty() {
                    c = c.push(container(scrollable(lines).height(Length::Fixed(220.0)).style(style::scroll)).padding(10).style(style::address));
                    c = c.push(row![button(text("Copy details").size(13)).padding(Padding::from([6, 12])).style(style::secondary_button).on_press(Message::CopyText(r.lines.join("\n")))]);
                }
                c = c.push(row![space().width(Length::Fill), primary("Close", Some(Message::CloseModal))]);
                (c.into(), 600.0)
            }
            Modal::Properties { title, lines, warning } => {
                let mut c = column![Self::title_row(Icon::Info, title.clone())].spacing(8);
                for (k, v) in lines {
                    if k.is_empty() {
                        c = c.push(rule::horizontal(1).style(style::rule));
                    } else {
                        c = c.push(row![container(muted(k.clone())).width(130), text(v.clone()).size(13).width(Length::Fill)].spacing(10));
                    }
                }
                if let Some(w) = warning {
                    c = c.push(container(row![icon(Icon::Warning, 18.0), text(w.clone()).size(12)].spacing(8)).padding(10).style(style::warning_box));
                }
                c = c.push(row![space().width(Length::Fill), primary("Close", Some(Message::CloseModal))]);
                (c.into(), 560.0)
            }
            Modal::Hashes(v, kinds) => {
                let mut col = Column::new().spacing(10);
                let mut all = String::new();
                for h in v.iter().take(1000) {
                    let name = safe_display(&h.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
                    let mut c = column![row![text(name.clone()).size(13).font(INTER_SEMI), space().width(Length::Fill), muted(human_size(h.size))]].spacing(2);
                    if let Some(e) = &h.error {
                        c = c.push(text(e.clone()).size(12));
                    }
                    for (k, val) in &h.values {
                        all.push_str(&format!("{}  {val}  {name}\n", k.name()));
                        c = c.push(
                            row![container(muted(k.name())).width(70), text(val.clone()).size(12).font(Font::MONOSPACE).width(Length::Fill), button(text("Copy").size(11)).padding(Padding::from([2, 8])).style(style::secondary_button).on_press(Message::CopyText(val.clone()))]
                                .spacing(8)
                                .align_y(Alignment::Center),
                        );
                    }
                    col = col.push(c);
                }
                let _ = kinds;
                (
                    column![
                        Self::title_row(Icon::Hash, "Checksums"),
                        container(scrollable(col).height(Length::Fixed(320.0)).style(style::scroll)).padding(10).style(style::address),
                        row![button(text("Copy all").size(13)).padding(Padding::from([6, 12])).style(style::secondary_button).on_press(Message::CopyText(all)), space().width(Length::Fill), primary("Close", Some(Message::CloseModal))]
                    ]
                    .spacing(12)
                    .into(),
                    720.0,
                )
            }
            Modal::Bench(res) => {
                let mut c = column![Self::title_row(Icon::Bench, "Benchmark")].spacing(12);
                match res {
                    None => {
                        c = c.push(label(format!("Measures how fast this computer compresses and decompresses with each method, using {} threads. Takes about half a minute.", zip67_core::util::default_threads())));
                        c = c.push(row![space().width(Length::Fill), secondary("Close", Message::CloseModal), primary("Start", Some(Message::RunBenchmark))].spacing(8));
                    }
                    Some(v) => {
                        let hdr = row![container(muted("Method")).width(Length::Fill), container(muted("Threads")).width(70), container(muted("Compress")).width(110), container(muted("Decompress")).width(110), container(muted("Ratio")).width(70)];
                        let mut t = column![hdr].spacing(6);
                        for r in v {
                            t = t.push(row![
                                text(r.method.clone()).size(13).width(Length::Fill),
                                text(r.threads.to_string()).size(13).width(70),
                                text(format!("{:.1} MB/s", r.compress_mbps)).size(13).width(110),
                                text(format!("{:.1} MB/s", r.decompress_mbps)).size(13).width(110),
                                text(format!("{:.1}%", r.ratio)).size(13).width(70),
                            ]);
                        }
                        c = c.push(t);
                        c = c.push(row![space().width(Length::Fill), secondary("Run again", Message::RunBenchmark), primary("Close", Some(Message::CloseModal))].spacing(8));
                    }
                }
                (c.into(), 620.0)
            }
            Modal::Settings => (self.view_settings(), 600.0),
            Modal::About => {
                let sandbox = self.sandbox.as_ref().map(|s| s.describe()).unwrap_or_else(|| "Archives are opened in a separate, locked-down worker process. Open an archive to see the sandbox status.".into());
                (
                    column![
                        row![icon(Icon::Logo, 64.0), column![text("67zip").size(28).font(INTER_SEMI), muted(format!("Version {}", zip67_core::VERSION))].spacing(2), space().width(Length::Fill), button(icon(Icon::Close, 14.0)).padding(6).style(style::tool_button).on_press(Message::CloseModal)]
                            .spacing(16)
                            .align_y(Alignment::Center),
                        label("A fast, secure archive manager for Linux. Our own engine is written in safe Rust: 7z, zip, tar and more."),
                        row![icon(Icon::Shield, 18.0), text(sandbox).size(13)].spacing(8),
                        muted("License: MIT. Interface font: Inter (SIL Open Font License)."),
                        row![space().width(Length::Fill), primary("Close", Some(Message::CloseModal))],
                    ]
                    .spacing(14)
                    .into(),
                    520.0,
                )
            }
        }
    }

    fn view_add<'a>(&'a self, f: &'a AddForm) -> Element<'a, Message> {
        let into = f.into.is_some();
        let what = match f.sources.as_slice() {
            [one] => safe_display(&one.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
            v => format!("{} items", v.len()),
        };
        let mut c = column![Self::title_row(Icon::Add, if into { "Add to this archive" } else { "Add to archive" }), muted(format!("Adding {what}"))].spacing(12);
        if !into {
            c = c.push(field(
                "Archive",
                row![input("Archive file", &f.archive, Message::AddArchive).width(Length::Fill), secondary("Browse…", Message::AddBrowse)].spacing(6),
            ));
            c = c.push(field("Format", pick_list(FORMATS, Some(f.format), Message::AddFormat).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)));
        }
        c = c.push(field("Compression", pick_list(LEVELS, Some(f.level), Message::AddLevel).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)));
        if !into && matches!(f.format.0, "7z" | "zip") {
            c = c.push(field("Method", pick_list(f.methods(), Some(f.method), Message::AddMethod).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)));
        }
        if !into && f.format.0 == "7z" {
            c = c.push(field("", checkbox(f.solid).label("Solid archive (smaller, slower to extract single files)").on_toggle(Message::AddSolid).text_size(13)));
        }
        if into {
            let note = match f.into.as_ref().and_then(|i| i.password.as_ref()) {
                Some(_) => "The added files get this archive's password.",
                None => "This archive has no password, so the added files won't have one either. To protect files, create a new archive with \"Add to zip with a password…\".",
            };
            c = c.push(row![icon(Icon::Lock, 16.0), muted(note)].spacing(8).align_y(Alignment::Center));
        } else {
            c = c.push(rule::horizontal(1).style(style::rule));
            // Always shown, so the option is easy to find: greyed out for formats without encryption.
            let protect = checkbox(f.protect && f.encryptable()).label("Protect with a password").text_size(14);
            let protect = if f.encryptable() { protect.on_toggle(Message::AddProtect) } else { protect };
            c = c.push(field("Encryption", row![icon(Icon::Lock, 18.0), protect].spacing(8).align_y(Alignment::Center)));
            if !f.encryptable() {
                c = c.push(field("", muted("Only 7z and zip archives can have a password.")));
            } else if f.protect {
                c = c.push(field(
                    "Password",
                    row![
                        input("Type a password", &f.password, Message::AddPassword).secure(!f.show_password).id(ADD_PASSWORD_ID).width(Length::Fill),
                        button(icon(Icon::Eye, 18.0)).padding(7).style(style::tool_button).on_press(Message::AddShowPassword(!f.show_password))
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                ));
                if !f.show_password {
                    c = c.push(field("Repeat", input("Type it again", &f.password2, Message::AddPassword2).secure(true)));
                }
                let note = if f.format.0 == "7z" {
                    "AES-256 encryption. With 7z you can also hide the file names."
                } else {
                    "AES-256 encryption (WinZip format, detects tampering). 7-Zip, 67zip and most archive apps open it; Windows Explorer can't."
                };
                c = c.push(field("", muted(note)));
                if f.format.0 == "7z" {
                    c = c.push(field("", checkbox(f.encrypt_names).label("Encrypt file names too").on_toggle(Message::AddEncryptNames).text_size(13)));
                }
            }
        }
        if !into {
            c = c.push(rule::horizontal(1).style(style::rule));
            c = c.push(field("Split into", pick_list(VOLUMES, Some(f.volume), Message::AddVolume).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)));
            c = c.push(field("Leave out", input("e.g. *.tmp, .git, node_modules", &f.exclude, Message::AddExclude)));
            c = c.push(field("", checkbox(f.delete_after).label("Delete the files after they were added").on_toggle(Message::AddDeleteAfter).text_size(13)));
            if f.delete_after {
                c = c.push(field(
                    "",
                    checkbox(f.shred)
                        .label("Securely: overwrite them with random data first (not reliable on SSDs and btrfs/ZFS)")
                        .on_toggle(Message::AddShred)
                        .text_size(13),
                ));
            }
        }
        if let Some(e) = &f.error {
            c = c.push(text(e.clone()).size(13).style(|t: &iced::Theme| text::Style { color: Some(t.palette().danger) }));
        }
        c = c.push(row![space().width(Length::Fill), secondary("Cancel", Message::CloseModal), primary(if into { "Add" } else { "Create" }, Some(Message::AddOk))].spacing(8));
        c.into()
    }

    fn view_extract<'a>(&'a self, f: &'a ExtractForm) -> Element<'a, Message> {
        let what = if let Some((_, sel, _)) = &f.selection {
            match sel {
                zip67_core::extract::Selection::All => "the whole archive".to_string(),
                zip67_core::extract::Selection::Paths(p) if p.len() == 1 => safe_display(p[0].rsplit('/').next().unwrap_or("")),
                zip67_core::extract::Selection::Paths(p) => format!("{} selected items", p.len()),
                _ => "the selection".into(),
            }
        } else {
            match f.archives.as_slice() {
                [one] => safe_display(&one.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
                v => format!("{} archives", v.len()),
            }
        };
        let sub_name = if let Some(a) = self.current_archive().filter(|_| f.selection.is_some()) {
            crate::app::stem_of(&std::path::Path::new(&a.display).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
        } else {
            match f.archives.as_slice() {
                [one] => crate::app::stem_of(&one.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
                _ => "<archive name>".into(),
            }
        };
        let mut c = column![Self::title_row(Icon::Extract, "Extract"), muted(format!("Extracting {what}"))].spacing(12);
        c = c.push(field("Destination", row![input("Folder", &f.dest, Message::ExDest).width(Length::Fill), secondary("Browse…", Message::ExBrowse)].spacing(6)));
        c = c.push(field("", checkbox(f.subfolder).label(format!("Into a new folder \"{}\"", safe_display(&sub_name))).on_toggle(Message::ExSubfolder).text_size(13)));
        c = c.push(field("Folders", pick_list(PATH_MODES, Some(f.path_mode), Message::ExPathMode).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)));
        c = c.push(field("Existing files", pick_list(OVERWRITES, Some(f.overwrite), Message::ExOverwrite).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)));
        c = c.push(field(
            "Password",
            row![
                input("Only if the archive is encrypted", &f.password, Message::ExPassword).secure(!f.show_password).width(Length::Fill),
                button(icon(Icon::Eye, 18.0)).padding(7).style(style::tool_button).on_press(Message::ExShowPassword(!f.show_password))
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        ));
        if let Some(e) = &f.error {
            c = c.push(text(e.clone()).size(13).style(|t: &iced::Theme| text::Style { color: Some(t.palette().danger) }));
        }
        c = c.push(
            container(row![icon(Icon::Shield, 16.0), muted("Files can only be written inside the destination folder. Links that point outside it are not created.")].spacing(8).align_y(Alignment::Center))
                .padding(Padding::from([4, 0])),
        );
        c = c.push(row![space().width(Length::Fill), secondary("Cancel", Message::CloseModal), primary("Extract", Some(Message::ExOk))].spacing(8));
        c.into()
    }

    fn view_settings(&self) -> Element<'_, Message> {
        let s = &self.settings;
        let theme_btn = |name: &'static str, t: ThemeChoice| -> Element<Message> {
            let active = s.theme == t;
            button(text(name).size(13))
                .padding(Padding::from([6, 14]))
                .style(move |th: &iced::Theme, st| if active { style::primary_button(th, st) } else { style::secondary_button(th, st) })
                .on_press(Message::SetTheme(t))
                .into()
        };
        let mut swatches = WRow::new().spacing(8).align_y(Alignment::Center);
        let sys_active = s.accent.is_none();
        swatches = swatches.push(
            button(text("System").size(12))
                .padding(Padding::from([5, 10]))
                .style(move |th: &iced::Theme, st| if sys_active { style::primary_button(th, st) } else { style::secondary_button(th, st) })
                .on_press(Message::SetAccent(None)),
        );
        for (name, color) in style::ACCENTS {
            let active = s.accent.as_deref() == Some(name);
            swatches = swatches.push(
                tooltip(
                    button(space().width(18).height(18))
                        .padding(0)
                        .style(move |th: &iced::Theme, _st| iced::widget::button::Style {
                            background: Some(iced::Background::Color(color)),
                            border: iced::Border { color: if active { th.palette().text } else { color }, width: if active { 2.5 } else { 0.0 }, radius: 999.0.into() },
                            ..Default::default()
                        })
                        .on_press(Message::SetAccent(Some(name.to_string()))),
                    container(text(name).size(12)).padding(5).style(style::menu),
                    tooltip::Position::Top,
                ),
            );
        }
        let scales = [Choice(90u32, "90%"), Choice(100, "100%"), Choice(110, "110%"), Choice(125, "125%"), Choice(150, "150%")];
        let cur_scale = scales.iter().copied().find(|c| c.0 == (s.scale * 100.0).round() as u32).unwrap_or(scales[1]);
        column![
            Self::title_row(Icon::Settings, "Settings"),
            field("Appearance", row![theme_btn("System", ThemeChoice::System), theme_btn("Light", ThemeChoice::Light), theme_btn("Dark", ThemeChoice::Dark)].spacing(6)),
            field("Accent colour", swatches),
            field("Size", pick_list(scales, Some(cur_scale), Message::SetScale).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu)),
            rule::horizontal(1).style(style::rule),
            field("", checkbox(s.show_hidden).label("Show hidden files (Ctrl+H)").on_toggle(Message::SetShowHidden).text_size(13)),
            field("", checkbox(s.use_trash).label("Delete moves files to the Trash").on_toggle(Message::SetUseTrash).text_size(13)),
            field("", checkbox(s.confirm_delete).label("Ask before deleting").on_toggle(Message::SetConfirmDelete).text_size(13)),
            field(
                "",
                checkbox(s.warn_temp_on_disk)
                    .label("Warn when a file from an encrypted archive has to be decrypted onto the disk")
                    .on_toggle(Message::SetWarnTempOnDisk)
                    .text_size(13)
            ),
            rule::horizontal(1).style(style::rule),
            field("New archives", pick_list(FORMATS, FORMATS.iter().copied().find(|f| f.0 == s.default_format), Message::SetDefaultFormat).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)),
            field("Compression", pick_list(LEVELS, LEVELS.iter().copied().find(|l| l.0 == s.default_level), Message::SetDefaultLevel).text_size(14).padding(Padding::from([7, 10])).style(style::pick).menu_style(style::pick_menu).width(Length::Fill)),
            row![space().width(Length::Fill), primary("Done", Some(Message::CloseModal))],
        ]
        .spacing(12)
        .align_x(Horizontal::Left)
        .into()
    }
}

#[allow(dead_code)]
fn _unused(_: Vertical) {}
