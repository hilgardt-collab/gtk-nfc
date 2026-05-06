use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::nfc::{
    self, watcher::ReaderWatcher, Backend, Command, Event, KeyType, MifareDump, Reader, ReaderId,
    SectorRead, TagInfo, WriteMode, Worker,
};

/// All the per-window state the event loop needs to mutate. Held in `Rc`s
/// so it can be shared across closures driven by the GTK main loop.
struct UiState {
    worker: Rc<Worker>,
    selected_reader: RefCell<Option<ReaderId>>,
    current_dump: RefCell<Option<MifareDump>>,
    // Buttons whose sensitivity tracks state.
    read_uid_btn: gtk::Button,
    dump_btn: gtk::Button,
    save_btn: gtk::Button,
    write_btn: gtk::Button,
    // Content widgets. dump_page lets us hide/show the Dump tab in the
    // ViewSwitcher based on whether a dump is loaded — there's nothing
    // useful to navigate to until one exists.
    view_stack: adw::ViewStack,
    dump_page: adw::ViewStackPage,
    status_page: adw::StatusPage,
    dump_buffer: gtk::TextBuffer,
    toast_overlay: adw::ToastOverlay,
    // Sidebar saved-dumps section. The ListBox shows .mfd files in
    // dumps_dir(); dump_paths is the parallel index from row position
    // back to filesystem path (ListBox doesn't carry per-row data).
    dump_list: gtk::ListBox,
    dump_paths: RefCell<Vec<PathBuf>>,
    // Per-reader auto-read watcher. Replaced when reader selection
    // changes; None when no reader is selected or selection is libnfc
    // (we only watch PC/SC, see watcher.rs).
    watcher: RefCell<Option<ReaderWatcher>>,
}

impl UiState {
    fn refresh_buttons(&self) {
        let has_reader = self.selected_reader.borrow().is_some();
        let has_dump = self.current_dump.borrow().is_some();
        self.read_uid_btn.set_sensitive(has_reader);
        self.dump_btn.set_sensitive(has_reader);
        self.save_btn.set_sensitive(has_dump);
        self.write_btn.set_sensitive(has_reader && has_dump);
        // Dump tab in the ViewSwitcher tracks dump availability — hidden
        // entirely when there's nothing to show, so the switcher is just
        // a single "Status" tab on a fresh launch.
        self.dump_page.set_visible(has_dump);
    }

    fn show_status(&self, icon: &str, title: &str, description: &str) {
        self.status_page.set_icon_name(Some(icon));
        self.status_page.set_title(title);
        self.status_page.set_description(Some(description));
        self.view_stack.set_visible_child_name("status");
    }

    fn show_dump(&self, dump: &MifareDump) {
        self.dump_buffer.set_text(&format_dump(dump));
        self.dump_page.set_visible(true);
        self.view_stack.set_visible_child_name("dump");
    }

    fn show_toast(&self, message: &str) {
        let toast = adw::Toast::new(message);
        toast.set_timeout(5);
        self.toast_overlay.add_toast(toast);
    }

    /// Re-scan dumps_dir() and rebuild the sidebar list. Cheap to call
    /// — handful of dirent reads — so we just trigger it on app start
    /// and after every successful save.
    fn refresh_dump_list(&self) {
        populate_dump_list(&self.dump_list, &self.dump_paths, &list_saved_dumps());
    }

    fn suspend_watcher(&self) {
        if let Some(w) = self.watcher.borrow().as_ref() {
            w.suspend();
        }
    }

    fn resume_watcher(&self) {
        if let Some(w) = self.watcher.borrow().as_ref() {
            w.resume();
        }
    }

    /// Re-parse the editable dump buffer back into a MifareDump. The
    /// `current_dump` in memory is the source for sector-read metadata
    /// (since user edits don't tell us anything new about which keys
    /// authed); the parsed bytes come from whatever the user has typed.
    /// Returns an error if no dump is loaded or if the buffer text is
    /// malformed.
    fn parse_buffer(&self) -> anyhow::Result<MifareDump> {
        let base_ref = self.current_dump.borrow();
        let base = base_ref
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no dump loaded"))?;
        let (start, end) = self.dump_buffer.bounds();
        let text = self.dump_buffer.text(&start, &end, false);
        parse_dump_text(text.as_str(), base)
    }
}

pub fn build(app: &adw::Application) -> adw::ApplicationWindow {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("gtk-nfc")
        .default_width(1080)
        .default_height(720)
        .build();

    let mut backends: Vec<Box<dyn Backend>> = Vec::new();
    backends.push(Box::new(nfc::pcsc_backend::PcscBackend::new()));
    #[cfg(feature = "libnfc")]
    match nfc::libnfc_backend::LibNfcBackend::new() {
        Ok(b) => backends.push(Box::new(b)),
        Err(e) => log::warn!("libnfc backend unavailable: {}", e),
    }

    let (event_tx, event_rx) = async_channel::unbounded::<Event>();
    let worker = Rc::new(Worker::spawn(backends, event_tx));

    // ----- Header / sidebar -----

    let header = adw::HeaderBar::new();
    let refresh = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Rescan for readers")
        .build();
    header.pack_start(&refresh);

    let reader_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();
    reader_list.set_placeholder(Some(&placeholder_row("No readers detected")));

    let dump_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();
    dump_list.set_placeholder(Some(&placeholder_row("No saved dumps")));

    let sidebar_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    sidebar_box.append(&section_header("Readers"));
    sidebar_box.append(&reader_list);
    sidebar_box.append(&section_header("Saved dumps"));
    sidebar_box.append(&dump_list);

    let sidebar_scroll = gtk::ScrolledWindow::builder()
        .child(&sidebar_box)
        .vexpand(true)
        .build();
    let sidebar_page = adw::NavigationPage::builder()
        .title("Sources")
        .tag("readers")
        .child(&sidebar_scroll)
        .build();

    // ----- Content: action bar + stack -----

    let read_uid_btn = gtk::Button::with_label("Read UID");
    let dump_btn = gtk::Button::with_label("Dump 1K");
    let load_btn = gtk::Button::with_label("Load .mfd…");
    let save_btn = gtk::Button::with_label("Save .mfd…");
    let write_btn = gtk::Button::with_label("Write to tag");
    write_btn.add_css_class("suggested-action");
    for b in [&read_uid_btn, &dump_btn, &save_btn, &write_btn] {
        b.set_sensitive(false);
    }

    let action_bar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(12)
        .margin_end(12)
        .build();
    action_bar.append(&read_uid_btn);
    action_bar.append(&dump_btn);
    let spacer = gtk::Box::builder()
        .hexpand(true)
        .orientation(gtk::Orientation::Horizontal)
        .build();
    action_bar.append(&spacer);
    action_bar.append(&load_btn);
    action_bar.append(&save_btn);
    action_bar.append(&write_btn);

    let status_page = adw::StatusPage::builder()
        .icon_name("media-removable-symbolic")
        .title("No reader selected")
        .description("Pick a reader on the left to read or dump a tag.")
        .vexpand(true)
        .build();

    let dump_buffer = gtk::TextBuffer::new(None);
    let dump_view = gtk::TextView::builder()
        .editable(true)
        .monospace(true)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .buffer(&dump_buffer)
        .build();
    let dump_scroll = gtk::ScrolledWindow::builder()
        .child(&dump_view)
        .vexpand(true)
        .hexpand(true)
        .build();

    let view_stack = adw::ViewStack::new();
    view_stack.add_titled_with_icon(
        &status_page,
        Some("status"),
        "Status",
        "dialog-information-symbolic",
    );
    let dump_page = view_stack.add_titled_with_icon(
        &dump_scroll,
        Some("dump"),
        "Dump",
        "view-list-symbolic",
    );
    dump_page.set_visible(false);
    view_stack.set_visible_child_name("status");

    let switcher = adw::ViewSwitcher::builder()
        .stack(&view_stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();
    header.set_title_widget(Some(&switcher));

    let content_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    content_box.append(&action_bar);
    content_box.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    content_box.append(&view_stack);

    // Toast overlay sits between the content box and the navigation page so
    // we can surface parse errors etc. without flipping the stack to the
    // status view (which would visually clobber the user's edits).
    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&content_box));

    let content_page = adw::NavigationPage::builder()
        .title("Tag")
        .tag("tag")
        .child(&toast_overlay)
        .build();

    let split = adw::NavigationSplitView::builder()
        .sidebar(&sidebar_page)
        .content(&content_page)
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&split));
    window.set_content(Some(&toolbar));

    // ----- Shared state -----

    let state = Rc::new(UiState {
        worker: Rc::clone(&worker),
        selected_reader: RefCell::new(None),
        current_dump: RefCell::new(None),
        read_uid_btn: read_uid_btn.clone(),
        dump_btn: dump_btn.clone(),
        save_btn: save_btn.clone(),
        write_btn: write_btn.clone(),
        view_stack: view_stack.clone(),
        dump_page: dump_page.clone(),
        status_page: status_page.clone(),
        dump_buffer: dump_buffer.clone(),
        toast_overlay: toast_overlay.clone(),
        dump_list: dump_list.clone(),
        dump_paths: RefCell::new(Vec::new()),
        watcher: RefCell::new(None),
    });

    let row_ids: Rc<RefCell<Vec<ReaderId>>> = Rc::new(RefCell::new(Vec::new()));

    // ----- Event wiring -----

    {
        let worker = Rc::clone(&worker);
        refresh.connect_clicked(move |_| worker.send(Command::ListReaders));
    }

    {
        let state = Rc::clone(&state);
        let row_ids = Rc::clone(&row_ids);
        reader_list.connect_row_selected(move |_, row| {
            let new = row.and_then(|r| {
                let i = r.index();
                if i < 0 {
                    None
                } else {
                    row_ids.borrow().get(i as usize).cloned()
                }
            });
            *state.selected_reader.borrow_mut() = new.clone();
            state.refresh_buttons();

            // Replace the auto-read watcher to track the new selection.
            // Dropping the old one signals it to stop; spawning the new
            // one starts polling immediately so a tag already on the
            // reader gets read straight away.
            *state.watcher.borrow_mut() = match new {
                Some(reader) => ReaderWatcher::spawn(reader, state.worker.cmd_sender()),
                None => None,
            };
        });
    }

    {
        let state = Rc::clone(&state);
        dump_list.connect_row_selected(move |_, row| {
            let Some(row) = row else { return };
            let i = row.index();
            if i < 0 {
                return;
            }
            let Some(path) = state.dump_paths.borrow().get(i as usize).cloned() else {
                return;
            };
            match load_dump(&path) {
                Ok(dump) => {
                    state.show_dump(&dump);
                    *state.current_dump.borrow_mut() = Some(dump);
                    state.refresh_buttons();
                }
                Err(e) => {
                    state.show_toast(&format!("Couldn't load {}: {}", path.display(), e));
                }
            }
        });
    }

    {
        let state = Rc::clone(&state);
        read_uid_btn.connect_clicked(move |_| {
            if let Some(reader) = state.selected_reader.borrow().clone() {
                state.worker.send(Command::ReadTag { reader });
            }
        });
    }

    {
        let state = Rc::clone(&state);
        dump_btn.connect_clicked(move |_| {
            if let Some(reader) = state.selected_reader.borrow().clone() {
                state.suspend_watcher();
                state.worker.send(Command::DumpTag { reader });
            }
        });
    }

    {
        let state = Rc::clone(&state);
        let window = window.clone();
        load_btn.connect_clicked(move |_| {
            let dir = dumps_dir();
            let _ = std::fs::create_dir_all(&dir);
            let dialog = gtk::FileDialog::builder()
                .title("Load .mfd dump")
                .modal(true)
                .initial_folder(&gtk::gio::File::for_path(&dir))
                .build();
            let state = Rc::clone(&state);
            dialog.open(Some(&window), gtk::gio::Cancellable::NONE, move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else {
                    state.show_toast("Couldn't load: selected file has no local path");
                    return;
                };
                match load_dump(&path) {
                    Ok(dump) => {
                        state.show_dump(&dump);
                        *state.current_dump.borrow_mut() = Some(dump);
                        state.refresh_buttons();
                    }
                    Err(e) => state.show_toast(&format!("Couldn't load dump: {}", e)),
                }
            });
        });
    }

    {
        let state = Rc::clone(&state);
        let window = window.clone();
        save_btn.connect_clicked(move |_| {
            let dump_bytes = match state.parse_buffer() {
                Ok(d) => d.bytes,
                Err(e) => {
                    state.show_toast(&format!("Can't save: {}", e));
                    return;
                }
            };
            // Default dialog location to the saved-dumps directory; mkdir
            // it so set_initial_folder has a real target. User can still
            // navigate elsewhere — we just make the common case ergonomic.
            let dir = dumps_dir();
            let _ = std::fs::create_dir_all(&dir);
            let dialog = gtk::FileDialog::builder()
                .title("Save .mfd dump")
                .modal(true)
                .initial_name("dump.mfd")
                .initial_folder(&gtk::gio::File::for_path(&dir))
                .build();
            let state = Rc::clone(&state);
            dialog.save(Some(&window), gtk::gio::Cancellable::NONE, move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else {
                    state.show_toast("Couldn't save: chosen location has no local path");
                    return;
                };
                match std::fs::write(&path, &dump_bytes) {
                    Ok(()) => state.refresh_dump_list(),
                    Err(e) => state.show_toast(&format!("Couldn't save dump: {}", e)),
                }
            });
        });
    }

    {
        let state = Rc::clone(&state);
        write_btn.connect_clicked(move |_| {
            let reader = match state.selected_reader.borrow().clone() {
                Some(r) => r,
                None => return,
            };
            let dump = match state.parse_buffer() {
                Ok(d) => d,
                Err(e) => {
                    state.show_toast(&format!("Can't write: {}", e));
                    return;
                }
            };
            state.suspend_watcher();
            state.worker.send(Command::WriteDump { reader, dump });
        });
    }

    // ----- Worker → UI event drain -----

    {
        let state = Rc::clone(&state);
        let reader_list = reader_list.clone();
        let row_ids = Rc::clone(&row_ids);
        glib::spawn_future_local(async move {
            while let Ok(ev) = event_rx.recv().await {
                match ev {
                    Event::ReadersListed(readers) => {
                        populate_reader_list(&reader_list, &readers, &row_ids);
                    }
                    Event::ReadingTag { reader } => state.show_status(
                        "content-loading-symbolic",
                        "Reading tag…",
                        &format!("Hold a tag against “{}”.", reader.key),
                    ),
                    Event::TagRead { reader, tag } => {
                        show_tag(&state.status_page, &reader, &tag);
                        state.view_stack.set_visible_child_name("status");
                    }
                    Event::TagError { reader, message } => state.show_status(
                        "dialog-warning-symbolic",
                        "Couldn't read tag",
                        &format!("{} — {}", reader.key, message),
                    ),
                    Event::DumpStarted { reader } => state.show_status(
                        "content-loading-symbolic",
                        "Dumping tag…",
                        &format!("Reading 16 sectors from “{}”.", reader.key),
                    ),
                    Event::DumpProgress { sector, total, .. } => {
                        state.status_page.set_description(Some(&format!(
                            "Read sector {}/{}…",
                            sector, total
                        )));
                    }
                    Event::TagDumped { dump, .. } => {
                        state.show_dump(&dump);
                        *state.current_dump.borrow_mut() = Some(dump);
                        state.refresh_buttons();
                        state.resume_watcher();
                    }
                    Event::DumpError { reader, message } => {
                        state.show_status(
                            "dialog-warning-symbolic",
                            "Dump failed",
                            &format!("{} — {}", reader.key, message),
                        );
                        state.resume_watcher();
                    }
                    Event::WriteStarted { reader } => state.show_status(
                        "content-loading-symbolic",
                        "Writing tag…",
                        &format!("Writing 64 blocks to “{}”.", reader.key),
                    ),
                    Event::WriteProgress { block, total, .. } => {
                        state.status_page.set_description(Some(&format!(
                            "Wrote block {}/{}…",
                            block, total
                        )));
                    }
                    Event::WriteComplete {
                        blocks_written,
                        blocks_skipped,
                        uid_changed,
                        mode,
                        ..
                    } => {
                        let mode_label = match mode {
                            WriteMode::Gen1aBackdoor => "Gen1a backdoor",
                            WriteMode::StandardAuth => "Gen2 / standard auth",
                        };
                        let (icon, title, desc) = if !uid_changed {
                            // Block 0 didn't round-trip. Either the standard-auth
                            // path ran (so Gen1a unlock didn't ACK and the tag
                            // isn't Gen2 either — likely a non-magic blank), or
                            // we somehow got the verify auth wrong. Either way:
                            // the destination didn't accept the new UID.
                            (
                                "dialog-warning-symbolic",
                                "Write didn't take",
                                format!(
                                    "Wrote {} block(s) via {} but block 0 didn't change. \
                                     The destination isn't a writable magic blank, or its \
                                     keys differ from the dump. Use a Gen1a or Gen2 blank.",
                                    blocks_written, mode_label
                                ),
                            )
                        } else if blocks_skipped == 0 {
                            (
                                "emblem-default-symbolic",
                                match mode {
                                    WriteMode::Gen1aBackdoor => "Wrote tag (Gen1a)",
                                    WriteMode::StandardAuth => "Wrote tag (Gen2)",
                                },
                                format!(
                                    "All {} blocks written via {}. UID confirmed.",
                                    blocks_written, mode_label
                                ),
                            )
                        } else {
                            (
                                "dialog-warning-symbolic",
                                "Wrote tag with skipped blocks",
                                format!(
                                    "{} block(s) written, {} skipped via {}. \
                                     UID changed but some blocks rejected the write \
                                     (typically auth-key mismatch on a partial blank).",
                                    blocks_written, blocks_skipped, mode_label
                                ),
                            )
                        };
                        state.show_status(icon, title, &desc);
                        state.resume_watcher();
                    }
                    Event::WriteError { reader, message } => {
                        state.show_status(
                            "dialog-warning-symbolic",
                            "Write failed",
                            &format!("{} — {}", reader.key, message),
                        );
                        state.resume_watcher();
                    }
                    Event::BackendError { backend, message } => {
                        log::warn!("backend {:?}: {}", backend, message);
                    }
                }
            }
        });
    }

    worker.send(Command::ListReaders);
    state.refresh_dump_list();

    unsafe { window.set_data("nfc-worker", worker) };

    window
}

/// Where Save dialogs default to and where the sidebar's "Saved dumps"
/// section reads from. XDG data dir per-user — `~/.local/share/gtk-nfc/dumps`
/// on a typical Linux setup.
fn dumps_dir() -> PathBuf {
    glib::user_data_dir().join("gtk-nfc").join("dumps")
}

/// Sorted list of `.mfd` files in `dumps_dir()`. Returns an empty Vec if
/// the directory doesn't exist or can't be read; never errors — a missing
/// dumps dir is the normal first-run state.
fn list_saved_dumps() -> Vec<PathBuf> {
    let dir = dumps_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("mfd"))
        .collect();
    out.sort();
    out
}

fn populate_dump_list(
    list: &gtk::ListBox,
    paths_cell: &RefCell<Vec<PathBuf>>,
    paths: &[PathBuf],
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    let mut p = paths_cell.borrow_mut();
    p.clear();
    for path in paths {
        let title = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("(unnamed)")
            .to_string();
        let row = adw::ActionRow::builder()
            .title(&title)
            .activatable(true)
            .build();
        list.append(&row);
        p.push(path.clone());
    }
}

fn section_header(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .halign(gtk::Align::Start)
        .css_classes(["heading"])
        .margin_top(12)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build()
}

fn populate_reader_list(
    list: &gtk::ListBox,
    readers: &[Reader],
    row_ids: &Rc<RefCell<Vec<ReaderId>>>,
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    let mut ids = row_ids.borrow_mut();
    ids.clear();
    for r in readers {
        let row = adw::ActionRow::builder()
            .title(&r.display_name)
            .subtitle(format!("{:?}", r.id.backend).to_lowercase())
            .activatable(true)
            .build();
        list.append(&row);
        ids.push(r.id.clone());
    }
}

fn show_tag(status: &adw::StatusPage, reader: &ReaderId, tag: &TagInfo) {
    status.set_icon_name(Some("emblem-default-symbolic"));
    status.set_title(&format!("UID  {}", hex(&tag.uid)));

    let mut lines = Vec::new();
    let push = |lines: &mut Vec<String>, label: &str, value: &str| {
        lines.push(format!("{:<8}{}", format!("{}:", label), value));
    };

    push(&mut lines, "Reader", &reader.key);
    if let Some(t) = tag_type_label(tag.sak, &tag.atr) {
        push(&mut lines, "Type", t);
    }
    if let Some(m) = manufacturer_label(&tag.uid) {
        push(&mut lines, "Maker", m);
    }
    push(&mut lines, "Size", uid_size_label(tag.uid.len()));
    if let Some(atqa) = tag.atqa {
        push(&mut lines, "ATQA", &format!("{:02X} {:02X}", atqa[0], atqa[1]));
    }
    if let Some(sak) = tag.sak {
        push(&mut lines, "SAK", &format!("{:02X}", sak));
    }
    if !tag.atr.is_empty() {
        push(&mut lines, "ATR", &hex(&tag.atr));
    }
    status.set_description(Some(&lines.join("\n")));
}

/// Friendly tag-type string. Prefers the SAK byte when libnfc gave us one
/// (most specific signal); otherwise pulls the card-name code out of the
/// PC/SC ATR's PC/SC Part 3 Annex A historical-bytes block.
fn tag_type_label(sak: Option<u8>, atr: &[u8]) -> Option<&'static str> {
    if let Some(s) = sak {
        return Some(sak_to_label(s));
    }
    pcsc_atr_card_name(atr)
}

/// SAK byte → tag family. Values from NXP AN10833 + ISO/IEC 14443-3.
/// "Cascade" SAKs (bit 0x04 set) mean anticollision is incomplete and the
/// caller should re-anticol — we shouldn't normally see those here.
fn sak_to_label(sak: u8) -> &'static str {
    match sak {
        0x00 => "MIFARE Ultralight / NTAG",
        0x08 => "MIFARE Classic 1K",
        0x09 => "MIFARE Mini",
        0x10 => "MIFARE Plus 2K (SL2)",
        0x11 => "MIFARE Plus 4K (SL2)",
        0x18 => "MIFARE Classic 4K",
        0x19 => "MIFARE Classic 2K",
        0x20 => "ISO 14443-4 (DESFire / JCOP / smartcard)",
        0x28 => "ISO 14443-4 with MIFARE emulation (Plus SL1)",
        0x38 => "ISO 14443-4, proprietary",
        0x88 => "MIFARE Classic 1K (Infineon)",
        0x98 => "MPCOS (Gemplus)",
        _ => "unrecognised SAK",
    }
}

/// Decode the PC/SC contactless ATR's "Card Name" code. The format
/// (per PC/SC Part 3 Annex A) embeds an AID prefix `A0 00 00 03 06`
/// followed by a Standard byte and a 2-byte Card Name code in the
/// historical bytes. Find the prefix and read the next 3 bytes.
fn pcsc_atr_card_name(atr: &[u8]) -> Option<&'static str> {
    let prefix = [0xA0, 0x00, 0x00, 0x03, 0x06];
    let pos = atr.windows(prefix.len()).position(|w| w == prefix)?;
    let standard = *atr.get(pos + 5)?;
    let name_hi = *atr.get(pos + 6)?;
    let name_lo = *atr.get(pos + 7)?;
    let name = u16::from_be_bytes([name_hi, name_lo]);
    pcsc_card_name(standard, name)
}

fn pcsc_card_name(standard: u8, name: u16) -> Option<&'static str> {
    // standard 0x03 = ISO/IEC 14443A part 3, 0x11 = FeliCa, 0x00 = no info.
    match (standard, name) {
        (0x03, 0x0001) => Some("MIFARE Classic 1K"),
        (0x03, 0x0002) => Some("MIFARE Classic 4K"),
        (0x03, 0x0003) => Some("MIFARE Ultralight"),
        (0x03, 0x0026) => Some("MIFARE Mini"),
        (0x03, 0x0036) => Some("MIFARE Plus SL1 2K"),
        (0x03, 0x0037) => Some("MIFARE Plus SL1 4K"),
        (0x03, 0x0038) => Some("MIFARE Plus SL2 2K"),
        (0x03, 0x0039) => Some("MIFARE Plus SL2 4K"),
        (0x03, 0x003A) => Some("MIFARE Ultralight C"),
        (0x03, 0x003B) => Some("FeliCa Lite"),
        (0x03, 0x003C) => Some("FeliCa Lite-S"),
        (0x03, 0x0030) => Some("Topaz / Jewel"),
        _ => None,
    }
}

/// IC manufacturer from UID byte 0 (ISO/IEC 7816-6 / JTC1 SC17 registry).
/// 0x08 isn't a manufacturer — it's the marker for a tag using a random
/// UID rather than its hardware UID.
fn manufacturer_label(uid: &[u8]) -> Option<&'static str> {
    match uid.first()? {
        0x02 => Some("ST Microelectronics"),
        0x04 => Some("NXP Semiconductors"),
        0x05 => Some("Infineon Technologies"),
        0x07 => Some("Texas Instruments"),
        0x08 => Some("(random UID)"),
        0x16 => Some("EM Microelectronic"),
        0x1D => Some("ASK / Atmel"),
        0x21 => Some("EM Marin"),
        0x28 => Some("LG-CNS"),
        0x33 => Some("AMIC Technology"),
        0x44 => Some("Gentag"),
        0x47 => Some("ORGA"),
        _ => None,
    }
}

fn uid_size_label(len: usize) -> &'static str {
    match len {
        4 => "4-byte UID (single anticollision)",
        7 => "7-byte UID (double anticollision)",
        10 => "10-byte UID (triple anticollision)",
        _ => "non-standard UID length",
    }
}

fn format_dump(dump: &MifareDump) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "UID: {}", hex(&dump.uid));
    let _ = writeln!(s, "Size: {} bytes (MIFARE Classic 1K)", dump.bytes.len());
    s.push('\n');
    for sector in 0..16usize {
        let result = dump.sectors.get(sector);
        let label = match result {
            Some(SectorRead::Ok { key, key_type }) => {
                let kt = match key_type {
                    KeyType::A => "A",
                    KeyType::B => "B",
                };
                format!("Sector {:02} — key {} {}", sector, kt, hex(key))
            }
            Some(SectorRead::Failed) => format!("Sector {:02} — read failed (no key worked)", sector),
            None => format!("Sector {:02}", sector),
        };
        let _ = writeln!(s, "{}", label);
        for b in 0..4usize {
            let block = sector * 4 + b;
            let off = block * 16;
            if off + 16 > dump.bytes.len() {
                break;
            }
            let _ = writeln!(s, "  {:02}: {}", block, hex(&dump.bytes[off..off + 16]));
        }
        s.push('\n');
    }
    s
}

/// Parse the editable dump TextView back into a MifareDump.
///
/// The buffer normally holds whatever `format_dump` produced, optionally
/// hand-edited. We only look at lines whose trimmed form starts with
/// `NN: <16 hex bytes>` (decimal block index 00..63); everything else
/// (UID/Size headers, "Sector NN — key ..." labels, blank lines, user
/// comments) is ignored. Strict on what we accept inside a block line:
/// must be exactly 16 whitespace-separated hex bytes, and each block
/// 0..=63 must appear exactly once.
fn parse_dump_text(text: &str, base: &MifareDump) -> anyhow::Result<MifareDump> {
    let mut bytes = vec![0u8; MifareDump::SIZE_1K];
    let mut seen = [false; 64];

    for (lineno, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let Some(colon) = trimmed.find(':') else { continue };
        let prefix = &trimmed[..colon];
        let Ok(block) = prefix.parse::<usize>() else { continue };
        if block >= 64 {
            continue;
        }
        if seen[block] {
            anyhow::bail!("line {}: block {:02} appears twice", lineno + 1, block);
        }

        let rest = trimmed[colon + 1..].trim();
        let chunks: Vec<&str> = rest.split_whitespace().collect();
        if chunks.len() != 16 {
            anyhow::bail!(
                "line {}: block {:02} has {} hex byte(s), expected 16",
                lineno + 1,
                block,
                chunks.len()
            );
        }
        let off = block * 16;
        for (i, c) in chunks.iter().enumerate() {
            bytes[off + i] = u8::from_str_radix(c, 16).map_err(|_| {
                anyhow::anyhow!(
                    "line {}: block {:02} byte {}: not hex ({:?})",
                    lineno + 1,
                    block,
                    i,
                    c
                )
            })?;
        }
        seen[block] = true;
    }

    if let Some(missing) = (0..64u8).find(|b| !seen[*b as usize]) {
        let total = (0..64u8).filter(|b| !seen[*b as usize]).count();
        anyhow::bail!(
            "{} block(s) missing from dump (first missing: {:02})",
            total,
            missing
        );
    }

    Ok(MifareDump {
        uid: bytes[0..4].to_vec(),
        bytes,
        sectors: base.sectors.clone(),
    })
}

fn load_dump(path: &PathBuf) -> anyhow::Result<MifareDump> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != MifareDump::SIZE_1K {
        anyhow::bail!(
            "expected {} bytes, file is {} bytes",
            MifareDump::SIZE_1K,
            bytes.len()
        );
    }
    MifareDump::from_raw_1k(bytes).ok_or_else(|| anyhow::anyhow!("invalid dump file"))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02X}", b));
    }
    s
}

fn placeholder_row(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .margin_top(24)
        .margin_bottom(24)
        .css_classes(["dim-label"])
        .build()
}
