use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib;

use crate::nfc::{
    self, Backend, Command, Event, KeyType, MifareDump, Reader, ReaderId, SectorRead, TagInfo,
    WriteMode, Worker,
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
    // Content widgets.
    stack: gtk::Stack,
    status_page: adw::StatusPage,
    dump_buffer: gtk::TextBuffer,
}

impl UiState {
    fn refresh_buttons(&self) {
        let has_reader = self.selected_reader.borrow().is_some();
        let has_dump = self.current_dump.borrow().is_some();
        self.read_uid_btn.set_sensitive(has_reader);
        self.dump_btn.set_sensitive(has_reader);
        self.save_btn.set_sensitive(has_dump);
        self.write_btn.set_sensitive(has_reader && has_dump);
    }

    fn show_status(&self, icon: &str, title: &str, description: &str) {
        self.status_page.set_icon_name(Some(icon));
        self.status_page.set_title(title);
        self.status_page.set_description(Some(description));
        self.stack.set_visible_child_name("status");
    }

    fn show_dump(&self, dump: &MifareDump) {
        self.dump_buffer.set_text(&format_dump(dump));
        self.stack.set_visible_child_name("dump");
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
    let sidebar_scroll = gtk::ScrolledWindow::builder()
        .child(&reader_list)
        .vexpand(true)
        .build();
    let sidebar_page = adw::NavigationPage::builder()
        .title("Readers")
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
        .editable(false)
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

    let stack = gtk::Stack::new();
    stack.add_named(&status_page, Some("status"));
    stack.add_named(&dump_scroll, Some("dump"));
    stack.set_visible_child_name("status");

    let content_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .build();
    content_box.append(&action_bar);
    content_box.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    content_box.append(&stack);

    let content_page = adw::NavigationPage::builder()
        .title("Tag")
        .tag("tag")
        .child(&content_box)
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
        stack: stack.clone(),
        status_page: status_page.clone(),
        dump_buffer: dump_buffer.clone(),
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
            *state.selected_reader.borrow_mut() = new;
            state.refresh_buttons();
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
                state.worker.send(Command::DumpTag { reader });
            }
        });
    }

    {
        let state = Rc::clone(&state);
        let window = window.clone();
        load_btn.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder()
                .title("Load .mfd dump")
                .modal(true)
                .build();
            let state = Rc::clone(&state);
            dialog.open(Some(&window), gtk::gio::Cancellable::NONE, move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else {
                    state.show_status(
                        "dialog-warning-symbolic",
                        "Couldn't load",
                        "The selected file has no local path.",
                    );
                    return;
                };
                match load_dump(&path) {
                    Ok(dump) => {
                        state.show_dump(&dump);
                        *state.current_dump.borrow_mut() = Some(dump);
                        state.refresh_buttons();
                    }
                    Err(e) => state.show_status(
                        "dialog-warning-symbolic",
                        "Couldn't load dump",
                        &e.to_string(),
                    ),
                }
            });
        });
    }

    {
        let state = Rc::clone(&state);
        let window = window.clone();
        save_btn.connect_clicked(move |_| {
            let dump_bytes = match state.current_dump.borrow().as_ref() {
                Some(d) => d.bytes.clone(),
                None => return,
            };
            let dialog = gtk::FileDialog::builder()
                .title("Save .mfd dump")
                .modal(true)
                .initial_name("dump.mfd")
                .build();
            let state = Rc::clone(&state);
            dialog.save(Some(&window), gtk::gio::Cancellable::NONE, move |res| {
                let Ok(file) = res else { return };
                let Some(path) = file.path() else {
                    state.show_status(
                        "dialog-warning-symbolic",
                        "Couldn't save",
                        "The chosen location has no local path.",
                    );
                    return;
                };
                if let Err(e) = std::fs::write(&path, &dump_bytes) {
                    state.show_status(
                        "dialog-warning-symbolic",
                        "Couldn't save dump",
                        &e.to_string(),
                    );
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
            let dump = match state.current_dump.borrow().clone() {
                Some(d) => d,
                None => return,
            };
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
                        state.stack.set_visible_child_name("status");
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
                    }
                    Event::DumpError { reader, message } => state.show_status(
                        "dialog-warning-symbolic",
                        "Dump failed",
                        &format!("{} — {}", reader.key, message),
                    ),
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
                    }
                    Event::WriteError { reader, message } => state.show_status(
                        "dialog-warning-symbolic",
                        "Write failed",
                        &format!("{} — {}", reader.key, message),
                    ),
                    Event::BackendError { backend, message } => {
                        log::warn!("backend {:?}: {}", backend, message);
                    }
                }
            }
        });
    }

    worker.send(Command::ListReaders);

    unsafe { window.set_data("nfc-worker", worker) };

    window
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
    lines.push(format!("Reader: {}", reader.key));
    if let Some(atqa) = tag.atqa {
        lines.push(format!("ATQA: {:02X} {:02X}", atqa[0], atqa[1]));
    }
    if let Some(sak) = tag.sak {
        lines.push(format!("SAK:  {:02X}", sak));
    }
    if !tag.atr.is_empty() {
        lines.push(format!("ATR:  {}", hex(&tag.atr)));
    }
    status.set_description(Some(&lines.join("\n")));
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
