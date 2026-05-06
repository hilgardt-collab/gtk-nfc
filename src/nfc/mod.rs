//! NFC backend abstraction and worker thread.
//!
//! The GUI never touches a backend directly: both `pcsc` and `nfc1` are
//! blocking APIs, and card-present polling can take hundreds of ms. Instead
//! the UI sends a [`Command`] to a worker thread and receives [`Event`]s
//! back on a glib-driven async channel so updates happen on the main loop.

use std::sync::mpsc;
use std::thread;

pub mod pcsc_backend;
#[cfg(feature = "libnfc")]
pub mod libnfc_backend;
pub mod watcher;

/// Which backend kind a reader came from. Determines which driver handles
/// subsequent commands for that reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Pcsc,
    #[cfg(feature = "libnfc")]
    LibNfc,
}

/// Stable identifier for a reader. For PC/SC this is the reader name string;
/// for libnfc it's the connstring. Always paired with a [`BackendKind`] so
/// names colliding between backends don't clash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReaderId {
    pub backend: BackendKind,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct Reader {
    pub id: ReaderId,
    pub display_name: String,
}

/// Commands the UI can send to the worker.
#[derive(Debug, Clone)]
pub enum Command {
    /// Rescan all enabled backends for attached readers.
    ListReaders,
    /// Read whatever tag is currently on the named reader. Surfaces
    /// `Event::TagRead` on success, `Event::TagError` if no card is
    /// present or the read fails.
    ReadTag { reader: ReaderId },
    /// Dictionary-auth + read every sector of a MIFARE Classic 1K tag.
    DumpTag { reader: ReaderId },
    /// Write a 1K dump back to a Gen2 magic blank under `reader`. Uses
    /// the default key (FFFFFFFFFFFF) on the destination tag.
    WriteDump { reader: ReaderId, dump: MifareDump },
    /// Shut the worker down cleanly.
    Shutdown,
}

/// Snapshot of a tag the worker just read.
#[derive(Debug, Clone)]
pub struct TagInfo {
    pub uid: Vec<u8>,
    /// PC/SC ATR or libnfc historical bytes — backend-specific, may be empty.
    pub atr: Vec<u8>,
    /// ISO-14443A SAK byte if the backend exposed it.
    pub sak: Option<u8>,
    /// ISO-14443A ATQA bytes if the backend exposed them.
    pub atqa: Option<[u8; 2]>,
}

/// Which MIFARE Classic key a sector was authenticated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    A,
    B,
}

/// Outcome of trying to read a single sector.
#[derive(Debug, Clone)]
pub enum SectorRead {
    /// Sector was authenticated with the recorded key (and optionally key
    /// type B). Bytes for the sector are present in [`MifareDump::bytes`].
    Ok { key: [u8; 6], key_type: KeyType },
    /// No key in the dictionary worked — those four blocks are zeroed.
    Failed,
}

/// MIFARE Classic 1K snapshot. Layout matches the standard `.mfd` file
/// format: 1024 bytes, 16 sectors × 4 blocks × 16 bytes. Sector trailers
/// are patched with the discovered key A so that re-writing the dump
/// produces a tag with the same keys.
#[derive(Debug, Clone)]
pub struct MifareDump {
    pub uid: Vec<u8>,
    pub bytes: Vec<u8>,
    pub sectors: Vec<SectorRead>,
}

impl MifareDump {
    pub const SIZE_1K: usize = 1024;

    /// Build a dump from a raw 1024-byte buffer (e.g. loaded from disk).
    /// Sector results are unknown so they're all marked Failed-but-bytes-present:
    /// callers that load a dump get the raw bytes and can write it without
    /// us pretending we know which key was used.
    pub fn from_raw_1k(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() != Self::SIZE_1K {
            return None;
        }
        // Block 0 layout: UID (4 bytes) + BCC + SAK + ATQA + manuf data.
        let uid = bytes[0..4].to_vec();
        Some(Self {
            uid,
            bytes,
            sectors: (0..16).map(|_| SectorRead::Failed).collect(),
        })
    }
}

/// Events the worker emits back to the UI.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `reader` fields are read via Debug for logging
pub enum Event {
    ReadersListed(Vec<Reader>),
    /// Sent immediately when a `ReadTag` starts so the UI can show a
    /// progress state before the (blocking) read completes.
    ReadingTag { reader: ReaderId },
    TagRead { reader: ReaderId, tag: TagInfo },
    TagError { reader: ReaderId, message: String },
    DumpStarted { reader: ReaderId },
    DumpProgress { reader: ReaderId, sector: u8, total: u8 },
    TagDumped { reader: ReaderId, dump: MifareDump },
    DumpError { reader: ReaderId, message: String },
    WriteStarted { reader: ReaderId },
    WriteProgress { reader: ReaderId, block: u8, total: u8 },
    WriteComplete {
        reader: ReaderId,
        blocks_written: u8,
        blocks_skipped: u8,
        uid_changed: bool,
        mode: WriteMode,
    },
    WriteError { reader: ReaderId, message: String },
    BackendError { backend: BackendKind, message: String },
}

/// Trait every backend implements. Must be `Send` because it lives on the
/// worker thread, which is separate from the GTK main thread.
pub trait Backend: Send {
    fn kind(&self) -> BackendKind;
    fn list_readers(&mut self) -> anyhow::Result<Vec<Reader>>;
    /// Read the tag presently on `key` (PC/SC reader name or libnfc
    /// connstring). Must return an error if no card is present.
    fn read_tag(&mut self, key: &str) -> anyhow::Result<TagInfo>;
    /// Dump a MIFARE Classic 1K tag, trying each candidate key (in order)
    /// against both key A and key B per sector. Calls `progress` with the
    /// 1-based sector index after each sector finishes.
    fn dump_mifare_classic_1k(
        &mut self,
        key: &str,
        candidate_keys: &[[u8; 6]],
        progress: &mut dyn FnMut(u8),
    ) -> anyhow::Result<MifareDump>;
    /// Write a dump to a Gen2 magic blank. Uses key A = FFFFFFFFFFFF on
    /// the destination. Calls `progress` after each block. Returns
    /// (blocks_written, blocks_skipped, uid_changed).
    fn write_mifare_classic_1k(
        &mut self,
        key: &str,
        dump: &MifareDump,
        progress: &mut dyn FnMut(u8),
    ) -> anyhow::Result<WriteOutcome>;
}

#[derive(Debug, Clone, Copy)]
pub struct WriteOutcome {
    pub blocks_written: u8,
    pub blocks_skipped: u8,
    /// True if the post-write block 0 read matches what we wrote — i.e.
    /// the destination really is a magic tag.
    pub uid_changed: bool,
    pub mode: WriteMode,
}

/// Which write strategy the backend ended up using. Detected per write,
/// not declared up-front, so the UI can surface the truth even when a
/// blank turns out to be a different magic generation than expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Gen1a "UID-writable" backdoor: unauthenticated `0x40`/`0x43` unlock
    /// followed by raw `0xA0`/data block writes. No keys needed.
    Gen1aBackdoor,
    /// Standard MIFARE auth + Update-Binary writes. Works on Gen2/CUID
    /// (block 0 writable after auth) and on factory-keyed normal tags
    /// for everything except the locked block 0.
    StandardAuth,
}

/// Default keys to try in order — covers factory blanks, MAD sectors,
/// NDEF-formatted tags, and a handful of well-known transport keys.
pub const DEFAULT_KEYS: &[[u8; 6]] = &[
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
    [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
];

/// Handle to the worker thread. Dropping it sends `Shutdown` and joins.
pub struct Worker {
    cmd_tx: mpsc::Sender<Command>,
    join: Option<thread::JoinHandle<()>>,
}

impl Worker {
    /// Spawn the worker with the given backends. Events are delivered on
    /// `event_tx`; clone the receiver into a `glib::spawn_future_local` to
    /// consume them on the GTK main loop.
    pub fn spawn(
        backends: Vec<Box<dyn Backend>>,
        event_tx: async_channel::Sender<Event>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let join = thread::Builder::new()
            .name("nfc-worker".into())
            .spawn(move || run(backends, cmd_rx, event_tx))
            .expect("failed to spawn nfc worker thread");
        Self { cmd_tx, join: Some(join) }
    }

    pub fn send(&self, cmd: Command) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// A clone of the worker's command-input channel. Used by the
    /// reader watcher so it can fire `Command::ReadTag` from its own
    /// background thread without going through the GTK main loop.
    pub fn cmd_sender(&self) -> mpsc::Sender<Command> {
        self.cmd_tx.clone()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Command::Shutdown);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

fn run(
    mut backends: Vec<Box<dyn Backend>>,
    cmd_rx: mpsc::Receiver<Command>,
    event_tx: async_channel::Sender<Event>,
) {
    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            Command::Shutdown => break,
            Command::ListReaders => {
                let mut all = Vec::new();
                for b in backends.iter_mut() {
                    match b.list_readers() {
                        Ok(mut rs) => all.append(&mut rs),
                        Err(e) => {
                            let _ = event_tx.send_blocking(Event::BackendError {
                                backend: b.kind(),
                                message: e.to_string(),
                            });
                        }
                    }
                }
                let _ = event_tx.send_blocking(Event::ReadersListed(all));
            }
            Command::ReadTag { reader } => {
                let _ = event_tx.send_blocking(Event::ReadingTag { reader: reader.clone() });
                let backend = backends.iter_mut().find(|b| b.kind() == reader.backend);
                let ev = match backend {
                    Some(b) => match b.read_tag(&reader.key) {
                        Ok(tag) => Event::TagRead { reader: reader.clone(), tag },
                        Err(e) => Event::TagError { reader: reader.clone(), message: e.to_string() },
                    },
                    None => Event::TagError {
                        reader: reader.clone(),
                        message: format!("no backend registered for {:?}", reader.backend),
                    },
                };
                let _ = event_tx.send_blocking(ev);
            }
            Command::DumpTag { reader } => {
                let _ = event_tx.send_blocking(Event::DumpStarted { reader: reader.clone() });
                let backend = backends.iter_mut().find(|b| b.kind() == reader.backend);
                let ev = match backend {
                    Some(b) => {
                        let tx = event_tx.clone();
                        let r = reader.clone();
                        let mut progress = move |sector: u8| {
                            let _ = tx.send_blocking(Event::DumpProgress {
                                reader: r.clone(),
                                sector,
                                total: 16,
                            });
                        };
                        match b.dump_mifare_classic_1k(&reader.key, DEFAULT_KEYS, &mut progress) {
                            Ok(dump) => Event::TagDumped { reader: reader.clone(), dump },
                            Err(e) => Event::DumpError { reader: reader.clone(), message: e.to_string() },
                        }
                    }
                    None => Event::DumpError {
                        reader: reader.clone(),
                        message: format!("no backend registered for {:?}", reader.backend),
                    },
                };
                let _ = event_tx.send_blocking(ev);
            }
            Command::WriteDump { reader, dump } => {
                let _ = event_tx.send_blocking(Event::WriteStarted { reader: reader.clone() });
                let backend = backends.iter_mut().find(|b| b.kind() == reader.backend);
                let ev = match backend {
                    Some(b) => {
                        let tx = event_tx.clone();
                        let r = reader.clone();
                        let mut progress = move |block: u8| {
                            let _ = tx.send_blocking(Event::WriteProgress {
                                reader: r.clone(),
                                block,
                                total: 64,
                            });
                        };
                        match b.write_mifare_classic_1k(&reader.key, &dump, &mut progress) {
                            Ok(o) => Event::WriteComplete {
                                reader: reader.clone(),
                                blocks_written: o.blocks_written,
                                blocks_skipped: o.blocks_skipped,
                                uid_changed: o.uid_changed,
                                mode: o.mode,
                            },
                            Err(e) => Event::WriteError { reader: reader.clone(), message: e.to_string() },
                        }
                    }
                    None => Event::WriteError {
                        reader: reader.clone(),
                        message: format!("no backend registered for {:?}", reader.backend),
                    },
                };
                let _ = event_tx.send_blocking(ev);
            }
        }
    }
}
