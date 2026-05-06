//! Per-reader background thread that auto-fires `Command::ReadTag` when a
//! tag arrives. PC/SC-only — libnfc lacks an equivalent
//! `SCardGetStatusChange`, and adding hot-loop polling there would beep the
//! reader and waste cycles. libnfc-selected readers simply get no watcher.
//!
//! Lifecycle: spawn one when a reader is selected; drop it (which sends a
//! Stop control message) when the selection changes or the window closes.
//! The thread is detached — Drop returns instantly; the thread itself
//! exits within the next ~500 ms when its `get_status_change` call wakes
//! up. We don't join because we don't want to stall the UI thread on
//! reader-switch.
//!
//! Suspend/Resume: long worker operations (Dump, Write) cause the RF
//! field to cycle several times mid-operation, which the watcher would
//! otherwise interpret as new tag arrivals and fire spurious reads. The
//! UI suspends the watcher before sending such commands and resumes
//! after they complete; resume also fires one explicit `ReadTag` so the
//! post-write UID gets confirmed automatically.

use std::ffi::CString;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::{BackendKind, Command, ReaderId};

/// Wake-up cadence inside the watcher's `get_status_change` loop. Caps
/// the latency of Stop / Suspend / Resume control messages — they only
/// take effect when the loop next wakes — and bounds the time between
/// reader-unplug and the watcher noticing.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Minimum gap between consecutive auto-read fires. Suppresses the
/// transient ABSENT→PRESENT bounce that happens after every PC/SC
/// session ends with `UnpowerCard` (the field briefly drops, the tag
/// reappears within ~200 ms — without debounce that would auto-fire a
/// second read for the same tag, looping forever).
const REFIRE_DEBOUNCE: Duration = Duration::from_millis(1500);

enum WatcherCmd {
    Stop,
    Suspend,
    Resume,
}

pub struct ReaderWatcher {
    ctrl_tx: mpsc::Sender<WatcherCmd>,
}

impl ReaderWatcher {
    /// Spawn a watcher for `reader`. Returns `None` for non-PC/SC
    /// readers (libnfc — no plan to support yet) so the UI can omit
    /// auto-read for those without storing a dummy handle.
    pub fn spawn(reader: ReaderId, worker_cmd_tx: mpsc::Sender<Command>) -> Option<Self> {
        if reader.backend != BackendKind::Pcsc {
            return None;
        }
        let (ctrl_tx, ctrl_rx) = mpsc::channel();
        thread::Builder::new()
            .name("nfc-watcher".into())
            .spawn(move || run(reader, worker_cmd_tx, ctrl_rx))
            .expect("failed to spawn nfc watcher thread");
        Some(Self { ctrl_tx })
    }

    /// Stop reacting to tag arrivals. Called before long worker
    /// operations to avoid the RF-cycle bounce mid-op.
    pub fn suspend(&self) {
        let _ = self.ctrl_tx.send(WatcherCmd::Suspend);
    }

    /// Resume reacting + fire one explicit ReadTag so a post-op tag
    /// (e.g. the just-cloned blank still on the reader) gets read back
    /// without the user clicking anything.
    pub fn resume(&self) {
        let _ = self.ctrl_tx.send(WatcherCmd::Resume);
    }
}

impl Drop for ReaderWatcher {
    fn drop(&mut self) {
        let _ = self.ctrl_tx.send(WatcherCmd::Stop);
        // Detach: the thread sees Stop at its next poll wake-up
        // (≤ POLL_INTERVAL) and exits. We don't join — we don't want
        // reader-switch to stall the UI for up to half a second.
    }
}

fn run(
    reader: ReaderId,
    worker_cmd_tx: mpsc::Sender<Command>,
    ctrl_rx: mpsc::Receiver<WatcherCmd>,
) {
    let Ok(ctx) = pcsc::Context::establish(pcsc::Scope::User) else {
        log::warn!("watcher: couldn't establish pcsc context for {}", reader.key);
        return;
    };
    let Ok(reader_c) = CString::new(reader.key.as_bytes()) else {
        log::warn!("watcher: reader name has NUL byte: {}", reader.key);
        return;
    };

    let mut state = pcsc::ReaderState::new(reader_c, pcsc::State::UNAWARE);
    let mut suspended = false;
    // Init to "long ago" so the first PRESENT detection fires
    // immediately (the user expects auto-read on tag-already-on-reader
    // when they select the reader).
    let mut last_fire = Instant::now() - REFIRE_DEBOUNCE * 2;

    loop {
        loop {
            match ctrl_rx.try_recv() {
                Ok(WatcherCmd::Stop) => return,
                Ok(WatcherCmd::Suspend) => suspended = true,
                Ok(WatcherCmd::Resume) => {
                    suspended = false;
                    let _ = worker_cmd_tx.send(Command::ReadTag {
                        reader: reader.clone(),
                    });
                    last_fire = Instant::now();
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        state.sync_current_state();
        match ctx.get_status_change(POLL_INTERVAL, std::slice::from_mut(&mut state)) {
            Ok(()) => {}
            Err(pcsc::Error::Timeout) => continue,
            Err(e) => {
                // Reader probably unplugged or pcscd restarted. Bail —
                // a fresh selection will spawn a new watcher.
                log::debug!("watcher: get_status_change failed: {}", e);
                return;
            }
        }

        if suspended {
            continue;
        }

        let event = state.event_state();
        if event.intersects(pcsc::State::CHANGED)
            && event.intersects(pcsc::State::PRESENT)
            && last_fire.elapsed() > REFIRE_DEBOUNCE
        {
            let _ = worker_cmd_tx.send(Command::ReadTag {
                reader: reader.clone(),
            });
            last_fire = Instant::now();
        }
    }
}
