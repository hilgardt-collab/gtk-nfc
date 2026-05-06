# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project goal

GTK4 + libadwaita desktop app (Rust) for working with ISO-14443 / MIFARE RFID tags: discover readers, read tags, dump sector data, clone onto writable "magic" tags, and hand-edit dumps before writing.

## Prerequisites

Arch / Arch-based:

```
sudo pacman -S gtk4 libadwaita pcsclite ccid
sudo systemctl enable --now pcscd
# Only when building --features libnfc:
sudo pacman -S cmake
```

- **`cmake`** — required only when building with `--features libnfc`. The `nfc1-sys` crate vendors libnfc + libusb and compiles them statically via cmake, so the system `libnfc` package is *not* used (and isn't needed). `cargo check` with default features skips this entirely.
- **`pcscd`** — daemon for the PC/SC backend. Must be running for PC/SC reader enumeration. Users may also need to be in the `plugdev` group or have a udev rule granting access to the reader's USB VID/PID (ACR122U is `072f:2200`).

## Build / run

```
cargo check                         # default features, no libnfc
cargo run                           # PC/SC only
cargo run --features libnfc         # both backends (requires libnfc headers)
cargo build --release --features libnfc
```

There are no tests yet. When adding them, prefer integration tests under `tests/` using fake backends — real readers can't be assumed in CI.

## Architecture

The UI never calls a backend directly. Both `pcsc` and `nfc1` are blocking, and card-present polling takes hundreds of ms, so running on the GTK main thread would freeze the UI.

```
GTK main thread                        nfc worker thread
  ┌──────────────┐   mpsc::Sender    ┌────────────────┐
  │ ui/window.rs │ ────Command────▶  │  nfc::run loop │
  │              │                   │  owns backends │
  │              │ ◀──Event──────────│                │
  └──────────────┘   async_channel    └────────────────┘
         ▲              (recv on
         └──────────── glib::spawn_future_local)
```

Key files:

- `src/nfc/mod.rs` — `Backend` trait, `Command`/`Event` enums, `Worker` that spawns the thread and owns the mpsc/async-channel plumbing.
- `src/nfc/pcsc_backend.rs` — PC/SC implementation. Establishes a fresh `pcsc::Context` per call so pcscd restarts are transparent.
- `src/nfc/libnfc_backend.rs` — libnfc implementation via the `nfc1` crate, feature-gated on `libnfc`.
- `src/ui/window.rs` — builds the Adwaita `NavigationSplitView`, wires the refresh button to `Command::ListReaders`, drains `Event`s on the main loop via `glib::spawn_future_local`.

The `Worker` is stored on the `ApplicationWindow` via `glib::Object::set_data` so it lives as long as the window. When the window is dropped, `Worker::Drop` sends `Shutdown` and joins the thread.

### Reader identity

A `ReaderId` is `(BackendKind, String)`. The string is the PC/SC reader name or the libnfc connstring — whichever uniquely identifies the reader within its backend. Pair them so that "OMNIKEY" under PC/SC and "OMNIKEY" under libnfc are distinct entries in the UI (they represent the same physical device via two drivers; the user picks which to use).

### Extending the backend

Adding a command (e.g. `Command::ReadTag { reader_id }`):

1. Add the variant to `Command` and the matching `Event` (e.g. `Event::TagRead { uid, atqa, sak, sectors }`).
2. Handle it in `nfc::run`. Dispatch to the right backend by `reader_id.backend`.
3. Add a method on the `Backend` trait — keep it blocking; the worker thread is allowed to block.
4. Handle the new `Event` variant in `ui/window.rs`'s event loop.

Do not call backend methods directly from the UI. Do not introduce `tokio` — the worker thread is deliberately synchronous; `async` is only used for the `event_rx` loop so it integrates with glib.

## Cloning and "magic tags" — read this before touching the write path

Standard MIFARE Classic tags have a factory-locked block 0 containing the UID. You **cannot** overwrite the UID of a normal tag; the write will silently succeed and the UID won't change, or the tag will NAK.

Cloning only works onto so-called "magic" tags:

- **Gen1a ("UID-writable", backdoor)** — responds to unauthenticated commands `0x40`/`0x43`; write block 0 without auth.
- **Gen2 ("CUID")** — behaves like a normal tag, but block 0 is writable after normal auth with the sector 0 key.
- **Gen4 / "GDM" / "ultimate magic"** — configurable via a backdoor password, can emulate 1K/4K/Ultralight.

The write path must (a) detect the magic generation and pick the right command sequence, or (b) let the user declare the tag type in the UI. Never assume a tag is writable. Surface failures in the UI so users understand it's the blank that's wrong, not their reader.

## Working in this repo

- Prefer editing existing files. Keep `main.rs` → `app.rs` → `ui/window.rs` as the top-level wiring chain.
- Don't add `tokio` or other async runtimes — glib drives the UI loop; the worker is plain threads.
- Don't unwrap in worker code — errors must become `Event::BackendError` so the UI can show them.
- The `libnfc` code is cfg-gated. Wrap new libnfc-specific modules in `#[cfg(feature = "libnfc")]`, not runtime checks.
