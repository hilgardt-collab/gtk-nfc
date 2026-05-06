//! PC/SC backend. Talks to `pcscd` via libpcsclite. Handles ACR122U and
//! most USB CCID NFC readers. Used as the fallback when libnfc isn't
//! available or doesn't recognise a device.

use std::ffi::CString;

use anyhow::{anyhow, Context as _, Result};
use pcsc::{Card, Context, Disposition, Protocols, Scope, ShareMode};

use super::{
    Backend, BackendKind, KeyType, MifareDump, Reader, ReaderId, SectorRead, TagInfo, WriteOutcome,
};

pub struct PcscBackend;

impl PcscBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for PcscBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Pcsc
    }

    fn list_readers(&mut self) -> Result<Vec<Reader>> {
        let ctx = Context::establish(Scope::User)
            .context("failed to connect to pcscd — is the service running?")?;

        let mut buf = [0u8; 4096];
        let names = ctx
            .list_readers(&mut buf)
            .context("pcsc list_readers failed")?;

        let mut out = Vec::new();
        for name in names {
            let display = name.to_string_lossy().into_owned();
            out.push(Reader {
                id: ReaderId {
                    backend: BackendKind::Pcsc,
                    key: display.clone(),
                },
                display_name: display,
            });
        }
        Ok(out)
    }

    fn read_tag(&mut self, key: &str) -> Result<TagInfo> {
        let card = connect_card(key)?;

        let uid = get_uid(&card)?;
        let mut name_buf = [0u8; 256];
        let mut atr_buf = [0u8; pcsc::MAX_ATR_SIZE];
        let atr = match card.status2(&mut name_buf, &mut atr_buf) {
            Ok(s) => s.atr().to_vec(),
            Err(_) => Vec::new(),
        };

        Ok(TagInfo {
            uid,
            atr,
            sak: None,
            atqa: None,
        })
    }

    fn dump_mifare_classic_1k(
        &mut self,
        reader_name: &str,
        candidate_keys: &[[u8; 6]],
        progress: &mut dyn FnMut(u8),
    ) -> Result<MifareDump> {
        // ACR122U firmware wedges if we accumulate too much state in one
        // pcsc session — many failed auths + reconnects in a row leave it
        // unable to detect tag-removal events. Open a fresh session per
        // sector so each one tears down cleanly via UnpoweredCard's drop.

        let uid = {
            let card = connect_card(reader_name)?;
            get_uid(&card)?
        };

        let mut bytes = vec![0u8; MifareDump::SIZE_1K];
        let mut sectors = Vec::with_capacity(16);

        for sector in 0..16u8 {
            let result = dump_sector(reader_name, sector, candidate_keys, &mut bytes)
                .with_context(|| format!("dump sector {}", sector))?;
            sectors.push(result);
            progress(sector + 1);
        }

        Ok(MifareDump {
            uid,
            bytes,
            sectors,
        })
    }

    fn write_mifare_classic_1k(
        &mut self,
        reader_name: &str,
        dump: &MifareDump,
        progress: &mut dyn FnMut(u8),
    ) -> Result<WriteOutcome> {
        if dump.bytes.len() != MifareDump::SIZE_1K {
            return Err(anyhow!(
                "dump is {} bytes, expected {}",
                dump.bytes.len(),
                MifareDump::SIZE_1K
            ));
        }

        let mut blocks_written = 0u8;
        let mut blocks_skipped = 0u8;

        // One pcsc session per sector — see the comment in dump_*. Even
        // more important here: writing block 0 of a Gen2 magic mutates the
        // tag's UID mid-session, which confuses pcscd's card-state cache.
        for sector in 0..16u8 {
            match write_sector(reader_name, sector, &dump.bytes) {
                Ok((written, skipped)) => {
                    blocks_written += written;
                    blocks_skipped += skipped;
                }
                Err(e) => {
                    return Err(e.context(format!("write sector {}", sector)));
                }
            }
            progress((sector + 1) * 4);
        }

        // Verification: fresh session, re-read block 0, compare. A
        // non-magic tag silently NAKs the block 0 update so the factory
        // UID is still there.
        let uid_changed = verify_block0(reader_name, &dump.bytes[..16]).unwrap_or(false);

        Ok(WriteOutcome {
            blocks_written,
            blocks_skipped,
            uid_changed,
        })
    }
}

const DEFAULT_KEY: [u8; 6] = [0xFF; 6];

/// Dump one sector in its own pcsc session. Tries each candidate key
/// (key A then key B) until one auths, then reads all four blocks.
fn dump_sector(
    reader_name: &str,
    sector: u8,
    candidate_keys: &[[u8; 6]],
    bytes: &mut [u8],
) -> Result<SectorRead> {
    let mut card = connect_card(reader_name)?;
    let block_anchor = sector * 4;

    let mut found: Option<([u8; 6], KeyType)> = None;
    'keys: for k in candidate_keys {
        for kt in [KeyType::A, KeyType::B] {
            match try_auth(&mut card, *k, kt, block_anchor)? {
                true => {
                    found = Some((*k, kt));
                    break 'keys;
                }
                false => continue,
            }
        }
    }

    let Some((k, kt)) = found else {
        return Ok(SectorRead::Failed);
    };

    for b in 0..4u8 {
        let block = block_anchor + b;
        let data = read_block(&card, block)
            .with_context(|| format!("read block {} after auth", block))?;
        let off = block as usize * 16;
        bytes[off..off + 16].copy_from_slice(&data);
    }
    // Sector trailer: bytes 0..6 read back as zeros (key A is never
    // readable). Splice the key we discovered so the dump round-trips
    // through write. Key B isn't recoverable this way.
    if matches!(kt, KeyType::A) {
        let trailer_off = (block_anchor as usize + 3) * 16;
        bytes[trailer_off..trailer_off + 6].copy_from_slice(&k);
    }
    Ok(SectorRead::Ok { key: k, key_type: kt })
}

/// Write one sector in its own pcsc session. Returns (blocks_written,
/// blocks_skipped). Auth uses the default factory key — custom-keyed
/// destinations are future work.
fn write_sector(reader_name: &str, sector: u8, dump_bytes: &[u8]) -> Result<(u8, u8)> {
    let mut card = connect_card(reader_name)?;
    let block_anchor = sector * 4;

    let auth_ok = match try_auth(&mut card, DEFAULT_KEY, KeyType::A, block_anchor)? {
        true => true,
        false => try_auth(&mut card, DEFAULT_KEY, KeyType::B, block_anchor)?,
    };
    if !auth_ok {
        return Ok((0, 4));
    }

    let mut written = 0u8;
    let mut skipped = 0u8;
    for b in 0..4u8 {
        let block = block_anchor + b;
        let off = block as usize * 16;
        let data: [u8; 16] = dump_bytes[off..off + 16].try_into().unwrap();
        match write_block(&card, block, &data) {
            Ok(()) => written += 1,
            Err(_) => skipped += 1,
        }
    }
    Ok((written, skipped))
}

/// Re-read block 0 in a fresh session and compare against the bytes we
/// wrote. Returns true iff the destination really took the new block 0
/// (i.e. it's a Gen2 magic tag).
fn verify_block0(reader_name: &str, expected_block0: &[u8]) -> Result<bool> {
    let mut card = connect_card(reader_name)?;
    if !try_auth(&mut card, DEFAULT_KEY, KeyType::A, 0)? {
        return Ok(false);
    }
    let actual = read_block(&card, 0)?;
    Ok(actual[..] == *expected_block0)
}

fn connect_card(reader_name: &str) -> Result<UnpoweredCard> {
    let ctx = Context::establish(Scope::User)
        .context("failed to connect to pcscd — is the service running?")?;
    let reader_c = CString::new(reader_name).context("reader name contains a NUL byte")?;
    let card = ctx
        .connect(&reader_c, ShareMode::Shared, Protocols::ANY)
        .map_err(|e| match e {
            pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard => {
                anyhow!("no tag present on the reader")
            }
            other => anyhow!(other).context("pcsc connect failed"),
        })?;
    Ok(UnpoweredCard::new(card))
}

/// RAII wrapper around `pcsc::Card` that disconnects with
/// `Disposition::UnpowerCard` rather than pcsc-rs's default `ResetCard`.
///
/// The ACR122U keeps its red LED on (and refuses to detect new tags) if a
/// session ends with `ResetCard` — the antenna stays powered and PICC
/// polling never resumes. `UnpowerCard` cold-resets the field, the LED
/// goes back to green, and the next tag is detected immediately.
struct UnpoweredCard {
    card: Option<Card>,
}

impl UnpoweredCard {
    fn new(card: Card) -> Self {
        Self { card: Some(card) }
    }
}

impl std::ops::Deref for UnpoweredCard {
    type Target = Card;
    fn deref(&self) -> &Card {
        self.card.as_ref().expect("card already taken")
    }
}

impl std::ops::DerefMut for UnpoweredCard {
    fn deref_mut(&mut self) -> &mut Card {
        self.card.as_mut().expect("card already taken")
    }
}

impl Drop for UnpoweredCard {
    fn drop(&mut self) {
        let Some(card) = self.card.take() else { return };
        if let Err((card, e)) = card.disconnect(Disposition::UnpowerCard) {
            log::debug!("UnpowerCard disconnect failed ({}); falling back to ResetCard drop", e);
            drop(card);
        }
    }
}

fn get_uid(card: &Card) -> Result<Vec<u8>> {
    let mut rx = [0u8; 32];
    let resp = card
        .transmit(&[0xFF, 0xCA, 0x00, 0x00, 0x00], &mut rx)
        .context("UID APDU transmit failed")?;
    let (data, sw) = split_sw(resp)?;
    if sw != [0x90, 0x00] {
        return Err(anyhow!(
            "reader returned {:02X}{:02X} for Get-UID",
            sw[0],
            sw[1]
        ));
    }
    Ok(data.to_vec())
}

/// Authenticate a block with a candidate key. Returns Ok(true) on auth
/// success, Ok(false) on auth failure (so the caller can try the next
/// key), Err for hard transmit errors.
fn try_auth(
    card: &mut Card,
    key: [u8; 6],
    kt: KeyType,
    block: u8,
) -> Result<bool> {
    // Load key into PC/SC reader slot 0: FF 82 00 00 06 K K K K K K
    let mut load = [0xFFu8, 0x82, 0x00, 0x00, 0x06, 0, 0, 0, 0, 0, 0];
    load[5..11].copy_from_slice(&key);
    let mut rx = [0u8; 16];
    let resp = card
        .transmit(&load, &mut rx)
        .context("Load-Keys APDU transmit failed")?;
    let (_, sw) = split_sw(resp)?;
    if sw != [0x90, 0x00] {
        return Err(anyhow!(
            "Load-Keys returned {:02X}{:02X}",
            sw[0],
            sw[1]
        ));
    }

    // Authenticate: FF 86 00 00 05 01 00 BLOCK KEYTYPE 00
    let key_byte = match kt {
        KeyType::A => 0x60,
        KeyType::B => 0x61,
    };
    let auth = [0xFFu8, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_byte, 0x00];
    let mut rx = [0u8; 16];
    let resp = card
        .transmit(&auth, &mut rx)
        .context("Authenticate APDU transmit failed")?;
    let (_, sw) = split_sw(resp)?;
    if sw == [0x90, 0x00] {
        return Ok(true);
    }
    // Auth failure on MIFARE Classic deselects the card; reset so the next
    // attempt starts from a known state. Failures here aren't fatal — the
    // dictionary loop will move on either way.
    let _ = card.reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard);
    Ok(false)
}

fn read_block(card: &Card, block: u8) -> Result<[u8; 16]> {
    // Read Binary: FF B0 00 BLOCK 10
    let cmd = [0xFFu8, 0xB0, 0x00, block, 0x10];
    let mut rx = [0u8; 32];
    let resp = card
        .transmit(&cmd, &mut rx)
        .context("Read-Binary transmit failed")?;
    let (data, sw) = split_sw(resp)?;
    if sw != [0x90, 0x00] {
        return Err(anyhow!(
            "Read-Binary block {} returned {:02X}{:02X}",
            block,
            sw[0],
            sw[1]
        ));
    }
    if data.len() != 16 {
        return Err(anyhow!(
            "Read-Binary returned {} bytes (expected 16)",
            data.len()
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(data);
    Ok(out)
}

fn write_block(card: &Card, block: u8, data: &[u8; 16]) -> Result<()> {
    // Update Binary: FF D6 00 BLOCK 10 <16 bytes>
    let mut cmd = [0u8; 5 + 16];
    cmd[0] = 0xFF;
    cmd[1] = 0xD6;
    cmd[2] = 0x00;
    cmd[3] = block;
    cmd[4] = 0x10;
    cmd[5..].copy_from_slice(data);
    let mut rx = [0u8; 16];
    let resp = card
        .transmit(&cmd, &mut rx)
        .context("Update-Binary transmit failed")?;
    let (_, sw) = split_sw(resp)?;
    if sw != [0x90, 0x00] {
        return Err(anyhow!(
            "Update-Binary block {} returned {:02X}{:02X}",
            block,
            sw[0],
            sw[1]
        ));
    }
    Ok(())
}

fn split_sw(resp: &[u8]) -> Result<(&[u8], [u8; 2])> {
    if resp.len() < 2 {
        return Err(anyhow!("short APDU response ({} bytes)", resp.len()));
    }
    let (data, sw) = resp.split_at(resp.len() - 2);
    Ok((data, [sw[0], sw[1]]))
}
