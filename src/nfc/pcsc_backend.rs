//! PC/SC backend. Talks to `pcscd` via libpcsclite. Handles ACR122U and
//! most USB CCID NFC readers. Used as the fallback when libnfc isn't
//! available or doesn't recognise a device.

use std::ffi::CString;

use anyhow::{anyhow, Context as _, Result};
use pcsc::{Card, Context, Disposition, Protocols, Scope, ShareMode};

use super::{
    Backend, BackendKind, KeyType, MifareDump, Reader, ReaderId, SectorRead, TagInfo, WriteMode,
    WriteOutcome,
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

        // Try the Gen1a backdoor first. If the unlock ACKs we commit to the
        // Gen1a path — the writes happen unauthenticated on the same
        // session, and falling back mid-tag to standard auth would mix two
        // strategies on the same blank. If the unlock doesn't ACK (or the
        // reader can't even attempt it), fall through to standard auth.
        if let Some(outcome) = try_gen1a_write(reader_name, dump, progress)? {
            return Ok(outcome);
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
            mode: WriteMode::StandardAuth,
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

// ===== Gen1a "UID-writable" backdoor support (ACR122U-only) ==================
//
// Gen1a magic tags accept an unauthenticated unlock sequence that puts them
// into a state where any block — including the factory-locked block 0 — can
// be written without keys. The sequence (mirroring libnfc's
// `mifare_classic_unlock_card`) is:
//
//   1. HALT       (50 00 + CRC)
//   2. 7-bit 0x40  → expect 4-bit ACK 0x0A
//   3. 8-bit 0x43  → expect 8-bit ACK 0x0A
//
// PC/SC has no portable way to send 7-bit frames, so we do this through the
// ACR122U's PN532 pseudo-APDU `FF 00 00 00 Lc <PN532-frame>`. The 7-bit
// framing requirement means we have to twiddle the PN532's CIU registers
// directly: CIU_TxMode/CIU_RxMode (0x6302/0x6303) for CRC handling, and
// CIU_BitFraming (0x6333) for transmit-side bit length. Other PC/SC readers
// don't expose these registers, so the dispatcher in
// `write_mifare_classic_1k` only attempts Gen1a on readers whose name
// contains "ACR122".

/// True if the PC/SC reader name suggests it's an ACR122U or compatible
/// (the only PC/SC reader we currently know how to drive raw enough to do
/// the Gen1a unlock through).
fn looks_like_acr122(reader_name: &str) -> bool {
    reader_name.to_uppercase().contains("ACR122")
}

/// Send one PN532 frame as an ACR122U Direct Transmit pseudo-APDU
/// (`FF 00 00 00 Lc <data>`) and return the response payload (the bytes
/// before SW1SW2). 256-byte rx buffer — generous for any PN532 reply,
/// since real frames here are well under 64 bytes.
fn pn532_transmit(card: &Card, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > 255 {
        return Err(anyhow!("PN532 frame too long ({} bytes)", data.len()));
    }
    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, data.len() as u8]);
    apdu.extend_from_slice(data);

    let mut rx = [0u8; 256];
    let resp = card
        .transmit(&apdu, &mut rx)
        .context("PN532 pseudo-APDU transmit failed")?;
    let (payload, sw) = split_sw(resp)?;
    if sw != [0x90, 0x00] {
        return Err(anyhow!(
            "PN532 pseudo-APDU returned SW {:02X}{:02X}",
            sw[0],
            sw[1]
        ));
    }
    Ok(payload.to_vec())
}

/// Did `pn532_transmit`'s reply look like a successful PN532
/// `InCommunicateThru` (`D5 43 00 …`) carrying the magic ACK byte 0x0A?
/// Used to recognise a Gen1a tag's responses to the unlock and the per-block
/// write commands.
fn is_magic_ack(resp: &[u8]) -> bool {
    resp.len() >= 4 && resp[0] == 0xD5 && resp[1] == 0x43 && resp[2] == 0x00 && resp[3] == 0x0A
}

/// Run the Gen1a backdoor unlock on whatever tag is currently active in the
/// session. Returns `Ok(true)` if both unlock steps got the magic ACK (so
/// the tag is genuinely Gen1a), `Ok(false)` if a step NAK'd or returned an
/// unexpected payload (so the tag isn't Gen1a — fall back to the standard
/// path). `Err` only for transport-level failures talking to the reader.
///
/// This is deliberately self-contained: no caller-visible side effects on
/// the PN532 register state — CRC handling is restored before we return,
/// whether we succeeded or not.
fn gen1a_unlock(card: &Card) -> Result<bool> {
    // Do NOT set RFConfiguration MaxRetries here. On the ACR122U the PN532's
    // register state survives PC/SC session teardown (only the RF field is
    // cycled), so any non-default MaxRetries leaks into subsequent sessions
    // and breaks polling — the LED stays red and new tags aren't detected
    // until the reader is unplugged. libnfc's reference unlock doesn't
    // touch MaxRetries either; the unlock works fine without it.

    // Disable hardware CRC on TX and RX. Bit 7 of CIU_TxMode/CIU_RxMode is
    // the CRC-enable flag; clearing it gives us raw frames for the unlock.
    pn532_transmit(card, &[0xD4, 0x08, 0x63, 0x02, 0x00, 0x63, 0x03, 0x00])
        .context("PN532 WriteRegister (disable CRC) failed")?;

    // Run the rest in a closure so we can guarantee CRC handling is
    // restored on every exit path, even on error.
    let outcome = (|| -> Result<bool> {
        // HALT (50 00) plus its precomputed CRC_A. Real Gen1a tags NAK or
        // ignore HALT; we don't care about the response — we just need the
        // tag in HALT state for the unlock to take.
        let _ = pn532_transmit(card, &[0xD4, 0x42, 0x50, 0x00, 0x57, 0xCD]);

        // Set CIU_BitFraming TxLastBits = 7 so the next byte goes out as a
        // 7-bit short frame.
        pn532_transmit(card, &[0xD4, 0x08, 0x63, 0x33, 0x07])
            .context("PN532 WriteRegister (BitFraming=7) failed")?;
        let resp1 = pn532_transmit(card, &[0xD4, 0x42, 0x40])
            .context("PN532 InCommunicateThru (unlock1) failed")?;

        // Restore standard byte framing before sending the 8-bit half.
        pn532_transmit(card, &[0xD4, 0x08, 0x63, 0x33, 0x00])
            .context("PN532 WriteRegister (BitFraming=0) failed")?;

        if !is_magic_ack(&resp1) {
            return Ok(false);
        }

        let resp2 = pn532_transmit(card, &[0xD4, 0x42, 0x43])
            .context("PN532 InCommunicateThru (unlock2) failed")?;
        Ok(is_magic_ack(&resp2))
    })();

    // Always restore CRC handling so subsequent commands (verification,
    // standard MFC, even Gen1a writes which use CRC) work normally.
    let _ = pn532_transmit(card, &[0xD4, 0x08, 0x63, 0x02, 0x80, 0x63, 0x03, 0x80]);

    outcome
}

/// Write one 16-byte block via the Gen1a backdoor. Assumes the session is
/// already unlocked. Two-stage MIFARE write: command frame `A0 <block>`,
/// expect ACK; data frame `<16 bytes>` (PN532 adds CRC), expect ACK.
fn gen1a_write_block(card: &Card, block: u8, data: &[u8; 16]) -> Result<()> {
    let resp1 = pn532_transmit(card, &[0xD4, 0x42, 0xA0, block])
        .context("Gen1a write — command-frame transmit failed")?;
    if !is_magic_ack(&resp1) {
        return Err(anyhow!(
            "Gen1a write block {} command NAK ({:02X?})",
            block,
            resp1
        ));
    }

    let mut payload = Vec::with_capacity(2 + 16);
    payload.extend_from_slice(&[0xD4, 0x42]);
    payload.extend_from_slice(data);
    let resp2 = pn532_transmit(card, &payload)
        .context("Gen1a write — data-frame transmit failed")?;
    if !is_magic_ack(&resp2) {
        return Err(anyhow!(
            "Gen1a write block {} data NAK ({:02X?})",
            block,
            resp2
        ));
    }
    Ok(())
}

/// Attempt the full Gen1a write path:
///
/// - Skip silently on non-ACR122 readers (no way to do raw frames).
/// - Open ONE pcsc session (the unlock state is volatile across reconnects,
///   unlike standard MFC where one-session-per-sector avoids ACR122U
///   firmware lockups; Gen1a writes don't auth, so the lockup risk doesn't
///   apply here).
/// - Probe the unlock; if it doesn't ACK, declare "not Gen1a" and let the
///   caller fall through to the standard-auth path.
/// - If the unlock ACKs, write all 64 blocks in this same session. We
///   commit to Gen1a here — falling back mid-write would mix two write
///   strategies on the same tag.
/// - Verify by re-reading block 0 in a fresh session, authing with the key
///   A we just wrote (extracted from the dump's sector 0 trailer). The
///   factory key won't necessarily auth on the destination after we've
///   replaced the trailer.
fn try_gen1a_write(
    reader_name: &str,
    dump: &MifareDump,
    progress: &mut dyn FnMut(u8),
) -> Result<Option<WriteOutcome>> {
    if !looks_like_acr122(reader_name) {
        return Ok(None);
    }

    let card = connect_card(reader_name)?;
    if !gen1a_unlock(&card)? {
        return Ok(None);
    }

    let mut blocks_written = 0u8;
    let mut blocks_skipped = 0u8;
    for block in 0..64u8 {
        let off = block as usize * 16;
        let data: [u8; 16] = dump.bytes[off..off + 16].try_into().unwrap();
        match gen1a_write_block(&card, block, &data) {
            Ok(()) => blocks_written += 1,
            Err(e) => {
                log::debug!("gen1a write block {} failed: {}", block, e);
                blocks_skipped += 1;
            }
        }
        progress(block + 1);
    }

    // Drop this session before verification so the field is cold-reset and
    // the tag enters a clean active state for the standard auth probe.
    drop(card);

    // Sector 0 trailer is at dump bytes [48..64); key A occupies bytes 48..54.
    let key_a: [u8; 6] = dump.bytes[48..54].try_into().unwrap();
    let uid_changed = verify_block0_with_key(reader_name, &dump.bytes[..16], key_a)
        .unwrap_or(false);

    Ok(Some(WriteOutcome {
        blocks_written,
        blocks_skipped,
        uid_changed,
        mode: WriteMode::Gen1aBackdoor,
    }))
}

/// Like `verify_block0` but auths with a caller-supplied key A. The Gen1a
/// path needs this because we may have just rewritten the sector trailer,
/// so the destination's key A is now whatever the dump says, not
/// necessarily the factory FFFFFFFFFFFF.
fn verify_block0_with_key(
    reader_name: &str,
    expected_block0: &[u8],
    key: [u8; 6],
) -> Result<bool> {
    let mut card = connect_card(reader_name)?;
    if !try_auth(&mut card, key, KeyType::A, 0)? {
        return Ok(false);
    }
    let actual = read_block(&card, 0)?;
    Ok(actual[..] == *expected_block0)
}
