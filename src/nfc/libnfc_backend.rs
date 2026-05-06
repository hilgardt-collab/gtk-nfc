//! libnfc backend via the `nfc1` crate. Primary path — speaks MIFARE
//! natively and supports the low-level command set needed for magic-tag
//! UID writes. Gated on the `libnfc` cargo feature.

use anyhow::{anyhow, Context as _, Result};
use nfc1::{BaudRate, Modulation, ModulationType};

use super::{Backend, BackendKind, MifareDump, Reader, ReaderId, TagInfo, WriteOutcome};

pub struct LibNfcBackend {
    ctx: nfc1::Context,
}

impl LibNfcBackend {
    pub fn new() -> Result<Self> {
        let ctx = nfc1::Context::new().context("nfc_init failed — is libnfc installed?")?;
        Ok(Self { ctx })
    }
}

impl Backend for LibNfcBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::LibNfc
    }

    fn list_readers(&mut self) -> Result<Vec<Reader>> {
        let connstrings = self
            .ctx
            .list_devices(16)
            .context("nfc_list_devices failed")?;

        let mut out = Vec::new();
        for cs in connstrings {
            let display = match self.ctx.open_with_connstring(&cs) {
                Ok(dev) => dev.name().to_string(),
                Err(_) => cs.clone(),
            };
            out.push(Reader {
                id: ReaderId {
                    backend: BackendKind::LibNfc,
                    key: cs,
                },
                display_name: display,
            });
        }
        Ok(out)
    }

    fn read_tag(&mut self, key: &str) -> Result<TagInfo> {
        let mut device = self
            .ctx
            .open_with_connstring(key)
            .context("failed to open libnfc device")?;
        device
            .initiator_init()
            .map_err(|e| anyhow!(e).context("initiator_init failed"))?;

        // ISO-14443A @ 106 kbps covers MIFARE Classic, Ultralight, NTAG, and
        // most desfire-style tags — the cards this app actually targets.
        let modulation = Modulation {
            modulation_type: ModulationType::Iso14443a,
            baud_rate: BaudRate::Baud106,
        };

        let target = device
            .initiator_select_passive_target(&modulation)
            .map_err(|e| match e {
                nfc1::Error::NoDeviceFound | nfc1::Error::NoSuchDeviceFound => {
                    anyhow!("no tag present on the reader")
                }
                other => anyhow!(other).context("passive-target select failed"),
            })?;

        match target.target_info {
            nfc1::target_info::TargetInfo::Iso14443a(info) => {
                let uid = info.uid[..info.uid_len].to_vec();
                let ats = info.ats[..info.ats_len].to_vec();
                Ok(TagInfo {
                    uid,
                    atr: ats,
                    sak: Some(info.sak),
                    atqa: Some(info.atqa),
                })
            }
            _ => Err(anyhow!(
                "unsupported tag type — only ISO-14443A is implemented"
            )),
        }
    }

    fn dump_mifare_classic_1k(
        &mut self,
        _key: &str,
        _candidate_keys: &[[u8; 6]],
        _progress: &mut dyn FnMut(u8),
    ) -> Result<MifareDump> {
        Err(anyhow!(
            "libnfc backend doesn't yet implement MIFARE Classic dump — use the PC/SC reader"
        ))
    }

    fn write_mifare_classic_1k(
        &mut self,
        _key: &str,
        _dump: &MifareDump,
        _progress: &mut dyn FnMut(u8),
    ) -> Result<WriteOutcome> {
        Err(anyhow!(
            "libnfc backend doesn't yet implement MIFARE Classic write — use the PC/SC reader"
        ))
    }
}
