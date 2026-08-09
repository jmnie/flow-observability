use anyhow::{Context, bail};

use crate::{model::IngestAck, spool::Spool};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadReport {
    pub acknowledged: u64,
}

pub fn upload_once(spool: &Spool, url: &str, limit: usize) -> anyhow::Result<UploadReport> {
    let mut acknowledged = 0;
    for envelope in spool.pending(limit)? {
        let response = ureq::post(url)
            .set("content-type", "application/json")
            .send_json(serde_json::to_value(&envelope)?)
            .with_context(|| format!("upload batch {}", envelope.batch_id))?;
        let ack: IngestAck = response.into_json().context("decode ingest ack")?;
        if ack.batch_id != envelope.batch_id {
            bail!("ingest ack batch id does not match request");
        }
        spool.acknowledge(&envelope.batch_id, &envelope.checksum)?;
        acknowledged += 1;
    }
    Ok(UploadReport { acknowledged })
}
