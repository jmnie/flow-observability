use std::net::IpAddr;

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Ingress,
    Egress,
    Internal,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "name", content = "number", rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl From<u8> for TransportProtocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 | 58 => Self::Icmp,
            number => Self::Other(number),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub capture_point: String,
    pub direction: Direction,
    pub protocol: TransportProtocol,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowBucket {
    pub bucket_start: u64,
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDiagnostics {
    pub received: u64,
    pub dropped: u64,
    pub interface_dropped: u64,
    pub parse_errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchBody {
    pub schema_version: u16,
    pub node_id: String,
    pub boot_id: String,
    pub seq: u64,
    pub created_at: u64,
    pub buckets: Vec<FlowBucket>,
    pub diagnostics: CaptureDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEnvelope {
    pub batch_id: String,
    pub checksum: String,
    pub body: BatchBody,
}

impl BatchEnvelope {
    pub fn new(
        node_id: String,
        boot_id: String,
        seq: u64,
        created_at: u64,
        buckets: Vec<FlowBucket>,
        diagnostics: CaptureDiagnostics,
    ) -> anyhow::Result<Self> {
        let body = BatchBody {
            schema_version: SCHEMA_VERSION,
            node_id,
            boot_id,
            seq,
            created_at,
            buckets,
            diagnostics,
        };
        let checksum = body_checksum(&body)?;
        let batch_id = format!(
            "{}:{}:{}:{}",
            body.node_id,
            body.boot_id,
            body.seq,
            &checksum[..16]
        );
        Ok(Self {
            batch_id,
            checksum,
            body,
        })
    }

    pub fn has_valid_checksum(&self) -> anyhow::Result<bool> {
        Ok(body_checksum(&self.body)? == self.checksum)
    }
}

fn body_checksum(body: &BatchBody) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(body).context("serialize batch body")?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapEvent {
    pub seq: u64,
    pub min_bucket: Option<u64>,
    pub max_bucket: Option<u64>,
    pub lost_bytes: u64,
    pub reason: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestAck {
    pub batch_id: String,
    pub status: IngestStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestStatus {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpoolStatus {
    pub pending_batches: u64,
    pub pending_payload_bytes: u64,
    pub gap_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlStats {
    pub batches: u64,
    pub flow_buckets: u64,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeriesPoint {
    pub bucket_start: u64,
    pub packets: u64,
    pub bytes: u64,
}
