use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use serde::Deserialize;
use thiserror::Error;

use crate::model::{
    BatchEnvelope, ControlStats, IngestAck, IngestStatus, SCHEMA_VERSION, SeriesPoint,
};
use crate::sqlite::{integer, unsigned};

const WAL_LIMIT_BYTES: i64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ControlLimits {
    pub max_database_bytes: u64,
    pub max_age_seconds: u64,
}

impl Default for ControlLimits {
    fn default() -> Self {
        Self {
            max_database_bytes: 128 * 1024 * 1024,
            max_age_seconds: 48 * 60 * 60,
        }
    }
}

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("batch checksum is invalid")]
    Checksum,
    #[error("batch identity conflicts with stored data")]
    Conflict,
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Encoding(#[from] anyhow::Error),
}

pub struct ControlStore {
    connection: Connection,
    limits: ControlLimits,
}

impl ControlStore {
    pub fn open(path: impl AsRef<Path>, limits: ControlLimits) -> anyhow::Result<Self> {
        if limits.max_database_bytes == 0 || limits.max_age_seconds == 0 {
            anyhow::bail!("control byte and age limits must be positive");
        }
        let connection = Connection::open(path)?;
        configure(&connection, limits.max_database_bytes)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS ingested_batches (
                 batch_id TEXT PRIMARY KEY,
                 checksum TEXT NOT NULL,
                 node_id TEXT NOT NULL,
                 boot_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 created_at INTEGER NOT NULL,
                 UNIQUE(node_id, boot_id, seq)
             );
             CREATE TABLE IF NOT EXISTS flow_buckets (
                 batch_id TEXT NOT NULL REFERENCES ingested_batches(batch_id),
                 bucket_start INTEGER NOT NULL,
                 node_id TEXT NOT NULL,
                 capture_point TEXT NOT NULL,
                 direction TEXT NOT NULL,
                 protocol TEXT NOT NULL,
                 source_ip TEXT NOT NULL,
                 destination_ip TEXT NOT NULL,
                 source_port INTEGER,
                 destination_port INTEGER,
                 packets INTEGER NOT NULL,
                 bytes INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS flow_buckets_node_time
             ON flow_buckets(node_id, bucket_start);",
        )?;
        Ok(Self { connection, limits })
    }

    pub fn ingest(&mut self, envelope: &BatchEnvelope) -> Result<IngestStatus, IngestError> {
        self.ingest_at(envelope, unix_seconds()?)
    }

    fn ingest_at(
        &mut self,
        envelope: &BatchEnvelope,
        now: u64,
    ) -> Result<IngestStatus, IngestError> {
        if envelope.body.schema_version != SCHEMA_VERSION {
            return Err(IngestError::SchemaVersion);
        }
        if !envelope.has_valid_checksum()? {
            return Err(IngestError::Checksum);
        }
        let transaction = self.connection.transaction()?;
        prune_expired(&transaction, self.limits.max_age_seconds, now)?;
        let existing_checksum = transaction
            .query_row(
                "SELECT checksum FROM ingested_batches WHERE batch_id = ?",
                [&envelope.batch_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(checksum) = existing_checksum {
            return if checksum == envelope.checksum {
                transaction.commit()?;
                Ok(IngestStatus::Duplicate)
            } else {
                Err(IngestError::Conflict)
            };
        }
        let sequence_exists = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM ingested_batches WHERE node_id = ? AND boot_id = ? AND seq = ?
             )",
            params![
                envelope.body.node_id,
                envelope.body.boot_id,
                integer(envelope.body.seq, "batch seq")?
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if sequence_exists {
            return Err(IngestError::Conflict);
        }
        let seq = integer(envelope.body.seq, "batch seq")?;
        let created_at = integer(envelope.body.created_at, "batch created_at")?;
        transaction.execute(
            "INSERT INTO ingested_batches(
                 batch_id, checksum, node_id, boot_id, seq, created_at
             ) VALUES (?, ?, ?, ?, ?, ?)",
            params![
                envelope.batch_id,
                envelope.checksum,
                envelope.body.node_id,
                envelope.body.boot_id,
                seq,
                created_at,
            ],
        )?;
        for bucket in &envelope.body.buckets {
            let direction = direction_key(bucket.key.direction);
            let protocol = protocol_key(bucket.key.protocol);
            transaction.execute(
                "INSERT INTO flow_buckets(
                     batch_id, bucket_start, node_id, capture_point, direction, protocol,
                     source_ip, destination_ip, source_port, destination_port, packets, bytes
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    envelope.batch_id,
                    integer(bucket.bucket_start, "bucket_start")?,
                    envelope.body.node_id,
                    bucket.key.capture_point,
                    direction,
                    protocol,
                    bucket.key.source_ip.to_string(),
                    bucket.key.destination_ip.to_string(),
                    bucket.key.source_port,
                    bucket.key.destination_port,
                    integer(bucket.packets, "bucket packets")?,
                    integer(bucket.bytes, "bucket bytes")?,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(IngestStatus::Inserted)
    }

    pub fn stats(&self, node: &str) -> anyhow::Result<ControlStats> {
        self.connection
            .query_row(
                "SELECT
                     (SELECT COUNT(*) FROM ingested_batches WHERE node_id = ?1),
                     COUNT(*),
                     COALESCE(SUM(packets), 0),
                     COALESCE(SUM(bytes), 0)
                 FROM flow_buckets
                 WHERE node_id = ?1",
                [node],
                |row| {
                    Ok(ControlStats {
                        batches: unsigned(row, 0)?,
                        flow_buckets: unsigned(row, 1)?,
                        packets: unsigned(row, 2)?,
                        bytes: unsigned(row, 3)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn series(
        &self,
        node: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> anyhow::Result<Vec<SeriesPoint>> {
        let from = from.unwrap_or(0);
        let to = to.unwrap_or(i64::MAX as u64);
        if from > to {
            anyhow::bail!("from must be less than or equal to to");
        }
        let mut statement = self.connection.prepare(
            "SELECT bucket_start, SUM(packets), SUM(bytes)
             FROM flow_buckets
             WHERE node_id = ?1 AND bucket_start BETWEEN ?2 AND ?3
             GROUP BY bucket_start
             ORDER BY bucket_start",
        )?;
        let from = integer(from, "series from")?;
        let to = integer(to, "series to")?;
        statement
            .query_map(params![node, from, to], |row| {
                Ok(SeriesPoint {
                    bucket_start: unsigned(row, 0)?,
                    packets: unsigned(row, 1)?,
                    bytes: unsigned(row, 2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

fn configure(connection: &Connection, max_database_bytes: u64) -> anyhow::Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 100_i64)?;
    connection.pragma_update(None, "journal_size_limit", WAL_LIMIT_BYTES)?;
    let page_size = connection.pragma_query_value(None, "page_size", |row| unsigned(row, 0))?;
    let max_pages = max_database_bytes.div_ceil(page_size);
    let page_count = connection.pragma_query_value(None, "page_count", |row| unsigned(row, 0))?;
    if page_count > max_pages {
        anyhow::bail!(
            "control database already uses {page_count} pages, above configured limit {max_pages}"
        );
    }
    connection.pragma_update(
        None,
        "max_page_count",
        integer(max_pages, "max_page_count")?,
    )?;
    Ok(())
}

fn prune_expired(
    transaction: &rusqlite::Transaction<'_>,
    max_age_seconds: u64,
    now: u64,
) -> rusqlite::Result<()> {
    let cutoff = now.saturating_sub(max_age_seconds);
    let cutoff = integer(cutoff, "control cutoff").map_err(to_sql_error)?;
    transaction.execute(
        "DELETE FROM flow_buckets
         WHERE batch_id IN (SELECT batch_id FROM ingested_batches WHERE created_at < ?)",
        [cutoff],
    )?;
    transaction.execute(
        "DELETE FROM ingested_batches WHERE created_at < ?",
        [cutoff],
    )?;
    Ok(())
}

fn unix_seconds() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system clock is before Unix epoch: {error}"))?
        .as_secs())
}

fn to_sql_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(error.into())
}

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<ControlStore>>,
}

#[derive(Debug, Deserialize)]
struct SeriesQuery {
    node: String,
    from: Option<u64>,
    to: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NodeQuery {
    node: String,
}

pub async fn serve(
    path: impl AsRef<Path>,
    listen: &str,
    limits: ControlLimits,
) -> anyhow::Result<()> {
    let state = AppState {
        store: Arc::new(Mutex::new(ControlStore::open(path, limits)?)),
    };
    let router = Router::new()
        .route("/v1/ingest", post(ingest))
        .route("/v1/stats", get(stats))
        .route("/v1/series", get(series))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn ingest(
    State(state): State<AppState>,
    Json(envelope): Json<BatchEnvelope>,
) -> Result<Json<IngestAck>, (StatusCode, String)> {
    let mut store = state
        .store
        .lock()
        .map_err(|_| internal("control store lock poisoned"))?;
    match store.ingest(&envelope) {
        Ok(status) => Ok(Json(IngestAck {
            batch_id: envelope.batch_id,
            status,
        })),
        Err(IngestError::SchemaVersion | IngestError::Checksum) => {
            Err((StatusCode::BAD_REQUEST, "invalid batch".into()))
        }
        Err(IngestError::Conflict) => Err((StatusCode::CONFLICT, "batch identity conflict".into())),
        Err(IngestError::Database(error)) if is_storage_full(&error) => Err((
            StatusCode::INSUFFICIENT_STORAGE,
            "control storage limit reached".into(),
        )),
        Err(error) => Err(internal(error)),
    }
}

fn is_storage_full(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _) if code.code == ErrorCode::DiskFull
    )
}

async fn stats(
    State(state): State<AppState>,
    Query(query): Query<NodeQuery>,
) -> Result<Json<ControlStats>, (StatusCode, String)> {
    let store = state
        .store
        .lock()
        .map_err(|_| internal("control store lock poisoned"))?;
    store.stats(&query.node).map(Json).map_err(internal)
}

async fn series(
    State(state): State<AppState>,
    Query(query): Query<SeriesQuery>,
) -> Result<Json<Vec<SeriesPoint>>, (StatusCode, String)> {
    let store = state
        .store
        .lock()
        .map_err(|_| internal("control store lock poisoned"))?;
    store
        .series(&query.node, query.from, query.to)
        .map(Json)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))
}

fn internal(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn direction_key(direction: crate::model::Direction) -> &'static str {
    match direction {
        crate::model::Direction::Ingress => "ingress",
        crate::model::Direction::Egress => "egress",
        crate::model::Direction::Internal => "internal",
        crate::model::Direction::Unknown => "unknown",
    }
}

fn protocol_key(protocol: crate::model::TransportProtocol) -> String {
    match protocol {
        crate::model::TransportProtocol::Tcp => "tcp".into(),
        crate::model::TransportProtocol::Udp => "udp".into(),
        crate::model::TransportProtocol::Icmp => "icmp".into(),
        crate::model::TransportProtocol::Other(number) => format!("other:{number}"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tempfile::tempdir;

    use super::*;
    use crate::model::{CaptureDiagnostics, Direction, FlowBucket, FlowKey, TransportProtocol};

    fn envelope() -> BatchEnvelope {
        BatchEnvelope::new(
            "node-a".into(),
            "boot".into(),
            0,
            100,
            vec![FlowBucket {
                bucket_start: 100,
                key: FlowKey {
                    capture_point: "physical:eth0".into(),
                    direction: Direction::Egress,
                    protocol: TransportProtocol::Tcp,
                    source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    destination_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    source_port: Some(50000),
                    destination_port: Some(443),
                },
                packets: 2,
                bytes: 300,
            }],
            CaptureDiagnostics::default(),
        )
        .unwrap()
    }

    #[test]
    fn duplicate_batch_is_idempotent() {
        let directory = tempdir().unwrap();
        let mut store = ControlStore::open(
            directory.path().join("control.db"),
            ControlLimits {
                max_database_bytes: 1024 * 1024,
                max_age_seconds: u64::MAX,
            },
        )
        .unwrap();
        let batch = envelope();

        assert_eq!(store.ingest(&batch).unwrap(), IngestStatus::Inserted);
        assert_eq!(store.ingest(&batch).unwrap(), IngestStatus::Duplicate);
        assert_eq!(store.stats("node-a").unwrap().flow_buckets, 1);
        assert_eq!(store.stats("node-a").unwrap().bytes, 300);
    }

    #[test]
    fn checksum_change_is_rejected() {
        let directory = tempdir().unwrap();
        let mut store = ControlStore::open(
            directory.path().join("control.db"),
            ControlLimits {
                max_database_bytes: 1024 * 1024,
                max_age_seconds: u64::MAX,
            },
        )
        .unwrap();
        let mut batch = envelope();
        store.ingest(&batch).unwrap();
        batch.checksum.replace_range(..1, "0");

        assert!(matches!(store.ingest(&batch), Err(IngestError::Checksum)));
    }

    #[test]
    fn age_limit_prunes_expired_batches_before_ingest() {
        let directory = tempdir().unwrap();
        let mut store = ControlStore::open(
            directory.path().join("control.db"),
            ControlLimits {
                max_database_bytes: 1024 * 1024,
                max_age_seconds: 10,
            },
        )
        .unwrap();
        let old = envelope();
        store.ingest_at(&old, 100).unwrap();
        let mut current = envelope();
        current.body.seq = 1;
        current.body.created_at = 120;
        current.body.buckets[0].bucket_start = 120;
        current = BatchEnvelope::new(
            current.body.node_id,
            current.body.boot_id,
            current.body.seq,
            current.body.created_at,
            current.body.buckets,
            current.body.diagnostics,
        )
        .unwrap();

        store.ingest_at(&current, 120).unwrap();

        let stats = store.stats("node-a").unwrap();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.flow_buckets, 1);
        assert_eq!(stats.bytes, 300);
    }
}
