use std::path::Path;

use anyhow::{Context, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::model::{BatchEnvelope, CaptureDiagnostics, FlowBucket, GapEvent, SpoolStatus};
use crate::sqlite::{integer, optional_unsigned, unsigned};

const SQLITE_OVERHEAD_BYTES: u64 = 16 * 1024 * 1024;
const WAL_LIMIT_BYTES: i64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct SpoolLimits {
    pub max_payload_bytes: u64,
    pub max_age_seconds: u64,
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 128 * 1024 * 1024,
            max_age_seconds: 24 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueResult {
    pub batch_id: String,
    pub evicted_batches: u64,
}

pub struct Spool {
    connection: Connection,
    limits: SpoolLimits,
}

impl Spool {
    pub fn open(path: impl AsRef<Path>, limits: SpoolLimits) -> anyhow::Result<Self> {
        if limits.max_payload_bytes == 0 || limits.max_age_seconds == 0 {
            bail!("spool byte and age limits must be positive");
        }
        let connection = Connection::open(path).context("open spool database")?;
        configure(&connection, limits.max_payload_bytes)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                 key TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO metadata(key, value) VALUES ('next_seq', 0);
             CREATE TABLE IF NOT EXISTS batches (
                 seq INTEGER PRIMARY KEY,
                 batch_id TEXT NOT NULL UNIQUE,
                 checksum TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 min_bucket INTEGER,
                 max_bucket INTEGER,
                 payload_bytes INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS batches_created_at ON batches(created_at, seq);
             CREATE TABLE IF NOT EXISTS gaps (
                 seq INTEGER PRIMARY KEY,
                 min_bucket INTEGER,
                 max_bucket INTEGER,
                 lost_bytes INTEGER NOT NULL,
                 reason TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );",
        )?;
        Ok(Self { connection, limits })
    }

    pub fn enqueue(
        &mut self,
        node_id: String,
        boot_id: String,
        created_at: u64,
        buckets: Vec<FlowBucket>,
        diagnostics: CaptureDiagnostics,
    ) -> anyhow::Result<EnqueueResult> {
        let transaction = self.connection.transaction()?;
        let seq = transaction.query_row(
            "SELECT value FROM metadata WHERE key = 'next_seq'",
            [],
            |row| unsigned(row, 0),
        )?;
        transaction.execute(
            "UPDATE metadata SET value = value + 1 WHERE key = 'next_seq'",
            [],
        )?;
        let envelope = BatchEnvelope::new(node_id, boot_id, seq, created_at, buckets, diagnostics)?;
        let payload = serde_json::to_vec(&envelope)?;
        let payload_bytes = payload.len() as u64;
        let (min_bucket, max_bucket) = bucket_range(&envelope.body.buckets);
        if payload_bytes > self.limits.max_payload_bytes {
            insert_gap(
                &transaction,
                seq,
                min_bucket,
                max_bucket,
                payload_bytes,
                "batch_exceeds_spool_limit",
                created_at,
            )?;
            transaction.commit()?;
            return Ok(EnqueueResult {
                batch_id: envelope.batch_id,
                evicted_batches: 1,
            });
        }
        transaction.execute(
            "INSERT INTO batches(
                 seq, batch_id, checksum, created_at, min_bucket, max_bucket, payload_bytes, payload
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                integer(seq, "seq")?,
                envelope.batch_id,
                envelope.checksum,
                integer(created_at, "created_at")?,
                min_bucket
                    .map(|value| integer(value, "min_bucket"))
                    .transpose()?,
                max_bucket
                    .map(|value| integer(value, "max_bucket"))
                    .transpose()?,
                integer(payload_bytes, "payload_bytes")?,
                payload,
            ],
        )?;
        let evicted_batches = enforce_limits(&transaction, self.limits, created_at)?;
        transaction.commit()?;
        Ok(EnqueueResult {
            batch_id: envelope.batch_id,
            evicted_batches,
        })
    }

    pub fn pending(&self, limit: usize) -> anyhow::Result<Vec<BatchEnvelope>> {
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM batches ORDER BY seq LIMIT ?")?;
        let rows = statement.query_map([i64::try_from(limit)?], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            let payload = row?;
            serde_json::from_slice(&payload).context("decode pending batch")
        })
        .collect()
    }

    pub fn acknowledge(&self, batch_id: &str, checksum: &str) -> anyhow::Result<()> {
        let deleted = self.connection.execute(
            "DELETE FROM batches WHERE batch_id = ? AND checksum = ?",
            params![batch_id, checksum],
        )?;
        if deleted != 1 {
            bail!("ack does not match a pending batch");
        }
        Ok(())
    }

    pub fn status(&self) -> anyhow::Result<SpoolStatus> {
        self.connection
            .query_row(
                "SELECT
                     COUNT(*),
                     COALESCE(SUM(payload_bytes), 0),
                     (SELECT COUNT(*) FROM gaps)
                 FROM batches",
                [],
                |row| {
                    Ok(SpoolStatus {
                        pending_batches: unsigned(row, 0)?,
                        pending_payload_bytes: unsigned(row, 1)?,
                        gap_events: unsigned(row, 2)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn gaps(&self) -> anyhow::Result<Vec<GapEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT seq, min_bucket, max_bucket, lost_bytes, reason, created_at
             FROM gaps ORDER BY seq",
        )?;
        statement
            .query_map([], |row| {
                Ok(GapEvent {
                    seq: unsigned(row, 0)?,
                    min_bucket: optional_unsigned(row, 1)?,
                    max_bucket: optional_unsigned(row, 2)?,
                    lost_bytes: unsigned(row, 3)?,
                    reason: row.get(4)?,
                    created_at: unsigned(row, 5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

fn configure(connection: &Connection, max_payload_bytes: u64) -> anyhow::Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 100_i64)?;
    connection.pragma_update(None, "journal_size_limit", WAL_LIMIT_BYTES)?;
    let page_size = connection.pragma_query_value(None, "page_size", |row| unsigned(row, 0))?;
    let max_pages = (max_payload_bytes + SQLITE_OVERHEAD_BYTES).div_ceil(page_size);
    connection.pragma_update(
        None,
        "max_page_count",
        integer(max_pages, "max_page_count")?,
    )?;
    Ok(())
}

fn enforce_limits(
    transaction: &Transaction<'_>,
    limits: SpoolLimits,
    now: u64,
) -> anyhow::Result<u64> {
    let cutoff = now.saturating_sub(limits.max_age_seconds);
    let cutoff_sql = integer(cutoff, "spool cutoff")?;
    let max_payload_bytes_sql = integer(limits.max_payload_bytes, "max_payload_bytes")?;
    let mut evicted = 0;
    loop {
        let total_bytes = transaction.query_row(
            "SELECT COALESCE(SUM(payload_bytes), 0) FROM batches",
            [],
            |row| unsigned(row, 0),
        )?;
        let total_bytes_sql = integer(total_bytes, "total_payload_bytes")?;
        let candidate = transaction
            .query_row(
                "SELECT seq, min_bucket, max_bucket, payload_bytes, created_at
                 FROM batches
                 WHERE created_at < ? OR ? > ?
                 ORDER BY seq
                 LIMIT 1",
                params![cutoff_sql, total_bytes_sql, max_payload_bytes_sql],
                |row| {
                    Ok((
                        unsigned(row, 0)?,
                        optional_unsigned(row, 1)?,
                        optional_unsigned(row, 2)?,
                        unsigned(row, 3)?,
                        unsigned(row, 4)?,
                    ))
                },
            )
            .optional()?;
        let Some((seq, min_bucket, max_bucket, payload_bytes, created_at)) = candidate else {
            return Ok(evicted);
        };
        let reason = if created_at < cutoff {
            "spool_age_limit"
        } else {
            "spool_byte_limit"
        };
        transaction.execute("DELETE FROM batches WHERE seq = ?", [integer(seq, "seq")?])?;
        insert_gap(
            transaction,
            seq,
            min_bucket,
            max_bucket,
            payload_bytes,
            reason,
            now,
        )?;
        evicted += 1;
    }
}

fn insert_gap(
    transaction: &Transaction<'_>,
    seq: u64,
    min_bucket: Option<u64>,
    max_bucket: Option<u64>,
    lost_bytes: u64,
    reason: &str,
    created_at: u64,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO gaps(seq, min_bucket, max_bucket, lost_bytes, reason, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            integer(seq, "gap seq").map_err(to_sql_error)?,
            min_bucket
                .map(|value| integer(value, "gap min_bucket"))
                .transpose()
                .map_err(to_sql_error)?,
            max_bucket
                .map(|value| integer(value, "gap max_bucket"))
                .transpose()
                .map_err(to_sql_error)?,
            integer(lost_bytes, "gap lost_bytes").map_err(to_sql_error)?,
            reason,
            integer(created_at, "gap created_at").map_err(to_sql_error)?,
        ],
    )?;
    Ok(())
}

fn to_sql_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(error.into())
}

fn bucket_range(buckets: &[FlowBucket]) -> (Option<u64>, Option<u64>) {
    (
        buckets.iter().map(|bucket| bucket.bucket_start).min(),
        buckets.iter().map(|bucket| bucket.bucket_start).max(),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tempfile::tempdir;

    use super::*;
    use crate::model::{Direction, FlowKey, TransportProtocol};

    fn bucket(timestamp: u64) -> FlowBucket {
        FlowBucket {
            bucket_start: timestamp,
            key: FlowKey {
                capture_point: "physical:eth0".into(),
                direction: Direction::Egress,
                protocol: TransportProtocol::Tcp,
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                destination_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                source_port: Some(40000),
                destination_port: Some(443),
            },
            packets: 1,
            bytes: 100,
        }
    }

    #[test]
    fn byte_limit_evicts_oldest_and_records_gap() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("spool.db");
        let mut spool = Spool::open(
            path,
            SpoolLimits {
                max_payload_bytes: 700,
                max_age_seconds: 3600,
            },
        )
        .unwrap();
        spool
            .enqueue(
                "node".into(),
                "boot".into(),
                100,
                vec![bucket(100)],
                Default::default(),
            )
            .unwrap();
        let result = spool
            .enqueue(
                "node".into(),
                "boot".into(),
                110,
                vec![bucket(110)],
                Default::default(),
            )
            .unwrap();

        assert_eq!(result.evicted_batches, 1);
        assert_eq!(spool.status().unwrap().pending_batches, 1);
        assert_eq!(spool.gaps().unwrap()[0].seq, 0);
        assert_eq!(spool.gaps().unwrap()[0].reason, "spool_byte_limit");
    }

    #[test]
    fn age_limit_records_bucket_range() {
        let directory = tempdir().unwrap();
        let mut spool = Spool::open(
            directory.path().join("spool.db"),
            SpoolLimits {
                max_payload_bytes: 1_000_000,
                max_age_seconds: 10,
            },
        )
        .unwrap();
        spool
            .enqueue(
                "node".into(),
                "boot".into(),
                100,
                vec![bucket(90)],
                Default::default(),
            )
            .unwrap();
        spool
            .enqueue(
                "node".into(),
                "boot".into(),
                120,
                vec![bucket(120)],
                Default::default(),
            )
            .unwrap();

        let gap = &spool.gaps().unwrap()[0];
        assert_eq!((gap.min_bucket, gap.max_bucket), (Some(90), Some(90)));
        assert_eq!(gap.reason, "spool_age_limit");
    }
}
