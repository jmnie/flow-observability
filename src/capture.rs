use std::{
    net::IpAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use pcap::{Capture, Error};

use crate::{
    aggregate::Aggregator,
    model::CaptureDiagnostics,
    packet::parse_packet,
    spool::{Spool, SpoolLimits},
};

pub struct CaptureConfig {
    pub interface: String,
    pub local_ips: Vec<IpAddr>,
    pub node_id: String,
    pub boot_id: String,
    pub capture_point: String,
    pub spool_path: PathBuf,
    pub bucket_seconds: u64,
    pub limits: SpoolLimits,
    pub max_batches: Option<u64>,
}

pub fn run(config: CaptureConfig) -> anyhow::Result<()> {
    if config.local_ips.is_empty() {
        bail!("at least one --local-ip is required to classify direction");
    }
    let mut capture = Capture::from_device(config.interface.as_str())?
        .promisc(false)
        .snaplen(256)
        .buffer_size(1024 * 1024)
        .immediate_mode(true)
        .timeout(1000)
        .open()
        .with_context(|| format!("open pcap interface {}", config.interface))?;
    capture.filter("ip or ip6", true)?;
    let link_type = capture.get_datalink().0;
    let mut spool = Spool::open(&config.spool_path, config.limits)?;
    let mut aggregator = Aggregator::new(config.bucket_seconds);
    let mut parse_errors = 0_u64;
    let mut prior_stats = (0_u64, 0_u64, 0_u64);
    let mut emitted = 0_u64;

    loop {
        match capture.next_packet() {
            Ok(packet) => {
                let timestamp = packet.header.ts.tv_sec as u64;
                match parse_packet(
                    packet.data,
                    link_type,
                    timestamp,
                    packet.header.len.into(),
                    &config.capture_point,
                    &config.local_ips,
                ) {
                    Ok(Some(packet)) => aggregator.push(packet),
                    Ok(None) => {}
                    Err(_) => parse_errors += 1,
                }
            }
            Err(Error::TimeoutExpired) => {}
            Err(error) => return Err(error.into()),
        }
        let now = unix_seconds()?;
        let current_bucket = now / config.bucket_seconds * config.bucket_seconds;
        let buckets = aggregator.drain_before(current_bucket);
        if buckets.is_empty() {
            continue;
        }
        let stats = capture.stats()?;
        let current_stats = (
            u64::from(stats.received),
            u64::from(stats.dropped),
            u64::from(stats.if_dropped),
        );
        let diagnostics = CaptureDiagnostics {
            received: current_stats.0.saturating_sub(prior_stats.0),
            dropped: current_stats.1.saturating_sub(prior_stats.1),
            interface_dropped: current_stats.2.saturating_sub(prior_stats.2),
            parse_errors,
        };
        prior_stats = current_stats;
        parse_errors = 0;
        let result = spool.enqueue(
            config.node_id.clone(),
            config.boot_id.clone(),
            now,
            buckets,
            diagnostics,
        )?;
        println!(
            "{}",
            serde_json::json!({
                "batch_id": result.batch_id,
                "evicted_batches": result.evicted_batches,
                "spool": spool.status()?,
            })
        );
        emitted += 1;
        if config.max_batches.is_some_and(|maximum| emitted >= maximum) {
            let remaining = aggregator.drain_all();
            if !remaining.is_empty() {
                spool.enqueue(
                    config.node_id,
                    config.boot_id,
                    unix_seconds()?,
                    remaining,
                    CaptureDiagnostics::default(),
                )?;
            }
            return Ok(());
        }
    }
}

fn unix_seconds() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}
