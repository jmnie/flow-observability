use std::{
    net::IpAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use flow_observability_spike::{
    control,
    model::{CaptureDiagnostics, Direction, FlowBucket, FlowKey, TransportProtocol},
    spool::{Spool, SpoolLimits},
    upload,
};

#[derive(Debug, Parser)]
#[command(name = "flow-observability-spike")]
#[command(about = "Bounded Phase 0C flow observability spike")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9080")]
        listen: String,
        #[command(flatten)]
        limits: ControlLimitArgs,
    },
    Synthetic {
        #[arg(long)]
        spool: PathBuf,
        #[arg(long, default_value = "synthetic")]
        node: String,
        #[arg(long, default_value_t = 3)]
        batches: u64,
        #[command(flatten)]
        limits: LimitArgs,
    },
    UploadOnce {
        #[arg(long)]
        spool: PathBuf,
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Status {
        #[arg(long)]
        spool: PathBuf,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Gaps {
        #[arg(long)]
        spool: PathBuf,
        #[command(flatten)]
        limits: LimitArgs,
    },
    #[cfg(feature = "live-capture")]
    Capture {
        #[arg(long)]
        interface: String,
        #[arg(long, required = true)]
        local_ip: Vec<IpAddr>,
        #[arg(long)]
        node: String,
        #[arg(long)]
        capture_point: String,
        #[arg(long)]
        spool: PathBuf,
        #[arg(long)]
        boot_id: Option<String>,
        #[arg(long, default_value_t = 10)]
        bucket_seconds: u64,
        #[arg(long)]
        max_batches: Option<u64>,
        #[command(flatten)]
        limits: LimitArgs,
    },
}

#[derive(Debug, Clone, clap::Args)]
struct LimitArgs {
    #[arg(long, default_value_t = 128)]
    max_spool_mib: u64,
    #[arg(long, default_value_t = 24)]
    max_spool_hours: u64,
}

#[derive(Debug, Clone, clap::Args)]
struct ControlLimitArgs {
    #[arg(long, default_value_t = 128)]
    max_control_mib: u64,
    #[arg(long, default_value_t = 48)]
    max_control_hours: u64,
}

impl ControlLimitArgs {
    fn limits(&self) -> control::ControlLimits {
        control::ControlLimits {
            max_database_bytes: self.max_control_mib * 1024 * 1024,
            max_age_seconds: self.max_control_hours * 60 * 60,
        }
    }
}

impl LimitArgs {
    fn limits(&self) -> SpoolLimits {
        SpoolLimits {
            max_payload_bytes: self.max_spool_mib * 1024 * 1024,
            max_age_seconds: self.max_spool_hours * 60 * 60,
        }
    }
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Serve { db, listen, limits } => {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()?
                .block_on(control::serve(db, &listen, limits.limits()))?;
        }
        Command::Synthetic {
            spool,
            node,
            batches,
            limits,
        } => synthetic(spool, node, batches, limits.limits())?,
        Command::UploadOnce {
            spool,
            url,
            limit,
            limits,
        } => {
            let spool = Spool::open(spool, limits.limits())?;
            let report = upload::upload_once(&spool, &url, limit)?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "acknowledged": report.acknowledged,
                    "spool": spool.status()?,
                }))?
            );
        }
        Command::Status { spool, limits } => {
            let spool = Spool::open(spool, limits.limits())?;
            println!("{}", serde_json::to_string(&spool.status()?)?);
        }
        Command::Gaps { spool, limits } => {
            let spool = Spool::open(spool, limits.limits())?;
            println!("{}", serde_json::to_string(&spool.gaps()?)?);
        }
        #[cfg(feature = "live-capture")]
        Command::Capture {
            interface,
            local_ip,
            node,
            capture_point,
            spool,
            boot_id,
            bucket_seconds,
            max_batches,
            limits,
        } => flow_observability_spike::capture::run(
            flow_observability_spike::capture::CaptureConfig {
                interface,
                local_ips: local_ip,
                node_id: node,
                boot_id: boot_id.unwrap_or_else(default_boot_id),
                capture_point,
                spool_path: spool,
                bucket_seconds,
                limits: limits.limits(),
                max_batches,
            },
        )?,
    }
    Ok(())
}

fn synthetic(path: PathBuf, node: String, batches: u64, limits: SpoolLimits) -> anyhow::Result<()> {
    let mut spool = Spool::open(path, limits)?;
    let now = unix_seconds()?;
    for index in 0..batches {
        let bucket_start = now + index * 10;
        spool.enqueue(
            node.clone(),
            "synthetic-boot".into(),
            bucket_start,
            vec![FlowBucket {
                bucket_start,
                key: FlowKey {
                    capture_point: "synthetic:fixture".into(),
                    direction: Direction::Egress,
                    protocol: TransportProtocol::Tcp,
                    source_ip: "10.0.0.2".parse::<IpAddr>()?,
                    destination_ip: "1.1.1.1".parse::<IpAddr>()?,
                    source_port: Some(40000 + index as u16),
                    destination_port: Some(443),
                },
                packets: 10 + index,
                bytes: 1_000 + index * 100,
            }],
            CaptureDiagnostics::default(),
        )?;
    }
    println!("{}", serde_json::to_string(&spool.status()?)?);
    Ok(())
}

fn unix_seconds() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(feature = "live-capture")]
fn default_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| format!("process-{}", std::process::id()))
}
