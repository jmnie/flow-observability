# Backend verification

The current verification covers data-path semantics, bounded storage, and the opt-in live-capture build. Results below use neutral fixture names and do not describe a deployment topology.

## Automated checks

```text
cargo test --all-targets --all-features       9 passed
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --features live-capture
```

## Data-path proof

Two fixture nodes shared one spool and control database without losing provenance:

```text
before upload:  5 batches, 2,863 payload bytes
offline upload: connection refused; all 5 batches remained pending
online upload:  5 acknowledged; spool returned to 0 pending
node-a query:   3 batches, 3 buckets, 33 packets, 3,300 bytes
node-b query:   2 batches, 2 buckets, 21 packets, 2,100 bytes
```

`/v1/stats` without a `node` parameter returned HTTP 400. Restarting the control process against the same database preserved the `node-a` result. Unit tests separately prove that exact duplicate ingest is idempotent and conflicting checksums are rejected.

## Storage-limit proof

A stress run with a 1 MiB control database cap reached the limit and returned HTTP 507. The uploader retained the unacknowledged batches in its bounded spool for retry. This verifies the fail-closed storage behavior; production limits still need to be selected from representative workload measurements.

## Remaining evidence

- Measure CPU, memory, packet loss, queue lag, and database growth under a representative long-running workload.
- Verify live capture on each supported operating-system and kernel family.
- Quantify bytes per hour and select spool and control-plane defaults from measured traffic.
