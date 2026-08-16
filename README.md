# Flow Observability

Flow Observability is an actively developed Rust project for lightweight traffic capture, bounded local buffering, and provenance-preserving comparison across independent nodes.

The current backend data path is:

```text
pcap headers -> 10s flow buckets -> bounded SQLite spool
             -> idempotent HTTP ingest -> provenance-preserving node/stats/series queries
```

It never persists packet payloads or pcap files. Live capture reads only enough bytes for L2/L3/L4 headers. Both agent and control-plane storage have byte and age limits, and agent-side eviction records explicit gaps.

## Development

Run the backend proof locally:

```bash
cargo test --all-targets
cargo run -- synthetic --spool /tmp/flow-spool.db --batches 3
cargo run -- serve --db /tmp/flow-control.db --listen 127.0.0.1:9080
cargo run -- upload-once --spool /tmp/flow-spool.db --url http://127.0.0.1:9080/v1/ingest
curl 'http://127.0.0.1:9080/v1/nodes'
curl 'http://127.0.0.1:9080/v1/stats?node=synthetic'
curl 'http://127.0.0.1:9080/v1/stats?node=synthetic&capture_point=synthetic:fixture'
curl 'http://127.0.0.1:9080/v1/series?node=synthetic'
curl 'http://127.0.0.1:9080/v1/series?node=synthetic&capture_point=synthetic:fixture'
```

Install the packet-capture headers and build the opt-in live-capture feature:

```bash
sudo apt-get install --no-install-recommends libpcap-dev
cargo build --release --features live-capture
```

Example capture command (local IPs must be explicit so direction is not guessed):

```bash
sudo ./target/release/flow-observability-spike capture \
  --interface eth0 \
  --local-ip 192.0.2.10 \
  --node node-a \
  --capture-point physical:eth0 \
  --spool /var/lib/flow-observability/spool.db \
  --max-spool-mib 128 \
  --max-spool-hours 24
```

`192.0.2.10` is a documentation-only address. Replace the interface, local IP, node ID, and storage path with values for your environment.

## Current boundaries

- The default spool payload budget is 128 MiB. SQLite main-file growth is capped with `max_page_count`, and WAL journal size is limited.
- The control database defaults to a 128 MiB main-file cap, a 4 MiB WAL cap, and 48-hour retention. Override these with `--max-control-mib` and `--max-control-hours`.
- Overflow evicts the oldest unacknowledged batch and records its bucket range as a gap.
- The control server defaults to loopback. Authentication, internet-facing deployment, and multi-user access are not implemented.
- No frontend is included yet. The first UI milestone will preserve `node + capture_point + time window` provenance in node and comparison views.

See [backend verification](docs/backend-verification.md) for the current proof and [roadmap](docs/roadmap.md) for planned work.
