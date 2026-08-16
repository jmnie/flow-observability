# Roadmap

Flow Observability is intended for continuous development. The roadmap is ordered by proving correctness and operability before expanding deployment scope.

## Current

- Header-only packet capture with explicit local-address direction.
- Ten-second flow aggregation with node and capture-point provenance.
- Bounded SQLite agent spool with explicit gap records.
- Idempotent ingest, `(node_id, capture_point)` inventory discovery, and provenance-preserving stats/series queries.
- Automated formatting, test, lint, and live-capture build checks.

## Next

- Node view and same-timeline comparison view.
- CPU, memory, packet-drop, spool-size, and ingest-lag visibility per node.
- Cross-platform capture validation and resource-budget measurements.
- Configuration, packaging, and release documentation.

## Design decisions still open

- **Continuous delivery:** release targets, artifact signing, approval gates, rollback, and how deployments receive host-specific configuration without committing it to the repository.
- **GitHub Actions automation:** which maintenance jobs need a bot, the minimum permissions for each job, and which writes require human approval.
- **Resource visualization:** sampling cadence, retention, aggregation, and whether runtime metrics share the traffic data path or use a separate metrics path.

CD, write-capable automation, and public deployment remain out of scope until these boundaries are agreed.
