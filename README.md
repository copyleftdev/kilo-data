# Kilo Data

Kilo Data is the open, deterministic threat-intelligence and IP-reputation data
pipeline for KiloCheck. It retrieves complete bulk publications from original
sources, validates and normalizes them, and publishes reproducible Apache Arrow
and Parquet release artifacts. It does not contain the future KiloCheck query
CLI and never performs per-IP intelligence lookups.

## Dataset coverage

- Threat indicators and evidence from established blocklists and malware
  infrastructure publications.
- BGP route-origin data, Regional Internet Registry (RIR) allocations, and IANA
  special-purpose address registries.
- Cloud-provider, crawler, Tor-exit, and network-attribution context.
- Normalized columnar tables designed for offline phishing and malware
  screening, threat detection, and IP intelligence tools.

## Current data workflow

```text
immutable bulk artifacts
        ↓
catalog hash validation
        ↓
format-aware corpus profiling
        ↓
source-native parsed records (Parquet)
        ↓
canonical semantic tables (next)
        ↓
optimized runtime index (later)
```

No collection or compilation command performs per-IP API lookups.

## Commands

```bash
cargo run -p kilo-data -- validate
cargo run -p kilo-data -- inspect
cargo run -p kilo-data -- compile-source-records
cargo run -p kilo-data -- compile-canonical
cargo run -p kilo-data -- validate-canonical
```

- `validate` verifies every artifact against `reference-data/sources.toml`.
- `inspect` regenerates `reference-data/profiles.json` without modifying inputs.
- `compile-source-records` rebuilds `dataset/source_records.parquet` from all
  cataloged artifacts.
- `compile-canonical` rebuilds the normalized indicator, allocation, routing,
  provider-context, and evidence tables.
- `validate-canonical` checks primary-key uniqueness and every cross-table
  indicator reference.

The source catalog and corpus review notes live in
`reference-data/README.md` and `reference-data/SOURCES.md`.

The public dataset release cadence, stable/edge channels, and future CLI merge
contract are documented in [docs/data-releases.md](docs/data-releases.md).
