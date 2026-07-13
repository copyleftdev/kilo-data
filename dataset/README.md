# KiloCheck columnar dataset

`source_records.parquet` is the first compiled layer of the KiloCheck data
pipeline. It contains source-native parsed records from every artifact listed in
`reference-data/sources.toml`.

Generated at the initial compilation:

- 5,069,251 parsed records
- 32 input artifacts
- 5 Parquet row groups
- Zstandard level 3 compression
- SHA-256: `5e6b562e431c59410b7536f0125dd7799dc5324b8f956106ff3d248a76c8856f`

## Columns

| Column | Arrow type | Meaning |
| --- | --- | --- |
| `source_id` | UTF-8 | Stable source catalog identifier |
| `record_index` | unsigned 64-bit integer | Ordinal within one parsed artifact |
| `collection` | nullable UTF-8 | Named JSON collection or archive-entry type |
| `raw_record` | UTF-8 | Canonical JSON representation of the parsed source record |
| `raw_record_hash` | UTF-8 | SHA-256 of `raw_record` |

This table does not replace the immutable artifacts. Formatting, comments, and
container metadata may be separated or canonicalized while parsing. Exact input
bytes remain under `reference-data/` and are pinned by the artifact hashes in
`sources.toml` and `CHECKSUMS.sha256`.

This table is deliberately pre-normalization. It proves complete ingestion and
provides one queryable columnar surface for schema analysis. Semantic tables
such as indicators, claims, allocations, route origins, and provider ranges
will be compiled from this layer only after their mappings and invariants are
explicitly defined.

