use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use arrow::{
    array::{Array, ArrayRef, StringArray, UInt8Array, UInt32Array, UInt64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use flate2::read::GzDecoder;
use parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    basic::{Compression, ZstdLevel},
    file::properties::WriterProperties,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::catalog::{self, Catalog, Source};

#[derive(Clone)]
struct Indicator {
    id: String,
    kind: String,
    value: String,
    version: Option<u8>,
    prefix: Option<u8>,
}
struct Allocation {
    indicator: String,
    registry: String,
    status: String,
    country: Option<String>,
    date: Option<String>,
    source: String,
    record: u64,
}
struct Route {
    prefix: String,
    asn: String,
    peers: Option<u32>,
    source: String,
    record: u64,
}
struct Provider {
    indicator: String,
    provider: String,
    service: Option<String>,
    region: Option<String>,
    border: Option<String>,
    role: String,
    source: String,
    record: u64,
}
struct Claim {
    id: String,
    indicator: String,
    source: String,
    claim_type: String,
    classification: Option<String>,
    first: Option<String>,
    last: Option<String>,
    confidence: Option<String>,
    record: u64,
    attributes: String,
}
struct Special {
    indicator: String,
    name: String,
    reference: String,
    allocation: Option<String>,
    termination: Option<String>,
    source_allowed: Option<String>,
    destination: Option<String>,
    forwardable: Option<String>,
    globally_reachable: Option<String>,
    reserved_protocol: Option<String>,
    source: String,
    record: u64,
}

pub fn compile(catalog_path: &Path, output: &Path) -> Result<()> {
    let catalog = catalog::load(catalog_path)?;
    fs::create_dir_all(output)?;
    let mut indicators = BTreeMap::new();
    let allocations = allocations(&catalog, catalog_path, &mut indicators)?;
    let routes = routes(&catalog, catalog_path, &mut indicators)?;
    let providers = providers(&catalog, catalog_path, &mut indicators)?;
    let claims = claims(&catalog, catalog_path, &mut indicators)?;
    let special = special_purpose(&catalog, catalog_path, &mut indicators)?;
    write_indicators(output, &indicators)?;
    write_allocations(output, &allocations)?;
    write_routes(output, &routes)?;
    write_providers(output, &providers)?;
    write_claims(output, &claims)?;
    write_special(output, &special)?;
    let tables = [
        ("claims", claims.len()),
        ("indicators", indicators.len()),
        ("network_allocations", allocations.len()),
        ("provider_ranges", providers.len()),
        ("route_origins", routes.len()),
        ("special_purpose", special.len()),
    ];
    let table_rows = tables
        .iter()
        .map(|(name, rows)| {
            let hash = catalog::digest(&output.join(format!("{name}.parquet")))
                .expect("compiled table digest");
            (
                (*name).to_owned(),
                serde_json::json!({"rows":rows,"sha256":hash}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let snapshot = id(&[&table_rows
        .values()
        .map(|v| v["sha256"].as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(":")]);
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"schema":"kilo.canonical.snapshot.v1","created_at":catalog.collected_at,"snapshot_id":snapshot,"compiler":"kilo-data 0.1.0","tables":table_rows,"sources":catalog.sources.iter().filter(|s|!matches!(s.status.as_str(),"license-review"|"context-only-upstream-review")).map(|s|serde_json::json!({"id":s.id,"sha256":s.sha256,"refresh":s.refresh,"status":s.status})).collect::<Vec<_>>()}),
        )?,
    )?;
    println!(
        "canonical\t{} indicators\t{} allocations\t{} routes\t{} provider ranges\t{} claims\t{} special-purpose rows",
        indicators.len(),
        allocations.len(),
        routes.len(),
        providers.len(),
        claims.len(),
        special.len()
    );
    Ok(())
}

pub fn compile_edge(catalog_path: &Path, output: &Path) -> Result<()> {
    let catalog = catalog::load(catalog_path)?;
    fs::create_dir_all(output)?;
    let mut indicators = BTreeMap::new();
    let claims = edge_claims(&catalog, catalog_path, &mut indicators)?;
    write_indicators(output, &indicators)?;
    write_claims(output, &claims)?;
    let snapshot = id(&[&catalog
        .sources
        .iter()
        .filter(|s| matches!(s.id.as_str(), "feodo-c2" | "tor-exits"))
        .map(|s| s.sha256.as_str())
        .collect::<Vec<_>>()
        .join(":")]);
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"schema":"kilo.edge.snapshot.v1","created_at":catalog.collected_at,"snapshot_id":snapshot,"indicators":indicators.len(),"claims":claims.len(),"sources":catalog.sources.iter().filter(|s|matches!(s.id.as_str(),"feodo-c2"|"tor-exits")).map(|s|serde_json::json!({"id":s.id,"sha256":s.sha256,"refresh":s.refresh})).collect::<Vec<_>>()}),
        )?,
    )?;
    println!(
        "edge\t{} indicators\t{} claims",
        indicators.len(),
        claims.len()
    );
    Ok(())
}

fn edge_claims(
    c: &Catalog,
    cp: &Path,
    inds: &mut BTreeMap<String, Indicator>,
) -> Result<Vec<Claim>> {
    let mut out = Vec::new();
    let s = source(c, "feodo-c2")?;
    let rows: Vec<Value> = serde_json::from_reader(File::open(artifact(cp, s))?)?;
    for (record, v) in rows.into_iter().enumerate() {
        let ip = v["ip_address"].as_str().context("Feodo IP")?;
        let kind = if ip.contains(':') { "ipv6" } else { "ipv4" };
        let indicator = add_indicator(inds, kind, ip)?;
        out.push(Claim {
            id: id(&[
                &s.id,
                &record.to_string(),
                &indicator,
                "command-and-control",
            ]),
            indicator,
            source: s.id.clone(),
            claim_type: "directly-observed".into(),
            classification: Some("command-and-control".into()),
            first: v["first_seen"].as_str().map(str::to_owned),
            last: v["last_online"].as_str().map(str::to_owned),
            confidence: Some("confirmed".into()),
            record: record as u64,
            attributes: serde_json::to_string(&v)?,
        });
    }
    let s = source(c, "tor-exits")?;
    let mut record = 0;
    for line in BufReader::new(File::open(artifact(cp, s))?).lines() {
        let ip = line?;
        if ip.trim().is_empty() || ip.starts_with('#') {
            continue;
        }
        let kind = if ip.contains(':') { "ipv6" } else { "ipv4" };
        let indicator = add_indicator(inds, kind, ip.trim())?;
        out.push(Claim {
            id: id(&[&s.id, &record.to_string(), &indicator, "tor-exit"]),
            indicator,
            source: s.id.clone(),
            claim_type: "provider-published".into(),
            classification: Some("tor-exit".into()),
            first: None,
            last: None,
            confidence: Some("confirmed".into()),
            record,
            attributes: "{}".into(),
        });
        record += 1;
    }
    Ok(out)
}

pub fn validate(dataset: &Path) -> Result<()> {
    let indicator_path = dataset.join("indicators.parquet");
    let file = File::open(&indicator_path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let mut ids = HashSet::new();
    let mut duplicate_indicators = 0_u64;
    for batch in builder.build()? {
        let batch = batch?;
        let column = batch
            .column_by_name("indicator_id")
            .context("indicator_id column")?
            .as_any()
            .downcast_ref::<StringArray>()
            .context("indicator_id UTF-8")?;
        for value in column.iter().flatten() {
            if !ids.insert(value.to_owned()) {
                duplicate_indicators += 1;
            }
        }
    }
    if duplicate_indicators != 0 {
        bail!("{duplicate_indicators} duplicate indicator IDs");
    }
    for (file, columns) in [
        ("network_allocations.parquet", &["indicator_id"][..]),
        (
            "route_origins.parquet",
            &["prefix_indicator_id", "origin_asn_indicator_id"][..],
        ),
        ("provider_ranges.parquet", &["indicator_id"][..]),
        ("claims.parquet", &["indicator_id"][..]),
        ("special_purpose.parquet", &["indicator_id"][..]),
    ] {
        let path = dataset.join(file);
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?.build()?;
        let mut rows = 0_u64;
        for batch in reader {
            let batch = batch?;
            rows += batch.num_rows() as u64;
            for name in columns {
                let column = batch
                    .column_by_name(name)
                    .with_context(|| format!("{file}:{name}"))?
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .context("reference UTF-8")?;
                for value in column.iter().flatten() {
                    if !ids.contains(value) {
                        bail!("dangling {file}:{name} reference {value}");
                    }
                }
            }
        }
        println!("valid\t{file}\t{rows} rows");
    }
    let reader =
        ParquetRecordBatchReaderBuilder::try_new(File::open(dataset.join("claims.parquet"))?)?
            .build()?;
    let mut claim_ids = HashSet::new();
    for batch in reader {
        let batch = batch?;
        let column = batch
            .column_by_name("claim_id")
            .context("claim_id")?
            .as_any()
            .downcast_ref::<StringArray>()
            .context("claim_id UTF-8")?;
        for value in column.iter().flatten() {
            if !claim_ids.insert(value.to_owned()) {
                bail!("duplicate claim ID {value}");
            }
        }
    }
    println!(
        "validated\t{} unique indicators\t{} unique claims",
        ids.len(),
        claim_ids.len()
    );
    Ok(())
}

fn special_purpose(
    c: &Catalog,
    cp: &Path,
    inds: &mut BTreeMap<String, Indicator>,
) -> Result<Vec<Special>> {
    let mut out = Vec::new();
    for id0 in ["iana-ipv4-special", "iana-ipv6-special"] {
        let s = source(c, id0)?;
        let mut reader = csv::Reader::from_path(artifact(cp, s))?;
        for (record, row) in reader.deserialize::<BTreeMap<String, String>>().enumerate() {
            let row = row?;
            let blocks = row.get("Address Block").context("IANA address block")?;
            for block in blocks.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                let block = block.split_once(" [").map_or(block, |(value, _)| value);
                let indicator = add_indicator(inds, "prefix", block)?;
                out.push(Special {
                    indicator,
                    name: row.get("Name").cloned().unwrap_or_default(),
                    reference: row.get("RFC").cloned().unwrap_or_default(),
                    allocation: clean(row.get("Allocation Date")),
                    termination: clean(row.get("Termination Date")),
                    source_allowed: clean(row.get("Source")),
                    destination: clean(row.get("Destination")),
                    forwardable: clean(row.get("Forwardable")),
                    globally_reachable: clean(row.get("Globally Reachable")),
                    reserved_protocol: clean(row.get("Reserved-by-Protocol")),
                    source: s.id.clone(),
                    record: record as u64,
                });
            }
        }
    }
    let s = source(c, "iana-asn-special")?;
    let mut reader = csv::Reader::from_path(artifact(cp, s))?;
    for (record, row) in reader.deserialize::<BTreeMap<String, String>>().enumerate() {
        let row = row?;
        let subject = row.get("AS Number").context("IANA AS number")?;
        let kind = if subject.contains('-') {
            "asn-range"
        } else {
            "asn"
        };
        let indicator = add_indicator(inds, kind, subject)?;
        out.push(Special {
            indicator,
            name: row
                .get("Reason for Reservation")
                .cloned()
                .unwrap_or_default(),
            reference: row.get("Reference").cloned().unwrap_or_default(),
            allocation: None,
            termination: None,
            source_allowed: None,
            destination: None,
            forwardable: None,
            globally_reachable: None,
            reserved_protocol: None,
            source: s.id.clone(),
            record: record as u64,
        });
    }
    Ok(out)
}
fn clean(v: Option<&String>) -> Option<String> {
    v.filter(|v| !v.is_empty() && v.as_str() != "N/A").cloned()
}

fn source<'a>(catalog: &'a Catalog, id: &str) -> Result<&'a Source> {
    catalog
        .sources
        .iter()
        .find(|s| s.id == id)
        .with_context(|| format!("catalog source {id}"))
}
fn artifact(catalog_path: &Path, s: &Source) -> std::path::PathBuf {
    catalog::resolve(catalog_path, s)
}
fn id(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    hex::encode(h.finalize())
}

fn add_indicator(map: &mut BTreeMap<String, Indicator>, kind: &str, value: &str) -> Result<String> {
    let (value, version, prefix) = match kind {
        "ipv4" => (IpAddr::from_str(value)?.to_string(), Some(4), Some(32)),
        "ipv6" => (IpAddr::from_str(value)?.to_string(), Some(6), Some(128)),
        "prefix" => {
            let (v, ver, p) = canonical_prefix(value)?;
            (v, Some(ver), Some(p))
        }
        "asn" => {
            let n: u32 = value.trim_start_matches("AS").parse()?;
            (n.to_string(), None, None)
        }
        "asn-range" => (value.to_owned(), None, None),
        _ => bail!("unknown indicator kind {kind}"),
    };
    let key = id(&[kind, &value]);
    map.entry(key.clone()).or_insert(Indicator {
        id: key.clone(),
        kind: kind.into(),
        value,
        version,
        prefix,
    });
    Ok(key)
}

fn canonical_prefix(value: &str) -> Result<(String, u8, u8)> {
    let (ip, p) = value.split_once('/').context("CIDR missing slash")?;
    let ip = IpAddr::from_str(ip)?;
    let p: u8 = p.parse()?;
    match ip {
        IpAddr::V4(v) => {
            if p > 32 {
                bail!("bad IPv4 prefix")
            };
            let n = u32::from(v) & if p == 0 { 0 } else { u32::MAX << (32 - p) };
            Ok((format!("{}/{}", Ipv4Addr::from(n), p), 4, p))
        }
        IpAddr::V6(v) => {
            if p > 128 {
                bail!("bad IPv6 prefix")
            };
            let n = u128::from(v) & if p == 0 { 0 } else { u128::MAX << (128 - p) };
            Ok((format!("{}/{}", Ipv6Addr::from(n), p), 6, p))
        }
    }
}

fn ipv4_cidrs(start: &str, count: u64) -> Result<Vec<String>> {
    let mut n = u32::from(Ipv4Addr::from_str(start)?) as u64;
    let mut left = count;
    let mut out = Vec::new();
    while left > 0 {
        let align = if n == 0 {
            1u64 << 32
        } else {
            1u64 << n.trailing_zeros()
        };
        let size = align.min(1u64 << (63 - left.leading_zeros())).min(left);
        let prefix = 32 - size.trailing_zeros();
        out.push(format!("{}/{}", Ipv4Addr::from(n as u32), prefix));
        n += size;
        left -= size;
    }
    Ok(out)
}

fn allocations(
    c: &Catalog,
    cp: &Path,
    inds: &mut BTreeMap<String, Indicator>,
) -> Result<Vec<Allocation>> {
    let mut out = Vec::new();
    for id0 in [
        "rir-afrinic",
        "rir-apnic",
        "rir-arin",
        "rir-lacnic",
        "rir-ripencc",
    ] {
        let s = source(c, id0)?;
        let mut record = 0;
        for line in BufReader::new(File::open(artifact(cp, s))?).lines() {
            let line = line?;
            let p: Vec<_> = line.split('|').collect();
            if p.len() < 7 || !matches!(p[2], "ipv4" | "ipv6" | "asn") {
                continue;
            }
            let values = match p[2] {
                "ipv4" => ipv4_cidrs(p[3], p[4].parse()?)?,
                "ipv6" => vec![format!("{}/{}", p[3], p[4])],
                "asn" => {
                    let start: u64 = p[3].parse()?;
                    let count: u64 = p[4].parse()?;
                    if count == 1 {
                        vec![start.to_string()]
                    } else {
                        vec![format!("{}-{}", start, start + count - 1)]
                    }
                }
                _ => unreachable!(),
            };
            for value in values {
                let kind = if p[2] == "asn" && value.contains('-') {
                    "asn-range"
                } else if p[2] == "asn" {
                    "asn"
                } else {
                    "prefix"
                };
                let indicator = add_indicator(inds, kind, &value)?;
                out.push(Allocation {
                    indicator,
                    registry: p[0].into(),
                    status: p[6].into(),
                    country: (!p[1].is_empty()).then(|| p[1].into()),
                    date: (p[5] != "00000000" && !p[5].is_empty()).then(|| p[5].into()),
                    source: s.id.clone(),
                    record,
                });
            }
            record += 1;
        }
    }
    Ok(out)
}

fn origins(value: &str) -> Vec<String> {
    value
        .trim_matches(|c| c == '{' || c == '}')
        .split(',')
        .filter_map(|v| v.trim().parse::<u32>().ok())
        .map(|v| v.to_string())
        .collect()
}
fn routes(c: &Catalog, cp: &Path, inds: &mut BTreeMap<String, Indicator>) -> Result<Vec<Route>> {
    let mut out = Vec::new();
    for id0 in ["ripe-ris-ipv4", "ripe-ris-ipv6"] {
        let s = source(c, id0)?;
        let reader = BufReader::new(GzDecoder::new(File::open(artifact(cp, s))?));
        let mut record = 0;
        for line in reader.lines() {
            let line = line?;
            if line.starts_with('%') || line.trim().is_empty() {
                continue;
            }
            let p: Vec<_> = line.split('\t').collect();
            if p.len() != 3 {
                continue;
            }
            let prefix = add_indicator(inds, "prefix", p[1])?;
            for origin in origins(p[0]) {
                let asn = add_indicator(inds, "asn", &origin)?;
                out.push(Route {
                    prefix: prefix.clone(),
                    asn,
                    peers: p[2].parse().ok(),
                    source: s.id.clone(),
                    record,
                });
            }
            record += 1;
        }
    }
    Ok(out)
}

fn providers(
    c: &Catalog,
    cp: &Path,
    inds: &mut BTreeMap<String, Indicator>,
) -> Result<Vec<Provider>> {
    let mut out = Vec::new();
    for id0 in [
        "aws-ranges",
        "gcp-cloud",
        "google-ranges",
        "google-common-crawlers",
        "google-special-crawlers",
        "google-user-fetchers",
        "google-user-fetchers-google",
        "google-user-agents",
    ] {
        let s = source(c, id0)?;
        let v: Value = serde_json::from_reader(File::open(artifact(cp, s))?)?;
        // source_records emits the non-array JSON envelope as record zero.
        let mut record = 1;
        for key in ["prefixes", "ipv6_prefixes"] {
            if let Some(rows) = v.get(key).and_then(Value::as_array) {
                for row in rows {
                    let cidr = ["ip_prefix", "ipv6_prefix", "ipv4Prefix", "ipv6Prefix"]
                        .iter()
                        .find_map(|k| row.get(k).and_then(Value::as_str));
                    if let Some(cidr) = cidr {
                        let indicator = add_indicator(inds, "prefix", cidr)?;
                        out.push(Provider {
                            indicator,
                            provider: if id0 == "aws-ranges" { "aws" } else { "google" }.into(),
                            service: row
                                .get("service")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            region: row
                                .get("region")
                                .or_else(|| row.get("scope"))
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            border: row
                                .get("network_border_group")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            role: if id0.contains("crawler")
                                || id0.contains("fetcher")
                                || id0.contains("agents")
                            {
                                "known-crawler"
                            } else {
                                "provider-range"
                            }
                            .into(),
                            source: s.id.clone(),
                            record,
                        });
                    }
                    record += 1;
                }
            }
        }
    }
    for (id0, provider) in [
        ("cloudflare-v4", "cloudflare"),
        ("cloudflare-v6", "cloudflare"),
    ] {
        let s = source(c, id0)?;
        for (record, line) in BufReader::new(File::open(artifact(cp, s))?)
            .lines()
            .enumerate()
        {
            let cidr = line?;
            if cidr.trim().is_empty() {
                continue;
            }
            let indicator = add_indicator(inds, "prefix", cidr.trim())?;
            out.push(Provider {
                indicator,
                provider: provider.into(),
                service: None,
                region: None,
                border: None,
                role: "provider-range".into(),
                source: s.id.clone(),
                record: record as u64,
            });
        }
    }
    Ok(out)
}

fn claims(c: &Catalog, cp: &Path, inds: &mut BTreeMap<String, Indicator>) -> Result<Vec<Claim>> {
    let mut out = Vec::new();
    for (id0, kind, class) in [
        ("spamhaus-drop-v4", "prefix", "dedicated-malicious-netblock"),
        ("spamhaus-drop-v6", "prefix", "dedicated-malicious-netblock"),
        ("spamhaus-asn-drop", "asn", "dedicated-malicious-network"),
    ] {
        let s = source(c, id0)?;
        for (record, line) in BufReader::new(File::open(artifact(cp, s))?)
            .lines()
            .enumerate()
        {
            let line = line?;
            let v: Value = serde_json::from_str(&line)?;
            let Some(subject_value) = v.get(if kind == "asn" { "asn" } else { "cidr" }) else {
                continue;
            };
            let subject = subject_value.to_string().trim_matches('"').to_owned();
            let indicator = add_indicator(inds, kind, &subject)?;
            let claim_id = id(&[&s.id, &record.to_string(), &indicator, class]);
            out.push(Claim {
                id: claim_id,
                indicator,
                source: s.id.clone(),
                claim_type: "investigator-confirmed".into(),
                classification: Some(class.into()),
                first: None,
                last: None,
                confidence: Some("confirmed".into()),
                record: record as u64,
                attributes: serde_json::to_string(&v)?,
            });
        }
    }
    let s = source(c, "feodo-c2")?;
    let rows: Vec<Value> = serde_json::from_reader(File::open(artifact(cp, s))?)?;
    for (record, v) in rows.into_iter().enumerate() {
        let ip = v["ip_address"].as_str().context("Feodo IP")?;
        let kind = if ip.contains(':') { "ipv6" } else { "ipv4" };
        let indicator = add_indicator(inds, kind, ip)?;
        out.push(Claim {
            id: id(&[
                &s.id,
                &record.to_string(),
                &indicator,
                "command-and-control",
            ]),
            indicator,
            source: s.id.clone(),
            claim_type: "directly-observed".into(),
            classification: Some("command-and-control".into()),
            first: v["first_seen"].as_str().map(str::to_owned),
            last: v["last_online"].as_str().map(str::to_owned),
            confidence: Some("confirmed".into()),
            record: record as u64,
            attributes: serde_json::to_string(&v)?,
        });
    }
    let s = source(c, "tor-exits")?;
    for (record, line) in BufReader::new(File::open(artifact(cp, s))?)
        .lines()
        .enumerate()
    {
        let ip = line?;
        if ip.trim().is_empty() {
            continue;
        }
        let kind = if ip.contains(':') { "ipv6" } else { "ipv4" };
        let indicator = add_indicator(inds, kind, ip.trim())?;
        out.push(Claim {
            id: id(&[&s.id, &record.to_string(), &indicator, "tor-exit"]),
            indicator,
            source: s.id.clone(),
            claim_type: "provider-published".into(),
            classification: Some("tor-exit".into()),
            first: None,
            last: None,
            confidence: Some("confirmed".into()),
            record: record as u64,
            attributes: "{}".into(),
        });
    }
    Ok(out)
}

fn props() -> Result<WriterProperties> {
    Ok(WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .set_created_by("kilo-data canonical compiler v0.1.0".into())
        .build())
}
fn write(path: &Path, schema: Schema, arrays: Vec<ArrayRef>) -> Result<()> {
    let schema = Arc::new(schema);
    let mut w = ArrowWriter::try_new(File::create(path)?, schema.clone(), Some(props()?))?;
    w.write(&RecordBatch::try_new(schema, arrays)?)?;
    w.close()?;
    Ok(())
}
fn strings<I: IntoIterator<Item = String>>(v: I) -> ArrayRef {
    Arc::new(StringArray::from_iter_values(v))
}
fn opts<I: IntoIterator<Item = Option<String>>>(v: I) -> ArrayRef {
    Arc::new(StringArray::from(v.into_iter().collect::<Vec<_>>()))
}
fn write_indicators(o: &Path, m: &BTreeMap<String, Indicator>) -> Result<()> {
    write(
        &o.join("indicators.parquet"),
        Schema::new(vec![
            Field::new("indicator_id", DataType::Utf8, false),
            Field::new("kind", DataType::Utf8, false),
            Field::new("canonical_value", DataType::Utf8, false),
            Field::new("ip_version", DataType::UInt8, true),
            Field::new("prefix_length", DataType::UInt8, true),
        ]),
        vec![
            strings(m.values().map(|x| x.id.clone())),
            strings(m.values().map(|x| x.kind.clone())),
            strings(m.values().map(|x| x.value.clone())),
            Arc::new(UInt8Array::from(
                m.values().map(|x| x.version).collect::<Vec<_>>(),
            )),
            Arc::new(UInt8Array::from(
                m.values().map(|x| x.prefix).collect::<Vec<_>>(),
            )),
        ],
    )
}
fn write_allocations(o: &Path, v: &[Allocation]) -> Result<()> {
    write(
        &o.join("network_allocations.parquet"),
        Schema::new(vec![
            Field::new("indicator_id", DataType::Utf8, false),
            Field::new("registry", DataType::Utf8, false),
            Field::new("status", DataType::Utf8, false),
            Field::new("registered_country", DataType::Utf8, true),
            Field::new("allocation_date", DataType::Utf8, true),
            Field::new("source_id", DataType::Utf8, false),
            Field::new("source_record_index", DataType::UInt64, false),
        ]),
        vec![
            strings(v.iter().map(|x| x.indicator.clone())),
            strings(v.iter().map(|x| x.registry.clone())),
            strings(v.iter().map(|x| x.status.clone())),
            opts(v.iter().map(|x| x.country.clone())),
            opts(v.iter().map(|x| x.date.clone())),
            strings(v.iter().map(|x| x.source.clone())),
            Arc::new(UInt64Array::from_iter_values(v.iter().map(|x| x.record))),
        ],
    )
}
fn write_routes(o: &Path, v: &[Route]) -> Result<()> {
    write(
        &o.join("route_origins.parquet"),
        Schema::new(vec![
            Field::new("prefix_indicator_id", DataType::Utf8, false),
            Field::new("origin_asn_indicator_id", DataType::Utf8, false),
            Field::new("ris_peer_count", DataType::UInt32, true),
            Field::new("source_id", DataType::Utf8, false),
            Field::new("source_record_index", DataType::UInt64, false),
        ]),
        vec![
            strings(v.iter().map(|x| x.prefix.clone())),
            strings(v.iter().map(|x| x.asn.clone())),
            Arc::new(UInt32Array::from(
                v.iter().map(|x| x.peers).collect::<Vec<_>>(),
            )),
            strings(v.iter().map(|x| x.source.clone())),
            Arc::new(UInt64Array::from_iter_values(v.iter().map(|x| x.record))),
        ],
    )
}
fn write_providers(o: &Path, v: &[Provider]) -> Result<()> {
    write(
        &o.join("provider_ranges.parquet"),
        Schema::new(vec![
            Field::new("indicator_id", DataType::Utf8, false),
            Field::new("provider", DataType::Utf8, false),
            Field::new("service", DataType::Utf8, true),
            Field::new("provider_region", DataType::Utf8, true),
            Field::new("network_border_group", DataType::Utf8, true),
            Field::new("role", DataType::Utf8, false),
            Field::new("source_id", DataType::Utf8, false),
            Field::new("source_record_index", DataType::UInt64, false),
        ]),
        vec![
            strings(v.iter().map(|x| x.indicator.clone())),
            strings(v.iter().map(|x| x.provider.clone())),
            opts(v.iter().map(|x| x.service.clone())),
            opts(v.iter().map(|x| x.region.clone())),
            opts(v.iter().map(|x| x.border.clone())),
            strings(v.iter().map(|x| x.role.clone())),
            strings(v.iter().map(|x| x.source.clone())),
            Arc::new(UInt64Array::from_iter_values(v.iter().map(|x| x.record))),
        ],
    )
}
fn write_claims(o: &Path, v: &[Claim]) -> Result<()> {
    write(
        &o.join("claims.parquet"),
        Schema::new(vec![
            Field::new("claim_id", DataType::Utf8, false),
            Field::new("indicator_id", DataType::Utf8, false),
            Field::new("source_id", DataType::Utf8, false),
            Field::new("claim_type", DataType::Utf8, false),
            Field::new("classification", DataType::Utf8, true),
            Field::new("first_seen", DataType::Utf8, true),
            Field::new("last_seen", DataType::Utf8, true),
            Field::new("confidence_band", DataType::Utf8, true),
            Field::new("source_record_index", DataType::UInt64, false),
            Field::new("attributes_json", DataType::Utf8, false),
        ]),
        vec![
            strings(v.iter().map(|x| x.id.clone())),
            strings(v.iter().map(|x| x.indicator.clone())),
            strings(v.iter().map(|x| x.source.clone())),
            strings(v.iter().map(|x| x.claim_type.clone())),
            opts(v.iter().map(|x| x.classification.clone())),
            opts(v.iter().map(|x| x.first.clone())),
            opts(v.iter().map(|x| x.last.clone())),
            opts(v.iter().map(|x| x.confidence.clone())),
            Arc::new(UInt64Array::from_iter_values(v.iter().map(|x| x.record))),
            strings(v.iter().map(|x| x.attributes.clone())),
        ],
    )
}
fn write_special(o: &Path, v: &[Special]) -> Result<()> {
    write(
        &o.join("special_purpose.parquet"),
        Schema::new(vec![
            Field::new("indicator_id", DataType::Utf8, false),
            Field::new("name", DataType::Utf8, false),
            Field::new("reference", DataType::Utf8, false),
            Field::new("allocation_date", DataType::Utf8, true),
            Field::new("termination_date", DataType::Utf8, true),
            Field::new("source_allowed", DataType::Utf8, true),
            Field::new("destination_allowed", DataType::Utf8, true),
            Field::new("forwardable", DataType::Utf8, true),
            Field::new("globally_reachable", DataType::Utf8, true),
            Field::new("reserved_by_protocol", DataType::Utf8, true),
            Field::new("source_id", DataType::Utf8, false),
            Field::new("source_record_index", DataType::UInt64, false),
        ]),
        vec![
            strings(v.iter().map(|x| x.indicator.clone())),
            strings(v.iter().map(|x| x.name.clone())),
            strings(v.iter().map(|x| x.reference.clone())),
            opts(v.iter().map(|x| x.allocation.clone())),
            opts(v.iter().map(|x| x.termination.clone())),
            opts(v.iter().map(|x| x.source_allowed.clone())),
            opts(v.iter().map(|x| x.destination.clone())),
            opts(v.iter().map(|x| x.forwardable.clone())),
            opts(v.iter().map(|x| x.globally_reachable.clone())),
            opts(v.iter().map(|x| x.reserved_protocol.clone())),
            strings(v.iter().map(|x| x.source.clone())),
            Arc::new(UInt64Array::from_iter_values(v.iter().map(|x| x.record))),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_host_bits_out_of_prefixes() {
        assert_eq!(
            canonical_prefix("192.0.2.129/24").unwrap().0,
            "192.0.2.0/24"
        );
        assert_eq!(
            canonical_prefix("2001:db8::1234/48").unwrap().0,
            "2001:db8::/48"
        );
    }

    #[test]
    fn converts_arbitrary_ipv4_ranges_to_minimal_cidrs() {
        assert_eq!(ipv4_cidrs("192.0.2.0", 256).unwrap(), ["192.0.2.0/24"]);
        assert_eq!(
            ipv4_cidrs("192.0.2.1", 3).unwrap(),
            ["192.0.2.1/32", "192.0.2.2/31"]
        );
    }

    #[test]
    fn splits_multi_origin_values() {
        assert_eq!(origins("{64500,64501}"), ["64500", "64501"]);
        assert_eq!(origins("64500"), ["64500"]);
    }
}
