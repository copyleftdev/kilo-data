use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::Path,
};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde::Serialize;
use serde_json::Value;

use crate::catalog::{self, Source};

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    catalog_schema: String,
    collected_at: String,
    profiled_at: String,
    artifacts: Vec<ArtifactProfile>,
}

#[derive(Debug, Serialize)]
struct ArtifactProfile {
    source_id: String,
    publisher: String,
    path: String,
    url: String,
    format: String,
    role: String,
    status: String,
    refresh: String,
    size_bytes: u64,
    sha256: String,
    records: u64,
    comments: u64,
    blank_lines: u64,
    fields: Vec<String>,
    observed_json_types: BTreeMap<String, Vec<String>>,
    sample: Option<Value>,
    warnings: Vec<String>,
}

pub fn inspect(catalog_path: &Path, output: &Path) -> Result<()> {
    let source_catalog = catalog::load(catalog_path)?;
    let mut artifacts = Vec::with_capacity(source_catalog.sources.len());
    for source in &source_catalog.sources {
        let artifact_path = catalog::resolve(catalog_path, source);
        let profile = profile_one(source, &artifact_path)
            .with_context(|| format!("profile {}", source.id))?;
        println!(
            "profiled\t{}\t{} records\t{} bytes",
            profile.source_id, profile.records, profile.size_bytes
        );
        artifacts.push(profile);
    }
    let report = Report {
        schema: "kilo.profiles.v1",
        catalog_schema: source_catalog.schema,
        collected_at: source_catalog.collected_at,
        profiled_at: now_utc(),
        artifacts,
    };
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    fs::write(output, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write {}", output.display()))?;
    Ok(())
}

fn profile_one(source: &Source, path: &Path) -> Result<ArtifactProfile> {
    let metadata = fs::metadata(path)?;
    let mut base = ArtifactProfile {
        source_id: source.id.clone(),
        publisher: source.publisher.clone(),
        path: source.path.display().to_string(),
        url: source.url.clone(),
        format: source.format.clone(),
        role: source.role.clone(),
        status: source.status.clone(),
        refresh: source.refresh.clone(),
        size_bytes: metadata.len(),
        sha256: catalog::digest(path)?,
        records: 0,
        comments: 0,
        blank_lines: 0,
        fields: Vec::new(),
        observed_json_types: BTreeMap::new(),
        sample: None,
        warnings: Vec::new(),
    };
    match source.format.as_str() {
        "csv" => profile_csv(path, &mut base)?,
        "json" => profile_json(path, &mut base)?,
        "ndjson" => profile_ndjson(path, &mut base)?,
        "nro" => profile_nro(path, &mut base)?,
        "ris-gzip" => profile_ris(path, &mut base)?,
        "text" => profile_text(path, &mut base)?,
        "tar-gzip" => profile_tar(path, &mut base)?,
        other => bail!("unsupported profile format {other}"),
    }
    Ok(base)
}

fn profile_csv(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    let mut reader = csv::Reader::from_path(path)?;
    profile.fields = reader.headers()?.iter().map(str::to_owned).collect();
    for (index, row) in reader.records().enumerate() {
        let row = row?;
        if index == 0 {
            profile.sample = Some(Value::Object(
                profile
                    .fields
                    .iter()
                    .cloned()
                    .zip(row.iter().map(|v| Value::String(v.to_owned())))
                    .collect(),
            ));
        }
        profile.records += 1;
    }
    Ok(())
}

fn profile_json(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    let value: Value = serde_json::from_reader(File::open(path)?)?;
    match &value {
        Value::Array(rows) => {
            profile.records = rows.len() as u64;
            profile.sample = rows.first().cloned();
            for row in rows {
                observe_json(row, profile);
            }
        }
        Value::Object(map) => {
            let arrays: Vec<&Vec<Value>> = map.values().filter_map(Value::as_array).collect();
            if arrays.is_empty() {
                profile.records = 1;
                profile.sample = Some(value.clone());
                observe_json(&value, profile);
            } else {
                for rows in arrays {
                    profile.records += rows.len() as u64;
                    if profile.sample.is_none() {
                        profile.sample = rows.first().cloned();
                    }
                    for row in rows {
                        observe_json(row, profile);
                    }
                }
            }
        }
        _ => {
            profile.records = 1;
            profile.sample = Some(value);
        }
    }
    Ok(())
}

fn profile_ndjson(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            profile.blank_lines += 1;
            continue;
        }
        if trimmed.starts_with('#') {
            profile.comments += 1;
            continue;
        }
        let value: Value = serde_json::from_str(trimmed)?;
        if profile.sample.is_none() {
            profile.sample = Some(value.clone());
        }
        observe_json(&value, profile);
        profile.records += 1;
    }
    Ok(())
}

fn profile_nro(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    profile.fields = [
        "registry",
        "country",
        "type",
        "start",
        "value",
        "date",
        "status",
        "extensions",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            profile.blank_lines += 1;
            continue;
        }
        if trimmed.starts_with('#') {
            profile.comments += 1;
            continue;
        }
        let parts: Vec<_> = trimmed.split('|').collect();
        if parts.first().is_some_and(|v| v.contains('.')) || parts.get(1) == Some(&"*") {
            profile.comments += 1;
            continue;
        }
        if profile.sample.is_none() {
            profile.sample = Some(Value::Array(
                parts
                    .iter()
                    .map(|v| Value::String((*v).to_owned()))
                    .collect(),
            ));
        }
        if !(7..=8).contains(&parts.len()) {
            profile
                .warnings
                .push(format!("record with {} pipe fields", parts.len()));
        }
        profile.records += 1;
    }
    profile.warnings.sort();
    profile.warnings.dedup();
    Ok(())
}

fn profile_ris(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    profile.fields = ["origin_as", "prefix", "ris_peer_count"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let decoder = GzDecoder::new(File::open(path)?);
    for line in BufReader::new(decoder).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            profile.blank_lines += 1;
            continue;
        }
        if trimmed.starts_with('%') {
            profile.comments += 1;
            continue;
        }
        let parts: Vec<_> = trimmed.split('\t').collect();
        if profile.sample.is_none() {
            profile.sample = Some(Value::Array(
                parts
                    .iter()
                    .map(|v| Value::String((*v).to_owned()))
                    .collect(),
            ));
        }
        if parts.len() != 3 {
            profile
                .warnings
                .push(format!("record with {} tab fields", parts.len()));
        }
        profile.records += 1;
    }
    profile.warnings.sort();
    profile.warnings.dedup();
    Ok(())
}

fn profile_text(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            profile.blank_lines += 1;
            continue;
        }
        if trimmed.starts_with('#') {
            profile.comments += 1;
            continue;
        }
        if profile.sample.is_none() {
            profile.sample = Some(Value::String(trimmed.to_owned()));
        }
        profile.records += 1;
    }
    Ok(())
}

fn profile_tar(path: &Path, profile: &mut ArtifactProfile) -> Result<()> {
    let decoder = GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut sample = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_file() {
            profile.records += 1;
            if sample.is_none() && entry.path()?.extension().is_some_and(|v| v == "json") {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                sample = serde_json::from_slice(&bytes).ok();
            }
        }
    }
    profile.sample = sample;
    profile.fields = vec!["archive_path".to_owned(), "entry_size".to_owned()];
    Ok(())
}

fn observe_json(value: &Value, profile: &mut ArtifactProfile) {
    let Value::Object(map) = value else {
        return;
    };
    let mut fields: BTreeSet<String> = profile.fields.iter().cloned().collect();
    for (key, value) in map {
        fields.insert(key.clone());
        let type_name = match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        let types = profile.observed_json_types.entry(key.clone()).or_default();
        if !types.iter().any(|existing| existing == type_name) {
            types.push(type_name.to_owned());
        }
    }
    profile.fields = fields.into_iter().collect();
}

fn now_utc() -> String {
    // Avoid adding a time dependency solely for the report receipt.
    std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}
