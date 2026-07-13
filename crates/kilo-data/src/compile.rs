use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use arrow::{
    array::{ArrayRef, StringArray, UInt64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use flate2::read::GzDecoder;
use parquet::{
    arrow::ArrowWriter,
    basic::{Compression, ZstdLevel},
    file::properties::WriterProperties,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::catalog::{self, Source};

const BATCH_ROWS: usize = 65_536;

struct Rows {
    sources: Vec<String>,
    indexes: Vec<u64>,
    collections: Vec<Option<String>>,
    records: Vec<String>,
    hashes: Vec<String>,
}

impl Rows {
    fn new() -> Self {
        Self {
            sources: Vec::with_capacity(BATCH_ROWS),
            indexes: Vec::with_capacity(BATCH_ROWS),
            collections: Vec::with_capacity(BATCH_ROWS),
            records: Vec::with_capacity(BATCH_ROWS),
            hashes: Vec::with_capacity(BATCH_ROWS),
        }
    }
    fn push(&mut self, source: &Source, index: u64, collection: Option<&str>, record: String) {
        self.sources.push(source.id.clone());
        self.indexes.push(index);
        self.collections.push(collection.map(str::to_owned));
        self.hashes
            .push(hex::encode(Sha256::digest(record.as_bytes())));
        self.records.push(record);
    }
    fn batch(&mut self, schema: Arc<Schema>) -> Result<RecordBatch> {
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from(std::mem::take(&mut self.sources))),
            Arc::new(UInt64Array::from(std::mem::take(&mut self.indexes))),
            Arc::new(StringArray::from(std::mem::take(&mut self.collections))),
            Arc::new(StringArray::from(std::mem::take(&mut self.records))),
            Arc::new(StringArray::from(std::mem::take(&mut self.hashes))),
        ];
        let batch = RecordBatch::try_new(schema, arrays)?;
        *self = Self::new();
        Ok(batch)
    }
}

pub fn source_records(catalog_path: &Path, output: &Path) -> Result<()> {
    let catalog_data = catalog::load(catalog_path)?;
    let schema = Arc::new(Schema::new(vec![
        Field::new("source_id", DataType::Utf8, false),
        Field::new("record_index", DataType::UInt64, false),
        Field::new("collection", DataType::Utf8, true),
        Field::new("raw_record", DataType::Utf8, false),
        Field::new("raw_record_hash", DataType::Utf8, false),
    ]));
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .set_created_by("kilo-data source-native compiler v0.1.0".into())
        .build();
    let mut writer = ArrowWriter::try_new(File::create(output)?, schema.clone(), Some(props))?;
    let mut rows = Rows::new();
    let mut total = 0_u64;
    for source in &catalog_data.sources {
        let before = total;
        let path = catalog::resolve(catalog_path, source);
        extract(source, &path, &mut |index, collection, record| {
            rows.push(source, index, collection, record);
            total += 1;
            if rows.sources.len() >= BATCH_ROWS {
                writer.write(&rows.batch(schema.clone())?)?;
            }
            Ok(())
        })?;
        println!("compiled\t{}\t{} records", source.id, total - before);
    }
    if !rows.sources.is_empty() {
        writer.write(&rows.batch(schema)?)?;
    }
    let metadata = writer.close()?;
    println!(
        "wrote\t{}\t{} records\t{} row groups",
        output.display(),
        total,
        metadata.num_row_groups()
    );
    Ok(())
}

type Emit<'a> = dyn FnMut(u64, Option<&str>, String) -> Result<()> + 'a;

fn extract(source: &Source, path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    match source.format.as_str() {
        "csv" => csv_rows(path, emit),
        "json" => json_rows(path, emit),
        "ndjson" => ndjson_rows(path, emit),
        "nro" => nro_rows(path, emit),
        "ris-gzip" => ris_rows(path, emit),
        "text" => text_rows(path, emit),
        "tar-gzip" => tar_rows(path, emit),
        other => bail!("unsupported source format {other}"),
    }
    .with_context(|| format!("extract {} from {}", source.id, path.display()))
}

fn csv_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    let mut reader = csv::Reader::from_path(path)?;
    let headers = reader.headers()?.clone();
    for (index, row) in reader.records().enumerate() {
        let row = row?;
        let object: Map<String, Value> = headers
            .iter()
            .zip(row.iter())
            .map(|(k, v)| (k.into(), Value::String(v.into())))
            .collect();
        emit(index as u64, None, serde_json::to_string(&object)?)?;
    }
    Ok(())
}

fn json_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    let value: Value = serde_json::from_reader(File::open(path)?)?;
    let mut index = 0;
    match value {
        Value::Array(records) => {
            for record in records {
                emit(index, None, serde_json::to_string(&record)?)?;
                index += 1;
            }
        }
        Value::Object(mut object) => {
            let arrays: Vec<_> = object
                .iter()
                .filter_map(|(k, v)| v.is_array().then_some(k.clone()))
                .collect();
            let metadata: Map<_, _> = object
                .iter()
                .filter(|(_, v)| !v.is_array())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if !metadata.is_empty() {
                emit(index, Some("_metadata"), serde_json::to_string(&metadata)?)?;
                index += 1;
            }
            for key in arrays {
                if let Some(Value::Array(records)) = object.remove(&key) {
                    for record in records {
                        emit(index, Some(&key), serde_json::to_string(&record)?)?;
                        index += 1;
                    }
                }
            }
            if index == 0 {
                emit(0, None, serde_json::to_string(&object)?)?;
            }
        }
        scalar => emit(0, None, serde_json::to_string(&scalar)?)?,
    }
    Ok(())
}

fn ndjson_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    line_rows(BufReader::new(File::open(path)?), true, emit)
}
fn text_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    line_rows(BufReader::new(File::open(path)?), false, emit)
}

fn line_rows<R: BufRead>(reader: R, json_input: bool, emit: &mut Emit<'_>) -> Result<()> {
    let mut index = 0;
    for line in reader.lines() {
        let line = line?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let record = if json_input {
            serde_json::to_string(&serde_json::from_str::<Value>(value)?)?
        } else {
            serde_json::to_string(value)?
        };
        emit(index, None, record)?;
        index += 1;
    }
    Ok(())
}

fn nro_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    let names = [
        "registry",
        "country",
        "type",
        "start",
        "value",
        "date",
        "status",
        "extensions",
    ];
    let mut index = 0;
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = value.split('|').collect();
        if parts.first().is_some_and(|v| v.contains('.')) || parts.get(1) == Some(&"*") {
            continue;
        }
        let object: Map<String, Value> = names
            .iter()
            .zip(parts)
            .map(|(k, v)| ((*k).into(), Value::String(v.into())))
            .collect();
        emit(index, None, serde_json::to_string(&object)?)?;
        index += 1;
    }
    Ok(())
}

fn ris_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    let reader = BufReader::new(GzDecoder::new(File::open(path)?));
    let mut index = 0;
    for line in reader.lines() {
        let line = line?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('%') {
            continue;
        }
        let p: Vec<_> = value.split('\t').collect();
        emit(
            index,
            None,
            serde_json::to_string(
                &json!({"origin_as":p.first(),"prefix":p.get(1),"ris_peer_count":p.get(2)}),
            )?,
        )?;
        index += 1;
    }
    Ok(())
}

fn tar_rows(path: &Path, emit: &mut Emit<'_>) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(File::open(path)?));
    let mut index = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        let record = match String::from_utf8(bytes) {
            Ok(content) => json!({"archive_path":path,"content":content}),
            Err(error) => {
                json!({"archive_path":path,"content_encoding":"hex","content":hex::encode(error.into_bytes())})
            }
        };
        emit(
            index,
            Some("archive-entry"),
            serde_json::to_string(&record)?,
        )?;
        index += 1;
    }
    Ok(())
}
