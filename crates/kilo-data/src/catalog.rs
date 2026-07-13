use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize, Serialize)]
pub struct Catalog {
    pub schema: String,
    pub collected_at: String,
    #[serde(rename = "source")]
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Source {
    pub id: String,
    pub publisher: String,
    pub path: PathBuf,
    pub url: String,
    pub format: String,
    pub role: String,
    pub status: String,
    pub sha256: String,
    pub refresh: String,
}

pub fn load(path: &Path) -> Result<Catalog> {
    let bytes = fs::read(path).with_context(|| format!("read catalog {}", path.display()))?;
    let catalog: Catalog = toml::from_slice(&bytes).context("parse source catalog")?;
    if catalog.schema != "kilo.sources.v1" {
        bail!("unsupported source catalog schema: {}", catalog.schema);
    }
    Ok(catalog)
}

pub fn resolve(catalog_path: &Path, source: &Source) -> PathBuf {
    let root = catalog_path.parent().unwrap_or_else(|| Path::new("."));
    root.join(&source.path)
}

pub fn digest(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn validate(path: &Path) -> Result<()> {
    let catalog = load(path)?;
    let mut failures = Vec::new();
    for source in &catalog.sources {
        let artifact = resolve(path, source);
        match digest(&artifact) {
            Ok(actual) if actual == source.sha256 => {
                println!("ok\t{}\t{}", source.id, artifact.display());
            }
            Ok(actual) => failures.push(format!(
                "{}: digest mismatch (catalog {}, actual {})",
                source.id, source.sha256, actual
            )),
            Err(error) => failures.push(format!("{}: {error:#}", source.id)),
        }
    }
    if failures.is_empty() {
        println!("validated {} artifacts", catalog.sources.len());
        return Ok(());
    }
    bail!("validation failed:\n{}", failures.join("\n"))
}

pub fn refresh(path: &Path) -> Result<()> {
    let mut catalog = load(path)?;
    let mut updated = 0;
    for source in &mut catalog.sources {
        let artifact = resolve(path, source);
        if artifact.is_file() {
            source.sha256 = digest(&artifact)?;
            updated += 1;
        }
    }
    catalog.collected_at = now_utc();
    fs::write(path, toml::to_string_pretty(&catalog)?)?;
    println!("refreshed {updated} artifact digests in {}", path.display());
    Ok(())
}

fn now_utc() -> String {
    std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|| "unknown".into())
}
