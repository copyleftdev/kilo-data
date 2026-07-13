mod catalog;
mod compile;
mod normalize;
mod profile;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "kilo-data", about = "Inspect and compile KiloCheck bulk data")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Profile every artifact in the source catalog without changing it.
    Inspect {
        #[arg(long, default_value = "reference-data/sources.toml")]
        catalog: PathBuf,
        #[arg(long, default_value = "reference-data/profiles.json")]
        output: PathBuf,
    },
    /// Validate that catalog artifacts exist and match their recorded digests.
    Validate {
        #[arg(long, default_value = "reference-data/sources.toml")]
        catalog: PathBuf,
    },
    /// Convert every artifact into a source-native parsed-record Parquet table.
    CompileSourceRecords {
        #[arg(long, default_value = "reference-data/sources.toml")]
        catalog: PathBuf,
        #[arg(long, default_value = "dataset/source_records.parquet")]
        output: PathBuf,
    },
    /// Compile semantically normalized canonical Parquet tables.
    CompileCanonical {
        #[arg(long, default_value = "reference-data/sources.toml")]
        catalog: PathBuf,
        #[arg(long, default_value = "dataset/canonical")]
        output: PathBuf,
    },
    /// Validate canonical table keys and cross-table indicator references.
    ValidateCanonical {
        #[arg(long, default_value = "dataset/canonical")]
        dataset: PathBuf,
    },
    /// Refresh catalog hashes for artifacts currently present on disk.
    RefreshCatalog {
        #[arg(long, default_value = "reference-data/sources.toml")]
        catalog: PathBuf,
    },
    /// Compile the small rapidly changing Feodo and Tor overlay.
    CompileEdge {
        #[arg(long, default_value = "reference-data/sources.toml")]
        catalog: PathBuf,
        #[arg(long, default_value = "dataset/edge")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { catalog, output } => profile::inspect(&catalog, &output),
        Command::Validate { catalog } => catalog::validate(&catalog),
        Command::CompileSourceRecords { catalog, output } => {
            compile::source_records(&catalog, &output)
        }
        Command::CompileCanonical { catalog, output } => normalize::compile(&catalog, &output),
        Command::ValidateCanonical { dataset } => normalize::validate(&dataset),
        Command::RefreshCatalog { catalog } => catalog::refresh(&catalog),
        Command::CompileEdge { catalog, output } => normalize::compile_edge(&catalog, &output),
    }
}
