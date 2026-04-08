//! reghidra-typegen — maintainer-only type archive generator.
//!
//! Walks the source tree of a Rust binding crate (currently `libc`; PR 3b
//! adds `windows-sys`) and emits a postcard-serialized [`TypeArchive`]
//! under `types/` for the Reghidra decompiler to consume at runtime.
//!
//! This crate is intentionally isolated from the main Reghidra workspace
//! (see its `Cargo.toml`). It runs only when a maintainer explicitly
//! invokes it and never participates in `cargo build` at the repo root.

mod model;
mod walker;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use crate::model::TypeArchive;

/// Generate a Reghidra type archive from a Rust binding crate.
#[derive(Debug, Parser)]
#[command(name = "reghidra-typegen", version)]
struct Args {
    /// Source crate to walk. Each crate has a bespoke walker because
    /// their source conventions differ: `libc` uses plain `extern "C"`
    /// blocks; `windows-sys` uses a `windows_link::link!()` macro
    /// (PR 3b).
    #[arg(long, value_enum)]
    source: SourceCrate,

    /// Target platform whose type definitions should be preferred when
    /// the source crate exposes cfg-gated alternatives (e.g. `libc`
    /// defines `time_t` differently on Linux vs macOS). Matches the
    /// `#[cfg(target_os = ...)]` predicate.
    #[arg(long, value_enum, default_value_t = Target::Linux)]
    target: Target,

    /// Output path for the generated `.rtarch` file. By convention this
    /// lives under `types/` at the repo root — the runtime loader reads
    /// that directory via `include_dir!`. Path is resolved relative to
    /// the caller's cwd, not the tool's manifest dir.
    #[arg(long)]
    out: PathBuf,

    /// Human-readable archive name recorded in the postcard blob (for
    /// status output and log lines, not used for lookup keys). Defaults
    /// to the output file's stem.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceCrate {
    /// The `libc` crate. Plain `extern "C"` blocks under
    /// `src/unix/linux_like/linux/`, `src/unix/bsd/apple/`, etc.
    Libc,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Target {
    /// Linux, gnu libc. Default — broadest coverage for fixture binaries.
    Linux,
    /// macOS / Apple Darwin.
    Macos,
}

impl Target {
    /// String matching the Rust `target_os` cfg value for this target.
    /// Used when filtering `#[cfg(target_os = "...")]` attributes during
    /// the walk.
    fn cfg_value(self) -> &'static str {
        match self {
            Target::Linux => "linux",
            Target::Macos => "macos",
        }
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let args = Args::parse();
    let name = args
        .name
        .clone()
        .or_else(|| {
            args.out
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| anyhow!("could not derive archive name from --out {:?}", args.out))?;

    log::info!("generating archive '{name}' from {:?}", args.source);

    let archive = match args.source {
        SourceCrate::Libc => {
            let src_dir = walker::libc::find_source_dir()
                .context("locating libc source via cargo metadata")?;
            log::info!("walking libc source at {}", src_dir.display());
            walker::libc::walk(&src_dir, args.target, &name)
                .context("walking libc source tree")?
        }
    };

    log::info!(
        "archive produced: {} functions, {} types",
        archive.functions.len(),
        archive.types.len()
    );

    write_archive(&archive, &args.out).context("writing archive")?;
    log::info!("wrote {}", args.out.display());

    Ok(())
}

/// Serialize a [`TypeArchive`] to postcard and write it to `out`. The
/// on-disk shape must match exactly what `reghidra-decompile::type_archive`
/// expects — both sides use postcard v1 with the same `alloc` feature set
/// and the same field definitions.
fn write_archive(archive: &TypeArchive, out: &std::path::Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory {}", parent.display()))?;
    }
    let bytes = postcard::to_allocvec(archive)
        .map_err(|e| anyhow!("postcard serialize failed: {e}"))?;
    std::fs::write(out, &bytes)
        .with_context(|| format!("writing {}", out.display()))?;
    Ok(())
}
