//! `reghidra-cli` — headless command-line driver for the reghidra
//! analysis pipeline. Designed for AI agents, scripting, and CI use:
//! every subcommand prints either a human-readable table OR a stable
//! JSON document (selected via `--json` on individual commands or
//! `--json` at the top level), and any state mutation can be persisted
//! to a session file for replay across invocations.
//!
//! # Subcommand inventory
//!
//! Each subcommand is documented inline with its `clap` definition
//! below. Run `reghidra-cli --help` or `reghidra-cli <cmd> --help` for
//! the canonical surface area; `crates/reghidra-cli/README.md` carries
//! the long-form usage walkthrough.
//!
//! # Design notes
//!
//! * Every subcommand that touches a binary takes `--binary <PATH>`
//!   OR `--session <FILE>`. With `--session`, the binary path lives
//!   in the session JSON; the project is opened via
//!   [`Project::open_with_session`] which restores annotations *and*
//!   replays data-source overrides + lazy-loaded entries.
//! * Mutating subcommands (`annotate ...`, `sources enable/disable`,
//!   `sources load-archive`, `sources load-sig`, `rename`, etc.)
//!   require `--session <FILE>` so the change can be persisted.
//!   Without `--session` they error out instead of silently dropping
//!   the mutation, because the only thing more confusing than no CLI
//!   parity is a CLI that pretends a write happened.
//! * `--json` output is the contract for machine consumers. The shape
//!   of each command's JSON is documented in the README. Adding a
//!   field is non-breaking; renaming/removing fields requires a
//!   version bump on the top-level CLI.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use reghidra_core::analysis::flirt::FlirtDatabase;
use reghidra_core::Project;
use reghidra_decompile::type_archive::which_archive_resolves;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "reghidra-cli",
    version,
    about = "Headless reverse engineering CLI for the reghidra analysis pipeline.",
    long_about = "Headless reverse engineering CLI for the reghidra analysis pipeline.\n\
\n\
Every subcommand loads a binary (via --binary or --session), runs analysis, \
performs the requested action, and exits. Pass --json on commands that support \
it for stable machine-readable output. Mutations require --session so the change \
can be persisted across invocations.\n\
\n\
See crates/reghidra-cli/README.md for the full usage walkthrough."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print binary metadata: format, arch, entry point, section/symbol/function counts.
    Info(BinaryArgs),
    /// List detected functions. Filter by source / name regex / address range.
    Functions(FunctionsArgs),
    /// List sections.
    Sections(BinaryArgs),
    /// List detected strings.
    Strings(StringsArgs),
    /// List cross-references to or from an address.
    Xrefs(XrefsArgs),
    /// Decompile a function (by entry address) to C-like pseudocode.
    Decompile(AddressArgs),
    /// Disassemble starting from an address.
    Disasm(DisasmArgs),
    /// Print the IR for a function.
    Ir(AddressArgs),
    /// Print the control-flow graph (blocks + edges) for a function.
    Cfg(AddressArgs),
    /// Look up a function by name (substring match) and print its address.
    Find(FindArgs),
    /// Loaded data sources: FLIRT signature databases and type archives.
    #[command(subcommand)]
    Sources(SourcesCommand),
    /// Annotations: rename functions/labels/variables, set comments, retype slots.
    #[command(subcommand)]
    Annotate(AnnotateCommand),
    /// Session management: create, dump, or rewrite a session file.
    #[command(subcommand)]
    Session(SessionCommand),
}

// ---------------------------------------------------------------------------
// Common arg groups
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
struct BinaryArgs {
    /// Path to a binary to analyze. Mutually exclusive with --session.
    #[arg(long, short = 'b', value_name = "PATH", conflicts_with = "session")]
    binary: Option<PathBuf>,
    /// Path to a reghidra session file (carries the binary path inside).
    #[arg(long, short = 's', value_name = "FILE")]
    session: Option<PathBuf>,
    /// Emit machine-readable JSON instead of a human table.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct AddressArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Function entry address (hex with 0x prefix or decimal).
    #[arg(value_name = "ADDR", value_parser = parse_address)]
    address: u64,
}

#[derive(clap::Args)]
struct FunctionsArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Filter by detection source (Symbol, Signature, EntryPoint, ...).
    #[arg(long)]
    source: Option<String>,
    /// Maximum number of rows to print. Use 0 for unlimited.
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Substring filter against function names (case-insensitive).
    #[arg(long, short = 'n')]
    name: Option<String>,
}

#[derive(clap::Args)]
struct StringsArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Maximum rows to print (0 = unlimited).
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Substring filter against the string value (case-insensitive).
    #[arg(long, short = 'p')]
    pattern: Option<String>,
}

#[derive(clap::Args)]
struct XrefsArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// References TO this address (e.g. callers).
    #[arg(long, value_parser = parse_address, conflicts_with = "from")]
    to: Option<u64>,
    /// References FROM this address (e.g. callees of an instruction).
    #[arg(long, value_parser = parse_address)]
    from: Option<u64>,
}

#[derive(clap::Args)]
struct DisasmArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Start address. Defaults to the entry point if omitted.
    #[arg(value_name = "ADDR", value_parser = parse_address)]
    address: Option<u64>,
    /// Number of instructions to print.
    #[arg(long, default_value_t = 30)]
    count: usize,
}

#[derive(clap::Args)]
struct FindArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Substring to match against function names (case-insensitive).
    #[arg(value_name = "NAME")]
    name: String,
    /// Maximum number of matches to print.
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

// ---------------------------------------------------------------------------
// `sources` subcommand: data source visibility + control
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
enum SourcesCommand {
    /// Print every loaded FLIRT db and type archive with hit counts.
    List(BinaryArgs),
    /// Print only FLIRT databases (bundled + user). Use --available to also
    /// list embedded sigs that are NOT currently loaded.
    Flirt(SourcesFlirtArgs),
    /// Print only type archives. Use --available to also list embedded
    /// stems that are NOT currently loaded.
    Archives(SourcesArchivesArgs),
    /// Look up which loaded type archive owns a function prototype.
    /// Mirrors the precedence chain used by the decompiler.
    Resolve(SourcesResolveArgs),
    /// Enable a data source. Requires --session for persistence.
    Enable(SourcesToggleArgs),
    /// Disable a data source. Requires --session for persistence.
    Disable(SourcesToggleArgs),
    /// Lazy-load an embedded type archive by stem. Requires --session.
    LoadArchive(SourcesLoadArchiveArgs),
    /// Lazy-load an embedded bundled FLIRT sig by (subdir, stem).
    /// Requires --session.
    LoadSig(SourcesLoadSigArgs),
    /// Load a user-supplied .sig file. Requires --session.
    LoadUserSig(SourcesLoadUserSigArgs),
}

#[derive(clap::Args)]
struct SourcesFlirtArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Include embedded sigs that are not currently loaded.
    #[arg(long)]
    available: bool,
}

#[derive(clap::Args)]
struct SourcesArchivesArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Include embedded archive stems that are not currently loaded.
    #[arg(long)]
    available: bool,
}

#[derive(clap::Args)]
struct SourcesResolveArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// The function name to look up (e.g. `CreateFileA`, `_fclose`).
    #[arg(value_name = "NAME")]
    name: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SourceKind {
    /// Bundled FLIRT signature database (key: `<subdir>/<stem>`).
    Bundled,
    /// User-loaded FLIRT signature database (key: header library name).
    User,
    /// Type archive (key: archive stem, e.g. `windows-x64`).
    Archive,
}

#[derive(clap::Args)]
struct SourcesToggleArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Which kind of source.
    #[arg(long)]
    kind: SourceKind,
    /// Identifying key. For bundled FLIRT, `<subdir>/<stem>`
    /// (e.g. `pe/x86/32/vc32_14`). For user FLIRT, the library header name.
    /// For archives, the archive stem (e.g. `windows-x64`).
    #[arg(value_name = "KEY")]
    key: String,
}

#[derive(clap::Args)]
struct SourcesLoadArchiveArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Embedded archive stem (e.g. `windows-arm64`, `rizin-libc`).
    #[arg(value_name = "STEM")]
    stem: String,
}

#[derive(clap::Args)]
struct SourcesLoadSigArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Subdirectory under `signatures/` (e.g. `pe/x86/32`).
    #[arg(long)]
    subdir: String,
    /// File stem of the .sig (e.g. `vc32_14`).
    #[arg(long)]
    stem: String,
}

#[derive(clap::Args)]
struct SourcesLoadUserSigArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Path to a `.sig` file on disk.
    #[arg(value_name = "PATH")]
    path: PathBuf,
}

// ---------------------------------------------------------------------------
// `annotate` subcommand: persisted user edits
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
enum AnnotateCommand {
    /// Set or clear a user comment at an address. Requires --session.
    Comment(AnnotateCommentArgs),
    /// Rename a function. Empty NAME clears the override. Requires --session.
    Rename(AnnotateRenameArgs),
    /// Rename a label (CFG block address). Requires --session.
    RenameLabel(AnnotateRenameArgs),
    /// Rename a local variable inside a function. Requires --session.
    RenameVar(AnnotateVarArgs),
    /// Set the type of a local variable. Requires --session.
    Retype(AnnotateRetypeArgs),
    /// Add a bookmark at an address. Requires --session.
    Bookmark(AnnotateBookmarkArgs),
    /// Remove a bookmark. Requires --session.
    Unbookmark(AnnotateBookmarkArgs),
    /// Print all current annotations as JSON or a table.
    List(BinaryArgs),
}

#[derive(clap::Args)]
struct AnnotateCommentArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Address (hex or decimal).
    #[arg(value_parser = parse_address)]
    address: u64,
    /// Comment text. Empty string clears.
    #[arg(value_name = "TEXT")]
    text: String,
}

#[derive(clap::Args)]
struct AnnotateRenameArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    #[arg(value_parser = parse_address)]
    address: u64,
    #[arg(value_name = "NAME")]
    name: String,
}

#[derive(clap::Args)]
struct AnnotateVarArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    /// Function entry address.
    #[arg(value_parser = parse_address)]
    func_address: u64,
    /// Currently displayed variable name (e.g. `arg_8`, `local_4`, `eax`).
    #[arg(value_name = "DISPLAYED_NAME")]
    displayed_name: String,
    /// New name. Empty string clears the override.
    #[arg(value_name = "NEW_NAME")]
    new_name: String,
}

#[derive(clap::Args)]
struct AnnotateRetypeArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    #[arg(value_parser = parse_address)]
    func_address: u64,
    #[arg(value_name = "DISPLAYED_NAME")]
    displayed_name: String,
    /// Free-form C type (e.g. `HANDLE`, `uint32_t*`, `char[16]`).
    /// Empty string clears.
    #[arg(value_name = "TYPE")]
    type_str: String,
}

#[derive(clap::Args)]
struct AnnotateBookmarkArgs {
    #[command(flatten)]
    bin: BinaryArgs,
    #[arg(value_parser = parse_address)]
    address: u64,
}

// ---------------------------------------------------------------------------
// `session` subcommand
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
enum SessionCommand {
    /// Create an empty session file pinned to a binary path.
    Init {
        /// Path to the binary the session will track.
        #[arg(long, short = 'b')]
        binary: PathBuf,
        /// Output session file path.
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
    /// Print the contents of a session file as JSON.
    Show {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Open a binary, apply a session, recompute everything, and re-save.
    /// Useful for upgrading session files when the analysis pipeline changes.
    Refresh {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Address parsing
// ---------------------------------------------------------------------------

fn parse_address(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).map_err(|e| format!("invalid hex address '{s}': {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid address '{s}': {e}"))
    }
}

// ---------------------------------------------------------------------------
// Project loading
// ---------------------------------------------------------------------------

/// Open a project from either `--binary` or `--session`. Exactly one
/// must be provided. With `--session`, this also replays the session's
/// data-source overrides via [`Project::open_with_session`].
fn open_project(args: &BinaryArgs) -> Result<Project> {
    match (&args.binary, &args.session) {
        (Some(path), None) => Project::open(path)
            .with_context(|| format!("failed to open binary '{}'", path.display())),
        (None, Some(session)) => Project::open_with_session(session)
            .with_context(|| format!("failed to load session '{}'", session.display())),
        (Some(_), Some(_)) => bail!("--binary and --session are mutually exclusive"),
        (None, None) => bail!("one of --binary or --session is required"),
    }
}

/// Open a project for a mutating command. The session file is required —
/// without one, the mutation would be discarded on exit and the user
/// would have no way to know.
fn open_project_for_mutation(args: &BinaryArgs) -> Result<(Project, PathBuf)> {
    let session_path = args
        .session
        .clone()
        .ok_or_else(|| anyhow!("mutating commands require --session <FILE> for persistence"))?;
    let project = open_project(args)?;
    Ok((project, session_path))
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn emit<T: Serialize>(json: bool, value: &T, table: impl FnOnce()) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        table();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON output structs (stable contract for machine consumers)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct InfoJson {
    path: String,
    format: String,
    architecture: String,
    is_64bit: bool,
    entry_point: u64,
    sections: usize,
    symbols: usize,
    instructions: usize,
    functions: usize,
    xrefs: usize,
    cfgs: usize,
    strings: usize,
    bundled_dbs_loaded: usize,
    user_dbs_loaded: usize,
    type_archives_loaded: usize,
    sig_status: Option<String>,
    /// PE only: pefile-compatible import hash (32-char lowercase hex MD5).
    imphash: Option<String>,
    /// PE only: TLS directory contains at least one callback.
    tls_callbacks_present: bool,
    /// PE only: file has bytes past the last section (overlay).
    overlay_present: bool,
}

#[derive(Serialize)]
struct FunctionJson {
    address: u64,
    name: String,
    display_name: String,
    size: u64,
    instructions: usize,
    blocks: usize,
    xrefs_to: usize,
    source: String,
    matched_signature_db: Option<String>,
}

#[derive(Serialize)]
struct SectionJson {
    name: String,
    virtual_address: u64,
    virtual_size: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

#[derive(Serialize)]
struct StringJson {
    address: u64,
    auto_name: String,
    value: String,
    xrefs_to: usize,
}

#[derive(Serialize)]
struct XrefJson {
    from: u64,
    to: u64,
    kind: String,
    from_function: Option<String>,
    to_function: Option<String>,
}

#[derive(Serialize)]
struct FlirtDbJson {
    kind: &'static str, // "bundled" | "user"
    /// Stable identifier for `sources enable/disable`. For bundled this
    /// is `<subdir>/<stem>`; for user this is the header library name.
    key: String,
    /// Friendly library name from the .sig header.
    library_name: String,
    signature_count: usize,
    enabled: bool,
    hits: usize,
    /// Embedded subdir (`pe/x86/32`); only set for bundled.
    subdir: Option<String>,
    /// File stem (`vc32_14`); only set for bundled.
    stem: Option<String>,
}

#[derive(Serialize)]
struct AvailableFlirtJson {
    subdir: String,
    stem: String,
    library_name: Option<String>,
    n_functions: Option<u32>,
    loaded: bool,
}

#[derive(Serialize)]
struct ArchiveJson {
    /// Same value as `key` for `sources enable/disable --kind archive`.
    name: String,
    function_count: usize,
    enabled: bool,
    hits: usize,
}

#[derive(Serialize)]
struct AvailableArchiveJson {
    stem: String,
    loaded: bool,
}

#[derive(Serialize)]
struct SourcesListJson {
    bundled: Vec<FlirtDbJson>,
    user: Vec<FlirtDbJson>,
    archives: Vec<ArchiveJson>,
}

#[derive(Serialize)]
struct ResolveJson {
    name: String,
    archive: Option<String>,
    archive_index: Option<usize>,
}

#[derive(Serialize)]
struct AnnotationsJson {
    comments: Vec<(u64, String)>,
    renamed_functions: Vec<(u64, String)>,
    label_names: Vec<(u64, String)>,
    variable_names: Vec<((u64, String), String)>,
    variable_types: Vec<((u64, String), String)>,
    bookmarks: Vec<u64>,
}

// ---------------------------------------------------------------------------
// main / dispatcher
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    match cli.command {
        Command::Info(args) => cmd_info(args),
        Command::Functions(args) => cmd_functions(args),
        Command::Sections(args) => cmd_sections(args),
        Command::Strings(args) => cmd_strings(args),
        Command::Xrefs(args) => cmd_xrefs(args),
        Command::Decompile(args) => cmd_decompile(args),
        Command::Disasm(args) => cmd_disasm(args),
        Command::Ir(args) => cmd_ir(args),
        Command::Cfg(args) => cmd_cfg(args),
        Command::Find(args) => cmd_find(args),
        Command::Sources(cmd) => cmd_sources(cmd),
        Command::Annotate(cmd) => cmd_annotate(cmd),
        Command::Session(cmd) => cmd_session(cmd),
    }
}

// ---------------------------------------------------------------------------
// Read-only commands
// ---------------------------------------------------------------------------

fn cmd_info(args: BinaryArgs) -> Result<()> {
    let project = open_project(&args)?;
    let info = &project.binary.info;
    let payload = InfoJson {
        path: info.path.display().to_string(),
        format: format!("{}", info.format),
        architecture: format!("{}", info.architecture),
        is_64bit: info.is_64bit,
        entry_point: info.entry_point,
        sections: project.binary.sections.len(),
        symbols: project.binary.symbols.len(),
        instructions: project.instructions.len(),
        functions: project.analysis.functions.len(),
        xrefs: project.analysis.xrefs.total_count(),
        cfgs: project.analysis.cfgs.len(),
        strings: project.binary.strings.len(),
        bundled_dbs_loaded: project.bundled_dbs.len(),
        user_dbs_loaded: project.user_dbs.len(),
        type_archives_loaded: project.type_archives.len(),
        sig_status: project.sig_status.clone(),
        imphash: info.imphash.clone(),
        tls_callbacks_present: info.tls_callbacks_present,
        overlay_present: info.overlay_present,
    };
    emit(args.json, &payload, || {
        println!("Path:                {}", payload.path);
        println!("Format:              {}", payload.format);
        println!("Architecture:        {}", payload.architecture);
        println!("64-bit:              {}", payload.is_64bit);
        println!("Entry point:         0x{:x}", payload.entry_point);
        println!("Sections:            {}", payload.sections);
        println!("Symbols:             {}", payload.symbols);
        println!("Instructions:        {}", payload.instructions);
        println!("Functions:           {}", payload.functions);
        println!("Xrefs:               {}", payload.xrefs);
        println!("CFGs:                {}", payload.cfgs);
        println!("Strings:             {}", payload.strings);
        println!("Bundled FLIRT dbs:   {}", payload.bundled_dbs_loaded);
        println!("User FLIRT dbs:      {}", payload.user_dbs_loaded);
        println!("Type archives:       {}", payload.type_archives_loaded);
        if let Some(s) = &payload.sig_status {
            println!("Signature status:    {s}");
        }
        if let Some(h) = &payload.imphash {
            println!("Imphash:             {h}");
        }
        if payload.tls_callbacks_present {
            println!("TLS callbacks:       present");
        }
        if payload.overlay_present {
            println!("Overlay:             present");
        }
    })
}

fn cmd_functions(args: FunctionsArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let needle = args.name.as_deref().map(|n| n.to_lowercase());
    let mut rows: Vec<FunctionJson> = project
        .analysis
        .functions
        .iter()
        .filter(|f| {
            if let Some(src) = &args.source {
                if !format!("{:?}", f.source).eq_ignore_ascii_case(src) {
                    return false;
                }
            }
            if let Some(n) = &needle {
                if !f.name.to_lowercase().contains(n) {
                    return false;
                }
            }
            true
        })
        .map(|f| FunctionJson {
            address: f.entry_address,
            name: f.name.clone(),
            display_name: project
                .display_function_name(f.entry_address)
                .unwrap_or_else(|| f.name.clone()),
            size: f.size,
            instructions: f.instruction_count,
            blocks: project
                .analysis
                .cfgs
                .get(&f.entry_address)
                .map(|c| c.block_count())
                .unwrap_or(0),
            xrefs_to: project.analysis.xrefs.ref_count_to(f.entry_address),
            source: format!("{:?}", f.source),
            matched_signature_db: f.matched_signature_db.clone(),
        })
        .collect();
    if args.limit > 0 && rows.len() > args.limit {
        rows.truncate(args.limit);
    }
    emit(args.bin.json, &rows, || {
        println!(
            "{:<12} {:<40} {:>6} {:>6} {:>6} {:<14} {}",
            "ADDR", "NAME", "INSNS", "BLKS", "XREFS", "SOURCE", "SIG_DB"
        );
        for r in &rows {
            println!(
                "0x{:08x} {:<40} {:>6} {:>6} {:>6} {:<14} {}",
                r.address,
                truncate(&r.display_name, 40),
                r.instructions,
                r.blocks,
                r.xrefs_to,
                r.source,
                r.matched_signature_db.as_deref().unwrap_or("-"),
            );
        }
    })
}

fn cmd_sections(args: BinaryArgs) -> Result<()> {
    let project = open_project(&args)?;
    let rows: Vec<SectionJson> = project
        .binary
        .sections
        .iter()
        .map(|s| SectionJson {
            name: s.name.clone(),
            virtual_address: s.virtual_address,
            virtual_size: s.virtual_size,
            readable: s.is_readable,
            writable: s.is_writable,
            executable: s.is_executable,
        })
        .collect();
    emit(args.json, &rows, || {
        println!("{:<24} {:<12} {:>10} PERM", "NAME", "ADDR", "SIZE");
        for s in &rows {
            println!(
                "{:<24} 0x{:08x}   0x{:08x} {}{}{}",
                s.name,
                s.virtual_address,
                s.virtual_size,
                if s.readable { 'r' } else { '-' },
                if s.writable { 'w' } else { '-' },
                if s.executable { 'x' } else { '-' },
            );
        }
    })
}

fn cmd_strings(args: StringsArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let pat = args.pattern.as_deref().map(|p| p.to_lowercase());
    let mut rows: Vec<StringJson> = project
        .binary
        .strings
        .iter()
        .filter(|s| {
            if let Some(p) = &pat {
                s.value.to_lowercase().contains(p)
            } else {
                true
            }
        })
        .map(|s| StringJson {
            address: s.address,
            auto_name: s.auto_name.clone(),
            value: s.value.clone(),
            xrefs_to: project.analysis.xrefs.ref_count_to(s.address),
        })
        .collect();
    if args.limit > 0 && rows.len() > args.limit {
        rows.truncate(args.limit);
    }
    emit(args.bin.json, &rows, || {
        for r in &rows {
            println!(
                "0x{:08x} ({:>3} xrefs) {:<24} {:?}",
                r.address, r.xrefs_to, r.auto_name, r.value
            );
        }
    })
}

fn cmd_xrefs(args: XrefsArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let xrefs: Vec<XrefJson> = match (args.to, args.from) {
        (Some(addr), None) => project
            .analysis
            .xrefs
            .xrefs_to(addr)
            .iter()
            .map(|x| xref_to_json(&project, x))
            .collect(),
        (None, Some(addr)) => project
            .analysis
            .xrefs
            .xrefs_from(addr)
            .iter()
            .map(|x| xref_to_json(&project, x))
            .collect(),
        _ => bail!("provide exactly one of --to / --from"),
    };
    emit(args.bin.json, &xrefs, || {
        for x in &xrefs {
            println!(
                "0x{:08x} -> 0x{:08x}  [{:<16}] {} -> {}",
                x.from,
                x.to,
                x.kind,
                x.from_function.as_deref().unwrap_or("-"),
                x.to_function.as_deref().unwrap_or("-"),
            );
        }
    })
}

fn xref_to_json(project: &Project, x: &reghidra_core::analysis::xrefs::XRef) -> XrefJson {
    XrefJson {
        from: x.from,
        to: x.to,
        kind: format!("{:?}", x.kind),
        from_function: project
            .analysis
            .function_containing(x.from)
            .map(|f| f.name.clone()),
        to_function: project.function_name(x.to).map(|s| s.to_string()),
    }
}

fn cmd_decompile(args: AddressArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let text = project
        .decompile(args.address)
        .ok_or_else(|| anyhow!("no decompile output for 0x{:x}", args.address))?;
    if args.bin.json {
        let payload = serde_json::json!({
            "address": args.address,
            "decompiled": text,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print!("{text}");
    }
    Ok(())
}

fn cmd_disasm(args: DisasmArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let start = args
        .address
        .unwrap_or(project.binary.info.entry_point);
    let rows: Vec<&reghidra_core::disasm::DisassembledInstruction> = project
        .instructions
        .iter()
        .skip_while(|i| i.address < start)
        .take(args.count)
        .collect();
    if args.bin.json {
        let json: Vec<_> = rows
            .iter()
            .map(|i| {
                serde_json::json!({
                    "address": i.address,
                    "bytes": i.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(""),
                    "mnemonic": i.mnemonic,
                    "operands": i.operands,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        for i in &rows {
            println!("  {}", i.display(true));
        }
    }
    Ok(())
}

fn cmd_ir(args: AddressArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let ir = project
        .analysis
        .ir_for(args.address)
        .ok_or_else(|| anyhow!("no IR for 0x{:x}", args.address))?;
    if args.bin.json {
        let payload = serde_json::json!({
            "address": args.address,
            "ir": format!("{ir}"),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print!("{ir}");
    }
    Ok(())
}

fn cmd_cfg(args: AddressArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let cfg = project
        .analysis
        .cfgs
        .get(&args.address)
        .ok_or_else(|| anyhow!("no CFG for 0x{:x}", args.address))?;
    if args.bin.json {
        let blocks: Vec<_> = cfg
            .blocks
            .iter()
            .map(|(addr, block)| {
                serde_json::json!({
                    "address": addr,
                    "instructions": block.instructions.len(),
                    "preds": cfg.preds(*addr),
                    "succs": cfg.succs(*addr),
                })
            })
            .collect();
        let edges: Vec<_> = cfg
            .edges
            .iter()
            .map(|e| {
                serde_json::json!({
                    "from": e.from,
                    "to": e.to,
                    "kind": format!("{:?}", e.kind),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "blocks": blocks,
            "edges": edges,
        }))?);
    } else {
        for (addr, block) in &cfg.blocks {
            println!(
                "  Block 0x{:08x} ({} insns)  preds={:x?}  succs={:x?}",
                addr,
                block.instructions.len(),
                cfg.preds(*addr),
                cfg.succs(*addr),
            );
        }
        println!("  {} edges", cfg.edges.len());
        for e in &cfg.edges {
            println!("    0x{:08x} -> 0x{:08x}  [{:?}]", e.from, e.to, e.kind);
        }
    }
    Ok(())
}

fn cmd_find(args: FindArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let needle = args.name.to_lowercase();
    let mut hits: Vec<FunctionJson> = project
        .analysis
        .functions
        .iter()
        .filter(|f| f.name.to_lowercase().contains(&needle))
        .map(|f| FunctionJson {
            address: f.entry_address,
            name: f.name.clone(),
            display_name: project
                .display_function_name(f.entry_address)
                .unwrap_or_else(|| f.name.clone()),
            size: f.size,
            instructions: f.instruction_count,
            blocks: project
                .analysis
                .cfgs
                .get(&f.entry_address)
                .map(|c| c.block_count())
                .unwrap_or(0),
            xrefs_to: project.analysis.xrefs.ref_count_to(f.entry_address),
            source: format!("{:?}", f.source),
            matched_signature_db: f.matched_signature_db.clone(),
        })
        .collect();
    if args.limit > 0 && hits.len() > args.limit {
        hits.truncate(args.limit);
    }
    emit(args.bin.json, &hits, || {
        for r in &hits {
            println!("0x{:08x}  {}", r.address, r.display_name);
        }
    })
}

// ---------------------------------------------------------------------------
// `sources` dispatcher
// ---------------------------------------------------------------------------

fn cmd_sources(cmd: SourcesCommand) -> Result<()> {
    match cmd {
        SourcesCommand::List(args) => sources_list(args),
        SourcesCommand::Flirt(args) => sources_flirt(args),
        SourcesCommand::Archives(args) => sources_archives(args),
        SourcesCommand::Resolve(args) => sources_resolve(args),
        SourcesCommand::Enable(args) => sources_set_enabled(args, true),
        SourcesCommand::Disable(args) => sources_set_enabled(args, false),
        SourcesCommand::LoadArchive(args) => sources_load_archive(args),
        SourcesCommand::LoadSig(args) => sources_load_sig(args),
        SourcesCommand::LoadUserSig(args) => sources_load_user_sig(args),
    }
}

fn collect_flirt_dbs(project: &Project) -> (Vec<FlirtDbJson>, Vec<FlirtDbJson>) {
    let bundled = project
        .bundled_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| {
            let key = db
                .source_path
                .to_str()
                .and_then(|s| s.strip_prefix("bundled:"))
                .unwrap_or("")
                .to_string();
            let (subdir, stem) = key
                .rsplit_once('/')
                .map(|(a, b)| (Some(a.to_string()), Some(b.to_string())))
                .unwrap_or((None, None));
            FlirtDbJson {
                kind: "bundled",
                key,
                library_name: db.header.name.clone(),
                signature_count: db.signature_count,
                enabled: project.bundled_db_enabled.get(i).copied().unwrap_or(true),
                hits: project.bundled_db_hits.get(i).copied().unwrap_or(0),
                subdir,
                stem,
            }
        })
        .collect();
    let user = project
        .user_dbs
        .iter()
        .enumerate()
        .map(|(i, db)| FlirtDbJson {
            kind: "user",
            key: db.header.name.clone(),
            library_name: db.header.name.clone(),
            signature_count: db.signature_count,
            enabled: project.user_db_enabled.get(i).copied().unwrap_or(true),
            hits: project.user_db_hits.get(i).copied().unwrap_or(0),
            subdir: None,
            stem: None,
        })
        .collect();
    (bundled, user)
}

fn collect_archives(project: &Project) -> Vec<ArchiveJson> {
    project
        .type_archives
        .iter()
        .enumerate()
        .map(|(i, a)| ArchiveJson {
            name: a.name.clone(),
            function_count: a.functions.len(),
            enabled: project.type_archive_enabled.get(i).copied().unwrap_or(true),
            hits: project.type_archive_hits.get(i).copied().unwrap_or(0),
        })
        .collect()
}

fn sources_list(args: BinaryArgs) -> Result<()> {
    let project = open_project(&args)?;
    let (bundled, user) = collect_flirt_dbs(&project);
    let archives = collect_archives(&project);
    let payload = SourcesListJson {
        bundled,
        user,
        archives,
    };
    emit(args.json, &payload, || {
        print_flirt_table("Bundled FLIRT", &payload.bundled);
        print_flirt_table("User FLIRT", &payload.user);
        println!("\nType archives");
        println!(
            "  {:<20} {:>10} {:>8} {:>8}",
            "NAME", "FUNCTIONS", "ENABLED", "HITS"
        );
        for a in &payload.archives {
            println!(
                "  {:<20} {:>10} {:>8} {:>8}",
                a.name, a.function_count, a.enabled, a.hits
            );
        }
    })
}

fn print_flirt_table(title: &str, dbs: &[FlirtDbJson]) {
    println!("{title}");
    if dbs.is_empty() {
        println!("  (none)");
        return;
    }
    println!(
        "  {:<40} {:<32} {:>10} {:>8} {:>6}",
        "KEY", "LIBRARY", "SIGS", "ENABLED", "HITS"
    );
    for db in dbs {
        println!(
            "  {:<40} {:<32} {:>10} {:>8} {:>6}",
            truncate(&db.key, 40),
            truncate(&db.library_name, 32),
            db.signature_count,
            db.enabled,
            db.hits,
        );
    }
}

fn sources_flirt(args: SourcesFlirtArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let (bundled, user) = collect_flirt_dbs(&project);
    if args.available {
        let loaded_keys: std::collections::HashSet<(String, String)> = bundled
            .iter()
            .filter_map(|db| {
                Some((db.subdir.clone()?, db.stem.clone()?))
            })
            .collect();
        let available: Vec<AvailableFlirtJson> = project
            .available_bundled_sigs
            .iter()
            .map(|s| AvailableFlirtJson {
                subdir: s.subdir.clone(),
                stem: s.stem.clone(),
                library_name: s.library_name.clone(),
                n_functions: s.n_functions,
                loaded: loaded_keys.contains(&(s.subdir.clone(), s.stem.clone())),
            })
            .collect();
        let payload = serde_json::json!({
            "bundled": bundled,
            "user": user,
            "available": available,
        });
        if args.bin.json {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            print_flirt_table("Bundled FLIRT (loaded)", &bundled);
            print_flirt_table("User FLIRT (loaded)", &user);
            println!("\nAll embedded sigs (loaded marker in last column):");
            println!(
                "  {:<14} {:<24} {:<32} {:>10} {:>8}",
                "SUBDIR", "STEM", "LIBRARY", "FUNCTIONS", "LOADED"
            );
            for s in &available {
                println!(
                    "  {:<14} {:<24} {:<32} {:>10} {:>8}",
                    s.subdir,
                    truncate(&s.stem, 24),
                    truncate(s.library_name.as_deref().unwrap_or("?"), 32),
                    s.n_functions
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    s.loaded,
                );
            }
        }
    } else {
        let payload = serde_json::json!({
            "bundled": bundled,
            "user": user,
        });
        if args.bin.json {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            print_flirt_table("Bundled FLIRT", &bundled);
            print_flirt_table("User FLIRT", &user);
        }
    }
    Ok(())
}

fn sources_archives(args: SourcesArchivesArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let archives = collect_archives(&project);
    if args.available {
        let loaded: std::collections::HashSet<&str> =
            archives.iter().map(|a| a.name.as_str()).collect();
        let available: Vec<AvailableArchiveJson> = project
            .available_archive_stems
            .iter()
            .map(|s| AvailableArchiveJson {
                stem: s.clone(),
                loaded: loaded.contains(s.as_str()),
            })
            .collect();
        let payload = serde_json::json!({
            "loaded": archives,
            "available": available,
        });
        if args.bin.json {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!(
                "{:<24} {:>10} {:>8} {:>8}",
                "NAME", "FUNCTIONS", "ENABLED", "HITS"
            );
            for a in &archives {
                println!(
                    "{:<24} {:>10} {:>8} {:>8}",
                    a.name, a.function_count, a.enabled, a.hits
                );
            }
            println!("\nAll embedded archives:");
            for s in &available {
                println!("  {:<24} loaded={}", s.stem, s.loaded);
            }
        }
    } else {
        emit(args.bin.json, &archives, || {
            println!(
                "{:<24} {:>10} {:>8} {:>8}",
                "NAME", "FUNCTIONS", "ENABLED", "HITS"
            );
            for a in &archives {
                println!(
                    "{:<24} {:>10} {:>8} {:>8}",
                    a.name, a.function_count, a.enabled, a.hits
                );
            }
        })?;
    }
    Ok(())
}

fn sources_resolve(args: SourcesResolveArgs) -> Result<()> {
    let project = open_project(&args.bin)?;
    let archives: Vec<Arc<reghidra_decompile::type_archive::TypeArchive>> =
        project.effective_type_archives();
    let idx = which_archive_resolves(&args.name, &archives);
    let payload = ResolveJson {
        name: args.name.clone(),
        archive: idx.map(|i| archives[i].name.clone()),
        archive_index: idx,
    };
    emit(args.bin.json, &payload, || match &payload.archive {
        Some(name) => println!("{} -> {name}", payload.name),
        None => println!("{} -> (not resolved by any loaded archive)", payload.name),
    })
}

fn sources_set_enabled(args: SourcesToggleArgs, enabled: bool) -> Result<()> {
    let (mut project, session_path) = open_project_for_mutation(&args.bin)?;
    match args.kind {
        SourceKind::Bundled => {
            let target = format!("bundled:{}", args.key);
            let idx = project
                .bundled_dbs
                .iter()
                .position(|db| db.source_path.to_str() == Some(target.as_str()))
                .ok_or_else(|| {
                    anyhow!(
                        "no bundled FLIRT db with key '{}'. Try `reghidra-cli sources flirt --available` to list valid keys.",
                        args.key
                    )
                })?;
            project.set_bundled_db_enabled(idx, enabled);
        }
        SourceKind::User => {
            let idx = project
                .user_dbs
                .iter()
                .position(|db| db.header.name == args.key)
                .ok_or_else(|| anyhow!("no user FLIRT db with key '{}'", args.key))?;
            project.set_user_db_enabled(idx, enabled);
        }
        SourceKind::Archive => {
            let idx = project
                .type_archives
                .iter()
                .position(|a| a.name == args.key)
                .ok_or_else(|| anyhow!("no type archive named '{}'", args.key))?;
            project.set_type_archive_enabled(idx, enabled);
        }
    }
    project.save_session(&session_path)?;
    if !args.bin.json {
        println!(
            "{}d {:?} '{}' (saved to {})",
            if enabled { "Enable" } else { "Disable" },
            args.kind,
            args.key,
            session_path.display()
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "kind": format!("{:?}", args.kind),
                "key": args.key,
                "enabled": enabled,
            }))?
        );
    }
    Ok(())
}

fn sources_load_archive(args: SourcesLoadArchiveArgs) -> Result<()> {
    let (mut project, session_path) = open_project_for_mutation(&args.bin)?;
    let idx = project
        .load_type_archive_by_stem(&args.stem)
        .ok_or_else(|| anyhow!("type archive '{}' not found in embedded set", args.stem))?;
    project.save_session(&session_path)?;
    println!(
        "Loaded type archive '{}' at index {idx} ({} functions)",
        project.type_archives[idx].name,
        project.type_archives[idx].functions.len()
    );
    Ok(())
}

fn sources_load_sig(args: SourcesLoadSigArgs) -> Result<()> {
    let (mut project, session_path) = open_project_for_mutation(&args.bin)?;
    let idx = project
        .load_bundled_sig(&args.subdir, &args.stem)
        .ok_or_else(|| {
            anyhow!(
                "bundled FLIRT sig '{}/{}' not found",
                args.subdir,
                args.stem
            )
        })?;
    project.save_session(&session_path)?;
    println!(
        "Loaded bundled sig '{}/{}' at index {idx} ({} signatures)",
        args.subdir, args.stem, project.bundled_dbs[idx].signature_count
    );
    Ok(())
}

fn sources_load_user_sig(args: SourcesLoadUserSigArgs) -> Result<()> {
    let (mut project, session_path) = open_project_for_mutation(&args.bin)?;
    // Validate the file parses before we touch project state.
    let _ = FlirtDatabase::load(&args.path)
        .with_context(|| format!("failed to parse '{}'", args.path.display()))?;
    let matched = project.load_signatures(&args.path)?;
    project.save_session(&session_path)?;
    println!("Loaded user sig from {}; {matched} total matches", args.path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// `annotate` dispatcher
// ---------------------------------------------------------------------------

fn cmd_annotate(cmd: AnnotateCommand) -> Result<()> {
    match cmd {
        AnnotateCommand::Comment(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            p.set_comment(args.address, args.text);
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::Rename(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            p.rename_function(args.address, args.name);
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::RenameLabel(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            p.rename_label(args.address, args.name);
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::RenameVar(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            p.rename_variable(args.func_address, args.displayed_name, args.new_name);
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::Retype(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            p.set_variable_type(args.func_address, args.displayed_name, args.type_str);
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::Bookmark(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            if !p.bookmarks.contains(&args.address) {
                p.bookmarks.push(args.address);
            }
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::Unbookmark(args) => {
            let (mut p, sp) = open_project_for_mutation(&args.bin)?;
            p.bookmarks.retain(|&a| a != args.address);
            p.save_session(&sp)?;
            Ok(())
        }
        AnnotateCommand::List(args) => {
            let project = open_project(&args)?;
            let payload = AnnotationsJson {
                comments: project
                    .comments
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect(),
                renamed_functions: project
                    .renamed_functions
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect(),
                label_names: project
                    .label_names
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect(),
                variable_names: project
                    .variable_names
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                variable_types: project
                    .variable_types
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                bookmarks: project.bookmarks.clone(),
            };
            emit(args.json, &payload, || {
                println!("Comments: {}", payload.comments.len());
                for (a, t) in &payload.comments {
                    println!("  0x{a:08x}  {t}");
                }
                println!("Renamed functions: {}", payload.renamed_functions.len());
                for (a, n) in &payload.renamed_functions {
                    println!("  0x{a:08x}  {n}");
                }
                println!("Renamed labels: {}", payload.label_names.len());
                for (a, n) in &payload.label_names {
                    println!("  0x{a:08x}  {n}");
                }
                println!("Renamed variables: {}", payload.variable_names.len());
                for ((fa, dn), n) in &payload.variable_names {
                    println!("  fn=0x{fa:08x}  {dn}  ->  {n}");
                }
                println!("Variable types: {}", payload.variable_types.len());
                for ((fa, dn), t) in &payload.variable_types {
                    println!("  fn=0x{fa:08x}  {dn}  : {t}");
                }
                println!("Bookmarks: {}", payload.bookmarks.len());
                for a in &payload.bookmarks {
                    println!("  0x{a:08x}");
                }
            })
        }
    }
}

// ---------------------------------------------------------------------------
// `session` dispatcher
// ---------------------------------------------------------------------------

fn cmd_session(cmd: SessionCommand) -> Result<()> {
    match cmd {
        SessionCommand::Init { binary, output } => {
            let project = Project::open(&binary)
                .with_context(|| format!("failed to open binary '{}'", binary.display()))?;
            project.save_session(&output)?;
            println!("Initialized session at {}", output.display());
            Ok(())
        }
        SessionCommand::Show { file } => {
            let data = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read '{}'", file.display()))?;
            let json: serde_json::Value = serde_json::from_str(&data)?;
            println!("{}", serde_json::to_string_pretty(&json)?);
            Ok(())
        }
        SessionCommand::Refresh { file } => {
            let project = Project::open_with_session(&file)?;
            project.save_session(&file)?;
            println!("Refreshed {}", file.display());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tiny utility
// ---------------------------------------------------------------------------

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

// Suppress the unused-import lint when we ever drop a downstream type.
#[allow(dead_code)]
fn _path_marker(_: &Path) {}
