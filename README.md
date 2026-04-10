<p align="center">
  <img src="assets/reghidra.png" alt="Reghidra" width="128" />
</p>

<h1 align="center">Reghidra</h1>

A Rust-based reverse engineering framework reimplementing Ghidra's core functionality with a modern, user-friendly interface. Cross-platform, built with Rust and egui.

## Features

- **Multi-format binary loading** — ELF, PE, and Mach-O via goblin
- **Multi-architecture disassembly** — x86_64, ARM64 (and more) via capstone
- **Automated analysis** — function detection (symbols, prologues including MSVC hotpatch, call targets, tail-call jmp targets) with CFG-reachability-based boundaries, control flow graphs, cross-references, string detection with auto-naming
- **PE metadata mining** — x64 `.pdata` exception table for authoritative function starts, CodeView Debug Directory for PDB references (GUID/age/path), Rich Header for MSVC toolchain fingerprinting
- **Intermediate representation** — register transfer language with ~30 opcodes, x86_64 and ARM64 lifters, optimization passes (constant folding, copy propagation, DCE)
- **Decompiler** — type inference, control flow structuring (if/else/while/goto), heuristic stack frame recovery (named `local_<hex>` / `arg_<hex>` slots with offset-keyed renaming) on x86 and ARM64 frame pointers, MSVC SEH4 prologue fallback that synthesizes arg slots from the prototype when the canonical frame setup is absent, global data naming (`g_dat_<hex>`), call-target resolution across PE IAT and Mach-O `__stubs`, blank-line separated logical sections, C-style compliant output with token-level syntax highlighting (Nord/Solarized palettes for dark/light themes)
- **Bundled type archives** — ~20 k Win32 prototypes (windows-sys) for x86/x64/ARM64, ~450 POSIX prototypes (libc), plus a 226-function MSVC CRT archive (`ucrt.rtarch`) shipped as postcard-serialized `.rtarch` blobs auto-selected by binary format + architecture. Drives arity capping on stack-arg collapse, surfaces parameter types at call sites as casts (`TerminateProcess((HANDLE)hProc, (DWORD)exit_code)`), propagates return types onto call-result locals (`HANDLE result = CreateFileA(...)`), and types the function's own signature line when the prototype is known. Cross-block pending propagation recovers arg lists that straddle basic-block boundaries (the canonical Win32 termination idiom where `push; call` is split by the lifter).
- **User retype UI** — right-click any local variable in the decompile view → **Set Type...** → enter a C type name (`HANDLE`, `uint32_t`, `char*`). Overrides the heuristic/archive-inferred type on the matching `VarDecl`, persists across session reloads, participates in undo/redo.
- **FLIRT signature matching** — ships with 160+ bundled signature databases (rizinorg/sigdb plus IDA-derived packs) covering ELF and PE across x86, ARM, and MIPS; auto-applied on binary load with IDA-precedence ordering, collision-placeholder filtering, and support for user-provided `.sig` files
- **Symbol demangling** — MSVC C++ mangled names (`?foo@Bar@@...`) are demangled for display via the `undname` crate (a Rust port of LLVM's MicrosoftDemangle), matching real MSVC `undname.dll` output; `@name@N` / `_name@N` calling-convention decorations are stripped for display. The canonical mangled form is preserved for xrefs, renames, and session storage.
- **Heuristic auto-naming** — IDA-style string labels (`s_EnterPassword`), function naming via thunk/wrapper/string-ref/API-pattern detection
- **Interactive GUI** — synchronized disassembly, decompile, hex, CFG, IR, and xref views with dark/light themes
- **Keyboard-driven workflow** — Vim-like navigation, command palette (Cmd+K), fuzzy search, inline annotations, undo/redo
- **Right-click context menu** — navigate, comment, rename (functions, labels, variables), bookmark, show xrefs, copy address/string from any symbol across disasm, decompile, xrefs, and side panels
- **Session persistence** — comments, function/label/variable renames, variable type overrides, bookmarks, and data-source enable overrides are saved to and loaded from session files
- **Loaded Data Sources panel** — View → Loaded Data Sources surfaces every bundled and user FLIRT database plus every loaded type archive, with hit counts on the current binary, a 3-level nested tree of the embedded sig set (format → arch → bits), and lazy-load opt-in for anything the format/arch auto-selection skipped. Library names are pulled from each `.sig` header so the tree shows "Visual Studio 2010 Professional" instead of `vc32_14`. Clicking the signature status in the bottom status bar opens the panel.
- **Headless CLI** — `reghidra-cli` is a full subcommand-based interface with feature parity for everything content/state-related the GUI exposes: function listing, decompile, disasm, IR, CFG, xrefs, strings, sections, find, data-source view/select, annotations (comment/rename/retype/bookmark), and session management. Every read command supports `--json` for AI-agent and Python-script consumers, every mutation persists to a session file, and the full surface is tested end-to-end. See [`crates/reghidra-cli/README.md`](crates/reghidra-cli/README.md) for the walkthrough.

## Installation

Download the latest release for your platform from [Releases](https://github.com/reghidra/reghidra/releases).

### macOS

After extracting the `.tar.gz`, macOS Gatekeeper may block the app since it isn't notarized. To fix this, remove the quarantine attribute before launching:

```sh
xattr -cr Reghidra.app
```

Alternatively, right-click the app → **Open** → **Open** on the first launch.

## Building

Requires Rust 2024 edition (1.85+) and the capstone library.

```sh
# Install capstone (macOS)
brew install capstone

# Install capstone (Debian/Ubuntu)
sudo apt install libcapstone-dev

# Build
cargo build --release

# Run the GUI
cargo run --release -p reghidra-gui

# Run the CLI
cargo run --release -p reghidra-cli -- info --binary <binary>
cargo run --release -p reghidra-cli -- --help
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `j` / `k` | Move down / up |
| `n` / `N` | Next / previous function |
| `gg` / `G` | Jump to top / bottom |
| `r` | Rename function or address |
| `x` | Show cross-references |
| `d` | Toggle decompile view |
| `;` | Add comment |
| `Space` | Toggle split view |
| `1`-`6` | Switch view (disasm, decompile, hex, CFG, IR, xrefs) |
| `Cmd+K` | Command palette |
| `Cmd+Z` / `Cmd+Shift+Z` | Undo / redo |
| `F1` / `?` | Help overlay |

## Project Structure

```
reghidra/
├── crates/
│   ├── reghidra-core/       # Binary loading, disassembly, analysis engine
│   ├── reghidra-ir/         # Intermediate representation + lifters
│   ├── reghidra-decompile/  # IR → C-like pseudocode
│   ├── reghidra-gui/        # egui-based interactive GUI
│   └── reghidra-cli/        # Headless CLI for batch analysis
├── signatures/              # Bundled FLIRT .sig files (rizinorg/sigdb)
└── tests/fixtures/          # Test binaries
```

## Roadmap

- [ ] Lua scripting API
- [ ] Rust trait-based plugin system
- [ ] Long-running `reghidra-cli serve` daemon (JSON-RPC over stdio) for iterated AI-agent use without re-analysis on every call

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE) for the
full text.

Reghidra was originally released under the MIT license through commit
`19d5581` (Phase 5c PR 4f). Starting with the next commit it is
distributed under GPL-3.0-or-later so it can incorporate type-archive
and signature data curated by the [Rizin](https://rizin.re/) project,
which is itself GPLv3-licensed. Code from before the relicense remains
available under MIT through git history; anyone needing a permissive
fork can branch from `19d5581` or earlier.

### Bundled third-party data

- `signatures/` — FLIRT signature databases sourced from
  [rizinorg/sigdb](https://github.com/rizinorg/sigdb) and the
  IDA-derived public packs.
- `types/rizin-windows.rtarch` and `types/rizin-libc.rtarch` —
  derived works of Rizin's `librz/arch/types/functions-*.sdb.txt`
  function-signature database (GPLv3). The pinned upstream commit
  is recorded in `.github/workflows/typegen-regen.yml` under
  `RIZIN_REF`. Every release auto-regenerates these (and the
  binding-crate-derived archives under `types/`) via the regen
  workflow and commits the refreshed bytes back to `main` before
  release artifacts are assembled.
