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
- **Decompiler** — type inference, control flow structuring (if/else/while/goto), heuristic stack frame recovery (named `local_<hex>` / `arg_<hex>` slots with offset-keyed renaming), global data naming (`g_dat_<hex>`), PE IAT call target resolution, blank-line separated logical sections, C-style compliant output with token-level syntax highlighting (Nord/Solarized palettes for dark/light themes)
- **FLIRT signature matching** — ships with 160+ bundled signature databases (rizinorg/sigdb plus IDA-derived packs) covering ELF and PE across x86, ARM, and MIPS; auto-applied on binary load with IDA-precedence ordering, collision-placeholder filtering, and support for user-provided `.sig` files
- **Symbol demangling** — MSVC C++ mangled names (`?foo@Bar@@...`) and `@name@N` / `_name@N` calling-convention decoration are demangled for display while the canonical mangled form is preserved for xrefs, renames, and session storage
- **Heuristic auto-naming** — IDA-style string labels (`s_EnterPassword`), function naming via thunk/wrapper/string-ref/API-pattern detection
- **Interactive GUI** — synchronized disassembly, decompile, hex, CFG, IR, and xref views with dark/light themes
- **Keyboard-driven workflow** — Vim-like navigation, command palette (Cmd+K), fuzzy search, inline annotations, undo/redo
- **Right-click context menu** — navigate, comment, rename (functions, labels, variables), bookmark, show xrefs, copy address/string from any symbol across disasm, decompile, xrefs, and side panels
- **Session persistence** — comments, renames, and bookmarks are saved to and loaded from session files

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
cargo run --release -p reghidra-cli -- <binary>
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
- [ ] Headless CLI batch analysis mode

## License

MIT
