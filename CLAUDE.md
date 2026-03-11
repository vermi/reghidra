# Reghidra — Project Instructions

## Overview
Reghidra is a Rust-based reverse engineering framework reimplementing Ghidra's core functionality with a modern, user-friendly interface. OS-agnostic, built with Rust + egui.

## Project Structure
```
reghidra/
├── Cargo.toml                          # workspace root
├── crates/
│   ├── reghidra-core/
│   │   └── src/
│   │       ├── lib.rs                  # public API re-exports
│   │       ├── arch.rs                 # Architecture enum
│   │       ├── binary.rs               # ELF/PE/Mach-O loader (goblin)
│   │       ├── disasm.rs               # Disassembler (capstone)
│   │       ├── error.rs                # CoreError
│   │       ├── project.rs              # Project (ties everything together)
│   │       └── analysis/
│   │           ├── mod.rs              # AnalysisResults
│   │           ├── functions.rs        # Function detection
│   │           ├── cfg.rs              # Control flow graph
│   │           ├── xrefs.rs            # Cross-references
│   │           ├── naming.rs           # Heuristic auto-naming
│   │           ├── flirt.rs            # FLIRT .sig parser + matcher
│   │           └── bundled_sigs.rs     # Bundled sigdb (auto-loaded per format+arch)
│   ├── reghidra-ir/
│   │   └── src/
│   │       ├── lib.rs                  # public API
│   │       ├── op.rs                   # IrOp enum (~30 opcodes), VarNode, VarSpace
│   │       ├── types.rs                # IrInstruction, IrBlock, IrFunction
│   │       ├── display.rs              # Display impls for pretty-printing
│   │       ├── optimize.rs             # constant fold, copy prop, DCE
│   │       └── lifter/
│   │           ├── mod.rs              # LiftContext, DisasmInput
│   │           ├── x86_64.rs           # x86_64 lifter
│   │           └── arm64.rs            # ARM64 lifter
│   ├── reghidra-decompile/
│   │   └── src/
│   │       ├── lib.rs                  # decompile() entry point
│   │       ├── ast.rs                  # Expr/Stmt/CType AST
│   │       ├── expr_builder.rs         # IR ops → AST expressions
│   │       ├── structuring.rs          # CFG → if/else/while/goto
│   │       ├── varnames.rs             # variable renaming pass
│   │       ├── types.rs                # type inference
│   │       └── emit.rs                 # AST → C-like text
│   ├── reghidra-gui/
│   │   └── src/
│   │       ├── main.rs                 # Entry point
│   │       ├── app.rs                  # App state + eframe::App impl
│   │       ├── help.rs                 # In-app help overlay (quickstart, keys, views, workflow)
│   │       └── views/
│   │           ├── disasm.rs           # Disassembly view
│   │           ├── decompile.rs        # Decompiled C view
│   │           ├── hex.rs              # Hex view
│   │           ├── cfg.rs              # CFG view
│   │           ├── ir.rs               # IR view
│   │           ├── xrefs.rs            # Cross-references view
│   │           └── side_panel.rs       # Sidebar (fns, symbols, etc.)
│   └── reghidra-cli/                   # Headless CLI
├── signatures/                         # Bundled FLIRT .sig files (from rizinorg/sigdb)
│   ├── elf/{arm,mips,x86}/{32,64}/     # ELF sigs by arch+bitness
│   └── pe/{arm,mips,sh,x86}/{32,64}/   # PE sigs by arch+bitness
└── tests/fixtures/                     # Test binaries
```

## Key Dependencies
- `goblin` — ELF/PE/Mach-O binary parsing
- `capstone` — multi-arch disassembly
- `egui` + `eframe` — GUI framework
- `sled` or `rusqlite` — project database
- `mlua` — Lua scripting
- `syntect` — syntax highlighting

## Implementation Phases & Status

### Phase 1 — Foundation (Binary Loading + Disassembly)
- [x] Project scaffolding (Cargo workspace with all crates)
- [x] Binary loader using goblin (ELF, PE, Mach-O)
- [x] Disassembler using capstone (x86_64, ARM64)
- [x] Basic GUI shell (file open, disasm view, hex view, symbols sidebar, function list)

### Phase 2 — Analysis Engine
- [x] Function detection (symbols + heuristic prologue/epilogue + call targets)
- [x] Control flow graph (basic blocks, interactive CFG view in GUI)
- [x] Cross-references (code xrefs + data xrefs, click-to-navigate, xref panel)
- [x] String detection with xrefs
- [x] Import/export resolution panel
- [x] Xref annotations inline in disassembly view
- [x] Function headers in disassembly with xref counts

### Phase 3 — Intermediate Representation + Lifting
- [x] Design RIR (register transfer language with varnodes, ~30 opcodes)
- [x] x86_64 lifter (mov, lea, push/pop, add/sub/mul, and/or/xor, shl/shr, cmp/test, jcc, call, ret, etc.)
- [x] ARM64 lifter (mov/movz/movn, ldr/str/ldp/stp, add/sub/mul, and/orr/eor, cmp/tst, b/bl/blr/cbz/b.cond, ret, etc.)
- [x] IR optimization passes (constant folding, copy propagation, dead code elimination, NOP removal)
- [x] IR view in GUI (color-coded by op type, linked to source addresses)

### Phase 4 — Decompiler
- [x] Type inference (varnode size → C types: int8..uint64, pointer)
- [x] Control flow structuring (if/else from CBranch, while from back-edges, goto fallback)
- [x] Expression builder (IR ops → C-like AST: binary/unary ops, calls, derefs, casts)
- [x] Variable naming heuristics (arg0-N for param regs, result for rax, var_N for temps)
- [x] C-like pseudocode renderer with flag/stack cleanup
- [x] Decompile view in GUI (color-coded by statement type)

### Phase 5 — User Experience
- [x] Unified click-to-navigate everywhere
- [x] Inline annotations (comments, renames, bookmarks) with popup dialogs
- [x] Fuzzy search + command palette (Cmd+K)
- [x] Dark/light themes, centralized color palette
- [x] Vim-like keyboard navigation (j/k, n/N, gg/G, ;, r, x, d, 1-6)
- [x] Split/tabbed synchronized views (Space to toggle split)
- [x] Full undo/redo history (Cmd+Z / Cmd+Shift+Z)

### Phase 5a — In-App Documentation
- [x] Help overlay with tabbed content (Quick Start, Keyboard, Views, Workflow)
- [x] F1 and ? keyboard shortcuts to toggle help
- [x] Help menu in menu bar
- [x] Help accessible from welcome screen (before loading a binary)
- [x] Help discoverable via command palette (Cmd+K → "Help")
- [x] Status bar hint for help shortcut

### Phase 6 — Extensibility + Scripting
- [ ] Lua scripting API
- [ ] Rust trait-based plugin system
- [ ] Headless CLI mode for batch analysis

## Conventions
- Workspace crates communicate via public APIs defined in each crate's `lib.rs`
- Error handling: use `thiserror` for library errors, `anyhow` in CLI/GUI
- All public APIs should have doc comments
- Test with real binaries in `tests/fixtures/`
- Never mention AI tools in commit messages or code comments
