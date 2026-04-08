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
│   │       ├── annotations.rs          # Comment/rename popup dialogs
│   │       ├── context_menu.rs         # Right-click context menu (symbol actions)
│   │       ├── palette.rs              # Command palette (Cmd+K)
│   │       ├── theme.rs                # Dark/light themes + color palette
│   │       ├── undo.rs                 # Undo/redo history (Action enum)
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
- [x] Function detection (symbols + heuristic prologue/epilogue + call targets + gated tail-call jmp targets + MSVC hotpatch prologue)
- [x] CFG-reachability-based function extents (two-pass: entry discovery → per-entry CFG walk stopping at rets, indirect branches, and other known entries)
- [x] PE metadata mining: x64 `.pdata` exception table, Debug Directory CodeView RSDS (PDB GUID/age/path), Rich Header (MSVC toolchain fingerprint)
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
- [x] Split/tabbed synchronized views (split is the default layout; Space to toggle single)
- [x] Full undo/redo history (Cmd+Z / Cmd+Shift+Z)
- [x] Right-click context menu on any symbol (navigate, comment, rename, bookmark, xrefs, copy address/string)
- [x] Rename labels and decompiler variables in addition to functions
- [x] Session persistence (comments, renames, bookmarks saved/loaded)

### Phase 5a — In-App Documentation
- [x] Help overlay with tabbed content (Quick Start, Keyboard, Views, Workflow)
- [x] F1 and ? keyboard shortcuts to toggle help
- [x] Help menu in menu bar
- [x] Help accessible from welcome screen (before loading a binary)
- [x] Help discoverable via command palette (Cmd+K → "Help")
- [x] Status bar hint for help shortcut

### Phase 5b — Decompiler Quality
- [x] Merge IDA FLIRT sig packs (86 added) into bundled `signatures/` tree, IDA-precedence ordering at load time
- [x] Fix FLIRT `IDASIG_FUNCTION_UNRESOLVED_COLLISION` (0x08) so collision-placeholder names don't leak through as `?`
- [x] Resolve PE IAT call targets (`call [imm]` x86-32 and `call [rip+disp]` x86-64) — emits `Call { target: iat_addr }` and `project::decompile` merges `binary.import_addr_map` into `function_names`
- [x] Fix double-deref bug: `parse_memory_expression` now returns address-value varnodes (`Constant`/`Register`/temp) for `[imm]`/`[reg]`/`[reg±imm]` instead of `VarSpace::Memory` descriptors that the expression builder was wrapping in a second `Deref`
- [x] Fix `pop [mem]` and `push [mem]` regression after the above (`read_operand`/`write_operand` helpers in x86_64 lifter)
- [x] Stack-arg collapsing in `expr_builder::build_statements` — defer `Store { addr=esp/rsp/sp }` ops, attach to following Call as args (reversed for source order), flush as plain stack writes if interrupted
- [x] Variable rename canonicalization: sized aliases of one register share a single rename via `canonical_reg_name` (rax/eax/ax/al → rax, etc.), and `is_known_register_name` routes ALL recognized GPRs through the renamer instead of leaking through. x86-32 detection pre-pass (`scan_for_x86_32`) suppresses argN mapping when 32-bit register forms are seen.
- [x] Tier-2 heuristic stack frame analysis (`reghidra-decompile/src/stackframe.rs`). Runs between `structure::structure` and `varnames::rename_variables`. Detects the canonical `push rbp; mov rbp, rsp` frame setup, classifies `*(rbp)` / `*(rbp ± k)` and via-temp (`tN = rbp + k; *(tN)`) accesses into a `FrameLayout` keyed on signed offset, rewrites them to `local_<hex>` / `arg_<hex>` slot names (IDA-style — offset-keyed, NOT sequential, so retyping doesn't renumber siblings), drops the prologue bookkeeping (`rsp = rsp - 8; *(rsp) = rbp; rbp = rsp;` and the matching epilogue `rbp = *(rsp); rsp = rsp + 8`), drops dead temp definitions whose only use was a stack-access address, and prepends `VarDecl` statements at the top of the function body for the discovered slots. Offset 0 is filtered out (saved rbp, always noise). Scope gaps: (a) no frame pointer → no rewrites (rsp-delta tracking deferred), (b) ARM64 `stp x29, x30; mov x29, sp` not yet recognized, (c) slots default to `CType::Unknown(size)` until typing arrives in Phase 5c.
- [ ] Phase 5c — Type library layer. Drop GDT (closed format, shipping TILs is a licensing grey area even after tilutil reverse engineering). Source types from MIT/Apache Rust binding crates: `windows-sys` for Win32 APIs (authoritative, pulled from microsoft/win32metadata), `libc` for POSIX / libc / Linux / macOS. Build-time extractor (`tools/typegen`) walks these crates with `syn` and emits a bespoke archive format (probably postcard) — no C parser needed. Archives auto-load at project init by format+arch, same pattern as FLIRT sigs. Drives arity capping, typed parameter display, return-type propagation, and retype slot subsumption. Optional PDB layer on top via the `pdb` crate — when a `.pdb` sibling is found next to a PE binary, it populates `FrameLayout` with authoritative slot names and types from `S_GPROC32`/`S_REGREL32`/`S_LOCAL` records, overriding the tier-2 heuristics.
- [x] Global data naming: bare `Load`/`Store` of a constant address ≥ `GLOBAL_DATA_MIN_ADDR` (0x1000) is rewritten by `expr_builder::memory_access_expr` into `g_dat_<hex>` instead of `*(0xADDR)`. Addresses in `function_names` (PE IAT slots etc.) emit the resolved function name instead. The GUI decompile tokenizer recognizes `g_dat_<hex>` as a clickable hex-address token. Click-to-navigate works; right-click rename works via the variable-name collector (g_dat names are picked up by `collect_displayed_names`). PDB symbol names are NOT yet wired up — only the `g_dat_` fallback is emitted (PDB parser currently only extracts GUID/age/path).
- [x] RMW memory destinations in `lift_binop`/`lift_xor`/`lift_inc_dec`/`lift_not`/`lift_neg` — new `rmw_begin`/`rmw_end` helpers load current value into a temp, perform the op on the temp, and store the result back. Register destinations unchanged (no spurious Load/Store).
- [x] `leave`/`pushfd`/`pushfq`/`popfd`/`popfq` lifter intrinsics (previously `/* unimpl */`)
- [x] MSVC C++ name demangling for display via `reghidra_core::demangle` (msvc-demangler crate). Mangled names stay canonical in storage/renames/xref keys; GUI views and `project.functions()`/`project.display_function_name` go through the helper. `DecompileContext::current_function_display_name` carries the demangled form into `emit_function` without mutating the IR.
  - **Two flavors**: `display_name` = full signature (used by decompile body + `function_names` call-target map); `display_name_short` (NAME_ONLY flag) = symbol only (used by sidebar function list, disasm block header, CFG/IR/xref headers, decompile top label). Full form and short form must match in their respective contexts — the reverse `name → addr` lookup map in `views/decompile.rs` uses `display_name` because that's what the decompile body prints in call expressions.
  - **Calling-convention decoration**: `strip_msvc_decoration` handles `@name@N` (fastcall) and `_name@N` (stdcall) — e.g. `@__security_check_cookie@4` → `__security_check_cookie`. Bare leading underscores without the `@N` suffix are intentionally left alone (legitimate on ELF symbols like `_start`).
  - **FLIRT `?` placeholder filter**: `is_meaningful_sig_name` in `flirt.rs` gates both `collect_matches` and the final apply step, so sig files that leak a bare `?` through the collision-bit filter no longer clutter the function list — affected functions stay as their canonical `sub_XXXX`.
- [x] Blocky disassembly function header: four-line block (top rule, `; FUNCTION name`, `;   0xADDR · N insns · M xrefs`, bottom rule). Right-click context menu is attached to the name row; rules and stats are passive. Implemented as separate `DisplayLine::FuncHeaderRule` / `FuncHeaderName` / `FuncHeaderStats` variants so the fixed-row-height `show_rows` scrolling still works.

### Phase 6 — Extensibility + Scripting
- [ ] Lua scripting API
- [ ] Rust trait-based plugin system
- [ ] Headless CLI mode for batch analysis

## Build & Packaging
- Workspace version lives in `Cargo.toml` under `[workspace.package]` — bump once, all crates inherit it.
- macOS .app bundle: `./scripts/bundle-macos.sh` (add `--debug` for debug builds); outputs `target/Reghidra.app`.
- Release builds hide the Windows console window via `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` in `reghidra-gui/src/main.rs` — debug builds keep the console for dev output.

## Conventions
- Workspace crates communicate via public APIs defined in each crate's `lib.rs`
- Error handling: use `thiserror` for library errors, `anyhow` in CLI/GUI
- All public APIs should have doc comments
- Test with real binaries in `tests/fixtures/`
- Never mention AI tools in commit messages or code comments

## Decompile output style
We follow the UChicago C style guide (https://uchicago-cs.github.io/student-resource-guide/style-guide/c.html) as the reference for generated pseudocode:
- 4-space indentation (no tabs). `reghidra-decompile/src/emit.rs` hard-codes this.
- K&R brace style (`void foo(void) {` on same line, closing `}` on its own).
- Empty parameter lists are `(void)`, not `()` — K&R `()` means "unspecified prototype" in strict C.
- Space after control keywords (`if (cond)`, `while (cond)`), space around binary operators, no space around `*`/`&`/`.`/`->` in their unary/postfix forms (we strip parens around simple deref/addrof operands via `needs_no_deref_parens` in emit.rs).
- Blank line between the leading `VarDecl` block and the rest of the function body so the variables section is visually distinct.
- No compound one-line statements — every body is a brace block.
- Block comments use `/* ... */`; line comments (`//`) only for annotations we explicitly emit.

## Decompile syntax highlighting
- Token-level coloring, not per-line. `reghidra-gui/src/syntax.rs` is the C lexer — every rendered decomp line is split into `SyntaxKind` spans (Keyword, Type, Number, String, Operator, Punctuation, Comment, Return, Goto, Identifier, Whitespace) and each span is painted with the theme's matching color. Do not regress this to per-line colorizing — it was literally a wall of code before.
- The rendering path is `render_interactive_line` → `emit_syntax_spans` in `views/decompile.rs`. The clickable-token pass (`tokenize_line`) still overlays on top so function calls / labels / hex addresses / variable references stay interactive with their own colors.
- Theme palette for dark mode is Nord-inspired (Nord Frost for types, Nord Aurora purple for keywords, Aurora orange for numbers, Aurora green for strings, Snow Storm for operators/default, Polar Night gray for comments). Light mode uses Solarized equivalents. When adding a new `SyntaxKind` remember to update both `Theme::dark` and `Theme::light` plus the `decomp_color` match, and extend the hand-curated keyword/type lists in `syntax::CONTROL_KEYWORDS` and `syntax::C_TYPE_KEYWORDS` (kept in sorted order for `binary_search`).

## Analysis pipeline notes
- `functions::detect_functions` is a two-pass design: (1) entry discovery from all sources (binary entry, symbols, call targets, gated tail-call jmps, prologues, PE `.pdata`, Guard CF), (2) per-entry CFG reachability walk via `cfg::build_cfg_from_entry` that stops at rets, indirect branches, and other known entries. Function size/instruction count come from `ControlFlowGraph::extent()` — do not fall back to linear walks. CFGs are built once during detection and reused by xrefs/IR lifting.
- Adding a new entry source? Feed it into `collect_extra_entries` in `analysis.rs` with a `FunctionSource` variant, not into `detect_functions` directly.
- PE-specific metadata lives on `LoadedBinary` (`pdata_function_starts`, `guard_cf_function_starts`) and `BinaryInfo` (`pdb_info`, `rich_header`). Guard CF parser is stubbed; the Load Config Directory decoder is a follow-up.

## Lifter / decompiler notes
- **VarNode address vs value distinction**: `parse_memory_expression` returns a varnode whose *value is the effective address*, not a `VarSpace::Memory` descriptor. Callers pass it as `Store.addr` / `Load.addr`, and the expression builder's single `Expr::Deref` wrap produces correct C. Do NOT reintroduce `VarSpace::Memory` flowing out of operand parsing — it caused a double-deref bug (`*(*(0x40dfd8))`).
- **Memory-destination ops**: x86 has read-modify-write forms (`mov [m], r`, `add [m], r`, `inc [m]`, `pop [m]`). Use the `read_operand`/`write_operand` helpers in `x86_64.rs` — `parse_operand` is fine for non-memory operands and for cases where you want the address itself (jmp/call targets). Currently only `lift_mov`, `lift_push`, `lift_pop` use the helpers; binops/inc/dec are still on the old path and have a latent bug for memory destinations.
- **IAT call resolution**: x86-32 `call [imm]` and x86-64 `call [rip+disp]` lift to `IrOp::Call { target: iat_slot_addr }` rather than `CallInd`. `project::decompile` merges `binary.import_addr_map` into `DecompileContext.function_names` keyed by IAT slot address, so the existing target-lookup path resolves them. Register-indirect calls (`call rax`, `call [rbx+8]`) still lift to `CallInd`.
- **Stack-arg collapsing** lives in `expr_builder::build_statements`, NOT in the lifter. It's a per-block walk that defers `Store { addr=stack_pointer }` into a `pending_stack_writes` queue and consumes it on the next `Call`/`CallInd` (in reverse order — first arg = last pushed). Any non-call instruction flushes the queue as plain `*(rsp) = x` assignments. Limitation: without per-function arity it can over-attribute pushes (e.g. an arg pushed for a later call gets consumed by an intervening 0-arg call). Fix needs the type-library loader.
- **Variable renamer** (`varnames.rs`):
  - All sized aliases of an x86 GPR canonicalize via `canonical_reg_name` (eax/ax/al → rax). The `renames` map is keyed on canonical names so mixed-width accesses share one rename.
  - `is_known_register_name` is the gate that decides whether an unrecognized var should become a fresh `var_N` (it's a register) or be left alone (probably a function name, global, or already-renamed).
  - x86-32 mode is detected by a pre-pass (`scan_for_x86_32`) before `collect_vars` runs. When set, the SysV `argN` mapping for `rdi/rsi/rdx/rcx/r8/r9` is suppressed because x86-32 cdecl/stdcall pass everything on the stack.
  - `rsp/rbp/result/flags` are intentionally left visible; eliminating them needs stack-frame analysis.

## FLIRT notes
- Bundled `signatures/` tree contains both rizinorg/sigdb sigs (named like `VisualStudio2015.sig`, `ubuntu-libc6.sig`) and IDA-derived sigs (named like `vc32_14.sig`, `pe.sig`). `bundled_sigs::collect_bundled_sigs` orders IDA sigs first so they take precedence at apply time (first DB to match wins).
- IDA `.sig` files use bit `0x08` (`IDASIG_FUNCTION_UNRESOLVED_COLLISION`) in the optional pre-name attribute byte to mark collision placeholders that `sigmake` couldn't resolve. The placeholder name is typically `?`. `parse_module` tracks `is_collision` per public-name candidate and clears the module name if every candidate is a collision; `apply_signatures` already skips empty-name modules. Don't reintroduce naive name parsing that ignores the attribute byte.
- The 16-bit/DOS/OS-2/NetWare/NE/LE/Mach-O-startup sigs from the IDA pack are intentionally NOT bundled (we don't target those formats); see the classification logic that was used to add the 86 files for which file_types/app_types we accepted.
