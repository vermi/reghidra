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
│   │       ├── demangle.rs             # MSVC C++ + @/_stdcall decoration stripping
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
│   │       ├── expr_builder.rs         # IR ops → AST (+ g_dat_ rewrite, stack-arg collapse)
│   │       ├── stackframe.rs           # Frame detection, local_/arg_ slots, prologue cleanup
│   │       ├── structuring.rs          # CFG → if/else/while/goto
│   │       ├── varnames.rs             # Register/temp renaming, canonical_reg_name
│   │       ├── types.rs                # Varnode → CType inference (stub)
│   │       ├── type_archive/           # Phase 5c: bundled type archives
│   │       │   ├── mod.rs              # TypeArchive, FunctionType, TypeRef, load_embedded
│   │       │   └── archive.rs          # postcard (de)serialization + version gate
│   │       └── emit.rs                 # AST → C-like text (style + blank-line separators)
│   ├── reghidra-gui/
│   │   └── src/
│   │       ├── main.rs                 # Entry point
│   │       ├── app.rs                  # App state + eframe::App impl
│   │       ├── annotations.rs          # Comment/rename popup dialogs
│   │       ├── context_menu.rs         # Right-click context menu (symbol actions)
│   │       ├── palette.rs              # Command palette (Cmd+K)
│   │       ├── syntax.rs               # C lexer for decomp view per-token coloring
│   │       ├── theme.rs                # Dark/light themes + color palette (Nord/Solarized)
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
├── signatures/                         # Bundled FLIRT .sig files (rizinorg/sigdb + IDA-derived packs, IDA-precedence at load)
│   ├── elf/{arm,mips,x86}/{32,64}/     # ELF sigs by arch+bitness
│   └── pe/{arm,mips,sh,x86}/{32,64}/   # PE sigs by arch+bitness
└── tests/fixtures/                     # Test binaries
```

## Key Dependencies
- `goblin` — ELF/PE/Mach-O binary parsing
- `capstone` — multi-arch disassembly
- `egui` + `eframe` — GUI framework
- `msvc-demangler` — MSVC C++ symbol demangling (wired via `reghidra-core::demangle`)
- `serde` + `serde_json` — session persistence
- `flate2`, `include_dir` — bundled signature loading

Planned (not yet pulled in):
- `pdb` — PDB debug info parser (Phase 5c)
- `syn` + `quote` — build-time type archive extraction from `windows-sys` / `libc` (Phase 5c `tools/typegen`)
- `postcard` — on-disk type archive format (Phase 5c)
- `mlua` — Lua scripting (Phase 6)

## Implementation Phases & Status

> **Where to start (for a fresh session).** Phases 1–5b are complete and merged to `main`. Workspace test count at the time of this note: **71 tests passing**, zero warnings, clean build. The next actionable work is **Phase 5c — Typing & debug info** — see that section below for the full design, research trail (so you don't have to redo it), architecture sketch, and concrete task breakdown. Start by reading the Phase 5c section, then the `stackframe.rs`, `expr_builder.rs`, and `project.rs` files since those are the integration points. Don't try to add GDT or TIL — that was researched and explicitly rejected; see Phase 5c for why.

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
- [x] Global data naming: bare `Load`/`Store` of a constant address ≥ `GLOBAL_DATA_MIN_ADDR` (0x1000) is rewritten by `expr_builder::memory_access_expr` into `g_dat_<hex>` instead of `*(0xADDR)`. Addresses in `function_names` (PE IAT slots etc.) emit the resolved function name instead. The GUI decompile tokenizer recognizes `g_dat_<hex>` as a clickable hex-address token. Click-to-navigate works; right-click rename works via the variable-name collector (g_dat names are picked up by `collect_displayed_names`). PDB symbol names are NOT yet wired up — only the `g_dat_` fallback is emitted (PDB parser currently only extracts GUID/age/path).
- [x] RMW memory destinations in `lift_binop`/`lift_xor`/`lift_inc_dec`/`lift_not`/`lift_neg` — new `rmw_begin`/`rmw_end` helpers load current value into a temp, perform the op on the temp, and store the result back. Register destinations unchanged (no spurious Load/Store).
- [x] `leave`/`pushfd`/`pushfq`/`popfd`/`popfq` lifter intrinsics (previously `/* unimpl */`)
- [x] MSVC C++ name demangling for display via `reghidra_core::demangle` (msvc-demangler crate). Mangled names stay canonical in storage/renames/xref keys; GUI views and `project.functions()`/`project.display_function_name` go through the helper. `DecompileContext::current_function_display_name` carries the demangled form into `emit_function` without mutating the IR.
  - **Two flavors**: `display_name` = full signature (used by decompile body + `function_names` call-target map); `display_name_short` (NAME_ONLY flag) = symbol only (used by sidebar function list, disasm block header, CFG/IR/xref headers, decompile top label). Full form and short form must match in their respective contexts — the reverse `name → addr` lookup map in `views/decompile.rs` uses `display_name` because that's what the decompile body prints in call expressions.
  - **Calling-convention decoration**: `strip_msvc_decoration` handles `@name@N` (fastcall) and `_name@N` (stdcall) — e.g. `@__security_check_cookie@4` → `__security_check_cookie`. Bare leading underscores without the `@N` suffix are intentionally left alone (legitimate on ELF symbols like `_start`).
  - **FLIRT `?` placeholder filter**: `is_meaningful_sig_name` in `flirt.rs` gates both `collect_matches` and the final apply step, so sig files that leak a bare `?` through the collision-bit filter no longer clutter the function list — affected functions stay as their canonical `sub_XXXX`.
- [x] Blocky disassembly function header: four-line block (top rule, `; FUNCTION name`, `;   0xADDR · N insns · M xrefs`, bottom rule). Right-click context menu is attached to the name row; rules and stats are passive. Implemented as separate `DisplayLine::FuncHeaderRule` / `FuncHeaderName` / `FuncHeaderStats` variants so the fixed-row-height `show_rows` scrolling still works.
- [x] Decompile output C-style compliance (UChicago guide). `void foo(void)` for empty param lists, `*var` / `&var` instead of `*(var)` / `&(var)` for tight operands (`needs_no_deref_parens` in `emit.rs`), unary operators on Binary/Ternary operands get explicit parens for precedence safety, blank-line separators between logical sections via `emit::emit_body_with_separators` + `should_separate` (triggers: VarDecl↔body, before Label, control-flow↔straight-line, after Return/Goto, around Comment; never double blanks; runs recursively into nested bodies; SourceAddr markers skipped when picking "previous visible").
- [x] Decompile view token-level syntax highlighting. New `reghidra-gui/src/syntax.rs` is a small C lexer that tokenizes each rendered line into `SyntaxKind` spans (Keyword, Type, Return, Goto, Number, String, Operator, Punctuation, Comment, Identifier, Whitespace). Hand-curated sorted `CONTROL_KEYWORDS` and `C_TYPE_KEYWORDS` tables (the type table includes stdint, common Windows API aliases — HANDLE/HWND/DWORD/LPCSTR/etc. — and the `unkN` defaults). `Theme::decomp_color(SyntaxKind)` replaces the old per-line `colorize_decompile_line`. Rendering path in `views/decompile.rs`: `render_interactive_line` → `emit_syntax_spans` walks the lexer output and paints every token with its category color. Existing clickable-token overlay (function calls, labels, hex addresses, variables) still works on top. Dark-mode palette is Nord-inspired (Frost teal for types, Aurora purple for keywords, Aurora orange for numbers, Aurora green for strings, Snow Storm for operators/default, Polar Night slate for comments); light mode is Solarized equivalents.

### Phase 5c — Typing & debug info (IN PROGRESS)

**Goal.** Stack slots currently default to `CType::Unknown(size)`. Make them typed. Two data sources feed a unified `TypeArchive`: (1) Rust binding crates (build-time extraction, ships pre-built archives), (2) PDB files (runtime load, overrides archive data for binaries that ship symbols). Once typed, wire into arity capping for the stack-arg collapser, typed parameter display in decompile output, return-type propagation, and a right-click "Set Type" retype UI with slot subsumption (retyping a slot to a wider type collapses adjacent slots that fall inside the new extent).

**Naming vs typing precedence — DO NOT flatten these into one pipeline.** A function has two independently-sourced attributes, its *name* (what to call it) and its *type* (its signature). Each has its own chain of sources, and the two chains meet at the name: the typing chain keys off whatever name the naming chain produced.

- **Name source precedence** (highest → lowest):
  1. User rename (`Project::renamed_functions`)
  2. PE Import/Export tables (deterministic — `binary.import_addr_map`, export table)
  3. PDB (authoritative when the sibling `.pdb` is present — Phase 5c PR 5)
  4. FLIRT (byte-pattern matching for statically-linked third-party code — CRT, libc, libstdc++)
  5. Heuristic `sub_XXXX`
- **Type source precedence** (highest → lowest):
  1. User retype (Phase 5c PR 5 right-click "Set Type", persisted in `slot_types`)
  2. PDB (when present — overrides archive data for functions in the symbol stream)
  3. Type archive lookup — `windows-sys` / `libc` / `ucrt` bindings, keyed on the name from the naming chain
  4. `CType::Unknown(size)` fallback

The crucial thing is that **`windows-sys` is NOT in the naming chain**. It contains `extern "system"` declarations (name + prototype), not byte patterns, so it can't identify unnamed functions. Its value is purely as a type source: once the naming chain has produced `CreateFileA` (from the PE IAT), we look `CreateFileA` up in `windows-x64.rtarch` to get the prototype. Analogously, **FLIRT is NOT in the typing chain**: it produces names only. A FLIRT-matched `memcpy` becomes typed when we look `memcpy` up in `posix.rtarch` (from `libc`). The two sources compose cleanly because they never produce the same kind of information.

A practical consequence: FLIRT matching on functions that already have an authoritative name (IAT imports, PDB entries) is wasted work. A small optimization landable any time during Phase 5c is to skip `apply_signatures` for functions whose `FunctionSource` is already `Import` or (later) `Pdb`. Low-risk, pure win, no new data structures.

**Why not GDT or TIL (so the fresh agent doesn't redo this research).**
- **GDT** (Ghidra Data Type archives): closed binary format tightly coupled to Ghidra's Java `DataTypeManager`, no standalone parser, tooling (`ghidra-gdt`, `gdt_helper`) all runs inside Ghidra itself. Skip.
- **TIL** (IDA Type Information Library): format is closed in spec, partially reverse-engineered by the MIT-licensed Python [`tilutil`](https://github.com/aerosoul94/tilutil) (27 commits, WIP, "very messy code for documenting the TIL file format"). The Python [`idatil2c`](https://github.com/NyaMisty/idatil2c) converter REQUIRES IDA's `tilib` binary as a preprocessing step, so it's not IDA-independent. Even with a perfect parser, IDA's shipped TIL content is proprietary Hex-Rays data we can't redistribute — usable only as a user-supplied-at-runtime model, not a bundled-with-Reghidra one. Skip.
- **Rizin `librz/arch/types/*.sdb.txt`**: ~90 hand-curated SDB text files covering Windows APIs (34 `functions-windows_*` split per-header), POSIX/libc/Linux/macOS/Android, x86/ARM/MIPS calling conventions. Trivially parseable flat `key=value` format. GPLv3 licensed. **As of Phase 5c PR 4g, Reghidra is itself GPL-3.0-or-later**, so the licensing barrier is gone — Rizin's SDB content is now bundleable, and is the intended source for the MSVC CRT internals (`__SEH_prolog4`, `__EH4_*`, `__lockexit`, `__mtinit`, ...) that aren't in any auto-extractable Rust binding crate. Implementation lives in `tools/typegen/src/walker/rizin_sdb.rs` (not yet written — first task in PR 4h): a parser for the flat SDB format that converts entries into `FunctionType` / `TypeDef` and emits a per-source `.rtarch` blob alongside the existing libc/windows-sys outputs. **Attribution requirement**: GPLv3 obligates us to preserve Rizin's copyright notices in any derived archive. The walker should embed the source file path and Rizin commit SHA in the archive metadata, and the LICENSE file should call out the Rizin import explicitly.
- **`windows-sys` + `libc` + `syn` (what we're doing)**: MIT/Apache-2.0 Rust binding crates are auto-generated from [microsoft/win32metadata](https://github.com/microsoft/win32metadata) (authoritative) for `windows-sys` and maintained by rust-lang for `libc`. Every Win32 function prototype, struct layout, and calling convention is in them as Rust syntax, parseable with `syn` (which the `windows-sys` build already uses anyway). Cross-platform — a macOS dev host still gets Windows API type data because it's Rust source in a crate, not platform-specific C headers. Clean licensing, free update cadence (new APIs land in `windows-sys` within a release cycle).

**Architecture (as landed in PR 1 + PR 2, updated from the original sketch).**

```
reghidra/
├── tools/
│   └── typegen/                                # maintainer-only, OUT-OF-WORKSPACE (PR 3)
│       ├── Cargo.toml                          # own [workspace] table — not a member of root
│       └── src/main.rs                         # CLI: --source, --features, --arch, --os, --out
├── types/                                      # bundled .rtarch blobs, include_dir!'d at compile time
│   ├── README.md                               # maintainer-only policy doc (PR 1)
│   ├── posix.rtarch                            # libc → Linux/macOS POSIX (PR 3, ~29 KB)
│   ├── windows-x64.rtarch                      # windows-sys → Win64 LLP64 (PR 3b, ~9 MB)
│   ├── windows-x86.rtarch                      # windows-sys → Win32 ILP32 (PR 3b, ~9 MB)
│   ├── windows-arm64.rtarch                    # windows-sys → ARM64 LLP64 (PR 3b, ~9 MB)
│   └── ucrt.rtarch                             # libc → Windows MSVC CRT (PR 4f, ~17 KB)
├── .github/workflows/typegen-drift-check.yml   # regenerates + diffs on types/ or tools/typegen/ PRs (PR 3)
└── crates/
    ├── reghidra-decompile/
    │   └── src/
    │       ├── type_archive/                   # data model lives HERE, not in reghidra-core (PR 2)
    │       │   ├── mod.rs                      # TypeArchive, FunctionType, TypeRef, Primitive, load_embedded
    │       │   └── archive.rs                  # postcard (de)serialization + version gate
    │       ├── stackframe.rs                   # FrameLayout now returned, not discarded (PR 2)
    │       └── lib.rs                          # DecompileOutput/DecompileAnnotated expose FrameLayout; DecompileContext.type_archives wired
    └── reghidra-core/
        └── src/
            └── project.rs                      # BinaryInfo → stems dispatch (fn archive_stems_for / fn load_type_archives)
```

The data model lives in `reghidra-decompile::type_archive` (not `reghidra-core::types` as originally sketched) because `reghidra-core` already depends on `reghidra-decompile` — reversing that would be a cycle, and `DecompileContext` needs to carry `Arc<TypeArchive>` directly. `BinaryInfo`-aware stem selection stays in `reghidra-core::project` as a thin wrapper around `type_archive::load_embedded(stem)`.

**Data model (start here).**

```rust
// crates/reghidra-core/src/types/mod.rs
pub struct TypeArchive {
    /// Canonical name → function prototype. Matches what the demangler
    /// produces for stripped binaries and what an import name resolves
    /// to. For C++ the key is the mangled name.
    pub functions: HashMap<String, FunctionType>,
    /// Named type aliases, structs, unions, enums.
    pub types: HashMap<String, TypeDef>,
}

pub struct FunctionType {
    pub name: String,
    pub args: Vec<ArgType>,
    pub return_type: TypeRef,
    pub calling_convention: CallingConvention,
    /// Fixed arg count — this is the key that unblocks the arity-capping
    /// fix for the stack-arg collapser. Variadic funcs (printf) set the
    /// `is_variadic` flag; fixed-arity callers get precise collapse.
    pub is_variadic: bool,
}

pub enum TypeRef {
    Primitive(Primitive),          // int8/uint8/.../int64/float/double/bool/void
    Pointer(Box<TypeRef>),
    Array(Box<TypeRef>, u32),
    FunctionPointer(Box<FunctionType>),
    Named(String),                  // late-bound, resolved via archive.types
}
```

The existing `reghidra-decompile::ast::CType` is a simpler subset. The typing layer lives in `reghidra-core::types` because it's shared between analysis (arity capping) and decompile (display). When emitting into the decompiler's AST, convert via a small bridge function.

**Implementation order (concrete tasks).**

1. **`reghidra-core::types` scaffolding.** Define the `TypeArchive`, `FunctionType`, `TypeRef`, `CallingConvention` data model. Implement the postcard serialize/deserialize. Add a `load_bundled` function modeled after `bundled_sigs::collect_bundled_sigs` (auto-select archives by `BinaryInfo.format` + `BinaryInfo.arch`). Stub it out so downstream code compiles with empty archives.

2. **`tools/typegen` — Rust crate → archive extractor.** New workspace crate. Takes a crate name (`windows-sys`), a feature list (`Win32_Storage_FileSystem,Win32_System_Memory,...`), and an output path. Uses `syn::parse_file` to walk the expanded source of the target crate, visits `ItemForeignMod` / `ItemStruct` / `ItemType`, builds a `TypeArchive`, postcard-serializes to the output path. Run via `cargo xtask typegen` (add a simple xtask dispatcher) or directly with `cargo run -p reghidra-typegen --release`. Do NOT run at user-build time — this is a maintainer-run tool; the resulting archives are checked into `types/` just like FLIRT sigs are checked into `signatures/`.

3. **First archive: `windows-x64.rtarch`.** Pick a conservative feature set that covers the top ~200 Win32 APIs most commonly seen in malware/research targets: `Win32_Foundation`, `Win32_Storage_FileSystem`, `Win32_System_Memory`, `Win32_System_Threading`, `Win32_System_ProcessStatus`, `Win32_System_LibraryLoader`, `Win32_System_Registry`, `Win32_System_Diagnostics_Debug`, `Win32_Security`, `Win32_NetworkManagement_WindowsFirewall`, `Win32_Networking_WinSock`. Check in the resulting `.rtarch` file. Do NOT check in any of `windows-sys` source itself — typegen references it as a build dep.

4. **Auto-load at project init.** In `project.rs`, after binary load, call `types::load_bundled(&binary.info)` and store the resulting `Option<TypeArchive>` on the `Project`. Wire it into `DecompileContext` (new field `type_archive: Option<Arc<TypeArchive>>`).

5. **[LANDED PR 4 / PR 4c / PR 4d] Arity capping + typed casts at call sites, with cross-block pending propagation.**
   - **PR 4**: arity capping in `drain_pending_for_call` — when the callee has a known prototype, take the *last N* pending stack writes as args (where N = `prototype.args.len()`), leaving any earlier pushes in the pending queue so they survive for a later call. "Take last N, leave rest" — the cap limits but never discards. Variadic functions opt out.
   - **PR 4c**: typed casts at call sites via `annotate_call_args` — each arg gets wrapped in `Expr::Cast(declared_type, arg)` using `type_archive::type_ref_to_ctype` to bridge `TypeRef` → `CType`. This is the only place in PR 4c where types from the bundled archives become *visible* for the common case of a user `sub_XXXX` caller with no archive entry of its own. Renders e.g. `TerminateProcess((HANDLE)result, (uint32_t)0xc0000409)`, `SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0)`, `UnhandledExceptionFilter((EXCEPTION_POINTERS*)0x40a160)`.
   - **PR 4d**: cross-block pending propagation — the pending queue now flows across basic-block boundaries when the boundary is part of an *extended basic block* (linear chain where every consecutive pair is single-pred-single-succ). The chain rule is enforced in `inherit_pending` / `successor_will_inherit`. This fixes the canonical Win32 termination idiom where `push exit_code; call GetCurrentProcess; push eax; call TerminateProcess` is split across three basic blocks (the lifter starts a new block on every call) — the two pushes belong to different calls in different blocks, but cross-block tracking recovers the full arg list.
   - **PR 4d**: stack-pointer delta skip — `is_stack_pointer_delta` detects `rsp = rsp ± const` bookkeeping ops emitted by the lifter as part of every push/pop, and skips them before the pending-flush check. Without this the `IntSub` at the start of a `push` in a freshly-entered block would dump the inherited pending state immediately.
   - **Arg display also typed on VarDecl side**: `stackframe::apply_prototype_arg_types` pairs arg slots (`arg_8`, `arg_c`, ...) positionally with `prototype.args` when the function being decompiled has an archive entry, so the emitted `VarDecl`s carry the real type instead of `CType::Unknown(size)`. This only fires for archived functions (narrow set — functions that match by name). The PR 4c typed-cast-at-call-site path is the dominant source of visible types in practice.
   - **Retype-removes-cast invariant (DEFERRED to PR 5)**: the casts wrapped at call sites by `annotate_call_args` are *derived*, not authoritative — they exist only because the source expression's type is currently too weak to match the declared parameter type. When the PR 5 right-click "Set Type" UI lands, if a user retypes the source to be assignment-compatible with the declared parameter type, the cast should disappear. See the long-form doc comment on `annotate_call_args` in `expr_builder.rs` for the implementation sketch (thread a "source type context" through, use width + signedness + named-alias-via-archive resolution for the compatibility predicate — strict equality is too narrow because e.g. `uint32_t → DWORD` is already a no-op cast).

6. **[LANDED PR 4e] Typed signature line + CRT-via-POSIX fallback + MSVC underscore stripping.** Post-PR 4d audit on the PE fixture showed 0/102 FLIRT-named functions were hitting the archive. Two root causes:
   - **PE binaries only loaded `windows-*.rtarch`**, which is Win32 API surface only — MSVC CRT functions aren't in `windows-sys`. Added `"posix"` as a lower-precedence fallback stem for all PE arches in `archive_stems_for` (first-archive-wins ordering still has Win32 take precedence on collisions like `strlen`/`exit`).
   - **FLIRT sigs preserve MSVC leading-underscore decoration** (`_fclose`, `_printf`, `__exit`), while libc-sourced `posix.rtarch` stores bare names (`fclose`, `printf`, `exit`). Added a fallback in `DecompileContext::lookup_prototype` that retries the lookup after stripping one and then two leading underscores. Safe: Win32 APIs never start with `_`, mangled C++ starts with `?` or `@`.
   - **Signature line now uses the prototype.** `emit::emit_function` / `emit_function_annotated` now take an `Option<&FunctionType>` and call a new `format_signature` helper that renders `int32_t _fclose(FILE* file)`, `int32_t _printf(char* format, ...)`, etc. Variadic functions render with a trailing `, ...`. Archive-sourced arg names are used when present; otherwise positional `arg0`, `arg1`, ...
   - **Defensive `Type::` sanitizer in `type_ref_to_ctype`.** Early PR 3 typegen runs leaked Rust's `syn::Debug` format of `syn::Type::Never` (`Type::Never { bang_token: Not }`) into the `libc`-sourced archive as a `TypeRef::Named(...)` for functions declared `-> !` in Rust (e.g. `_exit`). Until those archives are regenerated (maintainer task, drift-check will catch it), the bridge recognizes names containing `Type::` or `{` and degrades to `CType::Void`. Without this the signature line rendered gibberish like `Type::Never { bang_token: Not } _exit(int32_t status)`.
   - **Result.** Hit rate went from 0/102 to 8/102 on FLIRT-named CRT functions in the PE fixture (`_fclose`, `_printf`, `_exit`, `__exit`, `__close`, plus a few others). The remaining 94 misses are Microsoft-internal CRT functions (`__SEH_prolog4`, `__EH4_CallFilterFunc`, `__ftbuf`, `__invoke_watson`, `__lockexit`, `__mtinit`, `__commit`, `__flushall`, etc.) that simply aren't in any open-source POSIX/libc archive — these are MSVC CRT implementation details with no public header declaration. Closing that gap needs either a dedicated CRT archive generated from Microsoft UCRT headers (licensing unclear), a hand-curated CRT sdb in the Rizin reference tree (GPLv3 — not bundleable), or PDB-overlay in PR 5 when the sibling `.pdb` is present.
   - **What's still missing on the VarDecl side for these hits.** The typed signature line works, but the function *body* still shows untyped locals (`var_0`, `var_1`) because MSVC SEH prolog functions don't use the canonical `push rbp; mov rbp, rsp` pattern — they jump straight into `__SEH_prolog4`. The tier-2 stackframe pass returns an empty `FrameLayout` for those, so `apply_prototype_arg_types` has nothing to type. Fixing this needs an MSVC-SEH-aware prologue recognizer in `stackframe.rs` (detect the `__SEH_prolog4(scope_table, local_size); ...` idiom and synthesize `arg_8`, `arg_c` slots from the prototype's arg list + standard x86-32 cdecl/stdcall stack offsets). Tracked for a follow-up.

6a. **[LANDED PR 4f] `ucrt.rtarch` — MSVC CRT archive sourced from libc's Windows tree.** Extends the libc walker to support Windows targets (`--target windows-x64` etc.): pivots `TypeCtx` to `LLP64` / `ILP32`, flips the `unix`/`windows` umbrella cfg to take the `windows` branch, and walks `src/windows/mod.rs` instead of `src/unix/`. Produces a 17 KB archive of 226 functions covering the public MSVC CRT surface (`commit`, `close`, `open`, `creat`, `dup`, `fclose`, `fopen`, `chdir`, `chmod`, `execve` and friends, `aligned_realloc`, `calloc`, etc.). Wired into PE stems as a middle-precedence layer (`windows-{arch}` → `ucrt` → `posix`). Also fixes a typegen leak at the source: the rust-ty walker now maps `Type::Never` (Rust's `!`, used by `extern fn _exit(...) -> !`) to `Primitive::Void` instead of falling through to the `print_type` debug-format catchall that was producing `Type::Never { bang_token: Not }` named-type entries in the libc archive. Drift-check workflow extended to regenerate and diff `ucrt.rtarch`. Hit rate on the PE fixture went from 8/102 → 9/102; the additional hit is `__commit` → `commit` via underscore stripping. **The remaining 93 misses are MSVC CRT implementation internals (`__SEH_prolog4`, `__EH4_*`, `__lockexit`, `__mtinit`, `__getptd`, ...) that aren't in libc's Windows tree at all** — Microsoft does not document or expose them through any public header that a binding crate can wrap. Closing that gap fundamentally requires either MS UCRT headers (licensing TBD), a hand-curated reference (Rizin's GPLv3 SDB is the most complete but not bundleable), or PDB-overlay (Phase 5c PR 5).

7. **Return-type propagation (still pending).** For call expressions in the decompile output where the target has a known prototype, propagate the return type back onto the LHS var of the assignment. `eax = CreateFileA(...)` becomes `HANDLE hFile = CreateFileA(...)` at the point of first assignment. Not yet implemented.

8. **PDB overlay (optional layer).** Add the `pdb` crate as a `reghidra-core` dep behind a feature flag (so macOS builds without Windows targets don't pay for it unnecessarily). When a project loads a PE binary whose `BinaryInfo.pdb_info` points to an existing `.pdb` sibling, parse it with `pdb::PDB::open`, walk each `S_GPROC32` record for the current function, consume its child `S_REGREL32`/`S_BPREL32`/`S_LOCAL` scope records, and populate `FrameLayout` slots directly. Override the tier-2 heuristic output with authoritative data. Type records come from the TPI stream — map `TypeIndex` via `pdb::TypeFinder` and convert to `TypeRef`.

9. **Right-click "Set Type" + slot subsumption.** In `context_menu::ContextAction`, add `SetType { slot_key: (FnEntry, Offset), new_type: TypeRef }`. In `stackframe::FrameLayout`, implement `retype_slot(offset, new_type)`: widen the slot to the new type's size, mark any other slots whose offset falls in `[offset, offset + new_size)` as `subsumed_by: Some(offset)`, and rewrite references to subsumed slots as `local_<base>[i]` or `local_<base>.field_N`. Subsumed slots are kept in a shadow table so undo/redo works cleanly. Persist retype decisions in the session file alongside `variable_names`.

**Gotchas to watch for.**
- `windows-sys` gates everything behind Cargo features. The typegen tool needs to enable the right feature set when invoking `cargo expand` (or walking the source) — otherwise most of the API surface is conditionally compiled out and `syn` won't see it.
- PDB loading is not cheap for large binaries. Cache parsed layouts on the `Project`, don't reparse per-function.
- The existing `FrameLayout` in `stackframe.rs` is currently returned and immediately discarded by `lib.rs::decompile` (the `_frame_layout` binding). Phase 5c needs to plumb this back into `DecompileContext` so typed decls can consume it. Consider moving `FrameLayout` to `reghidra-core` or making a stable public API on it.
- The `CType` enum in `reghidra-decompile::ast` is simpler than `reghidra-core::types::TypeRef`. When emitting typed var decls you'll need a bridge function that downgrades `TypeRef` → `CType` for display, or upgrade `CType` to carry a named-type reference.

**Where to verify things are working.**
- Test binary: `tests/fixtures/` — if a Windows PE with imports exists, use it. `CreateFileA`/`GetModuleHandleW`/etc. are the best canaries. If not, first task is to add a small Win32 PE fixture.
- Unit test the archive loader with a tiny hand-written archive.
- Integration test via `cargo test --workspace`: load a fixture, decompile a function that calls a known Win32 API, assert the rendered output contains the typed arg names.

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
- Unary operators on Binary/Ternary operands always get explicit parens so precedence stays correct (`-(x + y)`, never `-x + y`).
- No compound one-line statements — every body is a brace block.
- Block comments use `/* ... */`; line comments (`//`) only for annotations we explicitly emit.
- **Logical section separation via blank lines**, per the guide's "the body of the function should include blank lines to indicate logical sections (with at most one blank line separating each logical section)" rule. Implemented in `emit::emit_body_with_separators` which inserts a blank line between adjacent visible statements when `should_separate(prev, curr)` returns true. The transitions that trigger a separator are: VarDecl ↔ non-VarDecl boundary, before any `Label`, control-flow block (`if`/`while`/`Loop`) ↔ straight-line code boundary, after `Return` or `Goto`, and around `Comment` annotations. Two adjacent control-flow blocks are NOT separated. The pass runs recursively inside `then_body`/`else_body`/`while body`/`loop body` so nested separators work, and never produces leading/trailing blanks inside a brace block or two consecutive blanks anywhere. `SourceAddr` markers are skipped when picking the "previous visible" statement so they don't anchor a wrong decision.

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
- **Stack-arg collapsing** lives in `expr_builder::build_statements`, NOT in the lifter. It's a per-block walk that defers `Store { addr=stack_pointer }` into a `pending_stack_writes` queue and consumes it on the next `Call`/`CallInd` (in reverse order — first arg = last pushed). Any non-call instruction flushes the queue as plain `*(rsp) = x` assignments, EXCEPT stack-pointer delta bookkeeping (`rsp = rsp ± const`) emitted by the lifter as part of every push/pop — `is_stack_pointer_delta` detects these and skips them, otherwise the `IntSub` that opens a `push` would dump the pending queue before the `Store` half arrives. Arity capping (Phase 5c PR 4) caps via "take last N, leave rest" semantics so pre-positioned args for a later call survive an intervening 0-arg call. Cross-block propagation (Phase 5c PR 4d) extends the queue across extended-basic-block boundaries (single-pred/single-succ chain rule) so `push; call` sequences that straddle a block boundary still form a call arg list — see `inherit_pending` / `successor_will_inherit` in `expr_builder.rs`. Joins, branches, and back-edges all reset to an empty pending queue.
- **Variable renamer** (`varnames.rs`):
  - All sized aliases of an x86 GPR canonicalize via `canonical_reg_name` (eax/ax/al → rax). The `renames` map is keyed on canonical names so mixed-width accesses share one rename.
  - `is_known_register_name` is the gate that decides whether an unrecognized var should become a fresh `var_N` (it's a register) or be left alone (probably a function name, global, or already-renamed).
  - x86-32 mode is detected by a pre-pass (`scan_for_x86_32`) before `collect_vars` runs. When set, the SysV `argN` mapping for `rdi/rsi/rdx/rcx/r8/r9` is suppressed because x86-32 cdecl/stdcall pass everything on the stack.
  - `rsp/rbp/result/flags` are intentionally left visible; eliminating them needs stack-frame analysis.

## FLIRT notes
- Bundled `signatures/` tree contains both rizinorg/sigdb sigs (named like `VisualStudio2015.sig`, `ubuntu-libc6.sig`) and IDA-derived sigs (named like `vc32_14.sig`, `pe.sig`). `bundled_sigs::collect_bundled_sigs` orders IDA sigs first so they take precedence at apply time (first DB to match wins).
- IDA `.sig` files use bit `0x08` (`IDASIG_FUNCTION_UNRESOLVED_COLLISION`) in the optional pre-name attribute byte to mark collision placeholders that `sigmake` couldn't resolve. The placeholder name is typically `?`. `parse_module` tracks `is_collision` per public-name candidate and clears the module name if every candidate is a collision; `apply_signatures` already skips empty-name modules. Don't reintroduce naive name parsing that ignores the attribute byte.
- The 16-bit/DOS/OS-2/NetWare/NE/LE/Mach-O-startup sigs from the IDA pack are intentionally NOT bundled (we don't target those formats); see the classification logic that was used to add the 86 files for which file_types/app_types we accepted.
