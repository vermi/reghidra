# Reghidra — Project Instructions

## Overview
Reghidra is a Rust-based reverse engineering framework reimplementing Ghidra's core functionality with a modern, user-friendly interface. OS-agnostic, built with Rust + egui.

## Project Structure
```
reghidra/
├── Cargo.toml                          # workspace root
├── crates/
│   ├── reghidra-core/src/
│   │   ├── lib.rs                      # public API re-exports
│   │   ├── arch.rs                     # Architecture enum
│   │   ├── binary.rs                   # ELF/PE/Mach-O loader (goblin)
│   │   ├── demangle.rs                 # MSVC C++ + @/_stdcall decoration stripping
│   │   ├── disasm.rs                   # Disassembler (capstone)
│   │   ├── error.rs                    # CoreError
│   │   ├── project.rs                  # Project (ties everything together)
│   │   └── analysis/                   # mod, functions, cfg, xrefs, naming, flirt, bundled_sigs
│   ├── reghidra-ir/src/
│   │   ├── op.rs                       # IrOp enum (~30 opcodes), VarNode, VarSpace
│   │   ├── types.rs                    # IrInstruction, IrBlock, IrFunction
│   │   ├── optimize.rs                 # constant fold, copy prop, DCE
│   │   └── lifter/{mod,x86_64,arm64}.rs
│   ├── reghidra-decompile/src/
│   │   ├── lib.rs                      # decompile() entry point
│   │   ├── ast.rs                      # Expr/Stmt/CType AST
│   │   ├── expr_builder.rs             # IR ops → AST (+ g_dat_ rewrite, stack-arg collapse)
│   │   ├── stackframe.rs               # Frame detection, local_/arg_ slots, prologue cleanup
│   │   ├── structuring.rs              # CFG → if/else/while/goto
│   │   ├── varnames.rs                 # Register/temp renaming, canonical_reg_name
│   │   ├── types.rs                    # Varnode → CType inference (stub)
│   │   ├── type_archive/               # TypeArchive, FunctionType, TypeRef, postcard (de)ser
│   │   └── emit.rs                     # AST → C-like text (style + blank-line separators)
│   ├── reghidra-gui/src/
│   │   ├── main.rs, app.rs             # entry + eframe::App
│   │   ├── annotations.rs              # Comment/rename popup dialogs
│   │   ├── context_menu.rs             # Right-click context menu (symbol actions)
│   │   ├── palette.rs                  # Command palette (Cmd+K)
│   │   ├── syntax.rs                   # C lexer for decomp view per-token coloring
│   │   ├── theme.rs                    # Dark/light themes (Nord/Solarized)
│   │   ├── undo.rs                     # Undo/redo history (Action enum)
│   │   ├── help.rs                     # In-app help overlay
│   │   └── views/                      # disasm, decompile, hex, cfg, ir, xrefs, side_panel
│   └── reghidra-cli/                   # Headless CLI (clap subcommands, --json, sessions)
│       ├── src/main.rs                 # all subcommand defs + dispatchers
│       ├── tests/cli.rs                # end-to-end via CARGO_BIN_EXE_reghidra-cli
│       └── README.md                   # full usage walkthrough for AI agents / scripts
├── signatures/                         # Bundled FLIRT .sig (rizinorg/sigdb + IDA packs)
│   └── {elf,pe}/{arm,mips,sh,x86}/{32,64}/
├── types/                              # Bundled .rtarch type archives (Phase 5c)
└── tests/fixtures/                     # Test binaries
```

## Key Dependencies
- `goblin` (binary parsing), `capstone` (disasm), `egui`+`eframe` (GUI)
- `msvc-demangler` (wired via `reghidra-core::demangle`)
- `serde`+`serde_json` (session persistence), `flate2`, `include_dir` (bundled sigs/archives)
- `postcard` (type archive on-disk format), `syn`+`quote` (typegen tool only)
- Planned: `pdb` (deprioritized), `mlua` (Phase 6)

## Implementation Phases & Status

### Phase 1 — Foundation [DONE]
Workspace scaffold, ELF/PE/Mach-O loader, x86_64 + ARM64 disassembly, basic GUI shell.

### Phase 2 — Analysis Engine [DONE]
- Function detection: symbols + heuristic prologue/epilogue + call targets + gated tail-call jmps + MSVC hotpatch prologue. Two-pass: entry discovery → per-entry CFG walk stopping at rets, indirect branches, and other entries.
- PE metadata: x64 `.pdata`, Debug Directory CodeView RSDS (PDB GUID/age/path), Rich Header.
- CFG (interactive view), code+data xrefs (click-to-navigate, panel), string detection.
- **Mach-O import resolution** (`from_single_macho` in `binary.rs`): populates `import_addr_map` from goblin's `imports()` (`__got`/`__la_symbol_ptr` VAs) AND walks `__TEXT,__stubs` in 6-byte strides parsing `ff 25 disp32` to map stub_addr → import_name. Takes a stripped Mach-O fixture from "1 named fn" to "every direct `call stub_addr` resolves." Gap: register-indirect calls (`mov r15, [got]; call r15`) still emit `CallInd`; the resolver doesn't follow register dataflow.
- Xref annotations and function headers in disasm view.

### Phase 3 — IR + Lifting [DONE]
- RIR (~30 opcodes, varnodes), x86_64 + ARM64 lifters, optimization passes (constfold, copyprop, DCE, NOP removal), IR view in GUI.

### Phase 4 — Decompiler [DONE]
- Type inference (varnode size → C types), control flow structuring (if/else, while, goto fallback), expression builder, var naming heuristics, C-like renderer with flag/stack cleanup, decompile view.

### Phase 5 — UX [DONE]
- Click-to-navigate everywhere; inline annotations (comments/renames/bookmarks); fuzzy command palette (Cmd+K); dark/light themes; vim-like nav (j/k, n/N, gg/G, ;, r, x, d, 1-6); split/tabbed views (split default, Space toggles); undo/redo (Cmd+Z); right-click context menu; rename labels and decompile vars; session persistence.

### Phase 5a — In-App Documentation [DONE]
Help overlay (tabbed: Quick Start, Keyboard, Views, Workflow); F1/? shortcuts; menu + welcome screen + palette + status bar entry points.

### Phase 5b — Decompiler Quality [DONE]
- IDA FLIRT sig packs merged (86 added) into `signatures/`, IDA-precedence ordering at load time. Fixed `IDASIG_FUNCTION_UNRESOLVED_COLLISION` (0x08) so collision-`?` placeholders don't leak.
- PE IAT call resolution (`call [imm]` x86-32 + `call [rip+disp]` x86-64) lift to `IrOp::Call { target: iat_addr }`; `project::decompile` merges `binary.import_addr_map` into `function_names`.
- Double-deref bug fix: `parse_memory_expression` returns address-value varnodes (`Constant`/`Register`/temp), NOT `VarSpace::Memory` descriptors.
- `pop [mem]`/`push [mem]` regression fix via `read_operand`/`write_operand` helpers in x86_64 lifter.
- Stack-arg collapsing in `expr_builder::build_statements`: defer `Store{addr=esp/rsp/sp}` ops, attach to following Call as args (reversed for source order), flush as plain stack writes if interrupted.
- Variable rename canonicalization: sized aliases (rax/eax/ax/al → rax) share one rename via `canonical_reg_name`. `is_known_register_name` routes recognized GPRs through renamer. x86-32 detection pre-pass (`scan_for_x86_32`) suppresses argN mapping when 32-bit reg forms appear.
- **Tier-2 heuristic stack frame analysis** (`stackframe.rs`): runs between `structure::structure` and `varnames::rename_variables`. Detects `push rbp; mov rbp, rsp` (x86) and ARM64 equivalents (`mov x29, sp`, `add x29, sp, #N`) via `is_rbp`/`is_rsp`. Classifies `*(rbp ± k)` and via-temp accesses into `FrameLayout` keyed on signed offset, rewrites to IDA-style `local_<hex>`/`arg_<hex>` slot names (offset-keyed, NOT sequential, so retypes don't renumber siblings), drops prologue/epilogue bookkeeping and dead address temps, prepends `VarDecl`s. Offset 0 filtered (saved rbp). When no FP found but prototype known AND a `__SEH_prolog4`-style helper is called, fallback synthesizes arg slots from prototype at x86-32 cdecl offsets. Gaps: FPO builds without SEH-prolog get no rewrites (rsp-delta tracking deferred); ARM64 `stp ..., [sp,#-N]!` pre-index writeback unmodeled; slots default `CType::Unknown(size)` without prototype.
- Global data naming: bare `Load`/`Store` of constant addr ≥ `GLOBAL_DATA_MIN_ADDR` (0x1000) → `g_dat_<hex>` (or resolved name if in `function_names`). GUI tokenizer recognizes `g_dat_<hex>` as clickable + renamable.
- RMW memory destinations in `lift_binop`/`lift_xor`/`lift_inc_dec`/`lift_not`/`lift_neg` via `rmw_begin`/`rmw_end` helpers.
- `leave`/`pushf[d|q]`/`popf[d|q]` lifter intrinsics implemented.
- **MSVC C++ demangling for display** via `reghidra_core::demangle`. Mangled names stay canonical in storage/renames/xref keys; GUI views go through helper. Two flavors: `display_name` (full sig, used by decompile body + `function_names` call-target map) and `display_name_short` (NAME_ONLY, for sidebar/headers). `views/decompile.rs` reverse `name → addr` map uses `display_name`. `strip_msvc_decoration` handles `@name@N` (fastcall) and `_name@N` (stdcall); bare leading underscores left alone (legitimate on ELF). FLIRT `?` placeholder filter: `is_meaningful_sig_name` in `flirt.rs` gates `collect_matches` and apply.
- Blocky disassembly function header: 4-line block (rule, name, stats, rule) as separate `DisplayLine::FuncHeader{Rule,Name,Stats}` variants for fixed-row scrolling.
- Decompile output C-style compliance (UChicago guide). See "Decompile output style" below.
- Token-level syntax highlighting via `reghidra-gui/src/syntax.rs`. See "Decompile syntax highlighting" below.

### Phase 5c — Typing & debug info (IN PROGRESS)

**Goal.** Stack slots default to `CType::Unknown(size)`. Make them typed using bundled type archives (build-time extracted from Rust binding crates) and optional PDB overlay. Drives arity capping for stack-arg collapser, typed parameter display, return-type propagation, and a right-click "Set Type" UI.

**Naming vs typing precedence — DO NOT flatten into one pipeline.** A function has two independently-sourced attributes — its name and its type. Each has its own chain; typing keys off whatever name the naming chain produced.

- **Name precedence** (high → low): User rename → PE Import/Export → PDB → FLIRT → heuristic `sub_XXXX`.
- **Type precedence** (high → low): User retype → PDB → Type archive lookup (windows-sys/libc/ucrt/rizin, keyed by name) → `CType::Unknown(size)`.

`windows-sys` is NOT in the naming chain (it has prototypes, not byte patterns) and FLIRT is NOT in the typing chain (it produces names only). They compose: FLIRT names `memcpy`, then `posix.rtarch` types it. A practical opt: skip `apply_signatures` for functions whose `FunctionSource` is already `Import` (or `Pdb`).

**Architecture (as landed).**
```
reghidra/
├── tools/typegen/                          # maintainer-only, OUT-OF-WORKSPACE
│   └── src/main.rs                         # CLI: --source, --features, --arch, --os, --filter, --out
├── types/                                  # bundled .rtarch, include_dir!'d at compile time
│   ├── posix.rtarch                        # libc → Linux/macOS POSIX (~29 KB)
│   ├── windows-{x64,x86,arm64}.rtarch      # windows-sys → Win32 (~9 MB each)
│   ├── ucrt.rtarch                         # libc → Windows MSVC CRT (~17 KB, 226 fns)
│   ├── rizin-windows.rtarch                # rizin SDB Win32 headers (~570 KB, ~5350 fns)
│   └── rizin-libc.rtarch                   # rizin SDB libc/linux/macos (~18 KB, ~530 fns)
├── .github/workflows/typegen-regen.yml     # auto-regenerates archives on release/tag/dispatch
└── crates/
    ├── reghidra-decompile/src/type_archive/    # data model lives HERE (avoids cycle with -core)
    └── reghidra-core/src/project.rs            # archive_stems_for / load_type_archives
```

The data model lives in `reghidra-decompile::type_archive` (not `reghidra-core::types`) because `reghidra-core` already depends on `reghidra-decompile`. `BinaryInfo`-aware stem selection stays in `reghidra-core::project` as a wrapper around `type_archive::load_embedded(stem)`.

**Data model (`reghidra-decompile::type_archive`).**
```rust
pub struct TypeArchive {
    pub functions: HashMap<String, FunctionType>, // canonical name → prototype (mangled for C++)
    pub types: HashMap<String, TypeDef>,
}
pub struct FunctionType {
    pub name: String,
    pub args: Vec<ArgType>,
    pub return_type: TypeRef,
    pub calling_convention: CallingConvention,
    pub is_variadic: bool,                        // unblocks arity capping
}
pub enum TypeRef {
    Primitive(Primitive),                         // int8..int64, float, double, bool, void
    Pointer(Box<TypeRef>),
    Array(Box<TypeRef>, u32),
    FunctionPointer(Box<FunctionType>),
    Named(String),                                // late-bound via archive.types
}
```
`reghidra-decompile::ast::CType` is a simpler subset; bridge via `type_ref_to_ctype` when emitting.

**What has landed.**

- **PR 1+2 — Scaffolding.** `TypeArchive`, `FunctionType`, `TypeRef`, postcard ser/de, `load_embedded`. `FrameLayout` plumbed back through `DecompileContext` instead of being discarded. `BinaryInfo`-keyed stem dispatch in `project.rs`.
- **PR 3+3b+4f — Archives.** `posix.rtarch` (libc Linux/macOS), `windows-{x64,x86,arm64}.rtarch` (windows-sys Win32), `ucrt.rtarch` (libc src/windows tree, 226 fns covering public MSVC CRT). Typegen leak fix: rust-ty walker maps `Type::Never` (Rust `!`) to `Primitive::Void` instead of falling through to debug-format catchall.
- **PR 4+4c+4d — Arity capping + typed casts + cross-block pending propagation.**
  - `drain_pending_for_call` takes the *last N* pending stack writes when callee has known prototype. "Take last N, leave rest" semantics — caps but never discards. Variadic opts out.
  - `annotate_call_args` wraps each arg in `Expr::Cast(declared_type, arg)` via `type_ref_to_ctype`. Renders e.g. `TerminateProcess((HANDLE)result, (uint32_t)0xc0000409)`. **This is the dominant source of visible types** for `sub_XXXX` callers with no archive entry of their own.
  - Pending queue flows across basic-block boundaries when both sides are part of an *extended basic block* (linear single-pred/single-succ chain). Enforced in `inherit_pending`/`successor_will_inherit`. Fixes `push exit_code; call GetCurrentProcess; push eax; call TerminateProcess` (split across 3 blocks because lifter starts a new block on every call). Joins/branches/back-edges reset.
  - `is_stack_pointer_delta` detects `rsp = rsp ± const` bookkeeping ops and skips them so they don't dump pending state inside a freshly-entered block.
  - VarDecl-side typing: `stackframe::apply_prototype_arg_types` pairs arg slots (`arg_8`, `arg_c`, ...) with `prototype.args` for archived functions.
- **PR 4e — Typed signature line + CRT-via-POSIX fallback + MSVC underscore stripping.** `emit_function` takes `Option<&FunctionType>` and renders typed sig (`int32_t _fclose(FILE* file)`, variadic gets `, ...`). PE binaries also load `posix` as fallback (Win32 still wins on collisions). `lookup_prototype` retries with 1-2 leading underscores stripped (safe — Win32 APIs never start with `_`, mangled C++ starts with `?`/`@`). Defensive `Type::` sanitizer in `type_ref_to_ctype` (recognizes leaked syn debug format like `Type::Never { bang_token: Not }` and degrades to `Void`).
- **PR 4e — MSVC-SEH-aware prologue fallback in `stackframe.rs`.** When no `mov ebp, esp` AND prototype supplied AND body Calls a function matching `is_seh_prolog_name` (`__SEH_prolog4`, `_SEH_prolog4`, `__SEH_prolog4_GS`, `__EH_prolog`, `_EH_prolog`, with up to 2 leading underscores stripped before prefix check), takes fallback: sets `has_frame_pointer = true`, calls `synthesize_arg_slots_from_prototype` at x86-32 cdecl offsets (`arg_8`, `arg_c`, ... — stride is `max(4, type_size_round_up_to_4)`), populates each slot's `ctype` from prototype, prepends typed `VarDecl`s. Body code is NOT rewritten (no stable offset info from SEH4). x86-32 only.
- **PR 4 — Return-type propagation.** Two-step pass:
  1. `promote_call_for_return_type` in `expr_builder.rs`: when `IrOp::Call` target has known prototype with non-void return, emits `Stmt::Assign(Var("rax"), Call(..))` instead of bare `ExprStmt`. Renamer canonicalizes `rax`/`eax`/`ax`/`al`/ARM64 `x0` (offset 0 size 8 in shared `register_name`) to `result`.
  2. `type_call_returns` post-rename pass: walks structured body, on the *first* `Assign(Var(name), Call(Var(callee), ..))` per LHS whose callee resolves with non-void return, replaces with `VarDecl { name, ctype: type_ref_to_ctype(return_type), init: Some(Call) }`. Subsequent assigns to same LHS pass through. Walks recursively into `if`/`while`/`Loop` bodies.
  Wired in `lib.rs` as Step 5 between `varnames::rename_variables` and `emit::emit_function`. Renders `DWORD result = GetLastError(); ...; ExitProcess((uint32_t)result);`.
  Limitation: only the first call's return type is captured for `result`. If subsequent calls return a different type, second renders as `result = ...` reusing first's type — wrong but quiet. Right fix is per-call SSA-style local naming (`hFile = CreateFileA(...)`) needing dataflow we lack.
- **PR 4i — Rizin SDB type archives.** `rizin-windows.rtarch` (every `functions-windows*.sdb.txt`, ~5350 fns across 35 headers, ~570 KB) + `rizin-libc.rtarch` (libc/linux/macos SDBs, ~530 fns). New `--filter` arg to typegen (comma-separated prefix list, exact-match-or-`{prefix}_`/`{prefix}.` boundary). `archive_stems_for` chain: PE = `windows-{arch}` → `ucrt` → `posix` → `rizin-windows` → `rizin-libc`; ELF/Mach-O = ... → `posix` → `rizin-libc`. First-archive-wins, so authoritative binding-crate archives stay in charge. License: PR 4g relicensed Reghidra to GPL-3.0-or-later as the prerequisite for bundling Rizin GPLv3 SDB data.
- **PR 4i — `typegen-regen.yml` workflow** replaces the old byte-diff drift-check (deleted because host-toolchain differences produced spurious mismatches). Triggers on `release: published`, `push: tags: v*`, `workflow_dispatch`. Clones Rizin at pinned `RIZIN_REF` SHA, regenerates every archive, commits back to main as `github-actions[bot]`. Bumping the Rizin SHA is a one-line edit.
- **PR 5 — Right-click "Set Type" on local variables (minimum viable).** No slot subsumption (deferred).
  - Data model: `Project::variable_types: HashMap<(u64, String), String>` mirroring `variable_names`, keyed on `(func_entry, displayed_name)`. Empty string = clear override.
  - Session: `Session::variable_types: Vec<((u64, String), String)>` with `#[serde(default)]`.
  - Parser: `ast::parse_user_ctype` strips `const`/`volatile`/`restrict`/`struct`/`union`/`enum` qualifiers, parses trailing `*`s, recognizes primitives (`void`, `int`/`int32_t`, `uint32_t`/`DWORD`, `size_t`/`SIZE_T`, `char`, `short`, ...), falls through to `CType::Named(base)`. Empty → `None` (clear).
  - Application: `expr_builder::apply_user_variable_types` runs as Step 6 in `lib.rs::decompile` (after `type_call_returns`). Walks body, finds `VarDecl { name }` in `ctx.variable_types`, replaces `ctype`. No-op fast path when empty.
  - GUI: `ContextAction::SetVariableType`, "Set Type..." button next to "Rename Variable...", `AnnotationKind::SetVariableType` popup.
  - Undo/redo: `Action::SetVariableType { func_entry, displayed_name, old_type, new_type }`. Counted by `action_affects_decompile`.
  - Limitations: (a) no slot subsumption (retyping `arg_8` to `uint64_t` doesn't consume `arg_c`); (b) no type picker UI (free-form text); (c) doesn't propagate to call-arg/return uses — only the `VarDecl` displays the new type.
- **PR 6 — Loaded Data Sources panel.** `View → Loaded Data Sources...` opens a modal `egui::Window` listing every FLIRT db (bundled + user) and every loaded `TypeArchive` for the current binary, with name / kind / function-or-sig count / hits-on-current-binary count, and per-source enable/disable checkboxes. Closes the silent-magic gap that motivated the feedback memory: "wired correctly but no data" used to render identically to "wiring bug."
  - **Per-db FLIRT attribution.** New `Function::matched_signature_db: Option<String>` (set in `flirt::apply_signatures` to `db.header.name`) — the only way to credit signature matches back to a specific db once analysis has flattened them all into `FunctionSource::Signature`. Counted parallel to `bundled_dbs`/`user_dbs` in `recompute_hit_counts`.
  - **Type archive attribution.** `type_archive::which_archive_resolves(name, &archives)` mirrors `DecompileContext::lookup_prototype` precedence (including the one/two-underscore strip fallback) and returns the first-match index. Counted against the *enabled* archive list so disabling one source surfaces the precedence chain ("turn off `windows-x64`, watch `rizin-windows` light up").
  - **Toggle semantics.** FLIRT toggles call `Project::reanalyze_with_current_signatures()` (full re-analysis — renames bake in at analysis time). Type archive toggles only invalidate `decompile_cache` and recompute hit counts; the next decompile-view paint picks up the new effective set via `effective_type_archives()`. Both setters are no-ops when the new value matches the current one.
  - **State on `Project`.** `bundled_db_enabled`/`user_db_enabled`/`type_archive_enabled` (parallel `Vec<bool>`s) and `bundled_db_hits`/`user_db_hits`/`type_archive_hits` (parallel `Vec<usize>`s). NOT session-persisted in v1 — every project open resets to all-enabled.
  - **GUI.** `views/data_sources.rs::render_window()` is called once per frame from `app.rs` after the central panel; it no-ops when `data_sources_open` is false. Snapshots names/counts/enabled flags up front to avoid fighting the borrow checker over `&mut project` while iterating.
  - **Tests.** `crates/reghidra-core/tests/data_sources.rs` covers: nonzero archive hits on PE fixture; FLIRT hit totals match `Signature`-source count; toggling an archive zeros its hits and re-enable restores them; disabling all archives changes a typed signature line.
  - Stretch (deferred to follow-up): search box answering "which archive provides this function's prototype?".
- **PR 7 — Loaded Data Sources panel: enumerate-all + lazy load + tree view.** Three follow-ups to PR 6 driven by user feedback that the panel was lossy: it only listed the auto-loaded subset, hiding the existence of `windows-x64`/`windows-arm64` on a PE x86 binary and offering no opt-in path.
  - **Enumerate, don't load, to list.** New `type_archive::available_stems()` walks `TYPES_DIR` for every `.rtarch` stem without decoding any of them; new `bundled_sigs::available_sigs()` walks `SIGNATURES_DIR` recursively returning `(subdir, stem)` pairs. Both are file-listing operations against `include_dir`'s in-memory tree — effectively free. Stored on `Project` as `available_archive_stems: Vec<String>` and `available_bundled_sigs: Vec<bundled_sigs::AvailableSig>`. Set once at `Project::open` and never mutated.
  - **Lazy-load on toggle.** New `Project::load_type_archive_by_stem(stem) -> Option<usize>` calls `type_archive::load_embedded`, appends to `type_archives`/`type_archive_enabled`/`type_archive_hits` (always enabled), recomputes hit counts. Idempotent — returns existing index if already loaded. New `Project::load_bundled_sig(subdir, stem)` is the FLIRT equivalent and triggers a full re-analysis since FLIRT renames bake in at analysis time. Unchecking a loaded source keeps it parsed in memory (cheap, ~25 MB ceiling for the entire types tree); we don't drop on uncheck because the churn isn't worth it.
  - **GUI tree view for FLIRT.** `views/data_sources.rs::render_flirt_section` builds a `BTreeMap<subdir, Vec<row>>` from `available_bundled_sigs`, joining each row with `bundled_dbs` by stem to fill in loaded/enabled/sig-count/hits. Each subdir renders as an `egui::CollapsingHeader` with `(N/M loaded)` in the label; default-open when any row is loaded, default-closed for fully-opt-in subdirs (so the long Borland/Watcom/Delphi lists don't drown out the relevant ones). User-loaded sigs render in their own `user` group below the embedded tree.
  - **GUI flat table for type archives.** `render_type_archive_section` walks `available_archive_stems` (the canonical source) and joins each stem with `type_archives` by name. Unloaded rows show `—` for Functions and Hits and start unchecked.
  - **Action queue pattern.** Both render functions buffer toggle requests into a local `Vec<Action>` during the `egui::Grid::show` immutable borrow, then drain after the closure ends to perform the `&mut project` mutations. Replaces PR 6's snapshot-up-front pattern, which didn't compose with the lazy-load case (we need to call the `&mut self` setter in response to a checkbox click against an unloaded entry whose state isn't even in the snapshot vec).
  - **Tests.** Two new tests in `data_sources.rs`: `enumeration_lists_archives_not_auto_loaded` pins that `available_archive_stems` includes `windows-x64`/`windows-arm64` on the PE x86 fixture even though only `windows-x86` auto-loads; `lazy_load_type_archive_by_stem_appends_and_resolves` pins that `load_type_archive_by_stem` appends to all three parallel vecs, marks the new entry enabled, and is idempotent on a second call.
  - **Roadmap follow-up.** This PR makes intelligent FLIRT pre-selection (Phase 5c remaining work item #4) cleanly implementable: the panel's lazy-load path is the user's escape hatch when the heuristic guesses wrong. Until that lands the auto-load set is still "every sig in the format/arch subdir" — same as before — just now the wrong-toolchain ones are visibly *checked* instead of silently parsed.
- **PR 7 follow-ups — panel polish + identity fix.** Five fixes driven by user feedback on PR 7's first cut.
  - **Friendly library names in the FLIRT tree.** `flirt::parse_header` promoted to `pub` (header-only parse, no trie walk) and called at enumeration time in `bundled_sigs::walk_sigs`. `AvailableSig` now carries `library_name: Option<String>` + `n_functions: Option<u32>`. The panel renders the friendly name (`Visual Studio 2010 Professional`) with the file stem trailing in dim monospace — no more staring at `vc32_14` wondering what toolchain you're looking at.
  - **Status bar → modal.** The bottom status bar's signature count label is now a clickable `egui::Label` with `PointingHand` cursor and an "Open Loaded Data Sources" hover tooltip. Click sets `data_sources_open = true` via a deferred `let mut open_data_sources` local so the `&project` borrow inside the status bar closure doesn't collide with the `&mut self` mutation.
  - **`(subdir, stem)` identity across arches.** Before this fix, bundled FLIRT was joined on the stem alone, which collapsed `VisualStudio2017.sig` across `pe/x86/32`, `pe/arm/32`, and `pe/arm/64` into a single entry — disabling the ARM 32 row would silently disable ARM 64 and x86 32 too. Now every layer keys on the full (subdir, stem) pair: `BundledSig` carries `subdir: &'static str`, `bundled_sigs::load_bundled_signatures` writes `source_path = bundled:<subdir>/<stem>`, `Project::load_bundled_sig`'s idempotency check joins on the full source_path, and the panel's `loaded_by_key: HashMap<(String, String), usize>` is populated by `rsplit_once('/')`. Hit attribution via `Function::matched_signature_db` still works in practice because only the matching-arch sig produces non-zero matches.
  - **Cross-leaf column alignment via `ui.set_width`.** The 3-level tree had each leaf's `egui::Grid` sizing its columns to its own content, drifting 20+ pixels between adjacent 32-bit and 64-bit leaves. Fix: pre-measure max widths once across every FLIRT row using `ui.fonts(|f| f.layout_no_wrap(...))`, then wrap each cell in `ui.scope(|ui| { ui.set_width(widths.X); ... })`. `set_width` (both min AND max) is critical: `set_min_width` alone lets a `right_to_left` sub-layout grab `available_width()` from the ScrollArea and slip the trailing column under the scroll bar. Numeric cells additionally use `right_to_left` *inside* the bounded scope for proper digit hugging without overflowing.
  - **Session persistence for data source state.** `Session` gained `data_source_overrides: Vec<DataSourceOverride>`, `loaded_archive_stems: Vec<String>`, `loaded_bundled_sigs: Vec<(String, String)>`, and `loaded_user_sig_paths: Vec<PathBuf>` (all `#[serde(default)]` for forward compat). `Project::to_session()` / `apply_session()` extracted as the single source of truth, used by `save_session`, `load_session`, and `open_with_session`. Replay order: opt-in lazy loads (archives → bundled sigs → user sigs via `load_signatures`) → enable/disable overrides → one re-analysis (if any FLIRT toggle changed) or hit recompute. The user sig replay path closed a real data-loss bug the CLI test caught: before this fix, `reghidra-cli sources load-user-sig` would save the db into the session but the next CLI invocation would silently drop it because nothing knew to re-read the file.

### Phase 5d — Headless CLI [DONE]
Full subcommand-based `reghidra-cli` with feature parity for everything content/state-related the GUI exposes. Motivated by "AI agents and Python scripts need a way to drive reghidra without the GUI or a long-running daemon."

**Surface.** `clap` derive-based subcommands split into four groups:
  - **Inspection (read-only)**: `info`, `functions` (with `--source`/`--name`/`--limit`), `sections`, `strings` (with `--pattern`), `xrefs --to/--from`, `decompile`, `disasm` (defaults to entry point), `ir`, `cfg`, `find`.
  - **Data sources**: `sources list/flirt/archives/resolve/enable/disable/load-archive/load-sig/load-user-sig`. `--available` on `flirt`/`archives` enumerates embedded-but-unloaded entries (the CLI equivalent of the panel's lazy-load opt-in). `resolve NAME` calls `which_archive_resolves` against the effective archive set, mirroring the decompiler's lookup chain — agents use this to answer "why isn't this prototype typed?"
  - **Annotations**: `annotate comment/rename/rename-label/rename-var/retype/bookmark/unbookmark/list`.
  - **Sessions**: `session init/show/refresh`. Refresh re-runs analysis and re-applies overrides — useful when the pipeline changes under an existing session.

**Contract.** Documented in `crates/reghidra-cli/README.md`:
  - Every read command takes `--binary PATH` OR `--session FILE`. The session form replays data-source overrides + lazy loads via `Project::open_with_session`.
  - **Mutating commands require `--session` and error out if missing.** Silent drops are worse than no parity.
  - Every read command supports `--json`. JSON shapes are pinned by the tests in `crates/reghidra-cli/tests/cli.rs` — adding fields is non-breaking, renaming/removing requires a CLI version bump.
  - Addresses accept `0x` hex or decimal via `parse_address`.

**Tests.** `crates/reghidra-cli/tests/cli.rs` runs `CARGO_BIN_EXE_reghidra-cli` as a subprocess for every subcommand — 25 tests covering the full surface. Every `annotate` subcommand has its own round-trip test (`annotate_comment_round_trips`, `annotate_rename_label_round_trips`, `annotate_rename_var_round_trips`, `annotate_retype_round_trips`, `annotate_bookmark_and_unbookmark`), every `sources` mutation kind has its own toggle test (`sources_enable_disable_bundled_round_trips`, `sources_load_archive_persists`, `sources_load_sig_persists_unloaded_subdir`, `sources_load_user_sig_and_toggle`). `session_refresh_preserves_overrides` verifies the session round-trip via `session refresh`. `mutating_commands_require_session` verifies the error-out contract.

**Session persistence for data sources** lives in the PR 7 follow-ups section above and is the core enabler — without persisted overrides, a CLI mutation would vanish on exit and the feature would be pointless.

**Caveats.** Each invocation re-opens and re-analyzes the binary. For iterative workflows against the same binary this is 3-10 seconds of wasted work per call. The deferred `reghidra-cli serve` daemon (Phase 6-adjacent roadmap) with JSON-RPC over stdio is the follow-up if iteration becomes the bottleneck.

**Hit-rate state.** On `pe-mingw32-strip.exe` (the current PE fixture, vendored from `JonathanSalwan/binary-samples`): 130 type archive hits total (windows-x86: 48, ucrt: 72, posix: 5, rizin-libc: 5) and 163 FLIRT matches. The MSVC CRT internals gap (`__SEH_prolog4`, `__EH4_*`, `__lockexit`, `__mtinit`, `__getptd`, `__fclose_nolock`, ...) remains unresolved across windows-sys, libc src/windows, libc src/unix, AND Rizin SDB — fundamentally needs licensable MS UCRT headers or PDB overlay.

**Gotchas to watch for.**
- `windows-sys` gates everything behind Cargo features. Typegen must enable the right feature set or `syn` won't see most APIs.
- `FrameLayout` is now plumbed back through `DecompileContext`; don't regress to discarding it.
- `CType` (decompile AST) is a simpler subset of `TypeRef`. Use `type_ref_to_ctype` to bridge.

**Where to verify.** `tests/fixtures/pe-mingw32-strip.exe` is the primary PE fixture (vendored from `JonathanSalwan/binary-samples` — see `tests/fixtures/SOURCES.md`); `_realloc`/`_srand` are the FLIRT-CRT canaries that exercise the typed-signature path. Unit tests in `reghidra-decompile::type_archive::tests`. End-to-end in `crates/reghidra-core/tests/rizin_visibility.rs` (asserts archives loaded, `EnumChildWindows` is resolvable *via the archive contents themselves* — independent of which fixture is loaded — and `__fclose_nolock` is intentionally unresolvable as a negative canary pinning the documented gap; invert it the day a UCRT-internals source lands).

**Remaining Phase 5c work — priorities.** Target workload is PE-heavy with some ELF/Mach-O; ARM is out of scope.

1. **Type system follow-ups (one PR).**
   - **Slot subsumption.** Retyping `arg_8` to `uint64_t` should consume `arg_c` on x86-32. Widening pass in `FrameLayout::retype_slot` walks siblings within `[offset, offset+new_size)`, marks subsumed (shadow table for undo), rewrites references.
   - **User-retype flow-through to call-site casts.** PR 4c's `annotate_call_args` wraps unconditionally; user retype doesn't reach it. Thread a "source type context" through and skip cast when assignment-compatible (width + signedness + named-alias resolution via archive `types`). Implementation sketch lives in a doc comment on `annotate_call_args`.
   - **Type picker UI.** Replace free-form text with dropdown from loaded archives' `TypeRef::Named` set + primitives.
2. **Mach-O symbol coverage** (when a real Mach-O target appears):
   - ObjC metadata (`__objc_classlist`/`__objc_protolist`/`__objc_selrefs`) for selector names.
   - macOS-specific FLIRT pack (libsystem, not glibc — current fallback maps Mach-O x86_64 → elf/x86/64).
   - `LC_FUNCTION_STARTS` consumption as additional entry source.
3. **Loaded Data Sources panel — search box stretch.** PR 6 shipped the panel without the search box from the original spec. Add a text input that takes a function name and answers "which db/archive in the chain owns this?" using `which_archive_resolves` (already exists) plus an analogous helper for FLIRT hit attribution. Useful when staring at a wall of `__SEH_prolog4`-style misses to know which data source *would* have answered if it carried the symbol.
4. **Intelligent FLIRT pre-selection.** `bundled_sigs::collect_bundled_sigs` currently loads *every* `.sig` file in the format/arch subdir unconditionally — on a PE x86 binary that's ~30 sigs spanning Borland, Watcom, MSVC, MinGW, Delphi/BCB regardless of which toolchain actually built the binary. FLIRT pattern matching makes wrong-toolchain sigs harmless at the data layer (they just don't match), but it wastes parse time, pollutes the panel, and clouds the precedence story. A smart selection should key off `BinaryInfo` signals: PE Rich Header `@comp.id` records (exact MSVC version), PE imports (`msvcr*.dll` / `vcruntime140.dll` / `ucrtbase.dll` / `libgcc_s_*.dll`), ELF `.note.ABI-tag` and `DT_NEEDED libc.so.6` vs `ld-musl-*`, Mach-O `LC_LOAD_DYLIB` of `libSystem.B.dylib`. The Loaded Data Sources panel's lazy-load opt-in (PR 7) is the natural escape hatch when the heuristic is wrong: auto-load the strong-signal sigs, leave the rest available-but-unchecked. Implementation lives in `bundled_sigs::auto_load_subdirs` (or a per-sig predicate replacing `sig_subdirs`'s blanket enumeration).
5. **ARM64 polish — deprioritized.** `stp`/`ldp` pre-index writeback unmodeled; no ARM64-specific FLIRT. Park until needed.
6. **PDB overlay — deprioritized.** Add `pdb` crate as `reghidra-core` dep behind feature flag; on PE load with sibling `.pdb`, parse `S_GPROC32`/`S_REGREL32`/`S_BPREL32`/`S_LOCAL` and populate `FrameLayout` directly, override tier-2 heuristic. TPI stream for type records via `pdb::TypeFinder`. Cache parsed layouts on `Project`. Revisit when a target actually ships a PDB.

### Phase 6 — Extensibility + Scripting
- [ ] Lua scripting API
- [ ] Rust trait-based plugin system
- [ ] `reghidra-cli serve` daemon (JSON-RPC over stdio) — avoids re-analyzing the binary on every CLI call for iterative AI-agent workflows

## Build & Packaging
- Workspace version lives in `Cargo.toml` under `[workspace.package]` — bump once, all crates inherit.
- macOS .app bundle: `./scripts/bundle-macos.sh` (`--debug` for debug); outputs `target/Reghidra.app`.
- Release builds hide the Windows console via `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]` in `reghidra-gui/src/main.rs`; debug builds keep it.

## Conventions
- Workspace crates communicate via public APIs in each crate's `lib.rs`.
- `thiserror` for library errors, `anyhow` in CLI/GUI.
- Public APIs have doc comments. Test with real binaries in `tests/fixtures/`.
- Never mention AI tools in commit messages or code comments.

## CLI parity rule
Anything the GUI can show or change about a binary's analysis state must have a `reghidra-cli` equivalent. The CLI is the contract for AI agents and Python scripts; if a feature exists only in egui, it doesn't exist as far as automation is concerned. Specifically:
- New `Project` field exposed by the GUI? Add a corresponding CLI accessor (read), and if the GUI lets the user toggle it, add a `sources`/`annotate` subcommand to mutate it.
- Mutating CLI commands MUST require `--session <FILE>` and persist via `Project::save_session`. A mutation that vanishes on exit is worse than no mutation.
- Every mutation must round-trip through `Session` serde — extend `Session` (with `#[serde(default)]` on new fields for forward compat) and update `Project::to_session` / `apply_session`.
- Read commands take either `--binary` OR `--session`; the session form replays data-source overrides via `Project::open_with_session`.
- All read commands support `--json`. The shape is the contract — adding fields is non-breaking, renaming/removing fields requires a CLI version bump. The integration tests in `crates/reghidra-cli/tests/cli.rs` pin the shape.
- Update `crates/reghidra-cli/README.md` when adding a subcommand. The README is what the AI agent reads when it gets confused.

## Decompile output style
Follows the UChicago C style guide (https://uchicago-cs.github.io/student-resource-guide/style-guide/c.html):
- 4-space indentation (no tabs); K&R brace style; empty params are `(void)`, not `()`.
- Space after control keywords, around binary operators; no space around unary `*`/`&`/`.`/`->` (parens stripped around simple deref/addrof operands via `needs_no_deref_parens` in `emit.rs`).
- Unary on Binary/Ternary operands always gets explicit parens (`-(x + y)`, never `-x + y`).
- No compound one-line statements; every body is a brace block.
- Block comments `/* ... */`; line comments `//` only for explicit annotations.
- **Logical section blank lines** via `emit::emit_body_with_separators` + `should_separate`. Triggers: VarDecl↔body, before `Label`, control-flow↔straight-line, after `Return`/`Goto`, around `Comment`. Two adjacent control-flow blocks NOT separated. Recursive into nested bodies. Never leading/trailing blanks inside a brace block; never two consecutive blanks. `SourceAddr` markers skipped when picking "previous visible".

## Decompile syntax highlighting
- **Token-level**, not per-line. `reghidra-gui/src/syntax.rs` is the C lexer; every rendered line is split into `SyntaxKind` spans (Keyword, Type, Number, String, Operator, Punctuation, Comment, Return, Goto, Identifier, Whitespace) and each span is painted with the theme's matching color. Do not regress to per-line colorizing.
- Render path: `render_interactive_line` → `emit_syntax_spans` in `views/decompile.rs`. The clickable-token pass (`tokenize_line`) overlays on top so calls/labels/hex/var refs stay interactive with their own colors.
- Dark mode is Nord-inspired (Frost teal types, Aurora purple keywords, Aurora orange numbers, Aurora green strings, Snow Storm operators/default, Polar Night gray comments). Light mode is Solarized equivalents. When adding a `SyntaxKind`, update both `Theme::dark`/`Theme::light` + `decomp_color`, and extend the sorted `syntax::CONTROL_KEYWORDS` / `syntax::C_TYPE_KEYWORDS` (the type table includes stdint, common Win32 aliases — HANDLE/HWND/DWORD/LPCSTR — and `unkN` defaults).

## Analysis pipeline notes
- `functions::detect_functions` is two-pass: (1) entry discovery from all sources (binary entry, symbols, call targets, gated tail-call jmps, prologues, PE `.pdata`, Guard CF), (2) per-entry CFG reachability via `cfg::build_cfg_from_entry` stopping at rets, indirect branches, other entries. Function size/instruction count come from `ControlFlowGraph::extent()` — do NOT fall back to linear walks. CFGs built once and reused by xrefs/IR lifting.
- New entry source? Feed it into `collect_extra_entries` in `analysis.rs` with a `FunctionSource` variant, NOT into `detect_functions` directly.
- PE-specific metadata lives on `LoadedBinary` (`pdata_function_starts`, `guard_cf_function_starts`) and `BinaryInfo` (`pdb_info`, `rich_header`). Guard CF parser stubbed; Load Config Directory decoder is a follow-up.

## Lifter / decompiler notes
- **VarNode address vs value distinction.** `parse_memory_expression` returns a varnode whose *value is the effective address*, not a `VarSpace::Memory` descriptor. Callers pass it as `Store.addr`/`Load.addr`, and the expression builder's single `Expr::Deref` wrap produces correct C. Do NOT reintroduce `VarSpace::Memory` flowing out of operand parsing — it caused a double-deref bug (`*(*(0x40dfd8))`).
- **Memory-destination ops.** x86 has RMW forms (`mov [m], r`, `add [m], r`, `inc [m]`, `pop [m]`). Use `read_operand`/`write_operand` helpers in `x86_64.rs`; `parse_operand` is fine for non-memory operands and address-itself cases (jmp/call targets). Only `lift_mov`/`lift_push`/`lift_pop` use the helpers; binops/inc/dec are still on the old path with a latent bug for memory destinations.
- **IAT call resolution.** x86-32 `call [imm]` and x86-64 `call [rip+disp]` lift to `IrOp::Call { target: iat_slot_addr }`, not `CallInd`. `project::decompile` merges `binary.import_addr_map` into `DecompileContext.function_names` keyed by IAT slot. Register-indirect (`call rax`, `call [rbx+8]`) still emits `CallInd`.
- **Stack-arg collapsing** lives in `expr_builder::build_statements`, NOT the lifter. Per-block walk defers `Store{addr=stack_pointer}` into `pending_stack_writes`, consumes on next `Call`/`CallInd` (reversed). Non-call instructions flush as plain `*(rsp) = x`, EXCEPT `is_stack_pointer_delta` (`rsp = rsp ± const` bookkeeping from push/pop), otherwise the `IntSub` opening a `push` would dump pending before the `Store` half arrives. Arity capping (PR 4) caps via "take last N, leave rest". Cross-block propagation (PR 4d) extends across extended-basic-block boundaries (single-pred/single-succ chain; see `inherit_pending`/`successor_will_inherit`). Joins/branches/back-edges reset.
- **Variable renamer (`varnames.rs`).**
  - All sized x86 GPR aliases canonicalize via `canonical_reg_name` (eax/ax/al → rax). `renames` keyed on canonical names.
  - `is_known_register_name` gates whether an unrecognized var becomes `var_N` (it's a register) or is left alone (function name, global, already-renamed).
  - x86-32 detected by `scan_for_x86_32` pre-pass before `collect_vars`; suppresses SysV `argN` mapping for `rdi/rsi/rdx/rcx/r8/r9` (cdecl/stdcall pass on stack).
  - `rsp/rbp/result/flags` intentionally visible; eliminating them needs stack-frame analysis.

## FLIRT notes
- `signatures/` contains both rizinorg/sigdb sigs (`VisualStudio2015.sig`, `ubuntu-libc6.sig`) and IDA-derived sigs (`vc32_14.sig`, `pe.sig`). `bundled_sigs::collect_bundled_sigs` orders IDA first so they win at apply time.
- IDA `.sig` files use bit `0x08` (`IDASIG_FUNCTION_UNRESOLVED_COLLISION`) in the optional pre-name attribute byte for collision placeholders `sigmake` couldn't resolve (typically `?`). `parse_module` tracks `is_collision` per public-name candidate and clears the module name if every candidate is a collision; `apply_signatures` skips empty-name modules. Don't reintroduce naive name parsing that ignores the attribute byte.
- 16-bit/DOS/OS-2/NetWare/NE/LE/Mach-O-startup sigs from the IDA pack are intentionally NOT bundled (we don't target those formats).
- **Per-db hit attribution.** `apply_signatures` stamps `Function::matched_signature_db = Some(db.header.name)` on every match so the Loaded Data Sources panel can credit hits back to a specific db. The `Signature` `FunctionSource` flattens which db won; the new field is the only path back. Don't drop the field on a future cleanup pass — `Project::recompute_hit_counts` walks it.
