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
│   │   └── views/                      # disasm, decompile, hex, cfg, ir, xrefs, side_panel, data_sources
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
- `undname` (MSVC C++ demangling via `reghidra-core::demangle`; Rust port of LLVM's MicrosoftDemangle, closer to real `undname.dll` output)
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
- **Mach-O import resolution** (`from_single_macho` in `binary.rs`): populates `import_addr_map` from goblin's `imports()` (`__got`/`__la_symbol_ptr` VAs) AND walks `__TEXT,__stubs` in 6-byte strides parsing `ff 25 disp32` to map stub_addr → import_name. Gap: register-indirect calls (`mov r15, [got]; call r15`) still emit `CallInd`; the resolver doesn't follow register dataflow.
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
- IDA FLIRT sig packs merged (86 added) into `signatures/`, IDA-precedence ordering. `IDASIG_FUNCTION_UNRESOLVED_COLLISION` (0x08) gates collision-`?` placeholders so they don't leak.
- PE IAT call resolution: x86-32 `call [imm]` and x86-64 `call [rip+disp]` lift to `IrOp::Call { target: iat_slot_addr }`; `project::decompile` merges `binary.import_addr_map` into `function_names` keyed by IAT slot. Register-indirect (`call rax`) still emits `CallInd`.
- Double-deref bug fix: `parse_memory_expression` returns address-value varnodes, NOT `VarSpace::Memory` descriptors. See "Lifter / decompiler notes" below.
- `pop [mem]`/`push [mem]` regression fix via `read_operand`/`write_operand` helpers in x86_64 lifter.
- **Stack-arg collapsing** in `expr_builder::build_statements`: defer `Store{addr=esp/rsp/sp}`, attach to following Call as args (reversed for source order), flush as plain stack writes if interrupted. `is_stack_pointer_delta` skips `rsp = rsp ± const` bookkeeping so push/pop sequences don't dump pending state prematurely.
- **Variable rename canonicalization**: sized aliases (rax/eax/ax/al → rax) share one rename via `canonical_reg_name`. `is_known_register_name` routes recognized GPRs through renamer. x86-32 detection pre-pass (`scan_for_x86_32`) suppresses argN mapping when 32-bit reg forms appear.
- **Tier-2 heuristic stack frame analysis** (`stackframe.rs`): runs between `structure::structure` and `varnames::rename_variables`. Detects `push rbp; mov rbp, rsp` (x86) and ARM64 `mov x29, sp` via `is_rbp`/`is_rsp`. Rewrites `*(rbp ± k)` accesses into IDA-style `local_<hex>`/`arg_<hex>` slots keyed on signed offset (NOT sequential, so retypes don't renumber siblings). Drops prologue/epilogue bookkeeping. Offset 0 filtered (saved rbp). **MSVC-SEH-aware fallback**: when no `mov ebp, esp` AND prototype supplied AND body Calls a `__SEH_prolog4`-style helper, synthesizes arg slots from prototype at x86-32 cdecl offsets. Gaps: FPO builds without SEH-prolog get no rewrites; ARM64 `stp ..., [sp,#-N]!` pre-index writeback unmodeled.
- Global data naming: bare `Load`/`Store` of constant addr ≥ `GLOBAL_DATA_MIN_ADDR` (0x1000) → `g_dat_<hex>`. GUI tokenizer recognizes it as clickable + renamable.
- RMW memory destinations in `lift_binop`/`lift_xor`/`lift_inc_dec`/`lift_not`/`lift_neg` via `rmw_begin`/`rmw_end` helpers.
- `leave`/`pushf[d|q]`/`popf[d|q]` lifter intrinsics.
- **MSVC C++ demangling for display** via `reghidra_core::demangle`. Mangled names stay canonical in storage/renames/xref keys; GUI views go through `display_name` (full sig) / `display_name_short` (NAME_ONLY). `strip_msvc_decoration` handles `@name@N` (fastcall) and `_name@N` (stdcall); bare leading underscores left alone (legitimate on ELF). `views/decompile.rs` reverse `name → addr` map uses `display_name`. FLIRT `?` placeholder filter: `is_meaningful_sig_name` in `flirt.rs`.
- Blocky disassembly function header: 4-line block (rule, name, stats, rule) as separate `DisplayLine::FuncHeader{Rule,Name,Stats}` variants for fixed-row scrolling.
- Decompile output C-style compliance (UChicago guide). See "Decompile output style" below.
- Token-level syntax highlighting via `reghidra-gui/src/syntax.rs`. See "Decompile syntax highlighting" below.

### Phase 5c — Typing & debug info [DONE]

**Goal.** Stack slots default to `CType::Unknown(size)`. Make them typed using bundled type archives (build-time extracted from Rust binding crates) and optional PDB overlay. Drives arity capping, typed parameter display, return-type propagation, and a right-click "Set Type" UI.

**Naming vs typing precedence — DO NOT flatten into one pipeline.** A function has two independently-sourced attributes — its name and its type. Each has its own chain; typing keys off whatever name the naming chain produced.

- **Name precedence** (high → low): User rename → PE Import/Export → PDB → FLIRT → heuristic `sub_XXXX`.
- **Type precedence** (high → low): User retype → PDB → Type archive lookup (windows-sys/libc/ucrt/rizin, keyed by name) → `CType::Unknown(size)`.

`windows-sys` is NOT in the naming chain (it has prototypes, not byte patterns) and FLIRT is NOT in the typing chain (it produces names only). They compose: FLIRT names `memcpy`, then `posix.rtarch` types it.

**Architecture.**
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

The data model lives in `reghidra-decompile::type_archive` (not `reghidra-core::types`) because `reghidra-core` already depends on `reghidra-decompile`. `BinaryInfo`-aware stem selection stays in `reghidra-core::project`.

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
    Primitive(Primitive), Pointer(Box<TypeRef>), Array(Box<TypeRef>, u32),
    FunctionPointer(Box<FunctionType>), Named(String),  // late-bound via archive.types
}
```
`reghidra-decompile::ast::CType` is a simpler subset; bridge via `type_ref_to_ctype`.

**What has landed (summary — git history has the play-by-play).**

- **Bundled archives** (`types/*.rtarch`, postcard-serialized, `include_dir!`'d). `archive_stems_for` chain: PE = `windows-{arch}` → `ucrt` → `posix` → `rizin-windows` → `rizin-libc`; ELF/Mach-O = ... → `posix` → `rizin-libc`. First-archive-wins. Auto-regenerated by `.github/workflows/typegen-regen.yml` on release. Reghidra is GPL-3.0-or-later as a prerequisite for bundling Rizin GPLv3 SDB data.
- **Arity capping + typed call-site casts.** `drain_pending_for_call` takes the *last N* pending stack writes when callee has known prototype (variadic opts out — caps but never discards). `annotate_call_args` wraps each arg in `Expr::Cast(declared_type, arg)`. Renders e.g. `TerminateProcess((HANDLE)result, (uint32_t)0xc0000409)`. **This is the dominant source of visible types** for `sub_XXXX` callers with no archive entry of their own. Pending queue flows across extended-basic-block boundaries (single-pred/single-succ chain; see `inherit_pending`/`successor_will_inherit`). Joins/branches/back-edges reset.
- **Typed signature line** (`emit_function` takes `Option<&FunctionType>`): `int32_t _fclose(FILE* file)`, variadic gets `, ...`. PE binaries load `posix` as fallback (Win32 wins on collisions). `lookup_prototype` retries with 1-2 leading underscores stripped. Defensive `Type::` sanitizer in `type_ref_to_ctype` catches leaked syn debug format (`Type::Never { ... }` → `Void`).
- **Return-type propagation.** Two-step: (1) `promote_call_for_return_type` emits `Assign(Var("rax"), Call(..))` when callee has non-void return; renamer canonicalizes rax/eax/ax/al/ARM64 x0 to `result`. (2) `type_call_returns` post-rename pass replaces the *first* `Assign(Var(name), Call(...))` per LHS with `VarDecl { name, ctype, init: Some(Call) }`. Renders `DWORD result = GetLastError(); ...; ExitProcess((uint32_t)result);`. Limitation: only the first call's return type is captured for `result` — per-call SSA naming (`hFile = CreateFileA(...)`) is a follow-up.
- **Set Type UI.** `Project::variable_types: HashMap<(u64, String), String>` keyed on `(func_entry, displayed_name)`. Session-persisted. Parser `ast::parse_user_ctype` strips qualifiers, parses trailing `*`s, recognizes primitives + Win32 aliases, falls through to `CType::Named(base)`. Applied in `expr_builder::apply_user_variable_types`. "Set Type..." popup has an `egui::ComboBox` populated from `Project::known_type_names()` (primitives + Win32 aliases + every loaded archive's `TypeDef` keys) above the free-form `TextEdit`. GUI reaches `parse_user_ctype` / `CType` via the `reghidra_core::ast` re-export (no direct dep on `reghidra-decompile`).
- **Slot subsumption.** `FrameLayout.subsumed_by: BTreeMap<i64, i64>` (child offset → parent) plus `retype_slot(offset, new_ctype, new_size) -> Vec<i64>` walks siblings in `[offset+old_size, offset+new_size)` and marks them subsumed when widened. Width resolution via `type_archive::ctype_size_bytes` which follows alias chains. Unknown widths fall back to type-only retype with no subsumption. Children stay in `slots` for undoability — only `prepend_var_decls` and `apply_user_variable_types` filter them at emit time.
- **Cast strip post-pass** (`expr_builder::strip_compatible_call_casts`): walks every `Expr::Call`, builds `local_types` from surviving `VarDecl`s, unwraps any `Cast(target, Var(name))` whose source type is assignment-compatible with `target` via `type_archive::is_assignment_compatible` (named-alias resolution, same-width/same-signedness matching, `Unknown(n)` wildcards, pointer recursion). Conservative on `IntLit` sources — literal casts like `(DWORD)0xc0000409` keep their cast for semantic intent. Known limitation: lifter inserts an intermediate register copy between slot read and `push`, so call sites reference `result`/`var_N` instead of `arg_8`; strip pass can't follow the one-step copy. `tests/cast_strip.rs::matching_retype_through_lifter_intermediate_keeps_cast_pinned_limitation` pins the behavior.
- **Loaded Data Sources panel** (`View → Loaded Data Sources...`, `views/data_sources.rs`): lists every FLIRT db + loaded `TypeArchive` with per-source enable/disable checkboxes. `Function::matched_signature_db` credits hits back to a specific db. `type_archive::which_archive_resolves(name, &archives)` attributes type hits, mirroring `DecompileContext::lookup_prototype` precedence. FLIRT toggles trigger re-analysis (`Project::reanalyze_with_current_signatures`); type archive toggles only invalidate `decompile_cache` + recompute hits. Panel uses an **action-queue pattern**: buffer toggles during the `egui::Grid::show` immutable borrow, drain after the closure to perform `&mut project` mutations.
- **Enumerate-all + lazy-load + tree view.** `type_archive::available_stems()` and `bundled_sigs::available_sigs()` walk the embedded tree without decoding (file-listing only). Stored on `Project` as `available_archive_stems` / `available_bundled_sigs`. Set once at `Project::open`. `Project::load_type_archive_by_stem(stem)` and `Project::load_bundled_sig(subdir, stem)` are the lazy-load paths — both idempotent, the FLIRT form triggers full re-analysis. Panel's FLIRT tree is 3-level nested (`format → arch → bits`) with per-leaf `egui::Grid` and pre-measured column widths for cross-leaf alignment. Rows render friendly library names (`Visual Studio 2010 Professional`) from `flirt::parse_header` at enumeration time with the file stem trailing in dim monospace.
- **`(subdir, stem)` identity across arches.** Bundled FLIRT joins on the full (subdir, stem) pair — stem-alone collapsed `VisualStudio2017.sig` across `pe/x86/32`, `pe/arm/32`, `pe/arm/64` into one entry. Now `BundledSig` carries `subdir: &'static str`, `load_bundled_signatures` writes `source_path = bundled:<subdir>/<stem>`, idempotency checks join on full `source_path`, panel's `loaded_by_key: HashMap<(String, String), usize>` is populated by `rsplit_once('/')`.
- **Session persistence for data sources.** `Session` gained `data_source_overrides`, `loaded_archive_stems`, `loaded_bundled_sigs`, `loaded_user_sig_paths` (all `#[serde(default)]`). `Project::to_session()` / `apply_session()` are the single source of truth, used by `save_session`/`load_session`/`open_with_session`. Replay order: opt-in lazy loads (archives → bundled sigs → user sigs) → enable/disable overrides → one re-analysis (if any FLIRT toggle changed) or hit recompute.

**Pipeline ordering.**
```
Step 3: stackframe::analyze_and_rewrite          → returns (body, frame_layout)
Step 4: varnames::rename_variables
Step 5: expr_builder::type_call_returns
Step 6: expr_builder::apply_user_variable_types  (&mut FrameLayout — slot subsumption hook)
Step 6.5: expr_builder::strip_compatible_call_casts
Step 7: emit::emit_function
```
`frame_layout` is plumbed `&mut` through Step 6 because `retype_slot` mutates `slots`/`subsumed_by` in place; the post-pass layout flows back into `DecompileOutput.frame_layout`.

**Gotchas.**
- `windows-sys` gates everything behind Cargo features. Typegen must enable the right feature set or `syn` won't see most APIs.
- `FrameLayout` is plumbed back through `DecompileContext`; don't regress to discarding it.
- `CType` (decompile AST) is a simpler subset of `TypeRef`. Use `type_ref_to_ctype` to bridge.

### Phase 5c — GUI perf hardening [DONE]

User reported the GUI burning 80% CPU + 2 GB RAM on real binaries. Four independent culprits, all pre-dated the type-system PR.

- **Side panel virtualization.** All six `views/side_panel.rs` panels (Functions, Symbols, Imports, Exports, Sections, Strings) switched from `ScrollArea::vertical().show()` to `.show_rows(ui, ROW_HEIGHT, len, |ui, range| { ... })`. Was laying out 1393 selectable widgets per frame per panel. `SIDE_PANEL_ROW_HEIGHT` is the shared constant. Panels with inline query filters pre-filter into a `Vec<_>` so `show_rows` can index by row.
- **Disasm display-list cache.** `views/disasm.rs` was rebuilding `display_lines: Vec<DisplayLine>` from all 226k instructions every frame — ~13M ops/sec at 60 fps. `build_display_lines` is now a free function; result cached on `ReghidraApp::disasm_lines_cache: Option<(u64, Box<dyn Any + Send + Sync>)>` keyed on `disasm_display_generation`. Counter bumps on file open, function rename, bookmark toggle, undo/redo, type archive enable/disable. Comments don't structurally affect the display list and don't bump it. Payload is `Box<dyn Any>` so `app.rs` doesn't need to know `DisplayLine`'s shape.
- **Decompile view hot-path cache.** `views/decompile.rs` used `.take()` on `app.decompile_cache` so the render loop can borrow its contents without fighting `&mut self`; cache put back unconditionally at end of render. Pre-fix: `annotated_lines.clone()` and `var_names.clone()` ran every frame, a full `Vec<AnnotatedLine>` clone per frame on long functions. Also added `DecompileAuxCache { addr_to_block, function_addrs }` on `ReghidraApp` keyed on `(func_entry, rename_generation)` so the O(ir_insns) walk and O(N_functions) walk only happen on function switch or rename. `func_name_to_addr_cache` (for the click-to-navigate tokenizer) is keyed on `rename_generation` — function renames are the only mutation that affects it.
- **Conditional repaint scheduling** (biggest win). `app.rs::update` was calling `ctx.request_repaint_after(33ms)` unconditionally, pinning egui to 30 fps forever. Replaced with conditional scheduling: only request a follow-up repaint when there's pending work (`hovered_address.is_some()` after double-buffer promote, or a `status_message` deadline that hasn't fired). Mouse/keyboard/scroll events are handled by egui's reactive mode automatically. Idle CPU dropped from ~40% to ~2%.

### Phase 5c — FLIRT/cache/GUI follow-ups [DONE]

A cluster of related fixes driven by live testing against the new MSVC-based PE fixture.

- **Disasm minimap lane** (`views/disasm.rs`, left of the scroll area, compressed overview). A thin column that plots every FLIRT+archive hit across the ENTIRE binary at a proportional y-position, NOT scrolling with the disasm content. Three colors: `theme.minimap_sig` (sig only), `theme.minimap_type` (archive only), `theme.minimap_both` (both). Selected-row indicator is a 1px line at the current scroll position. Click semantics: always snaps to the nearest marker by pixel distance (no radius cap) so every click deterministically lands on *some* stripe; empty-region fallback only fires when the binary has zero markers. Hover tooltip matches the click rule — shows the marker that would be selected. Markers + display lines cached together in `DisasmCache { lines, markers }` so the per-function classification happens at cache-rebuild time, not every frame. `MinimapMarkerKind` classification: `func.matched_signature_db.is_some()` for sig; `which_archive_resolves(&func.name, &enabled_archives).is_some()` for type. Archive enable/disable in the Loaded Data Sources panel bumps `disasm_display_generation` so the lane reflects the current effective set.
- **Legacy FLIRT sig filter** (`bundled_sigs::is_legacy_sig`). Borland/Delphi/C++ Builder (`b*`, `bds*`, `bh32*`, `bcb*`, `c4vcl`, `d3-d5vcl`), Watcom (`wa32rt*`, `og70`), Digital Mars/Symantec (`dm*`, `sm32rw32`, `omvc60`, `osc60`, `otp60`), old MFC 2.x (`msmfc2*`), VisualAge/Intel C/misc 1990s linkers (`vac35wc`, `iclapp`, `iclmat`, `ulink`, `mccor`, `vireo*`) are NOT auto-loaded. They remain enumerated by `available_sigs()` and visible in the panel under a nested "Legacy toolchains" `CollapsingHeader` per bits-leaf (default-closed unless something inside is loaded). `AvailableSig` carries `is_legacy: bool`. `FlirtRowSnapshot` mirrors it. Flipping a sig between modern and legacy is a one-line edit to `is_legacy_sig`. Cuts PE x86 open-time memory and parse cost dramatically — ~half the shipped x86 sigs are pre-2010 toolchains that almost never match modern binaries.
- **`apply_signatures` longer-match-wins.** `Function::matched_signature_length: Option<u32>` tracks the winning match's `module_length`. Later dbs can override a `Signature`-sourced function if their match is *strictly longer*. Equal lengths preserve the earlier match (deterministic across re-runs). Stops earlier-loaded sigs from poisoning function names with short generic matches (e.g. a WDK sig matching a 5-byte `jmp` thunk as `??0CHAROP@@QAE@XZ`) that would otherwise block more specific later sigs. Eligibility unchanged for authoritative sources (EntryPoint/Symbol/Import/AutoNamed/TailCallTarget/PData/GuardCf): those still skip apply_signatures entirely.
- **`Project::load_bundled_sig` prepends.** Newly lazy-loaded sigs insert at position 0 of `bundled_dbs` (parallel with `bundled_db_enabled` / `bundled_db_hits`) so they get first-match priority on the next re-analyze. The user explicitly clicked "enable" in the panel; giving priority matches intent. Combined with the longer-match fix, a lazy-loaded legacy sig can actually claim its CRT thunks instead of being blocked by generic modern sigs.

**Remaining Phase 5c work — priorities.** Target workload is PE-heavy with some ELF/Mach-O; ARM is out of scope.

1. **Mach-O symbol coverage** (when a real Mach-O target appears): ObjC metadata (`__objc_classlist`/`__objc_protolist`/`__objc_selrefs`) for selector names; macOS-specific FLIRT pack (libsystem); `LC_FUNCTION_STARTS` as entry source.
2. **Loaded Data Sources panel — search box stretch.** Text input that takes a function name and answers "which db/archive in the chain owns this?" via `which_archive_resolves` + an analogous helper for FLIRT hit attribution. Useful when staring at a wall of `__SEH_prolog4`-style misses.
3. **Intelligent FLIRT pre-selection.** `bundled_sigs::collect_bundled_sigs` currently loads *every* non-legacy `.sig` in the format/arch subdir unconditionally. Smart selection should key off `BinaryInfo` signals: PE Rich Header `@comp.id` records, PE imports (`msvcr*.dll` / `vcruntime140.dll` / `ucrtbase.dll` / `libgcc_s_*.dll`), ELF `.note.ABI-tag` + `DT_NEEDED`, Mach-O `LC_LOAD_DYLIB`. Panel lazy-load is the escape hatch when the heuristic guesses wrong. The legacy filter already halved the default-load set; intelligent pre-selection narrows it further.
4. **Hint hit source via color/badge in the views.** Right now a function name in disasm/decompile/side panel renders the same regardless of which data source produced it. Add per-source color (or badge / icon column / hover tooltip) — data is already on `Function::matched_signature_db` (FLIRT) and resolvable via `type_archive::which_archive_resolves` (archives); work is purely render-side. The minimap lane already encodes sig-vs-type-vs-both; extending to per-token is the next step.
5. **ARM64 polish — deprioritized.** `stp`/`ldp` pre-index writeback unmodeled; no ARM64-specific FLIRT. Park until needed.
6. **PDB overlay — deprioritized.** `pdb` crate behind a feature flag; on PE load with sibling `.pdb`, parse `S_GPROC32`/`S_REGREL32`/`S_BPREL32`/`S_LOCAL` and populate `FrameLayout` directly. TPI stream for type records. Revisit when a target actually ships a PDB.

### Phase 5d — Headless CLI [DONE]
Full subcommand-based `reghidra-cli` with feature parity for everything content/state-related the GUI exposes. Motivated by "AI agents and Python scripts need a way to drive reghidra without the GUI."

**Surface.** `clap` derive subcommands split into four groups:
- **Inspection (read-only)**: `info`, `functions` (`--source`/`--name`/`--limit`), `sections`, `strings` (`--pattern`), `xrefs --to/--from`, `decompile`, `disasm` (defaults to entry point), `ir`, `cfg`, `find`.
- **Data sources**: `sources list/flirt/archives/resolve/enable/disable/load-archive/load-sig/load-user-sig`. `--available` on `flirt`/`archives` enumerates embedded-but-unloaded entries. `resolve NAME` calls `which_archive_resolves` against the effective archive set — agents use this to answer "why isn't this prototype typed?"
- **Annotations**: `annotate comment/rename/rename-label/rename-var/retype/bookmark/unbookmark/list`.
- **Sessions**: `session init/show/refresh`. Refresh re-runs analysis and re-applies overrides — useful when the pipeline changes under an existing session.

**Contract.** Documented in `crates/reghidra-cli/README.md`:
- Every read command takes `--binary PATH` OR `--session FILE`. The session form replays data-source overrides + lazy loads via `Project::open_with_session`.
- **Mutating commands require `--session` and error out if missing.** Silent drops are worse than no parity.
- Every read command supports `--json`. JSON shapes are pinned by `crates/reghidra-cli/tests/cli.rs` — adding fields is non-breaking, renaming/removing requires a CLI version bump.
- Addresses accept `0x` hex or decimal via `parse_address`.

**Tests.** `crates/reghidra-cli/tests/cli.rs` runs `CARGO_BIN_EXE_reghidra-cli` as a subprocess — 25+ tests covering the full surface. Every `annotate` subcommand has its own round-trip test. Every `sources` mutation kind has its own toggle test. `session_refresh_preserves_overrides` verifies session round-trip. `mutating_commands_require_session` verifies the error-out contract.

**Caveats.** Each invocation re-opens and re-analyzes the binary. For iterative workflows against the same binary this is 3-10 seconds of wasted work per call. The deferred `reghidra-cli serve` daemon (JSON-RPC over stdio) is the follow-up.

**Where to verify.** `tests/fixtures/wildfire-test-pe-file.exe` is the primary PE fixture — MSVC-built PE32 x86, 219 functions, 99 modern FLIRT matches across Visual Studio 2005/2008/2010/14/MFC/WDK. `__realloc_crt`/`_malloc`/`__fclose_nolock` are the modern FLIRT-CRT canaries. Unit tests in `reghidra-decompile::type_archive::tests`. End-to-end in `crates/reghidra-core/tests/rizin_visibility.rs` (asserts `EnumChildWindows` resolves via archive chain, `__fclose_nolock` is an intentional negative canary for the UCRT-internals gap). See `tests/fixtures/SOURCES.md` for fixture provenance.

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
Anything the GUI can show or change about a binary's analysis state must have a `reghidra-cli` equivalent. The CLI is the contract for AI agents and Python scripts; if a feature exists only in egui, it doesn't exist as far as automation is concerned.
- New `Project` field exposed by the GUI? Add a corresponding CLI accessor, and if the GUI lets the user toggle it, add a `sources`/`annotate` subcommand.
- Mutating CLI commands MUST require `--session <FILE>` and persist via `Project::save_session`. A mutation that vanishes on exit is worse than no mutation.
- Every mutation must round-trip through `Session` serde — extend `Session` (with `#[serde(default)]` on new fields for forward compat) and update `Project::to_session` / `apply_session`.
- Read commands take either `--binary` OR `--session`; the session form replays data-source overrides via `Project::open_with_session`.
- All read commands support `--json`. The shape is the contract. Tests in `crates/reghidra-cli/tests/cli.rs` pin it.
- Update `crates/reghidra-cli/README.md` when adding a subcommand. The README is what the AI agent reads when confused.

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
- Dark mode is Nord-inspired (Frost teal types, Aurora purple keywords, Aurora orange numbers, Aurora green strings, Snow Storm operators/default, Polar Night gray comments). Light mode is Solarized equivalents. When adding a `SyntaxKind`, update both `Theme::dark`/`Theme::light` + `decomp_color`, and extend `syntax::CONTROL_KEYWORDS` / `syntax::C_TYPE_KEYWORDS` (type table includes stdint, common Win32 aliases — HANDLE/HWND/DWORD/LPCSTR — and `unkN` defaults).

## Analysis pipeline notes
- `functions::detect_functions` is two-pass: (1) entry discovery from all sources (binary entry, symbols, call targets, gated tail-call jmps, prologues, PE `.pdata`, Guard CF), (2) per-entry CFG reachability via `cfg::build_cfg_from_entry` stopping at rets, indirect branches, other entries. Function size/instruction count come from `ControlFlowGraph::extent()` — do NOT fall back to linear walks. CFGs built once and reused by xrefs/IR lifting.
- New entry source? Feed it into `collect_extra_entries` in `analysis.rs` with a `FunctionSource` variant, NOT into `detect_functions` directly.
- PE-specific metadata lives on `LoadedBinary` (`pdata_function_starts`, `guard_cf_function_starts`) and `BinaryInfo` (`pdb_info`, `rich_header`). Guard CF parser stubbed; Load Config Directory decoder is a follow-up.

## Lifter / decompiler notes
- **VarNode address vs value distinction.** `parse_memory_expression` returns a varnode whose *value is the effective address*, not a `VarSpace::Memory` descriptor. Callers pass it as `Store.addr`/`Load.addr`, and the expression builder's single `Expr::Deref` wrap produces correct C. Do NOT reintroduce `VarSpace::Memory` flowing out of operand parsing — it caused a double-deref bug (`*(*(0x40dfd8))`).
- **Memory-destination ops.** x86 has RMW forms (`mov [m], r`, `add [m], r`, `inc [m]`, `pop [m]`). Use `read_operand`/`write_operand` helpers in `x86_64.rs`; `parse_operand` is fine for non-memory operands and address-itself cases (jmp/call targets). Only `lift_mov`/`lift_push`/`lift_pop` use the helpers; binops/inc/dec are still on the old path with a latent bug for memory destinations.
- **IAT call resolution.** x86-32 `call [imm]` and x86-64 `call [rip+disp]` lift to `IrOp::Call { target: iat_slot_addr }`, not `CallInd`. `project::decompile` merges `binary.import_addr_map` into `DecompileContext.function_names` keyed by IAT slot. Register-indirect (`call rax`, `call [rbx+8]`) still emits `CallInd`.
- **Stack-arg collapsing** lives in `expr_builder::build_statements`, NOT the lifter. Per-block walk defers `Store{addr=stack_pointer}` into `pending_stack_writes`, consumes on next `Call`/`CallInd` (reversed). Non-call instructions flush as plain `*(rsp) = x`, EXCEPT `is_stack_pointer_delta` (`rsp = rsp ± const` bookkeeping from push/pop). Arity capping caps via "take last N, leave rest". Cross-block propagation extends across extended-basic-block boundaries. Joins/branches/back-edges reset.
- **Variable renamer (`varnames.rs`).**
  - All sized x86 GPR aliases canonicalize via `canonical_reg_name` (eax/ax/al → rax). `renames` keyed on canonical names.
  - `is_known_register_name` gates whether an unrecognized var becomes `var_N` (it's a register) or is left alone (function name, global, already-renamed).
  - x86-32 detected by `scan_for_x86_32` pre-pass; suppresses SysV `argN` mapping for `rdi/rsi/rdx/rcx/r8/r9` (cdecl/stdcall pass on stack).
  - `rsp/rbp/result/flags` intentionally visible; eliminating them needs stack-frame analysis.

## FLIRT notes
- `signatures/` contains both rizinorg/sigdb sigs (`VisualStudio2015.sig`, `ubuntu-libc6.sig`) and IDA-derived sigs (`vc32_14.sig`, `pe.sig`). `bundled_sigs::collect_bundled_sigs` orders IDA first, rizinorg last.
- **Legacy filter.** `bundled_sigs::is_legacy_sig` flags Borland/Watcom/Digital Mars/old MFC/VisualAge/etc. as legacy. Legacy sigs are enumerated by `available_sigs()` and visible in the panel (nested "Legacy toolchains" header per bits-leaf) but NOT auto-loaded. Flipping a sig between modern and legacy is a one-line edit.
- **Precedence via `module_length`.** `apply_signatures` allows a later db to override an earlier `Signature`-sourced function if its match's `module_length` is *strictly longer*. Tracked on `Function::matched_signature_length`. Stops short generic matches from blocking better ones. Equal lengths preserve the earlier match.
- **Lazy-load prepends.** `Project::load_bundled_sig` inserts new dbs at position 0 of `bundled_dbs` so user opt-ins win over the auto-load set on the next re-analyze.
- **Per-db hit attribution.** `apply_signatures` stamps `Function::matched_signature_db = Some(db.header.name)` on every match. `Project::recompute_hit_counts` walks it. Don't drop the field on a cleanup pass.
- IDA `.sig` files use bit `0x08` (`IDASIG_FUNCTION_UNRESOLVED_COLLISION`) in the optional pre-name attribute byte for collision placeholders `sigmake` couldn't resolve (typically `?`). `parse_module` tracks `is_collision` per public-name candidate and clears the module name if every candidate is a collision; `apply_signatures` skips empty-name modules. Don't reintroduce naive name parsing that ignores the attribute byte.
- 16-bit/DOS/OS-2/NetWare/NE/LE/Mach-O-startup sigs from the IDA pack are intentionally NOT bundled.
