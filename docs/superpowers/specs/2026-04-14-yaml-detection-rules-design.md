# YAML Detection Rules — Design

**Branch:** `detections-yaml-rules`
**Date:** 2026-04-14
**Status:** Draft — awaiting user approval

## Summary

Add a reghidra-native detection engine that evaluates YAML rules against an analyzed binary and surfaces hits as a new data source alongside FLIRT and type archives. Rules are capa-shaped (feature expressions + boolean combinators) but native to reghidra's analysis model: they reference the things reghidra already knows — imports, resolved callees, strings, function names from FLIRT/archives, section characteristics, PE metadata, mnemonics, xref topology, Shannon entropy.

Ships with a bundled collection of ~40–60 rules covering the common malicious/suspicious-behavior categories, plus an authoring guide for users to roll their own.

## Goals

- A pluggable **Detection** data source, enable/disable per rule-file, parallel to the existing FLIRT and type-archive model.
- Rule evaluation runs as a post-analysis pass; results attach to `Function` (function-scope hits) and `Project` (file-scope hits).
- **GUI surfaces:** new "Detections" side panel, function-row badge, decompile-view banner, Loaded Data Sources panel entries.
- **CLI parity:** `reghidra-cli detect list` (read) + `sources rules *` (load/enable/disable/list/available).
- **Session persistence:** which rule files are loaded, which are enabled — same contract as FLIRT/archives.
- **Bundled collection:** ~40–60 curated rules across anti-analysis, injection, persistence, crypto, network, suspicious-APIs, packer indicators.
- **Authoring guide:** a README-equivalent the user (or an AI agent) can read to write their own rules.

## Non-Goals

- Byte-pattern scanning (`pattern:` with hex + wildcards). FLIRT already owns byte scanning for reghidra's use case. Re-evaluate if real rules demand it.
- A sliding-window entropy *visualizer* (separate future feature). Per-section entropy is computed and rule-accessible.
- Rule authoring UI inside the GUI (text editor + live preview). Author in a text editor, load via the panel or CLI.
- Sandboxing / untrusted-rule safety. Rules are declarative YAML, not code; no `eval`. Regex DoS is mitigated by using `regex` crate (no backtracking).

## Rule DSL

### File shape

```yaml
rule:
  name: anti-debug.rdtsc-timing
  severity: suspicious              # info | suspicious | malicious
  scope: function                   # function | file
  description: |
    RDTSC-based timing check commonly used to detect debugger presence.
  author: reghidra
  references:
    - https://unprotect.it/technique/rdtsc/
  features:
    and:
      - mnemonic: rdtsc
      - count: { mnemonic: rdtsc, min: 2 }
```

A file may contain one or many rules (YAML document stream or a top-level `rules: [...]` list — both accepted).

### Feature vocabulary

| Feature                      | Matches when...                                                            | Scope          |
| ---                          | ---                                                                        | ---            |
| `import: lib!sym`            | Binary imports `sym` from `lib`. `lib` may be `*`. `sym` literal or regex. | file, function |
| `api: name`                  | Function calls a resolved callee matching `name` (literal/regex/glob).     | function       |
| `string: "literal"`          | String present. Literal or `/regex/flags` form.                            | file, function |
| `name: /regex/`              | Function's resolved name matches.                                          | function       |
| `section: name, entropy: >N` | Section name matches AND/OR Shannon entropy comparison.                    | file           |
| `section: { wx: true }`      | Section is both writable and executable.                                   | file           |
| `rich: comp_id: NNN`         | PE Rich Header contains a given `@comp.id`.                                | file (PE)      |
| `imphash: "hex"`             | PE import hash equals value (literal or list).                             | file (PE)      |
| `tls_callbacks: true`        | PE TLS directory has callbacks.                                            | file (PE)      |
| `overlay: true`              | PE overlay present (size > 0).                                             | file (PE)      |
| `mnemonic: op`               | Instruction with mnemonic present in function.                             | function       |
| `mnemonic_sequence: [a,b,c]` | Contiguous mnemonic sequence within function.                              | function       |
| `xrefs_to: { min: N }`       | Function is referenced ≥N places.                                          | function       |
| `xrefs_from: { min: N }`     | Function references ≥N distinct targets.                                   | function       |
| `matches: rule-name`         | Another rule fired. File-scope can reference function-scope by name.       | file           |

### Combinators

- `and: [ ... ]`
- `or: [ ... ]`
- `not: <feature>`
- `n_or_more: { n: 3, of: [ ... ] }` — capa's "N or more of"
- A bare list under `features:` is an implicit `and`.

### Count expressions

Any feature may be wrapped: `count: { <feature>, min: N, max: M }` — requires the feature to match at least `N` and at most `M` times in scope.

### Regex vs literal

A string starting with `/` and ending in `/flags` is a regex (ECMA-ish flags: `i`, `m`, `s`). Otherwise literal. Globs (`*`, `?`) work on `api:` and `import:` symbol fields.

## Evaluation model

### Pipeline placement

Runs as a new step after analysis completes but before the GUI renders the first frame — alongside FLIRT hit-count recomputation:

```
Project::open / reanalyze:
  ... existing steps ...
  Step N-1: apply_signatures + recompute_hit_counts
  Step N:   detections::evaluate(&project) -> DetectionResults   [NEW]
```

`DetectionResults` lives on `Project` and is:

```rust
pub struct DetectionResults {
    pub file_hits: Vec<DetectionHit>,
    pub function_hits: HashMap<u64, Vec<DetectionHit>>,   // func entry VA -> hits
    pub per_rule_file_counts: HashMap<String, usize>,     // keyed by source_path; for panel stats
}

pub struct DetectionHit {
    pub rule_name: String,
    pub severity: Severity,
    pub source_path: String,            // "bundled:malware/anti_debug.yml" or user path
    pub description: String,
    pub matched_features: Vec<FeatureMatch>,   // for hover tooltip + CLI --json
}
```

### Feature collection (`Features`)

Before rule evaluation we build a `Features` snapshot from `Project` state — one pass over functions/sections/imports. Rules query this snapshot; they never touch `Project` directly. This keeps the rule engine decoupled and makes unit tests trivial (build a synthetic `Features`, assert hits).

```rust
pub struct Features {
    pub file: FileFeatures,
    pub by_function: HashMap<u64, FunctionFeatures>,
}
pub struct FileFeatures {
    pub imports: Vec<Import>,                  // (lib, sym)
    pub strings: Vec<String>,
    pub sections: Vec<SectionInfo>,            // name, size, entropy, w, x
    pub pe: Option<PeFeatures>,                // rich, imphash, tls_callbacks, overlay
    pub binary_format: BinaryFormat,
}
pub struct FunctionFeatures {
    pub name: String,
    pub apis: Vec<String>,                     // resolved callee names
    pub string_refs: Vec<String>,              // strings referenced from body
    pub mnemonics: Vec<String>,                // in order
    pub xref_in_count: usize,
    pub xref_out_count: usize,
}
```

Per-section Shannon entropy is computed on binary load (goblin gives us the raw section bytes; ~20 LOC, cached on `LoadedBinary`).

### Parser

Rule files parse via `serde_yaml` into `RawRule`, then get lowered to a compiled `Rule { name, severity, scope, expr: FeatureExpr, ... }`. Compilation fails loudly with file + path context — a bad rule must never corrupt evaluation of other rules. Parse errors are collected and surfaced in the panel ("2 of 40 rules failed to load — click for details").

Regex features compile once at rule-load time (not per function). Precompiled `regex::Regex` lives on the `FeatureExpr` AST.

### Evaluation

Single-threaded in v1 (the hot loop is cheap vs. disassembly). Function-scope rules iterate over `by_function`; file-scope rules run once. File-scope rules that reference `matches: <rule-name>` run in a second pass after function-scope completes.

Rule-file ordering: alphabetical by `source_path` for determinism; order doesn't affect correctness since hits are additive (unlike FLIRT's longest-match-wins).

## Rule storage

- **Bundled rules:** `rules/` directory at the repo root, `include_dir!`'d at compile time. Subdirectories by category: `rules/anti_analysis/`, `rules/injection/`, `rules/persistence/`, `rules/crypto/`, `rules/network/`, `rules/packers/`, `rules/suspicious_api/`.
- **User rules:** loaded via `sources rules load-user-file <path>` CLI or file picker in the panel. Stored by absolute path.
- **Enumerate-all + lazy-load** follows the Phase 5c pattern: `detections::available_bundled_rulefiles()` walks the embedded tree without parsing; parsing happens on first enable.

## GUI surfaces

### Detections side panel (new)

Third tab group in the right side panel alongside Functions/Symbols/Imports/etc. Virtualized via `show_rows` (see `SIDE_PANEL_ROW_HEIGHT`).

Tree:
```
▾ Malicious (3)
  ▸ injection.createremotethread
    └ sub_401020  (in fn_foo)
▾ Suspicious (12)
  ▸ anti-debug.rdtsc-timing  (2 hits)
  ...
▾ Info (7)
```

Click a leaf → navigate to function (or binary info for file-scope).

### Function-row badge

In the Functions panel, rows with at least one detection get a small colored dot (severity-tinted). Hover → tooltip lists rule names.

### Decompile-view banner

At the top of `views/decompile.rs`, above the function signature, when the currently-viewed function has detections:

```
⚠ 2 detections: anti-debug.rdtsc-timing · crypto.aes-sbox
```

Clicking a rule name in the banner scrolls to the nearest statement at a hit's source address. The per-line mapping reuses the `SourceAddr` markers already emitted by `emit::emit_body`; we don't need new annotation infra.

### Loaded Data Sources panel

Third section below FLIRT and Type Archives. Each loaded rule file gets a row with:
- Enable/disable checkbox
- Rule-count / hit-count
- Source path
- Parse-error indicator if any rules failed to compile

Action-queue pattern (same as existing panel mutations). Enable/disable bumps a new `detections_generation` counter on `Project`; decompile view + side panel watch it to invalidate caches.

### Toolbar / menu entries

- `View → Detections Panel` toggles the panel.
- Command palette: `Load Detection Rules...`, `Reload Detection Rules`, `Toggle Detections Panel`.

## CLI surface

### `detect list`

```
reghidra-cli detect list --binary PATH | --session FILE
                        [--severity info|suspicious|malicious]
                        [--rule NAME-OR-REGEX]
                        [--function ADDR-OR-NAME]
                        [--json]
```

Human output: grouped by severity, one line per hit. JSON output: flat list of `DetectionHit` with `matched_features` included.

### `sources rules`

Mirrors `sources flirt` / `sources archives`:
- `sources rules list [--json]` — loaded rule files + enabled state + hit counts
- `sources rules available [--json]` — bundled-but-unloaded rule files
- `sources rules load <stem-or-subdir/stem>` — lazy-load a bundled file
- `sources rules load-user-file <path>` — load a user YAML
- `sources rules enable <stem|path>` / `sources rules disable <stem|path>`
- `sources rules resolve <function-name>` — list detections that fired on a given function (mirror of `sources resolve` for types)

All mutating commands require `--session` per project rule.

## Session persistence

Extend `Session`:
```rust
#[serde(default)] pub loaded_rule_stems: Vec<String>,
#[serde(default)] pub loaded_user_rule_paths: Vec<String>,   // matches existing user-sig/user-archive path handling
#[serde(default)] pub disabled_rule_sources: Vec<String>,
```

Replay order in `apply_session`: load bundled stems → load user files → apply enable/disable overrides → evaluate. One evaluation pass at the end (not per load).

## Bundled rule collection

Minimum ~40 rules, target ~60, spread across:

- **anti_analysis/** — `rdtsc-timing`, `isdebuggerpresent`, `checkremotedebuggerpresent`, `ntqueryinformationprocess-debug`, `peb-beingdebugged`, `peb-ntglobalflag`, `int3-scan`, `vmware-io-port`, `hypervisor-bit`, `cpuid-brand-string`, `sleep-skew`, `sandbox-username-check` (string-based)
- **injection/** — `createremotethread`, `virtualallocex+writeprocessmemory`, `setwindowshookex`, `queueuserapc`, `ntmapviewofsection`, `process-hollowing` (combo), `reflective-loader` (manual-mapping signature), `thread-hijack` (`GetThreadContext` + `SetThreadContext`)
- **persistence/** — `run-key-write`, `schtasks-shell`, `service-install` (`CreateServiceA/W`), `winlogon-notify-key`, `ifeo-debugger`, `appinit-dlls`, `wmi-event-subscription` (string + API)
- **crypto/** — `aes-sbox` (constant: `0x63,0x7c,0x77,...` via string feature), `rc4-ksa-pattern`, `crypt32-full-api-chain`, `bcrypt-aes`, `custom-xor-loop` (mnemonic_sequence heuristic)
- **network/** — `winsock-connect`, `wininet-http`, `winhttp`, `dns-exfil-heuristic` (`DnsQuery_*` + base64 string refs), `raw-sockets`
- **packers/** — `upx-sections` (`.UPX0`/`.UPX1` names), `aspack-section`, `themida-tls`, `packed-high-entropy` (section entropy > 7.5 + low import count), `vmprotect-sections`
- **suspicious_api/** — `getprocaddress-loadlibrary-only` (manual IAT), `dynamic-api-resolution` (string-based GetProcAddress arg hints), `shellcode-allocate-exec` (VirtualAlloc + PAGE_EXECUTE), `token-manipulation`, `privilege-escalation-apis`

Each rule includes `description` + `references` (URL to Unprotect, MITRE ATT&CK, or vendor write-up).

## Authoring guide

`rules/README.md` ships alongside the rules. Contents:

1. **Anatomy of a rule** — the minimal valid YAML, walked line-by-line.
2. **Feature reference** — full table above, each feature with a worked example.
3. **Combinators and counts** — `and`/`or`/`not`/`n_or_more`, count ranges.
4. **Choosing a scope** — when to use `function` vs `file`.
5. **Severity guidance** — info = "this is how it does its job", suspicious = "legitimate software sometimes does this", malicious = "high confidence this is bad or combined with other hits means bad".
6. **Testing your rule** — `reghidra-cli detect list --binary foo.exe --rule my-rule` + adding a unit test against a synthetic `Features`.
7. **Style conventions** — rule naming (`category.specific-behavior`), description length, reference links.
8. **Contributing back** — PR checklist: rule + test + fixture reference + references field filled in.

## Testing strategy

### Unit tests (`crates/reghidra-detect/tests/`)

- **Parser tests** per feature: valid YAML → expected AST; invalid YAML → specific error message.
- **Evaluator tests** against hand-built `Features`: one positive + one negative case per feature and per combinator.
- **Every bundled rule** has at least one unit test with a synthetic `Features` that fires it and one that doesn't.

### Integration tests (`crates/reghidra-core/tests/`)

- Run the full pipeline against `tests/fixtures/wildfire-test-pe-file.exe` and assert a stable set of expected hits (e.g. certain CRT-API-usage-triggered rules fire). Use this as a regression canary for the whole feature.

### CLI tests (`crates/reghidra-cli/tests/cli.rs`)

- `detect list` JSON shape pinned.
- `sources rules load / enable / disable` round-trip through `--session`.
- `mutating_commands_require_session` extended to cover `sources rules *`.

### Follow-up GUI testing (separate task)

After this feature lands, set up `egui_kittest` (tracked as a separate follow-up task) so a subagent can drive the Detections panel, function-row badges, and decompile banner and assert rendered state. Deferred — CLI is the contract for this PR.

## Crate structure

New crate: `crates/reghidra-detect`
- `src/lib.rs` — public API (`evaluate`, `Rule`, `DetectionHit`, `DetectionResults`).
- `src/features.rs` — `Features` snapshot builder from `Project`.
- `src/entropy.rs` — Shannon entropy helper.
- `src/rule.rs` — `Rule`, `FeatureExpr`, compilation.
- `src/parser.rs` — YAML → `RawRule` → `Rule`, precompiles regexes.
- `src/eval.rs` — evaluation engine.
- `src/bundled.rs` — `include_dir!` of `rules/` + `available_bundled_rulefiles()`.

Deps: `serde`, `serde_yaml`, `regex`, `include_dir`, `thiserror`. The crate depends on **nothing in reghidra except `reghidra-core` type definitions** it needs for `Features` construction — and ideally only the reverse: `reghidra-detect` gets pulled into `reghidra-core::project` at the evaluation site.

## Licensing

Rules in `rules/` are Apache-2.0 OR MIT (contributor's choice), compatible with the repo's GPL-3.0-or-later. Attribution for rules derived from capa, YARA-forge, or vendor blogs lives in the rule's `references` field.

## Migration + rollout

- New feature, no migration. Ships dark — panel is visible; bundled rules ship enabled.
- `Session` additions are `#[serde(default)]` so old sessions load without warning.
- CLI contract additions are non-breaking.

## Open questions

- **Per-token highlight in views** for detection hits (e.g. `CreateRemoteThread` call in decompile view gets a red underline). Deferred — the Phase 5c follow-up "hint hit source via color/badge" already plans per-token annotation infra; detections can ride on top once that lands.
- **Rule confidence scoring / aggregation** (weighted sum → verdict). v1 leaves this to the analyst. If we find the panel is noisy in practice, revisit.
- **MITRE ATT&CK tagging** in rules (`attack: [T1055, T1055.012]`). Drop-in addition — make the field optional-with-default now so we don't break rule format later.
