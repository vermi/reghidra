# reghidra-cli

Headless command-line driver for the [reghidra](../../README.md) reverse
engineering framework. Designed for AI agents, scripting, and CI use:
every subcommand prints either a human-readable table or a stable JSON
document, and any state mutation can be persisted to a session file for
replay across invocations.

## Why this exists

Reghidra's GUI is a window into a Rust analysis pipeline. Everything
the GUI shows comes from `reghidra_core::Project` — the same struct
this CLI drives. The CLI exists so that:

- An AI agent can ask "what functions are in this binary, and which
  ones came from FLIRT signatures?" and get a structured answer in
  one shell call
- A Python script can drive a reverse-engineering pipeline (rename
  functions, set types, decompile, dump JSON) without depending on
  PyO3 bindings or a long-running daemon
- A CI job can assert that a particular binary still has a specific
  function signature, comment, or annotation
- A user investigating a strange decompile result can ask the CLI
  "which type archive owns this prototype?" and get the same answer
  the GUI's Loaded Data Sources panel would give them

The CLI exposes feature parity with the GUI for everything that
isn't fundamentally interactive (mouse selection, vim navigation,
the command palette).

## Installation

```sh
cargo install --path crates/reghidra-cli
# or, in-tree:
cargo build --release -p reghidra-cli
./target/release/reghidra-cli --help
```

## Quick start

```sh
# Inspect a binary
reghidra-cli info --binary firmware.elf

# List the first 20 functions, JSON output
reghidra-cli functions --binary firmware.elf --limit 20 --json

# Decompile a function
reghidra-cli decompile --binary firmware.elf 0x401000

# See which FLIRT databases and type archives are loaded, with hit counts
reghidra-cli sources list --binary firmware.elf

# Look up which loaded type archive owns a function prototype
reghidra-cli sources resolve --binary firmware.elf CreateFileA
```

## Sessions: persisting state across invocations

Every CLI invocation is single-shot — open binary, do thing, exit. To
persist user annotations, data-source toggles, and lazy-loaded archive
opt-ins between calls, use a **session file**.

A session file is a JSON document that pins a binary path and tracks:

- Comments, function/label/variable renames, and variable retypes
- Bookmarks
- Per-data-source enable/disable overrides
- Lazy-loaded type archives and bundled FLIRT sigs (so the next open
  reproduces the same effective set)

Workflow:

```sh
# 1. Initialize a session pinned to a binary
reghidra-cli session init --binary firmware.elf --output firmware.session.json

# 2. Run mutating commands against the session — the binary path is implied
reghidra-cli annotate rename --session firmware.session.json 0x401000 main
reghidra-cli annotate comment --session firmware.session.json 0x401050 "buffer overflow check"
reghidra-cli sources disable --session firmware.session.json --kind archive rizin-libc

# 3. Read commands also accept --session and replay all overrides on open
reghidra-cli decompile --session firmware.session.json 0x401000

# 4. Inspect the persisted state
reghidra-cli session show firmware.session.json

# 5. Refresh the session if the analysis pipeline changed (re-runs analysis,
#    re-applies overrides, re-saves)
reghidra-cli session refresh firmware.session.json
```

**Mutating commands without `--session` exit with an error.** This is
intentional: the only thing more confusing than no CLI parity is a CLI
that pretends a write happened and silently drops it on exit.

## Address syntax

Addresses can be either hexadecimal with `0x` prefix or decimal:

```sh
reghidra-cli decompile --binary firmware.elf 0x401000
reghidra-cli decompile --binary firmware.elf 4198400
```

## JSON output

Pass `--json` to commands that support it for stable, machine-readable
output. Adding fields to a JSON document is non-breaking; renaming or
removing fields requires a CLI version bump (this matches the
`reghidra_core::Function` Serde contract).

The shape of each JSON document is documented in
[`src/main.rs`](src/main.rs) under the `*Json` structs at the top of
the file. The integration tests in `tests/cli.rs` pin the documented
keys.

## Subcommand reference

Run `reghidra-cli <subcommand> --help` for the full clap help. The
high-level groupings:

### Inspection (read-only)

| Command | Description |
| --- | --- |
| `info` | Binary metadata: format, arch, entry point, counts. |
| `functions` | List detected functions. Filter by `--source`, `--name`, `--limit`. |
| `find <NAME>` | Substring search across function names. |
| `sections` | List loaded sections with permissions. |
| `strings` | List detected strings. Filter by `--pattern`, `--limit`. |
| `xrefs --to ADDR` | References TO an address (callers). |
| `xrefs --from ADDR` | References FROM an address. |
| `decompile ADDR` | C-like pseudocode for the function at `ADDR`. |
| `disasm [ADDR] --count N` | Disassembly starting at `ADDR` (or entry point). |
| `ir ADDR` | Intermediate representation for the function at `ADDR`. |
| `cfg ADDR` | Control-flow graph blocks + edges. |

### Data sources

The `sources` group exposes everything the GUI's "Loaded Data Sources"
panel shows, plus the underlying enable/disable/load operations.

| Command | Description |
| --- | --- |
| `sources list` | All loaded FLIRT dbs + type archives, with hit counts. |
| `sources flirt [--available]` | FLIRT databases. `--available` includes embedded sigs that are NOT currently loaded. |
| `sources archives [--available]` | Type archives. `--available` includes embedded stems that are NOT currently loaded. |
| `sources resolve <NAME>` | Which loaded archive owns a function prototype? Mirrors the decompiler's lookup chain. |
| `sources enable --kind KIND KEY` | Enable a data source. Requires `--session`. |
| `sources disable --kind KIND KEY` | Disable a data source. Requires `--session`. |
| `sources load-archive STEM` | Lazy-load an embedded type archive (e.g. `windows-arm64`). Requires `--session`. |
| `sources load-sig --subdir SUBDIR --stem STEM` | Lazy-load a bundled FLIRT sig. Requires `--session`. |
| `sources load-user-sig PATH` | Load a `.sig` file from disk. Requires `--session`. |

`--kind` is one of `bundled` / `user` / `archive`. The `KEY` is:

- `bundled`: `<subdir>/<stem>` — e.g. `pe/x86/32/vc32_14`. The same
  stem can ship under multiple arches (`VisualStudio2017` exists in
  `pe/x86/32`, `pe/arm/32`, `pe/arm/64`); the subdir is part of the
  identity so toggling one doesn't affect the others. Use
  `sources flirt --available` to enumerate the valid keys.
- `user`: the FLIRT library header name (the human-readable string
  inside the `.sig` file, not the file path). Listed in `sources flirt`.
- `archive`: the archive stem (`windows-x64`, `posix`, `rizin-windows`).
  Listed in `sources archives`.

#### Example: investigate why a prototype isn't being typed

```sh
# Suppose the decompile output shows `CreateFileA` as `void(void)`
# instead of the typed Win32 prototype. Ask which archive owns it.
$ reghidra-cli sources resolve --binary app.exe CreateFileA
CreateFileA -> windows-x64

# Suppose `__SEH_prolog4` shows up untyped. Ask the same question.
$ reghidra-cli sources resolve --binary app.exe __SEH_prolog4
__SEH_prolog4 -> (not resolved by any loaded archive)

# Now check which sigs / archives are loaded and whether any have
# matched __SEH_prolog4 territory.
$ reghidra-cli sources list --binary app.exe --json | jq '.archives[].name'
```

#### Example: try a different toolchain's FLIRT sigs

```sh
# Initialize a session
reghidra-cli session init --binary app.exe --output app.session.json

# See what's currently loaded for pe/x86/32
reghidra-cli sources flirt --session app.session.json --available

# The auto-loaded set is "every sig in pe/x86/32" — wasteful but
# harmless. To narrow it: disable the toolchains you know aren't right.
reghidra-cli sources disable --session app.session.json \
    --kind bundled pe/x86/32/borland_v45

# To opt INTO a sig that wasn't auto-loaded (e.g. Watcom OS/2 sigs):
reghidra-cli sources load-sig --session app.session.json \
    --subdir pe/x86/32 --stem watcom_os2_sysl
```

### Annotations

| Command | Description |
| --- | --- |
| `annotate comment ADDR TEXT` | Set or clear a comment. Empty TEXT clears. |
| `annotate rename ADDR NAME` | Rename a function. Empty NAME clears. |
| `annotate rename-label ADDR NAME` | Rename a CFG block label. |
| `annotate rename-var FUNC_ADDR DISPLAYED_NAME NEW_NAME` | Rename a local variable. |
| `annotate retype FUNC_ADDR DISPLAYED_NAME TYPE` | Set the type of a local variable. |
| `annotate bookmark ADDR` / `annotate unbookmark ADDR` | Add/remove a bookmark. |
| `annotate list` | Print every annotation as a table or JSON. |

The `DISPLAYED_NAME` for variable rename/retype is whatever the
post-rename pass displayed in `decompile` output — `arg_8`, `local_4`,
`eax`, etc. Take it directly from a `decompile` invocation.

`TYPE` is a free-form C type string parsed by
`reghidra_decompile::ast::parse_user_ctype`. Examples: `HANDLE`,
`uint32_t`, `char*`, `LPCSTR`, `int[16]`. Common Win32 typedefs are
recognized. Unknown names fall through to `CType::Named(...)` and
display as-is.

### Sessions

| Command | Description |
| --- | --- |
| `session init --binary PATH --output FILE` | Create a session pinned to a binary. |
| `session show FILE` | Pretty-print the session JSON. |
| `session refresh FILE` | Re-open the binary, replay overrides, re-save. Useful after upgrading reghidra. |

## Programmatic use

For Python scripts, the recommended pattern is:

```python
import json, subprocess

def reghidra(*args):
    out = subprocess.run(
        ["reghidra-cli", *args, "--json"],
        capture_output=True,
        check=True,
    )
    return json.loads(out.stdout)

# One-shot inspection
info = reghidra("info", "--binary", "firmware.elf")
print(f"{info['functions']} functions in {info['format']}/{info['architecture']}")

# Find functions matching a pattern
hits = reghidra("find", "--binary", "firmware.elf", "decrypt")
for f in hits:
    print(f"0x{f['address']:08x}  {f['display_name']}")

# Drive a session
subprocess.run(
    ["reghidra-cli", "session", "init",
     "--binary", "firmware.elf",
     "--output", "firmware.session.json"],
    check=True,
)
for addr, name in [(0x401000, "main"), (0x401200, "decrypt_blob")]:
    subprocess.run(
        ["reghidra-cli", "annotate", "rename",
         "--session", "firmware.session.json",
         hex(addr), name],
        check=True,
    )
```

For AI agents, the same pattern applies — every subcommand has a
short, deterministic exit code (`0` on success, non-zero on error,
human-readable explanation on stderr) and the `--json` output shapes
are documented in the integration tests.

## Limitations

- Each invocation re-loads and re-analyzes the binary from scratch.
  For a 100MB binary that's a few seconds; on small fixtures it's
  imperceptible. A long-running daemon mode (`reghidra-cli serve`)
  with JSON-RPC over stdio is on the roadmap if iterating against the
  same binary becomes the bottleneck.
- The CLI does not expose a write path for binary patching or
  modification — it's read-only against the input file. Mutations
  only ever land in the session JSON.
- Some GUI features have no CLI analogue because they're inherently
  interactive: vim-style navigation, mouse-driven selection, the
  command palette, hex view scrolling. Everything *content*-related
  (function listings, decompile output, xref lookups, type/data
  source state) is exposed.

## Testing

```sh
cargo test -p reghidra-cli
```

The integration tests in `tests/cli.rs` invoke the built binary and
parse its `--json` output. They double as the canonical contract for
the JSON shapes documented in this README.
