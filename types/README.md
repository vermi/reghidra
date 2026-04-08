# Type archives

This directory holds bundled [`TypeArchive`](../crates/reghidra-decompile/src/type_archive/mod.rs)
files consumed by the decompiler to recover typed function prototypes,
parameter names, return values, and struct layouts for imported APIs.

## Policy

- **Do not hand-edit `.rtarch` files.** They are postcard-serialized binary
  blobs. Any "fix" should be made upstream in `tools/typegen` (or in the
  source crate it walks) and then regenerated here.
- **Archives are maintainer-generated, not user-generated.** End users who
  clone this repository and run `cargo build` never produce archives;
  they consume the ones checked in here. The `tools/typegen` crate lives in
  its own workspace outside the main cargo graph precisely so it can't be
  reached accidentally from a `cargo build` at the repo root.
- **CI drift-checks this directory.** Pull requests that modify `types/`
  or `tools/typegen/` trigger a workflow that regenerates each archive
  into a scratch directory and fails if the checked-in bytes don't match.
  Archive updates are therefore always a deliberate, reviewable commit by
  a human — the CI job never pushes regenerated archives itself.

## Regenerating archives

From a maintainer checkout:

```sh
cd tools/typegen
cargo run --release -- \
    --source windows-sys \
    --features Win32_Foundation,Win32_Storage_FileSystem,Win32_System_Memory,... \
    --arch x86_64 \
    --os windows \
    --out ../../types/windows-x64.rtarch
```

Commit the updated `.rtarch` alongside whatever change motivated the
regeneration (e.g. a bump of `windows-sys` in the typegen crate's
`Cargo.toml`).

## Layout

Archives are selected at load time by binary format and architecture;
see `archive_stems_for` in `crates/reghidra-core/src/project.rs` for
the mapping. Current targets:

| Stem              | Covers                                                |
| ----------------- | ----------------------------------------------------- |
| `posix`           | POSIX / libc / pthread core from `libc`               |
| `ucrt`            | MSVC CRT from `libc`'s `src/windows/` tree            |
| `windows-x64`     | Win32 APIs from `windows-sys` (LLP64, Win64 ABI)      |
| `windows-x86`     | Same, 32-bit target (ILP32, stdcall ABI)              |
| `windows-arm64`   | Same, ARM64 target (LLP64, AAPCS64 ABI)               |
| `rizin-windows`   | ~5 350 Win32 functions from Rizin's SDB (35 headers)  |
| `rizin-libc`      | ~530 POSIX/libc/linux/macos functions from Rizin SDB  |

The `rizin-*` archives are derived from
[Rizin](https://github.com/rizinorg/rizin)'s `librz/arch/types/`
SDB tree (GPLv3). The pinned upstream commit is recorded in
`.github/workflows/typegen-drift-check.yml` under `RIZIN_REF`; bump
that constant *and* commit the regenerated archives in the same PR.
At runtime they sit at the bottom of the precedence chain in
`archive_stems_for`, filling gaps left by the binding-crate-derived
archives — first-archive-wins ordering keeps `windows-x64` (etc.)
authoritative for any function name they share.
