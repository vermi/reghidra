# Type archives

This directory holds bundled [`TypeArchive`](../crates/reghidra-core/src/types/mod.rs)
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
see `archive_stems` in `crates/reghidra-core/src/types/mod.rs` for the
mapping. Current targets:

| Stem              | Covers                                                |
| ----------------- | ----------------------------------------------------- |
| `posix`           | POSIX / libc / pthread core from `libc`               |
| `windows-x64`     | Win32 APIs from `windows-sys` (LLP64, Win64 ABI)      |
| `windows-x86`     | Same, 32-bit target (ILP32, stdcall ABI)              |
| `windows-arm64`   | Same, ARM64 target (LLP64, AAPCS64 ABI)               |

The UCRT surface that ships under `Win32::System::Console`,
`Win32::System::Threading`, etc. is already covered by the
`windows-*` archives, so there's no separate `ucrt.rtarch`. If a
future PR splits the CRT out (e.g. to slim the main Windows blob),
it should add the new stem to `archive_stems_for` in
`crates/reghidra-core/src/project.rs`.
