# Test Fixtures — Sources & Attribution

The binary fixtures in this directory are vendored from the
[`JonathanSalwan/binary-samples`](https://github.com/JonathanSalwan/binary-samples)
collection, pinned at upstream commit
[`97e70694f1b8dac19e8f2a987ea478d0597c2371`](https://github.com/JonathanSalwan/binary-samples/tree/97e70694f1b8dac19e8f2a987ea478d0597c2371).

Upstream is MIT-licensed (`MIT_LICENSE` in the source repo). Reghidra is
GPL-3.0-or-later; MIT-licensed test data may be redistributed inside a
GPL project without conflict.

## Fixtures

| File                     | Format | Arch    | Origin                              | Purpose                                              |
|--------------------------|--------|---------|-------------------------------------|------------------------------------------------------|
| `pe-Windows-x86-cmd`     | PE     | x86     | Windows `cmd.exe` (32-bit)          | Primary PE fixture: MSVC, plenty of Win32 imports    |
| `pe-Windows-x64-cmd`     | PE     | x86_64  | Windows `cmd.exe` (64-bit)          | PE x64 coverage we previously lacked                 |
| `pe-mingw32-strip.exe`   | PE     | x86     | MinGW `strip.exe`                   | Non-MSVC PE toolchain — fuel for FLIRT pre-selection |
| `elf-Linux-x64-bash`     | ELF    | x86_64  | Linux `bash`                        | Primary ELF fixture                                  |
| `MachO-OSX-x64-ls`       | Mach-O | x86_64  | macOS `ls`                          | Primary Mach-O fixture                               |

## Refreshing

To re-vendor against a newer upstream:

```sh
SHA=<new-commit-sha>
BASE=https://raw.githubusercontent.com/JonathanSalwan/binary-samples/$SHA
cd tests/fixtures
for f in pe-Windows-x86-cmd pe-Windows-x64-cmd pe-mingw32-strip.exe \
         elf-Linux-x64-bash MachO-OSX-x64-ls; do
  curl -sSLfo "$f" "$BASE/$f"
done
```

Then update the SHA in this file and re-run `cargo test --workspace` to
re-pin any floor assertions that drift with the new bytes.
