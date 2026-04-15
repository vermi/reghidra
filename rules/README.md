# Reghidra Detection Rules — Authoring Guide

This guide explains how to write, test, and contribute YAML detection rules for
the reghidra detection engine.

---

## Table of contents

1. [Anatomy of a rule](#1-anatomy-of-a-rule)
2. [Feature reference](#2-feature-reference)
3. [Combinators and counts](#3-combinators-and-counts)
4. [Choosing a scope](#4-choosing-a-scope)
5. [Severity guidance](#5-severity-guidance)
6. [Testing your rule](#6-testing-your-rule)
7. [Style conventions](#7-style-conventions)
8. [Contributing back](#8-contributing-back)

---

## 1. Anatomy of a rule

Every rule is a single YAML file under `rules/<category>/`. Each file must
contain a top-level `rule:` document. Multi-rule files are allowed (separate
documents with `---`) but the preferred style is one rule per file.

```yaml
rule:
  name: injection.createremotethread          # (1)  "category.specific-behavior"
  severity: suspicious                         # (2)  info | suspicious | malicious
  scope: function                              # (3)  function | file
  description: |                              # (4)  free-form block; first line is the
    Calls CreateRemoteThread to inject into        summary shown in the UI
    another process.
  author: reghidra                             # (5)  optional attribution
  references:                                  # (6)  optional list of URLs / ATT&CK refs
    - https://attack.mitre.org/techniques/T1055/001/
  attack:                                      # (7)  optional MITRE ATT&CK IDs
    - T1055.001
  features:                                    # (8)  the match expression
    api: /CreateRemoteThread(Ex)?/
```

**(1) `name`** — Unique dotted identifier. `<category>.<behavior>`, all
lowercase, hyphens instead of spaces. Must be unique across all bundled rules.

**(2) `severity`** — How confident we are this behavior is malicious; see
[§5](#5-severity-guidance).

**(3) `scope`** — `function` fires once per function that matches; `file` fires
once per binary. See [§4](#4-choosing-a-scope).

**(4) `description`** — Required. Explain *what* the rule detects and *why* that
behavior is interesting. The first sentence is shown in the detections panel
tooltip.

**(5) `author`** — Optional. Use `reghidra` for bundled rules.

**(6) `references`** — Optional. Links to documentation, research, or ATT&CK
entries that justify the rule.

**(7) `attack`** — Optional list of MITRE ATT&CK technique IDs.

**(8) `features`** — Required. A feature expression; see [§2](#2-feature-reference)
and [§3](#3-combinators-and-counts).

---

## 2. Feature reference

All features are evaluated against a `Features` snapshot built from the loaded
binary. Function-scope features see both the per-function slice and the whole
file; file-scope features see only the file slice.

### `api`

Matches a string against the API calls (imported + resolved) inside a function.
Accepts a literal or a `/regex/`.

```yaml
features:
  api: /CreateRemoteThread(Ex)?/    # from rules/injection/createremotethread.yml
```

```yaml
features:
  api: Sleep                         # literal match
```

> **Recommended over `import:`** for API detections. The `import:` feature's
> `lib` field is currently always `""` (DLL stem metadata is not plumbed through
> the binary loader), so `import:` effectively only matches on symbol name. Use
> `api:` instead — it matches the same set of names and will not mislead you
> about DLL filtering.

### `import`

Matches against the binary-level import table (`lib` + `sym`). As noted above,
`lib` is always `""` in the current engine — use `api:` for name-based
matching.

```yaml
features:
  import:
    lib: ""                       # always "" — see warning above
    sym: /VirtualAlloc/
```

### `string`

Matches against string literals detected in the binary (file-wide) or
referenced inside the current function. Accepts literal or `/regex/`.

```yaml
features:
  string: AppInit_DLLs             # from rules/persistence/appinit-dlls.yml
```

```yaml
features:
  string: /[A-Za-z0-9+\/]{32,}={0,2}/   # from rules/network/dns-exfil-heuristic.yml
```

### `mnemonic`

Matches a single disassembled instruction mnemonic inside a function. Literal
or `/regex/`.

```yaml
features:
  mnemonic: rdtsc
```

### `mnemonic_sequence`

Matches a consecutive run of mnemonics in the function's instruction stream.
Accepts a YAML sequence of literals or `/regex/` matchers.

```yaml
features:
  mnemonic_sequence: [xor, inc, cmp, jne]   # from rules/crypto/custom-xor-loop.yml
```

### `name`

Matches the function's resolved name (post-FLIRT, post-rename). Useful for
flagging known-bad function names or patterns.

```yaml
features:
  name: /\?CryptDecrypt/
```

### `section`

Matches a section in the binary. All sub-keys are optional; any combination
of `name`, `entropy`, and `wx` may be used.

```yaml
features:
  section:
    name: /^\.aspack$/              # from rules/packers/aspack-section.yml
```

```yaml
features:
  section:
    entropy:
      op: gt                        # gt | ge | lt | le | eq
      value: 7.5                    # from rules/packers/packed-high-entropy.yml
```

```yaml
features:
  section:
    wx: true                        # writable AND executable
```

### `tls_callbacks`

Fires when the PE has at least one TLS callback entry. Boolean.

```yaml
features:
  tls_callbacks: true               # from rules/packers/themida-tls.yml
```

### `overlay`

Fires when the binary has bytes past the last section boundary. Boolean.

```yaml
features:
  overlay: true
```

### `rich_comp_id`

Matches a PE Rich Header `@comp.id` (product ID). Accepts a decimal integer.

```yaml
features:
  rich_comp_id: 147                 # MSVC linker 14.x
```

### `imphash`

Matches the pefile-compatible imphash. Accepts a list of lowercase hex
MD5 strings. Fires if any entry in the list matches.

```yaml
features:
  imphash:
    - a1b2c3d4e5f6...
```

### `xrefs_to`

Fires when the number of inbound cross-references to a function falls in the
given range. Accepts `min` and/or `max`.

```yaml
features:
  xrefs_to:
    min: 3                          # called from at least 3 places
```

### `xrefs_from`

Fires when the number of outbound cross-references from a function falls in
the given range.

```yaml
features:
  xrefs_from:
    min: 2                          # from rules/crypto/rc4-ksa-pattern.yml
```

### `matches`

References another rule by name. Fires when the named rule already fired on
this binary during the current evaluation pass. Only valid in `file`-scope
rules; this is a two-pass mechanism.

```yaml
# Fire only when a known packer AND high entropy are both present.
features:
  and:
    - matches: packers.upx-sections
    - section:
        entropy:
          op: gt
          value: 7.2
```

---

## 3. Combinators and counts

### `and`

All child expressions must match.

```yaml
features:
  and:
    - api: /^Sleep$/
    - mnemonic: rdtsc              # from rules/anti_analysis/sleep-skew.yml
```

### `or`

At least one child expression must match.

```yaml
features:
  or:
    - section:
        name: /^\.aspack$/
    - section:
        name: /^\.adata$/          # from rules/packers/aspack-section.yml
```

### `not`

The child expression must NOT match.

```yaml
features:
  and:
    - api: /VirtualAlloc/
    - not:
        api: /HeapAlloc/           # VirtualAlloc without HeapAlloc nearby
```

### `n_or_more`

At least `n` of the listed children must match. Useful for scoring rules
without requiring all signals.

```yaml
features:
  n_or_more:
    n: 5
    of:
      - string: VirtualAlloc
      - string: GetProcAddress
      - string: LoadLibraryA
      - string: WriteProcessMemory
      - string: CreateThread
      - string: OpenProcess
      - string: RtlMoveMemory
      - string: VirtualProtect      # from rules/suspicious_api/dynamic-api-resolution.yml
```

### `count`

Wraps a single feature and fires when the match count falls in the given
range. `min` and/or `max` may be omitted.

```yaml
features:
  count:
    feature:
      mnemonic: rdtsc
    min: 2                         # from rules/anti_analysis/rdtsc-timing.yml
```

```yaml
features:
  count:
    feature:
      api: /GetProcAddress/
    min: 3
    max: 20
```

---

## 4. Choosing a scope

| Scope | Use when | Fires |
|---|---|---|
| `function` | The behavior is localized to a single function (API usage, mnemonic patterns, local strings). | Once per matching function — you get the address of the function in the results. |
| `file` | The signal is binary-level (section names, PE metadata, imphash, TLS callbacks, `matches:` combinator). | Once per binary. |

Default to `function` when possible — it gives callers an address to navigate
to. Elevate to `file` only when the feature is inherently binary-wide (section
names, PE overlay, `matches:` cross-references).

---

## 5. Severity guidance

| Severity | Meaning | Examples from bundled rules |
|---|---|---|
| `info` | The behavior is noteworthy or worth examining but is common in benign software. | `anti-analysis.peb-beingdebugged` (many legitimate apps check their own debugger state) |
| `suspicious` | The behavior is rare in clean software and warrants investigation. | `anti-analysis.rdtsc-timing`, `packers.packed-high-entropy`, `injection.createremotethread` |
| `malicious` | The behavior is almost exclusively associated with malicious intent. Combine with care — false positives here are expensive. | `network.dns-exfil-heuristic`, `persistence.appinit-dlls`, `suspicious_api.privilege-escalation-apis` |

When in doubt, start at `suspicious` and promote after validation against real
benign binaries. It is easier to escalate severity than to dial it back after
agents have started alerting on it.

---

## 6. Testing your rule

### CLI smoke test

After dropping a new `.yml` into `rules/<category>/`, verify it is parsed and
fires on an appropriate binary:

```sh
# Show all detections on a binary (JSON)
reghidra-cli detect list --binary target.exe --json

# Filter to a specific rule
reghidra-cli detect list --binary target.exe --rule my-rule --json

# Filter to a specific severity
reghidra-cli detect list --binary target.exe --severity malicious --json

# Filter to a specific function (by address or name)
reghidra-cli detect list --binary target.exe --function 0x401000 --json
```

### Unit test pattern

Add one positive and one negative test to
`crates/reghidra-detect/tests/bundled_rules.rs` using the `one_fn` / `file_feats`
helpers:

```rust
use reghidra_detect::*;
use std::collections::HashMap;

fn load(subdir: &str, stem: &str) -> Vec<Rule> {
    let path = format!("{subdir}/{stem}.yml");
    let src = bundled_rule_contents(&path).expect("bundled rule exists");
    parse_rules_from_str(src, &path).expect("parses")
}

// Builds Features with a single synthetic function.
fn one_fn(mnemonics: Vec<&str>, apis: Vec<&str>, strings: Vec<&str>) -> Features {
    let mut bf = std::collections::HashMap::new();
    bf.insert(0x1000, FunctionFeatures {
        name: "t".into(),
        apis: apis.into_iter().map(String::from).collect(),
        string_refs: strings.into_iter().map(String::from).collect(),
        mnemonics: mnemonics.into_iter().map(String::from).collect(),
        xref_in_count: 0, xref_out_count: 0,
    });
    Features { by_function: bf, ..Features::default() }
}

// Builds Features with file-level strings only.
fn file_feats(strings: Vec<&str>) -> Features {
    Features {
        file: FileFeatures {
            strings: strings.into_iter().map(String::from).collect(),
            ..FileFeatures::default()
        },
        ..Features::default()
    }
}

#[test]
fn my_rule_fires() {
    let rules = load("injection", "createremotethread");
    let feats = one_fn(vec![], vec!["CreateRemoteThread"], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn my_rule_no_false_positive() {
    let rules = load("injection", "createremotethread");
    let feats = one_fn(vec![], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}
```

Run just the bundled-rules tests:

```sh
cargo test -p reghidra-detect --test bundled_rules
```

Run all detect tests:

```sh
cargo test -p reghidra-detect
```

---

## 7. Style conventions

### Naming

- Format: `<category>.<specific-behavior>` — all lowercase, hyphens for
  word separators, no underscores in the name portion.
- Category must be one of the existing directories:
  `anti_analysis`, `crypto`, `injection`, `network`, `packers`,
  `persistence`, `suspicious_api`.
- Names must be globally unique across all bundled rules.

### Description wording

- First sentence: short summary starting with a verb or noun that describes
  exactly what fires the rule. This is the string shown in the GUI tooltip.
- Subsequent sentences: explain *why* this is suspicious and flag common
  false-positive scenarios so analysts know what to verify.
- Example:
  > Calls CreateRemoteThread or CreateRemoteThreadEx to create a thread in
  > another process. This is the most common method for classic DLL injection
  > and shellcode injection into a remote process. Legitimate use is rare
  > outside of debugging tools.

### References section

Always include at least one reference for `malicious` or `suspicious` rules:

- MITRE ATT&CK technique URL: `https://attack.mitre.org/techniques/T1055/001/`
- Unprotect.it technique page when available.
- Vendor documentation (MSDN, etc.) for the key API.

### MITRE IDs

Add `attack:` IDs when the technique maps directly. Use the most specific
sub-technique ID available (prefer `T1055.001` over `T1055`).

### File placement

One rule per file, named after the rule's behavior portion:
`rules/injection/createremotethread.yml` for `injection.createremotethread`.

---

## 8. Contributing back

Before opening a PR, verify all of the following:

- [ ] **Rule file exists** under the correct `rules/<category>/` directory.
- [ ] **Name is unique.** Run `grep -r 'name:' rules/ | grep "your.rule.name"`.
- [ ] **Two tests added** to `crates/reghidra-detect/tests/bundled_rules.rs`:
      one that fires the rule and one that does not.
- [ ] **`cargo test -p reghidra-detect` passes** (128 existing tests + 2 new).
- [ ] **References filled in** for `suspicious` and `malicious` rules.
- [ ] **MITRE ATT&CK IDs** present where applicable.
- [ ] **Severity is appropriate.** If uncertain, default to `suspicious`.
- [ ] **`cargo check --workspace` clean.** Rules are embedded at compile time;
      a YAML parse error becomes a compile-time panic in tests.
- [ ] **CLI smoke test passes:** `reghidra-cli detect list --binary <target> --rule <name>` returns expected results.

### What counts as a good rule

- Targets a specific, documented malware technique — not generic "does math."
- Has a low false-positive rate OR documents the known false-positive scenarios
  in the description.
- Uses `api:` rather than `import:` for API-name matching (see [§2](#2-feature-reference)).
- Does not duplicate an existing rule — search `rules/` first.
