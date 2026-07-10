# 0.1.0 release checklist

0.1.0 is the freeze moment: on publish, every format in the frozen table of
[design/WIRE-FORMATS.md](design/WIRE-FORMATS.md) §1 is a permanent wire
contract. The publish is called by the operator, not inferred from readiness.

## Preconditions (in order)

1. **PEN assigned by IANA** — flip `LYS_OID_ARC` from the `58888` placeholder
   to the real number (single constant; see
   [PEN-REGISTRATION.md](PEN-REGISTRATION.md) for the location and sub-arc
   plan). Publishing certificates under the placeholder arc is not an option.
2. **Operator ratifications complete** — the WIRE-FORMATS decision log shows
   no `IMPLEMENTED`-pending-ratification rows for anything in the frozen table.
3. **Operator calls the publish.**

## Version flip — two lines, not one

Both crates inherit `version.workspace = true`, so the number lives only in
the workspace `Cargo.toml` — but in **two places**:

```toml
[workspace.package]
version = "0.1.0"                                            # was "0.0.1"

[workspace.dependencies]
lys-core = { version = "0.1.0", path = "crates/lys-core" }   # was "0.0.1"
```

The second line is the trap: on publish, cargo strips `path` and pins the
`lys` crate to `lys-core = "0.1.0"`. Left at `"0.0.1"`, the requirement is
`^0.0.1`, which `0.1.0` does **not** satisfy (0.0.x caret ranges are mutually
incompatible) — `lys-core` would publish fine and the `lys` publish would
fail against the registry.

## Publish

```console
$ cargo fmt --check && cargo clippy --all-targets -- -D warnings && LYS_REQUIRE_GO=1 cargo test --workspace
$ cargo package --list -p lys-core   # no tests/*-conformance/ entries; LICENSE present
$ cargo package --list -p lys        # LICENSE present
$ cargo publish -p lys-core          # first — lys depends on it
$ cargo publish -p lys
```

## After publish

- Flip the README **Install** section from the `--git` interim instruction to
  `cargo install lys` / `cargo add lys-core`.
- Tag the release commit (`v0.1.0`).
