# HTTP/3 vendor provenance

These MIT-licensed sources come from the crates.io archives of
[`hyperium/h3`](https://github.com/hyperium/h3). Each directory retains the
upstream license, manifest and `.cargo_vcs_info.json`.

| Crate | Version | Upstream commit |
| --- | --- | --- |
| h3 | 0.0.8 | 22c1aa3f44d1463cd7644c8f654fffc9a6da305c |
| h3-quinn | 0.0.10 | 2dc3412bdf6083451920d5bfd7a9484d054c1859 |

Original crates.io archive SHA-256 checksums:

```text
h3-0.0.8.crate        10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be
h3-quinn-0.0.10.crate 8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4
```

There are exactly two modifications to the extracted sources:

- `h3/src/proto/headers.rs`: ordinary CONNECT omits `:scheme` and `:path`, as
  required by RFC 9114 section 4.4. Extended CONNECT and other methods retain
  the upstream encoding. The pseudo-header count follows the actual fields.
- `h3-quinn/Cargo.toml`: the h3 dependency uses `../h3` so both sides share the
  patched types.

Cargo registry bookkeeping and the upstream library lockfiles are omitted.
The root crate uses optional path dependencies so the fix also reaches git
consumers; a root-only `[patch.crates-io]` would be ignored by consuming apps.
Versions, features and cryptographic backends are unchanged by vendoring.
Return to registry dependencies after an approved upstream version implements
ordinary CONNECT correctly and passes our wire-format and interoperability tests.
