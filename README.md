# proxy-tunnels

First-party Rust tunnel engine for [Scryer](https://github.com/scryer-media/scryer)
and [Weaver](https://github.com/scryer-media/weaver).

**This library is built only for Scryer and Weaver. Any other use is unsupported.
Your mileage may vary (YMMV).** APIs may change to meet first-party needs without
third-party compatibility guarantees. External support and feature requests
are not accepted.

## What it provides

- SSH TCP forwarding with Ed25519 key authentication and host-key pinning.
- Userspace WireGuard with an in-memory IP stack; no TUN device or routing-table changes.
- Authenticated, loopback-only SOCKS5 CONNECT fronts, tunnel lifecycle management,
  and bounded connection admission.
- An optional `test-support` feature for first-party integration fixtures.

The host application owns configuration, secret storage, host-key persistence,
authorization, and health reporting through `TunnelObserver`. It must enforce
shared host-key trust and reset/revocation policy across providers using
`authorize_host_key`; the default no-op observer does not provide that policy.
TOFU records continuity of identity, not independent verification of first use.
These tunnels carry explicitly routed application traffic, not all host traffic.

## Consumption

Scryer and Weaver consume this repository through **full Git commit pins**.
It is not published to crates.io; the manifest sets `publish = false`.

```toml
[dependencies]
proxy-tunnels = { git = "https://github.com/scryer-media/proxy-tunnels.git", rev = "<full-40-character-commit-SHA>" }
```

Replace the placeholder with a reviewed commit and commit the consumer's
`Cargo.lock`. Do not track a moving branch. Enable `test-support` only in
development dependencies. The package version is inherited from the initial
Scryer extraction; the Git revision identifies the code being consumed.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo nextest run --locked --all-features --no-fail-fast
```

Tests create local SSH, HTTP, and WireGuard fixtures and require local socket
access. There is no package-publication workflow.

## License

GPL-3.0-only (GNU General Public License version 3). See [LICENSE](LICENSE).
The unsupported-use policy does not restrict rights granted by that license.
