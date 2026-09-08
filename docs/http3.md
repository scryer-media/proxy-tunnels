# HTTP/3 CONNECT

The opt-in `http3` Cargo feature provides `Http3TunnelSpec`,
`Http3ProxyCredentials`, and `Http3TunnelProvider`. Enable it in the existing
git-tag dependency when consuming a version that includes this feature.
Existing SSH and WireGuard constructors and default features are unchanged.

This implements ordinary RFC 9114 CONNECT: an authenticated HTTP/3 proxy
forwards a separate TCP connection for each QUIC request stream. It does not
implement CONNECT-UDP, CONNECT-IP, WebTransport, or a WireGuard transport.
The server must support HTTP/3 forward proxying; an ordinary HTTP/3 website
is insufficient. UDP to the configured proxy endpoint must be reachable.

Construct one provider per immutable profile revision. Use
`TunnelProvider::dial(host, port)` for native asynchronous I/O, including
application-owned TLS adapters. `TunnelRegistry::ensure_http3_tunnel` supplies
the existing authenticated loopback SOCKS front. Private proxy deployments
can construct `Http3TunnelProvider::with_root_certificates` with an explicit
`rustls::RootCertStore`, or use it in `ensure_tunnel_with`.

The default trust store contains Mozilla public roots. Certificate and hostname
checks are always enabled, TLS uses AWS-LC, and 0-RTT is disabled. Optional
HTTP Basic credentials are sent only in the CONNECT proxy-authorization
header over verified TLS; debug output redacts both values. Host applications
remain responsible for persistence, secret storage, profile validation,
authorization, routing policy and sanitized health reporting.

Only the proxy endpoint uses host DNS and UDP networking. Destination names
are sent as CONNECT authorities, with no host lookup or direct fallback.
Callers with destination address restrictions must resolve and validate through
their route and dial the validated IP while retaining the original TLS name.
This provider does not itself implement destination DNS policy. Environment
proxy settings, redirects and HTTP authentication challenges do not change the
route. Non-2xx responses return `Http3ProxyStatus`; failures never downgrade
to TCP, HTTP/2, HTTP/1.1 or direct access.

## Bounds and lifecycle

Each provider admits at most 128 live streams and four QUIC sessions, including
sessions draining after GOAWAY. A connection has a 32 MiB receive window,
32 MiB send window and 2 MiB receive window per stream. The write adapter queues
at most one 64 KiB chunk plus one in flight per stream. Reads consume HTTP/3
DATA directly without a duplex copy pump. Downloading still involves protocol,
decryption and caller-buffer copies; this is not an end-to-end zero-copy path.

The configured dial deadline (greater than zero, at most 300 seconds) includes
admission, proxy bootstrap, TLS and the CONNECT response. Responses have a
16 KiB decoded header limit. Cancelling a dial resets its request and releases
admission. Dropping a stream resets its unfinished write side and stops reads.
Backpressure remains bounded when either endpoint stops consuming data.

An existing healthy QUIC session is reused. GOAWAY preserves accepted streams;
an attempt that encounters GOAWAY returns an error, and a subsequent dial
creates a new session. Connection loss fails affected streams; there is no
transparent replay or partial-response splicing. Application retry policy
decides whether and where to reconnect.

`shutdown().await` rejects future dials, cancels pending work, closes all sessions
and streams, aborts and joins owned driver/writer tasks, and waits up to five
seconds for each endpoint to become idle. Dropping the provider also closes
sessions and aborts its tasks. The host should await shutdown when replacing
a revision and retain its existing consumer-pool revocation logic.

## Independent interoperability fixture

Use a local Caddy build with the Naïve forwardproxy fork. The tested sources are
Caddy `v2.11.2`, xcaddy `v0.4.7`, and forwardproxy commit
`d62c80d3dd2c706b6b87579844d2397bddd18317` (tag `v2.11.2-naive`). The commit
form is necessary because the fork's release tag is not a valid Go module
version for its module path. These are external development tools, not Rust
package dependencies.

```sh
go run github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7 build v2.11.2 \
  --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@d62c80d3dd2c706b6b87579844d2397bddd18317 \
  --output ./caddy-fixture
openssl x509 -inform DER -in tests/fixtures/http3/server.der -out server.pem
openssl pkey -inform DER -in tests/fixtures/http3/server-key.der -out server-key.pem
```

In a disposable directory, use the following Caddyfile, substituting an unused
high port and absolute fixture certificate paths. The fixed credentials and
private key are public test material; never use this configuration for a
deployed proxy.

```caddyfile
{
    admin off
    auto_https off
    servers {
        protocols h3
    }
}
:54443 {
    bind 127.0.0.1
    tls /path/to/server.pem /path/to/server-key.pem
    route {
        forward_proxy {
            basic_auth fixture fixture-only
            hide_ip
            hide_via
            acl {
                allow 127.0.0.1
                deny all
            }
        }
    }
}
```

Confine Caddy storage with `XDG_DATA_HOME` and `XDG_CONFIG_HOME` pointing inside
the disposable directory, then run `caddy-fixture run --config Caddyfile
--adapter caddyfile`. The admin API and automatic certificate management are
disabled, only HTTP/3 is enabled, and both proxy and destination are loopback.
Stop that process when testing finishes.

```sh
cargo run --locked --release --features http3 --example http3_interop -- \
  54443 tests/fixtures/http3/ca.der 20 64
```

The harness starts its own ephemeral TCP origin, asserts an unauthenticated
CONNECT returns 407, downloads 64 MiB on each of 20 concurrent streams,
checks every byte and exact response length, and reports aggregate throughput.
It has an overall deadline and stops its origin and tunnel provider before exit.
Loopback throughput includes the proxy, origin and byte verification on the
same machine; it is not a WAN performance claim.

## Dependency provenance

The optional stack adds Quinn, h3, h3-quinn, rustls, Mozilla roots, HTTP types
and supporting packages. Bytes was already present transitively. Existing
locked registry versions are preserved. The lockfile also records inactive
optional and platform-specific packages. Quinn declares `ring` for browser
WebAssembly, an unsupported target for this native crate; `ring` is absent from
the macOS, Linux and Windows build graphs. Check each native target with
`cargo tree --locked --features http3 --target TARGET -i ring`.

Quinn, h3 and the adapter use MIT/Apache-2.0 or MIT licenses; rustls and its
verifier use permissive licenses. The Mozilla root bundle includes MPL-2.0
data. The two narrowly patched vendored MIT crates retain their licenses and
provenance in [vendor/README.md](../vendor/README.md). Upstream h3 currently
emits compiler warnings from unchanged code; first-party Clippy remains strict.
