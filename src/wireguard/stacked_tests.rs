//! A WireGuard tunnel carried inside another, against two real peers.
//!
//! The inner peer's endpoint exists only inside the outer tunnel: it is the
//! outer peer's tunnel address, where the outer peer relays UDP to the inner
//! peer. So a dial that reaches the inner peer's service has crossed both
//! tunnels, and the outer peer's relay log is the record of exactly what the
//! outer peer could see.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::TunnelError;
use crate::provider::{NoopTunnelObserver, TunnelObserver, TunnelProvider};
use crate::wireguard::test_peer::{
    TEST_CLIENT_ADDRESS, TEST_PEER_ADDRESS, TEST_PEER_HTTP_PORT, WireGuardTestPeer,
    WireGuardTestPeerOptions, test_key,
};
use crate::wireguard::{MIN_CARRIED_MTU, WireGuardSpec, WireGuardTunnelProvider, carried_mtu};

/// The name the outer peer's resolver gives the inner peer's endpoint.
const INNER_ENDPOINT_NAME: &str = "inner.vpn.test";
/// The port the outer peer relays to the inner peer, inside the outer tunnel.
const INNER_ENDPOINT_PORT: u16 = 51820;

#[derive(Default)]
struct Outcomes {
    successes: Mutex<Vec<String>>,
}

impl TunnelObserver for Outcomes {
    fn tunnel_dial_failed(&self, _proxy_config_id: &str, _message: &str) {}
    fn tunnel_dial_succeeded(&self, proxy_config_id: &str) {
        self.successes
            .lock()
            .expect("successes")
            .push(proxy_config_id.to_string());
    }
    fn host_key_pinned(&self, _proxy_config_id: &str, _fingerprint: &str) {}
}

/// Two peers, the second reachable only through the first.
struct Stacked {
    outer: WireGuardTestPeer,
    inner: WireGuardTestPeer,
}

impl Stacked {
    async fn start(inner_body: String) -> Self {
        let inner = WireGuardTestPeer::start_with(WireGuardTestPeerOptions {
            private_key: test_key(31),
            body: inner_body,
            ..WireGuardTestPeerOptions::default()
        })
        .await;
        let outer = WireGuardTestPeer::start_with(WireGuardTestPeerOptions {
            names: HashMap::from([(
                INNER_ENDPOINT_NAME.to_string(),
                vec![IpAddr::V4(TEST_PEER_ADDRESS)],
            )]),
            body: "the outer peer's own service".to_string(),
            udp_forward: Some((INNER_ENDPOINT_PORT, inner.endpoint())),
            ..WireGuardTestPeerOptions::default()
        })
        .await;
        Self { outer, inner }
    }

    fn outer_provider(&self, observer: Arc<dyn TunnelObserver>) -> Arc<WireGuardTunnelProvider> {
        Arc::new(WireGuardTunnelProvider::new(
            self.outer.client_spec("outer"),
            observer,
        ))
    }

    /// The inner tunnel's spec: its endpoint is a name only the outer
    /// tunnel's resolver knows, at an address only the outer tunnel routes.
    fn inner_spec(&self) -> WireGuardSpec {
        WireGuardSpec {
            endpoint_host: INNER_ENDPOINT_NAME.to_string(),
            endpoint_port: INNER_ENDPOINT_PORT,
            ..self.inner.client_spec("inner")
        }
    }

    fn inner_provider(&self, outer: &Arc<WireGuardTunnelProvider>) -> WireGuardTunnelProvider {
        WireGuardTunnelProvider::new(self.inner_spec(), Arc::new(NoopTunnelObserver))
            .with_inner_wireguard(Arc::clone(outer))
    }
}

async fn get(provider: &WireGuardTunnelProvider, host: &str) -> String {
    let mut stream = provider
        .dial(host, TEST_PEER_HTTP_PORT)
        .await
        .expect("a dial through both tunnels");
    stream
        .write_all(format!("GET /stacked HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .expect("request");
    stream.flush().await.expect("flush");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.expect("response");
    String::from_utf8_lossy(&answer).to_string()
}

/// A body far larger than one packet, so the download is made of full-sized
/// inner packets. Were the inner MTU not reduced to fit inside the outer
/// tunnel, every one of those would be too large to carry and the download
/// would never finish.
fn large_body() -> String {
    "inner-tunnel-payload;".repeat(8_000)
}

#[tokio::test]
async fn a_tunnel_inside_a_tunnel_carries_bytes_both_ways() {
    let body = large_body();
    let peers = Stacked::start(body.clone()).await;
    let outcomes = Arc::new(Outcomes::default());
    let outer = peers.outer_provider(Arc::clone(&outcomes) as Arc<dyn TunnelObserver>);
    let inner = peers.inner_provider(&outer);

    let response = get(&inner, "origin.tunnel.test").await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:.80}");
    assert!(response.ends_with(&body), "the whole body must arrive");
    assert_eq!(peers.inner.requests(), vec!["GET /stacked HTTP/1.1"]);
    assert!(
        peers.outer.requests().is_empty(),
        "the request belongs to the inner peer alone"
    );

    // Each name went to the resolver on its own side of the stack.
    assert_eq!(peers.outer.dns_queries(), vec![INNER_ENDPOINT_NAME]);
    assert_eq!(peers.inner.dns_queries(), vec!["origin.tunnel.test"]);

    // The outer peer carried datagrams from the outer tunnel's client
    // address only, and every one was a WireGuard message.
    let forwarded = peers.outer.udp_forwarded();
    assert!(!forwarded.is_empty(), "the inner tunnel rode the outer one");
    for (source, seen) in &forwarded {
        assert_eq!(source.ip(), IpAddr::V4(TEST_CLIENT_ADDRESS));
        assert!(seen.datagrams > 0);
        assert_eq!(seen.wireguard_datagrams, seen.datagrams, "{source}");
    }
    for datagram in peers.outer.udp_forwarded_recent() {
        let text = String::from_utf8_lossy(&datagram);
        assert!(
            !text.contains("GET /stacked"),
            "plaintext reached the outer peer"
        );
        assert!(
            !text.contains("inner-tunnel-payload"),
            "plaintext reached the outer peer"
        );
    }

    // The inner tunnel's source is its socket inside the outer tunnel, and
    // the outer tunnel reported carrying it.
    let source = inner.source_address().expect("a carried source");
    assert_eq!(source.ip(), IpAddr::V4(TEST_CLIENT_ADDRESS));
    assert!(
        outcomes
            .successes
            .lock()
            .expect("successes")
            .contains(&"outer".to_string())
    );

    inner.shutdown().await;
    outer.shutdown().await;
}

#[tokio::test]
async fn a_carried_tunnel_leaves_room_for_the_carriers_headers() {
    let peers = Stacked::start("small".to_string()).await;
    let outer = peers.outer_provider(Arc::new(NoopTunnelObserver));
    let inner = peers.inner_provider(&outer);

    inner.prepare().await.expect("the inner tunnel comes up");

    let outer_mtu = outer.tunnel().await.expect("outer").stack.mtu();
    let inner_mtu = inner.tunnel().await.expect("inner").stack.mtu();
    assert_eq!(outer_mtu, peers.outer.client_spec("outer").mtu);
    // An IPv4 endpoint: 20 bytes of IP, 8 of UDP and 32 of WireGuard come
    // off, and the rest is rounded down to WireGuard's padding block.
    assert_eq!(inner_mtu, (outer_mtu - 60) / 16 * 16);

    inner.shutdown().await;
    outer.shutdown().await;
}

#[tokio::test]
async fn stopping_the_outer_tunnel_ends_inner_streams_and_fails_inner_dials() {
    let peers = Stacked::start("small".to_string()).await;
    let outer = peers.outer_provider(Arc::new(NoopTunnelObserver));
    let inner = peers.inner_provider(&outer);

    let mut open = inner
        .dial(&TEST_PEER_ADDRESS.to_string(), TEST_PEER_HTTP_PORT)
        .await
        .expect("a dial through both tunnels");

    outer.shutdown().await;

    // The open stream ends rather than waiting on a carrier that is gone.
    let mut buffer = [0u8; 64];
    let read = open.read(&mut buffer).await;
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

    // A new dial fails on the carrier, not by waiting out its timeout.
    let error = match inner.dial("origin.tunnel.test", TEST_PEER_HTTP_PORT).await {
        Ok(_) => panic!("a dial through a stopped carrier must fail"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("tunnel beneath"), "{message}");
    assert!(message.contains("stopped"), "{message}");

    inner.shutdown().await;
}

#[tokio::test]
async fn an_inner_endpoint_given_as_an_address_skips_the_carriers_resolver() {
    let peers = Stacked::start("by address".to_string()).await;
    let outer = peers.outer_provider(Arc::new(NoopTunnelObserver));
    let inner = WireGuardTunnelProvider::new(
        WireGuardSpec {
            endpoint_host: TEST_PEER_ADDRESS.to_string(),
            ..peers.inner_spec()
        },
        Arc::new(NoopTunnelObserver),
    )
    .with_inner_wireguard(Arc::clone(&outer));

    let response = get(&inner, &TEST_PEER_ADDRESS.to_string()).await;

    assert!(response.ends_with("by address"), "{response}");
    assert!(peers.outer.dns_queries().is_empty());
    inner.shutdown().await;
    outer.shutdown().await;
}

#[test]
fn the_carried_mtu_subtracts_the_carriers_ip_udp_and_wireguard_headers() {
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 63, 0, 1));
    let v6: IpAddr = "fd00::1".parse().expect("v6");
    assert_eq!(carried_mtu(1420, 1420, v4).expect("fits"), 1360);
    // 1340 and 1220 left over, rounded down so padding can never overflow.
    assert_eq!(carried_mtu(1420, 1420, v6).expect("fits"), 1328);
    assert_eq!(carried_mtu(1280, 1280, v4).expect("fits"), 1216);
    // A configured MTU already small enough is kept.
    assert_eq!(carried_mtu(1280, 3800, v4).expect("fits"), 1280);
    // A link too narrow to carry a tunnel usefully is refused, not shrunk
    // into uselessness.
    let narrow = MIN_CARRIED_MTU + 59;
    assert!(matches!(
        carried_mtu(1280, narrow, v4),
        Err(TunnelError::Configuration(_))
    ));
    assert_eq!(
        carried_mtu(1280, MIN_CARRIED_MTU + 60, v4).expect("fits"),
        MIN_CARRIED_MTU
    );
}

#[test]
fn the_relay_evidence_tells_wireguard_from_plaintext() {
    use crate::wireguard::test_peer::is_wireguard_message;
    let mut initiation = vec![1, 0, 0, 0];
    initiation.resize(148, 7);
    assert!(is_wireguard_message(&initiation));
    let keepalive = [4u8, 0, 0, 0]
        .iter()
        .copied()
        .chain([0; 28])
        .collect::<Vec<_>>();
    assert!(is_wireguard_message(&keepalive));
    // An IPv4 packet is what a tunnel that failed to encrypt would send.
    let mut ip = vec![0x45, 0, 0, 40];
    ip.resize(40, 0);
    assert!(!is_wireguard_message(&ip));
    assert!(!is_wireguard_message(b"GET / HTTP/1.1"));
}
