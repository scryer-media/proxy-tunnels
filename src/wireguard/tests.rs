//! End-to-end tests for the WireGuard engine, against a real second device.
//!
//! Every test here talks to [`WireGuardTestPeer`]: a second gotatun device on
//! a real loopback UDP socket, with its own smoltcp stack answering TCP and
//! DNS. So a passing test means a real Noise handshake completed, real
//! ChaCha20-Poly1305 packets crossed a real socket, and a real userspace TCP
//! connection carried bytes — not that a mock was satisfied.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::TunnelError;
use crate::provider::{NoopTunnelObserver, TunnelObserver, TunnelProvider, TunnelStream};
use crate::registry::TunnelRegistry;
use crate::wireguard::spec::public_key_of;
use crate::wireguard::test_peer::{
    TEST_PEER_ADDRESS, WireGuardTestPeer, WireGuardTestPeerOptions, test_key, test_preshared_key,
};
use crate::wireguard::{WireGuardTunnelProvider, parse_key};

/// Records what the engine reported.
#[derive(Default)]
struct RecordingObserver {
    successes: Mutex<Vec<String>>,
    failures: Mutex<Vec<String>>,
    pins: Mutex<Vec<String>>,
}

impl TunnelObserver for RecordingObserver {
    fn tunnel_dial_failed(&self, proxy_config_id: &str, message: &str) {
        self.failures
            .lock()
            .expect("failures")
            .push(format!("{proxy_config_id}: {message}"));
    }
    fn tunnel_dial_succeeded(&self, proxy_config_id: &str) {
        self.successes
            .lock()
            .expect("successes")
            .push(proxy_config_id.to_string());
    }
    fn host_key_pinned(&self, proxy_config_id: &str, fingerprint: &str) {
        self.pins
            .lock()
            .expect("pins")
            .push(format!("{proxy_config_id}: {fingerprint}"));
    }
}

async fn http_get_through(stream: &mut Box<dyn TunnelStream>, host: &str) -> String {
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("request");
    stream.flush().await.expect("flush");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.expect("response");
    String::from_utf8_lossy(&answer).to_string()
}

#[tokio::test]
async fn a_handshake_completes_against_a_real_peer() {
    let peer = WireGuardTestPeer::start().await;
    let observer = Arc::new(RecordingObserver::default());
    let spec = peer.client_spec("proxy-handshake");
    let our_public_key = spec.public_key();

    let handshake =
        WireGuardTunnelProvider::handshake(spec, Arc::clone(&observer) as Arc<dyn TunnelObserver>)
            .await
            .expect("the handshake completes");

    assert_eq!(handshake.endpoint, peer.endpoint().to_string());
    assert_eq!(
        handshake.peer_public_key,
        public_key_of(&crate::wireguard::test_peer::test_peer_private_key())
    );
    assert_eq!(handshake.our_public_key, our_public_key);
    assert!(
        handshake.handshake_at < Duration::from_secs(10),
        "{:?}",
        handshake.handshake_at
    );
    assert!(
        observer.pins.lock().expect("pins").is_empty(),
        "WireGuard has no trust-on-first-use step, so nothing may be pinned"
    );
}

/// Readiness must not depend on the keepalive: with it off, nothing but the
/// bring-up probe packet makes gotatun initiate, so this is the test that
/// proves the probe works.
#[tokio::test]
async fn a_handshake_completes_with_the_keepalive_switched_off() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-no-keepalive");
    spec.persistent_keepalive = None;
    spec.request_timeout = Duration::from_secs(5);

    let handshake = WireGuardTunnelProvider::handshake(spec, Arc::new(NoopTunnelObserver))
        .await
        .expect("the probe packet must make the device initiate");
    assert!(handshake.handshake_at < Duration::from_secs(5));
}

/// The registry drops providers from whatever thread called it — a config
/// update on the blocking plugin worker, `stop_all` on the main thread at
/// shutdown — and none of those has a tokio runtime current. gotatun only
/// stops a device on drop when one is, so the tunnel has to enter its own
/// runtime first. This proves the drop neither panics nor leaks: after it,
/// the peer stops hearing from us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_tunnel_from_a_plain_thread_still_stops_the_device() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-thread-drop");
    // A one-second keepalive, so a device that was *not* stopped betrays
    // itself within the wait below.
    spec.persistent_keepalive = Some(1);
    let provider = Arc::new(WireGuardTunnelProvider::new(
        spec,
        Arc::new(NoopTunnelObserver),
    ));
    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("dial");
    let _ = http_get_through(&mut stream, "origin.tunnel.test").await;
    drop(stream);

    let moved = Arc::clone(&provider);
    drop(provider);
    std::thread::spawn(move || drop(moved))
        .join()
        .expect("dropping off-runtime must not panic");

    // Let the stop land, then prove the peer hears nothing more from that
    // device: not a keepalive, not a byte.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let quiet_from = peer.client_rx_bytes().await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        peer.client_rx_bytes().await,
        quiet_from,
        "a dropped tunnel's device must stop sending, even when it was dropped off-runtime"
    );

    let before = peer.requests().len();
    let second = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-thread-drop-2"),
        Arc::new(NoopTunnelObserver),
    );
    let mut stream = second
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("a new tunnel to the same peer still works after the old one was dropped");
    let _ = http_get_through(&mut stream, "origin.tunnel.test").await;
    assert_eq!(peer.requests().len(), before + 1);
}

#[tokio::test]
async fn caller_bound_udp_carries_wireguard_traffic() {
    let peer = WireGuardTestPeer::start().await;
    let factory = Arc::new(crate::endpoint::RecordingUdpFactory::default());
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("bound-wireguard"),
        Arc::new(NoopTunnelObserver),
    )
    .with_udp_factory(factory.clone());
    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .unwrap();
    let response = http_get_through(&mut stream, "origin.tunnel.test").await;
    assert!(response.ends_with("through the tunnel"));
    {
        let addresses = factory.0.lock().unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(provider.source_address(), Some(addresses[0]));
    }
    provider.shutdown().await;
}

#[tokio::test]
async fn a_dial_by_address_carries_bytes_end_to_end() {
    let peer = WireGuardTestPeer::start().await;
    let observer = Arc::new(RecordingObserver::default());
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-dial"),
        Arc::clone(&observer) as Arc<dyn TunnelObserver>,
    );

    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("dial");
    let response = http_get_through(&mut stream, "origin.tunnel.test").await;

    assert!(response.contains("200 OK"), "{response}");
    assert!(response.ends_with("through the tunnel"), "{response}");
    assert_eq!(peer.requests(), vec!["GET / HTTP/1.1".to_string()]);
    assert_eq!(
        observer.successes.lock().expect("successes").as_slice(),
        ["proxy-dial".to_string()]
    );
    assert!(
        peer.dns_queries().is_empty(),
        "an address literal must not be looked up"
    );
}

#[tokio::test]
async fn an_endpoint_name_is_resolved_by_the_injected_resolver() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-endpoint-name");
    let address = spec.endpoint_host.parse::<IpAddr>().expect("peer address");
    spec.endpoint_host = "vpn.endpoint.test".to_string();
    let resolver = crate::endpoint::RecordingResolver::answering(address);
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver))
        .with_endpoint_resolver(resolver.clone());

    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("dial");
    let response = http_get_through(&mut stream, "origin.tunnel.test").await;

    assert!(response.contains("200 OK"), "{response}");
    assert_eq!(resolver.asked(), vec!["vpn.endpoint.test".to_string()]);
}

#[tokio::test]
async fn an_endpoint_written_as_an_address_is_never_resolved() {
    let peer = WireGuardTestPeer::start().await;
    let resolver = crate::endpoint::RecordingResolver::answering(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-endpoint-address"),
        Arc::new(NoopTunnelObserver),
    )
    .with_endpoint_resolver(resolver.clone());

    provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("dial");

    assert!(resolver.asked().is_empty());
}

#[tokio::test]
async fn an_endpoint_name_with_no_resolver_is_not_dialled() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-endpoint-unresolved");
    spec.endpoint_host = "vpn.endpoint.test".to_string();
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

    let error = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .err()
        .expect("a name with no resolver must not dial");

    assert!(
        matches!(error, TunnelError::WireGuardConnect { .. }),
        "{error:?}"
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "proves the host resolver cannot answer the tunnel's name"
)]
async fn a_dial_by_name_resolves_through_the_tunnel() {
    let peer = WireGuardTestPeer::start().await;
    let provider =
        WireGuardTunnelProvider::new(peer.client_spec("proxy-dns"), Arc::new(NoopTunnelObserver));

    // `origin.tunnel.test` exists only in the peer's table. The operating
    // system cannot resolve it, so a successful dial is proof the query
    // travelled through the tunnel.
    let mut stream = provider
        .dial("origin.tunnel.test", peer.http_port())
        .await
        .expect("dial by name");
    let response = http_get_through(&mut stream, "origin.tunnel.test").await;
    assert!(response.contains("200 OK"), "{response}");

    assert_eq!(
        peer.dns_queries(),
        vec!["origin.tunnel.test".to_string()],
        "the peer's resolver must be the one that answered"
    );
    assert!(
        tokio::net::lookup_host(("origin.tunnel.test", 80))
            .await
            .is_err(),
        "the operating system must not be able to resolve this name at all"
    );
}

#[tokio::test]
async fn a_name_the_peer_does_not_know_fails_with_the_resolver_saying_so() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-nxdomain"),
        Arc::new(NoopTunnelObserver),
    );

    let error = provider
        .dial("absent.tunnel.test", 80)
        .await
        .err()
        .expect("an unknown name must not dial");
    let TunnelError::Dial { host, port, detail } = &error else {
        panic!("expected a dial failure, got {error}");
    };
    assert_eq!(host, "absent.tunnel.test");
    assert_eq!(*port, 80, "the caller's port, not the resolver's");
    assert!(detail.contains("does not know this name"), "{detail}");
}

#[tokio::test]
async fn a_wrong_peer_public_key_fails_inside_the_timeout() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-badkey");
    spec.peer_public_key = public_key_bytes(&public_key_of(&test_key(200)));
    spec.request_timeout = Duration::from_secs(2);

    let started = std::time::Instant::now();
    let error = WireGuardTunnelProvider::handshake(spec, Arc::new(NoopTunnelObserver))
        .await
        .expect_err("a peer that cannot answer must not connect");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, TunnelError::WireGuardConnect { .. }),
        "expected a WireGuard connect failure, got {error}"
    );
    assert!(
        error.to_string().contains("did not complete a handshake"),
        "{error}"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "the failure must land inside the budget, took {elapsed:?}"
    );
}

#[tokio::test]
async fn a_mismatched_preshared_key_fails_inside_the_timeout() {
    // The peer requires a preshared key; the client offers none.
    let peer = WireGuardTestPeer::start_with(WireGuardTestPeerOptions {
        preshared_key: Some(test_preshared_key()),
        ..WireGuardTestPeerOptions::default()
    })
    .await;
    let mut spec = peer.client_spec("proxy-badpsk");
    spec.preshared_key = None;
    spec.request_timeout = Duration::from_secs(2);

    let error = WireGuardTunnelProvider::handshake(spec, Arc::new(NoopTunnelObserver))
        .await
        .expect_err("a mismatched preshared key must not connect");
    assert!(
        matches!(error, TunnelError::WireGuardConnect { .. }),
        "expected a WireGuard connect failure, got {error}"
    );

    // And the matching key does connect, so the failure above was the key and
    // not the fixture.
    let peer_spec = peer.client_spec("proxy-goodpsk");
    assert_eq!(peer_spec.preshared_key, Some(test_preshared_key()));
    WireGuardTunnelProvider::handshake(peer_spec, Arc::new(NoopTunnelObserver))
        .await
        .expect("the matching preshared key connects");
}

#[tokio::test]
async fn an_unreachable_endpoint_fails_rather_than_hanging_on_the_first_dial() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-unreachable");
    // A port nothing is bound to.
    spec.endpoint_port = {
        let probe = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("a free port");
        probe.local_addr().expect("addr").port()
    };
    spec.request_timeout = Duration::from_secs(2);
    let observer = Arc::new(RecordingObserver::default());

    let provider =
        WireGuardTunnelProvider::new(spec, Arc::clone(&observer) as Arc<dyn TunnelObserver>);
    let error = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), 80)
        .await
        .err()
        .expect("an unreachable endpoint must not dial");
    assert!(
        matches!(error, TunnelError::WireGuardConnect { .. }),
        "{error}"
    );
    assert_eq!(
        observer.failures.lock().expect("failures").len(),
        1,
        "the failure must reach the observer"
    );

    // The provider is not poisoned: the next dial tries again rather than
    // reporting a cached failure.
    let error = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), 80)
        .await
        .err()
        .expect("still unreachable");
    assert!(
        matches!(error, TunnelError::WireGuardConnect { .. }),
        "{error}"
    );
    assert_eq!(observer.failures.lock().expect("failures").len(), 2);
}

#[tokio::test]
async fn a_closed_port_on_the_far_side_is_refused_without_taking_the_tunnel_down() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-refused"),
        Arc::new(NoopTunnelObserver),
    );

    let error = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), 9)
        .await
        .err()
        .expect("a closed port must not dial");
    assert!(
        matches!(error, TunnelError::Dial { .. }),
        "expected a dial failure, got {error}"
    );

    // The same tunnel still works, so a bad destination cost no reconnect.
    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("second dial");
    let response = http_get_through(&mut stream, "origin.tunnel.test").await;
    assert!(response.ends_with("through the tunnel"), "{response}");
}

#[tokio::test]
async fn a_tunnel_with_no_resolver_says_so_instead_of_asking_this_machine() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-nodns");
    spec.dns_servers.clear();
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

    let error = provider
        .dial("example.test", 80)
        .await
        .err()
        .expect("a name without a resolver must not dial");
    let TunnelError::Configuration(message) = &error else {
        panic!("expected a configuration error, got {error}");
    };
    assert!(message.contains("no DNS server configured"), "{message}");
    assert!(peer.dns_queries().is_empty());
}

#[tokio::test]
async fn localhost_is_refused_rather_than_pointed_at_this_machine() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-localhost"),
        Arc::new(NoopTunnelObserver),
    );

    for name in ["localhost", "LocalHost", "service.localhost"] {
        let error = provider
            .dial(name, 80)
            .await
            .err()
            .expect("localhost must never resolve locally");
        let TunnelError::Configuration(message) = &error else {
            panic!("expected a configuration error for {name}, got {error}");
        };
        assert!(message.contains("name this machine"), "{message}");
    }
}

#[tokio::test]
async fn the_socks5_front_carries_bytes_through_a_wireguard_tunnel() {
    let peer = WireGuardTestPeer::start().await;
    let registry = TunnelRegistry::with_handle(tokio::runtime::Handle::current());
    let observer = Arc::new(RecordingObserver::default());

    let front = registry
        .ensure_wireguard_tunnel(
            peer.client_spec("proxy-socks"),
            Arc::clone(&observer) as Arc<dyn TunnelObserver>,
            test_front_credentials(),
        )
        .expect("the front starts");
    assert!(front.addr.ip().is_loopback(), "{front:?}");

    let destination = SocketAddr::new(IpAddr::V4(TEST_PEER_ADDRESS), peer.http_port());
    let response = socks5_get(front, destination).await;
    assert!(response.contains("200 OK"), "{response}");
    assert!(response.ends_with("through the tunnel"), "{response}");
    assert_eq!(peer.requests(), vec!["GET / HTTP/1.1".to_string()]);

    registry.stop("proxy-socks");
}

#[tokio::test]
async fn the_socks5_front_resolves_names_on_the_far_side() {
    let peer = WireGuardTestPeer::start().await;
    let registry = TunnelRegistry::with_handle(tokio::runtime::Handle::current());

    let front = registry
        .ensure_wireguard_tunnel(
            peer.client_spec("proxy-socks-dns"),
            Arc::new(NoopTunnelObserver),
            test_front_credentials(),
        )
        .expect("the front starts");

    let response = socks5_get_by_name(front, "origin.tunnel.test", peer.http_port()).await;
    assert!(response.contains("200 OK"), "{response}");
    assert_eq!(peer.dns_queries(), vec!["origin.tunnel.test".to_string()]);

    registry.stop("proxy-socks-dns");
}

#[tokio::test]
async fn tearing_a_tunnel_down_leaves_nothing_running() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-teardown"),
        Arc::new(NoopTunnelObserver),
    );
    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("dial");
    let _ = http_get_through(&mut stream, "origin.tunnel.test").await;
    drop(stream);
    drop(provider);

    // Give the aborted pump and the device's own tasks a scheduling round to
    // finish unwinding, then prove the peer sees the tunnel go quiet rather
    // than something still driving it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = peer.requests().len();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        peer.requests().len(),
        before,
        "nothing may keep talking after the provider is dropped"
    );
}

#[tokio::test]
async fn a_dropped_stream_does_not_leak_its_socket_slot() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-slots"),
        Arc::new(NoopTunnelObserver),
    );

    // More dials than the stack has socket slots, one at a time. If a closed
    // socket did not give its slot back this would fail well before the end.
    for _ in 0..(crate::wireguard::DEFAULT_MAX_SOCKETS + 8) {
        let mut stream = provider
            .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
            .await
            .expect("dial");
        let response = http_get_through(&mut stream, "origin.tunnel.test").await;
        assert!(response.contains("200 OK"), "{response}");
    }
}

#[tokio::test]
async fn a_listener_inside_the_tunnel_accepts_a_peer_and_carries_bytes_both_ways() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-listen"),
        Arc::new(NoopTunnelObserver),
    );

    let mut listener = provider.listen(0, 4).await.expect("listen");
    let local = listener.local_addr();
    assert_eq!(
        local.ip(),
        IpAddr::V4(crate::wireguard::TEST_CLIENT_ADDRESS),
        "the listener reports the tunnel's own address"
    );
    assert!(
        local.port() >= 49152,
        "port 0 picks an ephemeral port: {local}"
    );

    let (accepted, dialed) = tokio::join!(listener.accept(), peer.dial_client(local.port()));
    let mut accepted = accepted.expect("accept");
    let mut dialed = dialed.expect("the peer dials the client inside the tunnel");
    assert_eq!(accepted.peer_addr().ip(), peer.tunnel_address());

    dialed.write_all(b"from the far side").await.expect("write");
    let mut inbound = [0u8; 17];
    accepted.read_exact(&mut inbound).await.expect("read");
    assert_eq!(&inbound, b"from the far side");

    accepted.write_all(b"answered").await.expect("write back");
    let mut answer = [0u8; 8];
    dialed.read_exact(&mut answer).await.expect("read back");
    assert_eq!(&answer, b"answered");
    provider.shutdown().await;
}

#[tokio::test]
async fn a_listener_takes_the_port_it_is_asked_for_and_refuses_a_second_one_there() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-listen-port"),
        Arc::new(NoopTunnelObserver),
    );

    let listener = provider.listen(6881, 2).await.expect("listen");
    assert_eq!(listener.local_addr().port(), 6881);
    assert!(
        provider.listen(6881, 2).await.is_err(),
        "a port one listener holds is not shared with another"
    );
    drop(listener);
    let again = provider
        .listen(6881, 2)
        .await
        .expect("a dropped listener frees its port");
    assert_eq!(again.local_addr().port(), 6881);
    provider.shutdown().await;
}

#[tokio::test]
async fn the_provider_says_whether_its_current_tunnel_listens_on_a_port() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-listens-on"),
        Arc::new(NoopTunnelObserver),
    );

    assert!(!provider.listens_on(6882).await, "no tunnel, no listener");
    let listener = provider.listen(6882, 2).await.expect("listen");
    assert!(provider.listens_on(6882).await);
    assert!(!provider.listens_on(6883).await);
    drop(listener);
    assert!(
        !provider.listens_on(6882).await,
        "a dropped listener frees its port"
    );

    let _listener = provider.listen(6882, 2).await.expect("listen");
    provider.retire().await;
    assert!(
        !provider.listens_on(6882).await,
        "a retired tunnel's listener is not the current tunnel's"
    );
    provider.shutdown().await;
}

#[tokio::test]
async fn a_listener_whose_tunnel_stopped_fails_its_accept() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-listen-stop"),
        Arc::new(NoopTunnelObserver),
    );

    let mut listener = provider.listen(0, 2).await.expect("listen");
    let pending = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    provider.retire().await;
    let accepted = pending.await.expect("the accept task ends");
    assert!(
        accepted.is_err(),
        "an accept on a stopped tunnel fails instead of waiting forever"
    );
}

fn public_key_bytes(base64: &str) -> [u8; 32] {
    parse_key(base64).expect("a valid key")
}

/// Drive the loopback SOCKS5 front by address and return the HTTP response.
async fn socks5_get(front: crate::TunnelFront, destination: SocketAddr) -> String {
    let mut socket = authenticated_front(&front).await;

    let mut request = vec![0x05, 0x01, 0x00];
    match destination.ip() {
        IpAddr::V4(address) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    socket.write_all(&request).await.expect("connect request");
    read_socks5_reply(&mut socket).await;
    http_over(socket, &destination.to_string()).await
}

/// Drive the front by *name*, which is what proves resolution happens on the
/// far side: the SOCKS5 front passes the name through unresolved.
async fn socks5_get_by_name(front: crate::TunnelFront, host: &str, port: u16) -> String {
    let mut socket = authenticated_front(&front).await;

    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&request).await.expect("connect request");
    read_socks5_reply(&mut socket).await;
    http_over(socket, host).await
}

fn test_front_credentials() -> crate::Socks5Credentials {
    crate::Socks5Credentials::new("test-user".into(), "test-secret".into()).unwrap()
}

async fn authenticated_front(front: &crate::TunnelFront) -> tokio::net::TcpStream {
    let mut socket = tokio::net::TcpStream::connect(front.addr).await.unwrap();
    socket.write_all(&[5, 1, 2]).await.unwrap();
    let mut answer = [0; 2];
    socket.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [5, 2]);
    socket
        .write_all(b"\x01\x09test-user\x0btest-secret")
        .await
        .unwrap();
    socket.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [1, 0]);
    socket
}

async fn read_socks5_reply(socket: &mut tokio::net::TcpStream) {
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await.expect("reply header");
    assert_eq!(header[0], 0x05);
    assert_eq!(header[1], 0x00, "the front refused the connection");
    let remaining = match header[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut length = [0u8; 1];
            socket.read_exact(&mut length).await.expect("name length");
            usize::from(length[0]) + 2
        }
        other => panic!("unexpected address type {other}"),
    };
    let mut rest = vec![0u8; remaining];
    socket.read_exact(&mut rest).await.expect("reply address");
}

async fn http_over(mut socket: tokio::net::TcpStream, host: &str) -> String {
    socket
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("request");
    let mut answer = Vec::new();
    socket.read_to_end(&mut answer).await.expect("response");
    String::from_utf8_lossy(&answer).to_string()
}

#[tokio::test]
async fn a_stack_with_only_ipv6_refuses_an_ipv4_destination_clearly() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-v6only");
    // Only a v6 interface address, so the stack has no v4 source address to
    // send from. The handshake is unaffected — WireGuard's own transport is
    // the UDP socket underneath, not the tunnel's addressing — so this proves
    // the *stack* refuses the destination, promptly and in words an operator
    // can act on, rather than emitting a packet with no source address or
    // sitting on the dial until the timeout.
    spec.addresses = vec!["fd00::2/128".parse().expect("a v6 address")];
    spec.dns_servers.clear();
    spec.request_timeout = Duration::from_secs(5);

    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));
    let started = std::time::Instant::now();
    let error = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .err()
        .expect("a v4 destination is unreachable from a v6-only stack");

    let TunnelError::Dial { host, port, detail } = &error else {
        panic!("expected a dial failure, got {error}");
    };
    assert_eq!(host, &TEST_PEER_ADDRESS.to_string());
    assert_eq!(*port, peer.http_port());
    assert!(detail.contains("family"), "{detail}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the refusal must be immediate, not a timeout"
    );
}

#[tokio::test]
async fn a_misconfigured_spec_fails_before_any_socket_is_opened() {
    let peer = WireGuardTestPeer::start().await;
    let mut spec = peer.client_spec("proxy-broken");
    spec.addresses.clear();
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

    let error = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), 80)
        .await
        .err()
        .expect("a spec with no interface address must not dial");
    let TunnelError::Configuration(message) = &error else {
        panic!("expected a configuration error, got {error}");
    };
    assert!(message.contains("interface address"), "{message}");
}

#[tokio::test]
async fn describe_never_leaks_key_material() {
    let peer = WireGuardTestPeer::start().await;
    let spec = peer.client_spec("proxy-describe");
    let private = spec.private_key;
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

    let described = provider.describe();
    assert!(described.starts_with("wireguard "), "{described}");
    assert!(
        described.contains(&peer.endpoint().to_string()),
        "{described}"
    );
    assert!(
        !described.contains(&public_key_of(&private)),
        "{described} must not carry a key in full"
    );
}

/// Belt and braces: the address constants really do describe a point-to-point
/// link, so a test that "worked" by talking to something on this machine would
/// be visible.
#[test]
fn the_test_addresses_are_private_and_distinct() {
    assert_ne!(TEST_PEER_ADDRESS, Ipv4Addr::LOCALHOST);
    assert!(TEST_PEER_ADDRESS.is_private());
    assert!(crate::wireguard::TEST_CLIENT_ADDRESS.is_private());
    assert_ne!(TEST_PEER_ADDRESS, crate::wireguard::TEST_CLIENT_ADDRESS);
}

/// What `replace_tunnel` and a stale-session rebuild do: a new device and a
/// new stack, same key, same peer, same tunnel address, on the same task. The
/// far side still holds the previous stack's connections in their closing
/// states, so this only works if the new stack does not reuse their ports.
#[tokio::test]
async fn a_rebuilt_tunnel_reaches_the_same_peer_again() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-seq-1"),
        Arc::new(NoopTunnelObserver),
    );
    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("dial");
    let _ = http_get_through(&mut stream, "origin.tunnel.test").await;
    drop(stream);
    drop(provider);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-seq-2"),
        Arc::new(NoopTunnelObserver),
    );
    let mut stream = second
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .expect("second tunnel");
    let _ = http_get_through(&mut stream, "origin.tunnel.test").await;
}

#[tokio::test]
async fn large_download_drains_after_receive_backpressure() {
    let body: String = (0..40_000)
        .map(|index| {
            format!("{index:08}:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n")
        })
        .collect();
    assert!(body.len() > 2 * 1024 * 1024);
    let peer = WireGuardTestPeer::start_for_downloads(
        WireGuardTestPeerOptions {
            body: body.clone(),
            ..Default::default()
        },
        None,
        Duration::from_millis(10),
        true,
    )
    .await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("download-backpressure"),
        Arc::new(NoopTunnelObserver),
    )
    .with_download_tuning();
    let mut stream = provider
        .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    // Let the receiver fill before draining more than two complete windows.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.split_once("\r\n\r\n").unwrap().1, body);
    drop(stream);
    provider.shutdown().await;
    assert!(
        provider
            .dial(&TEST_PEER_ADDRESS.to_string(), peer.http_port())
            .await
            .is_err()
    );
}

/// Every ERROR event a `gotatun` target emits while it is the subscriber.
#[derive(Clone, Default)]
struct GotatunErrors(Arc<Mutex<Vec<String>>>);

impl GotatunErrors {
    fn seen(&self) -> Vec<String> {
        self.0.lock().expect("gotatun errors").clone()
    }
}

/// The `message` field of one event.
struct EventMessage(String);

impl tracing::field::Visit for EventMessage {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl tracing::Subscriber for GotatunErrors {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::ERROR && metadata.target().starts_with("gotatun")
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = EventMessage(String::new());
        event.record(&mut message);
        self.0.lock().expect("gotatun errors").push(format!(
            "{}: {}",
            event.metadata().target(),
            message.0
        ));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Run `test` on a current-thread runtime that reports gotatun's errors to the
/// [`GotatunErrors`] it is handed. Every task of the tunnel and of the peer
/// runs on this one thread, so every error reaches it, and the scheduling
/// order is the same on every run.
fn with_gotatun_errors<F>(test: impl FnOnce(GotatunErrors) -> F)
where
    F: std::future::Future<Output = ()>,
{
    let errors = GotatunErrors::default();
    let dispatch = tracing::Dispatch::new(errors.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    tracing::dispatcher::with_default(&dispatch, || runtime.block_on(test(errors)));
}

/// Wait until every task spawned since `baseline` was counted has finished,
/// so nothing of a torn-down tunnel is left that could still log.
async fn until_tasks_return_to(baseline: usize) {
    let metrics = tokio::runtime::Handle::current().metrics();
    while metrics.num_alive_tasks() > baseline {
        tokio::task::yield_now().await;
    }
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// Retiring a tunnel stops its device before its stack, so gotatun's tasks
/// end on their own cancellation and never see the stack's channels close.
#[test]
fn retiring_a_tunnel_makes_gotatun_log_no_error() {
    with_gotatun_errors(|errors| async move {
        let peer = WireGuardTestPeer::start().await;
        let baseline = alive_tasks();
        let provider = WireGuardTunnelProvider::new(
            peer.client_spec("proxy-retire-quiet"),
            Arc::new(NoopTunnelObserver),
        );
        provider.prepare().await.expect("the tunnel comes up");

        provider.retire().await;
        until_tasks_return_to(baseline).await;

        assert_eq!(errors.seen(), Vec::<String>::new());
    });
}

/// Dropping a tunnel, from a thread with no runtime as the registry does,
/// stops its device before its stack.
#[test]
fn dropping_a_tunnel_makes_gotatun_log_no_error() {
    with_gotatun_errors(|errors| async move {
        let peer = WireGuardTestPeer::start().await;
        let baseline = alive_tasks();
        let provider = WireGuardTunnelProvider::new(
            peer.client_spec("proxy-drop-quiet"),
            Arc::new(NoopTunnelObserver),
        );
        provider.prepare().await.expect("the tunnel comes up");

        std::thread::spawn(move || drop(provider))
            .join()
            .expect("dropping off-runtime must not panic");
        until_tasks_return_to(baseline).await;

        assert_eq!(errors.seen(), Vec::<String>::new());
    });
}

/// A bring-up whose handshake never completes stops the device it built
/// before its stack.
#[test]
fn a_failed_handshake_makes_gotatun_log_no_error() {
    with_gotatun_errors(|errors| async move {
        let peer = WireGuardTestPeer::start().await;
        let baseline = alive_tasks();
        let mut spec = peer.client_spec("proxy-failed-quiet");
        spec.peer_public_key = public_key_bytes(&public_key_of(&test_key(200)));
        spec.request_timeout = Duration::from_secs(1);
        let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

        let error = provider
            .prepare()
            .await
            .expect_err("a peer that cannot answer must not connect");
        assert!(
            error.to_string().contains("did not complete a handshake"),
            "{error}"
        );
        until_tasks_return_to(baseline).await;

        assert_eq!(errors.seen(), Vec::<String>::new());
    });
}

/// A loopback hop between a client and a peer that holds the peer's
/// handshake responses for a fixed time, and records when it first saw an
/// initiation and when it first let a response go.
struct HandshakeRelay {
    address: SocketAddr,
    initiation_seen: Arc<Mutex<Option<std::time::Instant>>>,
    response_released: Arc<Mutex<Option<std::time::Instant>>>,
    task: tokio::task::JoinHandle<()>,
}

impl HandshakeRelay {
    async fn start(peer: SocketAddr, hold: Duration) -> Self {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("the relay binds");
        let address = socket.local_addr().expect("the relay's address");
        let initiation_seen = Arc::new(Mutex::new(None));
        let response_released = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&initiation_seen);
        let released = Arc::clone(&response_released);
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0u8; 65_536];
            loop {
                let Ok((read, from)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let datagram = &buffer[..read];
                if from != peer {
                    client = Some(from);
                    if datagram.first() == Some(&1) {
                        seen.lock()
                            .expect("initiation seen")
                            .get_or_insert_with(std::time::Instant::now);
                    }
                    let _ = socket.send_to(datagram, peer).await;
                    continue;
                }
                let Some(client) = client else {
                    continue;
                };
                if datagram.first() == Some(&2) {
                    tokio::time::sleep(hold).await;
                    released
                        .lock()
                        .expect("response released")
                        .get_or_insert_with(std::time::Instant::now);
                }
                let _ = socket.send_to(datagram, client).await;
            }
        });
        Self {
            address,
            initiation_seen,
            response_released,
            task,
        }
    }

    /// From the first initiation reaching the relay to the first response
    /// leaving it: a span the handshake itself cannot be shorter than.
    fn held_span(&self) -> Duration {
        let seen = self
            .initiation_seen
            .lock()
            .expect("initiation seen")
            .expect("an initiation crossed the relay");
        let released = self
            .response_released
            .lock()
            .expect("response released")
            .expect("a response crossed the relay");
        released.duration_since(seen)
    }
}

impl Drop for HandshakeRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The reported handshake time is measured, not read off gotatun's coarse
/// timers: a peer that answers a fixed time after it is asked, shorter than
/// those timers' tick, still reports at least the time the answer was held.
#[tokio::test]
async fn the_handshake_time_is_the_measured_round_trip() {
    let peer = WireGuardTestPeer::start().await;
    let hold = Duration::from_millis(100);
    let relay = HandshakeRelay::start(peer.endpoint(), hold).await;
    let mut spec = peer.client_spec("proxy-handshake-time");
    spec.endpoint_host = relay.address.ip().to_string();
    spec.endpoint_port = relay.address.port();
    // Nothing but the bring-up probe may make the device initiate, so the
    // first initiation the relay sees is the probe's.
    spec.persistent_keepalive = None;
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

    let called = std::time::Instant::now();
    let handshake = provider
        .probe_handshake()
        .await
        .expect("the handshake completes through the relay");
    let returned = called.elapsed();

    let held = relay.held_span();
    assert!(held >= hold, "the relay held the response for {held:?}");
    assert!(
        handshake.handshake_at >= held,
        "reported {:?}, but the response alone was held for {held:?}",
        handshake.handshake_at
    );
    assert!(
        handshake.handshake_at <= returned,
        "reported {:?}, longer than the whole call's {returned:?}",
        handshake.handshake_at
    );
}

/// A loopback hop between a client and a peer that drops the client's first
/// `dropped` handshake initiations, and records on the tokio clock when each
/// initiation reached it.
struct InitiationRelay {
    address: SocketAddr,
    initiations: Arc<Mutex<Vec<tokio::time::Instant>>>,
    task: tokio::task::JoinHandle<()>,
}

impl InitiationRelay {
    async fn start(peer: SocketAddr, dropped: usize) -> Self {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("the relay binds");
        let address = socket.local_addr().expect("the relay's address");
        let initiations = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&initiations);
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0u8; 65_536];
            loop {
                let Ok((read, from)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let datagram = &buffer[..read];
                if from != peer {
                    client = Some(from);
                    if datagram.first() == Some(&1) {
                        let mut seen = seen.lock().expect("initiations");
                        seen.push(tokio::time::Instant::now());
                        if seen.len() <= dropped {
                            continue;
                        }
                    }
                    let _ = socket.send_to(datagram, peer).await;
                    continue;
                }
                if let Some(client) = client {
                    let _ = socket.send_to(datagram, client).await;
                }
            }
        });
        Self {
            address,
            initiations,
            task,
        }
    }

    fn initiations(&self) -> Vec<tokio::time::Instant> {
        self.initiations.lock().expect("initiations").clone()
    }
}

impl Drop for InitiationRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A first initiation lost on the way is sent again after the bring-up
/// resend, not after gotatun's five-second rekey timeout, and the second one
/// brings the tunnel up.
///
/// The paused clock fires the resend's own timer on time. gotatun's retry
/// timer runs on the real clock, so a bring-up that waited for it would run
/// out its request timeout here instead.
#[tokio::test(start_paused = true)]
async fn a_lost_first_initiation_is_sent_again_after_the_bring_up_resend() {
    let peer = WireGuardTestPeer::start().await;
    let relay = InitiationRelay::start(peer.endpoint(), 1).await;
    let mut spec = peer.client_spec("proxy-lost-initiation");
    spec.endpoint_host = relay.address.ip().to_string();
    spec.endpoint_port = relay.address.port();
    // Nothing but the bring-up probe may make the device initiate.
    spec.persistent_keepalive = None;
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver));

    let started = tokio::time::Instant::now();
    provider
        .prepare()
        .await
        .expect("the second initiation is answered");

    let initiations = relay.initiations();
    assert_eq!(initiations.len(), 2, "{initiations:?}");
    let resent = initiations[1] - started;
    assert!(
        resent >= super::BRING_UP_RESEND && resent < Duration::from_secs(5),
        "the resend came {resent:?} into the bring-up"
    );
}

/// Both the first peer and the one a resend puts in its place run on
/// gotatun's own timers, so a tunnel that is up rekeys and retries as
/// WireGuard specifies.
#[tokio::test]
async fn the_bring_up_peer_keeps_gotatuns_timers() {
    let peer = WireGuardTestPeer::start().await;
    let provider = WireGuardTunnelProvider::new(
        peer.client_spec("proxy-timers"),
        Arc::new(NoopTunnelObserver),
    );
    assert!(provider.peer(peer.endpoint()).danger_timer_params.is_none());
}
