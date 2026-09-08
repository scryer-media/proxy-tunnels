use super::*;
use bytes::Buf;
use std::sync::atomic::AtomicUsize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::timeout,
};

const CA: &[u8] = include_bytes!("../../tests/fixtures/http3/ca.der");
const CERT: &[u8] = include_bytes!("../../tests/fixtures/http3/server.der");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/http3/server-key.der");

#[derive(Clone, Copy)]
enum Mode {
    Echo,
    Refuse(u16),
    Hang,
    Reset,
    Trailers,
    LargeHeaders,
    AfterFin,
    NoRead,
    Goaway,
}

struct Fixture {
    endpoint: quinn::Endpoint,
    task: JoinHandle<()>,
    authorities: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
}

fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(CA.to_vec()))
        .unwrap();
    roots
}

impl Fixture {
    async fn start(mode: Mode) -> Self {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(CERT.to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(KEY.to_vec().into()),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(128u32.into());
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server = endpoint.clone();
        let authorities = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let recorded = authorities.clone();
        let count = connections.clone();
        let cancellations = cancelled.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            while let Some(incoming) = server.accept().await {
                let recorded = recorded.clone();
                let count = count.clone();
                let cancellations = cancellations.clone();
                tasks.spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    count.fetch_add(1, Ordering::SeqCst);
                    let Ok(mut h3) = h3::server::builder()
                        .build(h3_quinn::Connection::new(connection))
                        .await
                    else {
                        return;
                    };
                    let mut streams = JoinSet::new();
                    while let Ok(Some(resolver)) = h3.accept().await {
                        if matches!(mode, Mode::Goaway) {
                            h3.shutdown(1).await.unwrap();
                        }
                        let recorded = recorded.clone();
                        let cancellations = cancellations.clone();
                        streams.spawn(async move {
                            let (request, mut stream) = resolver.resolve_request().await?;
                            assert_eq!(request.method(), http::Method::CONNECT);
                            assert!(request.uri().scheme().is_none());
                            assert!(request.uri().path_and_query().is_none());
                            recorded
                                .lock()
                                .unwrap()
                                .push(request.uri().authority().unwrap().to_string());
                            let expected =
                                Http3ProxyCredentials::new("fixture".into(), "fixture-only".into())
                                    .unwrap()
                                    .header();
                            if request.headers().get(http::header::PROXY_AUTHORIZATION)
                                != Some(&expected)
                            {
                                stream
                                    .send_response(
                                        http::Response::builder().status(407).body(()).unwrap(),
                                    )
                                    .await?;
                                stream.finish().await?;
                                return Ok::<_, h3::error::StreamError>(());
                            }
                            if matches!(mode, Mode::Hang) {
                                if stream.recv_data().await.is_err() {
                                    cancellations.fetch_add(1, Ordering::SeqCst);
                                }
                                return Ok(());
                            }
                            let mut response = http::Response::builder().status(
                                if let Mode::Refuse(status) = mode {
                                    status
                                } else {
                                    200
                                },
                            );
                            if matches!(mode, Mode::LargeHeaders) {
                                response = response.header("x-padding", "x".repeat(32 * 1024));
                            }
                            stream.send_response(response.body(()).unwrap()).await?;
                            match mode {
                                Mode::Refuse(_) | Mode::LargeHeaders => {
                                    stream.finish().await?;
                                }
                                Mode::Reset => {
                                    // Wait for DATA to prove the client accepted the response;
                                    // an immediate QUIC reset can discard unsent headers.
                                    let _ = stream.recv_data().await?;
                                    stream.stop_stream(h3::error::Code::H3_CONNECT_ERROR);
                                }
                                Mode::Trailers => {
                                    stream.send_trailers(http::HeaderMap::new()).await?;
                                }
                                Mode::AfterFin => {
                                    while stream.recv_data().await?.is_some() {}
                                    stream.send_data(Bytes::from_static(b"after-fin")).await?;
                                    stream.finish().await?;
                                }
                                Mode::NoRead => {
                                    std::future::pending::<()>().await;
                                }
                                Mode::Echo | Mode::Goaway => {
                                    while let Some(mut data) = stream.recv_data().await? {
                                        stream
                                            .send_data(data.copy_to_bytes(data.remaining()))
                                            .await?;
                                    }
                                    stream.finish().await?;
                                }
                                Mode::Hang => unreachable!(),
                            }
                            Ok(())
                        });
                    }
                });
            }
        });
        Self {
            endpoint,
            task,
            authorities,
            connections,
            cancelled,
        }
    }

    fn spec(&self) -> Http3TunnelSpec {
        Http3TunnelSpec {
            proxy_config_id: "h3-fixture".into(),
            revision: "1".into(),
            host: "127.0.0.1".into(),
            port: self.endpoint.local_addr().unwrap().port(),
            credentials: Some(
                Http3ProxyCredentials::new("fixture".into(), "fixture-only".into()).unwrap(),
            ),
            request_timeout: Duration::from_secs(3),
        }
    }

    fn provider(&self) -> Http3TunnelProvider {
        Http3TunnelProvider::with_root_certificates(self.spec(), roots()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"fixture stopped");
        self.task.abort();
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

async fn echo(provider: &Http3TunnelProvider, host: &str) {
    let mut stream = provider.dial(host, 563).await.unwrap();
    stream.write_all(b"article payload").await.unwrap();
    stream.flush().await.unwrap();
    let mut answer = [0; 15];
    timeout(Duration::from_secs(3), stream.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&answer, b"article payload");
}

#[tokio::test]
async fn forwards_names_and_ipv6_without_destination_dns_and_reuses_session() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = fixture.provider();
    echo(&provider, "never-resolve-locally.invalid").await;
    echo(&provider, "2001:db8::123").await;
    assert_eq!(
        *fixture.authorities.lock().unwrap(),
        ["never-resolve-locally.invalid:563", "[2001:db8::123]:563"]
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    provider.shutdown().await;
}

#[tokio::test]
async fn concurrent_streams_are_independent() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = Arc::new(fixture.provider());
    let mut jobs = JoinSet::new();
    for index in 0..20 {
        let provider = provider.clone();
        jobs.spawn(async move {
            echo(&provider, &format!("destination-{index}.invalid")).await;
        });
    }
    while let Some(result) = jobs.join_next().await {
        result.unwrap();
    }
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authorities.lock().unwrap().len(), 20);
    provider.shutdown().await;
}

#[tokio::test]
async fn verifies_untrusted_certificate_and_hostname() {
    let fixture = Fixture::start(Mode::Echo).await;
    let public = Http3TunnelProvider::new(fixture.spec()).unwrap();
    assert!(matches!(
        public.dial("destination.invalid", 563).await,
        Err(TunnelError::Http3Tls { .. })
    ));
    assert!(fixture.authorities.lock().unwrap().is_empty());
    public.shutdown().await;
    // The fixture does not serve this IP's name; connect_with can separate the
    // UDP endpoint and TLS name to prove the configured verifier checks names.
    let provider = fixture.provider();
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let result = endpoint
        .connect_with(
            provider.config.clone(),
            fixture.endpoint.local_addr().unwrap(),
            "wrong.invalid",
        )
        .unwrap()
        .await;
    assert!(result.is_err());
    assert!(fixture.authorities.lock().unwrap().is_empty());
}

#[tokio::test]
async fn authentication_and_http_errors_do_not_retry_or_follow_redirects() {
    let fixture = Fixture::start(Mode::Echo).await;
    let mut spec = fixture.spec();
    spec.credentials = None;
    let provider = Http3TunnelProvider::with_root_certificates(spec, roots()).unwrap();
    assert!(matches!(
        provider.dial("destination.invalid", 563).await,
        Err(TunnelError::Http3ProxyStatus { status: 407 })
    ));
    assert_eq!(fixture.authorities.lock().unwrap().len(), 1);
    provider.shutdown().await;
    for status in [302, 403, 502] {
        let fixture = Fixture::start(Mode::Refuse(status)).await;
        let provider = fixture.provider();
        assert!(
            matches!(provider.dial("destination.invalid", 563).await, Err(TunnelError::Http3ProxyStatus { status: actual }) if actual == status)
        );
        assert_eq!(fixture.authorities.lock().unwrap().len(), 1);
        provider.shutdown().await;
    }
}

#[tokio::test]
async fn dial_timeout_resets_request_and_releases_admission() {
    let fixture = Fixture::start(Mode::Hang).await;
    let mut spec = fixture.spec();
    spec.request_timeout = Duration::from_millis(150);
    let provider = Http3TunnelProvider::with_root_certificates(spec, roots()).unwrap();
    assert!(provider.dial("destination.invalid", 563).await.is_err());
    assert_eq!(provider.permits.available_permits(), MAX_STREAMS);
    wait_until(|| fixture.cancelled.load(Ordering::SeqCst) == 1).await;
    provider.shutdown().await;
}

#[tokio::test]
async fn cancelling_dial_resets_only_its_stream() {
    let fixture = Fixture::start(Mode::Hang).await;
    let provider = Arc::new(fixture.provider());
    let cloned = provider.clone();
    let task = tokio::spawn(async move { cloned.dial("destination.invalid", 563).await });
    wait_until(|| !fixture.authorities.lock().unwrap().is_empty()).await;
    task.abort();
    let _ = task.await;
    wait_until(|| fixture.cancelled.load(Ordering::SeqCst) == 1).await;
    assert_eq!(provider.permits.available_permits(), MAX_STREAMS);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    provider.shutdown().await;
}

#[tokio::test]
async fn shutdown_revokes_streams_pending_dials_and_future_dials() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = Arc::new(fixture.provider());
    let mut stream = provider.dial("destination.invalid", 563).await.unwrap();
    let session = provider.sessions.lock().unwrap().current.clone().unwrap();
    provider.shutdown().await;
    assert!(stream.read_u8().await.is_err());
    assert!(stream.write_all(b"no").await.is_err());
    assert!(provider.dial("destination.invalid", 563).await.is_err());
    assert!(session.writers.lock().unwrap().is_empty());
    assert!(session.driver.lock().unwrap().is_none());
    assert!(session.endpoint.lock().unwrap().is_none());
    let fixture = Fixture::start(Mode::Hang).await;
    let provider = Arc::new(fixture.provider());
    let cloned = provider.clone();
    let task = tokio::spawn(async move { cloned.dial("destination.invalid", 563).await });
    wait_until(|| !fixture.authorities.lock().unwrap().is_empty()).await;
    provider.shutdown().await;
    assert!(
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn dropping_provider_revokes_retained_streams() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = fixture.provider();
    let mut stream = provider.dial("destination.invalid", 563).await.unwrap();
    drop(provider);
    assert!(stream.write_all(b"no").await.is_err());
    assert!(stream.read_u8().await.is_err());
}

#[tokio::test]
async fn write_half_close_preserves_response_reading() {
    let fixture = Fixture::start(Mode::AfterFin).await;
    let provider = fixture.provider();
    let mut stream = provider.dial("destination.invalid", 563).await.unwrap();
    stream.write_all(b"request").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    assert!(stream.write_all(b"late").await.is_err());
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"after-fin");
    provider.shutdown().await;
}

#[tokio::test]
async fn resets_and_illegal_trailers_are_errors_not_clean_eof() {
    for mode in [Mode::Reset, Mode::Trailers] {
        let fixture = Fixture::start(mode).await;
        let provider = fixture.provider();
        let mut stream = provider.dial("destination.invalid", 563).await.unwrap();
        if matches!(mode, Mode::Reset) {
            stream.write_all(b"reset now").await.unwrap();
        }
        assert!(
            timeout(Duration::from_secs(3), stream.read_to_end(&mut Vec::new()))
                .await
                .unwrap()
                .is_err()
        );
        provider.shutdown().await;
    }
}

#[tokio::test]
async fn response_headers_are_bounded() {
    let fixture = Fixture::start(Mode::LargeHeaders).await;
    let provider = fixture.provider();
    assert!(provider.dial("destination.invalid", 563).await.is_err());
    provider.shutdown().await;
}

#[tokio::test]
async fn writes_apply_backpressure_and_cancel_promptly() {
    let fixture = Fixture::start(Mode::NoRead).await;
    let provider = fixture.provider();
    let mut stream = provider.dial("destination.invalid", 563).await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), async {
            for _ in 0..1024 {
                stream.write_all(&[0; 65536]).await.unwrap();
            }
        })
        .await
        .is_err()
    );
    provider.shutdown().await;
    assert!(stream.flush().await.is_err());
}

#[tokio::test]
async fn admission_is_bounded_and_waiting_can_be_cancelled() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = fixture.provider();
    let permit = provider
        .permits
        .clone()
        .acquire_many_owned(MAX_STREAMS as u32)
        .await
        .unwrap();
    assert!(
        timeout(
            Duration::from_millis(50),
            provider.dial("destination.invalid", 563)
        )
        .await
        .is_err()
    );
    assert!(fixture.authorities.lock().unwrap().is_empty());
    drop(permit);
    echo(&provider, "destination.invalid").await;
    provider.shutdown().await;
}

#[test]
fn credentials_are_redacted_and_inputs_cannot_inject_authorities() {
    let credentials =
        Http3ProxyCredentials::new("fixture-user".into(), "fixture-secret".into()).unwrap();
    assert!(!format!("{credentials:?}").contains("fixture-secret"));
    assert!(!format!("{:?}", credentials.header()).contains("Zml4"));
    for invalid in [
        "",
        "bad\r\nhost",
        "https://example.org",
        "user@example.org",
        "example.org:443",
        "example.org/path",
        "example.org?query",
    ] {
        assert!(spec::authority(invalid, 563).is_err(), "{invalid:?}");
    }
    assert!(Http3ProxyCredentials::new("user:other".into(), "test".into()).is_err());
    assert!(spec::authority("example.org", 0).is_err());
}

#[tokio::test]
async fn connection_loss_is_reported_and_next_dial_reconnects() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = fixture.provider();
    let mut old = provider.dial("old.invalid", 563).await.unwrap();
    let session = provider.sessions.lock().unwrap().current.clone().unwrap();
    session
        .connection
        .close(0u32.into(), b"fixture connection loss");
    assert!(
        timeout(Duration::from_secs(3), old.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    echo(&provider, "recovered.invalid").await;
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    provider.shutdown().await;
}

#[tokio::test]
async fn goaway_keeps_existing_streams_and_reconnects_for_later_dials() {
    let fixture = Fixture::start(Mode::Goaway).await;
    let provider = fixture.provider();
    let mut old = provider.dial("old.invalid", 563).await.unwrap();
    timeout(Duration::from_secs(3), async {
        loop {
            if provider.dial("later.invalid", 563).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    echo(&provider, "recovered.invalid").await;
    old.write_all(b"still alive").await.unwrap();
    let mut data = [0; 11];
    timeout(Duration::from_secs(3), old.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data, b"still alive");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    provider.shutdown().await;
}

#[tokio::test]
async fn dropping_a_pending_read_does_not_interrupt_another_stream() {
    let fixture = Fixture::start(Mode::Echo).await;
    let provider = fixture.provider();
    let mut old = provider.dial("old.invalid", 563).await.unwrap();
    assert!(
        timeout(Duration::from_millis(30), old.read_u8())
            .await
            .is_err()
    );
    drop(old);
    echo(&provider, "alive.invalid").await;
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    provider.shutdown().await;
}

#[tokio::test]
async fn concurrent_shutdown_cannot_leave_registered_writers() {
    for _ in 0..10 {
        let fixture = Fixture::start(Mode::Echo).await;
        let provider = Arc::new(fixture.provider());
        let session = provider.session().await.unwrap();
        let mut tasks = JoinSet::new();
        for _ in 0..20 {
            let provider = provider.clone();
            tasks.spawn(async move { provider.dial("race.invalid", 563).await });
        }
        tokio::task::yield_now().await;
        provider.shutdown().await;
        while let Some(result) = tasks.join_next().await {
            if let Ok(mut stream) = result.unwrap() {
                assert!(stream.read_u8().await.is_err());
            }
        }
        assert!(session.writers.lock().unwrap().is_empty());
        assert!(session.driver.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn authenticated_socks_front_uses_http3_and_revision_change_revokes_it() {
    use crate::{NoopTunnelObserver, Socks5Credentials, TunnelRegistry};
    let fixture = Fixture::start(Mode::Echo).await;
    let registry = TunnelRegistry::with_handle(tokio::runtime::Handle::current());
    let make = || Ok(Arc::new(fixture.provider()) as Arc<dyn TunnelProvider>);
    let front = registry
        .ensure_tunnel_with(
            "h3",
            "1",
            Duration::from_secs(3),
            Arc::new(NoopTunnelObserver),
            Socks5Credentials::new("local".into(), "local-only".into()).unwrap(),
            make,
        )
        .unwrap();
    let mut socket = tokio::net::TcpStream::connect(front.addr).await.unwrap();
    socket.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    socket
        .write_all(b"\x01\x05local\x0alocal-only")
        .await
        .unwrap();
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0]);
    let host = b"no-local-dns.invalid";
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&563u16.to_be_bytes());
    socket.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    socket.write_all(b"article").await.unwrap();
    let mut payload = [0; 7];
    socket.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"article");
    assert_eq!(
        *fixture.authorities.lock().unwrap(),
        ["no-local-dns.invalid:563"]
    );
    registry
        .ensure_tunnel_with(
            "h3",
            "2",
            Duration::from_secs(3),
            Arc::new(NoopTunnelObserver),
            front.credentials,
            make,
        )
        .unwrap();
    assert!(
        timeout(Duration::from_secs(3), socket.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    registry.stop_all();
}

#[tokio::test]
async fn unreachable_udp_proxy_never_uses_tcp_or_direct_destination() {
    let proxy_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_tcp.local_addr().unwrap();
    // Reserve UDP on the same port but do not answer QUIC packets.
    let _proxy_udp = tokio::net::UdpSocket::bind(proxy_addr).await.unwrap();
    let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = Http3TunnelProvider::new(Http3TunnelSpec {
        proxy_config_id: "no-fallback".into(),
        revision: "1".into(),
        host: "127.0.0.1".into(),
        port: proxy_addr.port(),
        credentials: None,
        request_timeout: Duration::from_millis(100),
    })
    .unwrap();
    assert!(
        provider
            .dial("127.0.0.1", destination.local_addr().unwrap().port())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(30), proxy_tcp.accept())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(30), destination.accept())
            .await
            .is_err()
    );
    provider.shutdown().await;
}
