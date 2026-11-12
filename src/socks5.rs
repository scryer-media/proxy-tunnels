//! A minimal SOCKS5 front, hand-rolled over tokio.
//!
//! This is the adaptor that makes a tunnel look like an ordinary transport
//! proxy: every existing egress site already knows how to hand reqwest a
//! `socks5h://` URL and credentials. A tunnel publishes that pair without
//! teaching consumers how to manage an SSH or WireGuard session.
//!
//! Deliberate limits, because this front serves exactly one caller (our own
//! process, over loopback) and every additional feature is attack surface:
//!
//! * **Loopback peers only.** The listener binds `127.0.0.1:0`, and the peer
//!   address is re-checked on accept anyway.
//! * **Authentication required.** RFC 1929 credentials are private to the
//!   front's owner. Loopback alone does not authenticate a local process.
//! * **CONNECT only.** BIND and UDP ASSOCIATE are answered `0x07`
//!   (command not supported).
//! * **All three address types.** IPv4, IPv6 and — the one that matters —
//!   domain names, which are passed to the provider unresolved so they resolve
//!   on the far side of the tunnel.
//! * **A handshake budget.** A peer gets [`NEGOTIATION_TIMEOUT`] (or the
//!   request timeout, if shorter) to authenticate and send its request, and
//!   is dropped after that instead of holding a task.
//! * **Handshakes apart from tunnels.** A connection takes tunnel capacity
//!   only once it has authenticated. Until then it holds one of
//!   [`MAX_FRONT_HANDSHAKES`] places, and when those are full a new
//!   connection displaces the oldest unfinished one, so idle local clients
//!   cannot keep the front's owner out.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;

use crate::error::TunnelError;
use crate::provider::{TunnelObserver, TunnelProvider, TunnelStream};

const SOCKS5_VERSION: u8 = 0x05;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Per-front budget for authenticated connections: their dials and pumps.
pub const MAX_FRONT_CONNECTIONS: usize = 256;
/// Aggregate budget for authenticated connections across all fronts in one
/// registry.
pub const MAX_REGISTRY_CONNECTIONS: usize = 1024;
/// Per-front number of connections that may be negotiating at once. When it
/// is full, a new connection displaces the oldest one still negotiating.
pub const MAX_FRONT_HANDSHAKES: usize = 64;
/// The most time a peer gets to finish method negotiation, authentication and
/// its CONNECT request. The front's owner is a client on the same host and
/// sends all three without waiting on anything but the front itself, so five
/// seconds leaves wide room for a loaded host while an idle peer cannot hold
/// a place for the whole request timeout.
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Bytes a client may send after its CONNECT request and before the reply.
/// One full TLS record (16 KiB) covers any ClientHello or request head a
/// client sends ahead of the reply.
const MAX_EARLY_DATA: usize = 16 * 1024;

/// Ephemeral front credentials. The owner supplies cryptographically random
/// tokens; they must never be persisted or embedded in a URL.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Credentials {
    username: String,
    password: String,
}

impl Socks5Credentials {
    pub fn new(username: String, password: String) -> Result<Self, TunnelError> {
        if username.is_empty()
            || username.len() > 255
            || password.is_empty()
            || password.len() > 255
        {
            return Err(TunnelError::Configuration(
                "invalid internal SOCKS credential length".into(),
            ));
        }
        Ok(Self { username, password })
    }

    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for Socks5Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Socks5Credentials(<redacted>)")
    }
}

/// Everything one front needs to serve connections.
pub struct Socks5Front {
    provider: Arc<dyn TunnelProvider>,
    observer: Arc<dyn TunnelObserver>,
    proxy_config_id: String,
    timeout: Duration,
    credentials: Socks5Credentials,
    connections: Arc<Semaphore>,
    registry_connections: Arc<Semaphore>,
    handshakes: Mutex<Handshakes>,
    handshake_capacity: usize,
}

/// Connections still negotiating, keyed by admission order. Dropping an
/// entry's sender ends that connection's negotiation.
#[derive(Default)]
struct Handshakes {
    next: u64,
    waiting: BTreeMap<u64, oneshot::Sender<()>>,
}

/// One connection's place among the handshakes; dropping it frees the place.
struct HandshakePlace<'a> {
    handshakes: &'a Mutex<Handshakes>,
    id: u64,
}

impl Drop for HandshakePlace<'_> {
    fn drop(&mut self) {
        self.handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .waiting
            .remove(&self.id);
    }
}

/// Why a single SOCKS5 conversation ended early. Never surfaced to an
/// operator — the peer is our own reqwest client, which reports the failure
/// in its own words — but traced, and mapped onto a SOCKS5 reply code.
#[derive(Debug)]
enum Socks5Failure {
    Io(std::io::Error),
    Protocol(&'static str),
    Dial(TunnelError),
}

impl std::fmt::Display for Socks5Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Failure::Io(error) => write!(f, "socket error: {error}"),
            Socks5Failure::Protocol(detail) => write!(f, "protocol error: {detail}"),
            Socks5Failure::Dial(error) => write!(f, "{error}"),
        }
    }
}

impl From<std::io::Error> for Socks5Failure {
    fn from(error: std::io::Error) -> Self {
        Socks5Failure::Io(error)
    }
}

/// A peer is allowed only if it is on the loopback interface.
///
/// The listener already binds a loopback address, so this can only fire if the
/// bind is ever changed; it is cheap insurance that a tunnel front never
/// becomes an open proxy for the network.
pub fn peer_is_permitted(peer: &SocketAddr) -> bool {
    peer.ip().is_loopback()
}

impl Socks5Front {
    pub fn new(
        provider: Arc<dyn TunnelProvider>,
        observer: Arc<dyn TunnelObserver>,
        proxy_config_id: String,
        timeout: Duration,
        credentials: Socks5Credentials,
        registry_connections: Arc<Semaphore>,
    ) -> Self {
        Self {
            provider,
            observer,
            proxy_config_id,
            timeout,
            credentials,
            connections: Arc::new(Semaphore::new(MAX_FRONT_CONNECTIONS)),
            registry_connections,
            handshakes: Mutex::new(Handshakes::default()),
            handshake_capacity: MAX_FRONT_HANDSHAKES,
        }
    }

    /// Give a new connection a place among the handshakes, displacing the
    /// oldest one when they are full. The receiver resolves if this
    /// connection is itself displaced later.
    fn admit_handshake(&self) -> (HandshakePlace<'_>, oneshot::Receiver<()>) {
        let (displace, displaced) = oneshot::channel();
        let mut handshakes = self
            .handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if handshakes.waiting.len() >= self.handshake_capacity {
            handshakes.waiting.pop_first();
        }
        let id = handshakes.next;
        handshakes.next += 1;
        handshakes.waiting.insert(id, displace);
        let place = HandshakePlace {
            handshakes: &self.handshakes,
            id,
        };
        (place, displaced)
    }

    /// Tunnel capacity for one authenticated connection, from this front's
    /// budget and the registry's.
    fn take_tunnel_slots(&self) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let local = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        let global = Arc::clone(&self.registry_connections)
            .try_acquire_owned()
            .ok()?;
        Some((local, global))
    }

    /// Accept loop. Runs until `shutdown` is notified or the listener dies.
    pub async fn serve(self: Arc<Self>, listener: TcpListener, shutdown: Arc<tokio::sync::Notify>) {
        // Dropping the set also aborts children when the registry aborts us.
        let mut connections = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                biased;
                () = shutdown.notified() => break,
                _ = connections.join_next(), if !connections.is_empty() => continue,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, peer)) => {
                    if !peer_is_permitted(&peer) {
                        tracing::warn!(
                            proxy_config_id = self.proxy_config_id.as_str(),
                            %peer,
                            "refused a non-loopback peer on a tunnel SOCKS5 front"
                        );
                        continue;
                    }
                    let front = Arc::clone(&self);
                    connections.spawn(async move {
                        if let Err(failure) = front.handle_connection(stream).await {
                            tracing::debug!(
                                proxy_config_id = front.proxy_config_id.as_str(),
                                failure = %failure,
                                "tunnel SOCKS5 connection ended early"
                            );
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        proxy_config_id = self.proxy_config_id.as_str(),
                        error = %error,
                        "tunnel SOCKS5 front stopped accepting"
                    );
                    break;
                }
            }
        }
        tracing::debug!(
            proxy_config_id = self.proxy_config_id.as_str(),
            "tunnel SOCKS5 front stopped"
        );
    }

    async fn handle_connection<S>(&self, mut stream: S) -> Result<(), Socks5Failure>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // The negotiation is bounded; the tunnelled conversation that follows
        // is not (an indexer response can legitimately take as long as the
        // request timeout the consumer's own client enforces).
        let (place, mut displaced) = self.admit_handshake();
        let budget = self.timeout.min(NEGOTIATION_TIMEOUT);
        let negotiated = tokio::select! {
            biased;
            _ = &mut displaced => {
                return Err(Socks5Failure::Protocol("a newer connection displaced the handshake"));
            }
            negotiated = tokio::time::timeout(budget, self.negotiate(&mut stream)) => negotiated,
        };
        drop(place);
        let (host, port) = match negotiated {
            Ok(result) => result?,
            Err(_) => return Err(Socks5Failure::Protocol("peer did not finish the handshake")),
        };

        // Only an authenticated connection takes tunnel capacity.
        let Some(_slots) = self.take_tunnel_slots() else {
            let _ = reply(&mut stream, REPLY_GENERAL_FAILURE).await;
            return Err(Socks5Failure::Protocol(
                "the front is at its connection limit",
            ));
        };

        // Watch the client while the tunnel dials, so a client that leaves
        // drops the dial and its capacity with it. Bytes it sends early are
        // kept, within a bound, and go to the tunnel first.
        let mut early = Vec::new();
        let dialled = tokio::select! {
            biased;
            failure = watch_client(&mut stream, &mut early) => return Err(failure),
            dialled = tokio::time::timeout(self.timeout, self.provider.dial(&host, port)) => dialled,
        };
        let mut upstream = match dialled {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(error)) => {
                self.report_failure(&error);
                let _ = reply(&mut stream, reply_code_for(&error)).await;
                return Err(Socks5Failure::Dial(error));
            }
            Err(_) => {
                let error = TunnelError::Dial {
                    host: host.clone(),
                    port,
                    detail: "the tunnel did not answer in time".to_string(),
                };
                self.report_failure(&error);
                let _ = reply(&mut stream, REPLY_HOST_UNREACHABLE).await;
                return Err(Socks5Failure::Dial(error));
            }
        };

        self.observer.tunnel_dial_succeeded(&self.proxy_config_id);
        reply(&mut stream, REPLY_SUCCEEDED).await?;
        if !early.is_empty() {
            upstream.write_all(&early).await?;
        }
        drop(early);
        self.pump(stream, upstream).await
    }

    fn report_failure(&self, error: &TunnelError) {
        self.observer
            .tunnel_dial_failed(&self.proxy_config_id, &error.to_string());
    }

    async fn pump<S>(
        &self,
        mut stream: S,
        mut upstream: Box<dyn TunnelStream>,
    ) -> Result<(), Socks5Failure>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::io::copy_bidirectional(&mut stream, &mut upstream)
            .await
            .map(|_| ())
            .map_err(Socks5Failure::Io)
    }

    /// Method negotiation followed by the CONNECT request. Returns the
    /// destination the peer asked for, unresolved.
    async fn negotiate<S>(&self, stream: &mut S) -> Result<(String, u16), Socks5Failure>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting[0] != SOCKS5_VERSION {
            return Err(Socks5Failure::Protocol("peer is not speaking SOCKS5"));
        }
        let method_count = greeting[1] as usize;
        if method_count == 0 {
            stream
                .write_all(&[SOCKS5_VERSION, METHOD_NONE_ACCEPTABLE])
                .await?;
            return Err(Socks5Failure::Protocol("peer offered no auth methods"));
        }
        let mut methods = vec![0u8; method_count];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&METHOD_PASSWORD) {
            stream
                .write_all(&[SOCKS5_VERSION, METHOD_NONE_ACCEPTABLE])
                .await?;
            return Err(Socks5Failure::Protocol("authentication is required"));
        }
        stream.write_all(&[SOCKS5_VERSION, METHOD_PASSWORD]).await?;
        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await?;
        if auth[0] != 1 || auth[1] == 0 {
            stream.write_all(&[1, 1]).await?;
            return Err(Socks5Failure::Protocol("invalid authentication"));
        }
        let mut username = vec![0u8; auth[1] as usize];
        stream.read_exact(&mut username).await?;
        let password_len = stream.read_u8().await? as usize;
        let mut password = vec![0u8; password_len];
        stream.read_exact(&mut password).await?;
        // Both values are always compared, and `&` rather than `&&` keeps a
        // wrong username from skipping the password comparison.
        let username_matches = credential_matches(self.credentials.username.as_bytes(), &username);
        let password_matches = credential_matches(self.credentials.password.as_bytes(), &password);
        if !(username_matches & password_matches) {
            stream.write_all(&[1, 1]).await?;
            return Err(Socks5Failure::Protocol("authentication failed"));
        }
        stream.write_all(&[1, 0]).await?;

        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await?;
        if request[0] != SOCKS5_VERSION {
            return Err(Socks5Failure::Protocol("request is not SOCKS5"));
        }
        if request[2] != 0 {
            return Err(Socks5Failure::Protocol("invalid reserved byte"));
        }
        if request[1] != CMD_CONNECT {
            let _ = reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await;
            return Err(Socks5Failure::Protocol("only CONNECT is supported"));
        }

        let host = match request[3] {
            ATYP_IPV4 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                IpAddr::V4(Ipv4Addr::from(octets)).to_string()
            }
            ATYP_IPV6 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                IpAddr::V6(Ipv6Addr::from(octets)).to_string()
            }
            ATYP_DOMAIN => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await?;
                if length[0] == 0 {
                    let _ = reply(stream, REPLY_GENERAL_FAILURE).await;
                    return Err(Socks5Failure::Protocol("empty destination name"));
                }
                let mut name = vec![0u8; length[0] as usize];
                stream.read_exact(&mut name).await?;
                match String::from_utf8(name) {
                    Ok(name) => name,
                    Err(_) => {
                        let _ = reply(stream, REPLY_GENERAL_FAILURE).await;
                        return Err(Socks5Failure::Protocol("destination name is not UTF-8"));
                    }
                }
            }
            _ => {
                let _ = reply(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await;
                return Err(Socks5Failure::Protocol("unsupported address type"));
            }
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        Ok((host, u16::from_be_bytes(port)))
    }
}

/// Whether a supplied credential equals the expected one, in time that does
/// not depend on where, or whether, they differ.
///
/// RFC 1929 caps each value at 255 bytes, so both are copied into zeroed
/// buffers of 256 bytes and every byte is compared. The lengths are compared
/// too, folded into the same result, so a shorter value padded with zeros
/// cannot match and a length mismatch does not end the comparison early.
fn credential_matches(expected: &[u8], supplied: &[u8]) -> bool {
    const WIDTH: usize = 256;
    // Neither length is secret here: the expected one is checked at
    // construction and the supplied one came off the wire.
    if expected.len() >= WIDTH || supplied.len() >= WIDTH {
        return false;
    }
    let mut want = [0u8; WIDTH];
    let mut got = [0u8; WIDTH];
    want[..expected.len()].copy_from_slice(expected);
    got[..supplied.len()].copy_from_slice(supplied);
    // Both lengths are below 256, so the XOR fits in a byte.
    let mut difference = (expected.len() ^ supplied.len()) as u8;
    for (want, got) in want.iter().zip(got.iter()) {
        difference |= want ^ got;
    }
    std::hint::black_box(difference) == 0
}

/// Read from a client whose tunnel is still dialling. Returns only when the
/// client closes, fails, or sends more than [`MAX_EARLY_DATA`]; anything it
/// sends before that is appended to `early` for the tunnel.
///
/// A client may legitimately send its first bytes (a TLS ClientHello, an HTTP
/// request head) before the CONNECT reply, so readable data is not a
/// disconnect. Only end of stream or an error is.
async fn watch_client<S>(stream: &mut S, early: &mut Vec<u8>) -> Socks5Failure
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => return Socks5Failure::Protocol("client left before the tunnel connected"),
            Ok(read) if early.len() + read > MAX_EARLY_DATA => {
                return Socks5Failure::Protocol("client sent too much before the CONNECT reply");
            }
            Ok(read) => early.extend_from_slice(&chunk[..read]),
            Err(error) => return Socks5Failure::Io(error),
        }
    }
}

/// Map a dial failure onto the closest SOCKS5 reply code. reqwest reports every
/// one of these as a connect error, which is what makes the proxy-hop
/// classification in `transport_proxy` fire.
fn reply_code_for(error: &TunnelError) -> u8 {
    match error {
        TunnelError::Dial { detail, .. } if detail.contains("ConnectFailed") => {
            REPLY_CONNECTION_REFUSED
        }
        TunnelError::Dial { .. } => REPLY_HOST_UNREACHABLE,
        _ => REPLY_GENERAL_FAILURE,
    }
}

/// A SOCKS5 reply with a zeroed bound address. The client never uses BND.ADDR
/// on a CONNECT, and there is no meaningful local address to report for a
/// stream that lives inside an SSH channel.
async fn reply<S>(stream: &mut S, code: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[SOCKS5_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::net::TcpStream;

    /// A provider that hands back one end of an in-memory duplex and records
    /// what it was asked to dial. No SSH, no sockets.
    struct FakeProvider {
        dialled: Mutex<Vec<(String, u16)>>,
        outcome: Mutex<Option<TunnelError>>,
        echo_prefix: &'static str,
    }

    impl FakeProvider {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                dialled: Mutex::new(Vec::new()),
                outcome: Mutex::new(None),
                echo_prefix: "echo:",
            })
        }

        fn failing(error: TunnelError) -> Arc<Self> {
            Arc::new(Self {
                dialled: Mutex::new(Vec::new()),
                outcome: Mutex::new(Some(error)),
                echo_prefix: "echo:",
            })
        }

        fn dialled(&self) -> Vec<(String, u16)> {
            self.dialled.lock().expect("dialled").clone()
        }
    }

    #[async_trait::async_trait]
    impl TunnelProvider for FakeProvider {
        async fn dial(&self, host: &str, port: u16) -> Result<Box<dyn TunnelStream>, TunnelError> {
            self.dialled
                .lock()
                .expect("dialled")
                .push((host.to_string(), port));
            if let Some(error) = self.outcome.lock().expect("outcome").clone() {
                return Err(error);
            }
            let (near, mut far) = tokio::io::duplex(64 * 1024);
            let prefix = self.echo_prefix;
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 1024];
                while let Ok(read) = far.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    let mut answer = prefix.as_bytes().to_vec();
                    answer.extend_from_slice(&buffer[..read]);
                    if far.write_all(&answer).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(near))
        }

        fn describe(&self) -> String {
            "fake tunnel".to_string()
        }
    }

    /// A provider whose dial never finishes. It says when a dial starts, and
    /// the receiver it hands out resolves when that dial's future is dropped.
    struct StuckProvider {
        started: Arc<tokio::sync::Notify>,
        on_drop: Mutex<Option<oneshot::Sender<()>>>,
    }

    impl StuckProvider {
        fn new() -> (Arc<Self>, Arc<tokio::sync::Notify>, oneshot::Receiver<()>) {
            let started = Arc::new(tokio::sync::Notify::new());
            let (on_drop, dropped) = oneshot::channel();
            let provider = Arc::new(Self {
                started: Arc::clone(&started),
                on_drop: Mutex::new(Some(on_drop)),
            });
            (provider, started, dropped)
        }
    }

    #[async_trait::async_trait]
    impl TunnelProvider for StuckProvider {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            let _signal = self.on_drop.lock().expect("on_drop").take();
            self.started.notify_one();
            std::future::pending().await
        }

        fn describe(&self) -> String {
            "stuck tunnel".to_string()
        }
    }

    /// A provider whose single dial waits for `gate`, then hands back the near
    /// end of a pipe whose far end the test holds.
    struct GatedProvider {
        gate: Arc<tokio::sync::Notify>,
        near: Mutex<Option<tokio::io::DuplexStream>>,
    }

    #[async_trait::async_trait]
    impl TunnelProvider for GatedProvider {
        async fn dial(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Box<dyn TunnelStream>, TunnelError> {
            self.gate.notified().await;
            let near = self.near.lock().expect("near").take().expect("one dial");
            Ok(Box::new(near))
        }

        fn describe(&self) -> String {
            "gated tunnel".to_string()
        }
    }

    struct RecordingObserver {
        failures: Mutex<Vec<String>>,
        successes: Mutex<Vec<String>>,
    }

    impl RecordingObserver {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                failures: Mutex::new(Vec::new()),
                successes: Mutex::new(Vec::new()),
            })
        }
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
        fn host_key_pinned(&self, _proxy_config_id: &str, _fingerprint: &str) {}
    }

    async fn start_front(
        provider: Arc<dyn TunnelProvider>,
        observer: Arc<dyn TunnelObserver>,
    ) -> (SocketAddr, Arc<tokio::sync::Notify>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let front = Arc::new(Socks5Front::new(
            provider,
            observer,
            "proxy-front".to_string(),
            Duration::from_secs(5),
            Socks5Credentials::new("test-user".into(), "test-secret".into()).unwrap(),
            Arc::new(Semaphore::new(MAX_REGISTRY_CONNECTIONS)),
        ));
        tokio::spawn(front.serve(listener, Arc::clone(&shutdown)));
        (addr, shutdown)
    }

    fn test_credentials() -> Socks5Credentials {
        Socks5Credentials::new("test-user".into(), "test-secret".into()).unwrap()
    }

    async fn greet<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> [u8; 2] {
        stream
            .write_all(&[SOCKS5_VERSION, 1, METHOD_PASSWORD])
            .await
            .expect("greeting");
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.expect("method reply");
        stream
            .write_all(b"\x01\x09test-user\x0btest-secret")
            .await
            .unwrap();
        let mut auth = [0; 2];
        stream.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [1, 0]);
        answer
    }

    async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> [u8; 10] {
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.expect("reply");
        reply
    }

    #[tokio::test]
    async fn a_connect_to_a_domain_name_is_dialled_unresolved_and_copies_both_ways() {
        let provider = FakeProvider::new();
        let observer = RecordingObserver::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::clone(&observer) as Arc<dyn TunnelObserver>,
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        assert_eq!(greet(&mut stream).await, [SOCKS5_VERSION, METHOD_PASSWORD]);

        let name = b"indexer.internal";
        let mut request = vec![
            SOCKS5_VERSION,
            CMD_CONNECT,
            0x00,
            ATYP_DOMAIN,
            name.len() as u8,
        ];
        request.extend_from_slice(name);
        request.extend_from_slice(&443u16.to_be_bytes());
        stream.write_all(&request).await.expect("request");

        let reply = read_reply(&mut stream).await;
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REPLY_SUCCEEDED);

        // The name is handed over unresolved: remote DNS is the whole point.
        assert_eq!(
            provider.dialled(),
            vec![("indexer.internal".to_string(), 443)]
        );

        stream.write_all(b"ping").await.expect("payload");
        let mut answer = vec![0u8; 9];
        stream.read_exact(&mut answer).await.expect("echo");
        assert_eq!(&answer, b"echo:ping");

        assert_eq!(
            observer.successes.lock().expect("successes").as_slice(),
            ["proxy-front".to_string()]
        );
    }

    #[tokio::test]
    async fn a_connect_to_an_ipv4_literal_is_dialled() {
        let provider = FakeProvider::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::new(crate::provider::NoopTunnelObserver),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        greet(&mut stream).await;
        let mut request = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
        request.extend_from_slice(&[10, 1, 2, 3]);
        request.extend_from_slice(&8080u16.to_be_bytes());
        stream.write_all(&request).await.expect("request");
        assert_eq!(read_reply(&mut stream).await[1], REPLY_SUCCEEDED);
        assert_eq!(provider.dialled(), vec![("10.1.2.3".to_string(), 8080)]);
    }

    #[tokio::test]
    async fn a_connect_to_an_ipv6_literal_is_dialled() {
        let provider = FakeProvider::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::new(crate::provider::NoopTunnelObserver),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        greet(&mut stream).await;
        let mut request = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6];
        request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&9090u16.to_be_bytes());
        stream.write_all(&request).await.expect("request");
        assert_eq!(read_reply(&mut stream).await[1], REPLY_SUCCEEDED);
        assert_eq!(provider.dialled(), vec![("::1".to_string(), 9090)]);
    }

    #[tokio::test]
    async fn bind_is_rejected_as_an_unsupported_command() {
        let provider = FakeProvider::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::new(crate::provider::NoopTunnelObserver),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        greet(&mut stream).await;
        let mut request = vec![SOCKS5_VERSION, 0x02, 0x00, ATYP_IPV4];
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&80u16.to_be_bytes());
        stream.write_all(&request).await.expect("request");
        assert_eq!(
            read_reply(&mut stream).await[1],
            REPLY_COMMAND_NOT_SUPPORTED
        );
        assert!(provider.dialled().is_empty(), "BIND must not dial");
    }

    #[tokio::test]
    async fn a_non_socks5_greeting_is_refused() {
        let provider = FakeProvider::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::new(crate::provider::NoopTunnelObserver),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(&[0x04, 0x01]).await.expect("greeting");
        let mut answer = [0u8; 1];
        // The front closes without answering a version it does not speak.
        assert!(stream.read_exact(&mut answer).await.is_err());
        assert!(provider.dialled().is_empty());
    }

    #[tokio::test]
    async fn a_no_auth_greeting_is_refused_with_no_acceptable_methods() {
        let provider = FakeProvider::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::new(crate::provider::NoopTunnelObserver),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        // Unauthenticated access is never offered.
        stream
            .write_all(&[SOCKS5_VERSION, 1, 0x00])
            .await
            .expect("greeting");
        let mut answer = [0u8; 2];
        stream.read_exact(&mut answer).await.expect("method reply");
        assert_eq!(answer, [SOCKS5_VERSION, METHOD_NONE_ACCEPTABLE]);
        assert!(provider.dialled().is_empty());
    }

    #[tokio::test]
    async fn a_refused_dial_is_reported_to_the_observer_and_answered_with_a_failure_code() {
        let provider = FakeProvider::failing(TunnelError::Dial {
            host: "indexer.internal".to_string(),
            port: 443,
            detail: "ConnectFailed".to_string(),
        });
        let observer = RecordingObserver::new();
        let (addr, _shutdown) = start_front(
            Arc::clone(&provider) as Arc<dyn TunnelProvider>,
            Arc::clone(&observer) as Arc<dyn TunnelObserver>,
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        greet(&mut stream).await;
        let name = b"indexer.internal";
        let mut request = vec![
            SOCKS5_VERSION,
            CMD_CONNECT,
            0x00,
            ATYP_DOMAIN,
            name.len() as u8,
        ];
        request.extend_from_slice(name);
        request.extend_from_slice(&443u16.to_be_bytes());
        stream.write_all(&request).await.expect("request");

        assert_eq!(read_reply(&mut stream).await[1], REPLY_CONNECTION_REFUSED);
        let failures = observer.failures.lock().expect("failures").clone();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].starts_with("proxy-front: tunnel could not reach indexer.internal:443"),
            "{failures:?}"
        );
    }

    #[tokio::test]
    async fn unauthenticated_and_invalid_clients_never_dial() {
        let provider = FakeProvider::new();
        let observer = RecordingObserver::new();
        let (addr, shutdown) = start_front(provider.clone(), observer.clone()).await;
        for methods in [vec![0], vec![1], vec![]] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut greeting = vec![5, methods.len() as u8];
            greeting.extend(methods);
            stream.write_all(&greeting).await.unwrap();
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 255]);
        }
        for auth in [
            b"\x01\x09test-user\x05wrong".as_slice(),
            b"\x01\x05wrong\x0btest-secret".as_slice(),
            b"\x01\x09test-user\x00".as_slice(),
            b"\x02\x01".as_slice(),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&[5, 2, 0, 2]).await.unwrap();
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 2], "no-auth must never be selected");
            stream.write_all(auth).await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 1]);
        }
        assert!(provider.dialled().is_empty());
        assert!(observer.successes.lock().unwrap().is_empty());
        assert!(observer.failures.lock().unwrap().is_empty());
        shutdown.notify_one();
    }

    /// Greet, authenticate and CONNECT to an IPv4 literal; the reply code.
    async fn connect_ipv4<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> u8 {
        greet(stream).await;
        stream
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        read_reply(stream).await[1]
    }

    async fn wait_for_permits(semaphore: &Semaphore, permits: usize) {
        while semaphore.available_permits() != permits {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn tunnel_limits_cover_dials_and_pumps_and_recover_on_stop() {
        let provider = FakeProvider::new();
        let global = Arc::new(Semaphore::new(3));
        let local = Arc::new(Semaphore::new(2));
        let mut front = Socks5Front::new(
            provider.clone(),
            RecordingObserver::new(),
            "limited".into(),
            Duration::from_secs(3600),
            test_credentials(),
            global.clone(),
        );
        front.connections = local.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(Arc::new(front).serve(listener, shutdown.clone()));

        let mut pumping = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            assert_eq!(connect_ipv4(&mut stream).await, REPLY_SUCCEEDED);
            pumping.push(stream);
        }
        assert_eq!(local.available_permits(), 0);
        assert_eq!(global.available_permits(), 1);

        // An unfinished handshake takes no tunnel capacity.
        let mut handshake = TcpStream::connect(addr).await.unwrap();
        handshake.write_all(&[5, 1, 2]).await.unwrap();
        let mut response = [0; 2];
        handshake.read_exact(&mut response).await.unwrap();
        assert_eq!(local.available_permits(), 0);
        assert_eq!(global.available_permits(), 1);

        // An authenticated connection past this front's budget is refused.
        let mut excess = TcpStream::connect(addr).await.unwrap();
        assert_eq!(connect_ipv4(&mut excess).await, REPLY_GENERAL_FAILURE);
        assert_eq!(excess.read(&mut response).await.unwrap(), 0);
        drop(pumping.pop());
        wait_for_permits(&local, 1).await;

        // A different front shares the registry budget.
        let other_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other_addr = other_listener.local_addr().unwrap();
        let other = Arc::new(Socks5Front::new(
            provider,
            RecordingObserver::new(),
            "other".into(),
            Duration::from_secs(3600),
            test_credentials(),
            global.clone(),
        ));
        let other_task =
            tokio::spawn(other.serve(other_listener, Arc::new(tokio::sync::Notify::new())));
        let mut held = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect(other_addr).await.unwrap();
            assert_eq!(connect_ipv4(&mut stream).await, REPLY_SUCCEEDED);
            held.push(stream);
        }
        assert_eq!(global.available_permits(), 0);
        let mut excess = TcpStream::connect(addr).await.unwrap();
        assert_eq!(connect_ipv4(&mut excess).await, REPLY_GENERAL_FAILURE);
        assert_eq!(excess.read(&mut response).await.unwrap(), 0);
        wait_for_permits(&local, 1).await;

        task.abort();
        let _ = task.await;
        other_task.abort();
        let _ = other_task.await;
        wait_for_permits(&global, 3).await;
        assert_eq!(local.available_permits(), 2);
        assert_eq!(pumping[0].read(&mut response).await.unwrap(), 0);
        assert_eq!(held[0].read(&mut response).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn idle_unauthenticated_clients_cannot_take_tunnel_capacity() {
        let provider = FakeProvider::new();
        let global = Arc::new(Semaphore::new(2));
        let local = Arc::new(Semaphore::new(2));
        let mut front = Socks5Front::new(
            provider.clone(),
            RecordingObserver::new(),
            "crowded".into(),
            Duration::from_secs(3600),
            test_credentials(),
            global.clone(),
        );
        front.connections = local.clone();
        front.handshake_capacity = 2;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(tokio::sync::Notify::new());
        tokio::spawn(Arc::new(front).serve(listener, shutdown.clone()));

        // Fill the handshake places with clients that get as far as the
        // method reply and then say nothing.
        let mut idle = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&[5, 1, 2]).await.unwrap();
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 2]);
            idle.push(stream);
        }
        // None of them holds tunnel capacity.
        assert_eq!(local.available_permits(), 2);
        assert_eq!(global.available_permits(), 2);

        // A client with the credentials still gets its tunnel.
        let mut client = TcpStream::connect(addr).await.unwrap();
        greet(&mut client).await;
        client
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(read_reply(&mut client).await[1], REPLY_SUCCEEDED);
        client.write_all(b"ping").await.unwrap();
        let mut answer = [0u8; 9];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"echo:ping");
        assert_eq!(local.available_permits(), 1);
        assert_eq!(global.available_permits(), 1);

        // The oldest idle handshake made room for it.
        let mut byte = [0u8; 1];
        assert_eq!(idle[0].read(&mut byte).await.unwrap(), 0);
        shutdown.notify_one();
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_handshake_is_dropped_after_the_negotiation_budget() {
        // The request timeout is an hour; the handshake must not get it.
        let request_timeout = Duration::from_secs(3600);
        let front = Arc::new(Socks5Front::new(
            FakeProvider::new(),
            RecordingObserver::new(),
            "slow".into(),
            request_timeout,
            test_credentials(),
            Arc::new(Semaphore::new(1)),
        ));
        let (mut client, server) = tokio::io::duplex(1024);
        let began = tokio::time::Instant::now();
        let task = tokio::spawn({
            let front = Arc::clone(&front);
            async move { front.handle_connection(server).await }
        });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 2]);

        // Silence from here. The front closes the pipe when its budget runs
        // out; the clock is paused, so this reads virtual time only.
        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert!(task.await.unwrap().is_err());
        let waited = began.elapsed();
        assert!(waited >= NEGOTIATION_TIMEOUT, "{waited:?}");
        assert!(waited < request_timeout, "{waited:?}");
        assert!(front.handshakes.lock().unwrap().waiting.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_leaves_during_the_dial_cancels_it_and_frees_its_slot() {
        let (provider, started, dropped) = StuckProvider::new();
        let local = Arc::new(Semaphore::new(1));
        let mut front = Socks5Front::new(
            provider,
            RecordingObserver::new(),
            "stuck".into(),
            Duration::from_secs(3600),
            test_credentials(),
            Arc::new(Semaphore::new(1)),
        );
        front.connections = local.clone();
        let front = Arc::new(front);
        let (mut client, server) = tokio::io::duplex(1024);
        let began = tokio::time::Instant::now();
        let task = tokio::spawn({
            let front = Arc::clone(&front);
            async move { front.handle_connection(server).await }
        });
        greet(&mut client).await;
        client
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        started.notified().await;
        assert_eq!(local.available_permits(), 0);

        drop(client);
        assert!(dropped.await.is_err(), "the dial future was dropped");
        assert!(task.await.unwrap().is_err());
        assert!(local.try_acquire().is_ok());
        // The clock is paused and never moved: the client's leaving ended the
        // dial, not the request timeout.
        assert_eq!(began.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn bytes_sent_before_the_reply_reach_the_tunnel_first() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let provider = Arc::new(GatedProvider {
            gate: Arc::clone(&gate),
            near: Mutex::new(Some(near)),
        });
        let front = Arc::new(Socks5Front::new(
            provider,
            RecordingObserver::new(),
            "early".into(),
            Duration::from_secs(3600),
            test_credentials(),
            Arc::new(Semaphore::new(1)),
        ));
        // A small pipe: the early bytes below fit only if the front reads
        // them while the dial is still waiting.
        let (mut client, server) = tokio::io::duplex(64);
        let task = tokio::spawn({
            let front = Arc::clone(&front);
            async move { front.handle_connection(server).await }
        });
        greet(&mut client).await;
        client
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let early: Vec<u8> = (0..200u8).collect();
        client.write_all(&early).await.unwrap();

        gate.notify_one();
        assert_eq!(read_reply(&mut client).await[1], REPLY_SUCCEEDED);
        let mut arrived = vec![0u8; early.len()];
        far.read_exact(&mut arrived).await.unwrap();
        assert_eq!(arrived, early);

        // The tunnel carries on as usual after the early bytes.
        client.write_all(b"later").await.unwrap();
        let mut later = [0u8; 5];
        far.read_exact(&mut later).await.unwrap();
        assert_eq!(&later, b"later");
        drop(client);
        drop(far);
        let _ = task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn too_many_bytes_before_the_reply_end_the_connection_and_the_dial() {
        let (provider, started, dropped) = StuckProvider::new();
        let front = Arc::new(Socks5Front::new(
            provider,
            RecordingObserver::new(),
            "flood".into(),
            Duration::from_secs(3600),
            test_credentials(),
            Arc::new(Semaphore::new(1)),
        ));
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn({
            let front = Arc::clone(&front);
            async move { front.handle_connection(server).await }
        });
        greet(&mut client).await;
        client
            .write_all(&[5, 1, 0, 1, 10, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        started.notified().await;
        // The front stops reading past its bound and closes the pipe, so the
        // write may fail part way; what matters is what the front did.
        let _ = client.write_all(&vec![0u8; MAX_EARLY_DATA + 1]).await;
        assert!(dropped.await.is_err(), "the dial future was dropped");
        assert!(task.await.unwrap().is_err());
    }

    #[test]
    fn credentials_match_only_when_equal_in_content_and_length() {
        assert!(credential_matches(b"test-secret", b"test-secret"));
        assert!(credential_matches(&[0xff; 255], &[0xff; 255]));
        assert!(!credential_matches(b"test-secret", b"test-secreT"));
        assert!(!credential_matches(b"test-secret", b"Test-secret"));
        // A prefix, an extension, and padding that only zeros could hide.
        assert!(!credential_matches(b"test-secret", b"test-secre"));
        assert!(!credential_matches(b"test-secret", b"test-secretX"));
        assert!(!credential_matches(b"secret", b"secret\0"));
        assert!(!credential_matches(b"secret", b""));
        assert!(!credential_matches(&[0xff; 255], &[0xff; 254]));
    }

    #[tokio::test]
    async fn a_right_username_with_a_near_miss_password_is_refused() {
        let provider = FakeProvider::new();
        let (addr, shutdown) = start_front(provider.clone(), RecordingObserver::new()).await;
        for auth in [
            b"\x01\x09test-user\x0atest-secre".as_slice(),
            b"\x01\x09test-user\x0ctest-secretX".as_slice(),
            b"\x01\x0atest-userX\x0btest-secret".as_slice(),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&[5, 1, 2]).await.unwrap();
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.unwrap();
            stream.write_all(auth).await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 1]);
        }
        assert!(provider.dialled().is_empty());
        shutdown.notify_one();
    }

    #[test]
    fn only_loopback_peers_are_served() {
        assert!(peer_is_permitted(&"127.0.0.1:5000".parse().expect("addr")));
        assert!(peer_is_permitted(&"[::1]:5000".parse().expect("addr")));
        assert!(!peer_is_permitted(&"10.0.0.4:5000".parse().expect("addr")));
        assert!(!peer_is_permitted(
            &"[2001:db8::1]:5000".parse().expect("addr")
        ));
    }
}
