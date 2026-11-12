//! The WireGuard implementation of [`TunnelProvider`], entirely in process.
//!
//! ```text
//!   caller ──▶ SOCKS5 front ──▶ WireGuardTunnelProvider::dial
//!                                 │
//!                                 ├─ resolve the name *through* the tunnel (smoltcp DNS)
//!                                 └─ open a TCP socket on the tunnel's smoltcp interface
//!                                       │
//!                                    the tunnel's engine — one task: decrypt, poll, encrypt
//!                                       │  (gotatun's Tunn: handshake, encrypt, rekey, keepalive)
//!                                       │
//!                                    Tokio UDP socket on an ephemeral local port
//! ```
//!
//! Nothing here needs a `tun` device, a route, a firewall rule or a
//! capability: the "network interface" is a queue in memory, and the only
//! socket the operating system sees is one ordinary UDP socket. That is what
//! makes a VPN tunnel usable from inside a container that has no `NET_ADMIN`,
//! and it is why this can be a per-proxy tunnel rather than a machine-wide one.
//!
//! ## What each half owns
//!
//! * **gotatun** owns the protocol: the Noise handshake, encryption, rekeying,
//!   keepalives, session state and the WireGuard timers.
//! * **smoltcp** owns everything above IP: the interface, TCP, UDP and DNS.
//! * This module owns the engine that moves packets between the two and the
//!   UDP socket ([`engine`]), and the lifecycle.
//!
//! ## Identity
//!
//! There is no trust-on-first-use step and no host key to learn, so
//! [`TunnelObserver::host_key_pinned`] is never called for this family. The
//! peer's public key *is* its identity, the operator configures it up front,
//! and a peer that does not hold the matching private key simply never
//! answers — which is also why a wrong key and an unreachable endpoint are
//! indistinguishable from here, and why [`TunnelError::WireGuardConnect`]
//! does not pretend otherwise.
//!
//! ## One tunnel inside another
//!
//! A tunnel's encrypted packets normally leave through an OS UDP socket. Built
//! with [`WireGuardTunnelProvider::with_datagram_transport`] they leave through
//! a [`DatagramSocket`] instead, and every [`WireGuardTunnelProvider`] is
//! itself a [`DatagramTransport`] that binds such sockets on its own stack. So
//! a tunnel can ride inside another:
//!
//! ```text
//!   inner smoltcp ─▶ inner engine ─▶ UDP socket on the outer stack
//!                                        ─▶ outer engine ─▶ OS UDP socket
//! ```
//!
//! The outer peer only ever sees the inner tunnel's WireGuard datagrams. The
//! inner tunnel's MTU shrinks by the outer IP, UDP and WireGuard headers it
//! now has to fit inside ([`carried_mtu`]), the inner endpoint name resolves
//! through the outer tunnel's resolver, and an inner tunnel whose carrier
//! stopped is treated as dead rather than waited on.

#[cfg(any(test, feature = "test-support"))]
mod adapter;
mod engine;
mod phy;
mod spec;
mod stack;
mod tcp;
mod transport;
mod udp;
mod worker;

#[cfg(test)]
mod stacked_tests;
#[cfg(any(test, feature = "test-support"))]
mod test_peer;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use gotatun::packet::{Ip, IpNextProtocol, Ipv4Header, Packet};
use gotatun::udp::UdpTransportFactory as _;
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;
use tokio::sync::Notify;

use crate::endpoint::{DatagramSocket, DatagramTransport};
use crate::error::TunnelError;
use crate::provider::{TunnelObserver, TunnelProvider, TunnelStream};

pub use spec::{
    DEFAULT_WIREGUARD_KEEPALIVE, DEFAULT_WIREGUARD_MTU, IpCidr, MAX_WIREGUARD_MTU,
    MIN_WIREGUARD_MTU, WIREGUARD_KEY_MESSAGE, WireGuardSpec, parse_key, public_key_of,
    validate_wireguard_keys,
};
pub use stack::{DEFAULT_MAX_SOCKETS, MAX_MAX_SOCKETS, MIN_MAX_SOCKETS, WgStack, socket_cap};
pub use tcp::{WgTcpListener, WgTcpStream};
pub use udp::WgUdpSocket;

#[cfg(any(test, feature = "test-support"))]
pub use test_peer::{
    ForwardedUdp, TEST_CLIENT_ADDRESS, TEST_PEER_ADDRESS, TEST_PEER_HTTP_PORT, WireGuardTestPeer,
    WireGuardTestPeerOptions, is_wireguard_message, test_client_private_key, test_key,
    test_peer_private_key, test_preshared_key,
};

pub(crate) use stack::StackConfig;

/// gotatun's own point of no return: after three times `REJECT_AFTER_TIME`
/// with no handshake it clears its keys and the session is unrecoverable.
/// A tunnel that has been silent for this long is dead, not slow.
const SESSION_EXPIRY: Duration = Duration::from_secs(180 * 3);

/// How often to look for the first handshake while bringing a tunnel up.
const HANDSHAKE_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long a bring-up waits on its first handshake initiation before it
/// sends a fresh one. gotatun retries an unanswered initiation only after
/// `REKEY_TIMEOUT`, five seconds, and a first initiation lost on the way, or
/// sent while the server still holds a session for the same key elsewhere,
/// would cost every bring-up that long. One early retry, with fresh
/// handshake state, takes that down to this; later retries keep gotatun's
/// own timers. gotatun as a responder counts handshakes per source address
/// against a limit of 100 a second before it answers with a cookie, so one
/// more initiation a second later stays far below it, and the fresh state
/// stamps it later than the first, as the responder requires.
const BRING_UP_RESEND: Duration = Duration::from_secs(1);

/// WireGuard's `REKEY_AFTER_TIME`. A peer that completed a handshake more
/// recently than this has proven, cryptographically, that it is alive, so a
/// dial that answered nothing inside such a window is the *destination*
/// keeping quiet (a firewalled port drops SYNs without a word), not the
/// tunnel. Rebuilding the session for every such dial would churn a healthy
/// tunnel on every unreachable host behind it.
const RECENT_HANDSHAKE: Duration = Duration::from_secs(120);

/// What WireGuard adds to every packet it carries: a 16-byte data-message
/// header (type, receiver index, counter) and a 16-byte authentication tag.
pub const WIREGUARD_DATA_OVERHEAD: u16 = 32;

/// The UDP header every WireGuard packet travels in.
const UDP_HEADER: u16 = 8;

/// The smallest MTU a tunnel carried inside another may be left with: the
/// minimum datagram every IPv4 host must accept. A link too narrow for this
/// is too narrow to carry a tunnel usefully.
pub const MIN_CARRIED_MTU: u16 = 576;

/// The MTU of a tunnel carried over a link of `link_mtu` to `endpoint`.
///
/// Every packet of the carried tunnel becomes one UDP datagram on the link,
/// grown by WireGuard's own overhead, a UDP header and the link's IP header
/// (20 bytes to an IPv4 endpoint, 40 to an IPv6 one). The carried tunnel must
/// leave room for all of that, so its MTU is the smaller of what the operator
/// configured and what the link leaves over. Without this, every full-sized
/// packet would be too large for the link and silently lost.
///
/// What the link leaves over is rounded down to a multiple of 16. WireGuard
/// pads every packet up to a multiple of 16, bounded only by the *sender's*
/// MTU, and the peer at the far end of the carried tunnel has its own,
/// usually larger, MTU. A packet that fits exactly could still grow by up to
/// 15 bytes of padding on its way back and no longer fit the link; one sized
/// to a multiple of 16 never grows.
pub fn carried_mtu(configured: u16, link_mtu: u16, endpoint: IpAddr) -> Result<u16, TunnelError> {
    let ip_header: u16 = if endpoint.is_ipv4() { 20 } else { 40 };
    let overhead = ip_header + UDP_HEADER + WIREGUARD_DATA_OVERHEAD;
    let available = link_mtu.saturating_sub(overhead) & !15;
    if available < MIN_CARRIED_MTU {
        return Err(TunnelError::Configuration(format!(
            "the tunnel beneath has an MTU of {link_mtu}, which leaves {available} bytes per \
             packet once this tunnel's {overhead} bytes of headers are added; at least \
             {MIN_CARRIED_MTU} are needed. Raise the MTU of the tunnel beneath."
        )));
    }
    Ok(configured.min(available))
}

/// What one successful handshake established. Returned by the health probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireGuardHandshake {
    /// `host:port` of the peer's UDP endpoint, as configured.
    pub endpoint: String,
    /// The peer's base64 public key. Its identity, and safe to show.
    pub peer_public_key: String,
    /// *Our* base64 public key — the line the operator must have put in the
    /// server's `[Peer]` section. Reporting it is what turns "it does not
    /// connect" into "you configured the wrong key over there".
    pub our_public_key: String,
    /// How long the handshake took: from queuing the packet that makes the
    /// device initiate to the first check that finds the session established,
    /// so it reads high by at most one poll interval and never low.
    pub handshake_at: Duration,
}

/// One live WireGuard tunnel: a smoltcp stack and the engine that drives it.
struct WgTunnel {
    stack: WgStack,
    /// The engine's task. It owns the UDP socket and the WireGuard session;
    /// once it ends, the stack is stopped and nothing moves again.
    pump: tokio::task::JoinHandle<()>,
    /// What the engine reports: when it last completed a handshake.
    engine: Arc<engine::EngineStatus>,
    shutdown: Arc<Notify>,
    handshake_at: Duration,
    /// The socket this tunnel rides on when it is carried by another
    /// transport. Once it closes, the tunnel can never move a packet again.
    carrier: Option<Arc<dyn DatagramSocket>>,
    /// Stops the pump once the carrier closes, so a carried tunnel whose
    /// carrier is gone ends its connections instead of leaving them waiting
    /// for packets that can never arrive.
    carrier_watch: Option<tokio::task::JoinHandle<()>>,
    /// The runtime the engine's task lives on. The registry drops tunnels
    /// from plain threads (a config update on the blocking plugin worker,
    /// `stop_all` at shutdown), so the drop stops the engine by spawning onto
    /// this handle rather than the current one, which may not exist.
    runtime: tokio::runtime::Handle,
    /// The thread `runtime` belongs to, for a tunnel built with download
    /// tuning (see [`worker`]); `None` when the tasks run on the caller's
    /// runtime.
    worker: Option<worker::TunnelWorker>,
}

impl WgTunnel {
    /// Whether this tunnel is still worth dialling on.
    ///
    /// Two ways to be dead: the engine stopped, or the peer has gone quiet
    /// for longer than WireGuard itself will tolerate, at which point gotatun
    /// has thrown its keys away and no amount of waiting brings the session
    /// back.
    async fn is_alive(&self) -> bool {
        if self.pump.is_finished() {
            return false;
        }
        if self
            .carrier
            .as_ref()
            .is_some_and(|carrier| carrier.is_closed())
        {
            return false;
        }
        match self.last_handshake_age() {
            Some(age) => age < SESSION_EXPIRY,
            None => false,
        }
    }

    fn last_handshake_age(&self) -> Option<Duration> {
        self.engine.last_handshake_age()
    }
}

impl Drop for WgTunnel {
    fn drop(&mut self) {
        // The engine stops on its runtime whatever thread this drop runs on
        // (see the field's comment for why that matters), and its socket
        // closes with it.
        let shutdown = Arc::clone(&self.shutdown);
        let pump = self.pump.abort_handle();
        let watch = self
            .carrier_watch
            .as_ref()
            .map(tokio::task::JoinHandle::abort_handle);
        // A tunnel thread ends once this teardown has run on it.
        let thread = self.worker.as_mut().and_then(worker::TunnelWorker::release);
        self.runtime.spawn(async move {
            shutdown.notify_waiters();
            pump.abort();
            if let Some(watch) = watch {
                watch.abort();
            }
            drop(thread);
        });
    }
}

/// A WireGuard tunnel to one configured peer.
pub struct WireGuardTunnelProvider {
    spec: WireGuardSpec,
    observer: Arc<dyn TunnelObserver>,
    tunnel: tokio::sync::Mutex<Option<Arc<WgTunnel>>>,
    download_tuning: bool,
    udp_factory: Option<Arc<dyn crate::endpoint::UdpSocketFactory>>,
    datagram: Option<Arc<dyn DatagramTransport>>,
    endpoint_resolver: Option<Arc<dyn crate::endpoint::EndpointResolver>>,
    source: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl WireGuardTunnelProvider {
    /// Build a provider. No I/O happens here.
    ///
    /// Deliberately the same shape as [`crate::SshTunnelProvider::new`]: the
    /// registry's factory closure is synchronous and is called from paths with
    /// no runtime at all (a blocking plugin worker), so bringing the tunnel up
    /// has to be the first dial's job. A failed bring-up therefore leaves the
    /// provider empty rather than poisoned, so the next dial tries again
    /// instead of the proxy being dead until a restart.
    pub fn new(spec: WireGuardSpec, observer: Arc<dyn TunnelObserver>) -> Self {
        Self {
            spec,
            observer,
            tunnel: tokio::sync::Mutex::new(None),
            download_tuning: false,
            udp_factory: None,
            datagram: None,
            endpoint_resolver: None,
            source: Arc::new(std::sync::Mutex::new(None)),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Opt into 1 MiB TCP buffers in each direction and a larger UDP receive
    /// buffer for concurrent bulk downloads. At the 256-socket limit, TCP
    /// buffers alone can consume 512 MiB. Ordinary providers retain 64 KiB
    /// buffers and the operating system's UDP defaults.
    ///
    /// A tuned tunnel also runs its device and stack on a thread of its own,
    /// so its packets pass between its tasks without waking the caller's
    /// runtime workers. Each tunnel then uses at most one core.
    pub fn with_download_tuning(mut self) -> Self {
        self.download_tuning = true;
        self
    }

    /// Bind the tunnel's OS UDP socket through `factory`, for example on a
    /// chosen egress interface.
    pub fn with_udp_factory(mut self, factory: Arc<dyn crate::endpoint::UdpSocketFactory>) -> Self {
        self.udp_factory = Some(factory);
        self.datagram = None;
        self
    }

    /// Resolve an endpoint name with `resolver`. A tunnel carried by a
    /// [`DatagramTransport`] asks that transport instead, and an endpoint
    /// written as an address is never resolved.
    pub fn with_endpoint_resolver(
        mut self,
        resolver: Arc<dyn crate::endpoint::EndpointResolver>,
    ) -> Self {
        self.endpoint_resolver = Some(resolver);
        self
    }

    /// Carry the tunnel over `transport` instead of an OS UDP socket.
    ///
    /// The endpoint name then resolves on the transport's far side, and the
    /// tunnel's MTU is reduced to fit inside the transport's link
    /// ([`carried_mtu`]). Replaces any [`Self::with_udp_factory`].
    pub fn with_datagram_transport(mut self, transport: Arc<dyn DatagramTransport>) -> Self {
        self.datagram = Some(transport);
        self.udp_factory = None;
        self
    }

    /// Carry the tunnel inside `outer`: its peer is reached through the outer
    /// tunnel, which only ever sees this tunnel's encrypted datagrams.
    pub fn with_inner_wireguard(self, outer: Arc<WireGuardTunnelProvider>) -> Self {
        self.with_datagram_transport(outer)
    }

    /// Accept TCP connections on `port` inside the tunnel, bringing the tunnel
    /// up if it is not. `0` picks a free ephemeral port; the listener's
    /// [`WgTcpListener::local_addr`] says which.
    ///
    /// The listener belongs to the tunnel that is current now. When that
    /// tunnel is replaced (a silent peer, a retire) its stack stops and
    /// [`WgTcpListener::accept`] fails, so a caller that wants to keep
    /// listening listens again, on the new tunnel.
    pub async fn listen(&self, port: u16, backlog: usize) -> Result<WgTcpListener, TunnelError> {
        self.tunnel().await?.stack.listen(port, backlog)
    }

    /// Whether the tunnel that is current now is alive and a listener inside
    /// it holds `port`. Never brings a tunnel up: with no live tunnel, nothing
    /// listens.
    pub async fn listens_on(&self, port: u16) -> bool {
        let guard = self.tunnel.lock().await;
        match guard.as_ref() {
            Some(tunnel) => tunnel.is_alive().await && tunnel.stack.listening_on(port),
            None => false,
        }
    }

    /// Resolve a destination using only this tunnel's configured DNS servers.
    pub async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, TunnelError> {
        self.tunnel()
            .await?
            .stack
            .resolve(host, self.spec.request_timeout)
            .await
    }

    /// Bring a tunnel up, report what the handshake established, tear it down.
    ///
    /// This is the health probe's entry point. Like the SSH one it deliberately
    /// does not touch the registry: probing must not leave a device behind, and
    /// it must fail with the real reason rather than "the proxy is unreachable".
    pub async fn handshake(
        spec: WireGuardSpec,
        observer: Arc<dyn TunnelObserver>,
    ) -> Result<WireGuardHandshake, TunnelError> {
        WireGuardTunnelProvider::new(spec, observer)
            .probe_handshake()
            .await
    }

    /// Bring this provider's tunnel up once, as configured (including any
    /// carrier set with [`Self::with_datagram_transport`]), report what the
    /// handshake established and tear it down. The provider's own session is
    /// neither used nor kept.
    pub async fn probe_handshake(&self) -> Result<WireGuardHandshake, TunnelError> {
        let spec = &self.spec;
        let endpoint = spec.endpoint_description();
        let peer_public_key = base64_of(&spec.peer_public_key);
        let our_public_key = spec.public_key();
        let tunnel = self.bring_up(self.request_deadline()).await?;
        let handshake = WireGuardHandshake {
            endpoint,
            peer_public_key,
            our_public_key,
            handshake_at: tunnel.handshake_at,
        };
        drop(tunnel);
        Ok(handshake)
    }

    /// The tunnel's stack, bringing the tunnel up if there is none.
    ///
    /// Also the place a dead tunnel is noticed: a device whose peer has been
    /// silent past WireGuard's own expiry is replaced here rather than being
    /// discovered by a dial that then has to unwind.
    async fn tunnel(&self) -> Result<Arc<WgTunnel>, TunnelError> {
        let mut guard = self.tunnel.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TunnelError::Engine("tunnel provider stopped".into()));
        }
        if let Some(existing) = guard.as_ref() {
            if existing.is_alive().await {
                return Ok(Arc::clone(existing));
            }
            tracing::debug!(
                proxy_config_id = self.spec.proxy_config_id.as_str(),
                tunnel = self.spec.describe().as_str(),
                "the WireGuard session went stale; bringing the tunnel up again"
            );
            *guard = None;
        }
        let tunnel = Arc::new(self.bring_up(self.request_deadline()).await?);
        *guard = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    /// When a request that starts now must be done by.
    fn request_deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.spec.request_timeout
    }

    /// Drop `stale` if it is still the current tunnel, and build a new one
    /// by `deadline`.
    async fn replace_tunnel(
        &self,
        stale: &Arc<WgTunnel>,
        deadline: tokio::time::Instant,
    ) -> Result<Arc<WgTunnel>, TunnelError> {
        let mut guard = self.tunnel.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TunnelError::Engine("tunnel provider stopped".into()));
        }
        if let Some(current) = guard.as_ref()
            && !Arc::ptr_eq(current, stale)
        {
            // Another dial already rebuilt it; use theirs.
            return Ok(Arc::clone(current));
        }
        *guard = None;
        let tunnel = Arc::new(self.bring_up(deadline).await?);
        *guard = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    /// Everything between "a validated spec" and "a tunnel that has shaken
    /// hands": resolve the endpoint, start the stack, build the device, prove
    /// the peer answers. Resolution and the handshake share one deadline.
    async fn bring_up(&self, deadline: tokio::time::Instant) -> Result<WgTunnel, TunnelError> {
        self.spec.validate()?;

        let caller = tokio::runtime::Handle::try_current().map_err(|_| {
            TunnelError::Engine("a WireGuard tunnel needs a tokio runtime".to_string())
        })?;
        // A tuned tunnel's device and pump run on a thread of their own.
        let worker = if self.download_tuning {
            Some(worker::TunnelWorker::start(&self.spec.proxy_config_id)?)
        } else {
            None
        };
        let runtime = worker
            .as_ref()
            .map_or(caller, |worker| worker.handle().clone());

        let endpoint = self.resolve_endpoint(deadline).await?;

        // A carried tunnel binds its socket first: the link it lands on
        // decides how large this tunnel's packets may be. Binding may bring
        // the carrier up from cold, which the carrier bounds by its own
        // timeouts; this tunnel's request timeout covers only its own
        // handshake.
        let (datagram, carrier, mtu) = match &self.datagram {
            None => (None, None, self.spec.mtu),
            Some(transport) => {
                let carrier = transport
                    .bind(endpoint)
                    .await
                    .map_err(|error| self.carrier_failure(error.to_string()))?;
                let mtu = match carrier.link_mtu() {
                    Some(link) => carried_mtu(self.spec.mtu, link, endpoint.ip())?,
                    None => self.spec.mtu,
                };
                let binding = transport::DatagramBinding {
                    transport: Arc::clone(transport),
                    peer: endpoint,
                    prebound: Some(Arc::clone(&carrier)),
                };
                (Some(binding), Some(carrier), mtu)
            }
        };

        let stack = WgStack::build_for_engine(StackConfig {
            addresses: self.spec.addresses.clone(),
            dns_servers: self.spec.dns_servers.clone(),
            mtu,
            proxy_config_id: self.spec.proxy_config_id.clone(),
            download_tuning: self.download_tuning,
            max_sockets: stack::socket_cap(self.spec.max_sockets),
        });

        // An ephemeral local port on an ordinary UDP socket. No listen port is
        // configured: nothing dials *us*. The socket is bound on the runtime
        // the engine runs on, whose reactor then serves it.
        let mut factory = transport::TunnelUdpFactory {
            tuning: self.download_tuning,
            bound: self.udp_factory.clone().map(|factory| (factory, endpoint)),
            source: self.source.clone(),
            datagram,
        };
        let params = os_socket_params(endpoint);
        let bound = match &worker {
            None => factory
                .bind(&params)
                .await
                .map_err(|error| error.to_string()),
            Some(_) => match runtime
                .spawn(async move { factory.bind(&params).await })
                .await
            {
                Ok(bound) => bound.map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            },
        };
        let (send, recv) = bound.map_err(|detail| TunnelError::WireGuardConnect {
            host: self.spec.endpoint_host.clone(),
            port: self.spec.endpoint_port,
            detail,
        })?;

        // The engine starts by sending the probe, which makes it initiate:
        // WireGuard only handshakes when it has something to send, so a
        // tunnel with no persistent keepalive would otherwise sit idle until
        // the first dial, and the point of waiting here is that a wrong key or
        // an unreachable endpoint surfaces as a connect error rather than as a
        // mysteriously slow first request.
        let probe_spec = self.spec.clone();
        let config = engine::EngineConfig {
            private_key: StaticSecret::from(self.spec.private_key),
            peer_public_key: PublicKey::from(self.spec.peer_public_key),
            preshared_key: self.spec.preshared_key,
            persistent_keepalive: self.spec.persistent_keepalive,
            endpoint,
            allowed: allowed_networks(&self.spec),
            mtu,
            probe: Box::new(move || handshake_probe(&probe_spec)),
            own_thread: worker.is_some(),
        };
        let status = Arc::new(engine::EngineStatus::default());
        let shutdown = Arc::new(Notify::new());
        let probed = std::time::Instant::now();
        let pump = runtime.spawn(
            engine::Engine::new(config, send, recv, Arc::clone(&status))
                .run(Arc::clone(stack.shared()), Arc::clone(&shutdown)),
        );

        let handshake_at = match self
            .await_handshake(&stack, &status, &pump, probed, deadline)
            .await
        {
            Ok(handshake_at) => handshake_at,
            Err(error) => {
                shutdown.notify_waiters();
                pump.abort();
                return Err(error);
            }
        };
        let carrier_watch = carrier.as_ref().map(|carrier| {
            let carrier = Arc::clone(carrier);
            let pump = pump.abort_handle();
            runtime.spawn(async move {
                carrier.closed().await;
                pump.abort();
            })
        });
        tracing::info!(
            proxy_config_id = self.spec.proxy_config_id.as_str(),
            tunnel = self.spec.describe().as_str(),
            handshake_ms = handshake_at.as_millis() as u64,
            mtu,
            carried = carrier.is_some(),
            "brought up a WireGuard tunnel"
        );

        Ok(WgTunnel {
            stack,
            pump,
            engine: status,
            shutdown,
            handshake_at,
            carrier,
            carrier_watch,
            runtime,
            worker,
        })
    }

    /// The tunnel beneath this one could not give it a socket.
    fn carrier_failure(&self, detail: String) -> TunnelError {
        TunnelError::WireGuardConnect {
            host: self.spec.endpoint_host.clone(),
            port: self.spec.endpoint_port,
            detail: format!("the tunnel beneath could not carry this one: {detail}"),
        }
    }

    /// Wait for the peer to answer, and say how long after `probed` it had,
    /// or say that it did not.
    ///
    /// A first initiation still unanswered after [`BRING_UP_RESEND`] is sent
    /// again once: the engine drops its handshake state, which has no session
    /// to lose yet, and initiates afresh. That leaves the engine's socket as
    /// it is, and its timers at gotatun's defaults.
    ///
    /// The time is this function's own measurement, taken at the first check
    /// that finds the session established, so it reads high by at most one
    /// poll interval and never low.
    async fn await_handshake(
        &self,
        stack: &WgStack,
        status: &engine::EngineStatus,
        pump: &tokio::task::JoinHandle<()>,
        probed: std::time::Instant,
        deadline: tokio::time::Instant,
    ) -> Result<Duration, TunnelError> {
        let resend_at = tokio::time::Instant::now() + BRING_UP_RESEND;
        let mut resent = false;
        let waited = tokio::time::timeout_at(deadline, async {
            loop {
                if status.last_handshake_age().is_some() {
                    return Some(probed.elapsed());
                }
                if !resent && tokio::time::Instant::now() >= resend_at {
                    resent = true;
                    status.restart(stack.shared());
                }
                if pump.is_finished() {
                    // The engine died under us; there will never be a
                    // handshake, so do not sit out the whole budget.
                    return None;
                }
                tokio::time::sleep(HANDSHAKE_POLL_INTERVAL).await;
            }
        })
        .await;

        match waited {
            Ok(Some(handshake_at)) => Ok(handshake_at),
            Ok(None) => Err(TunnelError::WireGuardConnect {
                host: self.spec.endpoint_host.clone(),
                port: self.spec.endpoint_port,
                detail: "the tunnel's network stack stopped before the handshake completed"
                    .to_string(),
            }),
            Err(_) => Err(TunnelError::WireGuardConnect {
                host: self.spec.endpoint_host.clone(),
                port: self.spec.endpoint_port,
                detail: format!(
                    "the peer did not complete a handshake within {}s. WireGuard answers nothing \
                     it cannot authenticate, so this is what a wrong private key, a wrong peer \
                     public key, a wrong or missing preshared key and an unreachable endpoint all \
                     look like. Check that the server's `[Peer]` section lists this tunnel's \
                     public key ({}).",
                    self.spec.request_timeout.as_secs().max(1),
                    self.spec.public_key()
                ),
            }),
        }
    }

    /// Resolve the peer's endpoint with the injected resolver, or, for a
    /// carried tunnel, with its carrier's.
    ///
    /// This one name is outside the tunnel by definition: it is the hop that
    /// carries the tunnel, so there is nothing to resolve it through yet. When
    /// another tunnel carries this one, the name means something on *that*
    /// tunnel's far side, so that is where it is asked.
    async fn resolve_endpoint(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<SocketAddr, TunnelError> {
        let host = self.spec.endpoint_host.trim().to_string();
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(address) = bare.parse::<IpAddr>() {
            return Ok(SocketAddr::new(address, self.spec.endpoint_port));
        }

        let port = self.spec.endpoint_port;
        if let Some(transport) = &self.datagram {
            // Asked of the carrier, which may have to come up first and
            // bounds that and the lookup by its own timeouts.
            let addresses = transport.resolve(&host).await.map_err(|error| {
                let detail = format!(
                    "the endpoint name could not be resolved through the tunnel beneath: {error}"
                );
                TunnelError::WireGuardConnect {
                    host: host.clone(),
                    port,
                    detail,
                }
            })?;
            return addresses
                .into_iter()
                .next()
                .map(|address| SocketAddr::new(address, port))
                .ok_or_else(|| TunnelError::WireGuardConnect {
                    host: host.clone(),
                    port,
                    detail: "the endpoint name resolved to no addresses".to_string(),
                });
        }
        let Some(resolver) = &self.endpoint_resolver else {
            return Err(TunnelError::WireGuardConnect {
                host,
                port,
                detail: "the endpoint is a name and no resolver was given for it".to_string(),
            });
        };
        let resolved = tokio::time::timeout_at(deadline, resolver.resolve(&host))
            .await
            .map_err(|_| TunnelError::WireGuardConnect {
                host: host.clone(),
                port,
                detail: "the endpoint name did not resolve in time".to_string(),
            })?;

        let addresses = resolved.map_err(|error| TunnelError::WireGuardConnect {
            host: host.clone(),
            port,
            detail: format!("the endpoint name could not be resolved: {error}"),
        })?;

        addresses
            .into_iter()
            .next()
            .map(|address| SocketAddr::new(address, port))
            .ok_or_else(|| TunnelError::WireGuardConnect {
                host: host.clone(),
                port,
                detail: "the endpoint name resolved to no addresses".to_string(),
            })
    }

    /// One dial attempt on a tunnel that is already up, done by `deadline`.
    ///
    /// Resolution and every address share that deadline. Each address gets
    /// an even share of what is left, so a silent address cannot spend the
    /// time of the addresses after it.
    async fn dial_on(
        &self,
        tunnel: &WgTunnel,
        host: &str,
        port: u16,
        deadline: tokio::time::Instant,
    ) -> Result<Box<dyn TunnelStream>, DialFailure> {
        let out_of_time = || TunnelError::Dial {
            host: host.to_string(),
            port,
            detail: "the tunnel did not open a connection in time".to_string(),
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(DialFailure::Tunnel(out_of_time()));
        }
        let addresses = tunnel
            .stack
            .resolve(host, remaining)
            .await
            .map_err(|error| DialFailure::Destination(relabel(error, host, port)))?;

        let mut last = None;
        let count = addresses.len();
        for (index, address) in addresses.into_iter().enumerate() {
            let share = share_of(deadline, count - index);
            if share.is_zero() {
                last = Some(out_of_time());
                break;
            }
            match tunnel
                .stack
                .connect(SocketAddr::new(address, port), share)
                .await
            {
                Ok(stream) => return Ok(Box::new(stream) as Box<dyn TunnelStream>),
                Err(error) => last = Some(error),
            }
        }

        let error = last.unwrap_or_else(|| TunnelError::Dial {
            host: host.to_string(),
            port,
            detail: "the name resolved to no usable address".to_string(),
        });
        // A refusal is the destination's answer and proves the tunnel works; a
        // silence might be either, so it is the only failure allowed to cost a
        // reconnect.
        if is_silence(&error) {
            Err(DialFailure::Tunnel(error))
        } else {
            Err(DialFailure::Destination(error))
        }
    }
}

/// Whether a failed dial means "that destination is bad" or "this tunnel may
/// be gone".
enum DialFailure {
    Destination(TunnelError),
    Tunnel(TunnelError),
}

impl DialFailure {
    fn into_error(self) -> TunnelError {
        match self {
            DialFailure::Destination(error) | DialFailure::Tunnel(error) => error,
        }
    }
}

/// An even share of what is left before `deadline`, for one of `left`
/// attempts still to make.
fn share_of(deadline: tokio::time::Instant, left: usize) -> Duration {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    remaining / u32::try_from(left.max(1)).unwrap_or(u32::MAX)
}

/// A dial that produced no answer at all, as opposed to a refusal.
fn is_silence(error: &TunnelError) -> bool {
    matches!(error, TunnelError::Dial { detail, .. } if detail.contains("in time"))
}

/// Re-label a resolver failure with the destination the caller asked for.
///
/// [`WgStack::resolve`] reports against the DNS port, because that is the hop
/// that failed; by the time it reaches an operator the interesting address is
/// the one they were trying to reach.
fn relabel(error: TunnelError, host: &str, port: u16) -> TunnelError {
    match error {
        TunnelError::Dial { detail, .. } => TunnelError::Dial {
            host: host.to_string(),
            port,
            detail,
        },
        other => other,
    }
}

#[async_trait::async_trait]
impl TunnelProvider for WireGuardTunnelProvider {
    async fn prepare(&self) -> Result<(), TunnelError> {
        self.tunnel().await.map(|_| ())
    }

    fn source_address(&self) -> Option<std::net::SocketAddr> {
        *self.source.lock().expect("WireGuard source")
    }

    async fn shutdown(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.retire().await;
    }
    async fn retire(&self) {
        if let Some(tunnel) = self.tunnel.lock().await.take() {
            tunnel.shutdown.notify_waiters();
            tunnel.pump.abort();
            if let Some(watch) = &tunnel.carrier_watch {
                watch.abort();
            }
            if let Ok(mut tunnel) = Arc::try_unwrap(tunnel) {
                let _ = (&mut tunnel.pump).await;
            }
        }
    }

    async fn dial(&self, host: &str, port: u16) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let tunnel = self.tunnel().await.inspect_err(|error| {
            self.observer
                .tunnel_dial_failed(&self.spec.proxy_config_id, &error.to_string());
        })?;

        // One deadline covers the whole dial: resolution, every address, and
        // the rebuild and second attempt when there is one. A tunnel whose
        // peer shook hands moments ago is provably up, so a silence on it is
        // the destination's and is never retried; any other tunnel keeps
        // half the budget back for a rebuild and a second attempt.
        let deadline = self.request_deadline();
        let recently_shaken =
            matches!(tunnel.last_handshake_age(), Some(age) if age < RECENT_HANDSHAKE);
        let first_deadline = if recently_shaken {
            deadline
        } else {
            tokio::time::Instant::now() + self.spec.request_timeout / 2
        };
        let outcome = match self.dial_on(&tunnel, host, port, first_deadline).await {
            Ok(stream) => Ok(stream),
            Err(DialFailure::Destination(error)) => Err(error),
            Err(DialFailure::Tunnel(first)) if recently_shaken => Err(first),
            Err(DialFailure::Tunnel(first)) => {
                tracing::debug!(
                    proxy_config_id = self.spec.proxy_config_id.as_str(),
                    error = %first,
                    "the WireGuard tunnel answered nothing; bringing it up again once"
                );
                match self.replace_tunnel(&tunnel, deadline).await {
                    Ok(tunnel) => self
                        .dial_on(&tunnel, host, port, deadline)
                        .await
                        .map_err(DialFailure::into_error),
                    Err(error) => Err(error),
                }
            }
        };

        match outcome {
            Ok(stream) => {
                self.observer
                    .tunnel_dial_succeeded(&self.spec.proxy_config_id);
                Ok(stream)
            }
            Err(error) => {
                self.observer
                    .tunnel_dial_failed(&self.spec.proxy_config_id, &error.to_string());
                Err(error)
            }
        }
    }

    fn describe(&self) -> String {
        self.spec.describe()
    }
}

/// A tunnel is a datagram transport for tunnels inside it: each bind opens a
/// UDP socket on this tunnel's stack, bringing the tunnel up if needed.
#[async_trait::async_trait]
impl DatagramTransport for WireGuardTunnelProvider {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, TunnelError> {
        self.resolve_host(host).await
    }

    async fn bind(&self, _peer: SocketAddr) -> Result<Arc<dyn DatagramSocket>, TunnelError> {
        let bound = match self.tunnel().await {
            Ok(tunnel) => tunnel.stack.bind_transport_udp(0),
            Err(error) => Err(error),
        };
        match bound {
            Ok(socket) => {
                self.observer
                    .tunnel_dial_succeeded(&self.spec.proxy_config_id);
                Ok(Arc::new(socket))
            }
            Err(error) => {
                self.observer
                    .tunnel_dial_failed(&self.spec.proxy_config_id, &error.to_string());
                Err(error)
            }
        }
    }
}

/// The peer's allowed IPs, as gotatun wants them.
fn allowed_networks(spec: &WireGuardSpec) -> Vec<IpNetwork> {
    spec.allowed_ips()
        .into_iter()
        .filter_map(|cidr| IpNetwork::new(cidr.address, cidr.prefix_len).ok())
        .collect()
}

/// A single inert IP packet, purely to make gotatun start a handshake.
///
/// gotatun encapsulates whatever the "tun device" hands it; with no session
/// yet it queues the packet and emits a handshake initiation instead, then
/// retransmits that on its own timer. The packet itself carries protocol 59
/// ("no next header") and no payload, so if the peer ever does decrypt it,
/// there is nothing there to act on.
fn handshake_probe(spec: &WireGuardSpec) -> Packet<Ip> {
    let source = spec
        .addresses
        .first()
        .map(|cidr| cidr.address)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    // Addressed to ourselves: the destination only has to match the peer's
    // allowed IPs (which are the default routes), and pointing it anywhere
    // else would put an address on the wire that is not ours to use.
    match source {
        IpAddr::V4(address) => {
            let mut header = Ipv4Header::new(address, address, IpNextProtocol::Ipv6NoNxt, &[]);
            header.header_checksum = ipv4_header_checksum(&header).into();
            Packet::copy_from(&header)
                .into_bytes()
                .try_into_ip()
                .expect("a hand-built IPv4 header is a valid IP packet")
        }
        IpAddr::V6(address) => {
            let mut bytes = Vec::with_capacity(40);
            bytes.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version 6
            bytes.extend_from_slice(&0u16.to_be_bytes()); // payload length
            bytes.push(59); // no next header
            bytes.push(64); // hop limit
            bytes.extend_from_slice(&address.octets());
            bytes.extend_from_slice(&address.octets());
            Packet::copy_from(bytes.as_slice())
                .try_into_ip()
                .expect("a hand-built IPv6 header is a valid IP packet")
        }
    }
}

/// The standard one's-complement checksum over an IPv4 header whose own
/// checksum field is zero.
fn ipv4_header_checksum(header: &Ipv4Header) -> u16 {
    let bytes = header_bytes(header);
    let mut sum: u32 = 0;
    for word in bytes.chunks(2) {
        let value = match word {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => unreachable!("chunks(2) yields one or two bytes"),
        };
        sum += u32::from(value);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The header's own bytes, via a packet, so no zerocopy import is needed here.
fn header_bytes(header: &Ipv4Header) -> Vec<u8> {
    Packet::copy_from(header).into_bytes().as_ref().to_vec()
}

/// How a tunnel's own OS socket binds: an ephemeral port on the wildcard
/// address of `endpoint`'s family, never a dual-stack socket.
///
/// macOS picks an ephemeral port for a dual-stack socket without looking at
/// the IPv4 sockets on the machine, so such a socket can share its port with
/// another program's IPv4 socket. That socket is the more specific match and
/// receives every IPv4 datagram for the port: the peer's answers never reach
/// the tunnel, and its handshake times out. A socket of the endpoint's own
/// family gets a port no other socket of that family holds. Only an
/// IPv4-mapped IPv6 endpoint, which only a dual-stack socket can reach, keeps
/// one.
pub(crate) fn os_socket_params(endpoint: SocketAddr) -> gotatun::udp::UdpTransportFactoryParams {
    let addr = match endpoint {
        SocketAddr::V4(_) => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => None,
        SocketAddr::V6(_) => Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
    };
    gotatun::udp::UdpTransportFactoryParams {
        addr,
        port: 0,
        #[cfg(target_os = "linux")]
        fwmark: None,
    }
}

fn base64_of(key: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::prelude::BASE64_STANDARD.encode(key)
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::time::Duration;

    fn spec_with(address: &str) -> WireGuardSpec {
        WireGuardSpec {
            proxy_config_id: "probe".to_string(),
            proxy_name: "Probe".to_string(),
            revision: "probe@v1".to_string(),
            endpoint_host: "vpn.test".to_string(),
            endpoint_port: 51820,
            private_key: [1u8; 32],
            peer_public_key: [2u8; 32],
            preshared_key: None,
            addresses: vec![address.parse().expect("an address")],
            dns_servers: Vec::new(),
            mtu: DEFAULT_WIREGUARD_MTU,
            persistent_keepalive: None,
            request_timeout: Duration::from_secs(5),
            max_sockets: DEFAULT_MAX_SOCKETS,
        }
    }

    /// A packet the peer will drop for a bad checksum still triggers the
    /// handshake, so a wrong checksum here would be invisible in the
    /// end-to-end tests. Check it directly instead.
    #[test]
    fn the_ipv4_probe_is_a_well_formed_packet_with_a_valid_checksum() {
        let probe = handshake_probe(&spec_with("10.63.0.2/32"));
        assert_eq!(
            probe.destination(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 63, 0, 2))),
            "gotatun routes the probe by its destination, so it must be readable"
        );

        let bytes = Packet::<[u8]>::from(probe);
        let bytes = bytes.as_ref();
        assert_eq!(bytes.len(), 20, "an IPv4 header and no payload");
        assert_eq!(bytes[0] >> 4, 4, "version");
        assert_eq!(bytes[9], 59, "no next header");

        // A header's checksum is valid when the one's-complement sum over the
        // whole header, checksum field included, is 0xffff.
        let mut sum: u32 = 0;
        for word in bytes.chunks(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff, "the header checksum must verify");
    }

    #[test]
    fn the_ipv6_probe_is_a_well_formed_packet() {
        let probe = handshake_probe(&spec_with("fd00::2/128"));
        assert_eq!(
            probe.destination(),
            Some(IpAddr::V6(
                "fd00::2".parse::<Ipv6Addr>().expect("a v6 address")
            ))
        );

        let bytes = Packet::<[u8]>::from(probe);
        let bytes = bytes.as_ref();
        assert_eq!(bytes.len(), 40, "an IPv6 header and no payload");
        assert_eq!(bytes[0] >> 4, 6, "version");
        assert_eq!(
            u16::from_be_bytes([bytes[4], bytes[5]]),
            0,
            "payload length"
        );
        assert_eq!(bytes[6], 59, "no next header");
        assert_eq!(bytes[7], 64, "hop limit");
    }

    /// The probe must be inert: it carries nothing a peer could act on, and it
    /// never puts an address on the wire that is not the tunnel's own.
    #[test]
    fn the_probe_uses_only_the_tunnels_own_address() {
        let probe = handshake_probe(&spec_with("10.63.0.2/32"));
        assert_eq!(probe.source(), probe.destination());
    }
}
