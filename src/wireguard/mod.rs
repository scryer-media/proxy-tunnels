//! The WireGuard implementation of [`TunnelProvider`], entirely in process.
//!
//! ```text
//!   caller ──▶ SOCKS5 front ──▶ WireGuardTunnelProvider::dial
//!                                 │
//!                                 ├─ resolve the name *through* the tunnel (smoltcp DNS)
//!                                 └─ open a TCP socket on the tunnel's smoltcp interface
//!                                       │
//!                                    in-memory IpSend / IpRecv adapter
//!                                       │
//!                                    gotatun device — handshake, encrypt, rekey, keepalive
//!                                       │
//!                                    Tokio UDP socket on an ephemeral local port
//! ```
//!
//! Nothing here needs a `tun` device, a route, a firewall rule or a
//! capability: the "network interface" is a pair of channels, and the only
//! socket the operating system sees is one ordinary UDP socket. That is what
//! makes a VPN tunnel usable from inside a container that has no `NET_ADMIN`,
//! and it is why this can be a per-proxy tunnel rather than a machine-wide one.
//!
//! ## What each half owns
//!
//! * **gotatun** owns the protocol: the Noise handshake, encryption, rekeying,
//!   keepalives, peer state, the WireGuard timers, and the UDP transport.
//! * **smoltcp** owns everything above IP: the interface, TCP, UDP and DNS.
//! * This module owns the seam and the lifecycle, and nothing else.
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
//!   inner smoltcp ─▶ inner gotatun ─▶ UDP socket on the outer stack
//!                                        ─▶ outer gotatun ─▶ OS UDP socket
//! ```
//!
//! The outer peer only ever sees the inner tunnel's WireGuard datagrams. The
//! inner tunnel's MTU shrinks by the outer IP, UDP and WireGuard headers it
//! now has to fit inside ([`carried_mtu`]), the inner endpoint name resolves
//! through the outer tunnel's resolver, and an inner tunnel whose carrier
//! stopped is treated as dead rather than waited on.

mod adapter;
mod phy;
mod spec;
mod stack;
mod tcp;
mod transport;
mod udp;

#[cfg(test)]
mod stacked_tests;
#[cfg(any(test, feature = "test-support"))]
mod test_peer;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::packet::{Ip, IpNextProtocol, Ipv4Header, Packet};
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
pub use stack::{MAX_SOCKETS, WgStack};
pub use tcp::WgTcpStream;
pub use udp::WgUdpSocket;

#[cfg(any(test, feature = "test-support"))]
pub use test_peer::{
    ForwardedUdp, TEST_CLIENT_ADDRESS, TEST_PEER_ADDRESS, TEST_PEER_HTTP_PORT, WireGuardTestPeer,
    WireGuardTestPeerOptions, is_wireguard_message, test_client_private_key, test_key,
    test_peer_private_key, test_preshared_key,
};

pub(crate) use adapter::ip_channels;
pub(crate) use stack::StackConfig;

/// gotatun's own point of no return: after three times `REJECT_AFTER_TIME`
/// with no handshake it clears its keys and the session is unrecoverable.
/// A tunnel that has been silent for this long is dead, not slow.
const SESSION_EXPIRY: Duration = Duration::from_secs(180 * 3);

/// How often to look for the first handshake while bringing a tunnel up.
const HANDSHAKE_POLL_INTERVAL: Duration = Duration::from_millis(25);

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

/// The transports one of our devices is built from.
pub(crate) type WgTransports = (
    transport::TunnelUdpFactory,
    adapter::DeviceToStack,
    adapter::StackToDevice,
);

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
    /// How long the handshake took, measured from the moment the tunnel began
    /// coming up.
    pub handshake_at: Duration,
}

/// One live WireGuard tunnel: a gotatun device, a smoltcp stack, and the pump
/// that joins them.
struct WgTunnel {
    stack: WgStack,
    /// `Option` only so [`Drop`] can take it and drop it *inside* the runtime
    /// context, or explicit shutdown can await device termination.
    device: tokio::sync::Mutex<Option<Device<WgTransports>>>,
    pump: tokio::task::JoinHandle<()>,
    shutdown: Arc<Notify>,
    peer_public_key: PublicKey,
    handshake_at: Duration,
    /// The socket this tunnel rides on when it is carried by another
    /// transport. Once it closes, the tunnel can never move a packet again.
    carrier: Option<Arc<dyn DatagramSocket>>,
    /// Stops the pump once the carrier closes, so a carried tunnel whose
    /// carrier is gone ends its connections instead of leaving them waiting
    /// for packets that can never arrive.
    carrier_watch: Option<tokio::task::JoinHandle<()>>,
    /// The runtime the device's tasks live on. gotatun stops a device on drop
    /// by spawning onto `Handle::try_current()`, and silently leaks it — UDP
    /// socket, keepalives and all — when there is no current runtime. The
    /// registry drops tunnels from plain threads (a config update on the
    /// blocking plugin worker, `stop_all` at shutdown), so the drop has to
    /// enter this handle first.
    runtime: tokio::runtime::Handle,
}

impl WgTunnel {
    /// Whether this tunnel is still worth dialling on.
    ///
    /// Two ways to be dead: the stack pump stopped (which also means the
    /// device's channels are closed), or the peer has gone quiet for longer
    /// than WireGuard itself will tolerate, at which point gotatun has thrown
    /// its keys away and no amount of waiting brings the session back.
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
        match self.last_handshake_age().await {
            Some(age) => age < SESSION_EXPIRY,
            None => false,
        }
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        match self.device.lock().await.as_ref() {
            Some(device) => last_handshake_age(device, &self.peer_public_key).await,
            None => None,
        }
    }
}

/// How long ago the device last completed a handshake with `peer`, if ever.
async fn last_handshake_age(device: &Device<WgTransports>, peer: &PublicKey) -> Option<Duration> {
    device
        .peers()
        .await
        .into_iter()
        .find(|entry| entry.peer.public_key == *peer)
        .and_then(|entry| entry.stats.last_handshake)
}

impl Drop for WgTunnel {
    fn drop(&mut self) {
        // Stop the pump first: that closes the adapter channels, which is how
        // the device's own tasks learn to stop.
        self.shutdown.notify_waiters();
        self.pump.abort();
        if let Some(watch) = &self.carrier_watch {
            watch.abort();
        }
        // Then the device, from inside its runtime's context whatever thread
        // this drop runs on — see the field's comment for why that matters.
        let _entered = self.runtime.enter();
        drop(self.device.get_mut().take());
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
            source: Arc::new(std::sync::Mutex::new(None)),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Opt into 1 MiB TCP buffers in each direction and a larger UDP receive
    /// buffer for concurrent bulk downloads. At the 256-socket limit, TCP
    /// buffers alone can consume 512 MiB. Ordinary providers retain 64 KiB
    /// buffers and the operating system's UDP defaults.
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
        let tunnel = self.bring_up().await?;
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
        let tunnel = Arc::new(self.bring_up().await?);
        *guard = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    /// Drop `stale` if it is still the current tunnel, and build a new one.
    async fn replace_tunnel(&self, stale: &Arc<WgTunnel>) -> Result<Arc<WgTunnel>, TunnelError> {
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
        let tunnel = Arc::new(self.bring_up().await?);
        *guard = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    /// Everything between "a validated spec" and "a tunnel that has shaken
    /// hands": resolve the endpoint, start the stack, build the device, prove
    /// the peer answers.
    async fn bring_up(&self) -> Result<WgTunnel, TunnelError> {
        self.spec.validate()?;
        let started = std::time::Instant::now();

        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            TunnelError::Engine("a WireGuard tunnel needs a tokio runtime".to_string())
        })?;

        let endpoint = self.resolve_endpoint().await?;

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

        let (to_stack, to_device, inbound, outbound) = ip_channels(mtu);
        let shutdown = Arc::new(Notify::new());
        let probe_channel = outbound.clone();
        let (stack, pump) = WgStack::start(
            StackConfig {
                addresses: self.spec.addresses.clone(),
                dns_servers: self.spec.dns_servers.clone(),
                mtu,
                proxy_config_id: self.spec.proxy_config_id.clone(),
                download_tuning: self.download_tuning,
            },
            inbound,
            outbound,
            Arc::clone(&shutdown),
            &runtime,
        );

        let peer_public_key = PublicKey::from(self.spec.peer_public_key);
        let mut peer = Peer::new(peer_public_key)
            .with_endpoint(endpoint)
            .with_allowed_ips(allowed_networks(&self.spec));
        peer.preshared_key = self.spec.preshared_key;
        peer.keepalive = self.spec.persistent_keepalive;

        let device = DeviceBuilder::new()
            // An ephemeral local port on an ordinary UDP socket. No listen
            // port is configured: nothing dials *us*.
            .with_udp(transport::TunnelUdpFactory {
                tuning: self.download_tuning,
                bound: self.udp_factory.clone().map(|factory| (factory, endpoint)),
                source: self.source.clone(),
                datagram,
            })
            .with_ip_pair(to_stack, to_device)
            .with_private_key(StaticSecret::from(self.spec.private_key))
            .with_peer(peer)
            .build()
            .await;

        let device = match device {
            Ok(device) => device,
            Err(error) => {
                shutdown.notify_waiters();
                pump.abort();
                return Err(TunnelError::WireGuardConnect {
                    host: self.spec.endpoint_host.clone(),
                    port: self.spec.endpoint_port,
                    detail: error.to_string(),
                });
            }
        };

        // Nudge the device into initiating. WireGuard only handshakes when it
        // has something to send, so a tunnel with no persistent keepalive
        // would otherwise sit idle until the first dial — and the point of
        // waiting here is that a wrong key or an unreachable endpoint surfaces
        // as a connect error rather than as a mysteriously slow first request.
        let _ = probe_channel.try_send(handshake_probe(&self.spec));

        let age = match self.await_handshake(&device, &peer_public_key, &pump).await {
            Ok(age) => age,
            Err(error) => {
                shutdown.notify_waiters();
                pump.abort();
                device.stop().await;
                return Err(error);
            }
        };
        let handshake_at = started.elapsed().saturating_sub(age);
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
            device: tokio::sync::Mutex::new(Some(device)),
            pump,
            shutdown,
            peer_public_key,
            handshake_at,
            carrier,
            carrier_watch,
            runtime,
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

    /// Wait for the peer to answer, or say that it did not.
    async fn await_handshake(
        &self,
        device: &Device<WgTransports>,
        peer_public_key: &PublicKey,
        pump: &tokio::task::JoinHandle<()>,
    ) -> Result<Duration, TunnelError> {
        let waited = tokio::time::timeout(self.spec.request_timeout, async {
            loop {
                if let Some(age) = last_handshake_age(device, peer_public_key).await {
                    return age;
                }
                if pump.is_finished() {
                    // The stack died under us; there will never be a
                    // handshake, so do not sit out the whole budget.
                    return Duration::MAX;
                }
                tokio::time::sleep(HANDSHAKE_POLL_INTERVAL).await;
            }
        })
        .await;

        match waited {
            Ok(age) if age != Duration::MAX => Ok(age),
            Ok(_) => Err(TunnelError::WireGuardConnect {
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

    /// Resolve the peer's endpoint with the **operating system's** resolver,
    /// or, for a carried tunnel, with its carrier's.
    ///
    /// This one name is outside the tunnel by definition: it is the hop that
    /// carries the tunnel, so there is nothing to resolve it through yet. When
    /// another tunnel carries this one, the name means something on *that*
    /// tunnel's far side, so that is where it is asked.
    async fn resolve_endpoint(&self) -> Result<SocketAddr, TunnelError> {
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
        let resolved = tokio::time::timeout(
            self.spec.request_timeout,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| TunnelError::WireGuardConnect {
            host: host.clone(),
            port,
            detail: "the endpoint name did not resolve in time".to_string(),
        })?;

        let mut addresses = resolved.map_err(|error| TunnelError::WireGuardConnect {
            host: host.clone(),
            port,
            detail: format!("the endpoint name could not be resolved: {error}"),
        })?;

        addresses
            .next()
            .ok_or_else(|| TunnelError::WireGuardConnect {
                host: host.clone(),
                port,
                detail: "the endpoint name resolved to no addresses".to_string(),
            })
    }

    /// One dial attempt on a tunnel that is already up.
    async fn dial_on(
        &self,
        tunnel: &WgTunnel,
        host: &str,
        port: u16,
    ) -> Result<Box<dyn TunnelStream>, DialFailure> {
        let timeout = self.spec.request_timeout;
        let addresses = tunnel
            .stack
            .resolve(host, timeout)
            .await
            .map_err(|error| DialFailure::Destination(relabel(error, host, port)))?;

        let mut last = None;
        for address in addresses {
            match tunnel
                .stack
                .connect(SocketAddr::new(address, port), timeout)
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
            if let Some(device) = tunnel.device.lock().await.take() {
                device.stop().await;
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

        let outcome = match self.dial_on(&tunnel, host, port).await {
            Ok(stream) => Ok(stream),
            Err(DialFailure::Destination(error)) => Err(error),
            Err(DialFailure::Tunnel(first)) if matches!(tunnel.last_handshake_age().await, Some(age) if age < RECENT_HANDSHAKE) =>
            {
                // The peer shook hands moments ago, so the tunnel is provably
                // up and the silence is the destination's. No rebuild.
                Err(first)
            }
            Err(DialFailure::Tunnel(first)) => {
                tracing::debug!(
                    proxy_config_id = self.spec.proxy_config_id.as_str(),
                    error = %first,
                    "the WireGuard tunnel answered nothing; bringing it up again once"
                );
                match self.replace_tunnel(&tunnel).await {
                    Ok(tunnel) => self
                        .dial_on(&tunnel, host, port)
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
