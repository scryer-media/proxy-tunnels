//! The smoltcp side: one interface, one socket set, one pump task.
//!
//! ## Shape
//!
//! Everything smoltcp owns lives inside a single [`std::sync::Mutex`]. That is
//! deliberate, and it is what makes the socket wrappers real futures:
//!
//! * The **pump** task holds the lock only for the duration of one
//!   `Interface::poll`, which is synchronous and bounded, then releases it and
//!   parks until something happens — an inbound packet, a socket wanting
//!   attention, or smoltcp's own `poll_delay` expiring.
//! * A **socket wrapper** (`poll_read`, `poll_write`, a pending connect)
//!   takes the same lock for a few microseconds, tries the operation, and on
//!   would-block registers *its own task waker* on the smoltcp socket. smoltcp
//!   wakes those wakers from inside `poll`, so a reader wakes exactly when its
//!   data arrives. Nothing in this crate polls in a loop.
//!
//! No `await` ever happens while the lock is held, so the mutex can never be
//! held across a suspension point and there is no lock ordering to get wrong.
//!
//! ## Time
//!
//! smoltcp counts from an arbitrary origin, so the origin is the moment this
//! stack started. Using a monotonic `std::time::Instant` (rather than the wall
//! clock) means a clock step cannot make TCP think a retransmit timer fired.
//!
//! ## Ports
//!
//! There is no operating system to allocate ephemeral ports, so the stack does
//! it: a rotating counter over the IANA ephemeral range, **started at a
//! per-stack random offset**. The offset matters: a rebuilt tunnel is a new
//! stack talking to the same far side from the same tunnel address, and if
//! every stack began at the same port its first connection would reuse the
//! exact four-tuple the previous stack's first connection left in TIME-WAIT
//! or LAST-ACK on the far side, which answers a fresh SYN on that tuple with
//! silence or a reset. With a cap of at most [`MAX_MAX_SOCKETS`] concurrent sockets
//! against a range of 16384, a port is otherwise reused only after every
//! other one has been, which is longer than any TIME-WAIT this stack can
//! produce.

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use gotatun::packet::{Ip, Packet};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr as SmolCidr};
use tokio::sync::Notify;

use crate::error::{SlotFreed, TunnelError};
use crate::wireguard::adapter::{InboundRx, OutboundTx};
use crate::wireguard::phy::WgPhy;
use crate::wireguard::spec::IpCidr;
use crate::wireguard::tcp::{WgTcpListener, WgTcpStream};
use crate::wireguard::udp::WgUdpSocket;

/// How many sockets one tunnel may have open at once when its spec asks for
/// no other number.
///
/// Each TCP socket costs 128 KiB of buffers, so the cap bounds a tunnel's
/// memory: 256 sockets is 32 MiB at worst, 1024 is 128 MiB. A dial past it
/// fails with [`TunnelError::AtCapacity`], which says the tunnel is full
/// rather than broken, so a caller can wait or go elsewhere.
pub const DEFAULT_MAX_SOCKETS: usize = 256;

/// The fewest sockets a tunnel may be capped at.
pub const MIN_MAX_SOCKETS: usize = 16;

/// The most sockets a tunnel may be capped at: 512 MiB of TCP buffers at
/// worst.
pub const MAX_MAX_SOCKETS: usize = 4096;

/// The cap a tunnel asking for `asked` sockets runs with: `asked`, held
/// between [`MIN_MAX_SOCKETS`] and [`MAX_MAX_SOCKETS`].
pub fn socket_cap(asked: usize) -> usize {
    asked.clamp(MIN_MAX_SOCKETS, MAX_MAX_SOCKETS)
}

/// Send and receive buffer per TCP socket, each way.
///
/// 64 KiB is the largest window a receiver can advertise without window
/// scaling, and it is enough to keep a long-fat tunnel busy: a 100 ms
/// round trip at 64 KiB per window is ~5 Mbit/s per connection, and our
/// consumers open several.
const TCP_BUFFER_BYTES: usize = 64 * 1024;

/// Datagrams and payload bytes buffered per UDP socket, each way.
const UDP_PACKETS: usize = 32;
const UDP_BUFFER_BYTES: usize = 64 * 1024;

/// How many DNS queries may be in flight at once on the one shared resolver
/// socket.
const DNS_QUERY_SLOTS: usize = 8;

/// Ephemeral port range (RFC 6335).
const EPHEMERAL_FIRST: u16 = 49152;
const EPHEMERAL_LAST: u16 = 65535;

/// Counts stacks ever started in this process; part of each stack's seed.
static STACKS_STARTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How long a closed socket may linger before its slot is reclaimed by force.
///
/// A graceful close needs a round trip for the FIN and its acknowledgement.
/// Past this, the connection is not coming back and holding the slot only
/// starves new dials.
const LINGER: Duration = Duration::from_secs(10);

/// What one stack needs to come up.
#[derive(Clone, Debug)]
pub(crate) struct StackConfig {
    /// The interface's own addresses inside the tunnel.
    pub(crate) addresses: Vec<IpCidr>,
    /// Resolvers reachable through the tunnel. May be empty.
    pub(crate) dns_servers: Vec<IpAddr>,
    /// Link MTU.
    pub(crate) mtu: u16,
    /// For log lines only.
    pub(crate) proxy_config_id: String,
    pub(crate) download_tuning: bool,
    /// How many sockets may be open at once, already held to its bounds.
    pub(crate) max_sockets: usize,
}

impl StackConfig {
    fn has_ipv4(&self) -> bool {
        self.addresses.iter().any(IpCidr::is_ipv4)
    }

    fn has_ipv6(&self) -> bool {
        self.addresses.iter().any(IpCidr::is_ipv6)
    }
}

/// Everything the pump and the socket wrappers share.
pub(crate) struct StackShared {
    inner: Mutex<StackInner>,
    /// Rung by anything that gave smoltcp work to do, so the pump runs a poll
    /// without waiting for its timer.
    wake: Notify,
    open_sockets: Arc<SocketSlots>,
    dns_slots: tokio::sync::Semaphore,
    config: StackConfig,
    /// Set, for good, once the pump has stopped. Nothing moves packets after
    /// that, so every socket wrapper must fail rather than wait.
    stopped: std::sync::atomic::AtomicBool,
    stopped_notify: Notify,
}

impl StackShared {
    /// Run `f` against the stack, then wake the pump so whatever it queued
    /// actually leaves.
    ///
    /// Every mutation goes through here: forgetting the wake is the one bug
    /// this design can have, so it is not possible to forget it.
    pub(crate) fn with_stack<R>(&self, f: impl FnOnce(&mut StackInner) -> R) -> R {
        let result = {
            let mut inner = self.inner.lock().expect("tunnel stack lock poisoned");
            f(&mut inner)
        };
        self.wake.notify_one();
        result
    }

    /// Like [`Self::with_stack`], for operations that may or may not have
    /// queued something. The caller rings [`Self::wake`] itself when they did,
    /// which keeps a would-block poll from costing a pointless stack poll.
    pub(crate) fn peek_stack<R>(&self, f: impl FnOnce(&mut StackInner) -> R) -> R {
        let mut inner = self.inner.lock().expect("tunnel stack lock poisoned");
        f(&mut inner)
    }

    /// Ask the pump for a poll.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    pub(crate) fn config(&self) -> &StackConfig {
        &self.config
    }

    /// Claim one of the stack's socket slots.
    pub(crate) fn claim_socket(&self) -> Result<SocketSlot<'_>, TunnelError> {
        let cap = self.config.max_sockets;
        if self.open_sockets.open.load(Ordering::SeqCst) >= cap {
            self.with_stack(|inner| inner.reclaim_finished(inner.now(), true));
        }
        let claimed =
            self.open_sockets
                .open
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |open| {
                    (open < cap).then_some(open + 1)
                });
        if claimed.is_err() {
            return Err(TunnelError::AtCapacity {
                open: cap,
                freed: self.open_sockets.freed.clone(),
            });
        }
        Ok(SocketSlot { shared: self })
    }

    pub(crate) fn release_socket(&self) {
        self.open_sockets.release();
    }

    /// Whether the pump has stopped, so no packet will ever move again.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Mark the stack stopped and close every socket on it.
    ///
    /// Closing is what releases waiters: smoltcp wakes a socket's registered
    /// readers and writers when a TCP socket is aborted or a UDP socket is
    /// closed, and each wrapper then sees the stack is gone. Without this a
    /// task blocked on a stopped stack would wait forever, because only the
    /// pump ever wakes it. The flag is set before the lock is taken, so a
    /// wrapper that checks it under the lock either sees it set or registers
    /// its waker before the close wakes it.
    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (_, socket) in inner.sockets.iter_mut() {
                match socket {
                    smoltcp::socket::Socket::Tcp(socket) => socket.abort(),
                    smoltcp::socket::Socket::Udp(socket) => socket.close(),
                    _ => {}
                }
            }
        }
        self.stopped_notify.notify_waiters();
    }

    /// Resolves once the stack has stopped.
    pub(crate) async fn wait_stopped(&self) {
        loop {
            let notified = self.stopped_notify.notified();
            tokio::pin!(notified);
            // Registered before the flag is read, so a stop between the two
            // still wakes this waiter.
            notified.as_mut().enable();
            if self.is_stopped() {
                return;
            }
            notified.await;
        }
    }
}

/// Marks the stack stopped however the pump ends, including by abort.
struct StopOnExit(Arc<StackShared>);

impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// One claimed socket slot, released if the socket is never created.
pub(crate) struct SocketSlot<'a> {
    shared: &'a StackShared,
}

impl SocketSlot<'_> {
    /// The socket now exists and owns the slot until the stack reclaims it.
    pub(crate) fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for SocketSlot<'_> {
    fn drop(&mut self) {
        self.shared.release_socket();
    }
}

/// A socket that has been closed and is waiting for its slot to be reclaimed.
struct Closing {
    handle: SocketHandle,
    deadline: Instant,
    counted: bool,
}

/// The tunnel's claimed socket slots, and the signal each freed one rings.
#[derive(Default)]
pub(crate) struct SocketSlots {
    open: AtomicUsize,
    freed: SlotFreed,
}

impl SocketSlots {
    fn release(&self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
        self.freed.signal();
    }
}

/// The smoltcp state itself. Only ever touched under [`StackShared`]'s lock.
pub(crate) struct StackInner {
    iface: Interface,
    sockets: SocketSet<'static>,
    phy: WgPhy,
    dns: Option<SocketHandle>,
    started: std::time::Instant,
    next_port: u16,
    closing: Vec<Closing>,
    open_sockets: Arc<SocketSlots>,
    tcp_buffer_bytes: usize,
}

impl StackInner {
    /// smoltcp's clock: microseconds since this stack started.
    pub(crate) fn now(&self) -> Instant {
        let elapsed = self.started.elapsed();
        Instant::from_micros(i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX))
    }

    pub(crate) fn sockets_mut(&mut self) -> &mut SocketSet<'static> {
        &mut self.sockets
    }

    /// The socket set and the interface context together, which is what
    /// `connect` and `start_query` both need.
    pub(crate) fn socket_and_context(
        &mut self,
    ) -> (&mut SocketSet<'static>, &mut smoltcp::iface::Context) {
        (&mut self.sockets, self.iface.context())
    }

    pub(crate) fn add_tcp_socket(&mut self) -> SocketHandle {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.tcp_buffer_bytes]),
            tcp::SocketBuffer::new(vec![0u8; self.tcp_buffer_bytes]),
        );
        self.sockets.add(socket)
    }

    /// A UDP socket with room for `packets` datagrams and `bytes` of payload
    /// in each direction.
    pub(crate) fn add_udp_socket_sized(&mut self, packets: usize, bytes: usize) -> SocketHandle {
        let socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; packets], vec![0u8; bytes]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; packets], vec![0u8; bytes]),
        );
        self.sockets.add(socket)
    }

    /// The next ephemeral port to try.
    pub(crate) fn next_ephemeral_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if port == EPHEMERAL_LAST {
            EPHEMERAL_FIRST
        } else {
            port + 1
        };
        port
    }

    /// Hand a closed socket back for reclamation.
    ///
    /// The socket is *not* removed here: a graceful close still has a FIN to
    /// send and an acknowledgement to wait for, and removing it now would
    /// abandon both. The pump reclaims it once smoltcp says it is closed, or
    /// after [`LINGER`] if the far side never answers.
    pub(crate) fn retire(&mut self, handle: SocketHandle, counted: bool) {
        let deadline = self.now() + smoltcp::time::Duration::from_micros(LINGER.as_micros() as u64);
        self.closing.push(Closing {
            handle,
            deadline,
            counted,
        });
    }

    /// Remove a socket immediately, for one that never reached a peer.
    pub(crate) fn discard(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }

    pub(crate) fn dns_socket(&mut self) -> Option<(&mut dns::Socket<'static>, SocketHandle)> {
        let handle = self.dns?;
        Some((self.sockets.get_mut::<dns::Socket>(handle), handle))
    }

    /// One poll of the whole stack. Returns how long the pump may sleep.
    fn poll(&mut self) -> Option<Duration> {
        let now = self.now();
        self.iface.poll(now, &mut self.phy, &mut self.sockets);
        self.reclaim(now);
        let protocol_delay = self
            .iface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_micros(delay.total_micros()));
        let linger_delay = self
            .closing
            .iter()
            .map(|closing| Duration::from_micros((closing.deadline - now).total_micros()))
            .min();
        match (protocol_delay, linger_delay) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Free the slots of sockets that finished closing.
    fn reclaim(&mut self, now: Instant) {
        self.reclaim_finished(now, false);
    }

    fn reclaim_finished(&mut self, now: Instant, under_pressure: bool) {
        let mut index = 0;
        while index < self.closing.len() {
            let Closing {
                handle,
                deadline,
                counted,
            } = self.closing[index];
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            // Retired TIME-WAIT sockets have no payload or FIN awaiting ACK.
            // Preserve their linger normally, but do not block new downloads
            // solely on those buffers. Other closing states stay charged.
            let finished = socket.state() == tcp::State::Closed
                || (under_pressure && socket.state() == tcp::State::TimeWait);
            if !finished && now < deadline {
                index += 1;
                continue;
            }
            if !finished {
                // The far side never finished the close. Take the slot back.
                socket.abort();
            }
            self.sockets.remove(handle);
            if counted {
                self.open_sockets.release();
            }
            self.closing.swap_remove(index);
        }
    }
}

/// A handle to one tunnel's network stack.
///
/// Cheap to clone; every clone talks to the same interface.
#[derive(Clone)]
pub struct WgStack {
    shared: Arc<StackShared>,
}

impl WgStack {
    /// Build the interface and start its pump on `runtime`.
    ///
    /// Returns the stack and the pump's join handle; dropping the handle's
    /// owner (or notifying `shutdown`) stops the stack, which closes the
    /// adapter channels, which stops the gotatun device.
    pub(crate) fn start(
        config: StackConfig,
        inbound: InboundRx,
        outbound: OutboundTx,
        shutdown: Arc<Notify>,
        runtime: &tokio::runtime::Handle,
    ) -> (WgStack, tokio::task::JoinHandle<()>) {
        let mut phy = WgPhy::new(outbound, config.mtu);
        let started = std::time::Instant::now();

        // The seed only has to differ between tunnels so two stacks do not
        // pick the same TCP sequence numbers or source ports; it is not
        // security-relevant (WireGuard's own encryption is). It does have to
        // be genuinely different per stack, though: a rebuilt tunnel runs the
        // same code on the same task, so anything address- or clock-derived
        // repeats, and a repeated seed reuses the four-tuples the previous
        // stack left on the far side. `RandomState` is seeded from the OS once
        // per thread and steps per instance, which is exactly the property
        // needed without pulling in a random-number crate.
        let seed = std::hash::BuildHasher::hash_one(
            &std::collections::hash_map::RandomState::new(),
            (
                STACKS_STARTED.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|since| since.as_nanos())
                    .unwrap_or_default(),
            ),
        );
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = seed;
        let mut iface = Interface::new(
            iface_config,
            &mut phy,
            Instant::from_micros(i64::try_from(started.elapsed().as_micros()).unwrap_or(0)),
        );

        iface.update_ip_addrs(|addresses| {
            for cidr in &config.addresses {
                let _ = addresses.push(SmolCidr::new(
                    IpAddress::from(cidr.address),
                    cidr.prefix_len,
                ));
            }
        });

        // Default routes for whichever families the interface carries.
        //
        // On `Medium::Ip` a route's gateway is never dialled — there is no
        // link layer and therefore no next hop to address — it only has to
        // exist so smoltcp considers an off-link destination reachable. The
        // interface's own address is used as that placeholder, which keeps
        // the tunnel from inventing an address that is not ours.
        for cidr in &config.addresses {
            match cidr.address {
                IpAddr::V4(address) => {
                    let _ = iface.routes_mut().add_default_ipv4_route(address);
                }
                IpAddr::V6(address) => {
                    let _ = iface.routes_mut().add_default_ipv6_route(address);
                }
            }
        }

        let mut sockets = SocketSet::new(Vec::new());
        let dns = (!config.dns_servers.is_empty()).then(|| {
            let servers: Vec<IpAddress> = config
                .dns_servers
                .iter()
                .copied()
                .map(IpAddress::from)
                .collect();
            let slots: Vec<Option<dns::DnsQuery>> = (0..DNS_QUERY_SLOTS).map(|_| None).collect();
            sockets.add(dns::Socket::new(&servers, slots))
        });

        let open_sockets = Arc::new(SocketSlots::default());
        let shared = Arc::new(StackShared {
            inner: Mutex::new(StackInner {
                tcp_buffer_bytes: if config.download_tuning {
                    1024 * 1024
                } else {
                    TCP_BUFFER_BYTES
                },
                iface,
                sockets,
                phy,
                dns,
                started,
                next_port: EPHEMERAL_FIRST
                    + (seed % u64::from(EPHEMERAL_LAST - EPHEMERAL_FIRST + 1)) as u16,
                closing: Vec::new(),
                open_sockets: Arc::clone(&open_sockets),
            }),
            wake: Notify::new(),
            open_sockets,
            dns_slots: tokio::sync::Semaphore::new(DNS_QUERY_SLOTS),
            config,
            stopped: std::sync::atomic::AtomicBool::new(false),
            stopped_notify: Notify::new(),
        });

        let pump = runtime.spawn(pump(Arc::clone(&shared), inbound, shutdown));
        (WgStack { shared }, pump)
    }

    /// Open a TCP connection to `remote` through the tunnel.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        timeout: Duration,
    ) -> Result<WgTcpStream, TunnelError> {
        let slot = self.shared.claim_socket()?;
        let stream = WgTcpStream::connect(Arc::clone(&self.shared), remote, timeout).await?;
        slot.keep();
        Ok(stream)
    }

    /// Accept TCP connections on `port` inside the tunnel, on every tunnel
    /// address.
    ///
    /// `0` picks a free port in the ephemeral range. smoltcp lets any number
    /// of sockets listen on one port (that is how the backlog works), so a
    /// port another listener on this stack already holds is refused here
    /// rather than silently shared.
    pub fn listen(&self, port: u16, backlog: usize) -> Result<WgTcpListener, TunnelError> {
        let port = if port == 0 {
            self.free_listen_port()?
        } else if self.listening_on(port) {
            return Err(TunnelError::Engine(format!(
                "the tunnel already listens on port {port}"
            )));
        } else {
            port
        };
        let address = self
            .shared
            .config()
            .addresses
            .first()
            .map(|cidr| cidr.address)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        WgTcpListener::bind(
            Arc::clone(&self.shared),
            SocketAddr::new(address, port),
            backlog,
        )
    }

    /// Whether a listener on this stack already holds `port`.
    pub(crate) fn listening_on(&self, port: u16) -> bool {
        self.shared.peek_stack(|stack| {
            stack.sockets.iter().any(|(_, socket)| match socket {
                smoltcp::socket::Socket::Tcp(socket) => {
                    socket.is_listening() && socket.listen_endpoint().port == port
                }
                _ => false,
            })
        })
    }

    /// A port in the ephemeral range no listener on this stack holds, starting
    /// from a random one.
    fn free_listen_port(&self) -> Result<u16, TunnelError> {
        let span = u64::from(EPHEMERAL_LAST - EPHEMERAL_FIRST) + 1;
        let start = std::hash::BuildHasher::hash_one(
            &std::collections::hash_map::RandomState::new(),
            std::time::Instant::now(),
        ) % span;
        (0..span)
            .map(|step| EPHEMERAL_FIRST + ((start + step) % span) as u16)
            .find(|port| !self.listening_on(*port))
            .ok_or_else(|| {
                TunnelError::Engine("the tunnel has no free port left to listen on".to_string())
            })
    }

    /// Bind a UDP socket inside the tunnel. `0` picks an ephemeral port.
    pub fn bind_udp(&self, port: u16) -> Result<WgUdpSocket, TunnelError> {
        self.bind_udp_sized(port, UDP_PACKETS, UDP_BUFFER_BYTES)
    }

    /// Bind a UDP socket that carries another tunnel's encrypted packets.
    ///
    /// Sized like the link itself rather than like a DNS socket: it queues as
    /// many datagrams as the adapter channels hold, each up to this link's
    /// MTU, so a burst on the carried tunnel is absorbed here instead of being
    /// dropped by a buffer meant for a handful of queries.
    pub fn bind_transport_udp(&self, port: u16) -> Result<WgUdpSocket, TunnelError> {
        let mtu = usize::from(self.shared.config().mtu);
        self.bind_udp_sized(
            port,
            crate::wireguard::adapter::PACKET_QUEUE_DEPTH,
            crate::wireguard::adapter::PACKET_QUEUE_DEPTH * mtu,
        )
    }

    fn bind_udp_sized(
        &self,
        port: u16,
        packets: usize,
        bytes: usize,
    ) -> Result<WgUdpSocket, TunnelError> {
        if self.shared.is_stopped() {
            return Err(TunnelError::Engine("the tunnel has stopped".to_string()));
        }
        let slot = self.shared.claim_socket()?;
        let socket = WgUdpSocket::bind(Arc::clone(&self.shared), port, packets, bytes)?;
        slot.keep();
        Ok(socket)
    }

    /// The link MTU this stack was built with.
    pub fn mtu(&self) -> u16 {
        self.shared.config().mtu
    }

    /// How many sockets this stack lets be open at once.
    pub fn max_sockets(&self) -> usize {
        self.shared.config().max_sockets
    }

    /// Whether the stack has stopped, so nothing on it will move again.
    pub fn is_stopped(&self) -> bool {
        self.shared.is_stopped()
    }

    /// Resolve `host` **through the tunnel**, using the configured resolvers.
    ///
    /// The operating system's resolver is never consulted: that is the whole
    /// point of a tunnel, and consulting it would leak the name to whoever
    /// runs the local network and would return addresses that mean something
    /// different on this side.
    ///
    /// IP literals short-circuit. Everything else needs a resolver, and a
    /// tunnel with none configured says so rather than silently falling back.
    pub async fn resolve(&self, host: &str, timeout: Duration) -> Result<Vec<IpAddr>, TunnelError> {
        let host = host.trim().trim_end_matches('.');
        if let Ok(literal) = host.parse::<IpAddr>() {
            return Ok(vec![literal]);
        }
        // A bracketed literal, as it arrives from a URL authority.
        if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'))
            && let Ok(literal) = inner.parse::<IpAddr>()
        {
            return Ok(vec![literal]);
        }

        let lowercase = host.to_ascii_lowercase();
        if lowercase == "localhost" || lowercase.ends_with(".localhost") {
            // Never answer this one locally. An SSH tunnel forwards the name
            // and the far side's `localhost` means the far side; a WireGuard
            // tunnel has no such forwarding, and resolving it here would
            // silently point at *this* machine — the one thing a tunnel exists
            // to avoid.
            return Err(TunnelError::Configuration(
                "`localhost` cannot be resolved through a WireGuard tunnel: it would name this \
                 machine, not the far side; use the far side's tunnel address instead"
                    .to_string(),
            ));
        }

        let config = self.shared.config();
        if config.dns_servers.is_empty() {
            return Err(TunnelError::Configuration(
                "the tunnel has no DNS server configured, so names cannot be resolved on the far \
                 side; add the `DNS` line from the WireGuard configuration, or address the \
                 destination by IP"
                    .to_string(),
            ));
        }

        // Ask for the family the interface can actually source packets from,
        // preferring IPv4 when it has both: a tunnel's v6 address is far more
        // often decorative than routable, and a AAAA answer we cannot reach
        // is worse than no answer.
        let mut order = Vec::with_capacity(2);
        if config.has_ipv4() {
            order.push(DnsQueryType::A);
        }
        if config.has_ipv6() {
            order.push(DnsQueryType::Aaaa);
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_error = None;
        for kind in order {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match self.query(host, kind, remaining).await {
                Ok(addresses) if !addresses.is_empty() => return Ok(addresses),
                Ok(_) => {}
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            resolve_failure(
                host,
                "the tunnel's DNS server returned no address for this name",
            )
        }))
    }

    async fn query(
        &self,
        host: &str,
        kind: DnsQueryType,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, TunnelError> {
        let shared = Arc::clone(&self.shared);
        let deadline = tokio::time::Instant::now() + timeout;
        let _permit = tokio::time::timeout_at(deadline, shared.dns_slots.acquire())
            .await
            .map_err(|_| resolve_failure(host, "timed out waiting for a tunnel DNS slot"))?
            .map_err(|_| resolve_failure(host, "the tunnel resolver stopped"))?;
        let started = shared.with_stack(|stack| {
            let dns_handle = stack.dns.expect("a resolver is configured");
            let (sockets, context) = stack.socket_and_context();
            sockets
                .get_mut::<dns::Socket>(dns_handle)
                .start_query(context, host, kind)
        });
        let handle = started.map_err(|error| {
            resolve_failure(
                host,
                match error {
                    dns::StartQueryError::NoFreeSlot => {
                        "the tunnel has too many DNS queries in flight"
                    }
                    dns::StartQueryError::InvalidName => "the name is not a valid host name",
                    dns::StartQueryError::NameTooLong => "the name is too long for DNS",
                },
            )
        })?;

        let mut query = QueryGuard {
            shared: &shared,
            handle: Some(handle),
        };
        let answered = tokio::time::timeout_at(
            deadline,
            poll_fn(|context| {
                shared.peek_stack(|stack| {
                    let (socket, _) = stack.dns_socket().expect("a resolver is configured");
                    match socket.get_query_result(handle) {
                        Ok(addresses) => Poll::Ready(Ok(addresses)),
                        Err(dns::GetQueryResultError::Pending) => {
                            socket.register_query_waker(handle, context.waker());
                            Poll::Pending
                        }
                        Err(dns::GetQueryResultError::Failed) => Poll::Ready(Err(())),
                    }
                })
            }),
        )
        .await;

        // Whether it answered, failed or timed out, the slot is either already
        // free (smoltcp frees it when it hands back a result) or ours to
        // cancel.
        let outcome = match answered {
            Ok(Ok(addresses)) => {
                query.handle = None;
                Ok(addresses.into_iter().map(IpAddr::from).collect())
            }
            Ok(Err(())) => {
                query.handle = None;
                Err(resolve_failure(
                    host,
                    "the tunnel's DNS server does not know this name",
                ))
            }
            Err(_) => Err(resolve_failure(
                host,
                "the tunnel's DNS server did not answer in time",
            )),
        };
        drop(query);
        outcome
    }
}

/// A name that could not be resolved through the tunnel.
///
/// Reported against the resolver's own port, because that is the hop that
/// failed. [`crate::wireguard::WireGuardTunnelProvider::dial`] re-labels it
/// with the destination the caller actually asked for.
fn resolve_failure(host: &str, detail: &str) -> TunnelError {
    TunnelError::Dial {
        host: host.to_string(),
        port: 53,
        detail: detail.to_string(),
    }
}

/// Cancels an in-flight DNS query if it is abandoned, so a timed-out lookup
/// does not hold one of the resolver's slots until the process exits.
struct QueryGuard<'a> {
    shared: &'a Arc<StackShared>,
    handle: Option<dns::QueryHandle>,
}

impl Drop for QueryGuard<'_> {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        self.shared.with_stack(|stack| {
            if let Some((socket, _)) = stack.dns_socket() {
                socket.cancel_query(handle);
            }
        });
    }
}

/// The one task that drives smoltcp.
///
/// It never busy-loops: after each poll it parks on whichever of the four
/// things can possibly need it next.
async fn pump(shared: Arc<StackShared>, mut inbound: InboundRx, shutdown: Arc<Notify>) {
    let _stop = StopOnExit(Arc::clone(&shared));
    let proxy_config_id = shared.config().proxy_config_id.clone();
    let mut batch: Vec<Packet<Ip>> = Vec::with_capacity(64);

    loop {
        let delay = shared.peek_stack(|stack| stack.poll());

        // Take the notification future *before* deciding to sleep: a wake that
        // arrives while we were polling has already left its permit, so it is
        // observed on the next pass rather than lost.
        let woken = shared.wake.notified();
        let stopped = shutdown.notified();
        tokio::pin!(woken, stopped);

        tokio::select! {
            biased;
            () = &mut stopped => break,
            received = inbound.recv_many(&mut batch, 64) => {
                if received == 0 {
                    // The device is gone.
                    break;
                }
                shared.peek_stack(|stack| {
                    for packet in batch.drain(..) {
                        stack.phy.push_inbound(packet);
                    }
                });
            }
            () = &mut woken => {}
            () = sleep_for(delay) => {}
        }
    }

    let (dropped, overrun) = shared.peek_stack(|stack| stack.phy.drop_counts());
    tracing::debug!(
        proxy_config_id = proxy_config_id.as_str(),
        dropped,
        overrun,
        "tunnel stack stopped"
    );
}

/// Sleep for smoltcp's advisory delay, or forever when it has nothing pending.
async fn sleep_for(delay: Option<Duration>) {
    match delay {
        Some(delay) if delay.is_zero() => tokio::task::yield_now().await,
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use std::future::Future;

    fn isolated_stack() -> WgStack {
        let (_, _, inbound, outbound) = crate::wireguard::adapter::ip_channels(1280);
        let (stack, pump) = WgStack::start(
            StackConfig {
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
                dns_servers: vec!["10.0.0.2".parse().unwrap()],
                mtu: 1280,
                proxy_config_id: "resource-test".into(),
                download_tuning: false,
                max_sockets: DEFAULT_MAX_SOCKETS,
            },
            inbound,
            outbound,
            Arc::new(Notify::new()),
            &tokio::runtime::Handle::current(),
        );
        pump.abort();
        stack
    }

    async fn poll_pending<F: Future>(future: std::pin::Pin<&mut F>) {
        let mut future = future;
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn closing_sockets_retain_capacity_until_reclaimed() {
        let stack = isolated_stack();
        let shared = &stack.shared;
        for _ in 0..DEFAULT_MAX_SOCKETS {
            let slot = shared.claim_socket().unwrap();
            shared.with_stack(|inner| {
                let handle = inner.add_tcp_socket();
                let port = inner.next_ephemeral_port();
                let (sockets, context) = inner.socket_and_context();
                sockets
                    .get_mut::<tcp::Socket>(handle)
                    .connect(
                        context,
                        (IpAddress::from(std::net::Ipv4Addr::new(10, 0, 0, 2)), 80),
                        port,
                    )
                    .unwrap();
                inner.retire(handle, true);
            });
            slot.keep();
        }
        assert!(matches!(
            shared.claim_socket(),
            Err(TunnelError::AtCapacity {
                open: DEFAULT_MAX_SOCKETS,
                ..
            })
        ));
        shared.peek_stack(|inner| {
            assert_eq!(
                inner.sockets.iter().count(),
                DEFAULT_MAX_SOCKETS + 1,
                "plus the fixed resolver"
            );
            inner.reclaim(inner.now());
            assert_eq!(inner.closing.len(), DEFAULT_MAX_SOCKETS);
            inner.reclaim(inner.now() + smoltcp::time::Duration::from_secs(11));
            assert!(inner.closing.is_empty());
            assert_eq!(inner.sockets.iter().count(), 1);
        });
        assert_eq!(shared.open_sockets.open.load(Ordering::SeqCst), 0);
        assert!(shared.claim_socket().is_ok());
    }

    #[tokio::test]
    async fn a_full_tunnel_wakes_its_waiters_when_a_slot_frees() {
        let stack = isolated_stack();
        let shared = &stack.shared;
        let mut slots: Vec<_> = (0..DEFAULT_MAX_SOCKETS)
            .map(|_| shared.claim_socket().unwrap())
            .collect();
        let Err(TunnelError::AtCapacity { freed, .. }) = shared.claim_socket() else {
            panic!("a full tunnel reports AtCapacity");
        };
        let notify = freed.notify();
        let mut woken = std::pin::pin!(notify.notified());
        woken.as_mut().enable();
        poll_fn(|cx| {
            assert!(woken.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(slots.pop());
        woken.await;
        assert!(shared.claim_socket().is_ok());
    }

    #[tokio::test]
    async fn cancelling_pending_tcp_connects_removes_handles_and_slots() {
        let stack = isolated_stack();
        for _ in 0..(DEFAULT_MAX_SOCKETS + 8) {
            let mut dial =
                Box::pin(stack.connect("10.0.0.2:80".parse().unwrap(), Duration::from_secs(30)));
            poll_pending(dial.as_mut()).await;
            assert_eq!(stack.shared.open_sockets.open.load(Ordering::SeqCst), 1);
            drop(dial);
            assert_eq!(stack.shared.open_sockets.open.load(Ordering::SeqCst), 0);
            assert_eq!(
                stack
                    .shared
                    .peek_stack(|inner| inner.sockets.iter().count()),
                1
            );
        }
    }

    #[tokio::test]
    async fn dns_waits_for_capacity_and_cancellation_recovers_every_slot() {
        let stack = isolated_stack();
        let mut queries = Vec::new();
        for _ in 0..DNS_QUERY_SLOTS {
            let mut query = Box::pin(stack.resolve("example.test", Duration::from_secs(30)));
            poll_pending(query.as_mut()).await;
            queries.push(query);
        }
        assert_eq!(stack.shared.dns_slots.available_permits(), 0);
        let mut ninth = Box::pin(stack.resolve("ninth.test", Duration::from_secs(30)));
        poll_pending(ninth.as_mut()).await;
        drop(queries.pop());
        poll_pending(ninth.as_mut()).await;
        assert_eq!(stack.shared.dns_slots.available_permits(), 0);
        drop(ninth);
        drop(queries);
        assert_eq!(stack.shared.dns_slots.available_permits(), DNS_QUERY_SLOTS);
        // All smoltcp handles were cancelled too, so the next batch can start.
        for _ in 0..DNS_QUERY_SLOTS {
            let mut query = Box::pin(stack.resolve("again.test", Duration::from_secs(30)));
            poll_pending(query.as_mut()).await;
        }
        assert_eq!(stack.shared.dns_slots.available_permits(), DNS_QUERY_SLOTS);
    }

    #[tokio::test]
    async fn dns_capacity_wait_uses_the_callers_deadline() {
        let stack = isolated_stack();
        let _held = stack
            .shared
            .dns_slots
            .acquire_many(DNS_QUERY_SLOTS as u32)
            .await
            .unwrap();
        let error = stack
            .resolve("example.test", Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out waiting"));
        drop(_held);
        assert_eq!(stack.shared.dns_slots.available_permits(), DNS_QUERY_SLOTS);
    }

    fn stack_with(
        address: &str,
        max_sockets: usize,
        inbound: InboundRx,
        outbound: OutboundTx,
    ) -> (WgStack, tokio::task::JoinHandle<()>) {
        WgStack::start(
            StackConfig {
                addresses: vec![address.parse().unwrap()],
                dns_servers: Vec::new(),
                mtu: 1280,
                proxy_config_id: format!("cap-{address}"),
                download_tuning: false,
                max_sockets,
            },
            inbound,
            outbound,
            Arc::new(Notify::new()),
            &tokio::runtime::Handle::current(),
        )
    }

    #[test]
    fn a_tunnels_cap_is_held_to_its_bounds() {
        assert_eq!(socket_cap(0), MIN_MAX_SOCKETS);
        assert_eq!(socket_cap(512), 512);
        assert_eq!(socket_cap(usize::MAX), MAX_MAX_SOCKETS);
    }

    #[tokio::test]
    async fn a_stack_is_full_at_its_own_cap() {
        let (_inbound_tx, inbound) = tokio::sync::mpsc::channel(1);
        let (outbound, _outbound_rx) = tokio::sync::mpsc::channel(1);
        let (stack, pump) = stack_with("10.0.0.1/24", MIN_MAX_SOCKETS, inbound, outbound);
        pump.abort();
        let slots: Vec<_> = (0..MIN_MAX_SOCKETS)
            .map(|_| stack.shared.claim_socket().unwrap())
            .collect();
        assert!(matches!(
            stack.shared.claim_socket(),
            Err(TunnelError::AtCapacity {
                open: MIN_MAX_SOCKETS,
                ..
            })
        ));
        drop(slots);
        assert!(stack.shared.claim_socket().is_ok());
    }

    /// What one poll of a stack holding `count` idle established TCP
    /// connections costs, on this machine. Two stacks are wired back to back,
    /// one dials the other `count` times, and once every connection is up the
    /// dialling stack is polled under its lock, the pump held off.
    async fn poll_cost(count: usize) -> Duration {
        const PASSES: u32 = 2000;
        let (a_to_b, b_inbound) = tokio::sync::mpsc::channel(PACKET_QUEUE);
        let (b_to_a, a_inbound) = tokio::sync::mpsc::channel(PACKET_QUEUE);
        let (dialler, _a_pump) = stack_with("10.9.0.1/24", MAX_MAX_SOCKETS, a_inbound, a_to_b);
        let (answerer, _b_pump) = stack_with("10.9.0.2/24", MAX_MAX_SOCKETS, b_inbound, b_to_a);
        let mut listener = answerer.listen(80, count.max(1)).unwrap();
        let accepted = tokio::spawn(async move {
            let mut streams = Vec::with_capacity(count);
            while streams.len() < count {
                streams.push(listener.accept().await.unwrap());
            }
            (listener, streams)
        });
        let remote: SocketAddr = "10.9.0.2:80".parse().unwrap();
        let mut dials = tokio::task::JoinSet::new();
        for _ in 0..count {
            let dialler = dialler.clone();
            dials.spawn(async move { dialler.connect(remote, Duration::from_secs(600)).await });
        }
        let mut streams = Vec::with_capacity(count);
        while let Some(dialled) = dials.join_next().await {
            streams.push(dialled.unwrap().unwrap());
        }
        let _answered = accepted.await.unwrap();
        dialler.shared.peek_stack(|inner| {
            inner.poll();
            let started = std::time::Instant::now();
            for _ in 0..PASSES {
                inner.poll();
            }
            started.elapsed() / PASSES
        })
    }

    const PACKET_QUEUE: usize = 8192;

    // Measures, asserts nothing: run it by name with `--ignored`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "a measurement, not a check"]
    async fn poll_cost_per_pass_with_idle_sockets() {
        for count in [0, 256, 1024] {
            let cost = poll_cost(count).await;
            println!("{count} idle sockets: {} ns per poll", cost.as_nanos());
        }
    }
}
