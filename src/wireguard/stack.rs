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

use std::collections::HashSet;
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
#[cfg(any(test, feature = "test-support"))]
use crate::wireguard::adapter::{InboundRx, OutboundTx};
use crate::wireguard::phy::{Outbound, PACKET_QUEUE_DEPTH, WgPhy};
use crate::wireguard::spec::IpCidr;
use crate::wireguard::tcp::{WgTcpListener, WgTcpStream};
use crate::wireguard::udp::{UdpQueue, WgUdpSocket};

/// How many sockets one tunnel may have open at once when its spec asks for
/// no other number.
///
/// A TCP socket at the plain default sizes holds 128 KiB of buffers, so 256
/// sockets is 32 MiB and 1024 is 128 MiB; on a download-tuned tunnel each
/// holds 2 MiB. A socket given sizes of its own ([`TcpBuffers`]) holds those,
/// so a tunnel's memory is its socket count times the sizes its callers
/// chose: the caller bounds it, not this cap. A dial past the cap fails with
/// [`TunnelError::AtCapacity`], which says the tunnel is full rather than
/// broken, so a caller can wait or go elsewhere.
pub const DEFAULT_MAX_SOCKETS: usize = 256;

/// The fewest sockets a tunnel may be capped at.
pub const MIN_MAX_SOCKETS: usize = 16;

/// The most sockets a tunnel may be capped at: 512 MiB of TCP buffers at the
/// plain default sizes.
pub const MAX_MAX_SOCKETS: usize = 4096;

/// The cap a tunnel asking for `asked` sockets runs with: `asked`, held
/// between [`MIN_MAX_SOCKETS`] and [`MAX_MAX_SOCKETS`].
pub fn socket_cap(asked: usize) -> usize {
    asked.clamp(MIN_MAX_SOCKETS, MAX_MAX_SOCKETS)
}

/// The most sockets one listener keeps listening at once; a larger backlog
/// asked of [`WgStack::listen`] is held to this, as `listen(2)` holds one to
/// `SOMAXCONN`.
///
/// Each listening socket owns a full pair of TCP buffers and one of the
/// tunnel's socket slots, so the backlog is memory taken from the cap before
/// any connection arrives. 64 is a quarter of [`DEFAULT_MAX_SOCKETS`]: a
/// listener on a default tunnel always leaves three quarters of it for dials
/// and accepted connections, and 64 sockets still take a burst of handshakes
/// that arrive together.
pub const MAX_LISTEN_BACKLOG: usize = 64;

/// Send and receive buffer per TCP socket, each way.
///
/// 64 KiB is the largest window a receiver can advertise without window
/// scaling, and it is enough to keep a long-fat tunnel busy: a 100 ms
/// round trip at 64 KiB per window is ~5 Mbit/s per connection, and our
/// consumers open several.
const TCP_BUFFER_BYTES: usize = 64 * 1024;

/// Send and receive buffer per TCP socket, each way, on a tunnel built with
/// download tuning.
///
/// 1 MiB is a full 16-bit window with a shift of 5, and keeps a few
/// connections busy across a long round trip. It is a default, not a bound:
/// a caller that wants more or less asks for it with [`TcpBuffers`].
const TUNED_TCP_BUFFER_BYTES: usize = 1024 * 1024;

/// The smallest receive or send buffer a TCP socket may be given.
///
/// Below this a buffer holds only a handful of full-sized segments, and a
/// receive window that small keeps even a short round trip from being
/// filled.
pub const MIN_TCP_BUFFER_BYTES: usize = 16 * 1024;

/// The largest receive or send buffer a TCP socket may be given: the largest
/// window TCP can advertise, 65,535 bytes shifted by the largest window
/// scale, 14 (RFC 7323 section 2.3), which is 1,073,725,440 bytes.
///
/// smoltcp derives a socket's window scale from its receive capacity, one
/// step per bit past 16, and refuses a capacity above 1 GiB; a capacity of
/// exactly 1 GiB would take a shift of 15, which RFC 7323 does not allow.
/// Every capacity up to this one takes a shift of 14 or less.
///
/// This bound only keeps the window arithmetic valid. It does not bound
/// memory: a socket's buffers are allocated at their full size when the
/// socket is made, so the caller that chooses the sizes, times the sockets
/// open, bounds what a tunnel holds.
pub const MAX_TCP_BUFFER_BYTES: usize = (u16::MAX as usize) << 14;

/// The receive and send buffer sizes of one TCP socket inside a tunnel.
///
/// The receive buffer is the window the far side may fill before it waits,
/// and its size sets the window scale the socket advertises when it
/// connects. The send buffer is how much the socket holds that the far
/// side has not acknowledged yet. A connection that mostly downloads wants
/// the first, one that mostly uploads the second.
///
/// Both are held between [`MIN_TCP_BUFFER_BYTES`] and
/// [`MAX_TCP_BUFFER_BYTES`]. Within those the caller decides: a socket's
/// buffers are memory the tunnel holds for as long as the socket lives, so
/// the sizes asked for, times the sockets open, are what a tunnel costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpBuffers {
    receive: usize,
    send: usize,
}

impl TcpBuffers {
    /// `receive` and `send` bytes, each held to its bounds.
    pub const fn new(receive: usize, send: usize) -> Self {
        Self {
            receive: clamp_buffer(receive),
            send: clamp_buffer(send),
        }
    }

    /// The receive buffer, in bytes.
    pub const fn receive(&self) -> usize {
        self.receive
    }

    /// The send buffer, in bytes.
    pub const fn send(&self) -> usize {
        self.send
    }

    /// What every socket on a stack gets unless it asks for other sizes.
    fn default_for(download_tuning: bool) -> Self {
        let bytes = if download_tuning {
            TUNED_TCP_BUFFER_BYTES
        } else {
            TCP_BUFFER_BYTES
        };
        Self::new(bytes, bytes)
    }
}

const fn clamp_buffer(bytes: usize) -> usize {
    if bytes < MIN_TCP_BUFFER_BYTES {
        MIN_TCP_BUFFER_BYTES
    } else if bytes > MAX_TCP_BUFFER_BYTES {
        MAX_TCP_BUFFER_BYTES
    } else {
        bytes
    }
}

/// How many engine passes' worth of datagrams a socket carrying another
/// tunnel receives.
///
/// The carrier's engine hands this socket up to a whole pass at once, while
/// the carried tunnel's engine, on its own thread, may still be taking in
/// the passes before. One pass deep, a 3-hop download over four connections
/// overflowed it on some runs and fell to half speed on the retransmissions.
/// Eight passes absorbed every burst measured. The queue is allocated when
/// the carried tunnel comes up: 8 x 512 datagrams of up to one MTU.
const TRANSPORT_RECEIVE_PASSES: usize = 8;

/// Datagrams and payload bytes buffered per UDP socket, each way.
const UDP_PACKETS: usize = 32;
const UDP_BUFFER_BYTES: usize = 64 * 1024;

/// How many lookups may be in flight at once on the one shared resolver
/// socket. Each holds up to [`DNS_LIVE_QUERIES`] queries on it, so the socket
/// never holds more than the product; its query list is made that long up
/// front.
const DNS_QUERY_SLOTS: usize = 8;

/// The most queries one unanswered lookup keeps in flight: the first, and a
/// fresh one each [`DNS_FRESH_QUERY_AFTER`] until there are this many.
///
/// smoltcp resends a query 1, 3 and 7 s after it first went out, then gives
/// the server up 10 s after it first went out. A server that has just
/// handshaked a key it had not seen for a while can drop everything through
/// the tunnel for about four seconds, so a lookup asked at once would be
/// answered only by the resend at 7 s. Four queries started a second apart
/// put one datagram on the wire every second for those 10 s (0, 1, 3, 7;
/// 1, 2, 4, 8; 2, 3, 5, 9; 3, 4, 6, 10), so the first one sent after the
/// dark spell is answered. A lookup never answered sends up to 16 datagrams
/// to a server in those 10 s, where one query sent 4.
pub(super) const DNS_LIVE_QUERIES: usize = 4;

/// How long a lookup waits on its queries before it starts a fresh one.
const DNS_FRESH_QUERY_AFTER: Duration = Duration::from_secs(1);

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
    #[cfg(test)]
    pub(crate) counts: StackCounts,
    /// Run by a new listener after its slots are claimed and before it
    /// takes its port, so a test can bring two listeners to that point
    /// together.
    #[cfg(test)]
    pub(crate) before_listen: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// How often the stack's lock was taken and its pump woken.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct StackCounts {
    pub(crate) locks: std::sync::atomic::AtomicUsize,
    pub(crate) wakes: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl StackCounts {
    /// The locks and wakes counted so far.
    pub(crate) fn read(&self) -> (usize, usize) {
        (
            self.locks.load(Ordering::SeqCst),
            self.wakes.load(Ordering::SeqCst),
        )
    }

    fn lock(&self) {
        self.locks.fetch_add(1, Ordering::SeqCst);
    }

    fn wake(&self) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

impl StackShared {
    /// Run `f` against the stack, then wake the pump so whatever it queued
    /// actually leaves.
    ///
    /// Every mutation goes through here: forgetting the wake is the one bug
    /// this design can have, so it is not possible to forget it.
    pub(crate) fn with_stack<R>(&self, f: impl FnOnce(&mut StackInner) -> R) -> R {
        let result = self.peek_stack(f);
        self.wake();
        result
    }

    /// Like [`Self::with_stack`], for operations that may or may not have
    /// queued something. The caller rings [`Self::wake`] itself when they did,
    /// which keeps a would-block poll from costing a pointless stack poll.
    pub(crate) fn peek_stack<R>(&self, f: impl FnOnce(&mut StackInner) -> R) -> R {
        #[cfg(test)]
        self.counts.lock();
        let mut inner = self.inner.lock().expect("tunnel stack lock poisoned");
        f(&mut inner)
    }

    #[cfg(test)]
    pub(crate) fn run_before_listen(&self) {
        let hook = self
            .before_listen
            .lock()
            .expect("listen hook lock poisoned")
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Ask the pump for a poll.
    pub(crate) fn wake(&self) {
        #[cfg(test)]
        self.counts.wake();
        self.wake.notify_one();
    }

    pub(crate) fn config(&self) -> &StackConfig {
        &self.config
    }

    /// Resolves at the next [`Self::wake`], or at once for a wake that came
    /// since the last one was taken.
    pub(crate) fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    /// Marks the stack stopped when dropped, however the task holding it
    /// ends, including by abort.
    pub(crate) fn stop_on_exit(self: &Arc<Self>) -> StopOnExit {
        StopOnExit(Arc::clone(self))
    }

    /// Claim one of the stack's socket slots.
    pub(crate) fn claim_socket(&self) -> Result<SocketSlot<'_>, TunnelError> {
        let cap = self.config.max_sockets;
        if self.open_sockets.open.load(Ordering::SeqCst) >= cap {
            self.with_stack(|inner| inner.reclaim(inner.now()));
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

    /// Rung each time a socket slot frees.
    pub(crate) fn slot_freed(&self) -> Arc<Notify> {
        self.open_sockets.freed.notify()
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
pub(crate) struct StopOnExit(Arc<StackShared>);

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
    /// What a TCP socket that asks for no sizes of its own gets.
    tcp_buffers: TcpBuffers,
    /// The ports listeners on this stack hold, each for as long as its
    /// listener lives, whether or not a socket is listening on it now.
    listen_ports: HashSet<u16>,
    /// Set by a test whose stack must run its protocol timers (DNS and TCP
    /// retransmits) on the paused tokio clock: when this stack's clock read
    /// zero on that clock.
    #[cfg(test)]
    tokio_started: Option<tokio::time::Instant>,
}

impl StackInner {
    /// smoltcp's clock: microseconds since this stack started.
    pub(crate) fn now(&self) -> Instant {
        #[cfg(test)]
        let elapsed = match self.tokio_started {
            Some(started) => started.elapsed(),
            None => self.started.elapsed(),
        };
        #[cfg(not(test))]
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

    /// A TCP socket with `buffers`, or with the stack's default sizes.
    pub(crate) fn add_tcp_socket(&mut self, buffers: Option<TcpBuffers>) -> SocketHandle {
        let buffers = buffers.unwrap_or(self.tcp_buffers);
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; buffers.receive()]),
            tcp::SocketBuffer::new(vec![0u8; buffers.send()]),
        );
        self.sockets.add(socket)
    }

    /// A UDP socket with room for `packets` datagrams and `bytes` of payload
    /// in each direction.
    pub(crate) fn add_udp_socket_sized(
        &mut self,
        receive: UdpQueue,
        send: UdpQueue,
    ) -> SocketHandle {
        let buffer = |queue: UdpQueue| {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; queue.packets],
                vec![0u8; queue.bytes],
            )
        };
        let socket = udp::Socket::new(buffer(receive), buffer(send));
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

    /// Take `port` for a new listener, or with `0` a free port in the
    /// ephemeral range, starting from a random one. Checking and taking
    /// happen under the one lock, so two listeners never hold one port.
    pub(crate) fn take_listen_port(&mut self, port: u16) -> Result<u16, TunnelError> {
        let port = if port != 0 {
            if self.listen_ports.contains(&port) {
                return Err(TunnelError::Engine(format!(
                    "the tunnel already listens on port {port}"
                )));
            }
            port
        } else {
            let span = u64::from(EPHEMERAL_LAST - EPHEMERAL_FIRST) + 1;
            let start = std::hash::BuildHasher::hash_one(
                &std::collections::hash_map::RandomState::new(),
                std::time::Instant::now(),
            ) % span;
            (0..span)
                .map(|step| EPHEMERAL_FIRST + ((start + step) % span) as u16)
                .find(|port| !self.listen_ports.contains(port))
                .ok_or_else(|| {
                    TunnelError::Engine("the tunnel has no free port left to listen on".to_string())
                })?
        };
        self.listen_ports.insert(port);
        Ok(port)
    }

    /// Give back a port a listener held.
    pub(crate) fn release_listen_port(&mut self, port: u16) {
        self.listen_ports.remove(&port);
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

    /// One pass for the engine: hand the interface every packet in
    /// `inbound`, poll once, and move every packet the poll composed to
    /// `outbound`. Returns how long the engine may sleep.
    pub(crate) fn pass(
        &mut self,
        inbound: &mut Vec<Packet<Ip>>,
        outbound: &mut Vec<Packet<Ip>>,
    ) -> Option<Duration> {
        for packet in inbound.drain(..) {
            self.phy.push_inbound(packet);
        }
        let delay = self.poll();
        self.phy.take_outbound(outbound);
        delay
    }

    /// Packets the link discarded in each direction.
    pub(crate) fn drop_counts(&self) -> (u64, u64) {
        self.phy.drop_counts()
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

    /// Free the slots, and the buffers, of sockets that finished closing.
    ///
    /// A retired socket in TIME-WAIT has finished: both FINs were sent and
    /// acknowledged, every byte either way was delivered, and nobody reads
    /// the socket any more. Holding it for smoltcp's ten seconds of
    /// TIME-WAIT would keep both its buffers for nothing. Removing it only
    /// changes the answer to a FIN the far side sends again because our last
    /// acknowledgement was lost: a reset instead of a second acknowledgement,
    /// for a connection the far side has already seen complete. A dialled
    /// socket's four-tuple does not come back soon enough to meet the old
    /// connection's late segments, because a stack reuses a port only after
    /// every other one in the ephemeral range. Every other closing state
    /// still has something to deliver and keeps its socket until it finishes
    /// or its [`LINGER`] runs out.
    fn reclaim(&mut self, now: Instant) {
        let mut index = 0;
        while index < self.closing.len() {
            let Closing {
                handle,
                deadline,
                counted,
            } = self.closing[index];
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let finished = matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait);
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
    /// Build the interface and start its pump on `runtime`, joined to a
    /// gotatun device by the adapter channels.
    ///
    /// Returns the stack and the pump's join handle; dropping the handle's
    /// owner (or notifying `shutdown`) stops the stack, which closes the
    /// adapter channels, which stops the gotatun device.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn start(
        config: StackConfig,
        inbound: InboundRx,
        outbound: OutboundTx,
        shutdown: Arc<Notify>,
        runtime: &tokio::runtime::Handle,
    ) -> (WgStack, tokio::task::JoinHandle<()>) {
        let stack = Self::build(config, Outbound::Channel(outbound));
        let pump = runtime.spawn(pump(Arc::clone(&stack.shared), inbound, shutdown));
        (stack, pump)
    }

    /// Build the interface with nothing driving it yet. Its composed packets
    /// wait in a queue for the engine that drives it to take.
    pub(crate) fn build_for_engine(config: StackConfig) -> WgStack {
        Self::build(config, Outbound::queue())
    }

    /// The state the engine driving this stack shares with its sockets.
    pub(crate) fn shared(&self) -> &Arc<StackShared> {
        &self.shared
    }

    fn build(config: StackConfig, outbound: Outbound) -> WgStack {
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
            let slots: Vec<Option<dns::DnsQuery>> = (0..DNS_QUERY_SLOTS * DNS_LIVE_QUERIES)
                .map(|_| None)
                .collect();
            sockets.add(dns::Socket::new(&servers, slots))
        });

        let open_sockets = Arc::new(SocketSlots::default());
        let shared = Arc::new(StackShared {
            inner: Mutex::new(StackInner {
                tcp_buffers: TcpBuffers::default_for(config.download_tuning),
                iface,
                sockets,
                phy,
                dns,
                started,
                next_port: EPHEMERAL_FIRST
                    + (seed % u64::from(EPHEMERAL_LAST - EPHEMERAL_FIRST + 1)) as u16,
                closing: Vec::new(),
                open_sockets: Arc::clone(&open_sockets),
                listen_ports: HashSet::new(),
                #[cfg(test)]
                tokio_started: None,
            }),
            wake: Notify::new(),
            open_sockets,
            dns_slots: tokio::sync::Semaphore::new(DNS_QUERY_SLOTS),
            config,
            stopped: std::sync::atomic::AtomicBool::new(false),
            stopped_notify: Notify::new(),
            #[cfg(test)]
            counts: StackCounts::default(),
            #[cfg(test)]
            before_listen: Mutex::new(None),
        });

        WgStack { shared }
    }

    /// Open a TCP connection to `remote` through the tunnel.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        timeout: Duration,
    ) -> Result<WgTcpStream, TunnelError> {
        self.connect_sized(remote, timeout, None).await
    }

    /// Open a TCP connection to `remote` through the tunnel, its socket
    /// holding `buffers` instead of the stack's default sizes.
    pub async fn connect_with(
        &self,
        remote: SocketAddr,
        timeout: Duration,
        buffers: TcpBuffers,
    ) -> Result<WgTcpStream, TunnelError> {
        self.connect_sized(remote, timeout, Some(buffers)).await
    }

    pub(crate) async fn connect_sized(
        &self,
        remote: SocketAddr,
        timeout: Duration,
        buffers: Option<TcpBuffers>,
    ) -> Result<WgTcpStream, TunnelError> {
        let slot = self.shared.claim_socket()?;
        let stream =
            WgTcpStream::connect(Arc::clone(&self.shared), remote, timeout, buffers).await?;
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
    ///
    /// `backlog` is how many sockets listen at once, held between 1 and
    /// [`MAX_LISTEN_BACKLOG`]. Each takes one of the tunnel's socket slots,
    /// so a backlog the tunnel has no room for fails with
    /// [`TunnelError::AtCapacity`] and listens on nothing.
    pub fn listen(&self, port: u16, backlog: usize) -> Result<WgTcpListener, TunnelError> {
        self.listen_sized(port, backlog, None)
    }

    /// Like [`Self::listen`], every listening socket, and so every connection
    /// it accepts, holding `buffers` instead of the stack's default sizes.
    pub fn listen_with(
        &self,
        port: u16,
        backlog: usize,
        buffers: TcpBuffers,
    ) -> Result<WgTcpListener, TunnelError> {
        self.listen_sized(port, backlog, Some(buffers))
    }

    pub(crate) fn listen_sized(
        &self,
        port: u16,
        backlog: usize,
        buffers: Option<TcpBuffers>,
    ) -> Result<WgTcpListener, TunnelError> {
        let address = self
            .shared
            .config()
            .addresses
            .first()
            .map(|cidr| cidr.address)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        WgTcpListener::bind(Arc::clone(&self.shared), address, port, backlog, buffers)
    }

    /// Whether a listener on this stack holds `port`.
    pub(crate) fn listening_on(&self, port: u16) -> bool {
        self.shared
            .peek_stack(|stack| stack.listen_ports.contains(&port))
    }

    /// Bind a UDP socket inside the tunnel. `0` picks an ephemeral port.
    pub fn bind_udp(&self, port: u16) -> Result<WgUdpSocket, TunnelError> {
        self.bind_udp_sized(port, UDP_PACKETS, UDP_BUFFER_BYTES)
    }

    /// Bind a UDP socket that carries another tunnel's encrypted packets.
    ///
    /// Sized like the link itself rather than like a DNS socket: each
    /// datagram may be up to this link's MTU, and it sends as many as one
    /// engine pass takes. It receives [`TRANSPORT_RECEIVE_PASSES`] passes'
    /// worth, so a burst on the carried tunnel is absorbed here instead of
    /// being dropped.
    pub fn bind_transport_udp(&self, port: u16) -> Result<WgUdpSocket, TunnelError> {
        let mtu = usize::from(self.shared.config().mtu);
        let send = UdpQueue {
            packets: PACKET_QUEUE_DEPTH,
            bytes: PACKET_QUEUE_DEPTH * mtu,
        };
        let receive = UdpQueue {
            packets: TRANSPORT_RECEIVE_PASSES * send.packets,
            bytes: TRANSPORT_RECEIVE_PASSES * send.bytes,
        };
        self.bind_udp_queues(port, receive, send)
    }

    pub(crate) fn bind_udp_sized(
        &self,
        port: u16,
        packets: usize,
        bytes: usize,
    ) -> Result<WgUdpSocket, TunnelError> {
        let queue = UdpQueue { packets, bytes };
        self.bind_udp_queues(port, queue, queue)
    }

    fn bind_udp_queues(
        &self,
        port: u16,
        receive: UdpQueue,
        send: UdpQueue,
    ) -> Result<WgUdpSocket, TunnelError> {
        if self.shared.is_stopped() {
            return Err(TunnelError::Engine("the tunnel has stopped".to_string()));
        }
        let slot = self.shared.claim_socket()?;
        let socket = WgUdpSocket::bind(Arc::clone(&self.shared), port, receive, send)?;
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
        let handle = start_query(&shared, host, kind).map_err(|error| {
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

        // Every query of this lookup still in flight. Whichever settles
        // first, answer or failure, settles the lookup. The first query is
        // the one that times out first, so a lookup nobody answers fails when
        // and as one query did; a later query only adds chances to be
        // answered.
        let mut queries = QueryGuard {
            shared: &shared,
            handles: vec![handle],
        };
        let mut fresh_at = tokio::time::Instant::now() + DNS_FRESH_QUERY_AFTER;
        let answered = tokio::time::timeout_at(deadline, async {
            loop {
                let room = queries.handles.len() < DNS_LIVE_QUERIES;
                let fresh = async {
                    if room {
                        tokio::time::sleep_until(fresh_at).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! {
                    biased;
                    settled = poll_fn(|context| queries.poll_settled(context)) => {
                        return settled;
                    }
                    () = fresh => {
                        fresh_at += DNS_FRESH_QUERY_AFTER;
                        // The first query took the name as it is, so another
                        // fails only for want of a slot, and then the queries
                        // in flight carry on alone.
                        if let Ok(handle) = start_query(&shared, host, kind) {
                            queries.handles.push(handle);
                        }
                    }
                }
            }
        })
        .await;

        // Whether it answered, failed or timed out, every query left in
        // flight is cancelled when `queries` drops; a settled one smoltcp has
        // already freed.
        let outcome = match answered {
            Ok(Ok(addresses)) => Ok(addresses),
            Ok(Err(())) => Err(resolve_failure(
                host,
                "the tunnel's DNS server does not know this name",
            )),
            Err(_) => Err(resolve_failure(
                host,
                "the tunnel's DNS server did not answer in time",
            )),
        };
        drop(queries);
        outcome
    }
}

/// Start one query for `host` on the stack's resolver socket.
fn start_query(
    shared: &StackShared,
    host: &str,
    kind: DnsQueryType,
) -> Result<dns::QueryHandle, dns::StartQueryError> {
    shared.with_stack(|stack| {
        let dns_handle = stack.dns.expect("a resolver is configured");
        let (sockets, context) = stack.socket_and_context();
        sockets
            .get_mut::<dns::Socket>(dns_handle)
            .start_query(context, host, kind)
    })
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

/// The queries of one lookup still in flight. Cancels every one left when it
/// drops, so a lookup that settled, timed out or was abandoned does not hold
/// the resolver's slots until the process exits.
struct QueryGuard<'a> {
    shared: &'a Arc<StackShared>,
    handles: Vec<dns::QueryHandle>,
}

impl QueryGuard<'_> {
    /// The first of the queries to settle, answered or failed, oldest first
    /// when several have. smoltcp frees a settled query's slot as it hands
    /// the result back, so that handle leaves the list.
    fn poll_settled(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Result<Vec<IpAddr>, ()>> {
        let handles = &mut self.handles;
        self.shared.peek_stack(|stack| {
            let (socket, _) = stack.dns_socket().expect("a resolver is configured");
            for index in 0..handles.len() {
                let handle = handles[index];
                let settled = match socket.get_query_result(handle) {
                    Ok(addresses) => Ok(addresses.into_iter().map(IpAddr::from).collect()),
                    Err(dns::GetQueryResultError::Pending) => {
                        socket.register_query_waker(handle, context.waker());
                        continue;
                    }
                    Err(dns::GetQueryResultError::Failed) => Err(()),
                };
                handles.remove(index);
                return Poll::Ready(settled);
            }
            Poll::Pending
        })
    }
}

impl Drop for QueryGuard<'_> {
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        let handles = std::mem::take(&mut self.handles);
        self.shared.with_stack(|stack| {
            if let Some((socket, _)) = stack.dns_socket() {
                for handle in handles {
                    socket.cancel_query(handle);
                }
            }
        });
    }
}

/// The one task that drives smoltcp for a gotatun device.
///
/// It never busy-loops: after each poll it parks on whichever of the four
/// things can possibly need it next. Each pass first takes every packet the
/// device has already handed over, so a burst costs one poll rather than one
/// per packet, and the one timer is moved rather than rebuilt.
#[cfg(any(test, feature = "test-support"))]
async fn pump(shared: Arc<StackShared>, mut inbound: InboundRx, shutdown: Arc<Notify>) {
    let _stop = StopOnExit(Arc::clone(&shared));
    let proxy_config_id = shared.config().proxy_config_id.clone();
    let mut batch: Vec<Packet<Ip>> = Vec::with_capacity(PACKET_QUEUE_DEPTH);
    let timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(timer);

    loop {
        let delay = shared.peek_stack(|stack| stack.poll());

        // Take the notification future *before* deciding to sleep: a wake that
        // arrives while we were polling has already left its permit, so it is
        // observed on the next pass rather than lost.
        let woken = shared.wake.notified();
        let stopped = shutdown.notified();
        tokio::pin!(woken, stopped);

        let now = delay.is_some_and(|delay| delay.is_zero());
        let sleeping = delay.is_some() && !now;
        if let Some(delay) = delay.filter(|_| sleeping) {
            timer.as_mut().reset(tokio::time::Instant::now() + delay);
        }

        tokio::select! {
            biased;
            () = &mut stopped => break,
            received = inbound.recv_many(&mut batch, PACKET_QUEUE_DEPTH) => {
                if received == 0 {
                    // The device is gone.
                    break;
                }
            }
            () = &mut woken => {}
            () = &mut timer, if sleeping => {}
            () = tokio::task::yield_now(), if now => {}
        }
        // Whatever else arrived while this task was waking is taken now too,
        // up to what one pass hands the interface.
        while batch.len() < PACKET_QUEUE_DEPTH {
            match inbound.try_recv() {
                Ok(packet) => batch.push(packet),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            shared.peek_stack(|stack| {
                for packet in batch.drain(..) {
                    stack.phy.push_inbound(packet);
                }
            });
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

#[cfg(test)]
mod resource_tests {
    use super::*;
    use std::future::Future;

    /// An IPv4 UDP datagram from `10.0.0.2:4000` to `10.0.0.1:port` whose
    /// payload starts with `index`.
    fn udp_datagram(port: u16, index: u32) -> Packet<Ip> {
        use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr};
        let mut payload = vec![index as u8; 1200];
        payload[..4].copy_from_slice(&index.to_be_bytes());
        let source = smoltcp::wire::Ipv4Address::new(10, 0, 0, 2);
        let destination = smoltcp::wire::Ipv4Address::new(10, 0, 0, 1);
        let udp = UdpRepr {
            src_port: 4000,
            dst_port: port,
        };
        let ip = Ipv4Repr {
            src_addr: source,
            dst_addr: destination,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let checksums = smoltcp::phy::ChecksumCapabilities::default();
        let mut bytes = vec![0u8; ip.buffer_len() + ip.payload_len];
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
        ip.emit(&mut packet, &checksums);
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &source.into(),
            &destination.into(),
            payload.len(),
            |buffer| buffer.copy_from_slice(&payload),
            &checksums,
        );
        Packet::copy_from(&bytes[..])
            .try_into_ip()
            .expect("an IPv4 datagram")
    }

    /// The carrier's engine can hand a carried tunnel's socket several whole
    /// passes before that tunnel's engine reads any of them; none is lost.
    // A plain test, outside any runtime, so that no task budget makes a
    // ready read look like a waiting one.
    #[test]
    fn a_carried_tunnels_socket_holds_several_passes_before_it_is_read() {
        const PORT: u16 = 51000;
        const PASSES: usize = 3;
        let stack = WgStack::build_for_engine(StackConfig {
            addresses: vec!["10.0.0.1/24".parse().unwrap()],
            dns_servers: vec!["10.0.0.2".parse().unwrap()],
            mtu: 1280,
            proxy_config_id: "carried-burst-test".into(),
            download_tuning: false,
            max_sockets: DEFAULT_MAX_SOCKETS,
        });
        let socket = stack.bind_transport_udp(PORT).unwrap();
        let mut outbound = Vec::new();
        for pass in 0..PASSES {
            let mut inbound: Vec<Packet<Ip>> = (0..PACKET_QUEUE_DEPTH)
                .map(|at| udp_datagram(PORT, (pass * PACKET_QUEUE_DEPTH + at) as u32))
                .collect();
            stack
                .shared()
                .peek_stack(|inner| inner.pass(&mut inbound, &mut outbound));
            outbound.clear();
        }
        // Every datagram is already queued, so each read completes on its
        // first poll; one that would wait was dropped.
        let mut buffer = vec![0u8; 2048];
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        for index in 0..(PASSES * PACKET_QUEUE_DEPTH) as u32 {
            let read = std::pin::pin!(socket.recv_from(&mut buffer)).poll(&mut context);
            let Poll::Ready(read) = read else {
                panic!("datagram {index} was dropped");
            };
            let (read, from) = read.unwrap();
            assert_eq!(read, 1200);
            assert_eq!(from, SocketAddr::from(([10, 0, 0, 2], 4000)));
            assert_eq!(buffer[..4], index.to_be_bytes(), "datagram {index}");
        }
    }

    /// A stack with no engine, for driving sends and passes by hand.
    fn engine_stack(name: &str) -> WgStack {
        WgStack::build_for_engine(StackConfig {
            addresses: vec!["10.0.0.1/24".parse().unwrap()],
            dns_servers: vec!["10.0.0.2".parse().unwrap()],
            mtu: 1280,
            proxy_config_id: name.into(),
            download_tuning: false,
            max_sockets: DEFAULT_MAX_SOCKETS,
        })
    }

    /// Payloads of `count` datagrams, each different and of its own length.
    fn payloads(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let mut payload = vec![index as u8; 100 + index * 7];
                payload[..4].copy_from_slice(&(index as u32).to_be_bytes());
                payload
            })
            .collect()
    }

    /// Run one pass and return each UDP datagram the stack sent: its
    /// destination, source port and payload, in the order sent.
    fn sent_datagrams(stack: &WgStack) -> Vec<(SocketAddr, u16, Vec<u8>)> {
        use smoltcp::wire::{Ipv4Packet, UdpPacket};
        let mut inbound = Vec::new();
        let mut outbound = Vec::new();
        stack
            .shared()
            .peek_stack(|inner| inner.pass(&mut inbound, &mut outbound));
        outbound
            .into_iter()
            .map(|packet| {
                let packet: Packet = packet.into();
                let ip = Ipv4Packet::new_checked(&packet[..]).expect("an IPv4 packet");
                let udp = UdpPacket::new_checked(ip.payload()).expect("a UDP datagram");
                (
                    SocketAddr::new(std::net::IpAddr::V4(ip.dst_addr()), udp.dst_port()),
                    udp.src_port(),
                    udp.payload().to_vec(),
                )
            })
            .collect()
    }

    /// Poll `future` once, outside any runtime; it must finish.
    fn ready<F: Future>(future: F) -> F::Output {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match std::pin::pin!(future).poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("the send waited with room in the buffer"),
        }
    }

    /// A batch sent through a socket inside the tunnel leaves the stack as
    /// the same datagrams, bytes and order, as one single send per datagram,
    /// for one hold of the stack's lock and one wake where the single sends
    /// take one of each per datagram.
    #[test]
    fn a_batch_send_leaves_as_the_single_sends_do_for_one_lock_and_one_wake() {
        const COUNT: usize = 40;
        let target = SocketAddr::from(([10, 0, 0, 2], 4000));
        let payloads = payloads(COUNT);
        let datagrams: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();

        let single = engine_stack("single-send-test");
        let single_socket = single.bind_transport_udp(51000).unwrap();
        let before = single.shared().counts.read();
        for datagram in &datagrams {
            ready(single_socket.send_to(datagram, target)).unwrap();
        }
        let after = single.shared().counts.read();
        assert_eq!((after.0 - before.0, after.1 - before.1), (COUNT, COUNT));
        let singles = sent_datagrams(&single);

        let batch = engine_stack("batch-send-test");
        let batch_socket = batch.bind_transport_udp(51000).unwrap();
        let before = batch.shared().counts.read();
        let accepted = ready(batch_socket.send_batch_to(&datagrams, target)).unwrap();
        let after = batch.shared().counts.read();
        assert_eq!(accepted, COUNT);
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
        let batched = sent_datagrams(&batch);

        assert_eq!(singles.len(), COUNT);
        assert_eq!(batched, singles);
        for (index, (to, from_port, payload)) in batched.iter().enumerate() {
            assert_eq!((*to, *from_port), (target, 51000));
            assert_eq!(payload, &payloads[index], "datagram {index}");
        }
    }

    /// A carried tunnel's engine hands a whole flush to its carrier's socket
    /// as one batch: one hold of the carrier's lock and one wake of its
    /// engine for the lot, and every packet leaves in order.
    #[test]
    fn a_carried_tunnels_flush_takes_the_carriers_lock_and_wakes_it_once() {
        use gotatun::udp::UdpSend;
        const COUNT: usize = 40;
        let target = SocketAddr::from(([10, 0, 0, 2], 4000));
        let payloads = payloads(COUNT);
        let carrier = engine_stack("carrier-flush-test");
        let socket: Arc<dyn crate::endpoint::DatagramSocket> =
            Arc::new(carrier.bind_transport_udp(51000).unwrap());
        let carried = crate::wireguard::transport::TunnelSocket::Datagram(socket);
        let mut packets: Vec<(Packet, SocketAddr)> = payloads
            .iter()
            .map(|payload| (Packet::copy_from(&payload[..]), target))
            .collect();

        let before = carrier.shared().counts.read();
        ready(carried.send_many_to(&mut Default::default(), &mut packets)).unwrap();
        let after = carrier.shared().counts.read();

        assert!(packets.is_empty());
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
        let sent: Vec<Vec<u8>> = sent_datagrams(&carrier)
            .into_iter()
            .map(|(_, _, payload)| payload)
            .collect();
        assert_eq!(sent, payloads);

        // A pass streams its packets into the carrier in batches as large as
        // what it already sent: 1, 1, 2, 4, ... up to one send call's worth.
        let mut sent = 0;
        let mut batches = Vec::new();
        while sent < 300 {
            let batch = carried.stream_batch(sent);
            batches.push(batch);
            sent += batch;
        }
        assert_eq!(batches, [1, 1, 2, 4, 8, 16, 32, 64, 64, 64, 64]);
    }

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
                let handle = inner.add_tcp_socket(None);
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

    /// A stack with no engine and no resolver, capped at `max_sockets`.
    fn capped_engine_stack(max_sockets: usize) -> WgStack {
        WgStack::build_for_engine(StackConfig {
            addresses: vec!["10.0.0.1/24".parse().unwrap()],
            dns_servers: Vec::new(),
            mtu: 1280,
            proxy_config_id: "listen-cap-test".into(),
            download_tuning: false,
            max_sockets,
        })
    }

    fn open_slots(stack: &WgStack) -> usize {
        stack.shared.open_sockets.open.load(Ordering::SeqCst)
    }

    fn socket_count(stack: &WgStack) -> usize {
        stack
            .shared
            .peek_stack(|inner| inner.sockets.iter().count())
    }

    /// A listener's sockets are charged to the tunnel's cap: a backlog the
    /// cap cannot hold fails as a full tunnel and creates no socket, however
    /// large it is, and one that fits holds a slot per listening socket.
    #[test]
    fn a_listeners_backlog_is_charged_to_the_socket_cap() {
        let stack = capped_engine_stack(MIN_MAX_SOCKETS);
        for backlog in [MIN_MAX_SOCKETS + 1, 100, usize::MAX] {
            let refused = stack.listen(7000, backlog);
            assert!(
                matches!(
                    refused,
                    Err(TunnelError::AtCapacity {
                        open: MIN_MAX_SOCKETS,
                        ..
                    })
                ),
                "a backlog of {backlog} does not fit a cap of {MIN_MAX_SOCKETS}"
            );
            assert_eq!(socket_count(&stack), 0, "backlog {backlog}");
            assert_eq!(open_slots(&stack), 0, "backlog {backlog}");
        }

        let listener = stack.listen(7000, 4).unwrap();
        assert_eq!((open_slots(&stack), socket_count(&stack)), (4, 4));
        // The other twelve slots are what dials and other listeners share.
        let rest = stack.listen(7001, MIN_MAX_SOCKETS - 4).unwrap();
        assert_eq!(open_slots(&stack), MIN_MAX_SOCKETS);
        assert!(matches!(
            stack.shared.claim_socket(),
            Err(TunnelError::AtCapacity { .. })
        ));
        drop((listener, rest));
        assert_eq!((open_slots(&stack), socket_count(&stack)), (0, 0));
    }

    /// A backlog past [`MAX_LISTEN_BACKLOG`] is held to it, and the 16 a
    /// consumer typically asks for fits a default tunnel.
    #[test]
    fn a_listeners_backlog_is_held_to_its_bound() {
        let stack = capped_engine_stack(DEFAULT_MAX_SOCKETS);
        let typical = stack.listen(7000, 16).unwrap();
        assert_eq!((open_slots(&stack), socket_count(&stack)), (16, 16));
        let large = stack.listen(7001, 4 * MAX_LISTEN_BACKLOG).unwrap();
        assert_eq!(open_slots(&stack), 16 + MAX_LISTEN_BACKLOG);
        assert_eq!(socket_count(&stack), 16 + MAX_LISTEN_BACKLOG);
        drop(large);
        let none = stack.listen(7001, 0).unwrap();
        assert_eq!(open_slots(&stack), 17, "a backlog of 0 still listens");
        drop((typical, none));
        assert_eq!((open_slots(&stack), socket_count(&stack)), (0, 0));
    }

    /// Run `listen(port, 2)` on two threads that both reach the point where
    /// a listener takes its port before either goes on.
    fn listen_together(stack: &WgStack, port: u16) -> [Result<WgTcpListener, TunnelError>; 2] {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let at = Arc::clone(&barrier);
        *stack.shared.before_listen.lock().unwrap() = Some(Arc::new(move || {
            at.wait();
        }));
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| stack.listen(port, 2));
            let second = scope.spawn(|| stack.listen(port, 2));
            [first.join().unwrap(), second.join().unwrap()]
        });
        *stack.shared.before_listen.lock().unwrap() = None;
        results
    }

    /// Two listeners asking for one port at the same moment: one gets it,
    /// the other is refused, and accepted connections are never split
    /// between two listeners.
    #[test]
    fn two_listeners_racing_for_one_port_get_one_listener() {
        let stack = capped_engine_stack(DEFAULT_MAX_SOCKETS);
        let [first, second] = listen_together(&stack, 7000);
        let (listener, refused) = match (first, second) {
            (Ok(listener), Err(refused)) | (Err(refused), Ok(listener)) => (listener, refused),
            (Ok(_), Ok(_)) => panic!("two listeners took port 7000"),
            (Err(first), Err(second)) => panic!("both refused: {first}; {second}"),
        };
        assert_eq!(listener.local_addr().port(), 7000);
        assert!(
            matches!(&refused, TunnelError::Engine(detail) if detail.contains("already listens on port 7000")),
            "{refused}"
        );
        assert_eq!(open_slots(&stack), 2, "the refused listener holds nothing");
        assert_eq!(socket_count(&stack), 2);
    }

    /// Two listeners asking for any port at the same moment get two
    /// different ports.
    #[test]
    fn two_listeners_racing_for_any_port_get_different_ports() {
        let stack = capped_engine_stack(DEFAULT_MAX_SOCKETS);
        let [first, second] = listen_together(&stack, 0);
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_ne!(first.local_addr().port(), second.local_addr().port());
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

#[cfg(test)]
mod link_tests {
    //! Two stacks joined back to back by the adapter channels, with no
    //! device between them: what one stack emits, the other receives.

    use super::*;
    use crate::wireguard::adapter::ip_channels;
    use gotatun::packet::PacketBufPool;
    use gotatun::tun::{IpRecv, IpSend};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PORT: u16 = 8080;

    struct Pair {
        near: WgStack,
        far: WgStack,
        /// Every SYN that crossed the wire, in order.
        syns: Arc<std::sync::Mutex<Vec<Syn>>>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    /// What a SYN, or a SYN-ACK, told the far side about its sender's
    /// receive window.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Syn {
        source_port: u16,
        acknowledges: bool,
        window: u16,
        window_scale: Option<u8>,
    }

    fn syn_in(packet: &[u8]) -> Option<Syn> {
        use smoltcp::phy::ChecksumCapabilities;
        use smoltcp::wire::{Ipv4Packet, TcpControl, TcpPacket, TcpRepr};
        let ip = Ipv4Packet::new_checked(packet).ok()?;
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        let repr = TcpRepr::parse(
            &tcp,
            &ip.src_addr().into(),
            &ip.dst_addr().into(),
            &ChecksumCapabilities::ignored(),
        )
        .ok()?;
        (repr.control == TcpControl::Syn).then_some(Syn {
            source_port: repr.src_port,
            acknowledges: repr.ack_number.is_some(),
            window: repr.window_len,
            window_scale: repr.window_scale,
        })
    }

    impl Drop for Pair {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    fn config(address: &str) -> StackConfig {
        StackConfig {
            addresses: vec![address.parse().unwrap()],
            dns_servers: Vec::new(),
            mtu: 1420,
            proxy_config_id: "link-test".into(),
            download_tuning: true,
            max_sockets: DEFAULT_MAX_SOCKETS,
        }
    }

    fn pair() -> Pair {
        pair_with_far_cap(DEFAULT_MAX_SOCKETS)
    }

    /// Two stacks back to back, the far one capped at `far_cap` sockets.
    fn pair_with_far_cap(far_cap: usize) -> Pair {
        pair_of(
            config("10.9.0.1/24"),
            StackConfig {
                max_sockets: far_cap,
                ..config("10.9.0.2/24")
            },
        )
    }

    /// Two stacks back to back, built from `near` and `far`.
    fn pair_of(near: StackConfig, far: StackConfig) -> Pair {
        let runtime = tokio::runtime::Handle::current();
        let (near_in, near_out, near_inbound, near_outbound) = ip_channels(1420);
        let (far_in, far_out, far_inbound, far_outbound) = ip_channels(1420);
        let (near, near_pump) = WgStack::start(
            near,
            near_inbound,
            near_outbound,
            Arc::new(Notify::new()),
            &runtime,
        );
        let (far, far_pump) = WgStack::start(
            far,
            far_inbound,
            far_outbound,
            Arc::new(Notify::new()),
            &runtime,
        );
        let syns = Arc::new(std::sync::Mutex::new(Vec::new()));
        let wire = |mut from: crate::wireguard::adapter::StackToDevice,
                    mut to: crate::wireguard::adapter::DeviceToStack| {
            let syns = Arc::clone(&syns);
            tokio::spawn(async move {
                let mut pool = PacketBufPool::new(1);
                while let Ok(packets) = from.recv(&mut pool).await {
                    let packets: Vec<_> = packets.collect();
                    for packet in packets {
                        let bytes: gotatun::packet::Packet = packet.into();
                        if let Some(syn) = syn_in(&bytes[..]) {
                            syns.lock().unwrap().push(syn);
                        }
                        let packet = bytes.try_into_ip().expect("an IP packet");
                        if to.send(packet).await.is_err() {
                            return;
                        }
                    }
                }
            })
        };
        Pair {
            tasks: vec![
                near_pump,
                far_pump,
                wire(near_out, far_in),
                wire(far_out, near_in),
            ],
            near,
            far,
            syns,
        }
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    /// A reader that stops reading holds the sender at its window; nothing
    /// that arrived is lost, and once it reads again every byte comes, in
    /// order. A full buffer's worth is in flight at once, so the window
    /// offered the whole buffer.
    #[tokio::test]
    async fn a_stalled_reader_loses_nothing_and_its_full_window_is_used() {
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let body = pattern(5 * 1024 * 1024 + 17);
        let sent = body.clone();
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            stream.write_all(&sent).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = pair
            .near
            .connect(
                SocketAddr::from(([10, 9, 0, 2], PORT)),
                // Far above any run; the test runner bounds the test.
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Read nothing until the receive buffer is full to within one
        // segment: the sender has filled the whole window and is waiting on
        // it.
        loop {
            let (queued, capacity) = stream.receive_buffer();
            assert_eq!(capacity, 1024 * 1024);
            if capacity - queued < 1420 {
                break;
            }
            tokio::task::yield_now().await;
        }

        let mut received = Vec::with_capacity(body.len());
        stream.read_to_end(&mut received).await.unwrap();
        assert!(received == body, "every byte, in order");
        server.await.unwrap();
        for stack in [&pair.near, &pair.far] {
            let (_, overrun) = stack.shared.peek_stack(|stack| stack.phy.drop_counts());
            assert_eq!(overrun, 0, "no packet the stack was handed was discarded");
        }
    }

    /// Reads from a buffer that is mostly free do not wake the stack, and
    /// the transfer still completes with every byte.
    #[tokio::test]
    async fn a_reader_keeping_up_moves_every_byte() {
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let body = pattern(3 * 1024 * 1024 + 5);
        let sent = body.clone();
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            stream.write_all(&sent).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = pair
            .near
            .connect(
                SocketAddr::from(([10, 9, 0, 2], PORT)),
                // Far above any run; the test runner bounds the test.
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let mut received = Vec::with_capacity(body.len());
        let mut chunk = vec![0u8; 1500];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..read]);
        }
        assert!(received == body, "every byte, in order");
        server.await.unwrap();
    }

    /// Accept one connection on the far stack, send `payload` on it, wait
    /// until the near side acknowledged every byte, then end it with a FIN
    /// (`reset == false`) or an RST (`reset == true`). Returns the near
    /// stream, holding the payload, once its socket has seen the end.
    async fn ended_after(pair: &Pair, payload: &[u8], reset: bool) -> WgTcpStream {
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let sent = payload.to_vec();
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            stream.write_all(&sent).await.unwrap();
            while stream.socket_state().1 != 0 {
                tokio::task::yield_now().await;
            }
            if reset {
                stream.abort();
            } else {
                stream.shutdown().await.unwrap();
            }
            stream
        });
        let stream = pair
            .near
            .connect(
                SocketAddr::from(([10, 9, 0, 2], PORT)),
                // Far above any run; the test runner bounds the test.
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        // Keep the far stream alive until the near side saw the end, so its
        // drop cannot add a FIN or an RST of its own.
        let far = server.await.unwrap();
        let ended = if reset {
            tcp::State::Closed
        } else {
            tcp::State::CloseWait
        };
        while stream.socket_state().0 != ended {
            tokio::task::yield_now().await;
        }
        drop(far);
        stream
    }

    /// A FIN after the payload: the reader gets every byte, then a clean end
    /// of stream.
    #[tokio::test]
    async fn a_fin_after_the_payload_is_the_end_of_the_stream() {
        let pair = pair();
        let payload = pattern(3000);
        let mut stream = ended_after(&pair, &payload, false).await;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert!(received == payload, "every byte, in order");
        let mut more = [0u8; 16];
        assert_eq!(stream.read(&mut more).await.unwrap(), 0, "still the end");
    }

    /// An RST after the payload: smoltcp keeps the bytes that arrived before
    /// it, so the reader gets those, and then an error. Never an end of
    /// stream, which would pass a cut-off response as a whole one.
    #[tokio::test]
    async fn a_reset_after_the_payload_is_an_error_not_the_end_of_the_stream() {
        let pair = pair();
        let payload = pattern(3000);
        let mut stream = ended_after(&pair, &payload, true).await;
        let mut received = vec![0u8; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert!(received == payload, "the bytes that came before the reset");
        let mut more = [0u8; 16];
        let error = stream
            .read(&mut more)
            .await
            .expect_err("a reset is not the end of the stream");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        let again = stream.read(&mut more).await.expect_err("still reset");
        assert_eq!(again.kind(), std::io::ErrorKind::ConnectionReset);
    }

    fn open_slots(stack: &WgStack) -> usize {
        stack.shared.open_sockets.open.load(Ordering::SeqCst)
    }

    fn socket_count(stack: &WgStack) -> usize {
        stack
            .shared
            .peek_stack(|inner| inner.sockets.iter().count())
    }

    fn listening_count(stack: &WgStack) -> usize {
        stack.shared.peek_stack(|inner| {
            inner
                .sockets
                .iter()
                .filter(|(_, socket)| match socket {
                    smoltcp::socket::Socket::Tcp(socket) => socket.is_listening(),
                    _ => false,
                })
                .count()
        })
    }

    async fn dial(pair: &Pair) -> WgTcpStream {
        pair.near
            .connect(
                SocketAddr::from(([10, 9, 0, 2], PORT)),
                // Far above any run; the test runner bounds the test.
                Duration::from_secs(3600),
            )
            .await
            .unwrap()
    }

    /// An accepted connection takes over the slot its listening socket held,
    /// and the listener puts a fresh listening socket, with a slot of its
    /// own, in its place: one slot per socket, none counted twice.
    #[tokio::test]
    async fn an_accepted_stream_holds_one_slot_and_its_listener_is_refilled() {
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 16).unwrap();
        assert_eq!((open_slots(&pair.far), socket_count(&pair.far)), (16, 16));

        let (accepted, dialled) = tokio::join!(listener.accept(), dial(&pair));
        let accepted = accepted.unwrap();
        assert_eq!(open_slots(&pair.far), 17);
        assert_eq!(socket_count(&pair.far), 17);
        assert_eq!(listening_count(&pair.far), 16);

        drop(listener);
        assert_eq!((open_slots(&pair.far), socket_count(&pair.far)), (1, 1));
        drop((accepted, dialled));
    }

    /// On a full tunnel the listener hands out what it accepted and runs
    /// short rather than go past the cap; once a slot frees, a waiting accept
    /// takes it, listens again and accepts the next connection.
    #[tokio::test]
    async fn a_listener_on_a_full_tunnel_runs_short_and_refills_when_a_slot_frees() {
        let pair = pair_with_far_cap(MIN_MAX_SOCKETS);
        let mut listener = pair.far.listen(PORT, MIN_MAX_SOCKETS).unwrap();
        assert_eq!(open_slots(&pair.far), MIN_MAX_SOCKETS);

        let mut far_streams = Vec::new();
        let mut near_streams = Vec::new();
        for _ in 0..MIN_MAX_SOCKETS {
            let (accepted, dialled) = tokio::join!(listener.accept(), dial(&pair));
            far_streams.push(accepted.unwrap());
            near_streams.push(dialled);
        }
        assert_eq!(open_slots(&pair.far), MIN_MAX_SOCKETS);
        assert_eq!(socket_count(&pair.far), MIN_MAX_SOCKETS);
        assert_eq!(listening_count(&pair.far), 0);
        assert!(
            pair.far.listening_on(PORT),
            "a listener holds its port while no socket listens on it"
        );

        let waiting = tokio::spawn(async move {
            let accepted = listener.accept().await;
            (listener, accepted)
        });

        // Free one slot: the near side closes first, so the far socket
        // finishes in LAST-ACK and closes for good.
        let far = far_streams.pop().unwrap();
        drop(near_streams.pop());
        while far.socket_state().0 != tcp::State::CloseWait {
            tokio::task::yield_now().await;
        }
        drop(far);

        while listening_count(&pair.far) == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(open_slots(&pair.far), MIN_MAX_SOCKETS);
        let dialled = dial(&pair).await;
        let (_listener, accepted) = waiting.await.unwrap();
        let accepted = accepted.unwrap();
        assert_eq!(open_slots(&pair.far), MIN_MAX_SOCKETS);
        drop((accepted, dialled));
    }

    /// A read into a buffer with no room left completes at once, reading
    /// nothing, as `AsyncRead` requires; it does not wait for bytes it could
    /// not take.
    #[tokio::test]
    async fn a_read_into_a_full_buffer_completes_at_once() {
        use tokio::io::{AsyncRead, ReadBuf};
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let (accepted, mut dialled) = tokio::join!(listener.accept(), dial(&pair));
        let _accepted = accepted.unwrap();

        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let mut full: [u8; 0] = [];
        let mut buffer = ReadBuf::new(&mut full);
        let read = std::pin::Pin::new(&mut dialled).poll_read(&mut context, &mut buffer);
        assert!(
            matches!(read, Poll::Ready(Ok(()))),
            "a full buffer is ready at once: {read:?}"
        );
        assert_eq!(buffer.filled().len(), 0);
    }

    const KIB: usize = 1024;
    const FAR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 9, 0, 2)),
        PORT,
    );
    // Far above any run; the test runner bounds the test.
    const FOREVER: Duration = Duration::from_secs(3600);

    fn syn_from(pair: &Pair, port: u16, acknowledges: bool) -> Syn {
        let syns = pair.syns.lock().unwrap();
        *syns
            .iter()
            .find(|syn| syn.source_port == port && syn.acknowledges == acknowledges)
            .expect("the SYN crossed the wire")
    }

    /// A dial and a listener that ask for nothing hold the stack's default
    /// sizes, and their handshake offers what a tuned socket always offered:
    /// a full 16-bit window, with a shift of 5.
    #[tokio::test]
    async fn a_default_dial_keeps_the_stacks_sizes_and_window_scale() {
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let (accepted, dialled) = tokio::join!(listener.accept(), dial(&pair));
        let accepted = accepted.unwrap();
        assert_eq!(dialled.buffer_capacities(), (1024 * KIB, 1024 * KIB));
        assert_eq!(accepted.buffer_capacities(), (1024 * KIB, 1024 * KIB));

        let dial_syn = syn_from(&pair, accepted.peer_addr().port(), false);
        assert_eq!(
            (dial_syn.window, dial_syn.window_scale),
            (u16::MAX, Some(5))
        );
        let answer = syn_from(&pair, PORT, true);
        assert_eq!((answer.window, answer.window_scale), (u16::MAX, Some(5)));
    }

    /// A sized dial and a sized listener hold exactly the sizes they asked
    /// for, the listener's idle sockets included, and each handshake offers
    /// the window scale of its own receive buffer: what a stack built with
    /// that buffer as its default offers.
    #[tokio::test]
    async fn a_sized_dial_and_listener_hold_their_sizes_and_scale_to_them() {
        let pair = pair();
        let listened = TcpBuffers::new(128 * KIB, 512 * KIB);
        let mut listener = pair.far.listen_with(PORT, 2, listened).unwrap();
        pair.far.shared.peek_stack(|inner| {
            for (_, socket) in inner.sockets.iter() {
                if let smoltcp::socket::Socket::Tcp(socket) = socket {
                    assert!(socket.is_listening());
                    assert_eq!(
                        (socket.recv_capacity(), socket.send_capacity()),
                        (128 * KIB, 512 * KIB)
                    );
                }
            }
        });
        let dialled_with = TcpBuffers::new(256 * KIB, 64 * KIB);
        let (accepted, dialled) = tokio::join!(
            listener.accept(),
            pair.near.connect_with(FAR, FOREVER, dialled_with)
        );
        let (accepted, dialled) = (accepted.unwrap(), dialled.unwrap());
        assert_eq!(dialled.buffer_capacities(), (256 * KIB, 64 * KIB));
        assert_eq!(accepted.buffer_capacities(), (128 * KIB, 512 * KIB));

        // smoltcp shifts by the bits a capacity takes past 16: 1 MiB takes
        // 21 bits, so 5; 256 KiB takes 19, so 3; 128 KiB takes 18, so 2.
        let dial_syn = syn_from(&pair, accepted.peer_addr().port(), false);
        assert_eq!(
            (dial_syn.window, dial_syn.window_scale),
            (u16::MAX, Some(3))
        );
        let answer = syn_from(&pair, PORT, true);
        assert_eq!((answer.window, answer.window_scale), (u16::MAX, Some(2)));
    }

    /// Sizes outside the bounds are held to them; sizes inside are kept.
    #[test]
    fn asked_sizes_are_held_to_their_bounds() {
        let low = TcpBuffers::new(0, 1);
        assert_eq!(
            (low.receive(), low.send()),
            (MIN_TCP_BUFFER_BYTES, MIN_TCP_BUFFER_BYTES)
        );
        let high = TcpBuffers::new(usize::MAX, MAX_TCP_BUFFER_BYTES + 1);
        assert_eq!(
            (high.receive(), high.send()),
            (MAX_TCP_BUFFER_BYTES, MAX_TCP_BUFFER_BYTES)
        );
        let edges = TcpBuffers::new(MIN_TCP_BUFFER_BYTES, MAX_TCP_BUFFER_BYTES);
        assert_eq!(
            (edges.receive(), edges.send()),
            (MIN_TCP_BUFFER_BYTES, MAX_TCP_BUFFER_BYTES)
        );
        let inside = TcpBuffers::new(200 * KIB + 3, 64 * KIB);
        assert_eq!((inside.receive(), inside.send()), (200 * KIB + 3, 64 * KIB));
        let large = TcpBuffers::new(4 * 1024 * KIB, 64 * 1024 * KIB + 1);
        assert_eq!(
            (large.receive(), large.send()),
            (4 * 1024 * KIB, 64 * 1024 * KIB + 1)
        );
    }

    /// The ceiling is the largest window TCP can advertise, 65,535 << 14,
    /// and it sits just under the 1 GiB smoltcp refuses. The defaults are
    /// their own numbers, not the ceiling.
    #[test]
    fn the_ceiling_is_the_largest_advertisable_window_and_defaults_stay_put() {
        assert_eq!(MAX_TCP_BUFFER_BYTES, 1_073_725_440);
        const { assert!(MAX_TCP_BUFFER_BYTES < 1 << 30) };
        assert_eq!(
            TcpBuffers::default_for(true),
            TcpBuffers::new(1024 * KIB, 1024 * KIB)
        );
        assert_eq!(
            TcpBuffers::default_for(false),
            TcpBuffers::new(64 * KIB, 64 * KIB)
        );
        assert_eq!(MIN_TCP_BUFFER_BYTES, 16 * KIB);
    }

    /// Sizes past the tuned default's 1 MiB are kept on a dial and on a
    /// listener, and each handshake offers the window scale of its own
    /// receive buffer: 4 MiB takes 23 bits, so 7; 16 MiB takes 25, so 9.
    #[tokio::test]
    async fn sizes_past_one_mib_are_kept_on_dial_and_listen() {
        let pair = pair();
        let listened = TcpBuffers::new(16 * 1024 * KIB, 2 * 1024 * KIB);
        let mut listener = pair.far.listen_with(PORT, 1, listened).unwrap();
        let dialled_with = TcpBuffers::new(4 * 1024 * KIB, 64 * KIB);
        let (accepted, dialled) = tokio::join!(
            listener.accept(),
            pair.near.connect_with(FAR, FOREVER, dialled_with)
        );
        let (accepted, dialled) = (accepted.unwrap(), dialled.unwrap());
        assert_eq!(dialled.buffer_capacities(), (4 * 1024 * KIB, 64 * KIB));
        assert_eq!(
            accepted.buffer_capacities(),
            (16 * 1024 * KIB, 2 * 1024 * KIB)
        );

        let dial_syn = syn_from(&pair, accepted.peer_addr().port(), false);
        assert_eq!(
            (dial_syn.window, dial_syn.window_scale),
            (u16::MAX, Some(7))
        );
        let answer = syn_from(&pair, PORT, true);
        assert_eq!((answer.window, answer.window_scale), (u16::MAX, Some(9)));
    }

    /// A dial at the ceiling offers the largest legal window scale, 14, and
    /// a full 16-bit window: the socket is made (smoltcp does not refuse it)
    /// and the handshake stays inside RFC 7323. The buffer's pages are never
    /// written here, so the operating system commits them lazily.
    #[tokio::test]
    async fn a_dial_at_the_ceiling_offers_the_largest_legal_window_scale() {
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let (accepted, dialled) = tokio::join!(
            listener.accept(),
            pair.near.connect_with(
                FAR,
                FOREVER,
                TcpBuffers::new(MAX_TCP_BUFFER_BYTES, MIN_TCP_BUFFER_BYTES)
            )
        );
        let (accepted, dialled) = (accepted.unwrap(), dialled.unwrap());
        assert_eq!(
            dialled.buffer_capacities(),
            (MAX_TCP_BUFFER_BYTES, MIN_TCP_BUFFER_BYTES)
        );
        let dial_syn = syn_from(&pair, accepted.peer_addr().port(), false);
        assert_eq!(
            (dial_syn.window, dial_syn.window_scale),
            (u16::MAX, Some(14))
        );
    }

    /// Sized sockets carry a body each way at once, every byte in order, and
    /// a receiver that stops reading is sent its whole receive buffer before
    /// the sender waits: the window it offered is all of the buffer.
    #[tokio::test]
    async fn sized_sockets_move_every_byte_both_ways_and_use_their_whole_window() {
        let pair = pair();
        let mut listener = pair
            .far
            .listen_with(PORT, 1, TcpBuffers::new(192 * KIB, 96 * KIB))
            .unwrap();
        let down = pattern(3 * 1024 * KIB + 11);
        let up: Vec<u8> = pattern(2 * 1024 * KIB + 7).into_iter().rev().collect();
        let (sent_down, expected_up) = (down.clone(), up.clone());
        let server = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let send = async {
                writer.write_all(&sent_down).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let mut received = Vec::new();
            let receive = reader.read_to_end(&mut received);
            let ((), read) = tokio::join!(send, receive);
            read.unwrap();
            assert!(received == expected_up, "every byte up, in order");
        });
        let stream = pair
            .near
            .connect_with(FAR, FOREVER, TcpBuffers::new(160 * KIB, 48 * KIB))
            .await
            .unwrap();
        loop {
            let (queued, capacity) = stream.receive_buffer();
            assert_eq!(capacity, 160 * KIB);
            if capacity - queued < 1420 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let (mut reader, mut writer) = tokio::io::split(stream);
        let send = async {
            writer.write_all(&up).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let mut received = Vec::new();
        let receive = reader.read_to_end(&mut received);
        let ((), read) = tokio::join!(send, receive);
        read.unwrap();
        assert!(received == down, "every byte down, in order");
        server.await.unwrap();
    }

    /// A socket that closed first and reached TIME-WAIT has delivered every
    /// byte both ways. Once its stream is dropped, its buffers and its slot
    /// are given back at the next reclaim, not after TIME-WAIT's wait.
    #[tokio::test]
    async fn a_finished_socket_gives_its_buffers_back_without_waiting_out_time_wait() {
        let pair = pair();
        let mut listener = pair.far.listen(PORT, 1).unwrap();
        let (accepted, mut dialled) = tokio::join!(listener.accept(), dial(&pair));
        let mut accepted = accepted.unwrap();
        drop(listener);
        let sockets_before = socket_count(&pair.near);

        dialled.write_all(b"the last request").await.unwrap();
        dialled.shutdown().await.unwrap();
        let mut request = Vec::new();
        accepted.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"the last request");
        accepted.shutdown().await.unwrap();
        while dialled.socket_state().0 != tcp::State::TimeWait {
            tokio::task::yield_now().await;
        }

        drop(dialled);
        pair.near.shared.with_stack(|inner| {
            inner.reclaim(inner.now());
            assert!(inner.closing.is_empty(), "nothing left to linger");
        });
        assert_eq!(socket_count(&pair.near), sockets_before - 1);
        assert_eq!(open_slots(&pair.near), 0);
        drop(accepted);
    }

    const RESOLVED: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 9, 0, 77);

    /// A resolver on the far stack that drops every query reaching it
    /// before `dark` has passed (forever with `None`), and with
    /// `only_first` answers only the transaction it saw first. It records
    /// when each query reached it, on the tokio clock, and its transaction.
    struct DarkResolver {
        queries: Arc<std::sync::Mutex<Vec<(Duration, u16)>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl DarkResolver {
        fn start(far: &WgStack, dark: Option<Duration>, only_first: bool) -> Self {
            let socket = far.bind_udp(53).unwrap();
            let names = std::collections::HashMap::from([(
                "dark.test".to_string(),
                vec![std::net::IpAddr::V4(RESOLVED)],
            )]);
            let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
            let seen = Arc::clone(&queries);
            let opened = tokio::time::Instant::now();
            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 1500];
                loop {
                    let Ok((read, from)) = socket.recv_from(&mut buffer).await else {
                        return;
                    };
                    let query = &buffer[..read];
                    let txid = u16::from_be_bytes([query[0], query[1]]);
                    let at = tokio::time::Instant::now() - opened;
                    let first = {
                        let mut seen = seen.lock().unwrap();
                        seen.push((at, txid));
                        seen[0].1
                    };
                    if dark.is_none_or(|dark| at < dark) || (only_first && txid != first) {
                        continue;
                    }
                    let (_, answer) =
                        crate::wireguard::test_peer::build_dns_answer(query, &names).unwrap();
                    let _ = socket.send_to(&answer, from).await;
                }
            });
            Self { queries, task }
        }

        fn queries(&self) -> Vec<(Duration, u16)> {
            self.queries.lock().unwrap().clone()
        }
    }

    impl Drop for DarkResolver {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Two stacks back to back, the near one resolving through a resolver
    /// on the far one, both running their protocol timers on the paused
    /// tokio clock.
    fn resolving_pair() -> Pair {
        let pair = pair_of(
            StackConfig {
                dns_servers: vec![FAR.ip()],
                ..config("10.9.0.1/24")
            },
            config("10.9.0.2/24"),
        );
        for stack in [&pair.near, &pair.far] {
            stack.shared.with_stack(|inner| {
                inner.tokio_started = Some(tokio::time::Instant::now() - inner.started.elapsed());
            });
        }
        pair
    }

    /// A lookup that has ended left none of its queries behind: smoltcp has
    /// no resend due on a stack that holds only its resolver, and every
    /// lookup slot is free.
    fn no_query_is_left_behind(stack: &WgStack) {
        let resend_due = stack.shared.with_stack(|inner| {
            let now = inner.now();
            inner.iface.poll_delay(now, &inner.sockets)
        });
        assert_eq!(resend_due, None);
        assert_eq!(stack.shared.dns_slots.available_permits(), DNS_QUERY_SLOTS);
    }

    /// A lookup through a path that drops everything for `dark`: how long
    /// it took on the tokio clock, and what the resolver saw.
    async fn resolve_through_a_dark_spell(
        dark: Option<Duration>,
        only_first: bool,
        budget: Duration,
    ) -> (
        Result<Vec<std::net::IpAddr>, TunnelError>,
        Duration,
        Vec<(Duration, u16)>,
    ) {
        let pair = resolving_pair();
        let resolver = DarkResolver::start(&pair.far, dark, only_first);
        let started = tokio::time::Instant::now();
        let resolved = pair.near.resolve("dark.test", budget).await;
        let took = tokio::time::Instant::now() - started;
        no_query_is_left_behind(&pair.near);
        (resolved, took, resolver.queries())
    }

    async fn answered_within_a_second_of(dark: Duration) -> Vec<(Duration, u16)> {
        let (resolved, took, queries) =
            resolve_through_a_dark_spell(Some(dark), false, Duration::from_secs(30)).await;
        assert_eq!(resolved.unwrap(), vec![std::net::IpAddr::V4(RESOLVED)]);
        assert!(
            took >= dark && took <= dark + Duration::from_secs(1),
            "answered {took:?} into a lookup dark for {dark:?}: {queries:?}"
        );
        queries
    }

    /// A path dark for half a second: the resend or the fresh query at 1 s
    /// is answered.
    #[tokio::test(start_paused = true)]
    async fn a_lookup_dark_for_half_a_second_is_answered_at_one_second() {
        answered_within_a_second_of(Duration::from_millis(500)).await;
    }

    /// A path dark for 2.5 s: a query goes out every second, so one is
    /// answered by 3.5 s, not on smoltcp's resend at 7 s.
    #[tokio::test(start_paused = true)]
    async fn a_lookup_dark_for_two_and_a_half_seconds_is_answered_within_a_second() {
        answered_within_a_second_of(Duration::from_millis(2500)).await;
    }

    /// A path dark for 4.2 s, as a cold server is: the queries already in
    /// flight keep one datagram a second on the wire, so one is answered
    /// by 5.2 s, and the lookup never held more than its four queries.
    #[tokio::test(start_paused = true)]
    async fn a_lookup_dark_for_four_seconds_is_answered_within_a_second() {
        let queries = answered_within_a_second_of(Duration::from_millis(4200)).await;
        let mut transactions: Vec<u16> = queries.iter().map(|(_, txid)| *txid).collect();
        transactions.sort_unstable();
        transactions.dedup();
        assert!(transactions.len() <= DNS_LIVE_QUERIES, "{queries:?}");
    }

    /// An answer to the first query, arriving after later ones went out, is
    /// taken: the earlier queries stay able to answer.
    #[tokio::test(start_paused = true)]
    async fn a_late_answer_to_an_older_query_is_taken() {
        let dark = Duration::from_millis(2500);
        let (resolved, took, queries) =
            resolve_through_a_dark_spell(Some(dark), true, Duration::from_secs(30)).await;
        assert_eq!(resolved.unwrap(), vec![std::net::IpAddr::V4(RESOLVED)]);
        let first = queries[0].1;
        assert!(
            queries.iter().any(|(_, txid)| *txid != first),
            "later queries went out: {queries:?}"
        );
        // The first query's own resend at 3 s is the one answered.
        assert_eq!(took, Duration::from_secs(3), "{queries:?}");
    }

    /// A lookup nobody answers ends at its budget, with the error a single
    /// query gave.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_lookup_ends_at_its_budget_as_before() {
        let budget = Duration::from_secs(6);
        let (resolved, took, _) = resolve_through_a_dark_spell(None, false, budget).await;
        let error = resolved.unwrap_err();
        assert!(
            error.to_string().contains("did not answer in time"),
            "{error}"
        );
        assert_eq!(took, budget);
    }

    /// A lookup nobody answers with a budget past smoltcp's ten seconds a
    /// server ends when its first query is given up, as a single query
    /// was: that query last went out at 7 s and smoltcp looks at it again
    /// only when its next resend is due, 8 s later, and finds its server's
    /// time up. Before then it sent 16 queries where one sent 4.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_lookup_past_smoltcps_server_timeout_fails_as_before() {
        let (resolved, took, queries) =
            resolve_through_a_dark_spell(None, false, Duration::from_secs(60)).await;
        let error = resolved.unwrap_err();
        assert!(
            error.to_string().contains("does not know this name"),
            "{error}"
        );
        assert_eq!(took, Duration::from_secs(15), "{queries:?}");
        assert_eq!(queries.len(), 16, "{queries:?}");
    }

    #[test]
    fn only_a_narrow_window_needs_a_wake() {
        use crate::wireguard::tcp::window_was_narrow;
        assert!(!window_was_narrow(1024, 0));
        assert!(!window_was_narrow(1024, 512));
        assert!(window_was_narrow(1024, 513));
        assert!(window_was_narrow(1024, 1024));
    }
}
