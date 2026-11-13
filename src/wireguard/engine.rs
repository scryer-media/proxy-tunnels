//! The tunnel's engine: one task that moves every packet of one tunnel.
//!
//! A pass of the engine reads every datagram the UDP socket holds (up to a
//! bound), decrypts each one, hands the lot to the smoltcp stack, polls the
//! stack once, encrypts whatever the stack composed, and writes it to the
//! socket in batches, each as soon as it is encrypted. Decryption, the stack
//! and encryption happen on the engine's own task, on the packets' own
//! buffers, with no channel or task between them, so a burst of packets
//! costs one wake-up rather than several per packet.
//!
//! ```text
//!   UDP ──▶ verify ─▶ decrypt ─▶ smoltcp poll ─▶ encrypt ──▶ UDP
//!                 (one task, one pass per burst)
//! ```
//!
//! The WireGuard protocol itself, handshakes, sessions, rekeying, replay
//! protection, cookies and keepalives, is gotatun's [`Tunn`]; the engine only
//! feeds it. A tunnel has exactly one peer, at a fixed endpoint, so there is
//! no peer table to look packets up in: every datagram goes to the one
//! [`Tunn`], which rejects what is not addressed to its sessions.
//!
//! The protocol's timers run every [`TIMER_TICK`], as gotatun's own device
//! runs them, and are checked on every pass as well as when the engine is
//! idle, so a tunnel that never stops receiving still sends its keepalives
//! and rekeys on time.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use gotatun::noise::errors::WireGuardError;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Ip, Packet, PacketBufPool, WgKind};
use gotatun::tun::MtuWatcher;
use gotatun::udp::{UdpRecv, UdpSend};
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;
use tokio::sync::Notify;

use crate::wireguard::phy::PACKET_QUEUE_DEPTH;
use crate::wireguard::stack::StackShared;
use crate::wireguard::transport::{RecvBatch, TunnelSocket};

/// How often the WireGuard timers run: gotatun's own device period.
pub(crate) const TIMER_TICK: Duration = Duration::from_millis(250);

/// How many handshakes one source address may start each second before it is
/// asked to prove its address with a cookie: gotatun's own device limit.
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// Receive buffers kept for reuse: one pass's worth of datagrams and one
/// socket read beyond it.
const RECEIVE_BUFFERS: usize = PACKET_QUEUE_DEPTH + 64;

/// How long a pass may wait, on a busy link, for more datagrams to join the
/// few it read.
///
/// A real link hands datagrams over spaced out, one or two per read, and
/// every pass costs a wake of the engine, a stack poll, an ACK and a wake of
/// each reader it fed, whatever it carries. Holding a short read this long
/// gathers the link's next datagrams into the same pass. Measured on a paced
/// 25 MB/s link with a 40 ms round trip, one tunnel's download then costs
/// well under half the CPU per gigabyte, at the same speed.
///
/// The cost is that delay on the datagrams held: the first of a pass waits
/// the whole hold, the last none. It is paid only where it is small next to
/// the round trip ([`HOLD_ROUND_TRIP_SHARE`]), and it adds up over nested
/// tunnels, each of which holds. A hold of 1 ms (which tokio's millisecond
/// timer made nearly 2 ms) slowed three nested tunnels by a quarter at
/// 100 MB/s; 500 µs cost three nested tunnels resends at 25 MB/s; this one
/// cost neither.
const RECEIVE_HOLD: Duration = Duration::from_micros(350);

/// A pass holds a read only when [`RECEIVE_HOLD`] is at most this share of
/// the tunnel's round trip (1/20, 5%), as the last handshake measured it. A
/// connection whose window, not the link, limits it slows by about that
/// share at worst; one the link limits does not slow at all. Over a short
/// round trip (loopback, a LAN) the engine never holds.
const HOLD_ROUND_TRIP_SHARE: u32 = 20;

/// A read of at least this many datagrams is already a burst, and is never
/// held.
const HOLD_BELOW: usize = 8;

/// A pass holds a read only when the link has lately brought at least this
/// many datagrams per [`RECEIVE_HOLD`]. A hold that gathers fewer costs more
/// than the passes it saves: measured on a paced 10 MB/s upload, whose ACKs
/// come about one per hold, holding cost a quarter more CPU per gigabyte.
const HOLD_GATHERS: u128 = 2;

/// How long the link's arrival rate is counted over before it is judged
/// again.
const RATE_WINDOW: Duration = Duration::from_millis(4);

/// What one tunnel's engine is built from.
pub(crate) struct EngineConfig {
    pub(crate) private_key: StaticSecret,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) preshared_key: Option<[u8; 32]>,
    pub(crate) persistent_keepalive: Option<u16>,
    /// Where every packet goes. The socket is connected to it when it can
    /// be, and the engine never follows a peer to another address.
    pub(crate) endpoint: SocketAddr,
    /// The peer's allowed IPs. A packet goes to the peer only when its
    /// destination is among them, and a decrypted packet is accepted only
    /// when its source is.
    pub(crate) allowed: Vec<IpNetwork>,
    /// The tunnel's MTU, which every packet is padded within.
    pub(crate) mtu: u16,
    /// Makes the packet whose sending starts a handshake.
    pub(crate) probe: Box<dyn Fn() -> Packet<Ip> + Send + Sync>,
    /// Whether the engine runs on a thread of its own, which it may then
    /// block for a [`RECEIVE_HOLD`]. An engine on the caller's runtime never
    /// holds.
    pub(crate) own_thread: bool,
}

/// What the rest of the tunnel can see of, and ask of, a running engine.
#[derive(Default)]
pub(crate) struct EngineStatus {
    /// When a handshake last established a session.
    last_handshake: Mutex<Option<std::time::Instant>>,
    /// Set to have the engine drop its handshake state and initiate afresh.
    restart: AtomicBool,
}

impl EngineStatus {
    /// How long ago a handshake last established a session, if one ever has.
    pub(crate) fn last_handshake_age(&self) -> Option<Duration> {
        self.last_handshake
            .lock()
            .expect("tunnel handshake time")
            .map(|at| at.elapsed())
    }

    /// Ask the engine to start over with fresh handshake state and initiate
    /// a new handshake, as if it had just been built. `stack` is the engine's
    /// stack, rung so the engine acts on the next pass.
    pub(crate) fn restart(&self, stack: &StackShared) {
        self.restart.store(true, Ordering::Release);
        stack.wake();
    }

    fn handshook(&self) {
        *self.last_handshake.lock().expect("tunnel handshake time") =
            Some(std::time::Instant::now());
    }
}

/// One tunnel's engine. Built by [`Engine::new`], run by [`Engine::run`].
pub(crate) struct Engine {
    tunn: Tunn,
    rate_limiter: Arc<RateLimiter>,
    index_table: IndexTable,
    config: EngineConfig,
    send: TunnelSocket,
    recv: TunnelSocket,
    mtu: MtuWatcher,
    status: Arc<EngineStatus>,
    /// Scratch the socket reuses across batched sends.
    send_buf: <TunnelSocket as UdpSend>::SendManyBuf,
    /// When the last handshake initiation went out, until its response.
    initiated: Option<std::time::Instant>,
    /// The round trip the last answered initiation measured.
    round_trip: Option<Duration>,
    /// Whether the current [`Tunn`] took in a cookie reply: the peer is
    /// under load and answers only an initiation that carries the cookie.
    cookie: bool,
}

impl Engine {
    /// An engine for the tunnel `config` describes, on the socket halves
    /// `send` and `recv`.
    pub(crate) fn new(
        config: EngineConfig,
        send: TunnelSocket,
        recv: TunnelSocket,
        status: Arc<EngineStatus>,
    ) -> Self {
        let public_key = PublicKey::from(&config.private_key);
        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));
        let index_table = IndexTable::from_os_rng();
        let tunn = fresh_tunn(&config, &index_table, &rate_limiter);
        Self {
            tunn,
            rate_limiter,
            index_table,
            mtu: MtuWatcher::new(config.mtu),
            config,
            send,
            recv,
            status,
            send_buf: Default::default(),
            initiated: None,
            round_trip: None,
            cookie: false,
        }
    }

    /// Initiate afresh, as [`EngineStatus::restart`] asks.
    ///
    /// Without a cookie in hand the handshake state is dropped and a new
    /// [`Tunn`] initiates, as if the engine had just been built. A peer that
    /// answered with a cookie is under load and answers only an initiation
    /// that carries it, and the cookie lives in the [`Tunn`]: dropping that
    /// would earn another cookie, and the answer would wait for gotatun's own
    /// retry. So with a cookie the current [`Tunn`] sends a new initiation
    /// instead, with a new ephemeral key, a later timestamp and the cookie.
    fn restart(&mut self, wire: &mut Vec<(Packet, SocketAddr)>) {
        if self.cookie
            && let Some(initiation) = self.tunn.format_handshake_initiation(true)
        {
            let initiation = WgKind::HandshakeInit(initiation);
            self.note_sent(&initiation);
            wire.push((initiation.into(), self.config.endpoint));
            return;
        }
        self.tunn = fresh_tunn(&self.config, &self.index_table, &self.rate_limiter);
        self.cookie = false;
        self.initiate(wire);
    }

    /// Note an outgoing handshake initiation, whose response measures the
    /// round trip.
    fn note_sent(&mut self, packet: &WgKind) {
        if matches!(packet, WgKind::HandshakeInit(_)) {
            self.initiated = Some(std::time::Instant::now());
        }
    }

    /// Run until `shutdown` is notified, the socket fails or the task is
    /// aborted. The stack is marked stopped however this ends.
    pub(crate) async fn run(mut self, shared: Arc<StackShared>, shutdown: Arc<Notify>) {
        let _stop = shared.stop_on_exit();
        let mut pool = PacketBufPool::new(RECEIVE_BUFFERS);
        let mut recv_batch = RecvBatch::default();
        let mut datagrams: Vec<(Packet, SocketAddr)> = Vec::with_capacity(RECEIVE_BUFFERS);
        let mut inbound: Vec<Packet<Ip>> = Vec::with_capacity(PACKET_QUEUE_DEPTH);
        let mut outbound: Vec<Packet<Ip>> = Vec::with_capacity(PACKET_QUEUE_DEPTH);
        let mut wire: Vec<(Packet, SocketAddr)> = Vec::with_capacity(PACKET_QUEUE_DEPTH);
        let mut chunk: Vec<(Packet, SocketAddr)> = Vec::new();
        let timer = tokio::time::sleep(Duration::ZERO);
        tokio::pin!(timer);
        let mut next_tick = tokio::time::Instant::now() + TIMER_TICK;
        let mut arrivals = ArrivalRate::new(tokio::time::Instant::now());

        self.initiate(&mut wire);
        loop {
            if self.status.restart.swap(false, Ordering::AcqRel) {
                self.restart(&mut wire);
            }
            let now = tokio::time::Instant::now();
            if now >= next_tick {
                next_tick = now + TIMER_TICK;
                self.run_timers(&mut wire);
            }

            let delay = shared.peek_stack(|stack| stack.pass(&mut inbound, &mut outbound));
            // A full queue means the stack had more to send than one pass
            // takes: go round again at once rather than wait.
            let more = outbound.len() >= PACKET_QUEUE_DEPTH;
            // Each batch leaves as soon as it is encrypted, so the far end, or
            // the carrier's engine on its own thread, starts on the first
            // packets while the rest are still being encrypted. How large a
            // batch is: `TunnelSocket::stream_batch`.
            let mut sent = 0;
            for packet in outbound.drain(..) {
                self.encrypt(packet, &mut wire);
                if wire.len() >= self.send.stream_batch(sent) {
                    sent += wire.len();
                    self.flush(&mut wire, &mut chunk).await;
                }
            }
            self.flush(&mut wire, &mut chunk).await;

            let woken = shared.notified();
            let stopped = shutdown.notified();
            tokio::pin!(woken, stopped);
            let immediate = more || delay.is_some_and(|delay| delay.is_zero());
            let wake_at = match delay {
                Some(delay) => next_tick.min(now + delay),
                None => next_tick,
            };
            timer.as_mut().reset(wake_at);

            let received = tokio::select! {
                biased;
                () = &mut stopped => break,
                received = self.recv.recv_many_from(&mut recv_batch, &mut pool, &mut datagrams) => {
                    if let Err(error) = received {
                        tracing::debug!(%error, "the tunnel's UDP socket failed");
                        break;
                    }
                    true
                }
                () = &mut woken => false,
                () = &mut timer => false,
                () = tokio::task::yield_now(), if immediate => false,
            };
            // A short read on a busy link waits a hold for the rest of the
            // link's datagrams to queue behind it: see `RECEIVE_HOLD`. The
            // hold blocks the thread, because tokio's timer counts whole
            // milliseconds; the thread runs only this tunnel, and a shutdown
            // waits at most one hold.
            if received
                && self.config.own_thread
                && holds(datagrams.len(), self.round_trip)
                && arrivals.busy(tokio::time::Instant::now())
            {
                std::thread::sleep(RECEIVE_HOLD);
            }
            // Decrypt what was read, then read again: whatever arrived while
            // those were decrypted joins the same pass, up to what one pass
            // hands the stack. Each pass costs a stack poll, an ACK and a
            // wake of every reader it fed, so the fuller the pass the less
            // each datagram costs.
            let mut taken = 0;
            loop {
                taken += datagrams.len();
                for (datagram, source) in datagrams.drain(..) {
                    self.receive(datagram, source, &mut inbound, &mut wire);
                }
                if !received || taken >= PACKET_QUEUE_DEPTH {
                    break;
                }
                let read = match self
                    .recv
                    .recv_queued(&mut recv_batch, &mut pool, &mut datagrams)
                {
                    Some(read) => Some(read),
                    None => poll_now(self.recv.recv_many_from(
                        &mut recv_batch,
                        &mut pool,
                        &mut datagrams,
                    )),
                };
                if !matches!(read, Some(Ok(()))) || datagrams.is_empty() {
                    break;
                }
            }
            arrivals.note(taken, tokio::time::Instant::now());
        }

        let (dropped, overrun) = shared.peek_stack(|stack| stack.drop_counts());
        tracing::debug!(
            proxy_config_id = shared.config().proxy_config_id.as_str(),
            dropped,
            overrun,
            "tunnel engine stopped"
        );
    }

    /// Send the probe, which the [`Tunn`] queues while it initiates a
    /// handshake.
    fn initiate(&mut self, wire: &mut Vec<(Packet, SocketAddr)>) {
        let probe = (self.config.probe)();
        self.encrypt(probe, wire);
    }

    /// Run the protocol timers once: keepalives, rekeys, handshake retries
    /// and the expiry of old sessions.
    fn run_timers(&mut self, wire: &mut Vec<(Packet, SocketAddr)>) {
        match self.tunn.update_timers() {
            Ok(Some(packet)) => {
                self.note_sent(&packet);
                wire.push((packet.into(), self.config.endpoint));
            }
            Ok(None) | Err(WireGuardError::ConnectionExpired) => {}
            Err(error) => tracing::debug!(?error, "the tunnel's timers failed"),
        }
    }

    /// Encrypt one packet the stack composed onto `wire`, or start a
    /// handshake and hold it until there is a session.
    fn encrypt(&mut self, packet: Packet<Ip>, wire: &mut Vec<(Packet, SocketAddr)>) {
        if !packet
            .destination()
            .is_some_and(|destination| self.allowed(destination))
        {
            return;
        }
        if let Some(packet) = self
            .tunn
            .handle_outgoing_packet(packet.into(), Some(&mut self.mtu))
        {
            self.note_sent(&packet);
            wire.push((packet.into(), self.config.endpoint));
        }
    }

    /// Take in one datagram: decrypted IP packets go to `inbound`, anything
    /// the protocol answers with goes to `wire`.
    fn receive(
        &mut self,
        datagram: Packet,
        source: SocketAddr,
        inbound: &mut Vec<Packet<Ip>>,
        wire: &mut Vec<(Packet, SocketAddr)>,
    ) {
        let message = match self.rate_limiter.verify_packet(source, datagram) {
            Ok(message) => message,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                wire.push((cookie.into(), source));
                return;
            }
            Err(_) => return,
        };
        let handshake = matches!(message, WgKind::HandshakeInit(_) | WgKind::HandshakeResp(_));
        let response = matches!(message, WgKind::HandshakeResp(_));
        let cookie = matches!(message, WgKind::CookieReply(_));
        match self.tunn.handle_incoming_packet(message) {
            // gotatun answers an accepted cookie reply with `Done`, and one
            // it could not open with `Err`.
            TunnResult::Done if cookie => self.cookie = true,
            TunnResult::Done | TunnResult::Err(_) => {}
            TunnResult::WriteToNetwork(answer) => {
                if handshake {
                    self.status.handshook();
                }
                if response && let Some(initiated) = self.initiated.take() {
                    self.round_trip = Some(initiated.elapsed());
                }
                wire.push((answer.into(), source));
                for queued in self.tunn.get_queued_packets(&mut self.mtu) {
                    wire.push((queued.into(), source));
                }
            }
            TunnResult::WriteToTunnel(packet) => {
                // An empty packet is a keepalive.
                if packet.is_empty() {
                    return;
                }
                let Ok(packet) = packet.try_into_ip() else {
                    return;
                };
                if packet.source().is_some_and(|source| self.allowed(source)) {
                    inbound.push(packet);
                }
            }
        }
    }

    fn allowed(&self, address: IpAddr) -> bool {
        self.config
            .allowed
            .iter()
            .any(|network| network.contains(address))
    }

    /// Write everything on `wire` to the socket, in order, as few calls as the
    /// socket allows. A datagram the socket refuses is lost, as it would be
    /// on any link.
    async fn flush(
        &mut self,
        wire: &mut Vec<(Packet, SocketAddr)>,
        chunk: &mut Vec<(Packet, SocketAddr)>,
    ) {
        let most = self.send.max_number_of_packets_to_send().max(1);
        let mut pending = wire.drain(..).peekable();
        while pending.peek().is_some() {
            chunk.clear();
            chunk.extend(pending.by_ref().take(most));
            if let Err(error) = self.send.send_many_to(&mut self.send_buf, chunk).await {
                tracing::trace!(%error, "the tunnel's UDP socket refused a send");
            }
        }
        chunk.clear();
    }
}

fn fresh_tunn(
    config: &EngineConfig,
    index_table: &IndexTable,
    rate_limiter: &Arc<RateLimiter>,
) -> Tunn {
    Tunn::new(
        config.private_key.clone(),
        config.peer_public_key,
        config.preshared_key,
        config.persistent_keepalive,
        index_table.clone(),
        Arc::clone(rate_limiter),
    )
}

/// Whether a pass that read `read` datagrams may wait [`RECEIVE_HOLD`] for
/// more, over a tunnel whose last handshake took `round_trip`. Whether the
/// link is busy enough is [`ArrivalRate::busy`].
fn holds(read: usize, round_trip: Option<Duration>) -> bool {
    read < HOLD_BELOW
        && round_trip.is_some_and(|round_trip| round_trip >= RECEIVE_HOLD * HOLD_ROUND_TRIP_SHARE)
}

/// How fast datagrams have lately arrived, judged once per [`RATE_WINDOW`],
/// and when they last did.
struct ArrivalRate {
    /// When the window being counted began.
    since: tokio::time::Instant,
    /// Datagrams taken in since then.
    count: u128,
    /// The last judgement.
    busy: bool,
    /// When the last pass that took datagrams in finished.
    last: Option<tokio::time::Instant>,
}

impl ArrivalRate {
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            since: now,
            count: 0,
            busy: false,
            last: None,
        }
    }

    /// Count in the `taken` datagrams of a pass that finished at `now`.
    fn note(&mut self, taken: usize, now: tokio::time::Instant) {
        if taken > 0 {
            self.count += taken as u128;
            self.last = Some(now);
        }
    }

    /// Whether the link brought at least [`HOLD_GATHERS`] datagrams per
    /// [`RECEIVE_HOLD`] over the last full window, and the pass before this
    /// read took datagrams in less than a hold ago. A read after any pause,
    /// such as the answer to a request or the start of a connection's next
    /// window, is taken at once.
    fn busy(&mut self, now: tokio::time::Instant) -> bool {
        let elapsed = now.duration_since(self.since);
        if elapsed >= RATE_WINDOW {
            self.busy = self.count * RECEIVE_HOLD.as_nanos() >= HOLD_GATHERS * elapsed.as_nanos();
            self.since = now;
            self.count = 0;
        }
        self.busy
            && self
                .last
                .is_some_and(|last| now.duration_since(last) <= RECEIVE_HOLD)
    }
}

/// Poll `future` once, without waiting: its output if it is ready now.
fn poll_now<F: Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAR: Duration = Duration::from_millis(40);

    /// A rate that has just judged a window in which `per_hold` datagrams
    /// came per hold, at `now`.
    fn judged(per_hold: u128, now: tokio::time::Instant) -> ArrivalRate {
        let mut rate = ArrivalRate::new(now - RATE_WINDOW);
        let came = (per_hold * RATE_WINDOW.as_nanos()).div_ceil(RECEIVE_HOLD.as_nanos());
        rate.note(came as usize, now);
        rate.busy(now);
        rate
    }

    #[test]
    fn a_short_read_on_a_far_link_may_be_held() {
        assert!(holds(1, Some(FAR)));
        assert!(holds(HOLD_BELOW - 1, Some(FAR)));
    }

    #[test]
    fn a_burst_is_never_held() {
        assert!(!holds(HOLD_BELOW, Some(FAR)));
    }

    #[test]
    fn a_tunnel_with_a_short_or_unknown_round_trip_never_holds() {
        let near = RECEIVE_HOLD * HOLD_ROUND_TRIP_SHARE - Duration::from_micros(1);
        assert!(!holds(1, Some(near)));
        assert!(!holds(1, None));
        assert!(holds(1, Some(RECEIVE_HOLD * HOLD_ROUND_TRIP_SHARE)));
    }

    #[test]
    fn a_link_that_fills_a_hold_is_busy() {
        let now = tokio::time::Instant::now();
        assert!(judged(HOLD_GATHERS, now).busy(now));
        assert!(judged(HOLD_GATHERS * 10, now).busy(now));
    }

    #[test]
    fn a_link_that_brings_less_than_a_hold_gathers_is_not_busy() {
        let now = tokio::time::Instant::now();
        assert!(!judged(HOLD_GATHERS - 1, now).busy(now));
        assert!(!ArrivalRate::new(now).busy(now), "nothing counted yet");
    }

    #[test]
    fn the_judgement_holds_until_the_window_closes() {
        let now = tokio::time::Instant::now();
        let mut rate = judged(HOLD_GATHERS, now);
        let soon = now + RECEIVE_HOLD / 2;
        rate.note(1, soon);
        assert!(rate.busy(soon + RECEIVE_HOLD / 2), "within the window");
        // A quiet window: the next read is taken at once.
        assert!(!rate.busy(now + RATE_WINDOW * 3));
    }

    #[test]
    fn a_read_after_a_pause_is_taken_at_once() {
        let now = tokio::time::Instant::now();
        let mut rate = judged(HOLD_GATHERS * 10, now);
        assert!(
            rate.busy(now + RECEIVE_HOLD),
            "straight after the last pass"
        );
        assert!(
            !rate.busy(now + RECEIVE_HOLD * 2),
            "a pause of more than a hold"
        );
    }
}
