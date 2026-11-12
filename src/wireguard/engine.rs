//! The tunnel's engine: one task that moves every packet of one tunnel.
//!
//! A pass of the engine reads every datagram the UDP socket holds (up to a
//! bound), decrypts each one, hands the lot to the smoltcp stack, polls the
//! stack once, encrypts whatever the stack composed, and writes it all to the
//! socket in batches. Decryption, the stack and encryption happen on the
//! engine's own task, on the packets' own buffers, with no channel or task
//! between them, so a burst of packets costs one wake-up rather than several
//! per packet.
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

        self.initiate(&mut wire);
        loop {
            if self.status.restart.swap(false, Ordering::AcqRel) {
                self.tunn = fresh_tunn(&self.config, &self.index_table, &self.rate_limiter);
                self.initiate(&mut wire);
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
            for packet in outbound.drain(..) {
                self.encrypt(packet, &mut wire);
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
            Ok(Some(packet)) => wire.push((packet.into(), self.config.endpoint)),
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
        match self.tunn.handle_incoming_packet(message) {
            TunnResult::Done | TunnResult::Err(_) => {}
            TunnResult::WriteToNetwork(answer) => {
                if handshake {
                    self.status.handshook();
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

/// Poll `future` once, without waiting: its output if it is ready now.
fn poll_now<F: Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}
