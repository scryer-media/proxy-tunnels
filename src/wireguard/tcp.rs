//! Tokio-shaped TCP over the tunnel's smoltcp stack.
//!
//! [`WgTcpStream`] is an ordinary [`AsyncRead`] + [`AsyncWrite`], which is all
//! [`crate::TunnelStream`] asks for, so a WireGuard dial drops into the SOCKS5
//! front and every consumer above it without any of them learning a new type.
//!
//! Every operation follows the same three steps: take the stack lock, try the
//! smoltcp call, and on would-block register *this task's* waker on the socket
//! before returning `Pending`. smoltcp wakes those wakers from the stack pump,
//! so a blocked reader costs nothing until its bytes arrive.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::TunnelError;
use crate::wireguard::stack::{MAX_LISTEN_BACKLOG, StackInner, StackShared};

/// A TCP connection to something on the far side of the tunnel.
pub struct WgTcpStream {
    shared: Arc<StackShared>,
    handle: SocketHandle,
    peer: SocketAddr,
    /// Set once `poll_shutdown` (or a fatal error) has closed our half, so a
    /// second shutdown is a no-op rather than a state-machine violation.
    shut_down: bool,
    /// Set once a read saw the far side's FIN. Only then is the end of the
    /// connection an end of stream; any other end is an error.
    fin_seen: bool,
}

impl WgTcpStream {
    /// The bytes waiting in the receive buffer, and the buffer's capacity.
    #[cfg(test)]
    pub(crate) fn receive_buffer(&self) -> (usize, usize) {
        self.shared.peek_stack(|stack| {
            let socket = stack.sockets_mut().get_mut::<tcp::Socket>(self.handle);
            (socket.recv_queue(), socket.recv_capacity())
        })
    }

    /// The socket's TCP state and the bytes not yet acknowledged by the peer.
    #[cfg(test)]
    pub(crate) fn socket_state(&self) -> (tcp::State, usize) {
        self.shared.peek_stack(|stack| {
            let socket = stack.sockets_mut().get_mut::<tcp::Socket>(self.handle);
            (socket.state(), socket.send_queue())
        })
    }

    /// Reset the connection: the peer is sent an RST, not a FIN.
    #[cfg(test)]
    pub(crate) fn abort(&mut self) {
        self.shared.with_stack(|stack| {
            stack
                .sockets_mut()
                .get_mut::<tcp::Socket>(self.handle)
                .abort();
        });
    }

    /// Dial `remote` and wait for the connection to establish.
    ///
    /// The caller has already claimed a socket slot; on any failure the socket
    /// is removed immediately rather than retired, because a connection that
    /// never opened has nothing to flush.
    pub(crate) async fn connect(
        shared: Arc<StackShared>,
        remote: SocketAddr,
        timeout: Duration,
    ) -> Result<WgTcpStream, TunnelError> {
        let endpoint = IpEndpoint::from(remote);
        let (handle, started) = shared.with_stack(|stack| {
            let handle = stack.add_tcp_socket();
            let local_port = stack.next_ephemeral_port();
            let (sockets, context) = stack.socket_and_context();
            let started = sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(context, endpoint, local_port);
            (handle, started)
        });

        if let Err(error) = started {
            shared.with_stack(|stack| stack.discard(handle));
            return Err(TunnelError::Dial {
                host: remote.ip().to_string(),
                port: remote.port(),
                detail: match error {
                    tcp::ConnectError::Unaddressable => {
                        "the tunnel has no address in that destination's family, so it cannot \
                         reach it"
                            .to_string()
                    }
                    tcp::ConnectError::InvalidState => {
                        "the tunnel could not open a socket for that destination".to_string()
                    }
                },
            });
        }

        // Own the allocated handle before the first await. Outer timeouts or
        // task cancellation must remove it as well as release the caller's slot.
        let mut pending = PendingConnect {
            shared: Arc::clone(&shared),
            handle: Some(handle),
        };
        let established = tokio::time::timeout(
            timeout,
            std::future::poll_fn(|context| {
                shared.peek_stack(|stack| {
                    let socket = stack.sockets_mut().get_mut::<tcp::Socket>(handle);
                    match socket.state() {
                        // Still shaking hands.
                        tcp::State::SynSent | tcp::State::SynReceived => {
                            socket.register_send_waker(context.waker());
                            Poll::Pending
                        }
                        // Refused, or reset before it ever opened.
                        tcp::State::Closed | tcp::State::TimeWait => Poll::Ready(false),
                        _ => Poll::Ready(true),
                    }
                })
            }),
        )
        .await;
        pending.handle = None;

        match established {
            Ok(true) => Ok(WgTcpStream {
                shared,
                handle,
                peer: remote,
                shut_down: false,
                fin_seen: false,
            }),
            Ok(false) => {
                shared.with_stack(|stack| stack.discard(handle));
                Err(TunnelError::Dial {
                    host: remote.ip().to_string(),
                    port: remote.port(),
                    detail: "the far side refused the connection".to_string(),
                })
            }
            Err(_) => {
                shared.with_stack(|stack| {
                    stack.sockets_mut().get_mut::<tcp::Socket>(handle).abort();
                    stack.discard(handle);
                });
                Err(TunnelError::Dial {
                    host: remote.ip().to_string(),
                    port: remote.port(),
                    detail: "the tunnel did not open a connection in time".to_string(),
                })
            }
        }
    }

    /// Adopt a socket that a listener has already seen become established,
    /// and whose socket slot the listener has already claimed.
    pub(crate) fn from_accepted(
        shared: Arc<StackShared>,
        handle: SocketHandle,
        peer: SocketAddr,
    ) -> Self {
        Self {
            shared,
            handle,
            peer,
            shut_down: false,
            fin_seen: false,
        }
    }

    /// The far-side address this stream is connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn close_half(&mut self) {
        if self.shut_down {
            return;
        }
        self.shut_down = true;
        let handle = self.handle;
        self.shared.with_stack(|stack| {
            stack.sockets_mut().get_mut::<tcp::Socket>(handle).close();
        });
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        // Close rather than abort: a consumer that drops a stream after a
        // complete HTTP response should still send its FIN, or the far side
        // logs a reset for every request. The pump reclaims the socket once
        // the close finishes, or gives up on it after the linger window.
        self.close_half();
        // Every stream holds one of the stack's socket slots, dialled or
        // accepted; reclaiming the socket frees it.
        let handle = self.handle;
        self.shared.with_stack(|stack| stack.retire(handle, true));
    }
}

struct PendingConnect {
    shared: Arc<StackShared>,
    handle: Option<SocketHandle>,
}

impl Drop for PendingConnect {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.shared.with_stack(|stack| stack.discard(handle));
        }
    }
}

/// Whether a read must ask the stack to tell the peer the receive window
/// opened, given the buffer's capacity and the bytes queued before the read.
///
/// The read wakes the pump only while less than half the buffer was free.
/// Every byte that arrives is acknowledged by a poll anyway, and smoltcp
/// sends a window update on its own only once the window doubled, so a
/// wake after a read from a mostly empty buffer moves no segment. While at
/// least half the buffer is free the window the peer holds is at least a
/// quarter of the buffer: the last waking read left at least half free, and
/// the poll it caused advertised that or kept a window no less than half of
/// it. So the sender is never held below a quarter of the buffer by a read
/// that did not wake.
pub(crate) fn window_was_narrow(capacity: usize, queued: usize) -> bool {
    capacity.saturating_sub(queued) < capacity / 2
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let handle = this.handle;
        let fin_seen = &mut this.fin_seen;
        let shared = &this.shared;
        let read = shared.peek_stack(|stack| {
            let socket = stack.sockets_mut().get_mut::<tcp::Socket>(handle);
            // Only these states follow a FIN from the far side. smoltcp
            // forgets the FIN when it leaves TIME-WAIT, so remember it here.
            if matches!(
                socket.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
            ) {
                *fin_seen = true;
            }
            let narrow = window_was_narrow(socket.recv_capacity(), socket.recv_queue());
            match socket.recv_slice(buffer.initialize_unfilled()) {
                Ok(0) => {
                    socket.register_recv_waker(context.waker());
                    Poll::Pending
                }
                Ok(read) => Poll::Ready(Ok((read, narrow))),
                // The far side sent its FIN and every byte before it has been
                // read: the stream is complete.
                Err(tcp::RecvError::Finished) => {
                    *fin_seen = true;
                    Poll::Ready(Ok((0, false)))
                }
                Err(tcp::RecvError::InvalidState) if *fin_seen => Poll::Ready(Ok((0, false))),
                // The connection ended without a FIN: reset by the far side,
                // timed out, or torn down with the tunnel. What arrived may be
                // cut short, so this is never an end of stream.
                Err(tcp::RecvError::InvalidState) => Poll::Ready(Err(if shared.is_stopped() {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the tunnel stopped before this connection finished",
                    )
                } else {
                    io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "the tunnel connection was reset before the far side finished sending",
                    )
                })),
            }
        });

        match read {
            Poll::Ready(Ok((read, narrow))) => {
                if read > 0 {
                    buffer.advance(read);
                    // Consuming bytes opened the receive window; the peer only
                    // learns that when the stack next polls. That matters only
                    // while the window is narrow: see `window_was_narrow`.
                    if narrow {
                        this.shared.wake();
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shut_down {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "this tunnel connection has been shut down",
            )));
        }
        let handle = this.handle;
        let written = this.shared.peek_stack(|stack| {
            let socket = stack.sockets_mut().get_mut::<tcp::Socket>(handle);
            if !socket.may_send() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the far side closed this tunnel connection",
                )));
            }
            match socket.send_slice(data) {
                Ok(0) => {
                    socket.register_send_waker(context.waker());
                    Poll::Pending
                }
                Ok(written) => Poll::Ready(Ok(written)),
                Err(tcp::SendError::InvalidState) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the far side closed this tunnel connection",
                ))),
            }
        });
        if matches!(written, Poll::Ready(Ok(_))) {
            // The bytes are in the send buffer; only a poll turns them into
            // segments on the wire.
            this.shared.wake();
        }
        written
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let handle = this.handle;
        this.shared.peek_stack(|stack| {
            let socket = stack.sockets_mut().get_mut::<tcp::Socket>(handle);
            if socket.send_queue() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !socket.may_send() && socket.state() == tcp::State::Closed {
                // Nothing will ever drain: the connection is gone.
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the tunnel connection closed before everything was sent",
                )));
            }
            socket.register_send_waker(context.waker());
            Poll::Pending
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A half-close: our FIN goes out, the far side may keep sending, and
        // reads keep working. That is what `AsyncWrite::shutdown` means, and
        // it is what a SOCKS5 relay needs when one direction finishes first.
        let this = self.get_mut();
        this.close_half();
        Poll::Ready(Ok(()))
    }
}

/// Accepts TCP connections arriving through the tunnel.
///
/// smoltcp has no listen backlog: a listening socket *becomes* the
/// connection. A backlog here is therefore a small pool of sockets all
/// listening on the same port. Every socket in the pool holds one of the
/// tunnel's socket slots, as a dialled connection does, so neither a large
/// backlog nor a flood of inbound peers can grow the tunnel's memory past its
/// cap. An accepted connection keeps the slot its socket held, and the
/// listener claims a new slot for the socket that takes its place. On a full
/// tunnel that replacement waits: the pool runs short and refills as slots
/// free, and a connection that arrives while no socket listens is refused.
///
/// The listener lives and dies with its stack: once the stack stops, every
/// pending and later [`WgTcpListener::accept`] fails.
pub struct WgTcpListener {
    shared: Arc<StackShared>,
    local: SocketAddr,
    /// The pool. Each socket in it holds one socket slot.
    listening: Vec<SocketHandle>,
    /// How many sockets the pool keeps listening while the tunnel has room.
    backlog: usize,
}

impl WgTcpListener {
    /// Listen on `port` on every tunnel address with `backlog` sockets, held
    /// between 1 and [`MAX_LISTEN_BACKLOG`]. `local` is the address the
    /// listener reports, which is the tunnel's first address and `port`.
    ///
    /// Every socket's slot is claimed before any socket exists, so a backlog
    /// the tunnel cannot hold fails whole and allocates nothing.
    pub(crate) fn bind(
        shared: Arc<StackShared>,
        local: SocketAddr,
        backlog: usize,
    ) -> Result<Self, TunnelError> {
        if shared.is_stopped() {
            return Err(stopped());
        }
        let backlog = backlog.clamp(1, MAX_LISTEN_BACKLOG);
        let mut slots = Vec::with_capacity(backlog);
        for _ in 0..backlog {
            slots.push(shared.claim_socket()?);
        }
        let port = local.port();
        let listening = shared.with_stack(|stack| {
            let mut listening = Vec::with_capacity(backlog);
            for _ in 0..backlog {
                match listen_on(stack, port) {
                    Ok(handle) => listening.push(handle),
                    Err(error) => {
                        for handle in listening {
                            stack.discard(handle);
                        }
                        return Err(error);
                    }
                }
            }
            Ok(listening)
        })?;
        for slot in slots {
            slot.keep();
        }
        Ok(Self {
            shared,
            local,
            listening,
            backlog,
        })
    }

    /// Bring the pool back to its backlog, as far as the tunnel has room.
    fn refill(&mut self) {
        let port = self.local.port();
        while self.listening.len() < self.backlog {
            let Ok(slot) = self.shared.claim_socket() else {
                return;
            };
            match self.shared.with_stack(|stack| listen_on(stack, port)) {
                Ok(handle) => {
                    slot.keep();
                    self.listening.push(handle);
                }
                Err(_) => return,
            }
        }
    }

    /// The tunnel address and port this listener accepts on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Wait for the next connection.
    ///
    /// Fails once the tunnel's stack has stopped: no packet will ever reach
    /// the listener again, so waiting would be waiting forever.
    pub async fn accept(&mut self) -> Result<WgTcpStream, TunnelError> {
        let port = self.local.port();
        loop {
            if self.shared.is_stopped() {
                return Err(stopped());
            }
            let notify = self.shared.slot_freed();
            let freed = notify.notified();
            tokio::pin!(freed);
            // Registered before the claim, so a slot freed in between still
            // wakes this accept.
            freed.as_mut().enable();
            self.refill();
            if !self.listening.is_empty() {
                break;
            }
            // Nothing listens until the tunnel has room for a socket again.
            tokio::select! {
                () = freed => {}
                () = self.shared.wait_stopped() => {}
            }
        }

        let ready = std::future::poll_fn(|context| {
            self.shared.peek_stack(|stack| {
                if self.shared.is_stopped() {
                    return Poll::Ready(Err(stopped()));
                }
                for (index, handle) in self.listening.iter().enumerate() {
                    let socket = stack.sockets_mut().get_mut::<tcp::Socket>(*handle);
                    // `is_active` would also report a half-open
                    // `SynReceived`, and handing that to a reader would
                    // look like an immediate end of stream. Wait for the
                    // handshake to finish.
                    if socket.may_send() || socket.may_recv() {
                        let peer = socket.remote_endpoint();
                        return Poll::Ready(Ok((index, peer)));
                    }
                    if socket.state() == tcp::State::Closed {
                        // A connection that was reset before it was taken
                        // leaves its socket closed; put it back to work.
                        let _ = socket.listen(port);
                    }
                    socket.register_recv_waker(context.waker());
                    socket.register_send_waker(context.waker());
                }
                Poll::Pending
            })
        })
        .await;

        let (index, peer) = ready?;
        // The socket's slot passes to the stream; the one that takes its
        // place in the pool claims its own.
        let handle = self.listening.swap_remove(index);
        self.refill();

        let peer = peer
            .map(|endpoint| SocketAddr::new(endpoint.addr.into(), endpoint.port))
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        Ok(WgTcpStream::from_accepted(
            Arc::clone(&self.shared),
            handle,
            peer,
        ))
    }
}

impl Drop for WgTcpListener {
    fn drop(&mut self) {
        let handles = std::mem::take(&mut self.listening);
        let released = handles.len();
        self.shared.with_stack(|stack| {
            for handle in handles {
                stack.sockets_mut().get_mut::<tcp::Socket>(handle).abort();
                stack.discard(handle);
            }
        });
        for _ in 0..released {
            self.shared.release_socket();
        }
    }
}

fn stopped() -> TunnelError {
    TunnelError::Engine("the tunnel has stopped".to_string())
}

/// Add one socket listening on `port`.
fn listen_on(stack: &mut StackInner, port: u16) -> Result<SocketHandle, TunnelError> {
    let handle = stack.add_tcp_socket();
    match stack
        .sockets_mut()
        .get_mut::<tcp::Socket>(handle)
        .listen(port)
    {
        Ok(()) => Ok(handle),
        Err(error) => {
            stack.discard(handle);
            Err(TunnelError::Engine(format!(
                "the tunnel could not listen on port {port}: {error:?}"
            )))
        }
    }
}
