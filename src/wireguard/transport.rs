//! The UDP side of a WireGuard device: an OS socket, an OS socket the
//! consumer bound on a chosen egress, or a datagram socket inside another
//! tunnel. Also the optional socket tuning for bursts of download traffic.
use std::sync::Arc;

use crate::endpoint::{DatagramSocket, DatagramTransport};
use gotatun::udp::{
    UdpTransportFactory, UdpTransportFactoryParams,
    socket::{UdpSocket, UdpSocketFactory},
};

pub(crate) struct TunnelUdpFactory {
    pub tuning: bool,
    pub bound: Option<(
        std::sync::Arc<dyn crate::endpoint::UdpSocketFactory>,
        std::net::SocketAddr,
    )>,
    pub source: std::sync::Arc<std::sync::Mutex<Option<std::net::SocketAddr>>>,
    /// Carry the device over another transport instead of an OS socket.
    pub datagram: Option<DatagramBinding>,
}

/// How a device carried by a [`DatagramTransport`] gets its socket.
pub(crate) struct DatagramBinding {
    pub transport: Arc<dyn DatagramTransport>,
    pub peer: std::net::SocketAddr,
    /// A socket bound before the device was built, so the tunnel's MTU could
    /// be derived from the link it rides. The first bind takes it; a rebind
    /// asks the transport for a fresh one.
    pub prebound: Option<Arc<dyn DatagramSocket>>,
}

#[derive(Clone)]
pub(crate) enum TunnelSocket {
    System(UdpSocket),
    Bound(Arc<BoundSocket>),
    Datagram(Arc<dyn DatagramSocket>),
}

/// The most datagrams one call moves through a caller-bound socket.
///
/// gotatun's buffered send task hands over up to this many queued packets at
/// once, and one readiness wake-up reads up to this many. It bounds the stack
/// space a Linux `sendmmsg`/`recvmmsg` call needs and how long one pass may
/// hold a worker before the packets it read move on.
pub(crate) const BOUND_BATCH: usize = 64;

/// A UDP socket the consumer bound, connected to the peer's endpoint.
///
/// A tunnel has one peer, so the socket is connected to that peer's address:
/// sends and receives then carry no address and the kernel skips the route
/// and address lookups it would otherwise repeat for every datagram. When the
/// device sends to a different address (its endpoint changed) the socket is
/// connected again to that address before the send. A connected socket only
/// receives from its peer; datagrams from any other address are dropped by
/// the kernel, which for a tunnel to a single configured endpoint is the
/// traffic that was never ours. A peer that starts answering from a new
/// address is not followed: its datagrams never reach the device.
///
/// When the operating system refuses the connect (an address family the
/// socket cannot reach, for one) the socket stays unconnected and every
/// datagram carries its address, as it would without this.
pub(crate) struct BoundSocket {
    socket: tokio::net::UdpSocket,
    /// The address the socket is connected to, or `None` while it sends and
    /// receives with explicit addresses.
    connected: std::sync::Mutex<Option<std::net::SocketAddr>>,
}

impl BoundSocket {
    /// Wrap `socket` and connect it to `peer`, falling back to an unconnected
    /// socket when the connect is refused.
    pub(crate) fn new(socket: tokio::net::UdpSocket, peer: std::net::SocketAddr) -> Self {
        let connected = match socket2::SockRef::from(&socket).connect(&peer.into()) {
            Ok(()) => Some(peer),
            Err(error) => {
                tracing::debug!(%error, "keeping the tunnel UDP socket unconnected");
                None
            }
        };
        Self {
            socket,
            connected: std::sync::Mutex::new(connected),
        }
    }

    fn connected(&self) -> Option<std::net::SocketAddr> {
        *self.connected.lock().expect("tunnel UDP peer")
    }

    /// Make `target` the socket's peer, if it is connected to another one.
    ///
    /// A failed reconnect keeps the old peer and returns the error, so this
    /// send fails rather than reaching the old address.
    fn aim(&self, target: std::net::SocketAddr) -> std::io::Result<bool> {
        let mut connected = self.connected.lock().expect("tunnel UDP peer");
        match *connected {
            None => Ok(false),
            Some(current) if current == target => Ok(true),
            Some(_) => {
                let socket = socket2::SockRef::from(&self.socket);
                socket.connect(&target.into())?;
                *connected = Some(target);
                // An error still pending now was earned by the old peer:
                // nothing has gone to the new one yet, and once connected the
                // socket no longer matches the old peer's ICMP. Left in place,
                // the kernel reports it on the next send and drops that
                // datagram, the first one meant for the new peer.
                let _ = socket.take_error();
                Ok(true)
            }
        }
    }

    /// Send one datagram to `target` without waiting.
    fn try_send_one(&self, packet: &[u8], target: std::net::SocketAddr) -> std::io::Result<()> {
        if self.aim(target)? {
            self.socket.try_send(packet)?;
        } else {
            self.socket.try_send_to(packet, target)?;
        }
        Ok(())
    }

    async fn send_to(&self, packet: &[u8], target: std::net::SocketAddr) -> std::io::Result<()> {
        loop {
            match self.try_send_one(packet, target) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.socket.writable().await?;
                }
                Err(error) if is_peer_refusal(&error) => return Ok(()),
                result => return result,
            }
        }
    }

    /// Send every packet in `packets`, in order, removing each one sent.
    ///
    /// One wake-up of the send task moves the whole batch: the socket is
    /// written until it would block, and only then does the task wait for
    /// room. A refusal reported by the far side's host (an ICMP port
    /// unreachable surfacing on a connected socket) is packet loss, not a
    /// broken socket, so the datagram is counted as sent and the rest go on.
    async fn send_many(
        &self,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        self.send_many_with(packets, |run| self.try_send_batch(run))
            .await
    }

    /// [`Self::send_many`] over `try_batch`, which sends a leading run of
    /// the packets it is given without waiting and returns how many left.
    async fn send_many_with(
        &self,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
        mut try_batch: impl FnMut(
            &[(gotatun::packet::Packet, std::net::SocketAddr)],
        ) -> std::io::Result<usize>,
    ) -> std::io::Result<()> {
        let mut sent = 0;
        let result = loop {
            if sent == packets.len() {
                break Ok(());
            }
            match try_batch(&packets[sent..]) {
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Err(error) = self.socket.writable().await {
                        break Err(error);
                    }
                }
                Err(error) if is_peer_refusal(&error) => sent += 1,
                Err(error) => break Err(error),
            }
        };
        packets.drain(..sent);
        result
    }

    /// Send a leading run of `packets` without waiting; how many were sent.
    #[cfg(not(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )))]
    fn try_send_batch(
        &self,
        packets: &[(gotatun::packet::Packet, std::net::SocketAddr)],
    ) -> std::io::Result<usize> {
        send_each(packets, |packet, target| self.try_send_one(packet, target))
    }

    /// Send a leading run of `packets` without waiting; how many were sent.
    ///
    /// The run of packets bound for one address goes out in one `sendmmsg`.
    /// `sendmmsg` fails only when its first message fails; a refusal there
    /// is that one packet lost, which [`Self::send_many`] counts and steps
    /// past, so no packet is sent twice. A failure on a later message ends
    /// the call early with the count sent, and the next call meets it on its
    /// first message.
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    fn try_send_batch(
        &self,
        packets: &[(gotatun::packet::Packet, std::net::SocketAddr)],
    ) -> std::io::Result<usize> {
        let target = packets[0].1;
        if !self.aim(target)? {
            self.socket.try_send_to(&packets[0].0, target)?;
            return Ok(1);
        }
        let run = packets
            .iter()
            .take(BOUND_BATCH)
            .take_while(|(_, to)| *to == target)
            .count();
        let datagrams: Vec<&[u8]> = packets[..run]
            .iter()
            .map(|(packet, _)| &packet[..])
            .collect();
        self.socket.try_io(tokio::io::Interest::WRITABLE, || {
            mmsg::send(&self.socket, &datagrams)
        })
    }

    /// Read one datagram into `packet` without waiting; its length and source.
    fn try_recv_into(
        &self,
        packet: &mut gotatun::packet::Packet,
    ) -> std::io::Result<(usize, std::net::SocketAddr)> {
        match self.connected() {
            Some(peer) => Ok((self.socket.try_recv(packet)?, peer)),
            None => self.socket.try_recv_from(packet),
        }
    }

    /// Read one datagram without waiting.
    fn try_recv_one(
        &self,
        pool: &mut gotatun::packet::PacketBufPool,
    ) -> std::io::Result<(gotatun::packet::Packet, std::net::SocketAddr)> {
        let mut packet = pool.get();
        let (size, source) = self.try_recv_into(&mut packet)?;
        packet.truncate(size);
        Ok((packet, source))
    }

    /// Read one datagram without waiting into a spare buffer, or a fresh one
    /// from `pool` when none is spare. A failed read keeps the buffer spare.
    #[cfg_attr(
        not(all(
            target_os = "linux",
            target_pointer_width = "64",
            target_endian = "little"
        )),
        allow(dead_code)
    )]
    fn try_recv_spare(
        &self,
        pool: &mut gotatun::packet::PacketBufPool,
        spare: &mut Vec<gotatun::packet::Packet>,
    ) -> std::io::Result<(gotatun::packet::Packet, std::net::SocketAddr)> {
        let mut packet = spare.pop().unwrap_or_else(|| pool.get());
        match self.try_recv_into(&mut packet) {
            Ok((size, source)) => {
                packet.truncate(size);
                Ok((packet, source))
            }
            Err(error) => {
                spare.push(packet);
                Err(error)
            }
        }
    }

    /// Wait for and read exactly one datagram.
    async fn recv_one(
        &self,
        pool: &mut gotatun::packet::PacketBufPool,
    ) -> std::io::Result<(gotatun::packet::Packet, std::net::SocketAddr)> {
        loop {
            self.socket.readable().await?;
            match self.try_recv_one(pool) {
                Ok(received) => return Ok(received),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if is_peer_refusal(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Wait until the socket is readable, then read up to [`BOUND_BATCH`]
    /// datagrams, stopping early when the socket would block.
    ///
    /// Datagrams land in `batch`'s spare buffers; a read takes from `pool`
    /// only as many buffers as the previous read filled.
    async fn recv_many(
        &self,
        batch: &mut RecvBatch,
        pool: &mut gotatun::packet::PacketBufPool,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        let start = packets.len();
        loop {
            self.socket.readable().await?;
            #[cfg(test)]
            {
                batch.passes += 1;
            }
            match self.try_recv_batch(pool, &mut batch.spare, packets) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if is_peer_refusal(&error) => {}
                Err(error) => return Err(error),
            }
            if packets.len() > start {
                return Ok(());
            }
        }
    }

    /// Read what the socket holds, up to [`BOUND_BATCH`] datagrams, without
    /// waiting. Errors only when nothing was read.
    #[cfg(not(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )))]
    fn try_recv_batch(
        &self,
        pool: &mut gotatun::packet::PacketBufPool,
        spare: &mut Vec<gotatun::packet::Packet>,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        let mut read = 0;
        while read < BOUND_BATCH {
            match self.try_recv_spare(pool, spare) {
                Ok(received) => {
                    packets.push(received);
                    read += 1;
                }
                // Loss reported by the far side's host; the next datagram
                // may well be there.
                Err(error) if is_peer_refusal(&error) => {}
                Err(error) if read > 0 => {
                    if error.kind() != std::io::ErrorKind::WouldBlock {
                        tracing::trace!(%error, "tunnel UDP receive stopped a batch");
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Read what the socket holds, up to [`BOUND_BATCH`] datagrams, with one
    /// `recvmmsg` when the socket is connected. Errors only when nothing was
    /// read.
    ///
    /// The read goes into `spare`, topped up from `pool` only by the buffers
    /// the last read handed on; the buffers it leaves empty stay spare for
    /// the next one.
    ///
    /// A read that fills fewer buffers than it offered found the socket's
    /// queue empty, so it clears the socket's readiness as a failed read
    /// would. Left set, the next wait would return at once and spend a
    /// `recvmmsg` that finds nothing. A datagram that lands after the read
    /// raises readiness again, as it does after a read that failed.
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    fn try_recv_batch(
        &self,
        pool: &mut gotatun::packet::PacketBufPool,
        spare: &mut Vec<gotatun::packet::Packet>,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        let Some(peer) = self.connected() else {
            packets.push(self.try_recv_spare(pool, spare)?);
            return Ok(());
        };
        while spare.len() < BOUND_BATCH {
            spare.push(pool.get());
        }
        let mut received = 0;
        let result = self.socket.try_io(tokio::io::Interest::READABLE, || {
            received = mmsg::recv(&self.socket, spare)?;
            if received < spare.len() {
                Err(std::io::ErrorKind::WouldBlock.into())
            } else {
                Ok(())
            }
        });
        if received == 0 {
            return result;
        }
        packets.extend(spare.drain(..received).map(|packet| (packet, peer)));
        Ok(())
    }

    /// Read what the socket holds now, up to [`BOUND_BATCH`] datagrams,
    /// whatever readiness was last seen; `None` when this socket cannot.
    ///
    /// A read that found the queue empty cleared the readiness, and only the
    /// runtime's next look at the socket raises it again, so datagrams that
    /// land meanwhile wait for that look. This asks the kernel itself, with
    /// one `recvmmsg`. Each datagram that arrives raises readiness again
    /// whether or not this read takes it, so nothing is missed: at worst the
    /// next wait returns at once and its read finds nothing.
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    fn recv_queued(
        &self,
        pool: &mut gotatun::packet::PacketBufPool,
        spare: &mut Vec<gotatun::packet::Packet>,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> Option<std::io::Result<()>> {
        let peer = self.connected()?;
        while spare.len() < BOUND_BATCH {
            spare.push(pool.get());
        }
        Some(match mmsg::recv(&self.socket, spare) {
            Ok(received) => {
                packets.extend(spare.drain(..received).map(|packet| (packet, peer)));
                Ok(())
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock || is_peer_refusal(&error) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        })
    }

    #[cfg(not(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    )))]
    fn recv_queued(
        &self,
        _pool: &mut gotatun::packet::PacketBufPool,
        _spare: &mut Vec<gotatun::packet::Packet>,
        _packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> Option<std::io::Result<()>> {
        None
    }
}

/// The receive side's own state, kept by the task that reads the socket from
/// one read to the next.
#[derive(Default)]
pub(crate) struct RecvBatch {
    /// What an OS socket's receive needs, made on its first read: a socket
    /// the consumer bound, or one inside another tunnel, never needs it.
    system: Option<Box<<UdpSocket as gotatun::udp::UdpRecv>::RecvManyBuf>>,
    /// Empty packet buffers, full length, that the next read fills first.
    spare: Vec<gotatun::packet::Packet>,
    /// Readiness wake-ups that led to a read attempt.
    #[cfg(test)]
    passes: usize,
}

/// Whether `error` is the far side's host refusing a datagram: an ICMP
/// unreachable that a connected socket reports on a later call. That is one
/// lost datagram, not a broken socket.
fn is_peer_refusal(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    )
}

/// Send a leading run of `packets` one at a time with `send_one`; how many
/// were dealt with.
///
/// A refusal counts its packet as dealt with (lost) and the run goes on with
/// the next, so a later call never sends it again. Any other error ends the
/// run: it is returned when nothing was sent, and otherwise left for the
/// next call to meet on its first packet.
#[cfg(any(
    test,
    not(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))
))]
fn send_each(
    packets: &[(gotatun::packet::Packet, std::net::SocketAddr)],
    mut send_one: impl FnMut(&[u8], std::net::SocketAddr) -> std::io::Result<()>,
) -> std::io::Result<usize> {
    let mut sent = 0;
    for (packet, target) in packets {
        match send_one(packet, *target) {
            Ok(()) => sent += 1,
            Err(error) if is_peer_refusal(&error) => sent += 1,
            Err(error) if sent > 0 => {
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    tracing::trace!(%error, "tunnel UDP send stopped a batch");
                }
                return Ok(sent);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(sent)
}

/// `sendmmsg` and `recvmmsg` on a connected socket, for Linux on 64-bit
/// little-endian targets. The structures are declared here: glibc and musl
/// lay `struct msghdr` out identically on these targets once the padding
/// musl names explicitly is zero.
#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod mmsg {
    use std::ffi::{c_int, c_uint, c_void};
    use std::os::fd::AsRawFd;

    use super::BOUND_BATCH;

    const MSG_DONTWAIT: c_int = 0x40;

    #[repr(C)]
    struct Iovec {
        base: *mut c_void,
        len: usize,
    }

    #[repr(C)]
    struct Msghdr {
        name: *mut c_void,
        namelen: u32,
        iov: *mut Iovec,
        iovlen: usize,
        control: *mut c_void,
        controllen: usize,
        flags: c_int,
    }

    #[repr(C)]
    struct Mmsghdr {
        hdr: Msghdr,
        len: c_uint,
    }

    const _: () = assert!(std::mem::size_of::<Msghdr>() == 56);
    const _: () = assert!(std::mem::size_of::<Mmsghdr>() == 64);

    unsafe extern "C" {
        fn sendmmsg(fd: c_int, messages: *mut Mmsghdr, count: c_uint, flags: c_int) -> c_int;
        fn recvmmsg(
            fd: c_int,
            messages: *mut Mmsghdr,
            count: c_uint,
            flags: c_int,
            timeout: *mut c_void,
        ) -> c_int;
    }

    fn header(iov: *mut Iovec) -> Mmsghdr {
        Mmsghdr {
            hdr: Msghdr {
                name: std::ptr::null_mut(),
                namelen: 0,
                iov,
                iovlen: 1,
                control: std::ptr::null_mut(),
                controllen: 0,
                flags: 0,
            },
            len: 0,
        }
    }

    /// Send `datagrams` (at most [`BOUND_BATCH`]) to the connected peer;
    /// returns how many left.
    pub(super) fn send(
        socket: &tokio::net::UdpSocket,
        datagrams: &[&[u8]],
    ) -> std::io::Result<usize> {
        let count = datagrams.len().min(BOUND_BATCH);
        let mut iovs: Vec<Iovec> = datagrams[..count]
            .iter()
            .map(|datagram| Iovec {
                base: datagram.as_ptr().cast_mut().cast(),
                len: datagram.len(),
            })
            .collect();
        let mut headers: Vec<Mmsghdr> = iovs.iter_mut().map(|iov| header(iov)).collect();
        // SAFETY: every header points at one live iovec, and every iovec at
        // a live datagram that the kernel only reads; `count` headers exist.
        let sent = unsafe {
            sendmmsg(
                socket.as_raw_fd(),
                headers.as_mut_ptr(),
                count as c_uint,
                MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(sent as usize)
    }

    /// Receive up to `buffers.len()` (at most [`BOUND_BATCH`]) datagrams from
    /// the connected peer, one per leading buffer, each buffer cut to its
    /// datagram's length; returns how many arrived. Buffers past those are
    /// left untouched.
    pub(super) fn recv(
        socket: &tokio::net::UdpSocket,
        buffers: &mut [gotatun::packet::Packet],
    ) -> std::io::Result<usize> {
        let count = buffers.len().min(BOUND_BATCH);
        let mut iovs: [Iovec; BOUND_BATCH] = std::array::from_fn(|_| Iovec {
            base: std::ptr::null_mut(),
            len: 0,
        });
        for (iov, buffer) in iovs.iter_mut().zip(buffers.iter_mut()) {
            *iov = Iovec {
                base: buffer.as_mut_ptr().cast(),
                len: buffer.len(),
            };
        }
        let first = iovs.as_mut_ptr();
        let mut headers: [Mmsghdr; BOUND_BATCH] =
            std::array::from_fn(|index| header(first.wrapping_add(index)));
        // SAFETY: the first `count` headers each point at one live iovec, and
        // each of those iovecs at a distinct live buffer of the stated length
        // that nothing else touches during the call.
        let received = unsafe {
            recvmmsg(
                socket.as_raw_fd(),
                headers.as_mut_ptr(),
                count as c_uint,
                MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let received = received as usize;
        for (buffer, header) in buffers.iter_mut().zip(&headers[..received]) {
            buffer.truncate(header.len as usize);
        }
        Ok(received)
    }
}

impl TunnelSocket {
    /// Read what the socket holds now without waiting, asking the kernel
    /// even when the last read found the queue empty; `None` when this
    /// socket only knows what its last readiness said. Errors only when
    /// the socket failed.
    pub(crate) fn recv_queued(
        &mut self,
        batch: &mut RecvBatch,
        pool: &mut gotatun::packet::PacketBufPool,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> Option<std::io::Result<()>> {
        match self {
            Self::Bound(socket) => socket.recv_queued(pool, &mut batch.spare, packets),
            Self::System(_) | Self::Datagram(_) => None,
        }
    }
}

impl gotatun::udp::UdpSend for TunnelSocket {
    type SendManyBuf = <UdpSocket as gotatun::udp::UdpSend>::SendManyBuf;

    async fn send_to(
        &self,
        packet: gotatun::packet::Packet,
        target: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        match self {
            Self::System(socket) => socket.send_to(packet, target).await,
            Self::Bound(socket) => socket.send_to(&packet, target).await,
            Self::Datagram(socket) => socket.send_to(&packet, target).await,
        }
    }
    fn max_number_of_packets_to_send(&self) -> usize {
        match self {
            Self::System(socket) => socket.max_number_of_packets_to_send(),
            Self::Bound(_) => BOUND_BATCH,
            Self::Datagram(_) => 1,
        }
    }
    async fn send_many_to(
        &self,
        buffer: &mut Self::SendManyBuf,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        match self {
            Self::System(socket) => socket.send_many_to(buffer, packets).await,
            Self::Bound(socket) => socket.send_many(packets).await,
            Self::Datagram(_) => {
                for (packet, target) in packets.drain(..) {
                    self.send_to(packet, target).await?;
                }
                Ok(())
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        match self {
            Self::System(socket) => socket.local_addr().map(Some),
            Self::Bound(socket) => socket.socket.local_addr().map(Some),
            Self::Datagram(socket) => Ok(socket.local_addr()),
        }
    }
    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> std::io::Result<()> {
        match self {
            Self::System(socket) => socket.set_fwmark(mark),
            Self::Bound(socket) => socket2::SockRef::from(&socket.socket).set_mark(mark),
            // A mark routes an OS socket; this one never reaches the OS.
            Self::Datagram(_) => Ok(()),
        }
    }
}

impl gotatun::udp::UdpRecv for TunnelSocket {
    type RecvManyBuf = RecvBatch;

    async fn recv_from(
        &mut self,
        pool: &mut gotatun::packet::PacketBufPool,
    ) -> std::io::Result<(gotatun::packet::Packet, std::net::SocketAddr)> {
        match self {
            Self::System(socket) => socket.recv_from(pool).await,
            // Exactly one datagram is read; the rest stay queued on the
            // socket for the next call.
            Self::Bound(socket) => socket.recv_one(pool).await,
            Self::Datagram(socket) => loop {
                let mut packet = pool.get();
                match socket.recv_from(&mut packet).await {
                    Ok((size, source)) => {
                        packet.truncate(size);
                        return Ok((packet, source));
                    }
                    // A datagram too large for a packet buffer is not a
                    // WireGuard packet of ours; skip it, exactly as an OS
                    // socket's truncated read is dropped by gotatun. Returning
                    // the error would end the device's receive task for good.
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                    Err(error) => return Err(error),
                }
            },
        }
    }
    async fn recv_many_from(
        &mut self,
        buffer: &mut Self::RecvManyBuf,
        pool: &mut gotatun::packet::PacketBufPool,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        match self {
            Self::System(socket) => {
                let system = buffer.system.get_or_insert_with(Default::default);
                socket.recv_many_from(system, pool, packets).await
            }
            Self::Bound(socket) => socket.recv_many(buffer, pool, packets).await,
            Self::Datagram(_) => {
                packets.push(self.recv_from(pool).await?);
                Ok(())
            }
        }
    }
    fn enable_udp_gro(&self) -> std::io::Result<()> {
        match self {
            Self::System(socket) => socket.enable_udp_gro(),
            Self::Bound(_) | Self::Datagram(_) => Ok(()),
        }
    }
}

impl UdpTransportFactory for TunnelUdpFactory {
    type Send = TunnelSocket;
    type Recv = TunnelSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> std::io::Result<(TunnelSocket, TunnelSocket)> {
        if let Some(binding) = &mut self.datagram {
            let socket = match binding.prebound.take() {
                Some(socket) => socket,
                None => binding
                    .transport
                    .bind(binding.peer)
                    .await
                    .map_err(std::io::Error::other)?,
            };
            *self.source.lock().expect("WireGuard source") = socket.local_addr();
            let socket = TunnelSocket::Datagram(socket);
            return Ok((socket.clone(), socket));
        }
        if let Some((factory, peer)) = &self.bound {
            let socket = factory.bind(*peer)?;
            #[cfg(target_os = "linux")]
            if let Some(mark) = params.fwmark {
                socket2::SockRef::from(&socket).set_mark(mark)?;
            }
            if self.tuning {
                let _ = socket2::SockRef::from(&socket).set_recv_buffer_size(4 * 1024 * 1024);
            }
            socket.set_nonblocking(true)?;
            *self.source.lock().expect("WireGuard source") = socket
                .local_addr()
                .ok()
                .filter(|addr| !addr.ip().is_unspecified());
            let socket = TunnelSocket::Bound(Arc::new(BoundSocket::new(
                tokio::net::UdpSocket::from_std(socket)?,
                *peer,
            )));
            return Ok((socket.clone(), socket));
        }
        let (send, recv) = if self.tuning {
            bind_with_buffer(params, 4 * 1024 * 1024).await?
        } else {
            UdpSocketFactory::default().bind(params).await?
        };
        *self.source.lock().expect("WireGuard source") = send
            .local_addr()
            .ok()
            .filter(|addr| !addr.ip().is_unspecified());
        Ok((TunnelSocket::System(send), TunnelSocket::System(recv)))
    }
}

async fn bind_with_buffer(
    params: &UdpTransportFactoryParams,
    bytes: usize,
) -> std::io::Result<(UdpSocket, UdpSocket)> {
    match (UdpSocketFactory {
        recv_buffer_size: Some(bytes),
        send_buffer_size: None,
    })
    .bind(params)
    .await
    {
        Ok(pair) => Ok(pair),
        Err(_) => {
            // Some kernels reject oversized requests rather than clamp them.
            tracing::debug!("retrying tunnel UDP socket with OS buffer defaults");
            UdpSocketFactory::default().bind(params).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gotatun::packet::{Packet, PacketBufPool};

    #[tokio::test]
    async fn oversized_receive_buffer_keeps_tunnel_available() {
        let params = UdpTransportFactoryParams {
            addr: Some("127.0.0.1".parse().unwrap()),
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (_, socket) = bind_with_buffer(&params, i32::MAX as usize).await.unwrap();
        assert!(socket.socket().local_addr().unwrap().ip().is_loopback());
    }

    fn loopback() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    fn bound_to(peer: std::net::SocketAddr) -> BoundSocket {
        let socket = loopback();
        socket.set_nonblocking(true).unwrap();
        BoundSocket::new(tokio::net::UdpSocket::from_std(socket).unwrap(), peer)
    }

    fn packet(pool: &PacketBufPool, bytes: &[u8]) -> Packet {
        let mut packet = pool.get();
        packet[..bytes.len()].copy_from_slice(bytes);
        packet.truncate(bytes.len());
        packet
    }

    fn received(peer: &std::net::UdpSocket) -> (Vec<u8>, std::net::SocketAddr) {
        let mut buffer = [0u8; 2048];
        let (size, source) = peer.recv_from(&mut buffer).unwrap();
        (buffer[..size].to_vec(), source)
    }

    #[tokio::test]
    async fn an_endpoint_change_reconnects_and_traffic_continues() {
        let first = loopback();
        let second = loopback();
        let socket = bound_to(first.local_addr().unwrap());
        let ours = socket.socket.local_addr().unwrap();
        assert_eq!(socket.connected(), Some(first.local_addr().unwrap()));

        socket
            .send_to(b"one", first.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(received(&first), (b"one".to_vec(), ours));

        // The device roamed: the next send goes to the new address, and the
        // socket now answers to that address.
        socket
            .send_to(b"two", second.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(received(&second), (b"two".to_vec(), ours));
        assert_eq!(socket.connected(), Some(second.local_addr().unwrap()));

        // The old address is no longer the peer, so its datagram, sent first,
        // never reaches the reader; the new peer's does.
        first.send_to(b"stale", ours).unwrap();
        second.send_to(b"three", ours).unwrap();
        let mut pool = PacketBufPool::new(8);
        let mut packets = Vec::new();
        socket
            .recv_many(&mut RecvBatch::default(), &mut pool, &mut packets)
            .await
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0].0[..], b"three");
        assert_eq!(packets[0].1, second.local_addr().unwrap());
    }

    /// Block until the kernel holds a datagram for `socket`, without reading
    /// it and without touching what the runtime knows of the socket.
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    fn wait_until_queued(socket: &tokio::net::UdpSocket) {
        use std::os::fd::AsRawFd;
        #[repr(C)]
        struct PollFd {
            fd: i32,
            events: i16,
            revents: i16,
        }
        unsafe extern "C" {
            fn poll(fds: *mut PollFd, count: u64, timeout: i32) -> i32;
        }
        const POLLIN: i16 = 1;
        let mut entry = PollFd {
            fd: socket.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, for the duration of the call; a negative
        // timeout waits for the condition itself.
        let ready = unsafe { poll(&mut entry, 1, -1) };
        assert_eq!(ready, 1, "poll: {}", std::io::Error::last_os_error());
    }

    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[tokio::test]
    async fn a_queued_read_takes_what_landed_after_the_queue_ran_dry() {
        let peer = loopback();
        let socket = Arc::new(bound_to(peer.local_addr().unwrap()));
        let ours = socket.socket.local_addr().unwrap();
        let mut tunnel = TunnelSocket::Bound(Arc::clone(&socket));
        let mut batch = RecvBatch::default();
        let mut pool = PacketBufPool::new(4 * BOUND_BATCH);
        let mut packets = Vec::new();

        // This read finds the queue short, so it leaves the socket marked
        // not readable.
        peer.send_to(b"one", ours).unwrap();
        socket
            .recv_many(&mut batch, &mut pool, &mut packets)
            .await
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0].0[..], b"one");
        packets.clear();

        // Nothing queued: the read finds nothing and is not an error.
        assert!(matches!(
            tunnel.recv_queued(&mut batch, &mut pool, &mut packets),
            Some(Ok(()))
        ));
        assert!(packets.is_empty());

        // A datagram lands; the queued read takes it at once, with no wait
        // for the runtime to see the socket readable again.
        peer.send_to(b"two", ours).unwrap();
        wait_until_queued(&socket.socket);
        assert!(matches!(
            tunnel.recv_queued(&mut batch, &mut pool, &mut packets),
            Some(Ok(()))
        ));
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0].0[..], b"two");
        assert_eq!(packets[0].1, peer.local_addr().unwrap());

        // The waiting read still works after it: a datagram that lands next
        // is delivered, not lost behind readiness the queued read consumed.
        packets.clear();
        peer.send_to(b"three", ours).unwrap();
        gotatun::udp::UdpRecv::recv_many_from(&mut tunnel, &mut batch, &mut pool, &mut packets)
            .await
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0].0[..], b"three");
    }

    #[tokio::test]
    async fn a_batch_drain_delivers_every_datagram_in_arrival_order() {
        const COUNT: usize = 3 * BOUND_BATCH + 7;
        let peer = loopback();
        let socket = bound_to(peer.local_addr().unwrap());
        let ours = socket.socket.local_addr().unwrap();
        socket2::SockRef::from(&socket.socket)
            .set_recv_buffer_size(1 << 20)
            .unwrap();
        for index in 0..COUNT as u32 {
            peer.send_to(&index.to_be_bytes(), ours).unwrap();
        }

        let mut pool = PacketBufPool::new(COUNT);
        let mut packets = Vec::new();
        while packets.len() < COUNT {
            let before = packets.len();
            socket
                .recv_many(&mut RecvBatch::default(), &mut pool, &mut packets)
                .await
                .unwrap();
            assert!(packets.len() - before <= BOUND_BATCH);
        }
        let order: Vec<u32> = packets
            .iter()
            .map(|(packet, source)| {
                assert_eq!(*source, peer.local_addr().unwrap());
                u32::from_be_bytes(packet[..].try_into().unwrap())
            })
            .collect();
        assert_eq!(order, (0..COUNT as u32).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_batch_send_delivers_every_datagram_in_order() {
        const COUNT: usize = 2 * BOUND_BATCH + 3;
        let peer = loopback();
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(1 << 20)
            .unwrap();
        let socket = bound_to(peer.local_addr().unwrap());
        let pool = PacketBufPool::new(COUNT);
        let mut packets: Vec<_> = (0..COUNT as u32)
            .map(|index| {
                (
                    packet(&pool, &index.to_be_bytes()),
                    peer.local_addr().unwrap(),
                )
            })
            .collect();
        socket.send_many(&mut packets).await.unwrap();
        assert!(packets.is_empty());
        for index in 0..COUNT as u32 {
            assert_eq!(received(&peer).0, index.to_be_bytes());
        }
    }

    #[tokio::test]
    async fn single_reads_deliver_every_queued_datagram_in_order() {
        const COUNT: u32 = 10;
        let peer = loopback();
        let socket = Arc::new(bound_to(peer.local_addr().unwrap()));
        let ours = socket.socket.local_addr().unwrap();
        for index in 0..COUNT {
            peer.send_to(&index.to_be_bytes(), ours).unwrap();
        }
        let mut tunnel = TunnelSocket::Bound(socket);
        let mut pool = PacketBufPool::new(COUNT as usize + 1);
        let mut next = async || {
            let (packet, source) = gotatun::udp::UdpRecv::recv_from(&mut tunnel, &mut pool)
                .await
                .unwrap();
            assert_eq!(source, peer.local_addr().unwrap());
            packet[..].to_vec()
        };
        assert_eq!(next().await, 0u32.to_be_bytes());
        // Queued behind the rest: a read that took more than one datagram
        // and kept only the first would answer with this one next.
        peer.send_to(b"last", ours).unwrap();
        for index in 1..COUNT {
            assert_eq!(next().await, index.to_be_bytes());
        }
        assert_eq!(next().await, b"last");
    }

    #[tokio::test]
    async fn a_refusal_mid_batch_sends_no_packet_twice() {
        let peer = loopback().local_addr().unwrap();
        let socket = bound_to(peer);
        let pool = PacketBufPool::new(8);
        let mut packets: Vec<_> = (0..6u8)
            .map(|index| (packet(&pool, &[index]), peer))
            .collect();
        let mut attempts: Vec<u8> = Vec::new();
        socket
            .send_many_with(&mut packets, |run| {
                send_each(run, |datagram, _| {
                    attempts.push(datagram[0]);
                    if datagram[0] == 2 {
                        Err(std::io::ErrorKind::ConnectionRefused.into())
                    } else {
                        Ok(())
                    }
                })
            })
            .await
            .unwrap();
        assert!(packets.is_empty());
        assert_eq!(attempts, vec![0, 1, 2, 3, 4, 5], "each packet tried once");
    }

    #[tokio::test]
    async fn a_failure_mid_batch_resumes_at_the_failed_packet() {
        let peer = loopback().local_addr().unwrap();
        let socket = bound_to(peer);
        let pool = PacketBufPool::new(8);
        let mut packets: Vec<_> = (0..4u8)
            .map(|index| (packet(&pool, &[index]), peer))
            .collect();
        let mut delivered: Vec<u8> = Vec::new();
        let mut failed = false;
        socket
            .send_many_with(&mut packets, |run| {
                send_each(run, |datagram, _| {
                    // One passing failure on packet 2: the batch stops there
                    // and the next call starts with packet 2.
                    if datagram[0] == 2 && !failed {
                        failed = true;
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                    delivered.push(datagram[0]);
                    Ok(())
                })
            })
            .await
            .unwrap();
        assert!(packets.is_empty());
        assert_eq!(delivered, vec![0, 1, 2, 3], "each packet delivered once");
    }

    #[tokio::test]
    async fn a_refused_datagram_does_not_break_the_socket() {
        // An address nothing listens on: the host answers with a refusal.
        let closed = loopback().local_addr().unwrap();
        let live = loopback();
        let socket = bound_to(closed);
        let ours = socket.socket.local_addr().unwrap();
        for _ in 0..3 {
            socket.send_to(b"lost", closed).await.unwrap();
        }
        let pool = PacketBufPool::new(4);
        let mut packets = vec![
            (packet(&pool, b"lost"), closed),
            (packet(&pool, b"lost"), closed),
            (packet(&pool, b"kept"), live.local_addr().unwrap()),
        ];
        socket.send_many(&mut packets).await.unwrap();
        assert!(packets.is_empty());
        assert_eq!(received(&live), (b"kept".to_vec(), ours));

        live.send_to(b"back", ours).unwrap();
        let mut pool = PacketBufPool::new(4);
        let mut packets = Vec::new();
        socket
            .recv_many(&mut RecvBatch::default(), &mut pool, &mut packets)
            .await
            .unwrap();
        assert_eq!(&packets[0].0[..], b"back");
    }

    /// The datagram `index` of the reuse test: its number, then a length and
    /// filler that vary with it, so a buffer written twice or cut to the
    /// wrong length shows.
    fn numbered(index: u32) -> Vec<u8> {
        let mut bytes = index.to_be_bytes().to_vec();
        bytes.resize(4 + (index as usize * 37) % 1200, index as u8);
        bytes
    }

    #[tokio::test]
    async fn reused_buffers_keep_every_datagram_intact_and_in_order() {
        let peer = loopback();
        let socket = bound_to(peer.local_addr().unwrap());
        let ours = socket.socket.local_addr().unwrap();
        socket2::SockRef::from(&socket.socket)
            .set_recv_buffer_size(1 << 22)
            .unwrap();
        let mut pool = PacketBufPool::new(16);
        let mut batch = RecvBatch::default();
        // Every packet stays held until the end, so a buffer handed on twice
        // would hold a later datagram where an earlier one should be.
        let mut held = Vec::new();
        let mut next = 0u32;
        // Short, full and longer-than-a-batch bursts, each read until empty.
        for burst in [
            1,
            3,
            BOUND_BATCH,
            1,
            BOUND_BATCH + 1,
            7,
            2 * BOUND_BATCH + 5,
            2,
        ] {
            for _ in 0..burst {
                peer.send_to(&numbered(next), ours).unwrap();
                next += 1;
            }
            let goal = next as usize;
            while held.len() < goal {
                let spare: Vec<*const u8> = batch.spare.iter().map(|p| p.as_ptr()).collect();
                let before = held.len();
                socket
                    .recv_many(&mut batch, &mut pool, &mut held)
                    .await
                    .unwrap();
                let read = held.len() - before;
                assert!(read <= BOUND_BATCH);
                // A read fills the buffers left spare by the last one first.
                for (packet, _) in &held[before..before + read.min(spare.len())] {
                    assert!(
                        spare.contains(&packet.as_ptr()),
                        "a spare buffer was skipped"
                    );
                }
                assert!(batch.spare.len() <= BOUND_BATCH);
            }
        }
        for (index, (packet, source)) in held.iter().enumerate() {
            assert_eq!(*source, peer.local_addr().unwrap());
            assert_eq!(&packet[..], &numbered(index as u32)[..], "datagram {index}");
        }
        let mut starts: Vec<usize> = held.iter().map(|(p, _)| p.as_ptr() as usize).collect();
        starts.sort_unstable();
        starts.dedup();
        assert_eq!(
            starts.len(),
            held.len(),
            "two held datagrams share a buffer"
        );
    }

    #[tokio::test]
    async fn a_read_that_empties_the_socket_spends_no_extra_wakeup() {
        let peer = loopback();
        let socket = bound_to(peer.local_addr().unwrap());
        let ours = socket.socket.local_addr().unwrap();
        for index in 0..5u32 {
            peer.send_to(&index.to_be_bytes(), ours).unwrap();
        }
        let mut pool = PacketBufPool::new(16);
        let mut batch = RecvBatch::default();
        let mut packets = Vec::new();
        socket
            .recv_many(&mut batch, &mut pool, &mut packets)
            .await
            .unwrap();
        assert_eq!(packets.len(), 5);
        assert_eq!(batch.passes, 1);
        // Nothing is queued now. The next read waits for the datagram sent
        // while it is parked, and reads it on the one wake-up it brings.
        let send = async {
            tokio::task::yield_now().await;
            peer.send_to(b"later", ours).unwrap();
        };
        let (read, ()) = tokio::join!(socket.recv_many(&mut batch, &mut pool, &mut packets), send);
        read.unwrap();
        assert_eq!(&packets[5].0[..], b"later");
        assert_eq!(batch.passes, 2, "a read found the socket empty");
    }
}
