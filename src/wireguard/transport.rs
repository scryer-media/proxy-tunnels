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
    Bound(std::sync::Arc<tokio::net::UdpSocket>),
    Datagram(Arc<dyn DatagramSocket>),
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
            Self::Bound(socket) => {
                socket.send_to(&packet, target).await?;
                Ok(())
            }
            Self::Datagram(socket) => socket.send_to(&packet, target).await,
        }
    }
    fn max_number_of_packets_to_send(&self) -> usize {
        match self {
            Self::System(socket) => socket.max_number_of_packets_to_send(),
            Self::Bound(_) | Self::Datagram(_) => 1,
        }
    }
    async fn send_many_to(
        &self,
        buffer: &mut Self::SendManyBuf,
        packets: &mut Vec<(gotatun::packet::Packet, std::net::SocketAddr)>,
    ) -> std::io::Result<()> {
        match self {
            Self::System(socket) => socket.send_many_to(buffer, packets).await,
            Self::Bound(_) | Self::Datagram(_) => {
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
            Self::Bound(socket) => socket.local_addr().map(Some),
            Self::Datagram(socket) => Ok(socket.local_addr()),
        }
    }
    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> std::io::Result<()> {
        match self {
            Self::System(socket) => socket.set_fwmark(mark),
            Self::Bound(socket) => socket2::SockRef::from(socket.as_ref()).set_mark(mark),
            // A mark routes an OS socket; this one never reaches the OS.
            Self::Datagram(_) => Ok(()),
        }
    }
}

impl gotatun::udp::UdpRecv for TunnelSocket {
    type RecvManyBuf = <UdpSocket as gotatun::udp::UdpRecv>::RecvManyBuf;

    async fn recv_from(
        &mut self,
        pool: &mut gotatun::packet::PacketBufPool,
    ) -> std::io::Result<(gotatun::packet::Packet, std::net::SocketAddr)> {
        match self {
            Self::System(socket) => socket.recv_from(pool).await,
            Self::Bound(socket) => {
                let mut packet = pool.get();
                let (size, source) = socket.recv_from(&mut packet).await?;
                packet.truncate(size);
                Ok((packet, source))
            }
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
            Self::System(socket) => socket.recv_many_from(buffer, pool, packets).await,
            Self::Bound(_) | Self::Datagram(_) => {
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
            let socket = TunnelSocket::Bound(std::sync::Arc::new(tokio::net::UdpSocket::from_std(
                socket,
            )?));
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
}
