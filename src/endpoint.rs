//! Caller-owned endpoint transports for bound and composed tunnels.
use crate::{TunnelError, TunnelStream};
use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

pub struct EndpointStream {
    pub stream: Box<dyn TunnelStream>,
    pub source: Option<SocketAddr>,
}

#[async_trait::async_trait]
pub trait EndpointTransport: Send + Sync {
    async fn connect(&self, host: &str, port: u16) -> Result<EndpointStream, TunnelError>;
}

pub struct SystemEndpointTransport;

#[async_trait::async_trait]
impl EndpointTransport for SystemEndpointTransport {
    async fn connect(&self, host: &str, port: u16) -> Result<EndpointStream, TunnelError> {
        let stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|error| TunnelError::Connect {
                host: host.into(),
                port,
                detail: error.to_string(),
            })?;
        stream
            .set_nodelay(true)
            .map_err(|error| TunnelError::Engine(error.to_string()))?;
        let source = stream.local_addr().ok();
        Ok(EndpointStream {
            stream: Box::new(stream),
            source,
        })
    }
}

/// Resolves the name of a tunnel's own endpoint: the hop that carries the
/// tunnel, so nothing inside the tunnel can answer it.
///
/// The embedding application decides who is asked. A provider given no
/// resolver dials only an endpoint written as an address, and an endpoint
/// written as an address is never handed to a resolver.
#[async_trait::async_trait]
pub trait EndpointResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<Vec<std::net::IpAddr>>;
}

/// Called for each new UDP session, including reconnects. Construction performs no I/O.
pub trait UdpSocketFactory: Send + Sync {
    fn bind(&self, peer: SocketAddr) -> io::Result<UdpSocket>;
}

/// One datagram socket somewhere other than the operating system, such as a
/// UDP socket bound inside another WireGuard tunnel.
///
/// The UDP counterpart of [`EndpointStream`]: a WireGuard tunnel built over a
/// [`DatagramTransport`] sends its encrypted packets through this socket
/// instead of an OS socket. Implementations must fail every pending and
/// future call once the socket can no longer carry traffic, rather than leave
/// a caller waiting forever.
#[async_trait::async_trait]
pub trait DatagramSocket: Send + Sync {
    /// Send one datagram to `target`, waiting for room rather than dropping.
    async fn send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<()>;

    /// Receive one datagram into `buffer`, returning its length and sender.
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// The address this socket sends from, when it has one.
    fn local_addr(&self) -> Option<SocketAddr>;

    /// The MTU of the link this socket's datagrams travel over, IP header
    /// included. A tunnel carried by this socket must fit its own packets,
    /// plus its own IP, UDP and WireGuard headers, inside this.
    fn link_mtu(&self) -> Option<u16>;

    /// Whether the socket has stopped for good.
    fn is_closed(&self) -> bool;

    /// Resolves once the socket has stopped for good.
    async fn closed(&self);
}

/// Something that can bind datagram sockets and resolve names on its far
/// side: the UDP counterpart of [`EndpointTransport`].
#[async_trait::async_trait]
pub trait DatagramTransport: Send + Sync {
    /// Resolve `host` on the far side of this transport.
    async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, TunnelError>;

    /// Bind one socket for a session with `peer`. Called again whenever a
    /// session is rebuilt.
    async fn bind(
        &self,
        peer: SocketAddr,
    ) -> Result<std::sync::Arc<dyn DatagramSocket>, TunnelError>;
}

pub struct SystemUdpSocketFactory;

impl UdpSocketFactory for SystemUdpSocketFactory {
    fn bind(&self, peer: SocketAddr) -> io::Result<UdpSocket> {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingUdpFactory(pub std::sync::Mutex<Vec<SocketAddr>>);

#[cfg(test)]
impl UdpSocketFactory for RecordingUdpFactory {
    fn bind(&self, peer: SocketAddr) -> io::Result<UdpSocket> {
        assert!(peer.ip().is_loopback());
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        self.0.lock().unwrap().push(socket.local_addr()?);
        Ok(socket)
    }
}

/// Answers every endpoint name with fixed addresses and keeps each name it
/// was asked.
#[cfg(test)]
pub(crate) struct RecordingResolver {
    pub answer: Vec<std::net::IpAddr>,
    pub asked: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl RecordingResolver {
    pub fn answering(answer: std::net::IpAddr) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            answer: vec![answer],
            asked: Default::default(),
        })
    }

    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl EndpointResolver for RecordingResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<std::net::IpAddr>> {
        self.asked.lock().unwrap().push(host.to_string());
        Ok(self.answer.clone())
    }
}
