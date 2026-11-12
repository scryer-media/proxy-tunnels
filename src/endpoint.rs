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

    /// Send several datagrams to `target`, in order, waiting for room rather
    /// than dropping, exactly as one [`send_to`](Self::send_to) per datagram
    /// would.
    ///
    /// Returns how many datagrams, from the start of `datagrams`, were
    /// accepted. Every one is accepted unless a send fails. A failure on the
    /// first datagram is returned as the error, and none was accepted. A
    /// failure on a later datagram ends the call early with the count
    /// accepted before it; the caller sends the rest again (call again with
    /// `&datagrams[count..]`), and that call meets the failure on its first
    /// datagram. An empty `datagrams` accepts none and returns `Ok(0)`.
    ///
    /// The default implementation calls [`send_to`](Self::send_to) once per
    /// datagram. A socket that can hand over several datagrams for less than
    /// several single sends overrides it, keeping these semantics.
    async fn send_batch_to(&self, datagrams: &[&[u8]], target: SocketAddr) -> io::Result<usize> {
        for (sent, datagram) in datagrams.iter().enumerate() {
            if let Err(error) = self.send_to(datagram, target).await {
                return if sent == 0 { Err(error) } else { Ok(sent) };
            }
        }
        Ok(datagrams.len())
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A socket that keeps every datagram sent to it and fails the send of
    /// any datagram whose first byte is in `refuse`. It implements only the
    /// single send, so a batch takes the default implementation.
    #[derive(Default)]
    struct RecordingSocket {
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        refuse: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DatagramSocket for RecordingSocket {
        async fn send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<()> {
            if self.refuse.contains(&data[0]) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "refused"));
            }
            self.sent.lock().unwrap().push((data.to_vec(), target));
            Ok(())
        }

        async fn recv_from(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn link_mtu(&self) -> Option<u16> {
            None
        }

        fn is_closed(&self) -> bool {
            false
        }

        async fn closed(&self) {
            std::future::pending().await
        }
    }

    fn target() -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 2], 4000))
    }

    /// The default batch sends each datagram once, in order, to the target.
    #[tokio::test]
    async fn the_default_batch_sends_each_datagram_once_in_order() {
        let socket = RecordingSocket::default();
        let datagrams: [&[u8]; 4] = [&[0, 10], &[1, 11, 12], &[2], &[3, 13]];
        assert_eq!(socket.send_batch_to(&datagrams, target()).await.unwrap(), 4);
        let sent = socket.sent.lock().unwrap().clone();
        let expected: Vec<(Vec<u8>, SocketAddr)> = datagrams
            .iter()
            .map(|datagram| (datagram.to_vec(), target()))
            .collect();
        assert_eq!(sent, expected);
        assert_eq!(socket.send_batch_to(&[], target()).await.unwrap(), 0);
        assert_eq!(socket.sent.lock().unwrap().len(), 4);
    }

    /// A failure part way returns the count sent before it and sends
    /// nothing after it; the call for the rest meets the failure as its
    /// error, and a failure on the first datagram sends none.
    #[tokio::test]
    async fn the_default_batch_stops_at_a_failure_and_counts_what_went() {
        let socket = RecordingSocket {
            refuse: vec![2],
            ..Default::default()
        };
        let datagrams: [&[u8]; 4] = [&[0], &[1], &[2], &[3]];
        assert_eq!(socket.send_batch_to(&datagrams, target()).await.unwrap(), 2);
        let error = socket
            .send_batch_to(&datagrams[2..], target())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let sent: Vec<Vec<u8>> = socket
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(datagram, _)| datagram.clone())
            .collect();
        assert_eq!(sent, vec![vec![0], vec![1]]);
        // Past the refused one, the rest go.
        assert_eq!(
            socket
                .send_batch_to(&datagrams[3..], target())
                .await
                .unwrap(),
            1
        );
        assert_eq!(socket.sent.lock().unwrap().len(), 3);
    }
}
