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

/// Called for each new UDP session, including reconnects. Construction performs no I/O.
pub trait UdpSocketFactory: Send + Sync {
    fn bind(&self, peer: SocketAddr) -> io::Result<UdpSocket>;
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
