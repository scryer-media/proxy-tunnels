//! Optional socket tuning for bursts of encrypted download traffic.
use gotatun::udp::{
    UdpTransportFactory, UdpTransportFactoryParams,
    socket::{UdpSocket, UdpSocketFactory},
};

pub(crate) struct TunnelUdpFactory(pub(crate) bool);

impl UdpTransportFactory for TunnelUdpFactory {
    type Send = UdpSocket;
    type Recv = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> std::io::Result<(UdpSocket, UdpSocket)> {
        if self.0 {
            // About 32 ms of gigabit traffic; only this socket is affected.
            bind_with_buffer(params, 4 * 1024 * 1024).await
        } else {
            UdpSocketFactory::default().bind(params).await
        }
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
