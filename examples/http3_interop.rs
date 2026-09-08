//! Isolated byte-verified download harness for a separately started HTTP/3 proxy.
//! See docs/http3.md. This only targets loopback fixture endpoints.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use proxy_tunnels::{
    Http3ProxyCredentials, Http3TunnelProvider, Http3TunnelSpec, TunnelError, TunnelProvider,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: http3_interop PROXY_PORT CA_DER CONNECTIONS MIB_PER_CONNECTION".into());
    }
    let port: u16 = args[0].parse()?;
    let connections: usize = args[2].parse()?;
    let mib: usize = args[3].parse()?;
    if !(1..=128).contains(&connections) || !(1..=1024).contains(&mib) {
        return Err("fixture size outside bounds".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(std::fs::read(
        &args[1],
    )?))?;
    let spec = Http3TunnelSpec {
        proxy_config_id: "local-interop".into(),
        revision: "1".into(),
        host: "127.0.0.1".into(),
        port,
        credentials: Some(Http3ProxyCredentials::new(
            "fixture".into(),
            "fixture-only".into(),
        )?),
        request_timeout: Duration::from_secs(10),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted?;
                    jobs.spawn(async move {
                        let size = socket.read_u64().await?;
                        let seed = socket.read_u8().await?;
                        if size > 1024 * 1024 * 1024 { return Err(std::io::Error::other("invalid fixture request")); }
                        let payload: Vec<_> = (0..65536).map(|i| (i as u8).wrapping_add(seed)).collect();
                        let mut remaining = size;
                        while remaining > 0 {
                            let count = remaining.min(payload.len() as u64) as usize;
                            socket.write_all(&payload[..count]).await?;
                            remaining -= count as u64;
                        }
                        socket.shutdown().await
                    });
                }
                Some(result) = jobs.join_next(), if !jobs.is_empty() => { result??; }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    });
    let provider = Arc::new(Http3TunnelProvider::with_root_certificates(
        spec.clone(),
        roots.clone(),
    )?);
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        let mut rejected = spec;
        rejected.credentials = None;
        let unauthenticated = Http3TunnelProvider::with_root_certificates(rejected, roots)?;
        let rejection = unauthenticated.dial("127.0.0.1", origin.port()).await;
        unauthenticated.shutdown().await;
        if !matches!(rejection, Err(TunnelError::Http3ProxyStatus { status: 407 })) { return Err("proxy did not reject missing authentication with 407".into()); }

        let started = Instant::now();
        let mut jobs = JoinSet::new();
        for index in 0..connections {
            let provider = provider.clone();
            jobs.spawn(async move {
                let mut stream = provider.dial("127.0.0.1", origin.port()).await?;
                let total = mib * 1024 * 1024;
                let seed = index as u8;
                stream.write_u64(total as u64).await?;
                stream.write_u8(seed).await?;
                stream.flush().await?;
                let mut buffer = vec![0; 65536];
                let mut received = 0;
                loop {
                    let count = stream.read(&mut buffer).await?;
                    if count == 0 { break; }
                    for (offset, byte) in buffer[..count].iter().enumerate() {
                        if *byte != ((received + offset) as u8).wrapping_add(seed) { return Err("fixture payload mismatch".into()); }
                    }
                    received += count;
                    if received > total { return Err("fixture response too long".into()); }
                }
                if received != total { return Err("truncated fixture response".into()); }
                Ok::<_, Error>(received)
            });
        }
        let mut bytes = 0;
        while let Some(result) = jobs.join_next().await { bytes += result??; }
        let elapsed = started.elapsed().as_secs_f64();
        println!("connections={connections} bytes_verified={bytes} seconds={elapsed:.3} gbps={:.3} authentication=407", bytes as f64 * 8.0 / elapsed / 1e9);
        Ok::<_, Error>(())
    }).await;
    provider.shutdown().await;
    server.abort();
    let _ = server.await;
    result?
}
