//! Loopback bulk-transfer measurement for the WireGuard path.
//!
//! Two processes on 127.0.0.1. A child process runs the in-process test peer
//! (a second gotatun device and smoltcp stack) with a loopback TCP source and
//! sink behind it. This process is the client: it brings a tunnel up through a
//! caller-bound UDP socket (`with_udp_factory`), the path Weaver uses, and
//! moves bytes through one TCP connection inside the tunnel. Only the client's
//! own costs land in this process, so its CPU time and socket message counts
//! are the client path's alone.
//!
//! Each run prints MB/s, CPU-seconds per GB (process user plus system time,
//! from `getrusage`) and UDP datagrams sent and received per MB (the
//! process's socket message counters, which only the tunnel's UDP socket
//! moves). Usage:
//!
//! ```text
//! cargo run --release --features test-support --example wireguard_loopback_bulk -- \
//!     download|upload MIB STREAMS RUNS
//! ```
//!
//! `MIB` is the total per run, split evenly over `STREAMS` concurrent
//! connections through the one tunnel.
use std::{
    io::{BufRead, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use proxy_tunnels::{
    IpCidr, NoopTunnelObserver, TunnelProvider, WireGuardSpec, WireGuardTunnelProvider,
    endpoint::SystemUdpSocketFactory,
    parse_key, public_key_of,
    wireguard::{
        TEST_CLIENT_ADDRESS, TEST_PEER_ADDRESS, TEST_PEER_HTTP_PORT, WireGuardTestPeer,
        WireGuardTestPeerOptions, test_client_private_key,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Error = Box<dyn std::error::Error + Send + Sync>;

const CHUNK: usize = 64 * 1024;

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if args.first().map(String::as_str) == Some("peer") {
        return runtime.block_on(peer());
    }
    let [mode, mib, streams, runs] = args.as_slice() else {
        return Err("usage: wireguard_loopback_bulk download|upload MIB STREAMS RUNS".into());
    };
    let upload = match mode.as_str() {
        "download" => false,
        "upload" => true,
        _ => return Err("mode is download or upload".into()),
    };
    let bytes = mib.parse::<u64>()? * 1024 * 1024;
    let streams: u64 = streams.parse()?;
    let runs: usize = runs.parse()?;
    if streams == 0 || bytes % streams != 0 {
        return Err("MIB must split evenly over STREAMS".into());
    }
    runtime.block_on(client(upload, bytes, streams, runs))
}

/// The far side: a test peer whose TCP service forwards to a loopback source
/// and sink. Prints its endpoint and key, then serves until stdin closes.
async fn peer() -> Result<(), Error> {
    let source = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let source_addr = source.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = source.accept().await {
            tokio::spawn(async move {
                let mut header = [0u8; 9];
                if connection.read_exact(&mut header).await.is_err() {
                    return;
                }
                let length = u64::from_be_bytes(header[1..].try_into().expect("eight bytes"));
                let mut buffer = vec![0u8; CHUNK];
                if header[0] == b'D' {
                    let mut left = length;
                    while left > 0 {
                        let take = left.min(CHUNK as u64) as usize;
                        if connection.write_all(&buffer[..take]).await.is_err() {
                            return;
                        }
                        left -= take as u64;
                    }
                    let _ = connection.shutdown().await;
                } else {
                    let mut left = length;
                    while left > 0 {
                        match connection.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => left = left.saturating_sub(read as u64),
                        }
                    }
                    let _ = connection.write_all(b"k").await;
                }
            });
        }
    });
    let peer = WireGuardTestPeer::start_for_downloads(
        WireGuardTestPeerOptions::default(),
        Some(source_addr),
        Duration::ZERO,
        true,
    )
    .await;
    println!(
        "READY {} {}",
        peer.endpoint().port(),
        public_key_of(&proxy_tunnels::wireguard::test_peer_private_key())
    );
    std::io::stdout().flush()?;
    tokio::task::spawn_blocking(|| {
        let mut sink = String::new();
        while std::io::stdin()
            .read_line(&mut sink)
            .map(|n| n > 0)
            .unwrap_or(false)
        {}
    })
    .await?;
    drop(peer);
    Ok(())
}

async fn client(upload: bool, bytes: u64, streams: u64, runs: usize) -> Result<(), Error> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("peer")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().ok_or("child stdout")?).read_line(&mut ready)?;
    let fields: Vec<&str> = ready.split_whitespace().collect();
    let ["READY", port, key] = fields.as_slice() else {
        return Err(format!("unexpected peer line: {ready:?}").into());
    };
    let spec = WireGuardSpec {
        proxy_config_id: "loopback-bulk".to_string(),
        proxy_name: "loopback bulk".to_string(),
        revision: "loopback-bulk@v1".to_string(),
        endpoint_host: Ipv4Addr::LOCALHOST.to_string(),
        endpoint_port: port.parse()?,
        private_key: test_client_private_key(),
        peer_public_key: parse_key(key)?,
        preshared_key: None,
        addresses: vec![IpCidr::host(IpAddr::V4(TEST_CLIENT_ADDRESS))],
        dns_servers: Vec::new(),
        mtu: proxy_tunnels::DEFAULT_WIREGUARD_MTU,
        persistent_keepalive: Some(proxy_tunnels::DEFAULT_WIREGUARD_KEEPALIVE),
        request_timeout: Duration::from_secs(30),
        max_sockets: proxy_tunnels::DEFAULT_MAX_SOCKETS,
    };
    let provider = WireGuardTunnelProvider::new(spec, Arc::new(NoopTunnelObserver))
        .with_download_tuning()
        .with_udp_factory(Arc::new(SystemUdpSocketFactory));
    let destination = SocketAddr::new(IpAddr::V4(TEST_PEER_ADDRESS), TEST_PEER_HTTP_PORT);

    println!(
        "mode,run,MiB,streams,seconds,MB_per_s,cpu_s_per_GB,dgrams_sent_per_MB,dgrams_recv_per_MB"
    );
    for run in 1..=runs {
        let share = bytes / streams;
        let mut opened = Vec::new();
        for _ in 0..streams {
            let stream = provider
                .dial(&destination.ip().to_string(), destination.port())
                .await?;
            let mut header = [0u8; 9];
            header[0] = if upload { b'U' } else { b'D' };
            header[1..].copy_from_slice(&share.to_be_bytes());
            opened.push((stream, header));
        }

        let before = Usage::now();
        let started = Instant::now();
        let mut transfers = tokio::task::JoinSet::new();
        for (mut stream, header) in opened {
            transfers.spawn(async move {
                stream.write_all(&header).await?;
                transfer(&mut stream, upload, share).await
            });
        }
        while let Some(done) = transfers.join_next().await {
            done??;
        }
        let seconds = started.elapsed().as_secs_f64();
        let after = Usage::now();

        let megabytes = bytes as f64 / 1e6;
        let cpu = after.cpu_seconds - before.cpu_seconds;
        println!(
            "{},{run},{},{streams},{seconds:.2},{:.1},{:.2},{:.0},{:.0}",
            if upload { "upload" } else { "download" },
            bytes / (1024 * 1024),
            megabytes / seconds,
            cpu / (bytes as f64 / 1e9),
            (after.sent - before.sent) as f64 / megabytes,
            (after.received - before.received) as f64 / megabytes,
        );
    }
    provider.shutdown().await;
    drop(child.stdin.take());
    child.wait()?;
    Ok(())
}

/// Move `bytes` through `stream` in the run's direction.
async fn transfer(
    stream: &mut Box<dyn proxy_tunnels::TunnelStream>,
    upload: bool,
    bytes: u64,
) -> Result<(), Error> {
    let mut buffer = vec![0u8; CHUNK];
    if upload {
        let mut left = bytes;
        while left > 0 {
            let take = left.min(CHUNK as u64) as usize;
            stream.write_all(&buffer[..take]).await?;
            left -= take as u64;
        }
        stream.flush().await?;
        let mut ack = [0u8; 1];
        stream.read_exact(&mut ack).await?;
    } else {
        let mut got = 0u64;
        while got < bytes {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(format!("stream ended after {got} of {bytes} bytes").into());
            }
            got += read as u64;
        }
    }
    Ok(())
}

/// The process's CPU time and socket message counters.
struct Usage {
    cpu_seconds: f64,
    sent: i64,
    received: i64,
}

#[repr(C)]
#[derive(Default)]
struct Timeval {
    seconds: i64,
    #[cfg(target_vendor = "apple")]
    micros: i32,
    #[cfg(not(target_vendor = "apple"))]
    micros: i64,
}

#[repr(C)]
#[derive(Default)]
struct Rusage {
    user: Timeval,
    system: Timeval,
    maxrss: i64,
    ixrss: i64,
    idrss: i64,
    isrss: i64,
    minflt: i64,
    majflt: i64,
    nswap: i64,
    inblock: i64,
    oublock: i64,
    msgsnd: i64,
    msgrcv: i64,
    nsignals: i64,
    nvcsw: i64,
    nivcsw: i64,
}

unsafe extern "C" {
    fn getrusage(who: i32, usage: *mut Rusage) -> i32;
}

impl Usage {
    fn now() -> Self {
        let mut usage = Rusage::default();
        // SAFETY: `usage` is a valid, writable `struct rusage`; 0 is RUSAGE_SELF.
        let status = unsafe { getrusage(0, &mut usage) };
        assert_eq!(status, 0, "getrusage");
        let seconds = |time: &Timeval| time.seconds as f64 + time.micros as f64 / 1e6;
        Self {
            cpu_seconds: seconds(&usage.user) + seconds(&usage.system),
            sent: usage.msgsnd,
            received: usage.msgrcv,
        }
    }
}
