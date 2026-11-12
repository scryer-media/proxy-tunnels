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
//! from `getrusage`, and each apart) and UDP datagrams sent and received per
//! MB (the process's socket message counters, which only the tunnel's UDP
//! socket moves). Usage:
//!
//! ```text
//! cargo run --release --features test-support --example wireguard_loopback_bulk -- \
//!     [direct-]download|[direct-]upload MIB STREAMS RUNS [TUNNELS]
//! ```
//!
//! `MIB` is the total per run, split evenly over `STREAMS` concurrent
//! connections through the one tunnel. `TUNNELS` (1 to 3, default 1) chains
//! that many tunnels in this process: the outermost rides the caller-bound
//! socket and each further one is carried inside the one before it, as
//! `with_inner_wireguard` builds it. The child then runs one peer per tunnel,
//! each relaying UDP inside its tunnel to the next peer. The `direct-` modes
//! skip the tunnel and move the bytes over loopback TCP, as a floor.
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
        WireGuardTestPeerOptions, test_client_private_key, test_key,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Error = Box<dyn std::error::Error + Send + Sync>;

const CHUNK: usize = 64 * 1024;

/// The UDP port each relaying peer forwards, on its own tunnel address.
const RELAY_PORT: u16 = 51820;

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if let [command, tunnels] = args.as_slice()
        && command == "peer"
    {
        return runtime.block_on(peer(tunnels.parse()?));
    }
    let (mode, mib, streams, runs, tunnels) = match args.as_slice() {
        [mode, mib, streams, runs] => (mode, mib, streams, runs, 1),
        [mode, mib, streams, runs, tunnels] => (mode, mib, streams, runs, tunnels.parse()?),
        _ => {
            return Err(
                "usage: wireguard_loopback_bulk [direct-]download|[direct-]upload \
                 MIB STREAMS RUNS [TUNNELS]"
                    .into(),
            );
        }
    };
    if !(1..=3).contains(&tunnels) {
        return Err("TUNNELS is 1, 2 or 3".into());
    }
    let (upload, direct) = match mode.as_str() {
        "download" => (false, false),
        "upload" => (true, false),
        "direct-download" => (false, true),
        "direct-upload" => (true, true),
        _ => return Err("mode is [direct-]download or [direct-]upload".into()),
    };
    let bytes = mib.parse::<u64>()? * 1024 * 1024;
    let streams: u64 = streams.parse()?;
    let runs: usize = runs.parse()?;
    if streams == 0 || bytes % streams != 0 {
        return Err("MIB must split evenly over STREAMS".into());
    }
    runtime.block_on(client(upload, direct, bytes, streams, runs, tunnels))
}

/// The private key of the peer at `level`, 0 being the outermost.
fn peer_key(level: usize) -> [u8; 32] {
    test_key(40 + level as u8)
}

/// The far side: `tunnels` test peers. The innermost one's TCP service
/// forwards to a loopback source and sink; each one before it relays UDP on
/// [`RELAY_PORT`] inside its tunnel to the next. Prints the source's port and
/// each peer's endpoint port, outermost first, then serves until stdin
/// closes.
async fn peer(tunnels: usize) -> Result<(), Error> {
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
    // Innermost first: each relay needs the endpoint of the peer it feeds.
    let mut peers: Vec<WireGuardTestPeer> = Vec::with_capacity(tunnels);
    for level in (0..tunnels).rev() {
        let options = WireGuardTestPeerOptions {
            private_key: peer_key(level),
            udp_forward: peers.last().map(|next| (RELAY_PORT, next.endpoint())),
            ..WireGuardTestPeerOptions::default()
        };
        let forward = peers.is_empty().then_some(source_addr);
        peers.push(
            WireGuardTestPeer::start_for_downloads(options, forward, Duration::ZERO, true).await,
        );
    }
    let mut ready = format!("READY {}", source_addr.port());
    for peer in peers.iter().rev() {
        ready.push_str(&format!(" {}", peer.endpoint().port()));
    }
    println!("{ready}");
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
    drop(peers);
    Ok(())
}

async fn client(
    upload: bool,
    direct: bool,
    bytes: u64,
    streams: u64,
    runs: usize,
    tunnels: usize,
) -> Result<(), Error> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("peer")
        .arg(tunnels.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().ok_or("child stdout")?).read_line(&mut ready)?;
    let fields: Vec<&str> = ready.split_whitespace().collect();
    let ["READY", source_port, ports @ ..] = fields.as_slice() else {
        return Err(format!("unexpected peer line: {ready:?}").into());
    };
    if ports.len() != tunnels {
        return Err(format!("expected {tunnels} peer ports: {ready:?}").into());
    }
    let spec = |level: usize, host: String, port: u16| -> Result<WireGuardSpec, Error> {
        Ok(WireGuardSpec {
            proxy_config_id: format!("loopback-bulk-{level}"),
            proxy_name: "loopback bulk".to_string(),
            revision: format!("loopback-bulk-{level}@v1"),
            endpoint_host: host,
            endpoint_port: port,
            private_key: test_client_private_key(),
            peer_public_key: parse_key(&public_key_of(&peer_key(level)))?,
            preshared_key: None,
            addresses: vec![IpCidr::host(IpAddr::V4(TEST_CLIENT_ADDRESS))],
            dns_servers: Vec::new(),
            mtu: proxy_tunnels::DEFAULT_WIREGUARD_MTU,
            persistent_keepalive: Some(proxy_tunnels::DEFAULT_WIREGUARD_KEEPALIVE),
            request_timeout: Duration::from_secs(30),
            max_sockets: proxy_tunnels::DEFAULT_MAX_SOCKETS,
        })
    };
    // The outermost tunnel rides the caller-bound socket; each one after it
    // reaches its peer's endpoint, a relay on the previous peer's tunnel
    // address, through the tunnel before it.
    let mut provider = Arc::new(
        WireGuardTunnelProvider::new(
            spec(0, Ipv4Addr::LOCALHOST.to_string(), ports[0].parse()?)?,
            Arc::new(NoopTunnelObserver),
        )
        .with_download_tuning()
        .with_udp_factory(Arc::new(SystemUdpSocketFactory)),
    );
    let mut carriers = Vec::new();
    for level in 1..tunnels {
        let carried = Arc::new(
            WireGuardTunnelProvider::new(
                spec(level, TEST_PEER_ADDRESS.to_string(), RELAY_PORT)?,
                Arc::new(NoopTunnelObserver),
            )
            .with_download_tuning()
            .with_inner_wireguard(Arc::clone(&provider)),
        );
        carriers.push(std::mem::replace(&mut provider, carried));
    }
    let destination = SocketAddr::new(IpAddr::V4(TEST_PEER_ADDRESS), TEST_PEER_HTTP_PORT);

    let source_port: u16 = source_port.parse()?;
    println!(
        "mode,run,MiB,streams,seconds,MB_per_s,cpu_s_per_GB,dgrams_sent_per_MB,dgrams_recv_per_MB,user_s_per_GB,sys_s_per_GB"
    );
    eprintln!("CLIENT_PID {}", std::process::id());
    for run in 1..=runs {
        let share = bytes / streams;
        let mut opened: Vec<(Box<dyn proxy_tunnels::TunnelStream>, [u8; 9])> = Vec::new();
        for _ in 0..streams {
            let stream: Box<dyn proxy_tunnels::TunnelStream> = if direct {
                Box::new(tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).await?)
            } else {
                provider
                    .dial(&destination.ip().to_string(), destination.port())
                    .await?
            };
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
            "{}{}{},{run},{},{streams},{seconds:.2},{:.1},{:.2},{:.0},{:.0},{:.2},{:.2}",
            if direct { "direct-" } else { "" },
            if upload { "upload" } else { "download" },
            if tunnels > 1 {
                format!("-x{tunnels}")
            } else {
                String::new()
            },
            bytes / (1024 * 1024),
            megabytes / seconds,
            cpu / (bytes as f64 / 1e9),
            (after.sent - before.sent) as f64 / megabytes,
            (after.received - before.received) as f64 / megabytes,
            (after.user - before.user) / (bytes as f64 / 1e9),
            (after.system - before.system) / (bytes as f64 / 1e9),
        );
    }
    provider.shutdown().await;
    for carrier in carriers.iter().rev() {
        carrier.shutdown().await;
    }
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
    user: f64,
    system: f64,
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
            user: seconds(&usage.user),
            system: seconds(&usage.system),
            sent: usage.msgsnd,
            received: usage.msgrcv,
        }
    }
}
