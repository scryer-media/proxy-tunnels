//! A diagnostic tap on the tunnel's inner packets.
//!
//! When a provider is given a path ([`super::WireGuardTunnelProvider::with_packet_capture`])
//! every decrypted packet that reaches the stack and every packet the stack
//! composes is noted in a pcap file there, so a question such as "did that
//! connection request arrive at all" has an answer that does not depend on
//! what the sockets above counted.
//!
//! Only headers are kept: the IP header, then a TCP header with its options,
//! or a UDP header and the [`UDP_PAYLOAD_HEAD`] bytes after it. No TCP payload
//! is written, so nothing an HTTP request carries can reach the file. The
//! addresses of both ends of every flow do.
//!
//! The tap never slows the tunnel. A packet's headers are copied into a
//! bounded queue and a thread of its own writes them; when that thread falls
//! behind, records are dropped, not waited for.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How many bytes after a UDP header are kept: the length of a uTP header,
/// which is what tells a connection request from data.
pub(crate) const UDP_PAYLOAD_HEAD: usize = 20;

/// The longest record: an IPv6 header and a TCP header with every option.
const SNAP_LENGTH: usize = 40 + 60;

/// Records that may wait for the writer before new ones are dropped.
const QUEUE_DEPTH: usize = 4096;

/// pcap's link type for packets that start at the IP header.
const LINKTYPE_RAW: u32 = 101;

struct Record {
    at: Duration,
    /// The packet's length on the link.
    length: u32,
    kept: u8,
    head: [u8; SNAP_LENGTH],
}

/// The sending half of a capture. Dropping it ends the writer once it has
/// written what is queued.
pub(crate) struct Capture {
    records: SyncSender<Record>,
    #[cfg(test)]
    writer: std::thread::JoinHandle<()>,
}

impl Capture {
    /// Start a capture into `path`, replacing any file there. The file is
    /// opened on the writer's thread; a path that cannot be written is logged
    /// and the tunnel runs without a capture. `tunnel` is for log lines only.
    pub(crate) fn start(path: PathBuf, tunnel: &str) -> Option<Self> {
        let (records, queue) = sync_channel(QUEUE_DEPTH);
        let tunnel = tunnel.to_string();
        let spawned = std::thread::Builder::new()
            .name("wg-capture".to_string())
            .spawn(move || match open(&path) {
                Ok(file) => {
                    tracing::warn!(
                        proxy_config_id = tunnel.as_str(),
                        path = %path.display(),
                        "capturing the headers of every packet inside the tunnel"
                    );
                    if let Err(error) = write_all(BufWriter::new(file), &queue) {
                        tracing::warn!(
                            proxy_config_id = tunnel.as_str(),
                            error = %error,
                            "the tunnel's packet capture stopped"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    proxy_config_id = tunnel.as_str(),
                    path = %path.display(),
                    error = %error,
                    "the tunnel's packet capture could not be opened"
                ),
            });
        match spawned {
            Ok(_writer) => Some(Self {
                records,
                #[cfg(test)]
                writer: _writer,
            }),
            Err(error) => {
                tracing::warn!(error = %error, "the tunnel's packet capture could not start");
                None
            }
        }
    }

    /// Note one packet. Never waits: with the queue full, or the writer gone,
    /// the record is dropped.
    pub(crate) fn note(&self, packet: &[u8]) {
        let kept = headers_length(packet);
        let mut head = [0; SNAP_LENGTH];
        head[..kept].copy_from_slice(&packet[..kept]);
        let record = Record {
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
            length: u32::try_from(packet.len()).unwrap_or(u32::MAX),
            kept: kept as u8,
            head,
        };
        match self.records.try_send(record) {
            Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    /// Stop, and return once everything noted is in the file.
    #[cfg(test)]
    pub(crate) fn finish(self) {
        drop(self.records);
        self.writer.join().expect("the capture writer ends cleanly");
    }
}

/// Only the owner may read the file: it names every peer of the tunnel.
fn open(path: &std::path::Path) -> io::Result<File> {
    let mut options = File::options();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_all(mut out: impl Write, queue: &Receiver<Record>) -> io::Result<()> {
    write_file_header(&mut out)?;
    out.flush()?;
    // Block for one record, write every other that is already waiting, then
    // flush, so the file is current whenever the tunnel is quiet.
    while let Ok(record) = queue.recv() {
        write_record(&mut out, &record)?;
        while let Ok(record) = queue.try_recv() {
            write_record(&mut out, &record)?;
        }
        out.flush()?;
    }
    Ok(())
}

fn write_file_header(out: &mut impl Write) -> io::Result<()> {
    out.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?;
    out.write_all(&2_u16.to_le_bytes())?;
    out.write_all(&4_u16.to_le_bytes())?;
    out.write_all(&0_u32.to_le_bytes())?;
    out.write_all(&0_u32.to_le_bytes())?;
    out.write_all(&(SNAP_LENGTH as u32).to_le_bytes())?;
    out.write_all(&LINKTYPE_RAW.to_le_bytes())
}

fn write_record(out: &mut impl Write, record: &Record) -> io::Result<()> {
    let kept = usize::from(record.kept);
    // pcap's seconds are 32 bits wide.
    out.write_all(&(record.at.as_secs() as u32).to_le_bytes())?;
    out.write_all(&record.at.subsec_micros().to_le_bytes())?;
    out.write_all(&u32::from(record.kept).to_le_bytes())?;
    out.write_all(&record.length.to_le_bytes())?;
    out.write_all(&record.head[..kept])
}

/// How much of `packet` is headers: the IP header, then a TCP header with its
/// options, or a UDP header and [`UDP_PAYLOAD_HEAD`] bytes. For any other
/// protocol, and for a packet that does not parse, the IP header alone.
pub(crate) fn headers_length(packet: &[u8]) -> usize {
    const TCP: u8 = 6;
    const UDP: u8 = 17;

    let (ip, protocol) = match packet.first().map(|first| first >> 4) {
        Some(4) if packet.len() >= 20 => (usize::from(packet[0] & 0x0f) * 4, packet[9]),
        // An extension header is "any other protocol": its length is not read.
        Some(6) if packet.len() >= 40 => (40, packet[6]),
        _ => return packet.len().min(20),
    };
    let ip = ip.clamp(20, 60).min(packet.len());
    let transport = match protocol {
        TCP => match packet.get(ip + 12) {
            Some(offset) => (usize::from(offset >> 4) * 4).clamp(20, 60),
            None => 0,
        },
        UDP => 8 + UDP_PAYLOAD_HEAD,
        _ => 0,
    };
    (ip + transport).min(packet.len()).min(SNAP_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, rest: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol];
        packet.extend_from_slice(&[0; 2]);
        packet.extend_from_slice(&[10, 6, 0, 2, 10, 6, 0, 1]);
        packet.extend_from_slice(rest);
        packet
    }

    fn ipv6(next: u8, rest: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0, 0, 0, next, 64];
        packet.extend_from_slice(&[0; 32]);
        packet.extend_from_slice(rest);
        packet
    }

    /// A TCP header of `header` bytes followed by `payload` bytes.
    fn tcp(header: usize, payload: usize) -> Vec<u8> {
        let mut segment = vec![0; header + payload];
        segment[12] = ((header / 4) as u8) << 4;
        segment
    }

    #[test]
    fn a_udp_packet_keeps_its_headers_and_a_utp_header_of_payload() {
        assert_eq!(headers_length(&ipv4(17, &[0; 500])), 20 + 8 + 20);
        assert_eq!(headers_length(&ipv6(17, &[0; 500])), 40 + 8 + 20);
        // A datagram shorter than that is kept whole.
        assert_eq!(headers_length(&ipv4(17, &[0; 12])), 20 + 12);
    }

    #[test]
    fn a_tcp_packet_keeps_its_header_and_options_and_no_payload() {
        assert_eq!(headers_length(&ipv4(6, &tcp(20, 1400))), 20 + 20);
        assert_eq!(headers_length(&ipv4(6, &tcp(32, 1400))), 20 + 32);
        assert_eq!(headers_length(&ipv6(6, &tcp(60, 1400))), 40 + 60);
        // A data offset below a real header's is read as the smallest header,
        // so it cannot reach past one.
        assert_eq!(headers_length(&ipv4(6, &tcp(0, 1400))), 20 + 20);
    }

    #[test]
    fn any_other_packet_keeps_its_ip_header_only() {
        assert_eq!(headers_length(&ipv4(1, &[0; 64])), 20);
        assert_eq!(headers_length(&ipv6(58, &[0; 64])), 40);
        assert_eq!(headers_length(&[0x45, 0, 0]), 3);
        assert_eq!(headers_length(&[0xff; 200]), 20);
        assert_eq!(headers_length(&[]), 0);
    }

    #[test]
    fn a_capture_writes_a_pcap_file_of_truncated_packets() {
        let path = std::env::temp_dir().join(format!(
            "proxy-tunnels-capture-{}-writes.pcap",
            std::process::id()
        ));
        let capture = Capture::start(path.clone(), "test").expect("the writer starts");
        let mut datagram = ipv4(17, &[0; 8]);
        datagram.extend_from_slice(&[0x41; 20]);
        datagram.extend_from_slice(b"payload that must not reach the file");
        capture.note(&datagram);
        capture.note(&ipv4(6, &tcp(20, 900)));
        capture.finish();

        let file = std::fs::read(&path).expect("the capture is on disk");
        std::fs::remove_file(&path).expect("the capture is removed");

        let word = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().expect("four bytes"));
        assert_eq!(word(0), 0xa1b2_c3d4);
        assert_eq!(word(16), SNAP_LENGTH as u32);
        assert_eq!(word(20), LINKTYPE_RAW);

        // First record: 48 bytes kept of the datagram.
        assert_eq!(word(24 + 8), 48);
        assert_eq!(word(24 + 12), datagram.len() as u32);
        assert_eq!(&file[40..40 + 48], &datagram[..48]);
        // Second record: the two headers of a 940-byte segment.
        let second = 40 + 48;
        assert_eq!(word(second + 8), 40);
        assert_eq!(word(second + 12), 940);
        assert_eq!(file.len(), second + 16 + 40);
        assert!(!file.windows(7).any(|window| window == b"payload"));
    }
}
