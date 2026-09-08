//! RFC 9114 CONNECT over authenticated HTTP/3, with no TCP or direct fallback.
mod spec;
mod stream;

pub use spec::{Http3ProxyCredentials, Http3TunnelSpec};

use std::{
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    sync::{Semaphore, watch},
    task::JoinHandle,
};

use crate::{TunnelError, TunnelProvider, TunnelStream};

const MAX_STREAMS: usize = 128;
const MAX_SESSIONS: usize = 4; // Includes connections draining after GOAWAY.
const MAX_RESPONSE_HEADERS: u64 = 16 * 1024;

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct PendingRequest(Option<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>);

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Some(request) = &mut self.0 {
            // Dropping the receive half stops it in Quinn, including when its
            // read future owns the stream. h3-quinn's explicit stop can panic
            // in that state; reset the send half and let ownership stop reads.
            request.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

struct Session {
    endpoint: Mutex<Option<quinn::Endpoint>>,
    connection: quinn::Connection,
    sender: Sender,
    retiring: AtomicBool,
    stopped: AtomicBool,
    driver: Mutex<Option<JoinHandle<()>>>,
    writers: Mutex<Vec<JoinHandle<()>>>,
}

impl Session {
    fn usable(&self) -> bool {
        !self.retiring.load(Ordering::Acquire)
            && self.connection.close_reason().is_none()
            && self
                .driver
                .lock()
                .expect("HTTP/3 driver lock")
                .as_ref()
                .is_some_and(|task| !task.is_finished())
    }

    fn stop(&self) -> (Option<quinn::Endpoint>, Vec<JoinHandle<()>>) {
        self.stopped.store(true, Ordering::Release);
        self.connection.close(0u32.into(), b"tunnel stopped");
        let endpoint = self.endpoint.lock().expect("HTTP/3 endpoint lock").take();
        if let Some(endpoint) = &endpoint {
            endpoint.close(0u32.into(), b"tunnel stopped");
        }
        let mut tasks = std::mem::take(&mut *self.writers.lock().expect("HTTP/3 writers lock"));
        if let Some(driver) = self.driver.lock().expect("HTTP/3 driver lock").take() {
            tasks.push(driver);
        }
        for task in &tasks {
            task.abort();
        }
        (endpoint, tasks)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Default)]
struct Sessions {
    current: Option<Arc<Session>>,
    all: Vec<Weak<Session>>,
}

/// Reuses a QUIC connection, with one independent CONNECT stream per dial.
///
/// The default trust store is Mozilla's public roots. Private proxy deployments
/// can supply an explicit root store. Certificate and hostname verification are
/// always enabled; environment proxy variables and 0-RTT are never used.
pub struct Http3TunnelProvider {
    spec: Http3TunnelSpec,
    config: quinn::ClientConfig,
    sessions: Mutex<Sessions>,
    connect_lock: tokio::sync::Mutex<()>,
    permits: Arc<Semaphore>,
    stop: watch::Sender<bool>,
}

impl Http3TunnelProvider {
    pub fn new(spec: Http3TunnelSpec) -> Result<Self, TunnelError> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_root_certificates(spec, roots)
    }

    pub fn with_root_certificates(
        spec: Http3TunnelSpec,
        roots: rustls::RootCertStore,
    ) -> Result<Self, TunnelError> {
        spec.validate()?;
        if roots.is_empty() {
            return Err(TunnelError::Configuration(
                "HTTP/3 proxy trust store is empty".into(),
            ));
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TunnelError::Configuration("HTTP/3 requires TLS 1.3".into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = false;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|_| TunnelError::Configuration("could not configure HTTP/3 TLS".into()))?;
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window((2u32 * 1024 * 1024).into());
        transport.receive_window((32u32 * 1024 * 1024).into());
        transport.send_window(32 * 1024 * 1024);
        transport.max_concurrent_bidi_streams(0u32.into());
        transport.max_concurrent_uni_streams(16u32.into());
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        transport.max_idle_timeout(Some(
            Duration::from_secs(90).try_into().expect("bounded timeout"),
        ));
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(transport));
        Ok(Self {
            spec,
            config,
            sessions: Mutex::new(Sessions::default()),
            connect_lock: tokio::sync::Mutex::new(()),
            permits: Arc::new(Semaphore::new(MAX_STREAMS)),
            stop: watch::channel(false).0,
        })
    }

    fn connect_error(&self, detail: &str) -> TunnelError {
        TunnelError::Http3Connect {
            host: self.spec.host.clone(),
            port: self.spec.port,
            detail: detail.into(),
        }
    }

    async fn session(&self) -> Result<Arc<Session>, TunnelError> {
        let _connecting = self.connect_lock.lock().await;
        {
            let mut sessions = self.sessions.lock().expect("HTTP/3 sessions lock");
            if let Some(session) = &sessions.current
                && session.usable()
            {
                return Ok(session.clone());
            }
            sessions.current = None;
            sessions.all.retain(|session| session.strong_count() != 0);
            if sessions.all.len() >= MAX_SESSIONS {
                return Err(self.connect_error("HTTP/3 draining connection limit reached"));
            }
        }
        let host = self.spec.host.trim_start_matches('[').trim_end_matches(']');
        // This is the only host resolver call. CONNECT destinations never enter it.
        let addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, self.spec.port)]
        } else {
            tokio::net::lookup_host((host, self.spec.port))
                .await
                .map_err(|_| self.connect_error("proxy endpoint DNS lookup failed"))?
                .take(8)
                .collect()
        };
        let mut last = self.connect_error("proxy endpoint has no addresses");
        for address in addresses {
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let endpoint = quinn::Endpoint::client(bind.parse().expect("constant address"))
                .map_err(|_| self.connect_error("could not bind QUIC UDP socket"))?;
            let connecting = endpoint
                .connect_with(self.config.clone(), address, host)
                .map_err(|_| self.connect_error("invalid QUIC endpoint configuration"))?;
            let connection = match connecting.await {
                Ok(connection) => connection,
                Err(quinn::ConnectionError::TransportError(error))
                    if (0x100..=0x1ff).contains(&u64::from(error.code)) =>
                {
                    return Err(TunnelError::Http3Tls {
                        host: self.spec.host.clone(),
                        port: self.spec.port,
                    });
                }
                Err(_) => {
                    last = self.connect_error("QUIC handshake failed");
                    continue;
                }
            };
            let (mut driver, sender) = h3::client::builder()
                .max_field_section_size(MAX_RESPONSE_HEADERS)
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|_| self.connect_error("HTTP/3 initialization failed"))?;
            let task = tokio::spawn(async move {
                let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            });
            let session = Arc::new(Session {
                endpoint: Mutex::new(Some(endpoint)),
                connection,
                sender,
                retiring: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                driver: Mutex::new(Some(task)),
                writers: Mutex::new(Vec::new()),
            });
            let mut sessions = self.sessions.lock().expect("HTTP/3 sessions lock");
            if *self.stop.borrow() {
                return Err(self.connect_error("provider stopped"));
            }
            sessions.all.push(Arc::downgrade(&session));
            sessions.current = Some(session.clone());
            return Ok(session);
        }
        Err(last)
    }

    fn stop_sessions(&self) -> Vec<Arc<Session>> {
        self.stop.send_replace(true);
        self.permits.close();
        let mut state = self.sessions.lock().expect("HTTP/3 sessions lock");
        let sessions = state
            .all
            .drain(..)
            .filter_map(|session| session.upgrade())
            .collect();
        state.current = None;
        sessions
    }
}

#[async_trait::async_trait]
impl TunnelProvider for Http3TunnelProvider {
    async fn dial(&self, host: &str, port: u16) -> Result<Box<dyn TunnelStream>, TunnelError> {
        let authority = spec::authority(host, port)?;
        let mut stop = self.stop.subscribe();
        if *stop.borrow() {
            return Err(self.connect_error("provider stopped"));
        }
        let dial = async {
            let permit = self
                .permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| self.connect_error("provider stopped"))?;
            let session = self.session().await?;
            let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(authority.as_str())
                .version(http::Version::HTTP_3);
            if let Some(credentials) = &self.spec.credentials {
                request = request.header(http::header::PROXY_AUTHORIZATION, credentials.header());
            }
            let request = request
                .body(())
                .map_err(|_| TunnelError::Configuration("invalid CONNECT request".into()))?;
            let mut sender = session.sender.clone();
            let request = sender.send_request(request).await.map_err(|_| {
                session.retiring.store(true, Ordering::Release);
                self.connect_error("HTTP/3 connection cannot open a new stream")
            })?;
            let mut pending = PendingRequest(Some(request));
            let response = pending
                .0
                .as_mut()
                .expect("pending request")
                .recv_response()
                .await
                .map_err(|_| self.connect_error("invalid or interrupted CONNECT response"))?;
            if !response.status().is_success() {
                return Err(TunnelError::Http3ProxyStatus {
                    status: response.status().as_u16(),
                });
            }
            let stream = stream::Http3Stream::new(
                pending.0.take().expect("accepted request"),
                session,
                permit,
            )
            .map_err(|_| self.connect_error("provider stopped"))?;
            Ok(Box::new(stream) as Box<dyn TunnelStream>)
        };
        tokio::select! {
            biased;
            _ = stop.changed() => Err(self.connect_error("provider stopped")),
            result = tokio::time::timeout(self.spec.request_timeout, dial) => result.unwrap_or_else(|_| Err(self.connect_error("HTTP/3 dial deadline exceeded"))),
        }
    }

    async fn shutdown(&self) {
        let stopped: Vec<_> = self
            .stop_sessions()
            .iter()
            .map(|session| session.stop())
            .collect();
        for (endpoint, tasks) in stopped {
            for task in tasks {
                let _ = task.await;
            }
            if let Some(endpoint) = endpoint {
                let _ = tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle()).await;
            }
        }
    }

    fn describe(&self) -> String {
        format!(
            "HTTP/3 CONNECT proxy at {}:{}",
            self.spec.host, self.spec.port
        )
    }
}

impl Drop for Http3TunnelProvider {
    fn drop(&mut self) {
        for session in self.stop_sessions() {
            session.stop();
        }
    }
}

#[cfg(test)]
mod tests;
