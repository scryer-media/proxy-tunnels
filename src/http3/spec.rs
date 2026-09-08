use std::{fmt, net::IpAddr, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::TunnelError;

/// HTTP Basic proxy credentials. Debug output never includes either value.
#[derive(Clone)]
pub struct Http3ProxyCredentials {
    username: String,
    password: String,
}

impl Http3ProxyCredentials {
    pub fn new(username: String, password: String) -> Result<Self, TunnelError> {
        if username.is_empty()
            || username.len() > 255
            || password.len() > 4096
            || username.contains(':')
            || username
                .chars()
                .chain(password.chars())
                .any(char::is_control)
        {
            return Err(TunnelError::Configuration(
                "invalid HTTP/3 proxy credentials".into(),
            ));
        }
        Ok(Self { username, password })
    }

    pub(super) fn header(&self) -> http::HeaderValue {
        let encoded = STANDARD.encode(format!("{}:{}", self.username, self.password));
        let mut value = http::HeaderValue::from_str(&format!("Basic {encoded}"))
            .expect("base64 is a valid header value");
        value.set_sensitive(true);
        value
    }
}

impl fmt::Debug for Http3ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Http3ProxyCredentials(<redacted>)")
    }
}

/// One immutable HTTP/3 proxy configuration revision.
///
/// Only `host` is resolved using host networking. Destination names in `dial`
/// travel in CONNECT's authority to the proxy, without local resolution.
#[derive(Clone, Debug)]
pub struct Http3TunnelSpec {
    pub proxy_config_id: String,
    pub revision: String,
    pub host: String,
    pub port: u16,
    pub credentials: Option<Http3ProxyCredentials>,
    /// Total admission, bootstrap, TLS, and CONNECT response deadline.
    pub request_timeout: Duration,
}

impl Http3TunnelSpec {
    pub(super) fn validate(&self) -> Result<(), TunnelError> {
        authority(&self.host, self.port)?;
        if self.request_timeout.is_zero() || self.request_timeout > Duration::from_secs(300) {
            return Err(TunnelError::Configuration(
                "HTTP/3 request timeout must be within (0, 300] seconds".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn authority(host: &str, port: u16) -> Result<http::uri::Authority, TunnelError> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let valid = !host.is_empty()
        && host.len() <= 253
        && port != 0
        && (host.parse::<IpAddr>().is_ok()
            || host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
    if !valid {
        return Err(TunnelError::Configuration(
            "invalid HTTP/3 tunnel host or port".into(),
        ));
    }
    let value = if matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    value
        .parse()
        .map_err(|_| TunnelError::Configuration("invalid CONNECT authority".into()))
}
