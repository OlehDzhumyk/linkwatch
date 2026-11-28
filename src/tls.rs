//! TLS client setup shared by the extensions that talk HTTPS: the CVE lookup (`cve`) and the
//! webhook alerts (`alerts`). Pure Rust (`rustls-rustcrypto`). Compiled only when one of them is on.
//!
//! Webhook requests can carry a bearer token, so secrets travel over this stack. Certificates are
//! verified against `webpki-roots`.

use std::sync::Arc;
use tokio_rustls::TlsConnector;

pub(crate) fn connector() -> anyhow::Result<TlsConnector> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}
