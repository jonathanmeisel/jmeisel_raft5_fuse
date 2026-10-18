//! Talking to the object store through URLs a server signed: what a mount
//! does to read and write blocks, and what `S3Store` builds its own
//! requests on.

use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{IF_NONE_MATCH, RANGE};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::{Error, status_error};

/// The client the functions here take, as `client` builds it.
pub use reqwest::Client;

/// How a client reaches the object store.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Certificates to trust beyond the system's, PEM: for a store behind
    /// a private CA, such as a MinIO deployment.
    pub extra_roots_pem: Option<Vec<u8>>,
    /// Whether `http://` URLs may be used. Only ever for tests and local
    /// setups: the URLs themselves are bearer credentials.
    pub allow_plaintext: bool,
    /// How long one request may take, start to finish.
    pub timeout: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            extra_roots_pem: None,
            allow_plaintext: false,
            timeout: Duration::from_secs(120),
        }
    }
}

/// An HTTP client for the object store: TLS through rustls and `ring`
/// (the provider the rest of the workspace uses), the system's roots plus
/// any extra ones, and plaintext refused unless allowed.
pub fn client(config: &HttpConfig) -> Result<reqwest::Client, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut extra = Vec::new();
    if let Some(pem) = &config.extra_roots_pem {
        for cert in CertificateDer::pem_slice_iter(pem) {
            extra.push(cert.map_err(|e| Error::Config(format!("extra CA: {e}")))?);
        }
        if extra.is_empty() {
            return Err(Error::Config("extra CA: no certificates in it".into()));
        }
    }
    let verifier =
        rustls_platform_verifier::Verifier::new_with_extra_roots(extra, provider.clone())
            .map_err(|e| Error::Config(format!("certificate verifier: {e}")))?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(!config.allow_plaintext)
        .timeout(config.timeout)
        .build()
        .map_err(|e| Error::Config(format!("HTTP client: {e}")))
}

/// Bytes `range` of the object a presigned GET `url` names.
pub async fn get_range(
    client: &reqwest::Client,
    url: &str,
    range: Range<u64>,
) -> Result<Vec<u8>, Error> {
    if range.is_empty() {
        return Ok(Vec::new());
    }
    let response = client
        .get(url)
        .header(RANGE, format!("bytes={}-{}", range.start, range.end - 1))
        .send()
        .await?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(status_error(response).await);
    }
    let body = response.bytes().await?;
    let want = range.end - range.start;
    if body.len() as u64 != want {
        // A range past the object's end comes back short, or as a 416.
        return Err(Error::Malformed(format!(
            "asked for {want} bytes, got {}",
            body.len()
        )));
    }
    Ok(body.to_vec())
}

/// Uploads `body` through a presigned PUT `url`, which signed exactly
/// this length and `If-None-Match: *` (see `S3Store::presign_put`); the
/// body sets the length.
/// `Error::AlreadyExists` if the URL has been used already.
pub async fn put(client: &reqwest::Client, url: &str, body: Vec<u8>) -> Result<(), Error> {
    let response = client
        .put(url)
        .header(IF_NONE_MATCH, "*")
        .body(body)
        .send()
        .await?;
    match response.status() {
        s if s.is_success() => Ok(()),
        StatusCode::PRECONDITION_FAILED => Err(Error::AlreadyExists),
        _ => Err(status_error(response).await),
    }
}
