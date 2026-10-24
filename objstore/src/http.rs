//! Access to the object store through URLs that a server signed. Mounts use
//! this to read and write blocks, and `S3Store` builds its own requests on
//! it.

use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{IF_NONE_MATCH, RANGE};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::{Error, status_error};

/// The client type that these functions take, as `client` builds it.
pub use reqwest::Client;

/// How a client connects to the object store.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Certificates to trust in addition to the system's, in PEM. Use this
    /// for a store behind a private CA, such as a MinIO deployment.
    pub extra_roots_pem: Option<Vec<u8>>,
    /// Whether `http://` URLs are allowed. Use only for tests and local
    /// setups, because the URLs are bearer credentials.
    pub allow_plaintext: bool,
    /// The longest time that one request can take, from start to finish.
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

/// An HTTP client for the object store. It uses TLS through rustls and
/// `ring` (the provider that the rest of the workspace uses), trusts the
/// system's roots and any extra ones, and refuses plaintext unless allowed.
/// On Android, "the system's roots" are Mozilla's, built in (see
/// `webpki_verifier`).
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
    #[cfg(not(target_os = "android"))]
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(
        rustls_platform_verifier::Verifier::new_with_extra_roots(extra, provider.clone())
            .map_err(|e| Error::Config(format!("certificate verifier: {e}")))?,
    );
    #[cfg(target_os = "android")]
    let verifier = webpki_verifier(extra, provider.clone())?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(!config.allow_plaintext)
        .timeout(config.timeout)
        .build()
        .map_err(|e| Error::Config(format!("HTTP client: {e}")))
}

/// A verifier that trusts Mozilla's roots (`webpki-roots`, built into the
/// binary) and `extra`. Android checks certificates through Java, which a
/// plain program, as under Termux, can't reach; this needs nothing from the
/// system. Elsewhere, `client` uses the system's own verifier.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn webpki_verifier(
    extra: Vec<CertificateDer<'static>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, Error> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra {
        roots
            .add(cert)
            .map_err(|e| Error::Config(format!("extra CA: {e}")))?;
    }
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| Error::Config(format!("certificate verifier: {e}")))?;
    Ok(verifier)
}

/// Fetches bytes `range` of the object that a presigned GET `url` names.
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

/// Uploads `body` through a presigned PUT `url`. The URL signed exactly
/// this length and `If-None-Match: *` (see `S3Store::presign_put`), and the
/// body sets the length. Returns `Error::AlreadyExists` if the URL was
/// already used.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn the_built_in_roots_make_a_verifier() {
        webpki_verifier(Vec::new(), provider()).unwrap();
    }

    #[test]
    fn a_bad_extra_root_is_refused() {
        let bad = CertificateDer::from(vec![1, 2, 3]);
        assert!(matches!(
            webpki_verifier(vec![bad], provider()),
            Err(Error::Config(_))
        ));
    }
}
