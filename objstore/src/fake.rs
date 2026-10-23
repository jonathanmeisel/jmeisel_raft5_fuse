//! An in-memory S3 bucket for tests. It supports the S3 requests that this
//! crate sends: GET with a range, PUT, ListObjectsV2, and DeleteObjects.
//!
//! Unlike a mock, it checks every request as S3 does:
//!
//! - the SigV4 signature, against its own credentials (so a header that a
//!   URL signed must be sent, with the signed value);
//! - the URL's expiry;
//! - `If-None-Match`;
//! - DeleteObjects' `Content-MD5`.
//!
//! Tests run the real `S3Store` and `http` code against it. Its clock can
//! move forward (`advance`), so tests can check expiry without waiting.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use jiff::Timestamp;
use md5::{Digest as _, Md5};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::S3Config;

pub const ACCESS_KEY: &str = "fake-access-key";
pub const SECRET_KEY: &str = "fake-secret-key";
pub const REGION: &str = "fake-region";

/// What the store was asked to do, for tests that count requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub puts: u64,
    pub gets: u64,
    /// Bytes that GETs returned.
    pub bytes_read: u64,
    pub lists: u64,
    pub deleted: u64,
    /// Requests refused for a bad or expired signature.
    pub refused: u64,
}

struct State {
    bucket: String,
    objects: BTreeMap<String, Vec<u8>>,
    /// How many keys one listing page holds. S3's default is 1000.
    page_size: usize,
    /// How far this store's clock is ahead of the real clock.
    skew: Duration,
    stats: Stats,
}

pub struct FakeStore {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl FakeStore {
    /// Starts a store with one empty bucket on a local port, served from
    /// the current Tokio runtime.
    pub async fn start(bucket: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            bucket: bucket.to_string(),
            objects: BTreeMap::new(),
            page_size: 1000,
            skew: Duration::ZERO,
            stats: Stats::default(),
        }));
        let shared = Arc::clone(&state);
        let app = Router::new().fallback(move |method, uri, headers, body| {
            let state = Arc::clone(&shared);
            async move { handle(&state, addr, method, uri, headers, body) }
        });
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(FakeStore { addr, state, task })
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Settings that connect to this store, with the credentials that it
    /// checks.
    pub fn config(&self, prefix: &str) -> S3Config {
        S3Config {
            endpoint: self.endpoint(),
            bucket: self.state.lock().unwrap().bucket.clone(),
            region: REGION.into(),
            path_style: true,
            access_key: ACCESS_KEY.into(),
            secret_key: SECRET_KEY.into(),
            prefix: prefix.into(),
        }
    }

    /// Every key in the bucket, in order.
    pub fn keys(&self) -> Vec<String> {
        self.state.lock().unwrap().objects.keys().cloned().collect()
    }

    pub fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().objects.get(key).cloned()
    }

    /// Puts an object directly into the bucket, as if something other than
    /// this crate stored it.
    pub fn insert(&self, key: &str, bytes: Vec<u8>) {
        self.state.lock().unwrap().objects.insert(key.into(), bytes);
    }

    /// Removes an object directly from the bucket, as if something other
    /// than this crate deleted it.
    pub fn remove(&self, key: &str) {
        self.state.lock().unwrap().objects.remove(key);
    }

    pub fn stats(&self) -> Stats {
        self.state.lock().unwrap().stats.clone()
    }

    pub fn set_page_size(&self, n: usize) {
        self.state.lock().unwrap().page_size = n.max(1);
    }

    /// Moves this store's clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        self.state.lock().unwrap().skew += by;
    }
}

impl Drop for FakeStore {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn handle(
    state: &Mutex<State>,
    addr: SocketAddr,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut state = state.lock().unwrap();
    let url = match url::Url::parse(&format!("http://{addr}{uri}")) {
        Ok(url) => url,
        Err(_) => return error(StatusCode::BAD_REQUEST, "InvalidURI"),
    };
    let now = SystemTime::now() + state.skew;
    if let Err(why) = check_signature(&method, &url, &headers, now) {
        state.stats.refused += 1;
        return error(StatusCode::FORBIDDEN, why);
    }

    let bucket_root = format!("/{}/", state.bucket);
    let path = url.path();
    let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let has = |k: &str| query.iter().any(|(q, _)| q == k);
    let param = |k: &str| query.iter().find(|(q, _)| q == k).map(|(_, v)| v.as_str());

    if path == bucket_root || path == bucket_root.trim_end_matches('/') {
        return match method {
            Method::GET if param("list-type") == Some("2") => {
                state.stats.lists += 1;
                list(
                    &state,
                    param("prefix").unwrap_or(""),
                    param("continuation-token"),
                )
            }
            Method::POST if has("delete") => delete(&mut state, &headers, &body),
            _ => error(StatusCode::BAD_REQUEST, "UnsupportedBucketRequest"),
        };
    }
    let Some(key) = path.strip_prefix(&bucket_root) else {
        return error(StatusCode::NOT_FOUND, "NoSuchBucket");
    };
    let key = match percent_decode(key) {
        Some(key) if !key.is_empty() => key,
        _ => return error(StatusCode::BAD_REQUEST, "InvalidURI"),
    };

    match method {
        Method::GET => {
            let Some(object) = state.objects.get(&key) else {
                return error(StatusCode::NOT_FOUND, "NoSuchKey");
            };
            let total = object.len() as u64;
            let range = match headers.get(header::RANGE).map(|v| v.to_str()) {
                None => None,
                Some(Ok(v)) => match parse_range(v, total) {
                    Some(r) => Some(r),
                    None => return error(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange"),
                },
                Some(Err(_)) => return error(StatusCode::BAD_REQUEST, "InvalidArgument"),
            };
            let (status, slice, content_range) = match range {
                Some((start, end)) => (
                    StatusCode::PARTIAL_CONTENT,
                    object[start as usize..end as usize].to_vec(),
                    Some(format!("bytes {start}-{}/{total}", end - 1)),
                ),
                None => (StatusCode::OK, object.clone(), None),
            };
            state.stats.gets += 1;
            state.stats.bytes_read += slice.len() as u64;
            let mut response = (status, slice).into_response();
            if let Some(cr) = content_range {
                response
                    .headers_mut()
                    .insert(header::CONTENT_RANGE, cr.parse().unwrap());
            }
            response
        }
        Method::PUT => {
            let declared = headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok());
            if declared != Some(body.len()) {
                return error(StatusCode::BAD_REQUEST, "IncompleteBody");
            }
            let exclusive = headers
                .get(header::IF_NONE_MATCH)
                .is_some_and(|v| v.as_bytes() == b"*");
            if exclusive && state.objects.contains_key(&key) {
                return error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed");
            }
            state.objects.insert(key, body.to_vec());
            state.stats.puts += 1;
            StatusCode::OK.into_response()
        }
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

/// Checks a presigned request as S3 does: the credential is ours, the URL
/// is not expired at `now`, and the signature matches the one that our
/// secret gives over the method, path, query, and the value of every signed
/// header in the request.
fn check_signature(
    method: &Method,
    url: &url::Url,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<(), &'static str> {
    let mut amz = BTreeMap::new();
    let mut rest = Vec::new();
    for (k, v) in url.query_pairs().into_owned() {
        if k.starts_with("X-Amz-") {
            amz.insert(k, v);
        } else {
            rest.push((k, v));
        }
    }
    let field = |k: &str| {
        amz.get(k)
            .map(String::as_str)
            .ok_or("AuthorizationQueryParametersError")
    };
    if field("X-Amz-Algorithm")? != "AWS4-HMAC-SHA256" {
        return Err("AuthorizationQueryParametersError");
    }
    let credential = field("X-Amz-Credential")?;
    if credential.split('/').next() != Some(ACCESS_KEY) {
        return Err("InvalidAccessKeyId");
    }
    let date = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%SZ", field("X-Amz-Date")?)
        .ok()
        .and_then(|d| d.to_zoned(jiff::tz::TimeZone::UTC).ok())
        .map(|z| z.timestamp())
        .ok_or("AuthorizationQueryParametersError")?;
    let expires: u64 = field("X-Amz-Expires")?
        .parse()
        .map_err(|_| "AuthorizationQueryParametersError")?;
    let now = Timestamp::try_from(now).map_err(|_| "AccessDenied")?;
    if now.as_second() > date.as_second() + expires as i64 {
        return Err("AccessDenied: Request has expired");
    }

    let mut signed = Vec::new();
    for name in field("X-Amz-SignedHeaders")?.split(';') {
        if name == "host" {
            continue;
        }
        let value = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or("SignatureDoesNotMatch")?;
        signed.push((name.to_string(), value.trim().to_string()));
    }
    signed.sort();
    rest.sort();

    let mut base = url.clone();
    base.set_query(None);
    let s3_method = match *method {
        Method::GET => rusty_s3::Method::Get,
        Method::PUT => rusty_s3::Method::Put,
        Method::POST => rusty_s3::Method::Post,
        Method::DELETE => rusty_s3::Method::Delete,
        Method::HEAD => rusty_s3::Method::Head,
        _ => return Err("MethodNotAllowed"),
    };
    let expected = rusty_s3::signing::sign(
        &date,
        s3_method,
        base,
        ACCESS_KEY,
        SECRET_KEY,
        None,
        REGION,
        expires,
        rest.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        signed.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    );
    let expected = expected
        .query_pairs()
        .find(|(k, _)| k == "X-Amz-Signature")
        .map(|(_, v)| v.into_owned());
    if expected.as_deref() != Some(field("X-Amz-Signature")?) {
        return Err("SignatureDoesNotMatch");
    }
    Ok(())
}

fn list(state: &State, prefix: &str, after: Option<&str>) -> Response {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    xml.push_str(&format!(
        "<Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{}</MaxKeys><EncodingType>url</EncodingType>",
        escape(&state.bucket),
        escape(&url_encode(prefix)),
        state.page_size
    ));
    let matching = state
        .objects
        .iter()
        .filter(|(k, _)| k.starts_with(prefix))
        .filter(|(k, _)| after.is_none_or(|a| k.as_str() > a));
    let mut last = None;
    let mut count = 0;
    let mut truncated = false;
    for (key, bytes) in matching {
        if count == state.page_size {
            truncated = true;
            break;
        }
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified>\
             <ETag>\"fake\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            escape(&url_encode(key)),
            bytes.len()
        ));
        last = Some(key.clone());
        count += 1;
    }
    xml.push_str(&format!(
        "<KeyCount>{count}</KeyCount><IsTruncated>{truncated}</IsTruncated>"
    ));
    if truncated && let Some(last) = last {
        // The token is the key where the next page starts. S3's tokens are
        // opaque.
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            escape(&last)
        ));
    }
    xml.push_str("</ListBucketResult>");
    xml_response(xml)
}

fn delete(state: &mut State, headers: &HeaderMap, body: &[u8]) -> Response {
    let md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(body));
    if headers.get("content-md5").and_then(|v| v.to_str().ok()) != Some(md5.as_str()) {
        return error(StatusCode::BAD_REQUEST, "InvalidDigest");
    }
    let Ok(body) = std::str::from_utf8(body) else {
        return error(StatusCode::BAD_REQUEST, "MalformedXML");
    };
    let quiet = body.contains("<Quiet>true</Quiet>");
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    let mut rest = body;
    while let Some(start) = rest.find("<Key>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</Key>") else {
            return error(StatusCode::BAD_REQUEST, "MalformedXML");
        };
        let key = unescape(&after[..end]);
        if state.objects.remove(&key).is_some() {
            state.stats.deleted += 1;
        }
        if !quiet {
            xml.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", escape(&key)));
        }
        rest = &after[end + 6..];
    }
    xml.push_str("</DeleteResult>");
    xml_response(xml)
}

/// Parses `bytes=a-b` (or `bytes=a-`) in an object of `total` bytes, as a
/// half-open range.
fn parse_range(v: &str, total: u64) -> Option<(u64, u64)> {
    let (start, end) = v.strip_prefix("bytes=")?.split_once('-')?;
    let start: u64 = start.parse().ok()?;
    let end: u64 = if end.is_empty() {
        total.checked_sub(1)?
    } else {
        end.parse::<u64>().ok()?.min(total.checked_sub(1)?)
    };
    (start <= end).then_some((start, end + 1))
}

fn xml_response(xml: String) -> Response {
    ([(header::CONTENT_TYPE, "application/xml")], xml).into_response()
}

fn error(status: StatusCode, code: &str) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code></Error>",
        escape(code)
    );
    (status, [(header::CONTENT_TYPE, "application/xml")], xml).into_response()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Percent-encodes everything except unreserved characters and `/`, as S3
/// does for `encoding-type=url`.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}
