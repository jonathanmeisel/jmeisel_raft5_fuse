//! The filesystem servers' side of the object store: it signs what mounts
//! can do, and lists and deletes objects for garbage collection.

use std::time::Duration;

use rusty_s3::actions::{DeleteObjects, ObjectIdentifier};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};

use crate::name::{ObjectName, validate_prefix};
use crate::{Error, status_error};

/// How long the URLs for the server's own requests (list, delete) stay
/// valid. The server uses them at once, so this only needs to allow for
/// clock differences between the server and the store.
const CONTROL_TTL: Duration = Duration::from_secs(300);

/// The most keys that one `DeleteObjects` request can send. This is S3's
/// limit.
const DELETE_BATCH: usize = 1000;

/// Where a filesystem's objects are, and the credentials to sign with.
#[derive(Clone)]
pub struct S3Config {
    /// The store's base URL, for example
    /// `https://s3.eu-west-1.amazonaws.com`.
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    /// Address the bucket as `endpoint/bucket/`, not `bucket.endpoint/`.
    /// MinIO and most self-hosted stores need this.
    pub path_style: bool,
    pub access_key: String,
    pub secret_key: String,
    /// The start of every object key (see `name::validate_prefix`).
    pub prefix: String,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .field("access_key", &self.access_key)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// One object that a listing found. `name` is `None` for a key under the
/// prefix that is not one of ours. Nothing here deletes such a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub key: String,
    pub name: Option<ObjectName>,
    pub size: u64,
}

pub struct S3Store {
    bucket: Bucket,
    credentials: Credentials,
    prefix: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for S3Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Store")
            .field("bucket", &self.bucket.name())
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl S3Store {
    /// `http` sends the server's own requests (see `http::client`).
    pub fn new(config: &S3Config, http: reqwest::Client) -> Result<Self, Error> {
        validate_prefix(&config.prefix)?;
        let endpoint = config
            .endpoint
            .parse()
            .map_err(|e| Error::Config(format!("endpoint {:?}: {e}", config.endpoint)))?;
        let style = if config.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let bucket = Bucket::new(
            endpoint,
            style,
            config.bucket.clone(),
            config.region.clone(),
        )
        .map_err(|e| Error::Config(format!("bucket {:?}: {e}", config.bucket)))?;
        Ok(S3Store {
            bucket,
            credentials: Credentials::new(config.access_key.clone(), config.secret_key.clone()),
            prefix: config.prefix.clone(),
            http,
        })
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// A URL that reads any range of `name`'s object, valid for `ttl`.
    pub fn presign_get(&self, name: &ObjectName, ttl: Duration) -> String {
        let key = name.key(&self.prefix);
        self.bucket
            .get_object(Some(&self.credentials), &key)
            .sign(ttl)
            .into()
    }

    /// A URL that creates `name`'s object, exactly `len` bytes long, valid
    /// for `ttl`. It signs the length and `If-None-Match: *`, so the store
    /// refuses any other size and any second upload. So after an object is
    /// stored, its name always means that object. `http::put` sends both
    /// headers.
    pub fn presign_put(&self, name: &ObjectName, len: u64, ttl: Duration) -> String {
        let key = name.key(&self.prefix);
        let mut action = self.bucket.put_object(Some(&self.credentials), &key);
        action
            .headers_mut()
            .insert("content-length", len.to_string());
        action.headers_mut().insert("if-none-match", "*");
        action.sign(ttl).into()
    }

    /// Every object under the prefix, in key order (so by inode, then by
    /// mint time).
    pub async fn list(&self) -> Result<Vec<Listed>, Error> {
        let mut found = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut action = self.bucket.list_objects_v2(Some(&self.credentials));
            action.with_prefix(self.prefix.as_str());
            if let Some(token) = &token {
                action.with_continuation_token(token.as_str());
            }
            let response = self.http.get(action.sign(CONTROL_TTL)).send().await?;
            if !response.status().is_success() {
                return Err(status_error(response).await);
            }
            let page = rusty_s3::actions::ListObjectsV2::parse_response(&response.text().await?)
                .map_err(|e| Error::Malformed(format!("a listing: {e}")))?;
            found.extend(page.contents.into_iter().map(|c| Listed {
                name: ObjectName::parse(&self.prefix, &c.key),
                key: c.key,
                size: c.size,
            }));
            match page.next_continuation_token {
                Some(next) if Some(&next) != token.as_ref() => token = Some(next),
                Some(_) => return Err(Error::Malformed("a listing that doesn't advance".into())),
                None => return Ok(found),
            }
        }
    }

    /// Deletes the objects that `names` name. It takes only names: a key
    /// under the prefix that does not parse as a name is not ours to
    /// delete. Deleting an object that is not there succeeds, so this is
    /// safe to repeat.
    pub async fn delete(&self, names: &[ObjectName]) -> Result<(), Error> {
        let mut failures = Vec::new();
        for batch in names.chunks(DELETE_BATCH) {
            let ids: Vec<_> = batch
                .iter()
                .map(|n| ObjectIdentifier::new(n.key(&self.prefix)))
                .collect();
            let mut action = DeleteObjects::new(&self.bucket, Some(&self.credentials), ids.iter());
            // Ask the store to report only failures.
            action.set_quiet(true);
            let url = action.sign(CONTROL_TTL);
            let (body, md5) = action.body_with_md5();
            let response = self
                .http
                .post(url)
                .header("content-md5", md5)
                .body(body)
                .send()
                .await?;
            if !response.status().is_success() {
                return Err(status_error(response).await);
            }
            let result = rusty_s3::actions::DeleteObjectsResponse::parse(&response.text().await?)
                .map_err(|e| Error::Malformed(format!("a deletion's result: {e}")))?;
            failures.extend(
                result
                    .errors
                    .into_iter()
                    .map(|e| format!("{}: {} {}", e.key, e.code, e.message)),
            );
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::NotDeleted(failures))
        }
    }
}
