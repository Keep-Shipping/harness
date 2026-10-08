//! `OciDistribution`: a [`Registry`] adapter for the OCI distribution API
//! ([#60](https://github.com/Keep-Shipping/harness/issues/60)).
//!
//! It speaks plain HTTP/1.1 through an [`HttpClient`] and nothing else: the
//! socket, the TLS and the host allowlist belong to the client the caller hands
//! it, so this crate holds the *protocol*, not the transport.
//!
//! # Invariants
//!
//! - **The digest comes from the registry.** Every descriptor this adapter
//!   returns is read off `Docker-Content-Digest` (or computed from bytes the
//!   registry just served), never from a digest the caller asserted. The one
//!   place this adapter hashes for itself is a blob it is *about to upload*,
//!   because the upload URL has to name the content.
//! - **Pulled bytes are verified.** Every `pull` re-hashes what came back and
//!   fails with [`RegistryError::DigestMismatch`] unless it is the digest that
//!   was asked for. So does every push, against the digest the registry
//!   reported.
//! - **A 404 is not an empty repository.** Existence checks only answer
//!   `Ok(false)` on a real 404; anything else propagates, so an adapter that
//!   cannot see does not lie about what is there.
//! - **Unknown is not an error.** A repository with no referrers, or a digest
//!   nothing refers to, is an empty list.
//!
//! # What a repository string means
//!
//! The first path component of `repository` is the registry host, port
//! included: `registry.example:5000/team/app` talks to `registry.example:5000`
//! about `team/app`. `https` is used unless the host is in
//! [`with_insecure_hosts`](OciDistribution::with_insecure_hosts), which is how
//! a plain-http registry on `localhost` is reached.
//!
//! Credential helpers (`credHelpers`, `credsStore`) are **not** run: a host
//! served by one is an error, not an anonymous push. See
//! [`CredentialStore`].
//!
//! The registries this has actually been run against are listed in
//! `docs/REGISTRIES.md` — including the ones it does not claim to support.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use ks_core::ports::BoxFuture;
use ks_core::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use ks_core::ports::supply_chain::{
    ArtifactUpload, Descriptor, Digest, ImageRef, OciLayoutContents, Reference, Registry,
    RegistryError,
};
use sha2::{Digest as _, Sha256};

mod auth;
mod credentials;

use auth::Challenge;
pub use credentials::{CredentialStore, Credentials};

/// The OCI image manifest this adapter pushes artifacts as.
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// The OCI image index, and the media type of the referrers fallback tag.
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// The media type of the conventional empty config.
pub const EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";
/// The media type of an artifact layer.
pub const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";

/// Everything a manifest lookup may legitimately return, OCI and Docker.
const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.manifest.v1+json,\
application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.v2+json,\
application/vnd.docker.distribution.manifest.list.v2+json,\
application/vnd.docker.distribution.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v1+prettyjws";

/// Blobs above this size are uploaded in chunks; below it, in one `PUT`.
const CHUNK_THRESHOLD: usize = 2 * 1024 * 1024;

/// A [`Registry`] over any OCI distribution registry.
pub struct OciDistribution {
    http: Arc<dyn HttpClient>,
    insecure_hosts: BTreeSet<String>,
    credentials: CredentialStore,
    /// Fetched bearer tokens, by [`Challenge::token_key`].
    tokens: Mutex<BTreeMap<String, String>>,
    /// Which hosts credentials were configured for, for `Debug` — the
    /// credentials themselves are never printed.
    credential_hosts: Vec<String>,
}

impl OciDistribution {
    /// An anonymous adapter over `http`. The client's
    /// [`HttpPolicy`](ks_core::ports::http::HttpPolicy) must already allowlist
    /// the registry hosts this will talk to.
    pub fn new(http: Arc<dyn HttpClient>) -> OciDistribution {
        OciDistribution {
            http,
            insecure_hosts: BTreeSet::new(),
            credentials: CredentialStore::new(),
            tokens: Mutex::new(BTreeMap::new()),
            credential_hosts: Vec::new(),
        }
    }

    /// Adds hosts that are spoken to over plain `http` rather than `https` —
    /// a registry on `localhost`, say. Without this every request is `https`.
    pub fn with_insecure_hosts(
        mut self,
        hosts: impl IntoIterator<Item = impl Into<String>>,
    ) -> OciDistribution {
        self.insecure_hosts.extend(hosts.into_iter().map(|host| host.into().to_ascii_lowercase()));
        self
    }

    /// Supplies credentials for registries that need them.
    pub fn with_credentials(mut self, credentials: CredentialStore) -> OciDistribution {
        self.credential_hosts = credentials.hosts();
        self.credentials = credentials;
        self
    }
}

impl std::fmt::Debug for OciDistribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciDistribution")
            .field("insecure_hosts", &self.insecure_hosts)
            .field("credential_hosts", &self.credential_hosts)
            .finish_non_exhaustive()
    }
}

/// Where a repository lives: the base URL, the host (credentials and token
/// caches are keyed by it) and the name within the registry.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Endpoint {
    base: String,
    host: String,
    name: String,
}

impl OciDistribution {
    /// Splits `host[:port]/name` into the URL prefix and the registry-local
    /// repository name.
    fn endpoint(&self, repository: &str) -> Result<Endpoint, RegistryError> {
        let Some((host, name)) = repository.split_once('/') else {
            return Err(RegistryError::Backend {
                message: format!(
                    "repository {repository:?} has no name: expected `host[:port]/name`, e.g. \
                     `registry.example:5000/team/app`"
                ),
            });
        };
        if name.is_empty() || host.is_empty() {
            return Err(RegistryError::Backend {
                message: format!("repository {repository:?} is not `host[:port]/name`"),
            });
        }
        let scheme =
            if self.insecure_hosts.contains(&host.to_ascii_lowercase()) { "http" } else { "https" };
        Ok(Endpoint {
            base: format!("{scheme}://{host}"),
            host: host.to_string(),
            name: name.to_string(),
        })
    }

    // -- transport ---------------------------------------------------------

    /// Sends one request, answering a `Bearer`/`Basic` challenge once.
    ///
    /// A 401 or 403 that survives the retry is [`RegistryError::Unauthorized`];
    /// everything else comes back as a response for the caller to read the
    /// status of, because 404 is an answer here and not a failure.
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse, RegistryError> {
        let host = url_host(&req.url).to_string();
        let first = self.raw(req.clone()).await?;
        let challenged = first.status == 401 && !has_header(&req, "authorization");
        let challenge =
            challenged.then(|| header(&first, "www-authenticate")).flatten().and_then(auth::parse);
        let Some(challenge) = challenge else {
            return deny_unauthorized(first, &host);
        };
        let authorization = self.authorize(&challenge, &host).await?;
        let mut retry = req;
        retry.headers.push(("Authorization".to_string(), authorization));
        deny_unauthorized(self.raw(retry).await?, &host)
    }

    /// One request, no authentication dance.
    async fn raw(&self, req: HttpRequest) -> Result<HttpResponse, RegistryError> {
        self.http.send(req).await.map_err(|error| RegistryError::Backend {
            message: format!("registry request failed: {error}"),
        })
    }

    /// The `Authorization` value for a challenge: a cached token, a freshly
    /// fetched one, or the credentials themselves for `Basic`.
    async fn authorize(&self, challenge: &Challenge, host: &str) -> Result<String, RegistryError> {
        let key = challenge.token_key(host);
        if let Some(token) = self.tokens.lock().expect("registry token cache").get(&key).cloned() {
            return Ok(format!("Bearer {token}"));
        }
        match challenge {
            Challenge::Basic { realm } => {
                let credentials = self.credentials.for_host(host)?.ok_or_else(|| {
                    RegistryError::Backend {
                        message: format!(
                            "{host} asked for basic auth for realm {realm:?} and no credentials are \
                             configured for it; put them in the docker config or pass them \
                             explicitly"
                        ),
                    }
                })?;
                Ok(credentials.basic())
            }
            Challenge::Bearer { realm, .. } => {
                self.check_realm(realm, host)?;
                let credentials = self.credentials.for_host(host)?;
                let query = challenge.token_query();
                let separator = if query.is_empty() { "" } else { "?" };
                let mut token_request =
                    HttpRequest::new(HttpMethod::Get, format!("{realm}{separator}{query}"));
                if let Some(credentials) = credentials {
                    token_request.headers.push(("Authorization".to_string(), credentials.basic()));
                }
                let response = self.raw(token_request).await?;
                if response.status != 200 {
                    return Err(RegistryError::Unauthorized { repository: host.to_string() });
                }
                let token = serde_json::from_slice::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| {
                        ["token", "access_token"]
                            .into_iter()
                            .find_map(|key| value.get(key).and_then(serde_json::Value::as_str))
                            .map(str::to_string)
                    })
                    .ok_or(RegistryError::Backend {
                        message: format!("the token endpoint at {realm} returned no token"),
                    })?;
                self.tokens.lock().expect("registry token cache").insert(key, token.clone());
                Ok(format!("Bearer {token}"))
            }
        }
    }

    /// Whether `host` is one this adapter speaks to over plain `http`.
    fn is_insecure(&self, host: &str) -> bool {
        self.insecure_hosts.contains(&host.to_ascii_lowercase())
    }

    /// The realm a challenge named gets the same rule as the registry itself:
    /// the credentials go there, so it is `https` unless both it and the
    /// registry are insecure hosts — an `https` registry never downgrades to a
    /// plain-`http` realm.
    fn check_realm(&self, realm: &str, host: &str) -> Result<(), RegistryError> {
        let plain = realm.starts_with("http://")
            && self.is_insecure(url_host(realm))
            && self.is_insecure(host);
        if realm.starts_with("https://") || plain {
            return Ok(());
        }
        Err(RegistryError::Backend {
            message: format!(
                "{host} challenged for a token at realm {realm:?}, which is not https; a \
                 registry cannot talk a client into sending its credentials in the clear"
            ),
        })
    }

    /// A manifest GET/HEAD/DELETE-shaped request with the Accept header every
    /// manifest lookup needs.
    fn manifest_request(method: HttpMethod, url: &str) -> HttpRequest {
        let mut req = HttpRequest::new(method, url);
        req.headers.push(("Accept".to_string(), ACCEPT_MANIFESTS.to_string()));
        req
    }

    /// Turns a non-2xx into the error the port names: 404 is
    /// [`RegistryError::NotFound`], anything else is a backend failure carrying
    /// what the registry said.
    fn ok(
        response: HttpResponse,
        endpoint: &Endpoint,
        reference: &str,
    ) -> Result<HttpResponse, RegistryError> {
        match response.status {
            200..=299 => Ok(response),
            404 => Err(RegistryError::NotFound {
                repository: endpoint.host.clone(),
                reference: reference.to_string(),
            }),
            _ => Err(backend(response, endpoint, reference)),
        }
    }

    // -- reads -------------------------------------------------------------

    /// The digest a manifest response reports: the `Docker-Content-Digest`
    /// header, or the hash of the body when a registry omits it.
    fn reported_digest(response: &HttpResponse) -> Result<Digest, RegistryError> {
        match header(response, "docker-content-digest") {
            Some(value) => Digest::parse(value).map_err(|error| RegistryError::Backend {
                message: format!("the registry reported an unusable digest {value:?}: {error}"),
            }),
            None => Ok(sha256_digest(&response.body)),
        }
    }

    async fn referrers_at(&self, url: &str, accept: &str) -> Result<HttpResponse, RegistryError> {
        let mut req = HttpRequest::new(HttpMethod::Get, url);
        req.headers.push(("Accept".to_string(), accept.to_string()));
        self.request(req).await
    }

    /// The tags `repository` currently serves, in whatever order the registry
    /// lists them.
    ///
    /// A repository that has never been pushed to answers 404 (`NAME_UNKNOWN`),
    /// which is an empty tag list and not a failure: "nothing published yet" is
    /// the answer to "which versions exist", not an error. Anything else that is
    /// not 2xx is a [`RegistryError::Backend`], as everywhere else.
    ///
    /// A paginated listing answers each page with a `Link` header naming the next;
    /// those are followed to the end rather than silently truncated, because a
    /// caller reading this cannot tell a complete answer from a first page.
    /// `TAG_PAGES` is a floor under a registry that never stops linking, not a
    /// limit a real one reaches.
    ///
    /// Not part of the [`Registry`] port: a caller that needs a *specific* tag has
    /// [`Registry::resolve`], and tag listing is the one read here with no port
    /// method behind it.
    pub async fn tags(&self, repository: &str) -> Result<Vec<String>, RegistryError> {
        let endpoint = self.endpoint(repository)?;
        let path = format!("/v2/{}/tags/list", endpoint.name);
        let mut url = format!("{}{path}", endpoint.base);
        let mut tags = Vec::new();
        for _ in 0..TAG_PAGES {
            let response = self.request(HttpRequest::new(HttpMethod::Get, url.clone())).await?;
            let next = next_page(&response, &path);
            let body = match response.status {
                200..=299 => response.body,
                404 if tags.is_empty() => return Ok(tags),
                _ => return Err(backend(response, &endpoint, "tags/list")),
            };
            let listing: serde_json::Value =
                serde_json::from_slice(&body).map_err(|error| RegistryError::Backend {
                    message: format!("the tag listing could not be read: {error}"),
                })?;
            tags.extend(
                listing
                    .get("tags")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|tag| tag.as_str().map(str::to_string)),
            );
            match next {
                Some(next) => url = format!("{}{next}", endpoint.base),
                None => return Ok(tags),
            }
        }
        Err(RegistryError::Backend {
            message: format!(
                "{} paginated its tag listing past {TAG_PAGES} pages without ending",
                endpoint.host
            ),
        })
    }
}

/// How many pages of `tags/list` [`OciDistribution::tags`] will follow before
/// calling it a registry that will not stop.
const TAG_PAGES: usize = 32;

/// The URL of the next page of a paginated listing: the `Link` header's
/// `<...>; rel="next"`. A `Link` that names no next page, or one naming a
/// different repository than the walk started on, ends the walk — following
/// either would answer a different question with someone else's answer.
fn next_page(response: &HttpResponse, path: &str) -> Option<String> {
    // The header is a comma-separated list of `<url>; rel="..."` entries.
    // Entries are found by their `<` rather than split on commas, because a
    // URL's own query string may carry commas that are not separators.
    let link = header(response, "link")?;
    link.split(", <")
        .filter_map(|entry| entry.strip_prefix('<')?.split_once('>'))
        .find(|(_, after)| after.contains("rel=\"next\""))
        .map(|(target, _)| target)
        .filter(|target| target.starts_with(path))
        .map(str::to_string)
}

impl Registry for OciDistribution {
    fn resolve<'a>(&'a self, image: &'a ImageRef) -> BoxFuture<'a, Result<Digest, RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(image.repository())?;
            let reference = match image.reference() {
                Reference::Tag(tag) => tag.clone(),
                Reference::Digest(digest) => digest.to_string(),
            };
            let url = format!("{}/v2/{}/manifests/{reference}", endpoint.base, endpoint.name);
            let head = self.request(Self::manifest_request(HttpMethod::Head, &url)).await?;
            // A HEAD that answered 200 but named no digest leaves nothing to
            // hash — its body is empty by definition — so the manifest is
            // fetched instead. Not every registry implements HEAD on
            // manifests either, and there a GET is the same lookup.
            let response = if head.status == 200 && header(&head, "docker-content-digest").is_some()
            {
                head
            } else {
                self.request(Self::manifest_request(HttpMethod::Get, &url)).await?
            };
            Self::ok(response, &endpoint, &reference)
                .and_then(|response| Self::reported_digest(&response))
        })
    }

    fn push_layout<'a>(
        &'a self,
        repository: &'a str,
        layout: &'a OciLayoutContents,
    ) -> BoxFuture<'a, Result<Descriptor, RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(repository)?;
            for blob in &layout.blobs {
                self.upload_blob(&endpoint, blob).await?;
            }
            let digest = sha256_digest(&layout.manifest);
            let reference = digest.to_string();
            self.put_manifest(&endpoint, &reference, &layout.media_type, &layout.manifest)
                .await
                .map(|(descriptor, _)| descriptor)
        })
    }

    fn push_artifact<'a>(
        &'a self,
        repository: &'a str,
        upload: &'a ArtifactUpload,
    ) -> BoxFuture<'a, Result<Descriptor, RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(repository)?;
            // The conventional empty config the artifact manifest points at.
            self.upload_blob(&endpoint, EMPTY_CONFIG_BYTES).await?;
            for blob in &upload.blobs {
                self.upload_blob(&endpoint, blob).await?;
            }
            let manifest = self.artifact_manifest(&endpoint, upload).await?;
            let digest = sha256_digest(&manifest);
            let reference = digest.to_string();
            let (stored, response) =
                self.put_manifest(&endpoint, &reference, &upload.media_type, &manifest).await?;
            // The descriptor of an artifact describes the artifact, so it
            // carries the annotations that were uploaded with it — the same
            // descriptor the registry will later list under `referrers`.
            let descriptor = Descriptor {
                media_type: stored.media_type,
                digest: stored.digest,
                size: stored.size,
                annotations: upload.annotations.clone(),
            };
            match &upload.subject {
                // `OCI-Subject` is how a registry says it indexed the
                // referrers itself. Without it the referrers API is not there,
                // and the tag fallback below is what makes the artifact
                // findable.
                None => {}
                Some(_) if header(&response, "oci-subject").is_some() => {}
                Some(subject) => {
                    self.maintain_fallback_index(&endpoint, subject, &descriptor).await?
                }
            }
            Ok(descriptor)
        })
    }

    fn pull<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<Vec<u8>, RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(repository)?;
            let reference = digest.to_string();
            let manifest = self
                .request(Self::manifest_request(
                    HttpMethod::Get,
                    &format!("{}/v2/{}/manifests/{reference}", endpoint.base, endpoint.name),
                ))
                .await?;
            let bytes = if manifest.status == 404 {
                // Not a manifest: a blob is the other thing a digest can name.
                let blob = self
                    .request(HttpRequest::new(
                        HttpMethod::Get,
                        format!("{}/v2/{}/blobs/{reference}", endpoint.base, endpoint.name),
                    ))
                    .await?;
                Self::ok(blob, &endpoint, &reference)?.body
            } else {
                Self::ok(manifest, &endpoint, &reference)?.body
            };
            verify(digest, &bytes)?;
            Ok(bytes)
        })
    }

    fn referrers<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<Vec<Descriptor>, RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(repository)?;
            let response = self
                .referrers_at(
                    &format!("{}/v2/{}/referrers/{digest}", endpoint.base, endpoint.name),
                    OCI_INDEX,
                )
                .await?;
            let bytes = match response.status {
                200..=299 => response.body,
                // No referrers API (distribution 2.x, for one): the tag
                // fallback the OCI distribution spec prescribes.
                404 => {
                    let tag = format!("sha256-{}", digest.hex());
                    let fallback = self
                        .referrers_at(
                            &format!("{}/v2/{}/manifests/{tag}", endpoint.base, endpoint.name),
                            OCI_INDEX,
                        )
                        .await?;
                    if fallback.status == 404 {
                        return Ok(Vec::new());
                    }
                    Self::ok(fallback, &endpoint, &tag)?.body
                }
                _ => return Err(backend(response, &endpoint, &digest.to_string())),
            };
            descriptors_of(&bytes)
        })
    }

    fn exists<'a>(
        &'a self,
        repository: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<bool, RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(repository)?;
            let reference = digest.to_string();
            let blob = self
                .request(HttpRequest::new(
                    HttpMethod::Head,
                    format!("{}/v2/{}/blobs/{reference}", endpoint.base, endpoint.name),
                ))
                .await?;
            let response = match blob.status {
                200..=299 => return Ok(true),
                404 => {
                    self.request(Self::manifest_request(
                        HttpMethod::Head,
                        &format!("{}/v2/{}/manifests/{reference}", endpoint.base, endpoint.name),
                    ))
                    .await?
                }
                _ => return Err(backend(blob, &endpoint, &reference)),
            };
            match response.status {
                200..=299 => Ok(true),
                404 => Ok(false),
                _ => Err(backend(response, &endpoint, &reference)),
            }
        })
    }

    fn tag<'a>(
        &'a self,
        repository: &'a str,
        tag: &'a str,
        digest: &'a Digest,
    ) -> BoxFuture<'a, Result<(), RegistryError>> {
        Box::pin(async move {
            let endpoint = self.endpoint(repository)?;
            let response = self
                .request(Self::manifest_request(
                    HttpMethod::Get,
                    &format!("{}/v2/{}/manifests/{digest}", endpoint.base, endpoint.name),
                ))
                .await?;
            let response = Self::ok(response, &endpoint, &digest.to_string())?;
            // Re-pushing a manifest under a tag publishes those exact bytes,
            // so they are checked against the digest they were fetched under
            // first: a retag must not launder what the registry served.
            verify(digest, &response.body)?;
            // The bytes are re-pushed verbatim; the media type comes from what
            // the registry served them as, so a retag cannot re-interpret them.
            let media_type = header(&response, "content-type")
                .map(|value| value.split(';').next().unwrap_or(value).trim().to_string())
                .unwrap_or_else(|| OCI_MANIFEST.to_string());
            self.put_manifest(&endpoint, tag, &media_type, &response.body).await?;
            Ok(())
        })
    }
}

impl OciDistribution {
    /// Uploads one blob, unless the repository already has it.
    async fn upload_blob(&self, endpoint: &Endpoint, blob: &[u8]) -> Result<(), RegistryError> {
        let digest = sha256_digest(blob);
        let reference = digest.to_string();
        let head = self
            .request(HttpRequest::new(
                HttpMethod::Head,
                format!("{}/v2/{}/blobs/{reference}", endpoint.base, endpoint.name),
            ))
            .await?;
        if head.status == 200 {
            return Ok(());
        }
        if head.status != 404 {
            return Err(backend(head, endpoint, &reference));
        }
        let upload_url = format!("{}/v2/{}/blobs/uploads/", endpoint.base, endpoint.name);
        let started = self.request(HttpRequest::new(HttpMethod::Post, &upload_url)).await?;
        if started.status != 202 && started.status != 201 {
            return Err(backend(started, endpoint, &reference));
        }
        let location = header(&started, "location").ok_or_else(|| RegistryError::Backend {
            message: "the registry accepted a blob upload without saying where to send it"
                .to_string(),
        })?;
        let url = absolute(&upload_url, location);
        let finished = if blob.len() > CHUNK_THRESHOLD {
            self.chunked_upload(&url, blob, endpoint, &reference).await?
        } else {
            let mut req = HttpRequest::new(HttpMethod::Put, with_digest(&url, &reference));
            req.headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
            req.body = blob.to_vec();
            self.request(req).await?
        };
        let response = Self::ok(finished, endpoint, &reference)?;
        let stored = Self::reported_digest(&response)?;
        if stored != digest {
            return Err(RegistryError::DigestMismatch { expected: digest, actual: stored });
        }
        Ok(())
    }

    /// Streams a large blob as a sequence of `PATCH`es, then commits it.
    async fn chunked_upload(
        &self,
        url: &str,
        blob: &[u8],
        endpoint: &Endpoint,
        reference: &str,
    ) -> Result<HttpResponse, RegistryError> {
        let mut location = url.to_string();
        for (index, chunk) in blob.chunks(CHUNK_THRESHOLD).enumerate() {
            let start = index * CHUNK_THRESHOLD;
            let mut req = HttpRequest::new(HttpMethod::Patch, location.clone());
            req.headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
            req.headers.push((
                "Content-Range".to_string(),
                format!("{start}-{}", start + chunk.len() - 1),
            ));
            req.body = chunk.to_vec();
            let response = self.request(req).await?;
            if response.status != 202 {
                return Err(backend(response, endpoint, reference));
            }
            if let Some(next) = header(&response, "location") {
                location = absolute(&location, next);
            }
        }
        let mut req = HttpRequest::new(HttpMethod::Put, with_digest(&location, reference));
        req.headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
        self.request(req).await
    }

    /// Puts a manifest and returns what the registry stored it as: the
    /// descriptor (with the digest the *registry* reported, checked against the
    /// bytes sent) and the response, because the `OCI-Subject` header decides
    /// whether the referrers fallback is needed.
    async fn put_manifest(
        &self,
        endpoint: &Endpoint,
        reference: &str,
        media_type: &str,
        manifest: &[u8],
    ) -> Result<(Descriptor, HttpResponse), RegistryError> {
        let mut req = HttpRequest::new(
            HttpMethod::Put,
            format!("{}/v2/{}/manifests/{reference}", endpoint.base, endpoint.name),
        );
        req.headers.push(("Content-Type".to_string(), media_type.to_string()));
        req.body = manifest.to_vec();
        let response = Self::ok(self.request(req).await?, endpoint, reference)?;
        let expected = sha256_digest(manifest);
        let stored = Self::reported_digest(&response)?;
        if stored != expected {
            return Err(RegistryError::DigestMismatch { expected, actual: stored });
        }
        let descriptor = Descriptor {
            media_type: header(&response, "content-type")
                .map(|value| value.split(';').next().unwrap_or(value).trim().to_string())
                .unwrap_or_else(|| media_type.to_string()),
            digest: stored,
            size: manifest.len() as u64,
            annotations: BTreeMap::new(),
        };
        Ok((descriptor, response))
    }

    /// The manifest an [`ArtifactUpload`] becomes: schemaVersion 2, the empty
    /// config, one layer per blob, the `subject` link and the annotations.
    /// `artifactType` is what makes it an artifact rather than an image.
    async fn artifact_manifest(
        &self,
        endpoint: &Endpoint,
        upload: &ArtifactUpload,
    ) -> Result<Vec<u8>, RegistryError> {
        let layers: Vec<serde_json::Value> = upload
            .blobs
            .iter()
            .map(|blob| {
                serde_json::json!({
                    "mediaType": OCI_LAYER,
                    "digest": sha256_digest(blob).to_string(),
                    "size": blob.len(),
                })
            })
            .collect();
        let mut manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": upload.media_type,
            "artifactType": upload.artifact_type,
            "config": {
                "mediaType": EMPTY_CONFIG,
                "digest": sha256_digest(EMPTY_CONFIG_BYTES).to_string(),
                "size": EMPTY_CONFIG_BYTES.len(),
            },
            "layers": layers,
            "annotations": upload.annotations,
        });
        if let Some(subject) = &upload.subject {
            let size = self.subject_size(endpoint, subject).await.unwrap_or(0);
            manifest["subject"] = serde_json::json!({
                "mediaType": OCI_MANIFEST,
                "digest": subject.to_string(),
                "size": size,
            });
        }
        serde_json::to_vec(&manifest).map_err(|error| RegistryError::Backend {
            message: format!("the artifact manifest would not serialize: {error}"),
        })
    }

    /// How big the subject is, so the `subject` descriptor in the manifest is a
    /// real descriptor. A subject this repository does not have is not fatal:
    /// the push reports what the registry says about the manifest.
    async fn subject_size(&self, endpoint: &Endpoint, subject: &Digest) -> Option<u64> {
        let response = self
            .request(Self::manifest_request(
                HttpMethod::Head,
                &format!("{}/v2/{}/manifests/{subject}", endpoint.base, endpoint.name),
            ))
            .await
            .ok()?;
        match response.status {
            200..=299 => header(&response, "content-length")?.parse().ok(),
            _ => None,
        }
    }

    /// The referrers tag fallback: an image index tagged `sha256-<hex>` of the
    /// subject, listing every artifact pushed for it. Registries without the
    /// referrers API serve this instead.
    ///
    /// The index is read, one entry added and written back — not atomic across
    /// concurrent pushers, so two pushes for the same subject racing can lose
    /// an entry. An existing index that cannot be read is an error rather than
    /// an empty list: overwriting it would delete the referrers in it.
    async fn maintain_fallback_index(
        &self,
        endpoint: &Endpoint,
        subject: &Digest,
        descriptor: &Descriptor,
    ) -> Result<(), RegistryError> {
        let tag = format!("sha256-{}", subject.hex());
        let url = format!("{}/v2/{}/manifests/{tag}", endpoint.base, endpoint.name);
        let existing = self.referrers_at(&url, OCI_INDEX).await?;
        let mut manifests: Vec<serde_json::Value> = match existing.status {
            200 => index_manifests(&existing.body, &tag)?,
            404 => Vec::new(),
            _ => return Err(backend(existing, endpoint, &tag)),
        };
        let entry = serde_json::json!({
            "mediaType": descriptor.media_type,
            "digest": descriptor.digest.to_string(),
            "size": descriptor.size,
            "annotations": descriptor.annotations,
        });
        // Re-pushing the same artifact (a rerun) must not double the list.
        manifests.retain(|existing| existing.get("digest") != entry.get("digest"));
        manifests.push(entry);
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": manifests,
        });
        let bytes = serde_json::to_vec(&index).map_err(|error| RegistryError::Backend {
            message: format!("the referrers index would not serialize: {error}"),
        })?;
        self.put_manifest(endpoint, &tag, OCI_INDEX, &bytes).await?;
        Ok(())
    }
}

/// The conventional empty config blob, `{}`.
const EMPTY_CONFIG_BYTES: &[u8] = b"{}";

/// SHA-256 of `bytes`, as a [`Digest`].
fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::sha256_from_hex(&hex(&Sha256::digest(bytes)))
        .expect("sha256 hex is 64 lowercase digits")
}

/// Confirms that `bytes` are the content `expected` names, which is the whole
/// point of addressing a registry by digest.
fn verify(expected: &Digest, bytes: &[u8]) -> Result<(), RegistryError> {
    let actual = sha256_digest(bytes);
    if actual == *expected {
        return Ok(());
    }
    // A sha512 reference cannot have come from a sha256 pull, so it is
    // reported as the mismatch it is rather than silently accepted.
    Err(RegistryError::DigestMismatch { expected: expected.clone(), actual })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The `manifests` entries of an image index, or [`RegistryError::Backend`]
/// when the bytes are not an index we can read — an index that cannot be read
/// is not an index with nothing in it.
fn index_manifests(bytes: &[u8], reference: &str) -> Result<Vec<serde_json::Value>, RegistryError> {
    let index: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| RegistryError::Backend {
            message: format!("the index {reference} is there but could not be read: {error}"),
        })?;
    let manifests = index.get("manifests").ok_or_else(|| RegistryError::Backend {
        message: format!("the index {reference} is there but has no `manifests` to add to"),
    })?;
    serde_json::from_value::<Vec<serde_json::Value>>(manifests.clone()).map_err(|error| {
        RegistryError::Backend {
            message: format!("the index {reference} has unreadable `manifests`: {error}"),
        }
    })
}

/// The descriptors in an image index (or a referrers response), which is the
/// one place either can come from.
fn descriptors_of(bytes: &[u8]) -> Result<Vec<Descriptor>, RegistryError> {
    let index: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| RegistryError::Backend {
            message: format!("the registry returned an unreadable index: {error}"),
        })?;
    let manifests =
        index.get("manifests").and_then(serde_json::Value::as_array).cloned().unwrap_or_default();
    let mut out = Vec::with_capacity(manifests.len());
    for entry in manifests {
        let digest = entry
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .and_then(|text| Digest::parse(text).ok());
        let Some(digest) = digest else { continue };
        out.push(Descriptor {
            media_type: entry
                .get("mediaType")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(OCI_MANIFEST)
                .to_string(),
            digest,
            size: entry.get("size").and_then(serde_json::Value::as_u64).unwrap_or(0),
            annotations: entry
                .get("annotations")
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

/// A response header, case-insensitively — a registry's spelling of
/// `Docker-Content-Digest` is not the contract, its presence is.
fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn has_header(req: &HttpRequest, name: &str) -> bool {
    req.headers.iter().any(|(field, _)| field.eq_ignore_ascii_case(name))
}

/// A 401 or 403 is the registry refusing us, which the port calls
/// unauthorized rather than a backend failure.
fn deny_unauthorized(response: HttpResponse, host: &str) -> Result<HttpResponse, RegistryError> {
    if response.status == 401 || response.status == 403 {
        return Err(RegistryError::Unauthorized { repository: host.to_string() });
    }
    Ok(response)
}

/// Anything else that is not a 2xx, with what the registry said about it.
fn backend(response: HttpResponse, endpoint: &Endpoint, reference: &str) -> RegistryError {
    let detail = String::from_utf8_lossy(&response.body);
    let detail: String = detail.chars().take(200).collect();
    RegistryError::Backend {
        message: format!(
            "{} answered {} for {reference}: {}",
            endpoint.host,
            response.status,
            detail.trim()
        ),
    }
}

/// The host of an absolute URL, for token caches and error messages.
fn url_host(url: &str) -> &str {
    url.split_once("://").map(|(_, rest)| rest).unwrap_or(url).split('/').next().unwrap_or(url)
}

/// Resolves an upload `Location` against the URL of the request that returned
/// it — not the registry base, which an upload URL may not hang off directly.
/// The `Location` may be absolute, root-relative (`/v2/…`) or relative to the
/// directory of the request, and may already carry a query string.
fn absolute(current: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    let (scheme, rest) = match current.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), current),
    };
    let authority = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (origin, path) = (&rest[..authority], &rest[authority..]);
    if location.starts_with('/') {
        return format!("{scheme}{origin}{location}");
    }
    // Everything up to the last `/` before the query is the request's
    // directory; a relative `Location` hangs off that.
    let directory = match path.split(['?', '#']).next().unwrap_or(path).rfind('/') {
        Some(at) => &path[..=at],
        None => "/",
    };
    format!("{scheme}{origin}{directory}{location}")
}

/// Adds `digest=` to an upload URL without losing the query the registry put
/// there (distribution's `_state`, notably). The digest is percent-encoded
/// like every other value this adapter puts in a query string.
fn with_digest(url: &str, digest: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}digest={}", auth::percent_encode(digest))
}
