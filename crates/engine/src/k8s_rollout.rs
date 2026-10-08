//! The `k8s.rollout` step kind: apply manifests with every image pinned by
//! digest, wait for the workloads to settle, and roll back when they do not
//! ([#73](https://github.com/Keep-Shipping/harness/issues/73)).
//!
//! Everything that can refuse the deploy refuses it before the cluster is
//! touched, because an input error after an `apply` could not be taken back: a
//! tag never reaches the cluster (every container image must be pinned, so an
//! unpinned sidecar fails rather than quietly running `nginx:latest`), and a
//! document naming a different `namespace` fails rather than being rewritten.
//! Waiting is the step's, not the port's: [`Cluster::apply`] returns once the
//! API server has *accepted* the manifests, so the step records each workload's
//! previous revision, applies, and polls [`Cluster::health`] until every
//! workload is [`Healthy`](ks_core::ports::health::Health::Healthy), one settles
//! [`Failed`](ks_core::ports::health::Health::Failed), or `wait` runs out.
//!
//! # What the port is handed
//!
//! Manifests are parsed — YAML or JSON, one file or many, multi-document — and
//! handed to [`Cluster::apply`] as serialized JSON, which `kubectl` accepts as
//! readily as YAML. Parsing is what makes the pinning exact: the images are
//! found at the pod spec's own locations rather than anywhere an `image:`
//! happens to appear, so a `ConfigMap` holding a config file that talks about
//! images is left exactly as its author wrote it.
//!
//! # Rollback goes through the port for every kind
//!
//! A `Deployment` returns to the revision its adapter recorded in
//! `revisionHistory`; a `StatefulSet` and a `DaemonSet` keep no such history, so
//! the *adapter* picks the mechanism for that kind — `rollout undo`, re-applying
//! a stored manifest, a delete-and-recreate. The step names a workload and the
//! revision it was on before this run, and never interprets the number. No
//! adapter ships yet; the one that does owns `--server-side --field-manager
//! keepshipping`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ks_core::ports::BoxFuture;
use ks_core::ports::cluster::{Cluster, ClusterError, Manifest, Revision};
use ks_core::ports::health::{Health, HealthReport};
use ks_core::ports::script_host::{Value, ValueType};
use ks_core::ports::supply_chain::ImageRef;
use ks_core::step::{
    ActionClass, ActionKind, Field, Inputs, LogLevel, Outputs, Port, StepCtx, StepError, StepKind,
    StepSchema, TypeRef, Version,
};
use serde::Deserialize;

/// How long between two health polls: fixed, so a slow cluster costs polls
/// rather than the step's judgement.
const POLL: Duration = Duration::from_secs(2);

/// The kinds whose rollout the step waits for. A `Service` or a `ConfigMap` is
/// applied and left alone: it has no rollout to settle.
const WORKLOADS: [&str; 3] = ["Deployment", "StatefulSet", "DaemonSet"];

/// The kinds that live outside a namespace. A `namespace:` is never written
/// into one: the API server would reject the manifest, and a document that
/// names its own namespace is saying something about the cluster, not a pod.
const CLUSTER_SCOPED: [&str; 12] = [
    "APIService",
    "ClusterRole",
    "ClusterRoleBinding",
    "CustomResourceDefinition",
    "IngressClass",
    "MutatingWebhookConfiguration",
    "Namespace",
    "Node",
    "PersistentVolume",
    "PriorityClass",
    "StorageClass",
    "ValidatingWebhookConfiguration",
];

/// Where each kind keeps its pod spec: the containers are only there.
const POD_SPECS: [(&str, &[&str]); 7] = [
    ("Deployment", &["spec", "template", "spec"]),
    ("StatefulSet", &["spec", "template", "spec"]),
    ("DaemonSet", &["spec", "template", "spec"]),
    ("ReplicaSet", &["spec", "template", "spec"]),
    ("Job", &["spec", "template", "spec"]),
    ("CronJob", &["spec", "jobTemplate", "spec", "template", "spec"]),
    ("Pod", &["spec"]),
];

/// The lists of containers a pod spec keeps, each container named.
const CONTAINER_LISTS: [&str; 3] = ["containers", "initContainers", "ephemeralContainers"];

/// The file extensions a manifests directory is read from.
const EXTENSIONS: [&str; 3] = ["yaml", "yml", "json"];

/// The default `wait`: the state every workload must reach, and how long.
const DEFAULT_WAIT: [&str; 2] = ["healthy", "5m"];

/// Rolls a set of manifests out to a cluster, and rolls back when they do not
/// settle.
#[derive(Debug, Default)]
pub struct K8sRollout;

impl StepKind for K8sRollout {
    fn name(&self) -> &'static str {
        "k8s.rollout"
    }

    fn version(&self) -> Version {
        Version::new(1, 0, 0)
    }

    /// `to` and `image` are plain strings, though the catalog types them as
    /// `k8s.Cluster` and `oci.Digest`: a nominal [`TypeRef`] must resolve in the
    /// harness (`ks_core::harness::Harness::build`), which knows neither name
    /// unless every composition declares a `type_def` for it — and its default
    /// must fit the type (`ks_core::catalog`), which the `""` that lets `image`
    /// and `images` stand in for each other does not.
    fn schema(&self) -> StepSchema {
        let text = TypeRef::Builtin(ValueType::String);
        StepSchema {
            doc: "Applies manifests to a cluster with every image pinned by digest, and waits for \
                  the workloads to become healthy.",
            inputs: vec![
                Field::new("to", text, "the cluster to deploy to: the environment's name"),
                Field::new("manifests", TypeRef::Named("path"), "a manifest file or a directory"),
                Field::new(
                    "image",
                    text,
                    "one `repository@sha256:…` for every container running that repository",
                )
                .with_default(Value::from("")),
                Field::new(
                    "images",
                    TypeRef::Builtin(ValueType::Map),
                    "digest-pinned images by container name, for a manifest with several images",
                )
                .with_default(Value::Map(BTreeMap::new())),
                Field::new("namespace", text, "the namespace to deploy into")
                    .with_default(Value::from("")),
                Field::new(
                    "wait",
                    TypeRef::Builtin(ValueType::List),
                    "the state to wait for and how long, as `healthy, 5m`",
                )
                .with_default(Value::List(DEFAULT_WAIT.iter().map(|p| Value::from(*p)).collect())),
                Field::new(
                    "rollback",
                    text,
                    "`auto` to roll back a rollout that does not settle, `none` to leave it",
                )
                .with_default(Value::from("auto")),
            ],
            outputs: vec![],
        }
    }

    /// The cluster port carries its own target, so a step never picks one: `to`
    /// says which environment the run meant, not which API server to call.
    fn requires(&self) -> &'static [Port] {
        &[Port::Cluster]
    }

    /// A deploy, in the environment the run named: `deploy prod` reads
    /// differently from `deploy dev` to whoever approves it.
    fn action(&self, inputs: &Inputs) -> ActionClass {
        let action = ActionClass::new(ActionKind::Deploy);
        match text(inputs, "to") {
            "" => action,
            to => action.in_env(to),
        }
    }

    fn run(&self, ctx: StepCtx, inputs: Inputs) -> BoxFuture<'_, Result<Outputs, StepError>> {
        Box::pin(async move {
            let Some(cluster) = ctx.ports().cluster() else {
                return Err(StepError::Port {
                    port: Port::Cluster,
                    message: "no cluster was provided".to_string(),
                });
            };
            let mut prepared = prepare(&inputs)?;
            // What each workload was on before this run. A workload the cluster
            // has never heard of has no previous revision: a first deploy, with
            // nothing to roll back to.
            let mut previous = Vec::with_capacity(prepared.workloads.len());
            for name in &prepared.workloads {
                previous.push(match cluster.rollout(name).await {
                    Ok(rollout) => Some(rollout.revision()),
                    Err(ClusterError::NotFound { .. }) => None,
                    Err(error) => return Err(port(&format!("reading {name} failed"), error)),
                });
            }

            // An apply that fails part way has still changed something, and the
            // previous revisions are already in hand: put them back before the
            // failure is reported, and say in the message that it was done.
            let applied = match cluster.apply(&prepared.manifests).await {
                Ok(applied) => applied,
                Err(error) => {
                    let rolled = roll_back(&ctx, cluster.as_ref(), &prepared, &previous).await;
                    return Err(port(&format!("applying the manifests failed, {rolled}"), error));
                }
            };
            ctx.log().info(
                &format!("applied {} manifests", applied.len()),
                &[
                    ("applied", &applied.join(", ")),
                    ("images", &prepared.images.join(", ")),
                    ("to", text(&inputs, "to")),
                ],
            );

            let reason = match wait_for(&ctx, cluster.as_ref(), &mut prepared).await? {
                None => return Ok(healthy(&ctx, &prepared)),
                Some(reason) => reason,
            };
            let rolled = roll_back(&ctx, cluster.as_ref(), &prepared, &previous).await;
            Err(StepError::Failed(format!("{reason}; {rolled}")))
        })
    }
}

/// The run that settled: one line per workload, with the adapter's own reason.
fn healthy(ctx: &StepCtx, prepared: &Prepared) -> Outputs {
    for (name, report) in &prepared.reports {
        ctx.log().info(&format!("{name} is healthy: {}", reason_of(report)), &[("workload", name)]);
    }
    Outputs::new()
}

/// Everything a run needs, resolved before the cluster is touched.
struct Prepared {
    manifests: Vec<Manifest>,
    /// The workload manifests, in apply order, by name.
    workloads: Vec<String>,
    /// The digest references that were pinned, for the log.
    images: Vec<String>,
    /// How long to wait, and the text it was written as, so a failure reads in
    /// the author's words rather than in seconds.
    wait: (Duration, String),
    rollback: bool,
    /// The last report seen for each workload, filled in by the wait.
    reports: Vec<(String, HealthReport)>,
}

/// The digest references this run pins: one image for every container running
/// that repository, or one per container name. Never both — two ways to say
/// which image goes where is one way too many.
struct Pins {
    /// The repository every matching container is moved to, and the pinned
    /// reference it is moved to.
    all: Option<(String, String)>,
    /// Pinned references by container name, and the names a pin has landed on,
    /// so a name no container answers to is an error rather than a no-op.
    by_name: BTreeMap<String, String>,
    used: BTreeSet<String>,
}

impl Pins {
    /// The pinned reference for this container's image, if one covers it.
    fn take(&mut self, container: Option<&str>, image: &ImageRef) -> Option<String> {
        if let Some((repository, reference)) = &self.all
            && image.repository() == *repository
        {
            return Some(reference.clone());
        }
        let name = container?;
        let reference = self.by_name.get(name)?.clone();
        self.used.insert(name.to_string());
        Some(reference)
    }

    /// The names no container answered to.
    fn unused(&self) -> Vec<&str> {
        self.by_name.keys().filter(|name| !self.used.contains(*name)).map(String::as_str).collect()
    }
}

/// Resolves every input into manifests no cluster has seen, or refuses.
fn prepare(inputs: &Inputs) -> Result<Prepared, StepError> {
    let mut pins = pins(inputs)?;
    let namespace = text(inputs, "namespace");
    let wanted = (!namespace.is_empty()).then_some(namespace);
    let mut manifests = Vec::new();
    let mut workloads = Vec::new();
    let mut images = BTreeSet::new();
    for (path, text) in read_manifests(Path::new(text(inputs, "manifests")))? {
        let source = path.display().to_string();
        for (at, document) in documents(&text, &source)? {
            let mut document = document;
            let Some(kind) = document["kind"].as_str().map(str::to_string) else {
                return Err(invalid("manifests", format!("{source} document {at} has no `kind`")));
            };
            let Some(object) = named(&document) else {
                return Err(invalid(
                    "manifests",
                    format!("{source} document {at} has no `metadata.name`"),
                ));
            };
            let name = format!("{kind}/{object}");
            namespace_into(&mut document, &kind, wanted, &name)?;
            pin(&mut document, &kind, &name, &mut pins, &mut images)?;
            if WORKLOADS.contains(&kind.as_str()) {
                workloads.push(name.clone());
            }
            let contents = serde_json::to_vec(&document).map_err(|error| {
                invalid("manifests", format!("{name} cannot be serialized: {error}"))
            })?;
            let manifest = Manifest::new(name, contents).map_err(|error| {
                invalid("manifests", format!("a document in {source} is not a manifest: {error}"))
            })?;
            manifests.push(manifest);
        }
    }
    let unused = pins.unused();
    if !unused.is_empty() {
        let reason = format!("no container is named {}", unused.join(", "));
        return Err(invalid("images", reason));
    }
    let rollback = match text(inputs, "rollback") {
        "auto" => true,
        "none" => false,
        other => return Err(invalid("rollback", format!("`{other}` is not `auto` or `none`"))),
    };
    Ok(Prepared {
        manifests,
        workloads,
        images: images.into_iter().collect(),
        wait: wait(inputs)?,
        rollback,
        reports: Vec::new(),
    })
}

/// One document's `metadata.name`, when it has one.
fn named(document: &serde_json::Value) -> Option<String> {
    document["metadata"]["name"].as_str().map(str::to_string)
}

/// Puts the namespace the run named into a namespaced document's metadata,
/// refusing a document that already says otherwise.
fn namespace_into(
    document: &mut serde_json::Value,
    kind: &str,
    wanted: Option<&str>,
    name: &str,
) -> Result<(), StepError> {
    let Some(wanted) = wanted.filter(|_| !CLUSTER_SCOPED.contains(&kind)) else { return Ok(()) };
    match document["metadata"]["namespace"].as_str() {
        Some(found) if found != wanted => {
            Err(invalid("namespace", format!("{name} is in {found:?}, not {wanted:?}")))
        }
        Some(_) => Ok(()),
        None => {
            let metadata = document["metadata"].as_object_mut().ok_or_else(|| {
                invalid("manifests", format!("{name} has no `metadata` to name a namespace in"))
            })?;
            metadata.insert("namespace".to_string(), serde_json::Value::from(wanted));
            Ok(())
        }
    }
}

/// Pins every image in the kind's pod spec to a digest, or refuses. A container
/// the pins do not cover is the refusal: it still carries its tag, and a tag is
/// what this step exists to keep off the cluster.
fn pin(
    document: &mut serde_json::Value,
    kind: &str,
    name: &str,
    pins: &mut Pins,
    images: &mut BTreeSet<String>,
) -> Result<(), StepError> {
    let Some(path) = POD_SPECS.iter().find(|(k, _)| *k == kind).map(|(_, path)| *path) else {
        return Ok(());
    };
    // No pod spec means no containers: a Job's `spec` without a template, or a
    // custom kind this step does not know, is left as its author wrote it.
    let Some(pod_spec) = at_path_mut(document, path) else { return Ok(()) };
    for list in CONTAINER_LISTS {
        let Some(serde_json::Value::Array(containers)) = pod_spec.get_mut(list) else { continue };
        for container in containers.iter_mut() {
            let image = match container.get("image") {
                None | Some(serde_json::Value::Null) => continue,
                Some(serde_json::Value::String(image)) => image.clone(),
                Some(other) => {
                    return Err(invalid("image", format!("{name} has a {} image", other)));
                }
            };
            let reference = pinned(name, container["name"].as_str(), &image, pins)?;
            images.insert(reference.clone());
            container["image"] = serde_json::Value::from(reference);
        }
    }
    Ok(())
}

/// The pinned reference for one container's image, or the refusal: an image
/// reference the step cannot read, or one no pin covers.
fn pinned(
    name: &str,
    container: Option<&str>,
    image: &str,
    pins: &mut Pins,
) -> Result<String, StepError> {
    let reference = ImageRef::parse(image).map_err(|error| {
        invalid("image", format!("{name} runs {image:?}, which is not a reference: {error}"))
    })?;
    pins.take(container, &reference)
        .ok_or_else(|| invalid("image", format!("{name} runs {reference}, not pinned by digest")))
}

/// The value at `path`, when every step of it is an object.
fn at_path_mut<'a>(
    document: &'a mut serde_json::Value,
    path: &[&str],
) -> Option<&'a mut serde_json::Value> {
    let mut value = document;
    for key in path {
        value = value.get_mut(key)?;
    }
    Some(value)
}

/// Reads the digest references `image` / `images` name, refusing a tag.
fn pins(inputs: &Inputs) -> Result<Pins, StepError> {
    let one = text(inputs, "image");
    let named = match inputs.get("images") {
        Some(Value::Map(entries)) if !entries.is_empty() => Some(entries),
        _ => None,
    };
    match (one.is_empty(), named.is_some()) {
        (true, false) => {
            return Err(invalid("image", "pin what you deploy: `image` or `images`"));
        }
        (true, true) | (false, false) => {}
        (false, true) => {
            return Err(invalid("image", "pin one repository with `image`, or each by `images`"));
        }
    }
    let mut pins = Pins { all: None, by_name: BTreeMap::new(), used: BTreeSet::new() };
    if !one.is_empty() {
        let image = digest_ref("image", one)?;
        pins.all = Some((image.repository().to_string(), image.to_string()));
    }
    for (name, value) in named.into_iter().flatten() {
        let Value::String(reference) = value else {
            return Err(invalid("images", format!("`{name}` is a {}", value.value_type())));
        };
        pins.by_name.insert(name.clone(), digest_ref("images", reference)?.to_string());
    }
    Ok(pins)
}

/// A digest-pinned reference, or the refusal a tag earns: prod must run the
/// image this run built, and `:latest` is not that.
fn digest_ref(field: &'static str, text: &str) -> Result<ImageRef, StepError> {
    let parse = |error| invalid(field, format!("`{text}` is not an image reference: {error}"));
    let image = ImageRef::parse(text).map_err(parse)?;
    if image.digest().is_none() {
        return Err(invalid(field, format!("`{image}` is a tag; pin it as `repository@sha256:…`")));
    }
    Ok(image)
}

/// `wait` as a deadline, from `healthy, 5m` written as a list or a comma string.
fn wait(inputs: &Inputs) -> Result<(Duration, String), StepError> {
    let parts = match inputs.get("wait") {
        Some(Value::List(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => Err(invalid("wait", format!("`{other:?}` is not a state or a duration"))),
            })
            .collect::<Result<Vec<_>, StepError>>()?,
        Some(Value::String(text)) => text.split(',').map(str::trim).map(str::to_string).collect(),
        _ => Vec::new(),
    };
    let [state, timeout] = parts.as_slice() else {
        return Err(invalid(
            "wait",
            format!("`wait` is `{}`, not `healthy, 5m`", parts.join("`, `")),
        ));
    };
    if state != "healthy" {
        return Err(invalid("wait", format!("only `healthy` settles, not {state:?}")));
    }
    let at = timeout
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| invalid("wait", format!("`{timeout}` has no unit; write `30s` or `5m`")))?;
    let (digits, unit) = timeout.split_at(at);
    let bad = || invalid("wait", format!("`{timeout}` is not a duration"));
    let amount = digits.parse::<u64>().map_err(|_| bad())?;
    let duration = match unit {
        "ms" => Some(Duration::from_millis(amount)),
        "s" => Some(Duration::from_secs(amount)),
        "m" => amount.checked_mul(60).map(Duration::from_secs),
        "h" => amount.checked_mul(3_600).map(Duration::from_secs),
        other => return Err(invalid("wait", format!("`{other}` is not a unit: ms, s, m or h"))),
    };
    let too_long = || invalid("wait", format!("`{timeout}` is longer than this step can wait"));
    Ok((duration.ok_or_else(too_long)?, timeout.clone()))
}

/// Polls until every workload is healthy, one settles failed, or the deadline
/// passes. Returns the reason the wait ended badly, or `None` for a rollout
/// that settled.
async fn wait_for(
    ctx: &StepCtx,
    cluster: &dyn Cluster,
    prepared: &mut Prepared,
) -> Result<Option<String>, StepError> {
    let (deadline, wording) = prepared.wait.clone();
    // The deadline is wall clock, not nap time: a slow `health` call is time
    // this step spent, and must not be quietly slept off the clock.
    let start: SystemTime = ctx.clock().now();
    let elapsed = || ctx.clock().now().duration_since(start).unwrap_or(Duration::ZERO);
    loop {
        // A run cancelled while waiting leaves the rollout where it is: the
        // rollback is the failure path's, not a cancelled run's.
        if ctx.cancel().is_cancelled() {
            return Err(StepError::Cancelled);
        }
        let mut failed = None;
        let mut healthy = 0usize;
        prepared.reports.clear();
        for name in &prepared.workloads {
            let report = match cluster.health(name).await {
                Ok(report) => report,
                Err(error) => return Ok(Some(format!("{name} could not be observed: {error}"))),
            };
            if report.state() == Health::Failed {
                failed = Some(format!("{name} failed: {}", reason_of(&report)));
            }
            healthy += usize::from(report.satisfies(Health::Healthy));
            prepared.reports.push((name.clone(), report));
        }
        if let Some(failure) = failed {
            return Ok(Some(failure));
        }
        if healthy == prepared.workloads.len() {
            return Ok(None);
        }
        let waited = elapsed();
        if waited >= deadline {
            let waiting = prepared
                .reports
                .iter()
                .filter(|(_, report)| !report.satisfies(Health::Healthy))
                .map(|(name, report)| format!("{name}: {}", reason_of(report)))
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(Some(format!("did not become healthy within {wording}: {waiting}")));
        }
        let nap = POLL.min(deadline - waited);
        ctx.clock().sleep(nap).await;
    }
}

/// Moves every workload back to the revision this run found it on, and says in
/// one sentence what it did — including what it could not do, because a
/// rollback that failed is part of why the run failed.
async fn roll_back(
    ctx: &StepCtx,
    cluster: &dyn Cluster,
    prepared: &Prepared,
    previous: &[Option<Revision>],
) -> String {
    if !prepared.rollback {
        ctx.log().log(LogLevel::Warn, "rollback is disabled; the rollout is left in place", &[]);
        return "rollback is disabled, so the rollout was left in place".to_string();
    }
    let mut notes = Vec::new();
    for (name, revision) in prepared.workloads.iter().zip(previous) {
        let (note, level) = match revision {
            Some(revision) => match cluster.rollback(name, *revision).await {
                Ok(_) => (format!("rolled back {name} to revision {revision}"), LogLevel::Info),
                Err(error) => (
                    format!("{name} could not be rolled back to {revision}: {error}"),
                    LogLevel::Error,
                ),
            },
            None => (
                format!("{name} had no earlier revision, so there was nothing to roll back to"),
                LogLevel::Warn,
            ),
        };
        ctx.log().log(level, &note, &[("workload", name)]);
        notes.push(note);
    }
    notes.join("; ")
}

/// Why a report reads as it does: adapters carry the target's own wording, and
/// a report without one still says something.
fn reason_of(report: &HealthReport) -> &str {
    report.reason().unwrap_or("healthy")
}

/// A refused input, named.
fn invalid(field: &str, reason: impl Into<String>) -> StepError {
    StepError::InvalidInput { field: field.to_string(), reason: reason.into() }
}

/// A port failure, with the step's own words first.
fn port(context: &str, error: ClusterError) -> StepError {
    StepError::Port { port: Port::Cluster, message: format!("{context}: {error}") }
}

/// The `&str` input under `name`; inputs arrive prepared, so a wrong type never
/// reaches a step.
fn text<'a>(inputs: &'a Inputs, name: &str) -> &'a str {
    match inputs.get(name) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// The manifests `path` names: one file, or every `*.yaml`, `*.yml` and
/// `*.json` in a directory, non-recursively and in name order.
fn read_manifests(path: &Path) -> Result<Vec<(PathBuf, String)>, StepError> {
    let read = |file: &Path| {
        std::fs::read_to_string(file).map_err(|error| {
            invalid("manifests", format!("{} cannot be read: {error}", file.display()))
        })
    };
    if path.is_file() {
        return Ok(vec![(path.to_path_buf(), read(path)?)]);
    }
    let entries = std::fs::read_dir(path).map_err(|error| {
        invalid("manifests", format!("{} cannot be read: {error}", path.display()))
    })?;
    let extension = |file: &PathBuf| {
        file.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|f| f.is_file() && extension(f))
        .collect();
    files.sort();
    if files.is_empty() {
        let reason = format!("{} is not a manifest, nor a directory of them", path.display());
        return Err(invalid("manifests", reason));
    }
    files.into_iter().map(|file| Ok((file.clone(), read(&file)?))).collect()
}

/// A file's documents, in order, numbered from one, with the empty ones (a
/// trailing `---`, a comment-only file) skipped.
fn documents(text: &str, source: &str) -> Result<Vec<(usize, serde_json::Value)>, StepError> {
    let mut parsed = Vec::new();
    for (at, document) in serde_yaml_ng::Deserializer::from_str(text).enumerate() {
        let document = serde_json::Value::deserialize(document).map_err(|error| {
            invalid("manifests", format!("{source} document {} is not YAML: {error}", at + 1))
        })?;
        if !document.is_null() {
            parsed.push((at + 1, document));
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A digest for `repository`, shaped like the ones the registry hands out.
    fn digest(repository: &str) -> String {
        format!("{repository}@sha256:{}", "a".repeat(64))
    }

    /// The input pairs under test, as a step's inputs arrive them.
    fn inputs(pairs: &[(&str, Value)]) -> Inputs {
        pairs.iter().map(|(name, value)| (name.to_string(), value.clone())).collect()
    }

    /// One `image` pin, by repository.
    fn by_repo() -> Pins {
        Pins {
            all: Some(("ghcr.io/acme/api".to_string(), digest("ghcr.io/acme/api"))),
            by_name: BTreeMap::new(),
            used: BTreeSet::new(),
        }
    }

    /// The first document of a manifest, parsed the way a run parses it.
    fn document(text: &str) -> serde_json::Value {
        documents(text, "test.yaml").expect("it parses").pop().expect("one document").1
    }

    /// Every image under `path`, as `(container, image)` pairs.
    fn images_at(value: &serde_json::Value, path: &[&str]) -> Vec<(String, String)> {
        let mut value = value;
        for key in path {
            value = &value[key];
        }
        value["containers"]
            .as_array()
            .expect("containers")
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap_or_default().to_string(),
                    c["image"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }

    const POD_SPEC: [&str; 3] = ["spec", "template", "spec"];

    /// Flow-style containers are pinned like block-style ones, and a container
    /// whose `env` entries are also `- name:` is matched by its own name.
    #[test]
    fn flow_style_containers_are_pinned_by_their_own_name() {
        let manifest = "\
apiVersion: apps/v1
kind: Deployment
metadata: {name: api}
spec:
  template:
    spec:
      containers: [{name: api, image: 'ghcr.io/acme/api:latest', env: [{name: PORT, value: 80}]}]
";
        let mut document = document(manifest);
        let mut pins = Pins {
            all: None,
            by_name: BTreeMap::from([("api".to_string(), digest("ghcr.io/acme/api"))]),
            used: BTreeSet::new(),
        };
        let mut images = BTreeSet::new();
        pin(&mut document, "Deployment", "Deployment/api", &mut pins, &mut images).expect("pinned");

        let found = images_at(&document, &POD_SPEC);
        assert_eq!(found, vec![("api".to_string(), digest("ghcr.io/acme/api"))]);
        assert_eq!(document["spec"]["template"]["spec"]["containers"][0]["env"][0]["name"], "PORT");
    }

    /// A `ConfigMap` body that talks about images is data, not a deployment: it
    /// is left exactly as its author wrote it, namespace and all.
    #[test]
    fn a_block_scalar_full_of_image_lines_is_left_alone() {
        let manifest = "\
apiVersion: v1
kind: ConfigMap
metadata:
  name: runbook
data:
  deploy.md: |
    image: ghcr.io/acme/api:latest
    run it with kubectl
";
        let mut document = document(manifest);
        let mut pins = by_repo();
        let mut images = BTreeSet::new();
        pin(&mut document, "ConfigMap", "ConfigMap/runbook", &mut pins, &mut images)
            .expect("nothing to pin");
        assert_eq!(
            document["data"]["deploy.md"],
            "image: ghcr.io/acme/api:latest\nrun it with kubectl\n"
        );
        assert!(images.is_empty(), "a body that mentions an image is not an image");
    }

    /// An image reference the step cannot read is refused rather than skipped:
    /// skipping it would deploy the tag the author wrote.
    #[test]
    fn an_unreadable_image_is_refused() {
        let mut document = document(
            "kind: Pod\nmetadata:\n  name: api\nspec:\n  containers:\n    - name: api\n      image: \"ghcr.io/acme/api:\"\n",
        );
        let mut pins = by_repo();
        let refused = pin(&mut document, "Pod", "Pod/api", &mut pins, &mut BTreeSet::new());
        assert!(
            matches!(&refused, Err(StepError::InvalidInput { field, reason })
                if field == "image" && reason.contains("not a reference")),
            "{refused:?}"
        );
    }

    /// What the port is handed is the parsed document, serialized as JSON: the
    /// image pinned by digest, the namespace written in, and everything the
    /// author wrote around them still there.
    #[test]
    fn the_manifest_the_port_is_handed_is_json_with_the_image_pinned() {
        let at = std::env::temp_dir().join("ks-rollout-json");
        let _ = std::fs::remove_dir_all(&at);
        std::fs::create_dir_all(&at).expect("the scratch directory can be created");
        std::fs::write(
            at.join("deployment.yaml"),
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n        - name: api\n          image: ghcr.io/acme/api:latest\n",
        )
        .expect("the manifest can be written");
        let inputs = inputs(&[
            ("to", Value::from("prod")),
            ("manifests", Value::from(at.display().to_string())),
            ("image", Value::from(digest("ghcr.io/acme/api"))),
            ("namespace", Value::from("prod")),
            ("wait", Value::List(vec![Value::from("healthy"), Value::from("5m")])),
            ("rollback", Value::from("auto")),
        ]);
        let prepared = prepare(&inputs).expect("the manifest applies");
        let _ = std::fs::remove_dir_all(&at);

        assert_eq!(prepared.manifests[0].name(), "Deployment/api");
        let handed: serde_json::Value = serde_json::from_slice(prepared.manifests[0].contents())
            .expect("the port is handed json");
        assert_eq!(handed["spec"]["replicas"], 2);
        assert_eq!(handed["metadata"]["namespace"], "prod");
        assert_eq!(
            images_at(&handed, &POD_SPEC),
            vec![("api".to_string(), digest("ghcr.io/acme/api"))]
        );
    }

    /// A namespace is written into a namespaced document, never into a
    /// cluster-scoped one, and a document naming another namespace is refused.
    #[test]
    fn only_a_namespaced_document_is_given_the_namespace() {
        let mut deployment = document(
            "kind: Deployment\nmetadata:\n  name: api\nspec: {template: {spec: {containers: []}}}\n",
        );
        namespace_into(&mut deployment, "Deployment", Some("prod"), "Deployment/api")
            .expect("a Deployment is namespaced");
        assert_eq!(deployment["metadata"]["namespace"], "prod");

        let mut cluster = document("kind: Namespace\nmetadata:\n  name: prod\n");
        namespace_into(&mut cluster, "Namespace", Some("prod"), "Namespace/prod")
            .expect("a Namespace is not namespaced, so nothing is written");
        assert_eq!(cluster["metadata"], serde_json::json!({ "name": "prod" }));

        let mut staged =
            document("kind: Deployment\nmetadata:\n  name: api\n  namespace: staging\n");
        let refused = namespace_into(&mut staged, "Deployment", Some("prod"), "Deployment/api");
        assert!(
            matches!(refused, Err(StepError::InvalidInput { field, .. }) if field == "namespace")
        );
    }

    /// `wait` is `healthy, 5m` in a list or a comma string, and its units are
    /// `ms`, `s`, `m` and `h`.
    #[test]
    fn wait_is_a_state_and_a_duration() {
        let pair = |timeout: &str| {
            inputs(&[("wait", Value::List(vec![Value::from("healthy"), Value::from(timeout)]))])
        };
        assert_eq!(
            wait(&pair("90s")).expect("healthy, 90s"),
            (Duration::from_secs(90), "90s".to_string())
        );
        assert_eq!(wait(&pair("250ms")).expect("250ms").0, Duration::from_millis(250));
        assert_eq!(
            wait(&inputs(&[("wait", Value::from("healthy, 1h"))])).expect("comma form").0,
            Duration::from_secs(3_600)
        );
        let refused = |value| wait(&inputs(&[("wait", value)]));
        assert!(refused(Value::from("settled, 5m")).is_err());
        assert!(refused(Value::from("healthy, 5")).is_err());
    }
}
