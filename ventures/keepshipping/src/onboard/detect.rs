//! Stack detection for the "manage as code" wizard: from the files of an app
//! repository, say what the app is built with, what it needs from a
//! database, file storage or cache, which Cloudflare resource would cover
//! each need, and which setting names it reads. The wizard shows the result
//! in plain words before anything is created.
//!
//! This module is pure. Nothing here fetches a file or touches a port: the
//! caller lists the repository, asks [`pick`] which paths are worth reading,
//! fetches those, and passes the contents to [`detect`]. Environment values
//! are never kept. A connection string is read only for its scheme (which
//! database it points at) and then dropped, so no secret can reach a
//! [`Stack`]. Parsing is forgiving: a file that does not parse contributes
//! nothing rather than failing the scan.
//!
//! TOML (wrangler, Cargo, pyproject) goes through a small parser in this
//! module rather than a crate: the files the wizard reads use a small subset
//! of the format, and the parser produces the same `serde_json::Value` shape
//! as the JSON files, so one set of lookups serves both.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The most files one scan reads. The wizard fetches each file over the
/// GitHub API, so the cap bounds the work for a large monorepo.
pub const MAX_FILES: usize = 25;

/// The files worth fetching, as names or name shapes. [`wanted`] is the rule
/// itself; this list is the plain index of it.
pub const WANTED: &[&str] = &[
    "wrangler.toml",
    "wrangler.json",
    "wrangler.jsonc",
    "package.json",
    "prisma/schema.prisma",
    "*.prisma",
    "drizzle.config.ts",
    "drizzle.config.js",
    "drizzle.config.mjs",
    ".env.example",
    ".env.sample",
    ".dev.vars.example",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "next.config.*",
    "astro.config.*",
    "nuxt.config.*",
    "svelte.config.js",
    "vite.config.*",
];

/// Whether a repository path is one [`detect`] reads.
///
/// Paths under `node_modules`, `vendor`, `target` or `.git` never are. Each
/// kind of file is taken only as deep as it can matter: a wrangler config,
/// `package.json` or manifest up to two directories down (so `apps/web/…`
/// counts and `apps/web/src/lib/…` does not), framework configs only at the
/// root, and Prisma schemas anywhere.
#[must_use]
pub fn wanted(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let Some((name, dirs)) = parts.split_last() else {
        return false;
    };
    if dirs.iter().any(|d| matches!(*d, "node_modules" | "vendor" | "target" | ".git")) {
        return false;
    }
    let depth = dirs.len();
    if name.ends_with(".prisma") {
        return true;
    }
    if config_framework(name).is_some() {
        return depth == 0;
    }
    if is_drizzle(name) || is_env_example(name) || is_compose(name) {
        return depth <= 2;
    }
    matches!(
        *name,
        "wrangler.toml"
            | "wrangler.json"
            | "wrangler.jsonc"
            | "package.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "Cargo.toml"
            | "go.mod"
            | "Gemfile"
    ) && depth <= 2
}

/// Chooses which of the listed paths to fetch: the [`wanted`] ones, root
/// files first, capped at [`MAX_FILES`]. The order is stable, so the same
/// listing always picks the same files.
#[must_use]
pub fn pick(paths: &[String]) -> Vec<String> {
    let mut picked: Vec<&str> = paths.iter().map(String::as_str).filter(|p| wanted(p)).collect();
    picked.sort_by(|a, b| depth(a).cmp(&depth(b)).then_with(|| a.cmp(b)));
    picked.dedup();
    picked.into_iter().take(MAX_FILES).map(str::to_owned).collect()
}

/// Works out a [`Stack`] from the contents of the repository files, keyed by
/// repository path. Entries [`wanted`] rejects are ignored, so a caller that
/// passes a whole listing still gets a clean answer.
#[must_use]
pub fn detect(files: &BTreeMap<String, String>) -> Stack {
    let mut ordered: Vec<(&String, &String)> =
        files.iter().filter(|(path, _)| wanted(path)).collect();
    // Shallowest first, so the root wrangler config wins over a nested one.
    ordered.sort_by(|a, b| depth(a.0).cmp(&depth(b.0)).then_with(|| a.0.cmp(b.0)));
    let mut acc = Acc::default();
    for (path, text) in ordered {
        acc.read(path, text);
    }
    acc.finish()
}

/// What the wizard learned about one app repository. Every field is either
/// a name, a kind, or a plain-English note. No environment value ever lands
/// here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stack {
    /// The framework the app is built with, the most specific one found.
    pub framework: Option<Framework>,
    /// Where Cloudflare would run the app, from its wrangler config.
    pub runtime: Option<Runtime>,
    /// The Cloudflare name from the wrangler config, when there is one.
    pub worker_name: Option<String>,
    /// What the app needs that Cloudflare may have to provide.
    pub needs: BTreeSet<Need>,
    /// Setting names the app reads. Names only, never values.
    pub env_vars: BTreeSet<String>,
    /// Bindings the wrangler config already declares.
    pub existing_bindings: Vec<Binding>,
    /// Cron expressions from the wrangler config.
    pub cron: Vec<String>,
    /// Things the wizard cannot set up automatically, in plain words.
    pub notes: Vec<String>,
}

impl Stack {
    /// Plain-English lines for the wizard, one per finding, in the order the
    /// person reads them: what the app is, what it needs, what it already
    /// declares, and what cannot be automated.
    #[must_use]
    pub fn summary(&self) -> Vec<String> {
        let mut lines = vec![match (self.framework, self.runtime) {
            (Some(fw), Some(rt)) => {
                format!("Built with {}, deployed as {}", fw.label(), rt.label())
            }
            (Some(fw), None) => {
                format!("Built with {}, not set up for Cloudflare yet", fw.label())
            }
            (None, Some(rt)) => format!("Deployed as {}", rt.label()),
            (None, None) => "Could not tell what this app is built with".to_owned(),
        }];
        if let Some(name) = &self.worker_name {
            lines.push(format!("Cloudflare name: {name}"));
        }
        if self.needs.is_empty() {
            lines.push("No database, file storage or cache found".to_owned());
        }
        for need in &self.needs {
            lines.push(match need.cloudflare_answer() {
                Some(answer) => format!("Needs {} → we'll use {answer}", need.label()),
                None => format!("Needs {} → not set up automatically", need.label()),
            });
        }
        if !self.existing_bindings.is_empty() {
            let list: Vec<String> = self
                .existing_bindings
                .iter()
                .map(|b| format!("{} {}", b.kind.label(), b.name))
                .collect();
            lines.push(format!("Already declared in the config: {}", list.join(", ")));
        }
        if !self.env_vars.is_empty() {
            let names: Vec<&str> = self.env_vars.iter().map(String::as_str).collect();
            lines.push(format!("Settings the app reads: {}", names.join(", ")));
        }
        if !self.cron.is_empty() {
            lines.push(format!("Runs on a schedule: {}", self.cron.join(", ")));
        }
        lines.extend(self.notes.iter().cloned());
        lines
    }
}

/// A web or language framework the app is built with. The variants are in
/// precedence order: when two are found, the earlier one is the app's
/// framework (a Next app with a small Vite tool beside it is a Next app).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Framework {
    /// Next.js.
    Next,
    /// Nuxt.
    Nuxt,
    /// Astro.
    Astro,
    /// SvelteKit.
    SvelteKit,
    /// Remix.
    Remix,
    /// Hono, a small web framework that runs on Workers.
    Hono,
    /// Ruby on Rails.
    Rails,
    /// A Rust program built for a Cloudflare Worker.
    RustWorker,
    /// Plain Vite (a frontend build tool).
    Vite,
    /// A Python project (FastAPI, Flask, Django or similar).
    Python,
    /// A Go module.
    Go,
    /// Static HTML served from a Pages build output.
    Static,
}

impl Framework {
    /// The framework's name, in the words a person would use.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Next => "Next.js",
            Self::Nuxt => "Nuxt",
            Self::Astro => "Astro",
            Self::SvelteKit => "SvelteKit",
            Self::Remix => "Remix",
            Self::Hono => "Hono",
            Self::Rails => "Rails",
            Self::RustWorker => "Rust",
            Self::Vite => "Vite",
            Self::Python => "Python",
            Self::Go => "Go",
            Self::Static => "static HTML",
        }
    }
}

/// Where Cloudflare would run the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Runtime {
    /// A Worker: code that runs on each request (wrangler `main`).
    Worker,
    /// A Pages project: a built site, optionally with functions
    /// (wrangler `pages_build_output_dir`).
    Pages,
}

impl Runtime {
    /// The runtime's name on Cloudflare, in plain words.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Worker => "Cloudflare Worker",
            Self::Pages => "Cloudflare Pages",
        }
    }
}

/// Something the app needs from outside itself that Cloudflare may have to
/// provide, or that the wizard must report instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Need {
    /// A Postgres database.
    Postgres,
    /// A MySQL (or MariaDB) database.
    MySql,
    /// A SQLite database (also Turso/libSQL).
    Sqlite,
    /// S3-style file storage.
    ObjectStorage,
    /// A key-value store.
    KeyValue,
    /// A message queue.
    Queue,
    /// A Redis cache (Upstash counts: it is Redis over HTTP).
    Redis,
    /// A MongoDB database.
    Mongo,
    /// Sending email through an outside service.
    Email,
    /// Scheduled jobs that run on a timer.
    Cron,
}

impl Need {
    /// The need in plain words, with its article ("a Postgres database").
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Postgres => "a Postgres database",
            Self::MySql => "a MySQL database",
            Self::Sqlite => "a SQLite database",
            Self::ObjectStorage => "S3-style file storage",
            Self::KeyValue => "a key-value store",
            Self::Queue => "a message queue",
            Self::Redis => "a Redis cache",
            Self::Mongo => "a MongoDB database",
            Self::Email => "email sending",
            Self::Cron => "scheduled jobs",
        }
    }

    /// The Cloudflare resource that covers this need, or `None` when there
    /// is no equivalent and the wizard must say so.
    #[must_use]
    pub const fn cloudflare_answer(self) -> Option<&'static str> {
        match self {
            Self::Postgres => Some("Hyperdrive (a fast connection to your Postgres database)"),
            Self::MySql => Some("Hyperdrive (MySQL)"),
            Self::Sqlite => Some("D1 database"),
            Self::ObjectStorage => Some("R2 bucket"),
            Self::KeyValue => Some("KV namespace"),
            Self::Queue => Some("Queue"),
            Self::Cron => Some("Cron Trigger (a scheduled task)"),
            Self::Redis | Self::Mongo | Self::Email => None,
        }
    }

    /// Whether this need is a database, which decides whether an environment
    /// variable name can stand in as evidence of one.
    const fn is_database(self) -> bool {
        matches!(self, Self::Postgres | Self::MySql | Self::Sqlite | Self::Mongo)
    }
}

/// A kind of binding a wrangler config can declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BindingKind {
    /// A D1 (SQLite) database.
    D1,
    /// A KV namespace.
    Kv,
    /// An R2 bucket.
    R2,
    /// A Hyperdrive connection to a Postgres database.
    Hyperdrive,
    /// A queue producer.
    Queue,
    /// A Durable Object class.
    DurableObject,
}

impl BindingKind {
    /// The binding's kind in plain words.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::D1 => "D1 database",
            Self::Kv => "KV namespace",
            Self::R2 => "R2 bucket",
            Self::Hyperdrive => "Hyperdrive connection",
            Self::Queue => "queue",
            Self::DurableObject => "Durable Object",
        }
    }

    /// The need a binding of this kind satisfies, if any.
    const fn need(self) -> Option<Need> {
        match self {
            Self::D1 => Some(Need::Sqlite),
            Self::Kv => Some(Need::KeyValue),
            Self::R2 => Some(Need::ObjectStorage),
            Self::Hyperdrive => Some(Need::Postgres),
            Self::Queue => Some(Need::Queue),
            Self::DurableObject => None,
        }
    }
}

/// A binding the wrangler config already declares: its kind and the name the
/// code uses for it. Ids and other config values are not kept.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Binding {
    /// What kind of resource the binding points at.
    pub kind: BindingKind,
    /// The name the code uses to reach it.
    pub name: String,
}

/// Accumulates findings file by file. [`detect`] feeds it in precedence
/// order, then [`Acc::finish`] settles the config-level answers.
#[derive(Default)]
struct Acc {
    frameworks: BTreeSet<Framework>,
    needs: BTreeSet<Need>,
    env_names: BTreeSet<String>,
    python: bool,
    upstash: bool,
    wrangler: Option<Value>,
}

impl Acc {
    /// Reads one file, dispatching on its name.
    fn read(&mut self, path: &str, text: &str) {
        let name = path.rsplit('/').next().unwrap_or(path);
        match name {
            "package.json" => self.node(text),
            "wrangler.toml" => self.wrangler(Some(parse_toml(text))),
            "wrangler.json" | "wrangler.jsonc" => {
                self.wrangler(serde_json::from_str(&strip_jsonc(text)).ok());
            }
            "pyproject.toml" => self.pyproject(text),
            "requirements.txt" => {
                self.python = true;
                for line in text.lines() {
                    if let Some(need) = python_name(line).and_then(|n| python_need(&n)) {
                        self.needs.insert(need);
                    }
                }
            }
            "Cargo.toml" => self.cargo(text),
            "go.mod" => self.go_mod(text),
            "Gemfile" => self.gemfile(text),
            _ if name.ends_with(".prisma") => self.sql_values(text, "provider"),
            _ if is_drizzle(name) => self.drizzle(text),
            _ if is_env_example(name) => self.env_file(text),
            _ if is_compose(name) => self.compose(text),
            _ => {
                if let Some(fw) = config_framework(name) {
                    self.frameworks.insert(fw);
                }
            }
        }
    }

    /// Keeps the first (shallowest) wrangler config that parsed.
    fn wrangler(&mut self, doc: Option<Value>) {
        if self.wrangler.is_none() {
            self.wrangler = doc;
        }
    }

    fn node(&mut self, text: &str) {
        let Ok(pkg) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let mut names = BTreeSet::new();
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
            names.extend(object_keys(pkg.get(key)));
        }
        for name in &names {
            if let Some(fw) = node_framework(name) {
                self.frameworks.insert(fw);
            }
            if let Some(need) = node_need(name) {
                self.needs.insert(need);
            }
        }
        if names.contains("@upstash/redis") {
            self.upstash = true;
        }
    }

    fn pyproject(&mut self, text: &str) {
        self.python = true;
        let doc = parse_toml(text);
        let mut specs = strings(doc.pointer("/project/dependencies"));
        for group in ["/project/optional-dependencies", "/dependency-groups"] {
            if let Some(map) = doc.pointer(group).and_then(Value::as_object) {
                for value in map.values() {
                    specs.extend(strings(Some(value)));
                }
            }
        }
        specs.extend(object_keys(doc.pointer("/tool/poetry/dependencies")));
        if let Some(groups) = doc.pointer("/tool/poetry/group").and_then(Value::as_object) {
            for group in groups.values() {
                specs.extend(object_keys(group.get("dependencies")));
            }
        }
        for spec in specs {
            if let Some(need) = python_name(&spec).and_then(|n| python_need(&n)) {
                self.needs.insert(need);
            }
        }
    }

    fn cargo(&mut self, text: &str) {
        let doc = parse_toml(text);
        let mut tables: Vec<&Value> = Vec::new();
        tables.extend(doc.get("dependencies"));
        tables.extend(doc.pointer("/workspace/dependencies"));
        if let Some(targets) = doc.get("target").and_then(Value::as_object) {
            tables.extend(targets.values().filter_map(|t| t.get("dependencies")));
        }
        for table in tables {
            let Some(map) = table.as_object() else {
                continue;
            };
            for (name, spec) in map {
                match name.as_str() {
                    "worker" => {
                        self.frameworks.insert(Framework::RustWorker);
                    }
                    "sqlx" | "diesel" => {
                        for feature in features(spec) {
                            match feature.as_str() {
                                "postgres" => {
                                    self.needs.insert(Need::Postgres);
                                }
                                "mysql" => {
                                    self.needs.insert(Need::MySql);
                                }
                                "sqlite" => {
                                    self.needs.insert(Need::Sqlite);
                                }
                                _ => {}
                            }
                        }
                    }
                    other => {
                        if let Some(need) = rust_need(other) {
                            self.needs.insert(need);
                        }
                    }
                }
            }
        }
    }

    fn go_mod(&mut self, text: &str) {
        self.frameworks.insert(Framework::Go);
        let modules = [
            ("github.com/jackc/pgx", Need::Postgres),
            ("github.com/lib/pq", Need::Postgres),
            ("github.com/go-sql-driver/mysql", Need::MySql),
            ("github.com/redis/go-redis", Need::Redis),
            ("github.com/go-redis/redis", Need::Redis),
            ("go.mongodb.org/mongo-driver", Need::Mongo),
        ];
        for (module, need) in modules {
            if text.contains(module) {
                self.needs.insert(need);
            }
        }
    }

    fn gemfile(&mut self, text: &str) {
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("gem ") else {
                continue;
            };
            let Some(gem) = rest.split(['\'', '"']).nth(1) else {
                continue;
            };
            if gem == "rails" {
                self.frameworks.insert(Framework::Rails);
            }
            let need = match gem {
                "pg" => Some(Need::Postgres),
                "mysql2" => Some(Need::MySql),
                "sqlite3" => Some(Need::Sqlite),
                "redis" => Some(Need::Redis),
                "mongoid" | "mongo" => Some(Need::Mongo),
                "aws-sdk-s3" => Some(Need::ObjectStorage),
                _ => None,
            };
            if let Some(need) = need {
                self.needs.insert(need);
            }
        }
    }

    fn drizzle(&mut self, text: &str) {
        self.sql_values(text, "dialect");
        if values_of(text, "driver").iter().any(|d| d == "d1-http") {
            self.needs.insert(Need::Sqlite);
        }
    }

    /// Records the need behind each value of `key` that names a SQL or
    /// document database (Prisma `provider`, Drizzle `dialect`).
    fn sql_values(&mut self, text: &str, key: &str) {
        for value in values_of(text, key) {
            if let Some(need) = sql_dialect(&value) {
                self.needs.insert(need);
            }
        }
    }

    /// Reads an example env file for names and connection-string schemes.
    /// The value is inspected only for its scheme and never stored.
    fn env_file(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if !is_env_name(name) {
                continue;
            }
            self.env_names.insert(name.to_owned());
            if let Some(need) = url_need(unquote(value)) {
                self.needs.insert(need);
            }
        }
    }

    fn compose(&mut self, text: &str) {
        for line in text.lines() {
            let Some(image) = line.trim().strip_prefix("image:") else {
                continue;
            };
            let image = image.split('#').next().unwrap_or(image);
            if let Some(need) = image_need(unquote(image)) {
                self.needs.insert(need);
            }
        }
    }

    /// Settles what the chosen wrangler config and the whole scan add up to.
    fn finish(mut self) -> Stack {
        let wrangler = self.wrangler.take();
        let doc = wrangler.as_ref();
        let existing_bindings = doc.map(wrangler_bindings).unwrap_or_default();
        let cron = doc.map(|d| strings(d.pointer("/triggers/crons"))).unwrap_or_default();
        let runtime = doc.and_then(|d| {
            if d.get("pages_build_output_dir").is_some() {
                Some(Runtime::Pages)
            } else if d.get("main").is_some() || d.get("assets").is_some() {
                Some(Runtime::Worker)
            } else {
                None
            }
        });
        let worker_name = doc.and_then(|d| string_at(d, "name"));

        for binding in &existing_bindings {
            if let Some(need) = binding.kind.need() {
                self.needs.insert(need);
            }
        }
        if let Some(d) = doc {
            if d.get("queues").is_some() {
                self.needs.insert(Need::Queue);
            }
            self.env_names.extend(object_keys(d.get("vars")));
        }
        if !cron.is_empty() {
            self.needs.insert(Need::Cron);
        }
        if self.python {
            self.frameworks.insert(Framework::Python);
        }
        if runtime == Some(Runtime::Pages) && self.frameworks.is_empty() {
            self.frameworks.insert(Framework::Static);
        }
        // No database evidence from packages, schemas, images or bindings:
        // fall back to the names of the settings. Postgres names win, then
        // MySQL, and a bare DATABASE_URL is taken as Postgres.
        if !self.needs.iter().any(|n| n.is_database()) {
            let fallback = if self.env_names.iter().any(|n| is_postgres_setting(n)) {
                Some(Need::Postgres)
            } else if self.env_names.iter().any(|n| n.starts_with("MYSQL")) {
                Some(Need::MySql)
            } else if self.env_names.contains("DATABASE_URL") {
                Some(Need::Postgres)
            } else {
                None
            };
            self.needs.extend(fallback);
        }

        let mut notes = Vec::new();
        for need in &self.needs {
            notes.extend(match need {
                Need::Redis if self.upstash => Some(
                    "Uses Upstash Redis, which works from Cloudflare as it is. Keep its URL \
                     and token as secrets."
                        .to_owned(),
                ),
                Need::Redis => Some(
                    "Uses Redis. Cloudflare has no Redis; KV or Upstash would replace it."
                        .to_owned(),
                ),
                Need::Mongo => Some("Uses MongoDB. Not set up automatically.".to_owned()),
                Need::Email => Some(
                    "Sends email through an outside service. Its key must be added as a \
                     secret; not set up automatically."
                        .to_owned(),
                ),
                _ => None,
            });
        }

        Stack {
            framework: self.frameworks.iter().next().copied(),
            runtime,
            worker_name,
            needs: self.needs,
            env_vars: self.env_names,
            existing_bindings,
            cron,
            notes,
        }
    }
}

fn depth(path: &str) -> usize {
    path.matches('/').count()
}

/// A framework named by its `package.json` dependency.
fn node_framework(name: &str) -> Option<Framework> {
    Some(match name {
        "next" => Framework::Next,
        "nuxt" => Framework::Nuxt,
        "astro" => Framework::Astro,
        "@sveltejs/kit" => Framework::SvelteKit,
        "remix" => Framework::Remix,
        "hono" => Framework::Hono,
        "vite" => Framework::Vite,
        _ if name.starts_with("@remix-run/") => Framework::Remix,
        _ => return None,
    })
}

/// A need named by its `package.json` dependency. Upstash is Redis over
/// HTTP, so it counts as Redis; the note says it works as it is.
fn node_need(name: &str) -> Option<Need> {
    Some(match name {
        "pg"
        | "postgres"
        | "@neondatabase/serverless"
        | "@vercel/postgres"
        | "@prisma/adapter-pg" => Need::Postgres,
        "mysql2" | "mysql" | "@planetscale/database" => Need::MySql,
        "better-sqlite3" | "sqlite3" | "@libsql/client" => Need::Sqlite,
        "@aws-sdk/client-s3" | "@aws-sdk/s3-request-presigner" | "minio" => Need::ObjectStorage,
        "ioredis" | "redis" | "@upstash/redis" | "bullmq" => Need::Redis,
        "mongodb" | "mongoose" => Need::Mongo,
        "resend" | "@sendgrid/mail" | "nodemailer" | "postmark" | "mailgun.js" => Need::Email,
        "@aws-sdk/client-sqs" => Need::Queue,
        "node-cron" => Need::Cron,
        _ => return None,
    })
}

/// A need named by a Python package. Names are already normalised by
/// [`python_name`].
fn python_need(name: &str) -> Option<Need> {
    Some(match name {
        "psycopg" | "psycopg2" | "psycopg2-binary" | "asyncpg" | "pg8000" => Need::Postgres,
        "pymysql" | "mysqlclient" | "mysql-connector-python" | "aiomysql" => Need::MySql,
        "pymongo" | "motor" => Need::Mongo,
        "redis" | "aioredis" => Need::Redis,
        "s3fs" | "minio" => Need::ObjectStorage,
        _ => return None,
    })
}

/// The bare package name from a requirement or a dependency spec, lowercased
/// and with PEP 503 separators: `psycopg[binary]==3.2` gives `psycopg`.
fn python_name(spec: &str) -> Option<String> {
    let name: String = spec
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    (!name.is_empty()).then(|| name.to_ascii_lowercase().replace(['_', '.'], "-"))
}

/// A need named by a Rust crate in `Cargo.toml` (sqlx and diesel are handled
/// by their features instead).
fn rust_need(name: &str) -> Option<Need> {
    Some(match name {
        "postgres" | "tokio-postgres" => Need::Postgres,
        "mysql" | "mysql_async" => Need::MySql,
        "rusqlite" | "libsql" => Need::Sqlite,
        "redis" => Need::Redis,
        "mongodb" => Need::Mongo,
        "aws-sdk-s3" => Need::ObjectStorage,
        _ => return None,
    })
}

/// The need behind a Docker image name. Exporters are monitoring sidecars,
/// not databases, so they are skipped.
fn image_need(image: &str) -> Option<Need> {
    let name = image.split('@').next().unwrap_or(image);
    let last = name.rsplit('/').next().unwrap_or(name).split(':').next().unwrap_or(name);
    let last = last.to_ascii_lowercase();
    if last.contains("exporter") {
        None
    } else if ["postgres", "postgis", "timescale"].iter().any(|s| last.contains(s)) {
        Some(Need::Postgres)
    } else if last.contains("mysql") || last.contains("mariadb") {
        Some(Need::MySql)
    } else if last.contains("redis") || last.contains("valkey") {
        Some(Need::Redis)
    } else if last.contains("mongo") {
        Some(Need::Mongo)
    } else if last.contains("minio") {
        Some(Need::ObjectStorage)
    } else {
        None
    }
}

/// The need a SQL dialect names (Prisma `provider`, Drizzle `dialect`).
fn sql_dialect(value: &str) -> Option<Need> {
    Some(match value {
        "postgresql" | "postgres" | "cockroachdb" => Need::Postgres,
        "mysql" => Need::MySql,
        "sqlite" | "turso" => Need::Sqlite,
        "mongodb" => Need::Mongo,
        _ => return None,
    })
}

/// The need a connection string's scheme names. Only the scheme is read.
fn url_need(value: &str) -> Option<Need> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        Some(Need::Postgres)
    } else if lower.starts_with("mysql://") || lower.starts_with("mariadb://") {
        Some(Need::MySql)
    } else if lower.starts_with("mongodb://") || lower.starts_with("mongodb+srv://") {
        Some(Need::Mongo)
    } else if lower.starts_with("redis://") || lower.starts_with("rediss://") {
        Some(Need::Redis)
    } else if lower.starts_with("libsql://") || lower.starts_with("sqlite:") {
        Some(Need::Sqlite)
    } else {
        None
    }
}

/// Setting names that say "Postgres": the `POSTGRES*` family and the libpq
/// `PG*` variables (`PGHOST`, `PGUSER`, ...). `DATABASE_URL` is weaker and is
/// handled separately.
fn is_postgres_setting(name: &str) -> bool {
    const PG_SUFFIXES: &[&str] =
        &["HOST", "PORT", "USER", "PASSWORD", "DATABASE", "URL", "SSLMODE"];
    name.starts_with("POSTGRES")
        || name.strip_prefix("PG").is_some_and(|r| PG_SUFFIXES.contains(&r))
}

/// The bindings a wrangler config declares, by kind, plus a queue producer
/// and Durable Object class where present.
fn wrangler_bindings(doc: &Value) -> Vec<Binding> {
    let mut out = Vec::new();
    let simple = [
        ("d1_databases", BindingKind::D1),
        ("kv_namespaces", BindingKind::Kv),
        ("r2_buckets", BindingKind::R2),
        ("hyperdrive", BindingKind::Hyperdrive),
    ];
    for (key, kind) in simple {
        for item in items(doc.get(key)) {
            if let Some(name) = string_at(item, "binding") {
                out.push(Binding { kind, name });
            }
        }
    }
    for item in items(doc.pointer("/queues/producers")) {
        if let Some(name) = string_at(item, "binding") {
            out.push(Binding { kind: BindingKind::Queue, name });
        }
    }
    for item in items(doc.pointer("/durable_objects/bindings")) {
        if let Some(name) = string_at(item, "name") {
            out.push(Binding { kind: BindingKind::DurableObject, name });
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The features listed on a dependency's spec (`{ features = [...] }`).
fn features(spec: &Value) -> Vec<String> {
    strings(spec.get("features"))
}

/// A setting name is a letter or underscore, then letters, digits or
/// underscores.
fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_drizzle(name: &str) -> bool {
    matches!(name, "drizzle.config.ts" | "drizzle.config.js" | "drizzle.config.mjs")
}

fn is_env_example(name: &str) -> bool {
    matches!(name, ".env.example" | ".env.sample" | ".dev.vars.example")
}

fn is_compose(name: &str) -> bool {
    (name.starts_with("docker-compose") || name.starts_with("compose"))
        && (name.ends_with(".yml") || name.ends_with(".yaml"))
}

/// The framework a framework's config file names, when the file is one.
fn config_framework(name: &str) -> Option<Framework> {
    if name.starts_with("next.config.") {
        Some(Framework::Next)
    } else if name.starts_with("astro.config.") {
        Some(Framework::Astro)
    } else if name.starts_with("nuxt.config.") {
        Some(Framework::Nuxt)
    } else if name == "svelte.config.js" {
        Some(Framework::SvelteKit)
    } else if name.starts_with("vite.config.") {
        Some(Framework::Vite)
    } else {
        None
    }
}

/// The value of an env-style setting: surrounding quotes and spaces removed.
fn unquote(value: &str) -> &str {
    value.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// Every value written for `key` in `text` as `key = "value"` or
/// `key: 'value'`, wherever the key sits on its line. Prisma and Drizzle
/// both use this shape, and a file may name the key more than once (Prisma
/// has a `provider` in the generator block and one in the datasource).
fn values_of(text: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        for (at, _) in line.match_indices(key) {
            let preceded_by_word =
                line[..at].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_');
            if preceded_by_word {
                continue;
            }
            let Some(rest) = line[at + key.len()..].trim_start().strip_prefix(['=', ':']) else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                continue;
            };
            if let Some(value) = rest[1..].split(quote).next() {
                out.push(value.to_owned());
            }
        }
    }
    out
}

/// Parses a `package.json`-style or wrangler-style document as JSON with
/// `//` and `/* */` comments and trailing commas allowed. Comment markers
/// inside strings (such as `https://`) are left alone.
fn strip_jsonc(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_str = false;
    while i < chars.len() {
        let ch = chars[i];
        if in_str {
            out.push(ch);
            if ch == '\\' {
                if let Some(next) = chars.get(i + 1) {
                    out.push(*next);
                    i += 1;
                }
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        } else if ch == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else {
            out.push(ch);
        }
        i += 1;
    }
    remove_trailing_commas(&out)
}

/// Drops a comma that is followed (after spaces) by `}` or `]`, outside
/// strings. Runs after comments are gone.
fn remove_trailing_commas(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut in_str = false;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if in_str {
            out.push(ch);
            if ch == '\\' {
                if let Some(next) = chars.get(i + 1) {
                    out.push(*next);
                    i += 1;
                }
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == ',' {
            let mut j = i + 1;
            while chars.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            if !matches!(chars.get(j), Some('}' | ']')) {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

/// Parses the subset of TOML the wizard reads: tables, arrays of tables,
/// key/value pairs with strings, numbers, booleans, arrays and inline tables,
/// and multi-line arrays. Lines it cannot read are skipped. The result has
/// the same shape `serde_json` gives a JSON file.
fn parse_toml(text: &str) -> Value {
    let mut root = Map::new();
    let mut path: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let line = strip_toml_comment(raw).trim();
        if let Some(buf) = pending.as_mut() {
            buf.push(' ');
            buf.push_str(line);
            if brackets_closed(buf) {
                // An empty line here cannot parse, so `take` never adds a pair by mistake.
                let done = pending.take().unwrap_or_default();
                toml_pair(&mut root, &path, &done);
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[").and_then(|r| r.strip_suffix("]]")) {
            let keys = split_path(inner);
            let appended = keys.split_last().and_then(|(last, parent)| {
                table_at(&mut root, parent)?
                    .entry(last.clone())
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
            });
            if let Some(items) = appended {
                items.push(Value::Object(Map::new()));
            }
            path = keys;
        } else if let Some(inner) = line.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            path = split_path(inner);
            let _ = table_at(&mut root, &path);
        } else if line.contains('=') {
            if brackets_closed(line) {
                toml_pair(&mut root, &path, line);
            } else {
                pending = Some(line.to_owned());
            }
        }
    }
    Value::Object(root)
}

/// Stores one `key = value` line under the table at `path`.
fn toml_pair(root: &mut Map<String, Value>, path: &[String], line: &str) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    let (Some(key), Some(value)) = (toml_key(key), parse_value(value)) else {
        return;
    };
    if let Some(table) = table_at(root, path) {
        table.insert(key, value);
    }
}

/// The table at `path`, created if absent. Walking through an array of
/// tables enters its last element, which is how TOML scopes keys.
fn table_at<'a>(
    root: &'a mut Map<String, Value>,
    path: &[String],
) -> Option<&'a mut Map<String, Value>> {
    let mut cur = root;
    for seg in path {
        let entry = cur.entry(seg.clone()).or_insert_with(|| Value::Object(Map::new()));
        cur = match entry {
            Value::Object(m) => m,
            Value::Array(items) => items.last_mut()?.as_object_mut()?,
            _ => return None,
        };
    }
    Some(cur)
}

fn split_path(inner: &str) -> Vec<String> {
    inner.split('.').filter_map(toml_key).collect()
}

/// A TOML key: bare, or quoted. `None` when there is nothing to name.
fn toml_key(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let key = if raw.starts_with('"') || raw.starts_with('\'') {
        unquote(raw).to_owned()
    } else {
        raw.to_owned()
    };
    (!key.is_empty()).then_some(key)
}

/// Removes a `#` comment that is not inside a string.
fn strip_toml_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if q == '"' && c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

/// Whether every `[` and `{` in `text` (outside strings) has been closed.
fn brackets_closed(text: &str) -> bool {
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if q == '"' && c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
        } else {
            match c {
                '"' | '\'' => quote = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                _ => {}
            }
        }
    }
    depth <= 0
}

/// Parses one TOML value from the start of `src`. Trailing text is ignored.
fn parse_value(src: &str) -> Option<Value> {
    let chars: Vec<char> = src.chars().collect();
    let mut at = 0;
    read_value(&chars, &mut at)
}

fn skip_space(c: &[char], at: &mut usize) {
    while c.get(*at).is_some_and(|ch| ch.is_whitespace()) {
        *at += 1;
    }
}

fn read_value(c: &[char], at: &mut usize) -> Option<Value> {
    skip_space(c, at);
    match *c.get(*at)? {
        '"' => read_quoted(c, at, '"').map(Value::String),
        '\'' => read_quoted(c, at, '\'').map(Value::String),
        '[' => {
            *at += 1;
            let mut items = Vec::new();
            loop {
                skip_space(c, at);
                match *c.get(*at)? {
                    ']' => {
                        *at += 1;
                        return Some(Value::Array(items));
                    }
                    ',' => *at += 1,
                    _ => items.push(read_value(c, at)?),
                }
            }
        }
        '{' => {
            *at += 1;
            let mut table = Map::new();
            loop {
                skip_space(c, at);
                match *c.get(*at)? {
                    '}' => {
                        *at += 1;
                        return Some(Value::Object(table));
                    }
                    ',' => *at += 1,
                    _ => {
                        let key = read_key(c, at)?;
                        skip_space(c, at);
                        if *c.get(*at)? != '=' {
                            return None;
                        }
                        *at += 1;
                        table.insert(key, read_value(c, at)?);
                    }
                }
            }
        }
        _ => read_bare(c, at),
    }
}

/// A quoted string starting at `*at`. Basic strings (`"`) honour escapes;
/// literal strings (`'`) do not.
fn read_quoted(c: &[char], at: &mut usize, quote: char) -> Option<String> {
    *at += 1;
    let mut out = String::new();
    loop {
        let ch = *c.get(*at)?;
        *at += 1;
        if ch == quote {
            return Some(out);
        }
        if ch == '\\' && quote == '"' {
            let esc = *c.get(*at)?;
            *at += 1;
            match esc {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'u' | 'U' => {
                    let len = if esc == 'u' { 4 } else { 8 };
                    let hex: String = c.get(*at..*at + len)?.iter().collect();
                    *at += len;
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                other => out.push(other),
            }
        } else {
            out.push(ch);
        }
    }
}

fn read_key(c: &[char], at: &mut usize) -> Option<String> {
    match c.get(*at)? {
        '"' | '\'' => {
            let quote = c[*at];
            read_quoted(c, at, quote)
        }
        _ => {
            let start = *at;
            while c
                .get(*at)
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
            {
                *at += 1;
            }
            (*at > start).then(|| c[start..*at].iter().collect())
        }
    }
}

/// An unquoted value: `true`, `false`, an integer, or otherwise the raw text
/// (dates and the like, which the wizard does not need).
fn read_bare(c: &[char], at: &mut usize) -> Option<Value> {
    let start = *at;
    while c.get(*at).is_some_and(|ch| !matches!(ch, ',' | ']' | '}') && !ch.is_whitespace()) {
        *at += 1;
    }
    let token: String = c[start..*at].iter().collect();
    match token.as_str() {
        "" => None,
        "true" => Some(Value::Bool(true)),
        "false" => Some(Value::Bool(false)),
        t => Some(t.parse::<i64>().map_or_else(|_| Value::String(t.to_owned()), Value::from)),
    }
}

/// The strings in an array value, in order. Anything else gives nothing.
fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The keys of an object value.
fn object_keys(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_object).into_iter().flat_map(|m| m.keys().cloned()).collect()
}

/// The elements of an array value.
fn items<'a>(v: Option<&'a Value>) -> impl Iterator<Item = &'a Value> + 'a {
    v.and_then(Value::as_array).into_iter().flatten()
}

fn string_at(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        files.iter().map(|(p, t)| ((*p).to_owned(), (*t).to_owned())).collect()
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// The secret must be absent from everything the wizard can show.
    fn assert_no_secret(stack: &Stack, secret: &str) {
        assert!(!format!("{stack:?}").contains(secret), "secret leaked into Debug output");
        assert!(!stack.summary().join("\n").contains(secret), "secret leaked into summary");
    }

    #[test]
    fn next_prisma_postgres_app() {
        let stack = detect(&repo(&[
            (
                "package.json",
                r#"{"dependencies":{"next":"15.0.0","react":"19.0.0","@prisma/client":"6.0.0"},
                    "devDependencies":{"prisma":"6.0.0"}}"#,
            ),
            (
                "prisma/schema.prisma",
                "generator client {\n  provider = \"prisma-client-js\"\n}\n\n\
                 datasource db {\n  provider = \"postgresql\"\n  url = env(\"DATABASE_URL\")\n}\n",
            ),
            (
                ".env.example",
                "DATABASE_URL=postgres://u:secretpw@h/db\nNEXT_PUBLIC_SITE=https://example.com\n",
            ),
        ]));
        assert_eq!(stack.framework, Some(Framework::Next));
        assert_eq!(stack.runtime, None);
        assert_eq!(stack.needs, BTreeSet::from([Need::Postgres]));
        assert_eq!(stack.env_vars, set(&["DATABASE_URL", "NEXT_PUBLIC_SITE"]));
        assert!(stack.notes.is_empty());
        assert_eq!(stack.summary()[0], "Built with Next.js, not set up for Cloudflare yet");
        assert!(stack.summary().iter().any(|l| l.contains(
            "Needs a Postgres database → we'll use Hyperdrive (a fast connection to your Postgres database)"
        )));
        assert_no_secret(&stack, "secretpw");
    }

    #[test]
    fn astro_static_site_on_pages() {
        let stack = detect(&repo(&[
            ("package.json", r#"{"dependencies":{"astro":"5.0.0"}}"#),
            ("astro.config.mjs", "export default {};\n"),
            (
                "wrangler.toml",
                "name = \"marketing-site\"\npages_build_output_dir = \"dist\"\n\
                 compatibility_date = \"2025-01-01\"\n",
            ),
        ]));
        assert_eq!(stack.framework, Some(Framework::Astro));
        assert_eq!(stack.runtime, Some(Runtime::Pages));
        assert_eq!(stack.worker_name.as_deref(), Some("marketing-site"));
        assert!(stack.needs.is_empty());
        assert!(stack.notes.is_empty());
        assert_eq!(stack.summary()[0], "Built with Astro, deployed as Cloudflare Pages");
    }

    #[test]
    fn hono_worker_with_comments_trailing_commas_and_bindings() {
        let stack = detect(&repo(&[
            (
                "wrangler.jsonc",
                r#"{
                  // the API worker
                  "name": "hono-api", /* deployed from main */
                  "main": "src/index.ts",
                  "compatibility_date": "2025-01-01",
                  "d1_databases": [
                    { "binding": "DB", "database_name": "app", "database_id": "abc" }, // one db
                  ],
                  "kv_namespaces": [{ "binding": "CACHE", "id": "kv-id" }],
                  "triggers": { "crons": ["0 * * * *"] },
                  "vars": { "APP_URL": "https://api.example.com//x", },
                }"#,
            ),
            (
                "package.json",
                r#"{"dependencies":{"hono":"4.0.0"},"devDependencies":{"wrangler":"4.0.0","vite":"6.0.0"}}"#,
            ),
        ]));
        assert_eq!(stack.framework, Some(Framework::Hono));
        assert_eq!(stack.runtime, Some(Runtime::Worker));
        assert_eq!(stack.worker_name.as_deref(), Some("hono-api"));
        assert_eq!(stack.needs, BTreeSet::from([Need::Sqlite, Need::KeyValue, Need::Cron]));
        assert_eq!(
            stack.existing_bindings,
            vec![
                Binding { kind: BindingKind::D1, name: "DB".to_owned() },
                Binding { kind: BindingKind::Kv, name: "CACHE".to_owned() },
            ]
        );
        assert_eq!(stack.cron, vec!["0 * * * *".to_owned()]);
        assert_eq!(stack.env_vars, set(&["APP_URL"]));
        assert!(stack.summary().iter().any(|l| l == "Runs on a schedule: 0 * * * *"));
    }

    #[test]
    fn python_fastapi_with_compose_postgres_and_redis() {
        let stack = detect(&repo(&[
            ("requirements.txt", "fastapi==0.115.0\npsycopg[binary]==3.2.1\nredis>=5\n"),
            (
                "docker-compose.yml",
                "services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7\n\
                 \n  metrics:\n    image: oliver006/redis_exporter:v1\n",
            ),
            (".env.example", "REDIS_URL=redis://localhost:6379\n"),
        ]));
        assert_eq!(stack.framework, Some(Framework::Python));
        assert_eq!(stack.needs, BTreeSet::from([Need::Postgres, Need::Redis]));
        assert_eq!(
            stack.notes,
            vec!["Uses Redis. Cloudflare has no Redis; KV or Upstash would replace it.".to_owned()]
        );
        assert!(stack.summary().iter().any(|l| l.starts_with("Needs a Redis cache")));
    }

    #[test]
    fn drizzle_mysql_app_keeps_mysql_over_env_name() {
        let stack = detect(&repo(&[
            (
                "package.json",
                r#"{"dependencies":{"drizzle-orm":"0.36.0","mysql2":"3.11.0"},
                    "devDependencies":{"drizzle-kit":"0.28.0","vite":"5.4.0"}}"#,
            ),
            (
                "drizzle.config.ts",
                "import { defineConfig } from 'drizzle-kit';\n\
                 export default defineConfig({ dialect: 'mysql', schema: './src/schema.ts' });\n",
            ),
            (".env.example", "DATABASE_URL=mysql://user:pw@host/db\n"),
        ]));
        assert_eq!(stack.framework, Some(Framework::Vite));
        assert_eq!(stack.needs, BTreeSet::from([Need::MySql]));
        assert_eq!(stack.env_vars, set(&["DATABASE_URL"]));
    }

    #[test]
    fn rust_worker_with_sqlx_postgres_multiline_features() {
        let stack = detect(&repo(&[
            (
                "Cargo.toml",
                "[package]\nname = \"rust-api\"\n\n[dependencies]\nworker = \"0.8\"\n\
                 sqlx = { version = \"0.8\", default-features = false, features = [\n  \
                 \"postgres\", # the driver\n  \"runtime-tokio\",\n] }\n",
            ),
            ("wrangler.toml", "name = \"rust-api\"\nmain = \"build/worker/shim.mjs\"\n"),
        ]));
        assert_eq!(stack.framework, Some(Framework::RustWorker));
        assert_eq!(stack.runtime, Some(Runtime::Worker));
        assert_eq!(stack.needs, BTreeSet::from([Need::Postgres]));
    }

    #[test]
    fn env_names_fall_back_when_nothing_else_names_a_database() {
        let pg = detect(&repo(&[(".env.example", "DATABASE_URL=\nAPI_KEY=\n")]));
        assert_eq!(pg.needs, BTreeSet::from([Need::Postgres]));
        assert_eq!(pg.env_vars, set(&["API_KEY", "DATABASE_URL"]));

        let mysql = detect(&repo(&[(".env.example", "MYSQL_HOST=\nMYSQL_USER=\n")]));
        assert_eq!(mysql.needs, BTreeSet::from([Need::MySql]));
    }

    #[test]
    fn redis_is_unsupported_and_upstash_says_so_differently() {
        let stack = detect(&repo(&[(
            "package.json",
            r#"{"dependencies":{"@upstash/redis":"1.0.0","resend":"4.0.0","mongoose":"8.0.0"}}"#,
        )]));
        assert_eq!(stack.needs, BTreeSet::from([Need::Redis, Need::Mongo, Need::Email]));
        assert_eq!(stack.notes.len(), 3);
        assert!(stack.notes.iter().any(|n| n.starts_with("Uses Upstash Redis")));
        assert!(stack.notes.iter().any(|n| n.starts_with("Uses MongoDB")));
        assert!(stack.notes.iter().any(|n| n.starts_with("Sends email")));
    }

    #[test]
    fn unknown_repo_says_so() {
        let stack = detect(&repo(&[("README.md", "hello")]));
        assert_eq!(stack, Stack::default());
        assert_eq!(stack.summary()[0], "Could not tell what this app is built with");
    }

    #[test]
    fn cloudflare_answers_match_the_plan() {
        assert_eq!(Need::Sqlite.cloudflare_answer(), Some("D1 database"));
        assert_eq!(Need::ObjectStorage.cloudflare_answer(), Some("R2 bucket"));
        assert_eq!(Need::Redis.cloudflare_answer(), None);
        assert_eq!(Need::Mongo.cloudflare_answer(), None);
    }

    #[test]
    fn wanted_follows_the_depth_rules() {
        assert!(wanted("wrangler.jsonc"));
        assert!(wanted("apps/web/wrangler.toml"));
        assert!(!wanted("a/b/c/wrangler.toml"));
        assert!(wanted("packages/a/package.json"));
        assert!(!wanted("node_modules/x/package.json"));
        assert!(!wanted("apps/web/src/package.json"));
        assert!(wanted("prisma/schema.prisma"));
        assert!(wanted("db/app.prisma"));
        assert!(wanted("docker-compose.prod.yml"));
        assert!(wanted("next.config.mjs"));
        assert!(!wanted("src/next.config.js"));
        assert!(!wanted("src/index.ts"));
        assert!(!wanted("README.md"));
    }

    #[test]
    fn pick_orders_root_first_and_caps() {
        let mut paths: Vec<String> =
            (0..40).map(|i| format!("pkgs/p{i:02}/package.json")).collect();
        paths.insert(0, "package.json".to_owned());
        paths.push("README.md".to_owned());
        let picked = pick(&paths);
        assert_eq!(picked.len(), MAX_FILES);
        assert_eq!(picked[0], "package.json");
        assert!(picked.iter().all(|p| wanted(p)));
    }

    #[test]
    fn jsonc_comment_markers_inside_strings_survive() {
        let text = r#"{"a": "http://x/*not a comment*/", // gone
            "b": [1, 2,],}"#;
        let value: Value = serde_json::from_str(&strip_jsonc(text)).expect("valid after strip");
        assert_eq!(value["a"], "http://x/*not a comment*/");
        assert_eq!(value["b"], serde_json::json!([1, 2]));
    }
}
