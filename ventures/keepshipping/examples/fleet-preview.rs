//! The fleet console as static files: renders the fleet list, every site
//! page, the connect page and the empty state from a snapshot and writes
//! them to `target/fleet-preview/`, so a design change can be looked at in
//! a browser without a Worker, a sign-in or a Cloudflare token:
//!
//! ```text
//! cargo run -p keepshipping-waitlist --example fleet-preview [-- snapshot.json]
//! python3 -m http.server -d target/fleet-preview 8080
//! # then open http://localhost:8080/console/fleet/index.html
//! ```
//!
//! Without an argument it reads the checked-in `tests/fixtures/fleet.json`.
//! Links between pages point at the Worker's routes, so only the files
//! named below open directly.

use keepshipping_waitlist::cloudflare::page::connect_page;
use keepshipping_waitlist::fleet::{self, Fleet};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::fs;
use std::path::Path;

const FIXTURE: &str = include_str!("../tests/fixtures/fleet.json");

fn main() {
    let snapshot = match std::env::args().nth(1) {
        Some(path) => fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}")),
        None => FIXTURE.to_owned(),
    };
    let snapshot: Fleet = serde_json::from_str(&snapshot).expect("a fleet snapshot");
    // An hour after the snapshot, so the relative times read as they would.
    let now = later(&snapshot.generated_at);
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/fleet-preview/console");
    let write = |name: &str, html: String| {
        let path = out.join(name);
        fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        fs::write(&path, html).expect("write");
    };
    write("fleet/index.html", fleet::render_index(&snapshot, &now));
    for site in &snapshot.sites {
        let id = utf8_percent_encode(&site.id, NON_ALPHANUMERIC).to_string();
        write(
            &format!("fleet/{id}.html"),
            fleet::render_site(&snapshot, &site.id, &now).expect("a known id"),
        );
    }
    let accounts = vec!["Factory0".to_owned(), "Earth.OS".to_owned()];
    write("connect.html", connect_page(Some(&snapshot.generated_at), &accounts, None, &now));
    write(
        "connect-error.html",
        connect_page(None, &[], Some("Cloudflare did not accept that token."), &now),
    );
    write("empty.html", fleet::empty_snapshot_page(true));
    write(
        "notice.html",
        fleet::notice_page(
            "Not allowed",
            "This account is not on the console's allowlist.",
            Some(("/console/fleet", "Back to sites")),
        ),
    );
    println!("wrote {}", out.display());
}

/// `generated_at` plus one hour, RFC 3339; the snapshot's own time when it
/// does not parse.
fn later(generated_at: &str) -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::parse(generated_at, &Rfc3339)
        .map(|at| (at + time::Duration::hours(1)).format(&Rfc3339).unwrap_or_default())
        .unwrap_or_else(|_| generated_at.to_owned())
}
