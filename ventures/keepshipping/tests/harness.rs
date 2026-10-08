//! The composition the worker serves, asserted without Workers.
//!
//! `src/lib.rs` freezes `composition()` plus the Cloudflare runtime into a
//! `OnceLock` on an isolate's first event, and its `#[event]` handlers can
//! only fail that build inside a real isolate — long after CI. These two
//! tests move both checks onto a host build: the composition the worker
//! serves must build, and the probe an operator reads must name the module
//! that serves the traffic.

use cratefield_core::{Port, Runtime};
use cratefield_testing::{TestHarness, request};
use http::{Method, StatusCode};
use keepshipping_waitlist::{composition, module, templates, venture};

/// A native stand-in for `Cloudflare` that claims every port, so
/// `build()` validates what is static in the composition — the venture,
/// the module's routes, its surface, its migrations.
///
/// It deliberately claims *more* than a deployment does. `Cloudflare`'s
/// ports are binding-conditional: no `TURNSTILE_SECRET` means no Captcha
/// port at all, and a missing `DB` binding means no Database. Nothing here
/// can stand in for that, because those bindings exist only on a real
/// Workers `Env`. So this test proves the composition builds, not that a
/// deployment binds every port it declares — `tests/guards.rs` covers the
/// ports' behaviour through fakes, and only a deploy covers the bindings.
struct TestRuntime;

impl Runtime for TestRuntime {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// `src/lib.rs` will not serve anything if this is `Err` — so this is the
/// test the `expect` in `instance()` leans on.
#[test]
fn harness_builds() {
    composition().runtime(TestRuntime).build().expect("the venture's composition builds");
}

/// The health probe is open (no tenant, no origin guard) and must answer
/// with the composition actually mounted — a deployment that serves a
/// module `/__health` does not list is a deployment nobody can diagnose.
#[pollster::test]
async fn health_lists_the_waitlist_module() {
    let kit = TestHarness::with_builder(
        vec![Box::new(module())],
        |builder| builder.venture(venture()).templates(templates()),
        |_| {},
    );
    let health = request(&kit.router, Method::GET, "/__health", None).await;
    assert_eq!(health.status, StatusCode::OK);

    let body = health.json();
    let listed = body["modules"]
        .as_array()
        .unwrap_or_else(|| panic!("/__health lists no modules: {body}"))
        .clone();
    let entry = listed
        .iter()
        .find(|entry| entry["name"] == "waitlist")
        .unwrap_or_else(|| panic!("/__health does not list waitlist: {body}"));

    // The version is the mounted module's own, read back off the wire. It is
    // not compared against a constant: it moves with every module bump, and a
    // test that broke on each one would only be busywork. What matters is
    // that health carries *a* version at all — an entry that lost it would
    // leave an operator with a name and no way to tell what answered.
    let version = entry["version"]
        .as_str()
        .unwrap_or_else(|| panic!("/__health lists waitlist with no version: {body}"));
    assert!(!version.is_empty(), "/__health lists waitlist with an empty version: {body}");

    // The port declaration is the load-bearing part: it is the waitlist
    // module's own, and it is what an operator reads to see which bindings a
    // deployment must actually provide.
    let required: Vec<&str> = entry["requires"]
        .as_array()
        .unwrap_or_else(|| panic!("/__health lists no requires for waitlist: {body}"))
        .iter()
        .filter_map(|port| port.as_str())
        .collect();
    assert!(required.contains(&"Database"), "waitlist needs a Database binding: {required:?}");
    assert!(required.contains(&"Mailer"), "waitlist needs a Mailer binding: {required:?}");
}
