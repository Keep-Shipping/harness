//! Basic behaviour of the port fakes: scripted HTTP with policy enforcement,
//! a hand-advanced clock driving retry backoff, and sequential run ids.

use std::time::Duration;

use ks_core::ports::clock::Clock;
use ks_core::ports::http::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};
use ks_core::ports::id_gen::IdGen;
use ks_core::ports::secrets::{SecretRef, Secrets};
use ks_testing::clock::{FakeClock, conformance as clock_conformance};
use ks_testing::http::{FakeHttpClient, conformance as http_conformance};
use ks_testing::id_gen::{SequentialIdGen, conformance as id_gen_conformance};
use ks_testing::secrets::{FakeSecrets, conformance as secrets_conformance};
use ks_testing::{block_on, secrets};

fn get(url: &str) -> HttpRequest {
    HttpRequest::new(HttpMethod::Get, url)
}

fn ok(body: &[u8]) -> HttpResponse {
    HttpResponse { status: 200, headers: vec![], body: body.to_vec() }
}

#[test]
fn the_fake_http_client_serves_scripted_responses() {
    let client = FakeHttpClient::new()
        .with_allowed_host("api.example.com")
        .with_response(HttpMethod::Get, "https://api.example.com/v1/ping", ok(b"pong"))
        .with_response(
            HttpMethod::Post,
            "https://api.example.com/v1/things",
            HttpResponse { status: 201, headers: vec![], body: vec![] },
        );

    let ping = block_on(client.send(get("https://api.example.com/v1/ping")))
        .expect("the ping is scripted");
    assert_eq!((ping.status, ping.body.as_slice()), (200, b"pong".as_slice()));

    let create = block_on(client.send(get("https://api.example.com/v1/things")));
    // Scripted under POST; a GET for the same URL is unscripted.
    assert!(matches!(create, Err(HttpError::Transport { .. })), "{create:?}");

    let requests = client.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, HttpMethod::Get);
    assert_eq!(requests[1].method, HttpMethod::Get);
}

#[test]
fn the_fake_http_client_rejects_hosts_outside_the_policy() {
    let client = FakeHttpClient::new().with_allowed_host("api.example.com").with_response(
        HttpMethod::Get,
        "https://evil.example/steal",
        ok(b"stolen"),
    );

    // Not on the allowlist: refused before the scripted response is consulted,
    // and before any socket would have been opened.
    let error = block_on(client.send(get("https://evil.example/steal")))
        .expect_err("evil.example is not allowed");
    assert_eq!(error, HttpError::HostNotAllowed { host: "evil.example".to_string() }, "{error}");

    // The pure check agrees with what send reported.
    assert_eq!(
        client.policy().check("https://evil.example/steal"),
        Err(HttpError::HostNotAllowed { host: "evil.example".to_string() })
    );
    // And the allowed host gets through.
    assert_eq!(client.policy().check("https://api.example.com/v1/ping"), Ok(()));
}

#[test]
fn the_fake_http_client_enforces_the_response_size_cap() {
    let client = FakeHttpClient::new()
        .with_allowed_host("api.example.com")
        .with_max_response_bytes(4)
        .with_response(HttpMethod::Get, "https://api.example.com/big", ok(b"0123456789"))
        .with_response(HttpMethod::Get, "https://api.example.com/fits", ok(b"okay"));

    assert_eq!(
        block_on(client.send(get("https://api.example.com/big"))),
        Err(HttpError::ResponseTooLarge { limit: 4 })
    );
    let fits = block_on(client.send(get("https://api.example.com/fits")))
        .expect("4 bytes fit a 4-byte cap");
    assert_eq!(fits.body, b"okay");
}

#[test]
fn the_fake_http_client_can_script_a_timeout() {
    let client = FakeHttpClient::new().with_allowed_host("api.example.com").with_error(
        HttpMethod::Get,
        "https://api.example.com/slow",
        HttpError::Timeout { after: Duration::from_secs(30) },
    );
    let error = block_on(client.send(get("https://api.example.com/slow")))
        .expect_err("the slow endpoint is scripted to time out");
    assert_eq!(error, HttpError::Timeout { after: Duration::from_secs(30) });
}

#[test]
fn retries_with_backoff_run_on_the_fake_clock() {
    let url = "https://api.example.com/v1/flaky";
    let client = FakeHttpClient::new()
        .with_allowed_host("api.example.com")
        // Two failures, then success: the queue hands out entries in order and
        // repeats the last one.
        .with_error(HttpMethod::Get, url, HttpError::Timeout { after: Duration::from_secs(1) })
        .with_error(HttpMethod::Get, url, HttpError::Timeout { after: Duration::from_secs(1) })
        .with_response(HttpMethod::Get, url, ok(b"recovered"));

    let clock = FakeClock::new();
    let mut attempts = 0;
    let mut delay = Duration::from_secs(1);
    let response = loop {
        attempts += 1;
        match block_on(client.send(get(url))) {
            Ok(response) => break response,
            Err(error) => {
                assert_eq!(error, HttpError::Timeout { after: Duration::from_secs(1) });
                block_on(clock.sleep(delay));
                delay *= 2;
            }
        }
    };

    assert_eq!((attempts, response.body.as_slice()), (3, b"recovered".as_slice()));
    // The backoff schedule is explicit and instant: no test ever waits 3s.
    assert_eq!(clock.sleeps(), vec![Duration::from_secs(1), Duration::from_secs(2)]);
    assert_eq!(clock.elapsed_since_start(), Duration::from_secs(3));
}

#[test]
fn the_fake_clock_starts_fixed_and_only_moves_when_advanced() {
    let clock = FakeClock::new();
    let start = clock.now();
    assert_eq!(start, FakeClock::default_start());
    clock.advance(Duration::from_secs(10));
    assert_eq!(clock.now(), start + Duration::from_secs(10));
    assert!(clock.sleeps().is_empty(), "advance is not a sleep");
}

#[test]
fn the_sequential_id_gen_hands_out_distinct_ulids() {
    let id_gen = SequentialIdGen::new();
    let first = id_gen.run_id();
    let second = id_gen.run_id();
    assert_ne!(first, second);
    assert_eq!(first.as_str(), "00000000000000000000000001");
    assert_eq!(second.as_str(), "00000000000000000000000002");
    // They are real, canonical ULIDs: timestamp 0, random 1 and 2.
    assert_eq!(first, ks_core::ids::RunId::from_parts(0, 1));
}

#[test]
fn every_fake_passes_its_port_conformance_kit() {
    let resolver = FakeSecrets::new().with(SecretRef::new("env", "token"), b"x".to_vec());
    block_on(secrets_conformance(&resolver));

    let client = FakeHttpClient::new().with_allowed_host("api.example.com").with_response(
        HttpMethod::Get,
        "https://api.example.com/v1/ping",
        ok(b"pong"),
    );
    block_on(http_conformance(&client));

    block_on(clock_conformance(&FakeClock::new()));

    id_gen_conformance(&SequentialIdGen::new());

    // And the conformance kits are usable through the port traits.
    let dynamic: &dyn Secrets = &resolver;
    block_on(secrets::conformance(dynamic));
}
