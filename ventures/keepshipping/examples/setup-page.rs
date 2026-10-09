//! The Standard setup console as a static site (issue #273): runs the real
//! module over the testing kit's scripted DNS fake and writes the pages it
//! renders to `target/setup-site/`, so the checklist — its chips, its
//! polling script, its forms — can be walked in a browser with
//!
//! ```text
//! cargo run -p keepshipping-waitlist --example setup-page
//! python3 -m http.server -d target/setup-site 8080
//! # then open http://localhost:8080/v1/setup/
//! ```
//!
//! Two domains tell the story: `example.test`, mid-setup (nothing live
//! yet), and `done.example.test`, where every record answers and the
//! outside services are confirmed. No GitHub is connected — the pages say
//! so honestly.

use cratefield_core::axum::body::Bytes;
use cratefield_testing::{FakeAuth, FakeHttpClient, TestHarness, request_as};
use http::{Method, StatusCode};
use keepshipping_waitlist::{Setup, venture};
use std::sync::Arc;

/// One DoH answer carrying the given TXT chunks, quoted the way Cloudflare
/// frames them.
fn doh(records: &[&str]) -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    let answers: Vec<serde_json::Value> = records
        .iter()
        .map(|data| serde_json::json!({"name": "x", "type": 16, "data": format!("\"{data}\"")}))
        .collect();
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Bytes::from(serde_json::json!({ "Status": 0, "Answer": answers }).to_string()))
        .expect("a scripted response builds"))
}

fn no_records() -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Bytes::from(r#"{"Status": 0, "Answer": []}"#))
        .expect("a scripted response builds"))
}

fn text_response(body: &str) -> Result<http::Response<Bytes>, cratefield_core::HttpError> {
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Bytes::from(body.to_owned()))
        .expect("a scripted response builds"))
}

/// One DNS board where nothing is live: apex, dkim, dmarc, mta-sts, tls.
fn nothing_live() -> Vec<Result<http::Response<Bytes>, cratefield_core::HttpError>> {
    vec![no_records(), no_records(), no_records(), no_records(), no_records()]
}

/// The board of a fully-set-up domain: SPF and the Search Console
/// verification token on the apex, DKIM, DMARC, the MTA-STS record plus
/// its answering policy page, and TLS-RPT.
fn everything_live() -> Vec<Result<http::Response<Bytes>, cratefield_core::HttpError>> {
    vec![
        doh(&["\"v=spf1 include:_spf.google.com ~all\"", "\"google-site-verification=done-123\""]),
        doh(&["\"v=DKIM1; k=rsa; p=MIIBIjANBgkq\""]),
        doh(&["\"v=DMARC1; p=none; rua=mailto:dmarc-reports@done.example.test\""]),
        doh(&["\"v=STSv1; id=20261009\""]),
        text_response("version: STSv1\nmode: testing\nmx: smtp.google.com\nmax_age: 604800\n"),
        doh(&["\"v=TLSRPTv1; rua=mailto:tls-reports@done.example.test\""]),
    ]
}

/// The checklist form with everything on and Google's DKIM key pasted.
const ALL_ON: &str = "search_console=on&postmaster=on&bing=on&spf=on&dkim=on&dmarc=on\
     &mta_sts=on&tls_rpt=on\
     &spf_value=v%3Dspf1+include%3A_spf.google.com+~all\
     &dkim_selector=google\
     &dkim_key=v%3DDKIM1%3B+k%3Drsa%3B+p%3DMIIBIjANBgkq\
     &dmarc_rua=mailto%3Admarc-reports%40done.example.test\
     &sitemap_url=https%3A%2F%2Fdone.example.test%2Fsitemap.xml";

#[pollster::main]
async fn main() {
    let http = FakeHttpClient::scripted({
        let mut script = nothing_live(); // example.test page
        script.extend(nothing_live()); // example.test status
        script.extend(everything_live()); // done.example.test page
        script.extend(everything_live()); // done.example.test status
        script
    });
    let kit = TestHarness::with_builder(
        vec![Box::new(Setup::new(None))],
        |builder| builder.venture(venture()),
        |ports| {
            ports.auth = Some(Arc::new(FakeAuth::subjects()));
            ports.http = Some(Arc::new(http));
        },
    );

    // The index.
    let index = request_as(&kit.router, Method::GET, "/v1/setup", "acc_1", None).await;
    assert_eq!(index.status, StatusCode::OK, "the index renders");

    // example.test: a first view (which seeds it), then the status poll.
    let mid = request_as(&kit.router, Method::GET, "/v1/setup/example.test", "acc_1", None).await;
    assert_eq!(mid.status, StatusCode::OK, "the checklist renders");
    let mid_status =
        request_as(&kit.router, Method::GET, "/v1/setup/example.test/status", "acc_1", None).await;
    assert_eq!(mid_status.status, StatusCode::OK, "the status answers");

    // done.example.test: send the change (no GitHub: saved, honestly
    // unfiled), confirm the three outside services, then read the board.
    let sent =
        request_as(&kit.router, Method::POST, "/v1/setup/done.example.test", "acc_1", Some(ALL_ON))
            .await;
    assert_eq!(sent.status, StatusCode::SEE_OTHER, "the change is saved");
    for item in ["search_console", "postmaster", "bing"] {
        let confirmed = request_as(
            &kit.router,
            Method::POST,
            "/v1/setup/done.example.test/confirmed",
            "acc_1",
            Some(&format!("item={item}")),
        )
        .await;
        assert_eq!(confirmed.status, StatusCode::SEE_OTHER, "{item} confirmed");
    }
    let done = request_as(
        &kit.router,
        Method::GET,
        "/v1/setup/done.example.test?note=saved",
        "acc_1",
        None,
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "the finished checklist renders");
    let done_status =
        request_as(&kit.router, Method::GET, "/v1/setup/done.example.test/status", "acc_1", None)
            .await;
    assert_eq!(done_status.status, StatusCode::OK, "the finished status answers");

    // Write the tree the page's own absolute fetches expect: the browser
    // asks for `/v1/setup/...` from the server root.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/setup-site");
    let write = |path: &str, body: &[u8]| {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the directory builds");
        std::fs::write(&path, body).expect("the page writes");
        println!("wrote {}", path.display());
    };
    write("v1/setup/index.html", index.body());
    write("v1/setup/example.test/index.html", mid.body());
    write("v1/setup/example.test/status.json", mid_status.body());
    // The page's script fetches `{here}/status`; the extensionless copy
    // keeps the static site honest to that.
    write("v1/setup/example.test/status", mid_status.body());
    write("v1/setup/done.example.test/index.html", done.body());
    write("v1/setup/done.example.test/status.json", done_status.body());
    write("v1/setup/done.example.test/status", done_status.body());
    println!("\nServe it: python3 -m http.server -d target/setup-site 8080");
    println!("Then open http://localhost:8080/v1/setup/");
}
