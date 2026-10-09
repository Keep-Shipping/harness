//! The Search Console console (issue #274) on a laptop: the same module the
//! worker mounts, over a scripted Google that always says the domain is
//! verified and the sitemap is in, a throwaway service-account document the
//! real JWT flow signs with, a clock that reads the wall clock, and a dev
//! auth that calls everyone `dev-operator`. Nothing here touches real
//! Google — to try it for real, set the secret in the worker instead.
//!
//! ```text
//! cargo run -p keepshipping-waitlist --example gsc_dev
//! # then open http://127.0.0.1:8787/v1/console/search-console?zone=example.com
//! ```

use cratefield_core::axum::body::Bytes;
use cratefield_core::{Auth, AuthError, Caller, Clock, HttpClient, HttpError, Subject};
use cratefield_testing::TestHarness;
use http::{HeaderMap, StatusCode};
use keepshipping_waitlist::{Gsc, gsc_module, venture};
use std::sync::Arc;

/// Everyone is `dev-operator`: this server exists to look at the page, not
/// to gate it. The production worker never mounts this — its auth port
/// names real callers.
struct DevAuth;

#[async_trait::async_trait]
impl Auth for DevAuth {
    async fn identify(&self, _headers: &HeaderMap) -> Result<Caller, AuthError> {
        Ok(Caller::Subject(Subject::new("dev-operator")))
    }
}

/// The wall clock, so `Last checked` moves as the page is reloaded.
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

/// A throwaway RSA-2048 key body, generated once for this example: it
/// signs the dev JWT assertion and opens nothing. Wrapped at 64 columns
/// like any PEM, and embedded in the service-account document below as
/// `\n` escapes — exactly the shape a Google-issued key file has, so the
/// page's reads run the real auth flow end to end.
const DEV_KEY_BODY: &str = "\
     MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCh9fZyAcq+ddM7\n\
     LKwlTr/pGe3jIqzpSPfJKe2SIQtiidGNS+TpB8bGF2EGCHrBIscDXtlaGj9OiVfY\n\
     Ir6Cb5WzU7OR8pZMeFDcKoNeEYsR5nTzRpGV26TvRAfNDcG58eJTPNSOaP7aRK6F\n\
     +zl33ywO1YpiLrQYop86MgqJIaYaWCTrN3Egv3VpOHM5e7/DbLGr/B/Adrfn0XjF\n\
     VyPoLWKeOzRYyZ7xHy/5nrEN4Jxmc2k0cyTHclXu6tNHh/JVa65mtnImB0T+l69U\n\
     7URAQM5kOBwWKXNGjHYY/LTGd+NYRlMXrPipnsVGPx7+u73juNo2wH71lnghU+wc\n\
     36W0wXJ/AgMBAAECggEABSZC3a7PMEjHU2V37f+8acAPTRUvKIOq1lSJg755ywyL\n\
     3og27G5mlGCkxfAMOWYXrBAMP2BJHwAgnpiefXafWm/+kMLOEI2BncwkPSABGNBQ\n\
     /eMnFCBn9Kb6gs2rK3RUgY9K/2Hdg/A5YgZNZAhOepbVz9MPLR8OirCRw3i0adzS\n\
     mG1plKvv545kZFp1DYauRVmX1GsDkl60QrEUunADn4rz7zg7KmBOq3vijf2P3hdA\n\
     brl58CzrNT22jLLpp5BpfMIJi9B7v2qpE+jX5MmqUPptEI9kaHp3Q5pcmbElhR40\n\
     2+BroTanA4LzK2BcSEUADGm1/vOKBeYi1271xhHcAQKBgQDdLSGpLb/8s4irVcme\n\
     QUPnghocChY0cNuZrRFfMbk5FpkO2jTiFilmmzTvHMMrwXYjOuwTIEG6jla55Gkd\n\
     socgoXV9mzcIEIHiNHqjbX1NnZndIOOXq5QgF+2qCG1gEg+1t9G+AwuxJKajytcL\n\
     pMi2Y4RB9q45EZkO3tZd04VdfwKBgQC7dg3zyA6Zl6xG5xoJOERVsN4LHhsDNPg3\n\
     T3+5HjHYx3LSodacu4DNklTL/xJChx7NQub97vBOKwE47bMYAkrRTcETak4iDdZq\n\
     j2FY1sjO54XhODEQT0Ctk1cd5spoY3yudX9kbp9EKnsfVdwaYwGC9DDQn81p9IGX\n\
     gxtHwNhrAQKBgC+JscBxCuC/ndJln+4ZzQSHXCFGsbsXvrtrDV7OiycQClm84Lzv\n\
     UnqxRVFXd0OCU2gDFBaQSlBUo6NUypsNcim7Skty/wMGuUPrT6issc/q3dU/amuA\n\
     /1dejUCMiyWo/CNsnPIgKXUrkX2G7W2dP16kSRr8cDnn5GPj1WNZQUL1AoGBAJsT\n\
     azFbMzC+NyckcPZllKoquVULH5+Ehz4CRw+Vufix7fvvI8HenwvwXLOxG6LrcoCt\n\
     MreonSSdENLOWJSo+Mmy/+EW1PH47oKSgB5k+BOplagduwDZ/xBYTf4PeSvn+TG9\n\
     Q5iKprhWSCpA9ebiNlLlvSgoul5HhZkYPU4bay0BAoGAQOYhuA9UAxWDF/HNeMfg\n\
     59cdIDB2oY9PoOVamgEpBtcp7FcH34HQKoyacwsj21KsXD8MPh4IbTc7gBba75OO\n\
     NC3MoM1FfBZT7NRNE2RMXk1orgI1y2quejX57dRd3tW94EvDYI+8dCx0k0djla8w\n\
     N/HAkXwNlwG6VDKFA7HKb6Y=\n\
     ";

/// The service-account document the dev secret is: same fields, the key
/// re-escaped as JSON `\n`s, no reality.
fn dev_service_account() -> String {
    let key = DEV_KEY_BODY.replace('\n', "\\n");
    format!(
        r#"{{"client_email":"dev@keepshipping-dev.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\n{key}-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}}"#
    )
}

/// A canned Google that answers forever, by request shape: the token
/// exchange mints a token, `sites.get` says the service account owns the
/// property, `sitemaps.list` has the sitemap. Reload the page as often as
/// you like — unlike the test kit's scripted fake, this never runs dry.
struct CannedGoogle;

fn ok_json(body: &str) -> Result<http::Response<Bytes>, HttpError> {
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Bytes::from(body.to_owned()))
        .expect("a canned response builds"))
}

#[async_trait::async_trait]
impl HttpClient for CannedGoogle {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let uri = request.uri().to_string();
        if uri.contains("oauth2.googleapis.com/token") {
            ok_json(r#"{"access_token":"ya29.dev-token","expires_in":3599,"token_type":"Bearer"}"#)
        } else if uri.ends_with("/sitemaps") {
            ok_json(r#"{"sitemap":[{"path":"https://example.com/sitemap.xml","type":"sitemap"}]}"#)
        } else {
            ok_json(r#"{"siteUrl":"sc-domain:example.com","permissionLevel":"siteOwner"}"#)
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let module = gsc_module(Gsc::new(
        Arc::new(CannedGoogle),
        Arc::new(SystemClock),
        Some(dev_service_account()),
    ));
    let kit = TestHarness::with_builder(
        vec![Box::new(module)],
        |builder| builder.venture(venture()),
        |ports| ports.auth = Some(Arc::new(DevAuth)),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8787").await?;
    println!("the Search Console console: http://127.0.0.1:8787/v1/console/search-console");
    println!("the JSON twin:              http://127.0.0.1:8787/v1/console/gsc?zone=example.com");
    // The kit owns its ports (it has a `Drop`), so the router is borrowed
    // out by clone.
    axum::serve(listener, kit.router.clone()).await
}
