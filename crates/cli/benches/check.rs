//! The check-path budget, measured through the real binary on the site
//! fixture — the documented example, so this times exactly what the site
//! shows. One cold sample (process start, parse, check, print), then warm
//! repeats; the p95 of those must stay under budget. `cargo bench -p
//! ks-cli --bench check` fails the CI `bench` job the moment one isn't.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What a cold check may take, all-in.
const COLD_BUDGET: Duration = Duration::from_secs(1);
/// What the 95th percentile of warm checks must stay under.
const WARM_P95_BUDGET: Duration = Duration::from_millis(100);
/// How many warm samples the p95 is taken over.
const WARM_RUNS: usize = 50;

fn main() {
    let exe = env!("CARGO_BIN_EXE_keepshipping");
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/site");

    let cold = timed(|| run(exe, dir));
    let mut warm: Vec<Duration> = (0..WARM_RUNS).map(|_| timed(|| run(exe, dir))).collect();
    warm.sort();
    let p95 = warm[WARM_RUNS * 95 / 100];

    println!("cold:  {cold:.3?} (budget {COLD_BUDGET:?})");
    println!("warm p95 of {WARM_RUNS}: {p95:.3?} (budget {WARM_P95_BUDGET:?})");
    assert!(cold < COLD_BUDGET, "cold check took {cold:.3?}, over the {COLD_BUDGET:?} budget");
    assert!(p95 < WARM_P95_BUDGET, "warm p95 {p95:.3?} is over the {WARM_P95_BUDGET:?} budget");
}

fn timed(body: impl FnOnce()) -> Duration {
    let start = Instant::now();
    body();
    start.elapsed()
}

/// One check of the site fixture. Exit code 1 is the expected outcome: the
/// fixture is wrong on purpose, and a hang here is a blown budget. The
/// report itself is dropped — the numbers are the point.
fn run(exe: &str, dir: &str) {
    let status = Command::new(exe)
        .arg("check")
        .current_dir(dir)
        .stdout(Stdio::null())
        .status()
        .expect("spawn keepshipping");
    assert_eq!(status.code(), Some(1), "the site fixture must check as failing");
}
