//! The check-path budget, measured through the real binary on the site
//! fixture — the documented example, so this times exactly what the site
//! shows — and on the script fixture, where a check also reads a TypeScript
//! module. One cold sample (process start, parse, check, print), then warm
//! repeats; the p95 of those must stay under budget. `cargo bench -p
//! ks-cli --bench check` fails the CI `bench` job the moment one isn't.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What a cold check may take, all-in.
const COLD_BUDGET: Duration = Duration::from_secs(1);
/// What the 95th percentile of warm checks must stay under.
const WARM_P95_BUDGET: Duration = Duration::from_millis(100);
/// How many warm samples the p95 is taken over.
const WARM_RUNS: usize = 50;

/// What a cold check of a site with a script step may take. It runs `node`,
/// so it has a budget of its own rather than the bare site's. ubuntu-latest
/// measures ~85 ms with Node 22 pinned in the bench job; the 0.7-1 s seen
/// before came from the runner's unpinned default Node, not the checker.
const SCRIPT_COLD_BUDGET: Duration = Duration::from_millis(500);
/// …and what its warm checks, which read the cache and spawn nothing, must
/// stay under. The bare site's budget would hide what this one is for.
const SCRIPT_WARM_P95_BUDGET: Duration = Duration::from_millis(50);

fn main() {
    let exe = env!("CARGO_BIN_EXE_keepshipping");
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/site");

    let cold = timed(|| run(exe, dir, 1));
    let p95 = p95((0..WARM_RUNS).map(|_| timed(|| run(exe, dir, 1))).collect());

    println!("cold:  {cold:.3?} (budget {COLD_BUDGET:?})");
    println!("warm p95 of {WARM_RUNS}: {p95:.3?} (budget {WARM_P95_BUDGET:?})");
    assert!(cold < COLD_BUDGET, "cold check took {cold:.3?}, over the {COLD_BUDGET:?} budget");
    assert!(p95 < WARM_P95_BUDGET, "warm p95 {p95:.3?} is over the {WARM_P95_BUDGET:?} budget");

    script(exe);
}

/// The script fixture, cold and warm. Reading a module is a subprocess the
/// first time and a file read every time after; the budget is what keeps
/// that honest. Skipped, with a note, where there is no `node` to skip.
fn script(exe: &str) {
    let has_node =
        Command::new("node").arg("--version").output().is_ok_and(|out| out.status.success());
    if !has_node {
        println!("script: skipped, no node");
        return;
    }
    // Copied out of the repository first: a cold run writes a cache beside
    // the site file, and the checkout is not somewhere to write one.
    let dir =
        std::env::temp_dir().join(format!("keepshipping-bench-script-{}", std::process::id()));
    copy(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/script"), &dir);
    let dir = dir.to_string_lossy().into_owned();

    let cold = timed(|| run(exe, &dir, 0));
    // Warm: the cache is written, so no run spawns node again.
    let p95 = p95((0..WARM_RUNS).map(|_| timed(|| run(exe, &dir, 0))).collect());

    println!("script cold:  {cold:.3?} (budget {SCRIPT_COLD_BUDGET:?})");
    println!("script warm p95 of {WARM_RUNS}: {p95:.3?} (budget {SCRIPT_WARM_P95_BUDGET:?})");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(cold < SCRIPT_COLD_BUDGET, "cold script check took {cold:.3?}");
    assert!(p95 < SCRIPT_WARM_P95_BUDGET, "warm script p95 {p95:.3?} is over budget");
}

/// The 95th percentile of `samples`, which sorting them by duration names.
fn p95(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() * 95 / 100]
}

/// `from`, whole, at `to` — which need not exist yet. The signature cache is
/// left behind: a cache copied from a previous local run would turn the
/// "cold" sample into a warm one.
fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the copy");
    for entry in std::fs::read_dir(from).expect("read the fixture") {
        let entry = entry.expect("a fixture entry");
        if entry.file_name() == ".keepshipping" {
            continue;
        }
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy the fixture file");
        }
    }
}

fn timed(body: impl FnOnce()) -> Duration {
    let start = Instant::now();
    body();
    start.elapsed()
}

/// One check of a fixture. The site fixture is wrong on purpose and exits 1;
/// the script fixture is right and exits 0. Either way a hang here is a
/// blown budget. The report itself is dropped — the numbers are the point.
fn run(exe: &str, dir: &str, expect: i32) {
    let status = Command::new(exe)
        .arg("check")
        .current_dir(dir)
        .stdout(Stdio::null())
        .status()
        .expect("spawn keepshipping");
    assert_eq!(status.code(), Some(expect), "{dir} must check as expected");
}
