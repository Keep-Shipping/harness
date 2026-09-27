//! Parse throughput check: build a ~500-line source from the fixtures, time
//! `ks_lang::parse` over it, and fail the run if the median exceeds 5 ms.
//!
//! Run with `cargo bench -p ks-lang`.

use std::time::Instant;

/// ~500 lines: the four site fixtures per generated site, varied with the
/// site index so no two copies are identical.
fn source() -> String {
    let hero = include_str!("../tests/fixtures/site-hero.ks");
    let block = include_str!("../tests/fixtures/site-block.ks");
    let policy = include_str!("../tests/fixtures/site-policy.ks");
    let decide = include_str!("../tests/fixtures/site-decide.ks");
    let mut src = String::new();
    for i in 0..9 {
        src.push_str(&format!("# generated site {i}\n"));
        src.push_str(&format!("site-{i}:\n"));
        for (name, body) in
            [("hero", hero), ("block", block), ("policy", policy), ("decide", decide)]
        {
            src.push_str(&format!("  {name}-{i}:\n"));
            for line in body.lines() {
                if line.starts_with('#') {
                    src.push_str(line);
                    src.push('\n');
                } else if line.is_empty() {
                    src.push('\n');
                } else {
                    src.push_str("  ");
                    src.push_str(line);
                    src.push('\n');
                }
            }
        }
    }
    src
}

fn main() {
    let src = source();
    let lines = src.lines().count();
    println!("parsing a {lines}-line, {} KiB source", src.len() / 1024);

    // Warmup (also proves the parse is clean enough to measure).
    for _ in 0..3 {
        drop(ks_lang::parse(&src));
    }

    let runs = 100;
    let mut times: Vec<u128> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        let parse = ks_lang::parse(&src);
        times.push(start.elapsed().as_micros());
        std::hint::black_box(parse);
    }
    times.sort();
    let median_us = times[times.len() / 2];
    println!("median over {runs} runs: {median_us} us");

    let budget_us = 5_000;
    if median_us > budget_us {
        eprintln!("FAIL: median {median_us} us exceeds the {budget_us} us budget");
        std::process::exit(1);
    }
}
