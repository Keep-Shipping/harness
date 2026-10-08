//! The `keepshipping about` command and `--version`: what Keep Shipping itself
//! is built with, from the venture's entry in the Factory Zero registry
//! ([#178](https://github.com/Keep-Shipping/harness/issues/178)). The entry is
//! vendored into `ks-core` — nothing here fetches anything — so the report and
//! the version line are as offline as the rest of the binary, and every entry
//! is labelled `live` or `planned` exactly as the registry says.

use std::io::Write;
use std::process::ExitCode;

use ks_core::built_with;

use crate::args::USAGE;

/// The entry point for `keepshipping about`.
///
/// 0 for a report printed; 2 for any argument at all — the command takes none;
/// 1 when stdout could not be written.
pub fn about(args: &[String]) -> ExitCode {
    if let Some(arg) = args.first() {
        return unexpected_argument(arg);
    }
    let mut out = std::io::stdout().lock();
    if let Err(message) = out.write_all(render().as_bytes()) {
        eprintln!("error: writing the report failed ({message})");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The entry point for `keepshipping --version`: the version, and the same
/// built-with summary `about` reports, on one line.
///
/// 0 for the two lines printed; 2 for any argument at all — what a script
/// reads back off the installed file must not depend on what else was passed;
/// 1 when stdout could not be written.
pub fn version(args: &[String]) -> ExitCode {
    if let Some(arg) = args.first() {
        return unexpected_argument(arg);
    }
    let mut out = std::io::stdout().lock();
    if let Err(message) = out.write_all(version_text().as_bytes()) {
        eprintln!("error: writing the version failed ({message})");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn unexpected_argument(arg: &str) -> ExitCode {
    eprintln!("error: unexpected argument '{arg}'");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// `--version`'s two lines: the version, then the built-with summary.
fn version_text() -> String {
    format!("keepshipping {}\nBuilt with: {}\n", env!("CARGO_PKG_VERSION"), built_with::summary())
}

/// The report: the venture header, one padded row per use — phrase, name,
/// status, link, with the note under the row, indented to the name column —
/// then the subprocessors link and where the data came from. Column widths
/// are computed from the entry, so a longer name the registry adds later
/// lines up without anyone re-measuring.
fn render() -> String {
    let venture = built_with::venture();
    let phrase_w = venture.uses.iter().map(|u| u.phrase.chars().count()).max().unwrap_or(0);
    let name_w = venture.uses.iter().map(|u| u.name.chars().count()).max().unwrap_or(0);
    let status_w =
        venture.uses.iter().map(|u| u.status.as_str().chars().count()).max().unwrap_or(0);
    let note_pad = " ".repeat(2 + phrase_w + 2);

    let mut out = format!("{} ({})\n{}\n\nBuilt with\n", venture.name, venture.id, venture.site);
    for u in &venture.uses {
        out.push_str(&format!(
            "  {phrase:<phrase_w$}  {name:<name_w$}  {status:<status_w$}  {url}\n{note_pad}{note}\n",
            phrase = u.phrase,
            name = u.name,
            status = u.status.as_str(),
            url = u.url,
            note = u.note,
        ));
    }
    out.push_str(&format!("\nSubprocessors: {}\n", built_with::SUBPROCESSORS_URL));
    out.push_str(&format!(
        "Source: vendored from {} (no network at runtime).\n",
        built_with::REGISTRY_URL
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use ks_core::built_with::Status;

    /// The report is headed by the venture, names the subprocessors list, and
    /// says where the data came from.
    #[test]
    fn the_report_is_headed_and_signed() {
        let report = render();
        assert!(report.starts_with("Keep Shipping (FZ-012)\nhttps://keepshipping.run/\n\n"));
        assert!(
            report.contains("Subprocessors: https://factory0.ventures/ventures/keep-shipping/\n")
        );
        assert!(report.contains(
            "Source: vendored from https://factory0.ventures/stack.json (no network at runtime).\n"
        ));
    }

    /// Every use is rendered on its phrase row with the status the registry
    /// gave it — and never the other word — so a `planned` entry cannot drift
    /// into reading as live.
    #[test]
    fn every_use_carries_its_own_status_and_no_other() {
        let report = render();
        for u in &built_with::venture().uses {
            let line = report
                .lines()
                .find(|line| line.contains(&u.url))
                .unwrap_or_else(|| panic!("{} is not rendered", u.name));
            assert!(line.contains(u.status.as_str()), "{line}");
            let other = match u.status {
                Status::Live => Status::Planned,
                Status::Planned => Status::Live,
            };
            assert!(!line.contains(other.as_str()), "{line}");
        }
    }

    /// The row itself: phrase, name and status padded into columns, the note
    /// under the row at the name column.
    #[test]
    fn a_row_lines_up_and_carries_its_note() {
        let venture = built_with::venture();
        let cratefield = venture.uses.first().expect("at least one use");
        let report = render();
        let row = report
            .lines()
            .find(|line| line.contains(&cratefield.url))
            .expect("the first use is rendered");
        let expected = format!(
            "  {:<14}  {:<13}  {:<7}  {}",
            cratefield.phrase,
            cratefield.name,
            cratefield.status.as_str(),
            cratefield.url
        );
        assert_eq!(row, expected);
        let note = report
            .lines()
            .nth(report.lines().position(|line| line == row).expect("the row") + 1)
            .expect("the note follows the row");
        assert_eq!(note, format!("{}{}", " ".repeat(2 + 14 + 2), cratefield.note));
    }

    /// `--version` is exactly two lines: the version, then the summary.
    #[test]
    fn the_version_is_two_lines() {
        let text = version_text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0], format!("keepshipping {}", env!("CARGO_PKG_VERSION")));
        assert_eq!(lines[1], format!("Built with: {}", built_with::summary()));
    }
}
