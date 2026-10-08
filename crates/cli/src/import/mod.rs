//! The `import` subcommands: turning something that already exists into a
//! starting `.ks` file. Today `import shell` is the only one — it reads a
//! deployment shell script, recognises the commands keepshipping has a step
//! kind for, and writes out the file those become.
//!
//! Import is a **best effort**, and says so. A shell script is not a
//! pipeline: it branches, it loops, it holds values in variables. `.ks` has
//! none of those. So the converter recognises the well-known deploy commands,
//! emits real typed steps for them, and puts everything it could not recognise
//! — and every piece of control flow, which has no home in `.ks` at all — into
//! one script step the operator has to write. It never guesses: an unrecognised
//! command is reported by line, not quietly dropped.
//!
//! Exit codes follow the house rules: 0 when the file was written, 2 for a
//! usage problem or a script that cannot be read, 2 when the output file
//! already exists (this command writes, it does not overwrite), and 1 when the
//! output cannot be written.

mod shell;

use std::process::ExitCode;

use crate::args::USAGE;

/// The entry point for `keepshipping import <subcommand>`.
pub fn import(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("shell") => shell::shell(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
