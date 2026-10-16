//! The test database's address, read from the connection string a person
//! pastes (`postgres://user:password@host:5432/dbname`). Pure: no socket, no
//! clock, and nothing here is ever printed. The password is the one value in
//! the wizard that must not reach a page, a log or a D1 row, so [`DbAddress`]
//! hides it in `Debug` and the wizard only ever hands the parts to GitHub's
//! Actions secrets, one at a time.

use std::fmt;

use percent_encoding::percent_decode_str;

use super::generate::DbKind;

/// PostgreSQL's default port, used when the string names none.
pub const POSTGRES_PORT: u16 = 5432;
/// MySQL's default port, used when the string names none.
pub const MYSQL_PORT: u16 = 3306;

/// One database connection, parsed. The password is kept only so it can be
/// sealed into a repository secret; `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct DbAddress {
    /// The engine, from the scheme.
    pub kind: DbKind,
    /// The host name or address.
    pub host: String,
    /// The port: the one named, else the engine's default.
    pub port: u16,
    /// The database name (the path, percent-decoded).
    pub database: String,
    /// The user name, percent-decoded.
    pub user: String,
    /// The password, percent-decoded. Never printed.
    pub password: String,
}

impl fmt::Debug for DbAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbAddress")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &"***")
            .finish()
    }
}

/// Why a connection string was refused. Each names only the part at fault;
/// none of them repeats the string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbUrlError {
    /// Nothing was pasted.
    Empty,
    /// The scheme is not `postgres`, `postgresql` or `mysql`.
    Scheme,
    /// The user name or password is missing or not valid text.
    Credentials,
    /// The host is missing or malformed.
    Host,
    /// The port is not a number.
    Port,
    /// The database name is missing.
    Database,
}

impl DbUrlError {
    /// The refusal in plain words, for the wizard to show.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Empty => "Paste the test database address, or leave the box blank.",
            Self::Scheme => "The test database address must start with postgres:// or mysql://.",
            Self::Credentials => {
                "The test database address needs a user name and a password before the @ sign."
            }
            Self::Host => "The test database address needs a host name after the @ sign.",
            Self::Port => "The port in the test database address must be a number.",
            Self::Database => {
                "The test database address needs a database name after the host, like /myapp."
            }
        }
    }
}

/// Parses a connection string. Query options (`?sslmode=require`) are
/// dropped: the wizard sets only the five values the workflow reads.
///
/// The user name and password are split at the last `@` and the first `:`
/// of what precedes it, so a password may carry a raw `:` or `@`; a raw `/`
/// in the password is not supported and reads as a missing host.
pub fn parse(text: &str) -> Result<DbAddress, DbUrlError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(DbUrlError::Empty);
    }
    let (scheme, rest) = text.split_once("://").ok_or(DbUrlError::Scheme)?;
    let (kind, default_port) = match scheme.to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" => (DbKind::Postgres, POSTGRES_PORT),
        "mysql" => (DbKind::MySql, MYSQL_PORT),
        _ => return Err(DbUrlError::Scheme),
    };
    let (userinfo, location) = rest.rsplit_once('@').ok_or(DbUrlError::Credentials)?;
    let (user, password) = userinfo.split_once(':').ok_or(DbUrlError::Credentials)?;
    let user = decode(user).ok_or(DbUrlError::Credentials)?;
    let password = decode(password).ok_or(DbUrlError::Credentials)?;
    if user.is_empty() || password.is_empty() {
        return Err(DbUrlError::Credentials);
    }

    let (authority, path) = location.split_once('/').ok_or(DbUrlError::Database)?;
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let database = decode(path).ok_or(DbUrlError::Database)?;
    if database.is_empty() {
        return Err(DbUrlError::Database);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, port.parse::<u16>().map_err(|_| DbUrlError::Port)?)
        }
        _ => (authority, default_port),
    };
    if host.is_empty() || host.contains([':', '[', ']', ' ', '\t']) {
        return Err(DbUrlError::Host);
    }
    Ok(DbAddress { kind, host: host.to_owned(), port, database, user, password })
}

/// Percent-decodes one part; `None` when the bytes are not UTF-8.
fn decode(part: &str) -> Option<String> {
    percent_decode_str(part).decode_utf8().ok().map(|text| text.into_owned())
}

/// The repository secrets the test database needs, by name, with the value
/// each carries. The port is text because every Actions secret is.
#[must_use]
pub fn secrets(address: &DbAddress) -> [(&'static str, String); 5] {
    [
        ("TEST_DB_HOST", address.host.clone()),
        ("TEST_DB_PORT", address.port.to_string()),
        ("TEST_DB_DATABASE", address.database.clone()),
        ("TEST_DB_USER", address.user.clone()),
        ("TEST_DB_PASSWORD", address.password.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_postgres_address_is_read_with_its_port_and_database() {
        let parsed = parse("postgres://app:s3cret@db.example.com:6543/myapp").expect("parses");
        assert_eq!(parsed.kind, DbKind::Postgres);
        assert_eq!(parsed.host, "db.example.com");
        assert_eq!(parsed.port, 6543);
        assert_eq!(parsed.database, "myapp");
        assert_eq!(parsed.user, "app");
        assert_eq!(parsed.password, "s3cret");
    }

    #[test]
    fn the_default_ports_apply_when_none_is_named() {
        let pg = parse("postgresql://u:p@host.example/db").expect("parses");
        assert_eq!((pg.kind, pg.port), (DbKind::Postgres, 5432));
        let my = parse("mysql://u:p@host.example/db").expect("parses");
        assert_eq!((my.kind, my.port), (DbKind::MySql, 3306));
    }

    #[test]
    fn user_and_password_are_percent_decoded() {
        let parsed = parse("postgres://me%40corp:p%40ss%2Fw%3Ard@host/db").expect("parses");
        assert_eq!(parsed.user, "me@corp");
        assert_eq!(parsed.password, "p@ss/w:rd");
    }

    #[test]
    fn a_raw_colon_or_at_in_the_password_is_kept() {
        let parsed = parse("postgres://u:pa:ss@x@host/db").expect("parses");
        assert_eq!(parsed.password, "pa:ss@x");
        assert_eq!(parsed.host, "host");
    }

    #[test]
    fn query_options_are_dropped() {
        let parsed = parse("postgres://u:p@host:5432/db?sslmode=require").expect("parses");
        assert_eq!(parsed.database, "db");
    }

    #[test]
    fn other_schemes_are_refused() {
        for text in ["http://u:p@h/db", "sqlite:///tmp/x.db", "mongodb://u:p@h/db", "u:p@h/db"] {
            assert_eq!(parse(text), Err(DbUrlError::Scheme), "{text}");
        }
    }

    #[test]
    fn each_missing_part_is_named_without_echoing_the_string() {
        assert_eq!(parse("   "), Err(DbUrlError::Empty));
        assert_eq!(parse("postgres://host/db"), Err(DbUrlError::Credentials));
        assert_eq!(parse("postgres://user@host/db"), Err(DbUrlError::Credentials));
        assert_eq!(parse("postgres://:pw@host/db"), Err(DbUrlError::Credentials));
        assert_eq!(parse("postgres://u:p@/db"), Err(DbUrlError::Host));
        assert_eq!(parse("postgres://u:p@host:port/db"), Err(DbUrlError::Host));
        assert_eq!(parse("postgres://u:p@host:99999/db"), Err(DbUrlError::Port));
        assert_eq!(parse("postgres://u:p@host"), Err(DbUrlError::Database));
        assert_eq!(parse("postgres://u:p@host/"), Err(DbUrlError::Database));
    }

    #[test]
    fn an_invalid_utf8_escape_is_refused_as_credentials() {
        assert_eq!(parse("postgres://u:%FF@host/db"), Err(DbUrlError::Credentials));
    }

    #[test]
    fn the_debug_form_never_shows_the_password() {
        let parsed = parse("postgres://app:hunter2@host/db").expect("parses");
        let shown = format!("{parsed:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("***"));
    }

    #[test]
    fn the_secrets_carry_the_parts_with_a_text_port() {
        let parsed = parse("mysql://app:pw@host/shop").expect("parses");
        let names: Vec<(&str, String)> = secrets(&parsed).into_iter().collect();
        assert_eq!(names[1], ("TEST_DB_PORT", "3306".to_owned()));
        assert_eq!(names[4], ("TEST_DB_PASSWORD", "pw".to_owned()));
        assert_eq!(names.len(), 5);
    }
}
