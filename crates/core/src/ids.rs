//! Identifiers shared by the engine and the ports: steps and runs.
//!
//! Ids are plain printable names — never secret, safe to log and to put in
//! diagnostics. [`RunId`] is a [ULID](https://github.com/ulid/spec): its 48-bit
//! timestamp keeps runs sortable, and its 80-bit random part keeps ids unique
//! across machines without a coordinator.

use std::fmt;

/// The name of one step within a workflow, e.g. `build-image`.
///
/// Uniqueness (and the naming rules) are the checker's job; this type only
/// carries the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepId(String);

impl StepId {
    /// Creates a step id from any string-like value.
    pub fn new(id: impl Into<String>) -> StepId {
        StepId(id.into())
    }

    /// The step name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StepId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A unique identifier for one run: a 26-character Crockford base32 ULID.
///
/// Layout is the standard one — 48 bits of Unix milliseconds followed by 80
/// bits of randomness, big-endian, so the textual form sorts by creation time.
/// Use [`IdGen`](crate::ports::id_gen::IdGen) to mint one; this type does the
/// pure encoding and decoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId(String);

impl RunId {
    /// The Crockford base32 alphabet used by the ULID spec (no `I`, `L`, `O`
    /// or `U`).
    const ALPHABET: &'static [u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    /// A ULID is always 26 characters.
    const ENCODED_LEN: usize = 26;
    /// Width of the random field.
    const RANDOM_BITS: u32 = 80;
    /// `unix_millis` and `random` are masked to these widths before encoding.
    const TIME_MASK: u64 = (1 << 48) - 1;
    const RANDOM_MASK: u128 = (1 << 80) - 1;

    /// Encodes a ULID from its two fields (pure; no clock, no randomness).
    ///
    /// `unix_millis` is masked to its low 48 bits and `random` to its low 80
    /// bits, so over-wide inputs encode deterministically instead of
    /// wrapping into a different time field.
    pub fn from_parts(unix_millis: u64, random: u128) -> RunId {
        let value = (u128::from(unix_millis & Self::TIME_MASK) << Self::RANDOM_BITS)
            | (random & Self::RANDOM_MASK);
        let mut chars = [b'0'; Self::ENCODED_LEN];
        chars[0] = Self::ALPHABET[((value >> 125) & 0x7) as usize];
        for (index, slot) in chars.iter_mut().skip(1).enumerate() {
            let shift = 120 - 5 * index;
            *slot = Self::ALPHABET[((value >> shift) & 0x1F) as usize];
        }
        RunId(String::from_utf8(chars.to_vec()).expect("the ULID alphabet is ASCII"))
    }

    /// Decodes and canonicalises a textual ULID.
    ///
    /// The 32 canonical characters are accepted case-insensitively; anything
    /// else — including the letters Crockford decoding sometimes maps onto
    /// other digits (`I`, `L`, `O`, `U`) — is rejected, so a typo never
    /// silently reads a different id. The first character encodes only 3 bits,
    /// so a value above `7` there is rejected as overflow.
    pub fn parse(text: &str) -> Result<RunId, InvalidRunId> {
        let bytes = text.as_bytes();
        if bytes.len() != Self::ENCODED_LEN {
            return Err(InvalidRunId::WrongLength { len: bytes.len() });
        }
        let mut value: u128 = 0;
        for (position, &byte) in bytes.iter().enumerate() {
            let digit = Self::decode_char(byte)
                .ok_or(InvalidRunId::InvalidChar { position, character: char::from(byte) })?;
            if position == 0 && digit > 7 {
                return Err(InvalidRunId::Overflow { character: char::from(byte) });
            }
            value =
                if position == 0 { u128::from(digit) } else { (value << 5) | u128::from(digit) };
        }
        Ok(RunId::from_parts((value >> Self::RANDOM_BITS) as u64, value & Self::RANDOM_MASK))
    }

    /// Maps one ASCII byte onto its alphabet index, case-insensitively.
    fn decode_char(byte: u8) -> Option<u8> {
        let upper = byte.to_ascii_uppercase();
        Self::ALPHABET.iter().position(|&candidate| candidate == upper).map(|index| index as u8)
    }

    /// The canonical uppercase textual form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a string is not a valid [`RunId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidRunId {
    /// Not 26 characters.
    WrongLength {
        /// The number of characters that were supplied.
        len: usize,
    },
    /// A character outside the Crockford base32 alphabet (case-insensitive).
    InvalidChar {
        /// Zero-based position of the offending character.
        position: usize,
        /// The offending character.
        character: char,
    },
    /// The first character encodes bits above bit 127 (its value exceeds 7).
    Overflow {
        /// The offending first character.
        character: char,
    },
}

impl fmt::Display for InvalidRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidRunId::WrongLength { len } => {
                write!(f, "a run id is 26 characters, got {len}")
            }
            InvalidRunId::InvalidChar { position, character } => {
                write!(f, "character {position} ({character:?}) is not in the ULID alphabet")
            }
            InvalidRunId::Overflow { character } => {
                write!(
                    f,
                    "first character {character:?} would overflow a ULID (it must encode a value of 7 or less)"
                )
            }
        }
    }
}

impl std::error::Error for InvalidRunId {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec-ecosystem vector `01ARZ3NDEKTSV4RRFFQ69G5FAV`, decoded
    /// independently: timestamp 1469922850259 ms, random 0xd6764c61efb99302bd5b.
    const KNOWN: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    #[test]
    fn encodes_the_known_vector() {
        let run = RunId::from_parts(1_469_922_850_259, 0xd676_4c61_efb9_9302_bd5b);
        assert_eq!(run.as_str(), KNOWN);
        assert_eq!(run.to_string(), KNOWN);
    }

    #[test]
    fn parses_the_known_vector() {
        let run = RunId::parse(KNOWN).expect("the known vector is a valid ULID");
        assert_eq!(run.as_str(), KNOWN);
        assert_eq!(run, RunId::from_parts(1_469_922_850_259, 0xd676_4c61_efb9_9302_bd5b));
    }

    #[test]
    fn round_trips_in_both_directions() {
        let run = RunId::from_parts(1_700_000_000_000, 0x0123_4567_89ab_cdef_0123);
        let parsed = RunId::parse(run.as_str()).expect("a generated id parses");
        assert_eq!(parsed, run);
        assert_eq!(parsed.as_str(), run.as_str());
    }

    #[test]
    fn encodes_the_extremes() {
        assert_eq!(RunId::from_parts(0, 0).as_str(), "0".repeat(26));
        assert_eq!(
            RunId::from_parts((1 << 48) - 1, (1 << 80) - 1).as_str(),
            "7".to_string() + &"Z".repeat(25)
        );
    }

    #[test]
    fn masks_over_wide_fields() {
        assert_eq!(RunId::from_parts(1 << 48, 0), RunId::from_parts(0, 0));
        assert_eq!(RunId::from_parts(0, 1 << 80), RunId::from_parts(0, 0));
    }

    #[test]
    fn parse_accepts_lowercase_and_canonicalises() {
        let run = RunId::parse(&KNOWN.to_ascii_lowercase()).expect("lowercase ULIDs decode");
        assert_eq!(run.as_str(), KNOWN);
    }

    #[test]
    fn parse_rejects_bad_lengths() {
        assert_eq!(RunId::parse(""), Err(InvalidRunId::WrongLength { len: 0 }));
        assert_eq!(RunId::parse(&"0".repeat(25)), Err(InvalidRunId::WrongLength { len: 25 }));
        assert_eq!(RunId::parse(&"0".repeat(27)), Err(InvalidRunId::WrongLength { len: 27 }));
    }

    #[test]
    fn parse_rejects_bad_characters() {
        for (position, character) in [(2, 'U'), (5, 'I'), (9, 'L'), (12, 'O'), (3, 'u'), (7, '!')] {
            let mut text: Vec<u8> = b"0".repeat(26);
            text[position] = character as u8;
            let text = String::from_utf8(text).expect("ASCII only");
            assert_eq!(
                RunId::parse(&text),
                Err(InvalidRunId::InvalidChar { position, character }),
                "expected {character:?} at {position} to be rejected"
            );
        }
    }

    #[test]
    fn parse_rejects_first_character_overflow() {
        // '8' and '9' are valid alphabet digits, but only 3 bits fit in the
        // first character; so are letters above '7' such as 'A' and 'Z'.
        for character in ['8', '9', 'A', 'Z'] {
            let mut text: Vec<u8> = b"0".repeat(26);
            text[0] = character as u8;
            let text = String::from_utf8(text).expect("ASCII only");
            assert_eq!(
                RunId::parse(&text),
                Err(InvalidRunId::Overflow { character }),
                "expected leading {character:?} to be rejected"
            );
        }
    }

    #[test]
    fn invalid_ids_have_actionable_messages() {
        let message = RunId::parse("short").expect_err("wrong length").to_string();
        assert!(message.contains("26 characters"), "{message}");
        let message = RunId::parse(&("0".repeat(25) + "U")).expect_err("bad char").to_string();
        assert!(message.contains("ULID alphabet"), "{message}");
        let message =
            RunId::parse(&("Z".to_string() + &"0".repeat(25))).expect_err("overflow").to_string();
        assert!(message.contains("overflow"), "{message}");
    }

    #[test]
    fn step_ids_display_as_their_name() {
        let step = StepId::new("build-image");
        assert_eq!(step.as_str(), "build-image");
        assert_eq!(step.to_string(), "build-image");
    }
}
