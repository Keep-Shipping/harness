//! The predicate that says whether rendered plan text can still be treated as
//! data — every class of glyph it refuses, every kind of text it must leave
//! alone, and the order it reports them in.
//!
//! The refusals are the point; so is the narrowness. A guard that refused
//! ordinary text would escalate every plan and be turned off within a week, so
//! the negatives are tested as carefully as the positives: a rendering full of
//! `→`, accents and CJK has to come back `None`, every time.

use ks_core::decision_guard::{Defect, first_defect};

/// Every codepoint the guard refuses, as the class it is refused as. Spelled
/// out here rather than asked of the guard under test, so a class that quietly
/// stopped matching would shrink this table instead of quietly passing.
///
/// The guard holds a block whole, edges included, so a few entries here are
/// codepoints nobody can type: U+2065 is one past the last assigned invisible
/// operator (U+2064), and U+E0000 one before the first assigned tag (U+E0001).
/// Those are the range boundaries rather than assignable characters — an
/// attacker's string would carry the assigned neighbour, but a range that let
/// one through to be assigned later would not.
const REFUSED: [(Defect, u32); 34] = [
    // Invisible: no ink, but the text underneath it is not what it renders as.
    (Defect::Invisible(0x00AD), 0x00AD),
    (Defect::Invisible(0x034F), 0x034F),
    (Defect::Invisible(0x180E), 0x180E),
    (Defect::Invisible(0x200B), 0x200B),
    (Defect::Invisible(0x200C), 0x200C),
    (Defect::Invisible(0x200D), 0x200D),
    (Defect::Invisible(0x2060), 0x2060),
    (Defect::Invisible(0x2061), 0x2061),
    (Defect::Invisible(0x2062), 0x2062),
    (Defect::Invisible(0x2063), 0x2063),
    (Defect::Invisible(0x2064), 0x2064),
    (Defect::Invisible(0x2065), 0x2065),
    (Defect::Invisible(0xFEFF), 0xFEFF),
    (Defect::Invisible(0xFFF9), 0xFFF9),
    (Defect::Invisible(0xFFFA), 0xFFFA),
    (Defect::Invisible(0xFFFB), 0xFFFB),
    // Bidirectional: the glyph reorders what a reader sees.
    (Defect::Bidirectional(0x061C), 0x061C),
    (Defect::Bidirectional(0x200E), 0x200E),
    (Defect::Bidirectional(0x200F), 0x200F),
    (Defect::Bidirectional(0x202A), 0x202A),
    (Defect::Bidirectional(0x202E), 0x202E),
    (Defect::Bidirectional(0x2066), 0x2066),
    (Defect::Bidirectional(0x2069), 0x2069),
    // Line breaks `sanitize` lets through: one field, two rendered lines.
    (Defect::LineBreak(0x2028), 0x2028),
    (Defect::LineBreak(0x2029), 0x2029),
    // Variation selectors: the bytes a diff sees, the glyphs a human does not.
    (Defect::Variation(0x180B), 0x180B),
    (Defect::Variation(0x180C), 0x180C),
    (Defect::Variation(0x180D), 0x180D),
    (Defect::Variation(0xFE0F), 0xFE0F),
    (Defect::Variation(0xE0100), 0xE0100),
    (Defect::Variation(0xE01EF), 0xE01EF),
    // Tags: invisible ASCII, and the ends of both blocks.
    (Defect::Tag(0xE0000), 0xE0000),
    (Defect::Tag(0xE0061), 0xE0061),
    (Defect::Tag(0xE007F), 0xE007F),
];

/// A control character from each block: the guard has no list for these, it
/// takes [`char::is_control`] as the definition.
const CONTROLS: [u32; 7] = [0x0000, 0x0007, 0x000B, 0x001B, 0x007F, 0x0085, 0x009B];

/// Text that must be sent: newlines and tabs are what a plan rendering is made
/// of, and everything else here is a language somebody reads.
const ALLOWED: [&str; 8] = [
    "",
    "aws_db_instance.main",
    "1 to add, 0 to change, 0 to destroy",
    "instance_type: t3.small -> m5.large\nregion: eu-west-1\n",
    "\tindented with a tab\n",
    "→ eu-west-1 →",
    "日本語のリソース名",
    "λ omega — em dash, ümlaut, é",
];

/// Every refused glyph lands in the class it belongs to, named for a reviewer.
#[test]
fn each_refused_glyph_is_named_for_a_reviewer() {
    for (defect, codepoint) in REFUSED {
        let character = char::from_u32(codepoint).expect("every codepoint here is a scalar value");
        assert_eq!(
            first_defect(&character.to_string()),
            Some(defect),
            "U+{codepoint:04X} has no place in a rendered plan"
        );
    }
    for codepoint in CONTROLS {
        let character = char::from_u32(codepoint).expect("a C0 or C1 control is a scalar value");
        assert_eq!(
            first_defect(&character.to_string()),
            Some(Defect::Control(codepoint)),
            "U+{codepoint:04X} reaching a rendered state means the renderer has a hole"
        );
    }
}

/// **What a review is shown must not carry the glyph it is about.** The reason
/// line reaches a human through `show: risk.reason`, so a `describe` that
/// interpolated the character would put the attacker's byte back into the one
/// place it was refused from reaching. Every class, every codepoint: the
/// codepoint as a number, and nothing else.
#[test]
fn the_description_is_the_codepoint_and_never_the_glyph() {
    for (defect, codepoint) in
        REFUSED.iter().copied().chain(CONTROLS.map(|c| (Defect::Control(c), c)))
    {
        let said = defect.describe();
        assert!(said.contains("U+"), "U+{codepoint:04X} is named as a number: {said}");
        assert!(said.contains(&format!("U+{codepoint:04X}")), "the right number: {said}");
        let character = char::from_u32(codepoint).expect("every codepoint here is a scalar value");
        assert!(!said.contains(character), "U+{codepoint:04X} is not shown back: {said:?}");
        // And the caller can still hold the glyph, without `describe` being the
        // way it does.
        assert_eq!(defect.glyph(), Some(character), "the glyph is one `char::from_u32` away");
    }
}

/// What a review is shown, so an escalation names the glyph it stopped for.
#[test]
fn the_description_names_the_glyph_and_starts_lowercase() {
    assert_eq!(Defect::Bidirectional(0x202E).describe(), "a bidirectional override (U+202E)");
    assert_eq!(Defect::Invisible(0x200B).describe(), "an invisible character (U+200B)");
    assert_eq!(Defect::Control(0x0007).describe(), "a control character (U+0007)");
    assert_eq!(Defect::LineBreak(0x2028).describe(), "a line break that is not a newline (U+2028)");
    assert_eq!(Defect::Tag(0xE0061).describe(), "a tag character (U+E0061)");
    assert_eq!(Defect::Variation(0xFE0F).describe(), "a variation selector (U+FE0F)");
    // Four hex digits even below U+1000, so a reader can look the glyph up in
    // the one format a Unicode chart accepts — and five for the planes above,
    // which `{:04X}` pads rather than truncates.
    assert!(Defect::Control(0x0007).describe().ends_with("(U+0007)"), "zero-padded");
    assert!(Defect::Tag(0xE0061).describe().ends_with("(U+E0061)"), "not truncated");
    assert_eq!(Defect::Tag(0xE0000).codepoint(), 0xE0000, "the payload is a codepoint");

    // The caller owns the sentence, so `describe` must be a phrase it can drop
    // into one: `the plan's text carries {}`.
    for defect in [
        Defect::LineBreak(0x2028),
        Defect::Bidirectional(0x202E),
        Defect::Variation(0xFE0F),
        Defect::Tag(0xE0061),
        Defect::Invisible(0x200B),
        Defect::Control(0x0007),
    ] {
        let first = defect.describe().chars().next().expect("a phrase is never empty");
        assert!(first.is_lowercase(), "{}", defect.describe());
    }
}

/// A guard that refused ordinary text would escalate every plan, so the
/// negatives matter as much as the refusals.
#[test]
fn ordinary_text_is_not_a_defect() {
    for text in ALLOWED {
        assert_eq!(first_defect(text), None, "{text:?} is a plan rendering, not an attack");
    }
    // Newlines and tabs are the exception inside the control class, and they
    // are the only exception.
    assert_eq!(first_defect("a\nb\tc"), None, "a rendering is built from these two");
    assert!(first_defect("a\rb").is_some(), "a carriage return forges a line, unlike a newline");

    // The neighbours of what is refused are not: an address is allowed to end
    // a sentence in any of these scripts, and a guard that said otherwise
    // would be turned off on the first pull request to name a resource in it.
    for text in ["aws_s3_bucket.région", "aws_iam_role.\u{4F60}\u{597D}", "aws_lb.\u{2003}api"] {
        assert_eq!(first_defect(text), None, "{text:?} is ordinary text");
    }
}

/// The first glyph in scan order, so the reason a review reads names the one
/// the author had to have meant rather than whichever a later pass reached.
#[test]
fn the_first_defect_is_the_one_reported() {
    // Zero-width space first, bidi second: the earlier one wins.
    let text = "aws_db_instance.pro\u{200B}d \u{202E}low\u{202C}";
    assert_eq!(first_defect(text), Some(Defect::Invisible(0x200B)));
    // Same pair, the other way round, so the answer cannot be an ordering
    // coincidence in the ranges.
    let text = "aws_db_instance.main \u{202E}low\u{202C}pro\u{200B}d";
    assert_eq!(first_defect(text), Some(Defect::Bidirectional(0x202E)));
    // A clean prefix before the defect changes nothing, and a clean suffix
    // after it does not hide it.
    assert_eq!(first_defect("1 to add, 0 to change, 0 to destroy\naws_db_instance.main\n"), None,);
    assert_eq!(
        first_defect("aws_db_instance.main\u{0007}"),
        Some(Defect::Control(0x0007)),
        "a defect at the very end is still a defect",
    );
    // A forged line reports itself as one, and the text after it is not what
    // makes it a defect.
    assert_eq!(
        first_defect("aws_lb.api\u{2028}1 to add, 0 to change, 0 to destroy"),
        Some(Defect::LineBreak(0x2028)),
    );
    assert_eq!(
        first_defect("aws_db_instance.main\u{E0061}"),
        Some(Defect::Tag(0xE0061)),
        "a tag letter is a channel, not an address",
    );
}

/// An empty state has nothing to carry, so an empty plan is not an attack —
/// it is a plan the step refuses to ask about, one layer up.
#[test]
fn nothing_written_is_nothing_carried() {
    assert_eq!(first_defect(""), None);
}
