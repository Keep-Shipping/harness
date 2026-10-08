//! Whether text that survived redaction can still carry an instruction.
//!
//! Redaction answers one question — *which values did the plan mark secret?* —
//! and answers it by masking them. It says nothing about whether what is left
//! is data. A resource address is chosen by whoever wrote the pull request,
//! or by an agent acting for them, and it is rendered verbatim into the state
//! a decision model reads; nothing in a mask removes an instruction someone
//! typed into an address field.
//!
//! So this module asks the narrower question, after rendering rather than
//! before: *did anything instruction-shaped survive?* It is deliberately a
//! predicate and not a sanitiser — it does not rewrite the text it refuses, it
//! reports why the text cannot be trusted, and the caller decides that a state
//! carrying such a glyph must not be asked about.
//!
//! One block is deliberately left alone: U+206A..=U+206F, the deprecated
//! inhibit-swap and Arabic-shaping controls. Renderers stopped honouring them
//! years ago, so a glyph there is invisible ink rather than a way to reorder a
//! review — refusing it would spend a class on a threat that is not one.
//!
//! It is also designed to retire. Once [`summarize`](crate::plan_summary) renders
//! these glyphs as `\uXXXX` escapes (#107), every call here returns `None` and
//! the layer costs a scan and nothing else — which is the outcome a defence in
//! depth wants: the check stays until the hole is closed at the source, then
//! goes quiet.

/// One way a rendered state can lie about what it says.
///
/// The classes are ordered by how much they change what a reader takes away, and
/// the payload is the codepoint as a number — the one thing a review has to be
/// able to name, and the one thing it must never be handed back as ink.
///
/// The payload is `u32` rather than `char` on purpose. A `char` can be printed
/// with `{}` or `{:?}` and looks like data; a `u32` cannot be anything but the
/// `U+2028` a reviewer already knows how to look up. The guarantee the type
/// buys is over the message and the payload: [`describe`](Defect::describe) is
/// `U+XXXX` and nothing else, which is what the reason line depends on because
/// it is shown to a human through `show: risk.reason`. [`glyph`](Defect::glyph)
/// does hand the `char` back — a test naming it, or a renderer pointing at one,
/// has to be able to — so the type is a guard on what is written, not a
/// promise that the character cannot be obtained here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    /// A separator that ends a line without being a newline.
    ///
    /// U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are what a
    /// renderer breaks on and `sanitize` does not escape, because
    /// [`char::is_control`] is false for both. An address carrying one splits
    /// the rendered state where no newline was written: the second half lands
    /// on a line of its own, under a plan entry that has nothing to do with the
    /// resource the author actually named.
    LineBreak(u32),
    /// A bidirectional override, isolate or mark — the glyph that reorders
    /// what a reader sees without changing what a copy-paste reads.
    Bidirectional(u32),
    /// A variation selector: a glyph modifier with no ink that changes how the
    /// character before it is drawn, in U+180B..=U+180D and U+FE00..=U+FE0F (the
    /// BMP selectors) and in U+E0100..=U+E01EF (the ideographic ones).
    ///
    /// The codepoint stream a reviewer copies is unchanged and the rendering is
    /// not, so two addresses can differ in bytes, diff identically against a
    /// plan and still show as different resources.
    Variation(u32),
    /// A tag character, U+E0000..=U+E007F: the invisible ASCII channel, where a
    /// whole string of letters rides along as codepoints nothing displays.
    /// `is_control()` is false for every one of them, so they survive
    /// [`sanitize`](crate::plan_summary) — and the letters they carry are what
    /// the state then renders as.
    Tag(u32),
    /// A character with no ink that still changes the text: a zero-width
    /// space, a word joiner, a soft hyphen.
    Invisible(u32),
    /// A C0 or C1 control character, which renders as an escape at best and
    /// drives a terminal at worst.
    Control(u32),
}

impl Defect {
    /// The codepoint this defect is about, as a number.
    #[must_use]
    pub fn codepoint(self) -> u32 {
        match self {
            Defect::LineBreak(codepoint)
            | Defect::Bidirectional(codepoint)
            | Defect::Variation(codepoint)
            | Defect::Tag(codepoint)
            | Defect::Invisible(codepoint)
            | Defect::Control(codepoint) => codepoint,
        }
    }

    /// The character this defect is about, for a caller that has to hold the
    /// text — a test naming the glyph, or a renderer that wants to point at
    /// it. `None` for a codepoint that is not a scalar value, which no `&str`
    /// can contain.
    #[must_use]
    pub fn glyph(self) -> Option<char> {
        char::from_u32(self.codepoint())
    }

    /// A phrase for a reviewer, folded into a sentence the caller writes —
    /// `"the plan's text carries a bidirectional override (U+202E)"` — rather
    /// than a message of its own, so the caller owns the grammar.
    ///
    /// Only ever the codepoint, never the glyph: this string is what the run's
    /// reason and log line carry, and re-delivering the character would put
    /// back into a reviewer's terminal the exact byte the guard stopped for.
    #[must_use]
    pub fn describe(self) -> String {
        let glyph = format!("U+{:04X}", self.codepoint());
        match self {
            Defect::LineBreak(_) => format!("a line break that is not a newline ({glyph})"),
            Defect::Bidirectional(_) => format!("a bidirectional override ({glyph})"),
            Defect::Variation(_) => format!("a variation selector ({glyph})"),
            Defect::Tag(_) => format!("a tag character ({glyph})"),
            Defect::Invisible(_) => format!("an invisible character ({glyph})"),
            Defect::Control(_) => format!("a control character ({glyph})"),
        }
    }
}

/// The first thing in `text` that cannot be treated as data, in scan order.
///
/// First, not all, so the reason a review sees names the earliest glyph in the
/// plan rather than whichever one a later pass happened to reach — an author
/// who hid five of them gets one fact about the first, which is the one they
/// had to have meant.
///
/// Nothing here refuses prose. Newlines and tabs are what the plan rendering is
/// built from; every other control character reaching a rendered state means
/// [`summarize`](crate::plan_summary)'s escaping has a hole, and is reported as
/// such. `None` means the text is clean, and the caller may send it.
#[must_use]
pub fn first_defect(text: &str) -> Option<Defect> {
    text.chars().find_map(classify)
}

/// What class a character falls in, or nothing if it is ordinary text. The
/// tests run in the classes' reading order — no codepoint is in two of them,
/// so the order is a way of reading the function rather than a precedence
/// anything can depend on.
fn classify(character: char) -> Option<Defect> {
    let codepoint = character as u32;
    if character.is_control() && character != '\n' && character != '\t' {
        // A C0 or C1 control character inside a rendered plan means the
        // renderer let one through: it has no place in an address, and the
        // escapes that would render it are what `sanitize` is supposed to have
        // written. Seeing one is a report about the renderer, not about this
        // plan, and the honest thing to do with a rendering bug is to stop.
        return Some(Defect::Control(codepoint));
    }
    if is_bidirectional(codepoint) {
        // RIGHT-TO-LEFT OVERRIDE renders `low` as `ɯol` to a human reading the
        // review and as `low` to anything reading the bytes, so the reviewer
        // and the model are looking at different plans. The isolates and marks
        // do the same thing more quietly — and a mark can also be pasted in
        // from a log or a ticket without anyone noticing it arrive.
        return Some(Defect::Bidirectional(codepoint));
    }
    if is_line_break(codepoint) {
        // The one class that forges structure rather than merely hiding
        // something. `sanitize` escapes [`char::is_control`] and stops at the
        // newline, and these two sit either side of that gap: a renderer that
        // treats them as line breaks shows the reviewer two plan entries where
        // the author wrote one, and the second is the attacker's.
        return Some(Defect::LineBreak(codepoint));
    }
    if is_variation_selector(codepoint) {
        return Some(Defect::Variation(codepoint));
    }
    if is_tag(codepoint) {
        // Tags are the channel rather than the disguise: U+E0061 is a letter
        // `a` that no font draws, and a run of them spells whatever the author
        // liked inside a field a reviewer reads as an address.
        return Some(Defect::Tag(codepoint));
    }
    if is_invisible(codepoint) {
        // A zero-width space lets two addresses that render identically differ
        // in the bytes a reviewer compares, which is exactly what a homograph
        // attack wants: `prod-db` and `prod-db` review as one resource and
        // apply as two. The rest are the same trick wearing a different hat —
        // a joiner, a word joiner, a soft hyphen, a byte order mark.
        return Some(Defect::Invisible(codepoint));
    }
    None
}

/// The Unicode bidirectional formatting controls: the embedding and override
/// runs (`U+202A..U+202E`), the isolates (`U+2066..U+2069`), and the three
/// directional marks. Named as a set because the set is the hazard — any one
/// of them alone is inert, and it is the pairing with the reviewer's renderer
/// that does the damage. U+061C ARABIC LETTER MARK is one of them: it has no
/// ink of its own and is refused for what it does to a line, not for being
/// blank.
fn is_bidirectional(codepoint: u32) -> bool {
    matches!(codepoint, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C)
}

/// The separators that break a rendered line without being a newline:
/// `U+2028` LINE SEPARATOR and `U+2029` PARAGRAPH SEPARATOR. `char::is_control`
/// is false for both, so `sanitize` lets them through — which is the problem.
/// An address carrying one puts a line break inside a field that was supposed
/// to hold none, and everything after it renders as a plan entry of its own.
fn is_line_break(codepoint: u32) -> bool {
    matches!(codepoint, 0x2028..=0x2029)
}

/// The variation selectors, in all three blocks: `U+180B..U+180D` and
/// `U+FE00..U+FE0F` in the BMP, and `U+E0100..U+E01EF` for ideographs. Each
/// changes how the character before it is drawn while leaving the codepoint
/// stream a reviewer compares untouched, so the bytes a diff sees and the
/// glyphs a human sees come apart.
///
/// The Mongolian block is the one that gets missed: U+180B..U+180D are the
/// only variation selectors there, they are `Mn` like every other mark, and
/// their immediate neighbour U+180E MONGOLIAN VOWEL SEPARATOR — deprecated,
/// and once a zero-width space — is refused below as [`Defect::Invisible`].
fn is_variation_selector(codepoint: u32) -> bool {
    matches!(codepoint, 0x180B..=0x180D | 0xFE00..=0xFE0F | 0xE0100..=0xE01EF)
}

/// The tag characters, `U+E0000..U+E007F`: ASCII letters and punctuation
/// spelled as codepoints that render as nothing at all. Not a control category
/// and not zero-width — they simply have no glyph, which is what makes them
/// the standard way to carry invisible text through a system that has learned
/// to strip everything else.
fn is_tag(codepoint: u32) -> bool {
    matches!(codepoint, 0xE0000..=0xE007F)
}

/// The characters that take no space and show no ink: the zero-width space,
/// non-joiner and joiner, the word joiner and the invisible operators, plus
/// the soft hyphen and the byte order mark. Neither end is special-cased —
/// soft hyphen is `Cf` as much as the zero-width space is, and a BOM in the
/// middle of an address hides a difference just as well.
///
/// Two more ends earn their place by breaking the text apart rather than
/// shortening it: U+034F COMBINING GRAPHEME JOINER separates clusters that
/// would otherwise be one, and U+FFF9..U+FFFB are the interlinear annotation
/// anchors, which position text between lines without being one.
fn is_invisible(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0x200B..=0x200D | 0x2060..=0x2065 | 0x00AD | 0x034F | 0x180E | 0xFEFF | 0xFFF9..=0xFFFB
    )
}
