/**
 * Highlighting grammar for `ship.ks` (Keep Shipping site files).
 *
 * Deliberately not a semantic parser. There is no external scanner, so
 * INDENT/DEDENT do not exist: a file is a sequence of lines, each an
 * optional `key:` followed by a tolerant run of value tokens. Parens are
 * flat punctuation and the body of a block string (`key: |`) is
 * best-effort tokenised as ordinary lines — accepted, because every
 * shared fixture has to parse without one ERROR/MISSING node.
 *
 * The lexical rules of docs/LANGUAGE.md fall out of token precedence:
 * `key:` beats a bare word on a tie, so `name:` is a key while
 * `ghcr.io/acme/api:{git.sha}` is one word plus an interpolation, and an
 * operator only wins when whitespace delimits it (`a == b`, not `a==b`).
 */

// A word part: any run of characters that cannot start or end a token.
const PART = /[^\s,|(){}"\\]+/;

// A scalar class is only a tie against a whole word (`true`, `5m`, `@acme/on-call`).
const WORD = 1, KEY = 2, COMMENT = 3, OP = 4, SCALAR = 5;

module.exports = grammar({
  name: 'keepshipping',

  // Newlines are structure, so they are not extras; a missing trailing
  // newline is recovered for.
  extras: $ => [/[ \t]/],

  rules: {
    document: $ => seq(repeat(choice($._line, $._newline)), optional($._content)),

    _line: $ => seq($._content, $._newline),
    _content: $ => choice(seq($.key, repeat($._value)), repeat1($._value)),
    _newline: _ => /\r?\n/,

    key: _ => token(prec(KEY, /[A-Za-z_][A-Za-z0-9_-]*:/)),

    _value: $ => choice(
      $.string,
      $.boolean,
      $.duration,
      $.number,
      $.handle,
      $.keyword,
      $.operator,
      $.punctuation,
      $.word,
      $.comment,
    ),

    // Longest match wins, so these lose to a whole word whenever they are
    // only a prefix of it (`android` is a word, not `and` + `roid`).
    keyword: _ => token(prec(SCALAR, choice('and', 'or', 'not', 'is'))),
    boolean: _ => token(prec(SCALAR, choice('true', 'false'))),
    handle: _ => token(prec(SCALAR, /@[A-Za-z_][\w-]*(?:\/[\w-]+)*/)),
    duration: _ => token(prec(SCALAR, /\d+(?:\.\d+)?(?:ms|s|m|h|d)/)),
    number: _ => token(prec(SCALAR, /-?\d+(?:\.\d+)*/)),
    operator: _ => token(prec(OP, /==|!=|>=|<=|≥|≤|<|>|=/)),
    punctuation: _ => token(prec(OP, /[,|:()]/)),
    // `#` only opens a comment where a token may start, because `a#b` is
    // one word.
    comment: _ => token(prec(COMMENT, /#[^\n]*/)),

    word: $ => prec.right(repeat1(choice(token(prec(WORD, PART)), $.interpolation))),

    string: $ => seq(
      '"',
      repeat(choice($._string_part, $.escape, $.interpolation)),
      token.immediate('"'),
    ),
    _string_part: _ => token.immediate(/[^"\\{\n\r]+/),
    escape: _ => token.immediate(seq('\\', /["\\]/)),

    interpolation: $ => seq('{', $.dotted_name, '}'),
    dotted_name: _ => /[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*/,
  },
});