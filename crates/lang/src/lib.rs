//! The Keep Shipping language: lexer, parser, CST with spans, and formatter.
//!
//! Pure computation: no I/O of any kind, so the crate compiles unchanged for
//! `wasm32-unknown-unknown`.

#![forbid(unsafe_code)]
