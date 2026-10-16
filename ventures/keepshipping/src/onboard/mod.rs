//! The pure half of the "manage as code" wizard: what an app repository is
//! built with and what it needs, worked out from its files. Nothing here
//! touches the network or a worker binding, so every part compiles natively
//! and to wasm and is unit-tested directly.

pub mod detect;
