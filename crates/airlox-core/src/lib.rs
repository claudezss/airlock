//! Airlox protocol core (v1).
//!
//! One implementation of the wire formats and cryptography, shared by the
//! relay server, the runner, the Python SDK (via PyO3) and the browser (via
//! wasm). See `docs/protocol.md` for the normative description and
//! `vectors/v1.json` for the test vectors every binding must pass.

pub mod api;
pub mod cert;
pub mod encoding;
mod error;
pub mod invite;
pub mod item;
pub mod keys;
pub mod payload;
pub mod policy;
pub mod session;
pub mod shim;
pub mod transfer;
pub mod validate;
pub mod vectors;

pub use error::{Error, Result};

/// Wire protocol version carried in every signed structure as `v`.
pub const PROTOCOL_VERSION: u32 = 1;
