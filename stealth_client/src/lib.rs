//! Rust helper library for the ICP stealth announcement protocol.

pub mod types;

mod client;
mod encryption;
mod error;
pub mod recipient;

pub use client::StealthCanisterClient;
pub use encryption::{decrypt_announcement, encrypt_payload, scan_announcements, EncryptionResult};
pub use error::{ClientError, ClientResult, Result, StealthError};
