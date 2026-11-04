//! Ransomware shield. Watches what each process does to files, scores it
//! over a rolling window, and freezes the whole app when it looks like mass
//! encryption. `unsafe` lives only in `sys`.
#![deny(unsafe_code)]

pub mod allowlist;
pub mod detect;
pub mod freeze;
pub mod monitor;
pub mod procinfo;
pub mod score;
pub mod sys;

pub use monitor::{Config, MarkStatus, Monitor, ShieldEvent, Trip};
