//! **Loom** (`loom-scrubber`) — Bidirectional Format-Preserving Cryptographic PII, IP,
//! and Secret Pseudonymizer for LLMs, Logs, and Codebases.
//!
//! Enforces `#![forbid(unsafe_code)]` across the entire crate.

#![forbid(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod detector;
pub mod engine;
pub mod store;
pub mod tui;
