//! CLI module — subcommand handlers for the `ironclaw` binary.
//!
//! Each submodule handles a specific CLI subcommand:
//! - `doctor`  — 14+ diagnostic checks across all security subsystems
//! - `onboard` — Interactive onboarding wizard for initial setup
//! - `policy`  — Display current security policy summary
//! - `audit`   — View audit log entries
//! - `skills`  — List, verify, install, and scan skills

pub mod audit;
pub mod doctor;
pub mod models;
pub mod onboard;
pub mod policy;
pub mod skills;
