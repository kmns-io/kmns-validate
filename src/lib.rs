#![forbid(unsafe_code)]

//! Reusable native validation engine and supporting CLI modules.
//!
//! The `kmns-validate` binary provides a thin, high-performance command-line interface around this engine.

pub mod cli;
pub mod config;
pub mod host;
pub mod output;
pub mod resource;
pub mod runtime;
pub mod validate;
pub mod version;
