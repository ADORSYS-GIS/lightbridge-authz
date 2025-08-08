pub mod config;
pub mod error;

pub use crate::config::{load_from_path, Config};
pub use crate::error::{Error, Result};
