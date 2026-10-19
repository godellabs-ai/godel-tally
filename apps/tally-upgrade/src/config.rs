//! Host upgrade settings and recovery state.
use std::{env, path::PathBuf};

pub fn setting(name: &str) -> Result<String, env::VarError> {
    env::var(format!("TALLY_UPGRADE_{name}"))
}

pub fn state_dir() -> PathBuf {
    setting("STATE_DIR").map_or_else(
        |_| {
            env::var_os("TALLY_DATA_DIR").map_or_else(
                || PathBuf::from(".local/upgrade"),
                |root| PathBuf::from(root).join("upgrade"),
            )
        },
        PathBuf::from,
    )
}
