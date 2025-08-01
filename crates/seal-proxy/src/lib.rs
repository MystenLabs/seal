// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod admin;
pub mod config;
pub mod consumer;
pub mod handlers;
pub mod histogram_relay;
pub mod metrics;
pub mod middleware;
pub mod prom_to_mimir;
pub mod providers;
pub mod remote_write;

/// Hidden reexports for the bin_version macro
pub mod _hidden {
    pub use const_str::concat;
    pub use git_version::git_version;
}

pub type BearerToken = String;

/// The Allower trait provides an interface for callers to decide if a generic
/// key type should be allowed
pub trait Allower<KeyType>: std::fmt::Debug + Send + Sync {
    /// allowed is called in middleware to determine if a client should be
    /// allowed. Providers implement this interface
    fn allowed(&self, key: &KeyType) -> (bool, String);
}

/// Define constants that hold the git revision and package versions.
///
/// Defines two global `const`s:
///   `GIT_REVISION`: The git revision as specified by the `GIT_REVISION` env
/// variable provided at   compile time, or the current git revision as
/// discovered by running `git describe`.
///
///   `VERSION`: The value of the `CARGO_PKG_VERSION` environment variable
/// concatenated with the   value of `GIT_REVISION`.
///
/// Note: This macro must only be used from a binary, if used inside a library
/// this will fail to compile.
#[macro_export]
macro_rules! bin_version {
    () => {
        $crate::git_revision!();

        const VERSION: &str =
            $crate::_hidden::concat!(env!("CARGO_PKG_VERSION"), "-", GIT_REVISION);
    };
}

/// Defines constant that holds the git revision at build time.
///
///   `GIT_REVISION`: The git revision as specified by the `GIT_REVISION` env
/// variable provided at   compile time, or the current git revision as
/// discovered by running `git describe`.
///
/// Note: This macro must only be used from a binary, if used inside a library
/// this will fail to compile.
#[macro_export]
macro_rules! git_revision {
    () => {
        const _ASSERT_IS_BINARY: () = {
            env!(
                "CARGO_BIN_NAME",
                "`bin_version!()` must be used from a binary"
            );
        };

        const GIT_REVISION: &str = {
            if let Some(revision) = option_env!("GIT_REVISION") {
                revision
            } else {
                let version = $crate::_hidden::git_version!(
                    args = ["--always", "--abbrev=12", "--dirty", "--exclude", "*"],
                    fallback = ""
                );

                if version.is_empty() {
                    panic!("unable to query git revision");
                }
                version
            }
        };
    };
}

/// var extracts environment variables at runtime with a default fallback value
/// if a default is not provided, the value is simply an empty string if not
/// found This function will return the provided default if env::var cannot find
/// the key or if the key is somehow malformed.
#[macro_export]
macro_rules! var {
    ($key:expr) => {
        match std::env::var($key) {
            Ok(val) => val,
            Err(_) => "".into(),
        }
    };
    ($key:expr, $default:expr) => {
        match std::env::var($key) {
            Ok(val) => val.parse::<_>().unwrap(),
            Err(_) => $default,
        }
    };
}

#[macro_export]
macro_rules! with_label {
    ($metric:expr, $($label:expr),+$(,)?) => {
        $metric.with_label_values(&[$($label.as_ref()),+])
    };
}
