// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Get the git version.
/// Based on https://github.com/MystenLabs/walrus/blob/7e282a681e6530ae4073210b33cac915fab439fa/crates/walrus-service/src/common/utils.rs#L69
#[macro_export]
macro_rules! git_version {
    () => {{
        /// The Git revision obtained through `git describe` at compile time.
        const GIT_REVISION: &str = {
            if let Some(revision) = option_env!("GIT_REVISION") {
                revision
            } else {
                let version = git_version::git_version!(
                    args = ["--always", "--abbrev=12", "--dirty", "--exclude", "*"],
                    fallback = ""
                );
                if version.is_empty() {
                    panic!("unable to query git revision");
                }
                version
            }
        };

        GIT_REVISION
    }};
}
pub use git_version;
