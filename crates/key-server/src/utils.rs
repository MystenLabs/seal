// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Construct constant string.
/// Based on https://github.com/MystenLabs/walrus/blob/aa95d189627da61d9e4c44b75cb92b59db7ab2c5/crates/walrus-core/src/utils.rs#L27
#[macro_export]
macro_rules! concat_const_str {
    ($($str:expr),+ $(,)?) => {{
        const STRS: &[&str] = &[$($str),+];
        const OUTPUT_LENGTH: usize = {
            let mut output_length = 0;
            let mut i = 0;

            while i < STRS.len() {
                output_length += STRS[i].as_bytes().len();
                i += 1;
            }
            output_length
        };
        const OUTPUT: [u8; OUTPUT_LENGTH] = {
            let mut output = [0u8; OUTPUT_LENGTH];
            let mut output_index = 0;
            let mut str_index = 0;

            while str_index < STRS.len() {
                let mut byte_index = 0;
                let current_bytes = STRS[str_index].as_bytes();
                while byte_index < current_bytes.len() {
                    output[output_index] = current_bytes[byte_index];
                    byte_index += 1;
                    output_index += 1;
                }
                str_index += 1;
            }
            output
        };

        // Safety: inputs are all strings, so output should be valid utf8
        unsafe { core::str::from_utf8_unchecked(&OUTPUT) }
    }};
}

/// Get package version and git version.
/// Based on https://github.com/MystenLabs/walrus/blob/7e282a681e6530ae4073210b33cac915fab439fa/crates/walrus-service/src/common/utils.rs#L69
#[macro_export]
macro_rules! version {
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

        // The version consisting of the package version and Git revision.
        concat_const_str!(env!("CARGO_PKG_VERSION"), "-", GIT_REVISION)
    }};
}
pub use version;
