// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub use seal_committee::InternalError;

#[macro_export]
macro_rules! return_err {
    ($err:expr, $msg:expr $(, $arg:expr)*) => {{
        debug!($msg $(, $arg)*);
        return Err($err);
    }};
}
