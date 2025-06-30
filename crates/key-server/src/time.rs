// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

/// Compute the difference between the current time and the offset in milliseconds.
/// Returns a tuple containing the absolute value of the duration in milliseconds and a boolean indicating if the offset is in the past.
fn duration_since(offset: u64) -> (u64, bool) {
    if offset <= current_epoch_time() {
        (current_epoch_time() - offset, true)
    } else {
        (offset - current_epoch_time(), false)
    }
}

/// Returns the duration since the offset as a signed f64.
pub(crate) fn duration_since_as_f64(offset: u64) -> f64 {
    match duration_since(offset) {
        (duration, true) => duration as f64,
        (duration, false) => -(duration as f64),
    }
}

/// Returns the duration since the offset.
/// Returns `Duration::ZERO` if the offset is greater than the current time.
pub(crate) fn saturating_duration_since(offset: u64) -> Duration {
    match checked_duration_since(offset) {
        Some(duration) => duration,
        _ => Duration::ZERO,
    }
}

/// Returns the duration since the offset.
/// Returns `None` if the offset is greater than the current time.
pub(crate) fn checked_duration_since(offset: u64) -> Option<Duration> {
    match duration_since(offset) {
        (duration, true) => Some(Duration::from_millis(duration)),
        _ => None,
    }
}

/// Returns the current epoch time in milliseconds since the UNIX epoch.
pub(crate) fn current_epoch_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fixed start time")
        .as_millis() as u64
}

/// Creates a [Duration] from a given number of minutes.
/// Can be removed once the `Duration::from_mins` method is stabilized.
pub(crate) fn from_mins(mins: u16) -> Duration {
    // safe cast since 64 bits is more than enough to hold 2^16 * 60 seconds
    Duration::from_secs((mins * 60) as u64)
}
