// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

/// Compute the difference between the current time and the offset in milliseconds.
/// Returns a tuple containing the absolute value of the duration in milliseconds and a boolean indicating if the offset is in the past.
fn duration_since(offset: u64) -> (u64, bool) {
    let now = current_epoch_time();
    if offset <= now {
        (now - offset, true)
    } else {
        (offset - now, false)
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

#[cfg(test)]
mod tests {
    use crate::time::{checked_duration_since, current_epoch_time, duration_since, from_mins};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_from_mins() {
        assert_eq!(from_mins(17), Duration::from_secs(17 * 60));
    }

    #[test]
    fn test_current_epoch_time_sanity() {
        let now = current_epoch_time();
        // 30th of June 2025 10:19:00
        assert!(now > 1751271540000);
        thread::sleep(Duration::from_secs(1));
        let now2 = current_epoch_time();
        assert!(now2 >= now + 1000 && now2 < now + 1100);
    }

    #[test]
    fn test_duration_since_past() {
        let now = current_epoch_time();
        let offset_in_past = now - 1000;
        let (duration, is_past) = duration_since(offset_in_past);
        assert!((1000..=1100).contains(&duration));
        assert!(is_past);
        let checked_duration = checked_duration_since(offset_in_past);
        assert!(
            checked_duration.unwrap() >= Duration::from_millis(1000)
                && checked_duration.unwrap() < Duration::from_millis(1100)
        );
    }

    #[test]
    fn test_duration_since_future() {
        let now = current_epoch_time();
        let offset_in_future = now + 1000;
        let (duration, is_past) = duration_since(offset_in_future);
        assert!((900..=1000).contains(&duration));
        assert!(!is_past);
        let checked_duration = checked_duration_since(offset_in_future);
        assert!(checked_duration.is_none());
    }
}
