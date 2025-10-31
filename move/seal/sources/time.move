module seal::time;

const EStaleFullnode: u64 = 5;

public fun check_duration_since(now: u64, allowed_delay: u64, clock: &sui::clock::Clock) {
    // If the clock timestamp is more recent, the check passes
    let timestamp = clock.timestamp_ms();
    if (now < timestamp) {
        return
    };
    assert!(now - timestamp <= allowed_delay, EStaleFullnode);
}
