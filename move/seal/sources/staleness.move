module seal::time;

use sui::clock;

const EStaleFullnode: u64 = 93492;

/// Check that the state of the chain is not stale: Abort if the on-chain time is more than `allowed_staleness_in_ms` behind `now`.
public fun check_staleness(now: u64, allowed_staleness_in_ms: u64, clock: &clock::Clock) {
    // If the clock timestamp is more recent, the check passes
    let timestamp = clock.timestamp_ms();
    if (now < timestamp) {
        return
    };
    assert!(now - timestamp <= allowed_staleness_in_ms, EStaleFullnode);
}

#[test]
#[expected_failure(abort_code = EStaleFullnode)]
fun test_is_stale() {
    let mut ctx = tx_context::dummy();
    let clock = clock::create_for_testing(&mut ctx);

    // Clock is zero, so this should fail
    check_staleness(10, 9, &clock);

    clock.destroy_for_testing();
}

#[test]
fun test_is_ok() {
    let mut ctx = tx_context::dummy();
    let mut clock = clock::create_for_testing(&mut ctx);

    check_staleness(9, 10, &clock);
    check_staleness(99, 100, &clock);

    // `now` in the past should also work
    clock.increment_for_testing(10);
    check_staleness(9, 0, &clock);

    clock.destroy_for_testing();
}
