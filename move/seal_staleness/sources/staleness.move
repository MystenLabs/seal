module seal_staleness::time;

use sui::clock;

#[test_only]
use sui::test_scenario;

const EStaleFullnode: u64 = 93492;
const EStaleKeyServer: u64 = 93493;

/// The maximum amount the key server's time (`now`) may lag behind the on-chain time.
const ALLOWED_KEY_SERVER_STALENESS_IN_MS: u64 = 60_000;

/// Check that neither the full-node nor the key server is stale, where `now` is the key server's time:
/// - Abort with `EStaleFullnode` if the on-chain time is more than `allowed_staleness_in_ms` behind `now`.
/// - Abort with `EStaleKeyServer` if `now` is more than `ALLOWED_KEY_SERVER_STALENESS_IN_MS` behind the on-chain time.
public fun check_staleness(now: u64, allowed_staleness_in_ms: u64, clock: &clock::Clock) {
    let timestamp = clock.timestamp_ms();
    if (now < timestamp) {
        assert!(timestamp - now <= ALLOWED_KEY_SERVER_STALENESS_IN_MS, EStaleKeyServer);
        return
    };
    assert!(now - timestamp <= allowed_staleness_in_ms, EStaleFullnode);
}

#[test]
#[expected_failure(abort_code = EStaleFullnode)]
fun test_is_stale() {
    // Clock is zero, so this should fail
    check_staleness(10, 9, clock::borrow());
}

#[test]
#[expected_failure(abort_code = EStaleKeyServer)]
fun test_key_server_is_stale() {
    // `now` lags the on-chain time by more than the allowed key server staleness
    let tx = test_scenario::ctx_builder_from_sender(@0x0).set_clock_timestamp(
        ALLOWED_KEY_SERVER_STALENESS_IN_MS + 1,
    );
    let scenario = test_scenario::begin_with_context(tx);
    check_staleness(0, 9, clock::borrow());
    scenario.end();
}

#[test]
fun test_is_ok() {
    let mut scenario = test_scenario::begin(@0x0);

    check_staleness(9, 10, clock::borrow());
    check_staleness(99, 100, clock::borrow());

    // `now` slightly in the past should also work
    let tx = scenario.ctx_builder().set_clock_timestamp(10);
    scenario.next_with_context(tx);
    check_staleness(9, 0, clock::borrow());

    // `now` at exactly the allowed key server staleness limit should pass
    let tx = scenario.ctx_builder().set_clock_timestamp(ALLOWED_KEY_SERVER_STALENESS_IN_MS);
    scenario.next_with_context(tx);
    check_staleness(0, 0, clock::borrow());

    scenario.end();
}
