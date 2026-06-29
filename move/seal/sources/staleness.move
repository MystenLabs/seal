module seal::time;

use sui::clock;

const EStaleFullnode: u64 = 93492;
const EStaleKeyServer: u64 = 93493;

/// The maximum amount the key server's time (`now`) may lag behind the on-chain time.
const ALLOWED_KEY_SERVER_STALENESS_IN_MS: u64 = 30_000;

/// Check that neither the full-node nor the key server is stale, where `keyserver_time` is the key server's time:
/// - Abort with `EStaleFullnode` if the on-chain time is more than `allowed_staleness_in_ms` behind `keyserver_time`.
/// - Abort with `EStaleKeyServer` if `keyserver_time` is more than `ALLOWED_KEY_SERVER_STALENESS_IN_MS` behind the on-chain time.
public fun check_staleness(
    keyserver_time: u64,
    allowed_staleness_in_ms: u64,
    clock: &clock::Clock,
) {
    let timestamp = clock.timestamp_ms();
    if (keyserver_time < timestamp) {
        assert!(timestamp - keyserver_time <= ALLOWED_KEY_SERVER_STALENESS_IN_MS, EStaleKeyServer);
        return
    };
    assert!(keyserver_time - timestamp <= allowed_staleness_in_ms, EStaleFullnode);
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
#[expected_failure(abort_code = EStaleKeyServer)]
fun test_key_server_is_stale() {
    let mut ctx = tx_context::dummy();
    let mut clock = clock::create_for_testing(&mut ctx);

    // `now` lags the on-chain time by more than the allowed key server staleness
    clock.increment_for_testing(ALLOWED_KEY_SERVER_STALENESS_IN_MS + 1);
    check_staleness(0, 9, &clock);

    clock.destroy_for_testing();
}

#[test]
fun test_is_ok() {
    let mut ctx = tx_context::dummy();
    let mut clock = clock::create_for_testing(&mut ctx);

    check_staleness(9, 10, &clock);
    check_staleness(99, 100, &clock);

    // `now` slightly in the past should also work
    clock.increment_for_testing(10);
    check_staleness(9, 0, &clock);

    // `now` at exactly the allowed key server staleness limit should pass
    clock.increment_for_testing(ALLOWED_KEY_SERVER_STALENESS_IN_MS - 10);
    check_staleness(0, 0, &clock);

    clock.destroy_for_testing();
}
