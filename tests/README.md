# Key Server Testing Suite

This test suite verifies that your key server is properly serving requests. It's recommended to add this test to your continuous testing workflow.

Run tests with the appropriate network and your key server object IDs.

If your server is in permissioned mode, ensure the following package IDs are allowed in your key server configuration:

| Network | Package ID                                                           |
| ------- | -------------------------------------------------------------------- |
| Testnet | `0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2` |
| Mainnet | `0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029` |

## Running Tests

```bash
pnpm --version
# matches 10.17.0

pnpm i
```

### Test

Run the following test to run end to end encrypt and decrypt test against the provided servers.

Options:
`--network`: Provide the network.
`--servers`: Provide a list of servers with their object IDs, optionally provide API key name and value. Supports independent servers (open or permissioned) and committee servers. For a committee server, provide an aggregator URL.
`--threshold`: Provide a threshold, default to the count of all servers.

```bash
# Independent servers with API keys.
pnpm test --network mainnet \
  --servers '[{"objectId":"0xserver1","apiKeyName":"apiKey1","apiKey":"apiValue1"},{"objectId":"0xserver2","apiKeyName":"apiKey2","apiKey":"apiValue2"}]' \
  --threshold 2

# Committee server with aggregator URL and default threshold (1/1).
pnpm test --network testnet \
  --servers '[{"objectId":"0x8a0e2e09a4c5255336d234b11014642b350634f07d07df6fc4c17bf07430c872","aggregatorUrl":"https://aggregator.example.com"}]'

# Committee and independent server.
pnpm test --network mainnet \
  --servers '[{"objectId":"0xcommitteeId","aggregatorUrl":"https://aggregator.example.com","apiKeyName":"apiKeyName","apiKey":"apiKeyValue"}, {"objectId":"0xindependentServer"}]'
```

### Load Test

`load-test.ts` runs the same end-to-end encrypt/decrypt flow as the functional test and reports both full-operation latency and decrypt-only latency. Decrypt-only latency is timed around `client.decrypt(...)`; it includes the SDK fetch-key call and local decrypt work, but not the preceding encrypt/session/PTB setup.

Options:

- `--network`: `testnet` or `mainnet`.
- `--servers`: JSON array of independent or committee server configs. Permissioned servers can include `apiKeyName` and `apiKey`.
- `--threshold`: Threshold for independent server configs. Defaults to the number of server configs.
- `--rate-per-second`: Fixed request start rate. Use this for repeatable throughput comparisons.
- `--duration-seconds`: Test duration in seconds.
- `--data-bytes`: Plaintext payload size. Note that Seal does not send the plaintext/ciphertext bytes to `/v1/fetch_key`; this mainly changes client-side encrypt/decrypt work.
- `--concurrency`: Alternative mode that keeps this many workers busy. Ignored when `--rate-per-second` is set.
- `--timeout`: SDK key-server request timeout in milliseconds. Defaults to `10000`.

Fixed-rate examples:

```bash
# Mainnet independent permissioned server.
# Replace API_KEY_VALUE with the real secret; do not commit secrets.
pnpm exec tsx load-test.ts \
  --network mainnet \
  --servers '[{"objectId":"0xfabd2fb03a16ba9a8f2f961876675aa7ac2359b863627d7e3b948dc2cb3077ba","apiKeyName":"apiKey","apiKey":"API_KEY_VALUE"}]' \
  --threshold 1 \
  --rate-per-second 10 \
  --duration-seconds 60 \
  --data-bytes 102400

# Testnet independent Mysten 2/2.
pnpm exec tsx load-test.ts \
  --network testnet \
  --servers '[{"objectId":"0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75"},{"objectId":"0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"}]' \
  --threshold 2 \
  --rate-per-second 10 \
  --duration-seconds 60 \
  --data-bytes 102400

# Testnet committee via aggregator.
pnpm exec tsx load-test.ts \
  --network testnet \
  --servers '[{"objectId":"0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98","aggregatorUrl":"https://seal-aggregator-testnet.mystenlabs.com"}]' \
  --rate-per-second 10 \
  --duration-seconds 60 \
  --data-bytes 102400
```

Useful `--data-bytes` values:

| Size  | Value      |
| ----- | ---------- |
| 100KB | `102400`   |
| 1MB   | `1048576`  |
| 10MB  | `10485760` |

The final line includes:

- `ok` and `failed`: successful and failed operations.
- `rps`: completed attempts per second.
- `avg`, `p95`, `p99`: full operation latency.
- `decryptAvg`, `decryptP95`: decrypt-only latency for successful operations.

Concurrency-mode example:

```bash
pnpm exec tsx load-test.ts \
  --network testnet \
  --servers '[{"objectId":"0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98","aggregatorUrl":"https://seal-aggregator-testnet.mystenlabs.com"}]' \
  --concurrency 100 \
  --duration-seconds 300
```
