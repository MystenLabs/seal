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
