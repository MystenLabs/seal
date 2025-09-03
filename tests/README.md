# Key Server Testing Suite

This test suite verifies that your key server is properly serving requests. It's recommended to add this test to your continuous testing workflow.

Run tests with the appropriate network and your key server object IDs.

If your server is in permissioned mode, ensure the following package IDs are allowed in your key server configuration:

| Network | Package ID |
|---------|------------|
| Testnet | `0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2` |
| Mainnet | `0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029` |

## Running Tests
```bash
pnpm i

# Run tests with server configurations
# Format: --servers "objectId" or "objectId:apiKeyName:apiKeyValue"

# Servers without API keys
pnpm test -- --network testnet --servers "0xabc123,0xdef456"

# Servers with API keys (for permissioned servers)
pnpm test -- --network mainnet --servers "0x123abc:myKey:mySecret,0x456def:otherKey:otherSecret"

# Mixed configuration (some with API keys, some without)
pnpm test -- --network testnet --servers "0xabc123,0xdef456:apiKey:apiValue"
```