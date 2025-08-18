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

# Run tests with additional server object IDs (comma-separated), in addition to mysten server(s).
pnpm test -- --network testnet --object_ids 0xabc123,0xdef456
pnpm test -- --network mainnet --object_ids 0x123abc,0x456def,0x789ghi
```