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

### Independent Key Server Tests

Test multiple independent key servers with threshold encryption/decryption.

```bash
# Format: --servers "objectId" or "objectId:apiKeyName:apiKeyValue"

# Servers without API keys
pnpm test --network testnet --servers "0xabc123,0xdef456"

# Servers with API keys (for permissioned servers)
pnpm test --network mainnet --servers "0x123abc:myKey:mySecret,0x456def:otherKey:otherSecret"

# Mixed configuration (some with API keys, some without)
pnpm test --network testnet --servers "0xabc123,0xdef456:apiKey:apiValue"
```

### Committee Mode Tests

Test committee aggregator (managing a committee of key servers) combined with independent servers.

```bash
# Committee without API keys
pnpm test --network testnet \
  --committee '{"objectId":"0xa5d2b47e7c649a3c6f9730967a5514abb8e21f19f908ad78a6ad943970c6ad02","aggregatorUrl":"https://seal-aggregator-ci.mystenlabs.com"}' \
  --servers '[{"objectId":"0x71a3962c5d06a94d1ef5a9c0e7d63ad72cefb48acc93001eaa7ba13fab52786e"}]'

# Committee with API keys
pnpm test --network mainnet \
  --committee '{"objectId":"0xcommitteeId","aggregatorUrl":"https://aggregator.example.com","apiKeyName":"apiKeyName","apiKey":"apiKeyValue"}' \
  --servers '[{"objectId":"0xserver1","apiKeyName":"apiKey1","apiKey":"apiValue1"},{"objectId":"0xserver2","apiKeyName":"apiKey2","apiKey":"apiValue2"}]'
```
