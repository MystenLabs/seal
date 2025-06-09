# Seal Package

Seal is a decentralized secrets management (DSM) service that enforces access control policies defined and validated on the [Sui](https://docs.sui.io/concepts/components) blockchain. It enables application developers and users to securely encrypt and manage access to sensitive data — whether stored on decentralized storage platforms like [Walrus](https://docs.wal.app/) or other onchain/offchain storage systems.

This Move package provides the core Seal functionality for:

- Registering and managing key servers
- Enforcing decryption policies
- Performing decryption using Boneh-Franklin key encapsulation (over BLS12-381) and HMAC-256-CTR as the data encapsulation mechanism (DEM)

## Supported environments

Seal is available available in Testnet. To use the package in your Move-based project, add the following to your `Move.toml`:

For testnet:
```toml
[dependencies]
seal = { git = "https://github.com/MystenLabs/seal.git", subdir = "move/seal", rev = "testnet" }
```