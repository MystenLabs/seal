# Seal Package

Seal is a decentralized secrets management (DSM) service that relies on access control policies defined and validated on [Sui](https://docs.sui.io/concepts/components). Application developers and users can use Seal to secure sensitive data at rest on decentralized storage like [Walrus](https://docs.wal.app/), or on any other onchain / offchain storage.

The Seal package includes the key server registry and decryption for Seal using Boneh-Franklin over BLS12-381 as KEM and Hmac256Ctr as DEM.

## Published Envs

Seal package is available in Testnet. To use it, add the following to your `Move.toml`:

For testnet:
```toml
[dependencies]
seal = { git = "https://github.com/MystenLabs/seal.git", subdir = "move/seal", rev = "testnet" }
```