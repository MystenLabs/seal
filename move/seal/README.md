# Seal Package

Seal is a decentralized secrets management (DSM) service that relies on access control policies defined and validated on [Sui](https://docs.sui.io/concepts/components). Application developers and users can use Seal to secure sensitive data at rest on decentralized storage like [Walrus](https://docs.wal.app/), or on any other onchain / offchain storage.

This Move package provides the onchain functionality for:
- Registering and managing key servers
- Performing decryption using Boneh-Franklin key encapsulation (over BLS12-381) and HMAC-256-CTR as the data encapsulation mechanism (DEM)