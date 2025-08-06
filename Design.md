## Table of Contents:

- [Introduction](README.md)
- [Using Seal](UsingSeal.md)
- [Security Best Practices and Risk Mitigations](SecurityBestPractices.md)
- [Pricing](Pricing.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Seal design

### Overview

Seal uses a cryptographic primitive called *Identity-Based Encryption (IBE)* to encrypt stored data. This design detail is abstracted away from both developers and users, as Seal does not have visibility into the data it helps secure.

An [IBE scheme](https://en.wikipedia.org/wiki/Identity-based_encryption) consists of the following algorithms:
- `Setup`: Generates a master secret key `msk` and a master public key `mpk`.
- `Derive(msk, id)`: Given a master secret key and an identity `id` (string or byte array), generates a derived secret key `sk` for that identity.
- `Encrypt(mpk, id, m)`: Given a public key, an identity and a message, returns an encryption `c`.
- `Decrypt(sk, c)`: Given  a derived secret key and a ciphertext, compute the message `m`.
Such a scheme is correct if for any `id` and `m`, `(msk, mpk) ← Setup()` and `c ← Encrypt(mpk, id, m)` we have `Decrypt(Derive(msk, id, m), c) = m`.

Note that the domain of identities is *not* fixed, and can be any string/byte array. We use that property below to bound onchain strings to IBE identities.

Seal consists of two main components:
- **Access policies defined on Sui:** A Move package at address `PkgId` controls the subdomain of IBE identities that starts with `[PkgId]` (i.e., all strings of the form `[PkgId]*`). You can think of `[PkgId]` as an identity *namespace*. The package defines, through Move code, who is authorized to access the keys associated with its identity subdomain.
- **Off-chain Key Servers:** Key servers are off-chain services, each holding a single IBE master secret key. Users can request a derived secret key for a specific identity. The key server returns the derived key only if the associated onchain access policy approves the request.

Consider the following basic example for realizing time-lock encryption:
```move
module patterns::tle;

use sui::bcs;
use sui::clock;

const ENoAccess : u64 = 1;

/////////////////////////////////////////////
/// Access control
/// The IBE identity being used: [pkg id][bcs::to_bytes(time)]
/// The following function accepts only the inner identity, i.e., [bcs::to_bytes(time)], and Seal extends it with the namespace.
entry fun seal_approve(id: vector<u8>, c: &clock::Clock) {
    // Convert the identity to u64.
    let mut prepared: BCS = bcs::new(id);
    let t = prepared.peel_u64();
    let leftovers = prepared.into_remainder_bytes();

    // Check that the time has passed and the entire identity is consumed.
    assert!((leftovers.length() == 0) && (c.timestamp_ms() >= t), ENoAccess);
}
```

The module above controls all IBE identities that begin with its package ID, `PkgId`. To encrypt data with a time-lock `T`, a user selects a key server and encrypts the data using the identity `[PkgId][bcs::to_bytes(T)]` and the server’s IBE master public key. Once the onchain time on Sui exceeds `T`, *anyone* can request the decryption key for the identity `[PkgId][bcs::to_bytes(T)]` from the Seal key server. Access control is enforced by the `seal_approve` function defined in the module. This function receives the requested identity (excluding the `PkgId` prefix) and a `Clock` as arguments. It returns success only if the current time is greater than or equal to `T`. The key server evaluates `seal_approve` locally to determine whether the derived key can be returned.

Time-lock encryption can be applied to a variety of onchain use cases, including MEV-resistant trading, secure voting, and more. For additional examples and useful implementation patterns, see [move/patterns](./move/patterns).

The framework is fully generic. Developers can define custom authorization logic within `seal_approve*` functions and choose which key servers to use based on their application's needs. For example, they may use a fixed set of trusted key servers or allow users to select their preferred servers.

When you upgrade a package, it retains the same identity subdomain. To support secure upgrades, follow the recommended best practices for [versioned shared objects](https://docs.sui.io/concepts/sui-move-concepts/packages/upgrade#versioned-shared-objects). Specifically, version your shared objects, or create a global shared object for your package. For examples, see the whitelist and subscription [patterns](./move/patterns).
Keep in mind that if a package is upgradeable, the access control policy can be changed at any time by the package owner. These changes are transparent and publicly visible onchain.

### Decentralization and trust model

Seal is designed to reduce centralization using a couple of mechanisms.

First, users can choose any combination of one or more key servers and use their master public keys to encrypt data. This setup supports `t-out-of-n` threshold encryption, which ensures:
- **Privacy** as long as fewer than `t` key servers are compromised
- **Liveness** as long as at least `t` key servers are available

Seal does not mandate the use of any specific key server. Instead, users can select key servers based on their own trust assumptions. Key servers may vary in security characteristics, such as running within secure enclaves or being air-gapped, and may operate across different locations and jurisdictions.

> [!IMPORTANT]
> The set of key servers is **not** dynamic once the data is encrypted, and encrypted data cannot be changed to use a different set of servers.

Secondly, a single key server can also be implemented using a multi-party computation (MPC) committee in a `t-out-of-n` configuration. This committee can consist of Sui validators or any other group of participants. This mechanism is not yet available, but we expect MPC-based key servers to be deployed in the near future. Users can choose to use these in addition to standalone key servers. In this setup, the participants in the MPC committee can change over time, allowing for dynamic membership.

The security of encrypted data relies on the following assumptions:
- **Key server integrity**: The Seal key servers are not compromised, or, in the case of threshold encryption, fewer than the required threshold are compromised. This includes both the Seal key servers and the Sui full nodes they depend on to evaluate the access policies.
- **Correct access control policy**: The access control policy associated with the encrypted data is accurate and appropriately configured. If package upgrades are enabled, the package owner can modify the policy at any time. The new policy replaces the previous one and governs future access.

### Key Server
A light server is initialized with an identity-based encryption (IBE) master secret key and has access to a trusted full node. In simple deployments, the server runs as a backend service with the secret key stored in protected storage, optionally secured using a software or hardware vault. More advanced deployments may use secure enclaves, MPC committees, or even air-gapped environments to enhance security.

The server exposes only two APIs:
- `/v1/service` - Returns information about the service's onchain registered information.
- `/v1/fetch_key` - Handles a request for one or more derived keys and returns them if access is permitted by the associated package / policies. Each request must meet the following requirements:
    - Be signed by the user's address using `signPersonalMessage`. For details, see the [signed_message](crates/key-server/src/signed_message.rs) format.
    - Include a valid PTB, which is evaluated against the `seal_approve*` rules. For PTB construction guidelines, see [valid_ptb](./crates/key-server/src/valid_ptb.rs).
    - Provide an encryption key to encrypt the response. Encrypting the response ensures that only the requester (the initiator) can decrypt and access the returned keys.

See [crates/key-server](crates/key-server/src/server.rs) for the implementation of the key server.

### User confirmation and sessions
Decryption keys returned from the key server are returned directly to the caller, which is typically the dApp's web page. To ensure that dApps can access only keys explicitly approved by the user, the user must approve the key access request in their wallet. This approval is granted once per package and authorizes a `session key`. The session key allows the dApp to retrieve associated decryption keys for a limited time without requiring repeated user confirmations.

### Cryptographic primitives
Seal is designed to support multiple identity-based encryption (IBE) schemes as Key Encapsulation Mechanisms (KEMs) and various symmetric encryption schemes as Data Encapsulation Mechanisms (DEMs). Currently supported primitives include:
- KEM: Boneh-Franklin IBE with the BLS12-381 curve.
- DEM: AES-256-GCM, HMAC based CTR mode (to be used when onchain decryption is needed).

Post-quantum primitives are planned to be added in the future.

[Back to table of contents](#table-of-contents)
