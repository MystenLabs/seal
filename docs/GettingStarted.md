# Getting Started

!!! note
    This guide is meant to help you quickly bootstrap with Seal. Before deploying your app to production or Mainnet, please review the full Seal documentation to understand the design, security best practices, and operational requirements.

## Bootstrap your app

Seal makes it simple to add decentralized encryption and programmable access control to your Web3 applications. Follow these steps to get started:

**1. Install the Seal SDK**

Seal provides a TypeScript SDK for easy integration. Install it from npm:

```shell
$ npm install @mysten/seal
```

Reference: [SDK on NPM](https://www.npmjs.com/package/@mysten/seal)

**2. Choose key servers in Testnet**

Seal relies on a committee of key servers to generate threshold-based decryption keys.

- Use [verified key servers](./Pricing.md#verified-key-servers) for Testnet.
- For permissioned servers, contact the provider to allowlist your access policy package ID (see below).

**3. Define your access policy**

Access policies are written as Move modules on Sui. Examples include:

- Token-gated access
- Subscription-based access
- Time-locked decryption
- Allowlist-based access

See [Example patterns](./ExamplePatterns.md) to help you get started.

**4. Encrypt your data**

Use the SDK to encrypt data before storing it:

```typescript
const { encryptedObject: encryptedBytes, key: backupKey } = await client.encrypt({
    threshold: 2,
    packageId: fromHEX(packageId),
    id: fromHEX(id),
    data,
});
```

Learn more in [Encryption Guide](./UsingSeal.md#encryption).

**5. Store encrypted data**

Store your encrypted content in Walrus (using [HTTP API](https://docs.wal.app/usage/web-api.html) or [one of the SDKs](https://docs.wal.app/usage/sdks.html)), Sui (as [Objects](https://docs.sui.io/concepts/object-model)), or any storage of your choice.

**6. Decrypt data with access control**

When a user requests access, Seal checks your onchain policy. If approved, decryption keys are provided to meet the threshold.

```typescript
// Create the Transaction for evaluating the seal_approve function.
const tx = new Transaction();
tx.moveCall({
    target: `${packageId}::${moduleName}::seal_approve`, 
    arguments: [
        tx.pure.vector("u8", fromHEX(id)),
        // other arguments
   ]
 });  
const txBytes = tx.build( { client: suiClient, onlyTransactionKind: true })
const decryptedBytes = await client.decrypt({
    data: encryptedBytes,
    sessionKey,
    txBytes,
});
```

Learn more in [Decryption Guide](./UsingSeal.md#decryption).

## Next steps

- Read the [Seal Design](./Design.md) doc for a deeper understanding of how Seal works.
- Explore example apps in the [Examples Directory](https://github.com/MystenLabs/seal/tree/main/examples).
- Review the [Security Best Practices](./SecurityBestPractices.md) to ensure you’re following recommended guidelines.
- When deploying to Mainnet, decide whether to run your own key server as part of your threshold committee.
    - If you operate a secure, hardened Full node and have the necessary DevOps expertise & bandwidth, you can choose to self-run a key server. See the [Key Server Operations Guide](./KeyServerOps.md).
