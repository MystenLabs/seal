# Using Seal

Use this guide to learn how to protect your app and user data with Seal.

!!! tip
    Read the [Seal Design document](Design.md) first to understand the underlying architecture and concepts before using this guide.

## Access control management

Packages should define `seal_approve*` functions in their modules to control access to the keys associated with their identity namespace. Guidelines for defining `seal_approve*` functions:

- A package can include multiple `seal_approve*` functions, each implementing different access control logic and accepting different input parameters.
- The first parameter must be the requested identity, excluding the package ID prefix. For example: `id: vector<u8>`.
- If access is not granted, the function should abort without returning a value.
- To support future upgrades and maintain backward compatibility, define `seal_approve*` functions as non-public `entry` functions when possible, and either version your shared objects or use a shared global object with the latest version (see [whitelist](https://github.com/MystenLabs/seal/tree/main/move/patterns/sources/whitelist.move) and [subscription](https://github.com/MystenLabs/seal/tree/main/move/patterns/sources/subscription.move) examples).

See [move/patterns](https://github.com/MystenLabs/seal/tree/main/move/patterns) for examples and useful patterns.

As `seal_approve*` functions are standard Move functions, they can be tested locally using Move tests.
Building and publishing the code can be done using the [`Sui CLI`](https://docs.sui.io/references/cli), e.g.,:
 
```shell
$ cd examples/move
$ sui move build
$ sui client publish
```

### Limitations

The `seal_approve*` functions are evaluated on full nodes using the `dry_run_transaction_block` RPC call. This call executes the associated Move code using the full node’s local view of the chain state. Because full nodes operate independently, the result of `dry_run_transaction_block` may vary across nodes based on differences in their internal state.

When using `seal_approve*` functions, keep the following in mind:

- Changes to onchain state may take time to propagate. As a result, full nodes may not always reflect the latest state.
- `seal_approve*` functions are not evaluated atomically across all key servers. Avoid relying on frequently changing state to determine access, as different full nodes may observe different versions of the chain.
- Do not rely on invariants that depend on the relative order of transactions within a checkpoint. For example, the following code assumes a specific ordering of increment operations, but full nodes may observe different intermediate counter values due to interleaved execution.

```move

struct Counter {
    id: UID,
    count: u64,
}

public fun increment(counter: &mut Counter) {
    counter.count = counter.count + 1;
}

entry fun seal_approve(id: vector<u8>, cnt1: &Counter, cnt2: &Counter) {
    assert!(cnt1.count == cnt2.count, ENoAccess);
    ...
}
```

- `seal_approve*` functions must be side-effect free and cannot modify onchain state.
- Although the `Random` module is available, its output is not secure and not deterministic across full nodes. Avoid using it within `seal_approve*` functions.
- During Seal evaluation, only `seal_approve*` functions can be invoked directly. These functions should not assume composition with other [PTB (Programmable Transaction Block)](https://docs.sui.io/concepts/transactions/prog-txn-blocks) commands.

## Encryption

The recommended way to encrypt and decrypt the data is to use the [Seal SDK](https://www.npmjs.com/package/@mysten/seal).

First, the app must select the set of key servers it intends to use. Each key server registers its name, public key, and URL onchain by creating a `KeyServer` object. To reference a key server, use the object ID of its corresponding `KeyServer`. A common approach for app developers is to use a fixed, preconfigured set of key servers within their app. Alternatively, the app can support a dynamic selection of key servers, for example, allowing users to choose which servers to use. In this case, the app should display a list of available key servers along with their URLs. After the user selects one or more servers, the app must verify that each provided URL corresponds to the claimed key server (see `verifyKeyServers` below).

A key server may be used multiple times to enable weighting, which allows the app to specify how many times a key server can contribute towards reaching the decryption threshold. This is useful for scenarios where some key servers are more reliable or trusted than others, or when the app wants to ensure that certain key servers are always included in the decryption process.

!!! info
    Anyone can create an onchain `KeyServer` object that references a known URL (such as `seal.mystenlabs.com`) but uses a different public key. To prevent impersonation, the SDK may perform a verification step: it fetches the object ID from the server’s `/v1/service` endpoint and compares it with the object ID registered onchain.

Apps can define a list of Seal key server object IDs from the [verified key servers](Pricing.md#verified-key-servers) available in each environment. You can use any `Open` mode key servers directly. For `Permissioned` mode servers, contact the key server operator to register your package ID and receive the corresponding object ID.

Next, the app should create a `SealClient` object for the selected key servers.

```typescript
const suiClient = new SuiClient({ url: getFullnodeUrl('testnet') });

// Replace this with a list of custom key server object IDs.
// Replace with the Seal server object ids.
const serverObjectIds = ["0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"];

const client = new SealClient({
  suiClient,
  serverConfigs: serverObjectIds.map((id) => ({
    objectId: id,
    weight: 1,
  })),
  verifyKeyServers: false,
});
```
The `serverConfigs` is a list of objects, where each object contains a key server object ID and its weight. Recall that the weight indicates how many times the key server can contribute towards reaching the decryption threshold. In this example, all key servers are given equal weight 1. The config object may contain also the fields `apiKeyName` and `apiKey` for sending the HTTP header `apiKeyName: apiKey` in case a key server expects an API key.

Set `verifyKeyServers` to `true` if the app or user needs to confirm that the provided URLs correctly correspond to the claimed key servers, as described above. Note that enabling verification introduces additional round-trip requests to the key servers. For best performance, use this option primarily when verifying key servers at app startup. Set `verifyKeyServers` to `false` when verification is not required.

Next, the app can call the `encrypt` method on the `client` instance. This function requires the following parameters:

- the encryption threshold
- the package id of the deployed contract containing the `seal_approve*` functions
- the id associated with the access control policy (without the prefix of the package id discussed in [Seal Design](Design.md))
- the data to encrypt

The `encrypt` function returns two values: the encrypted object, and the symmetric key used for encryption (i.e., the key from the DEM component of the KEM/DEM scheme). The symmetric key can either be ignored or returned to the user as a backup for disaster recovery. If retained, the user can decrypt the data manually using the CLI and the `symmetric-decrypt` command, as shown in the example below.

```typescript
const { encryptedObject: encryptedBytes, key: backupKey } = await client.encrypt({
    threshold: 2,
    packageId: fromHEX(packageId),
    id: fromHEX(id),
    data,
});
```

Note that the encryption does **not** conceal the size of the message. If message size is considered sensitive, pad the message with zeros until its length no longer reveals meaningful information.

!!! note
    Seal supports encrypting an ephemeral symmetric key, which you can use to encrypt your actual content. This approach is useful when storing encrypted data immutably on Walrus while keeping the encrypted key separately on Sui. By managing the key separately, you can update access policies or rotate key servers without modifying the stored content.

!!! tip
    The `encryptedBytes` returned from the encryption call can be parsed using `EncryptedObject.parse(encryptedBytes)`. It returns an `EncryptedObject` instance that includes metadata such as the ID and other associated fields.

## Decryption

Decryption involves a few additional steps:

- The app must create a `SessionKey` object to access the decryption keys for a specific package.
- The user must approve the request by signing it in their wallet. This grants time-limited access to the associated keys.
- The app stores the resulting signature in the `SessionKey` to complete its initialization.

Once initialized, the session key can be used to retrieve multiple decryption keys for the specified package without requiring further user confirmation.

```typescript
const sessionKey = await SessionKey.create({
    address: suiAddress,
    packageId: fromHEX(packageId),
    ttlMin: 10, // TTL of 10 minutes
    suiClient: new SuiClient({ url: getFullnodeUrl('testnet') }),
});
const message = sessionKey.getPersonalMessage();
const { signature } = await keypair.signPersonalMessage(message); // User confirms in wallet
sessionKey.setPersonalMessageSignature(signature); // Initialization complete
```

!!! note
    Notes on Session Key:
    
    1. You can also optionally initialize a `SessionKey` with a passed in `Signer` in the constructor. This is useful for classes that extend `Signer`, e.g. `EnokiSigner`.
    2. You can optionally set an `mvr_name` value in the `SessionKey`. This should be the [Move Package Registry](https://www.moveregistry.com/) name for the package. Seal requires the MVR name to be registered to the first version of the package for this to work. If this is set, the message shown to the user in the wallet would use the much more readable MVR package name instead of `packageId`.
    3. You can optionally store the `SessionKey` object in [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) instead of localStorage if you would like to persist the `SessionKey` across tabs. See usage for `import` and `export` methods in the `SessionKey` class. 

The simplest way to perform decryption is to call the client’s `decrypt` function. This function expects a `Transaction` object that invokes the relevant `seal_approve*` functions. The transaction must meet the following requirements:

- It may only call `seal_approve*` functions.
- All calls must be to  the same package.

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

!!! tip
    To debug a transaction, call `dryRunTransactionBlock` directly with the transaction block.

The `SealClient` caches keys retrieved from Seal key servers to optimize performance during subsequent decryptions, especially when the same id is used across multiple encryptions.
Reusing the same client instance helps reduce backend calls and improve latency.

To retrieve multiple keys more efficiently, use the `fetchKeys` function with a multi-command PTB. This approach is recommended when multiple keys are required, as it reduces the number of requests to the key servers. Because key servers may apply rate limiting, developers should design their applications and access policies to minimize the frequency of key retrieval requests.

```typescript
await client.fetchKeys({
    ids: [id1, id2],
    txBytes: txBytesWithTwoSealApproveCalls,
    sessionKey,
    threshold: 2,
});
```

Check out our [integration tests](https://github.com/MystenLabs/ts-sdks/blob/main/packages/seal/test/unit/integration.test.ts)  for a full end-to-end example. You can also explore the [example app](https://github.com/MystenLabs/seal/tree/main/examples) to see how to implement allowlist and NFT-gated content access in practice.

!!! tip
    If a key server request fails with an `InvalidParameter` error, the cause may be a recently created on-chain object in the PTB input. The key server's full node may not have indexed it yet. Wait a few seconds and retry the request, as subsequent attempts should succeed once the node is in sync.

### On-chain decryption

Seal supports on-chain decryption in Move through the [`seal::bf_mac_encryption`](https://github.com/MystenLabs/seal/tree/main/move/seal/sources/bf_hmac_encryption.move) package. This enables Move packages to decrypt Seal-encrypted objects and use the results in on-chain logic such as auctions, secure voting (see [voting.move](https://github.com/MystenLabs/seal/tree/main/move/patterns/sources/voting.move)), or other verifiable workflows.

Use one of the published Seal package IDs as the `SEAL_PACKAGE_ID`:

| <NETWORK> | <PACKAGE_ID> |
| -------- | ------- |
| Testnet | 0x927a54e9ae803f82ebf480136a9bcff45101ccbe28b13f433c89f5181069d682 |
| Mainnet | 0xa212c4c6c7183b911d0be8768f4cb1df7a383025b5d0ba0c014009f0f30f5f8d | 

To decrypt an encrypted object in a Move package, follow these steps:

- **Verify derived keys**
    - Call `bf_hmac_encryption::verify_derived_keys` with the raw keys, package ID, identity, and the vector of key server public keys.
    - The function returns a vector of `VerifiedDerivedKey` objects.
    -  Use the Seal SDK client to fetch derived keys via `client.getDerivedKeys`, which returns a map of key server object IDs to their derived keys.
    - Retrieve public keys with `client.getPublicKeys` and convert them with `bf_hmac_encryption::new_public_key`.
    - For both derived keys and public keys, you may need to convert from bytes to `Element<G1>` or `Element<G2>` using the [`from_bytes`](https://docs.sui.io/references/framework/sui/group_ops#sui_group_ops_from_bytes) function.
- **Perform decryption**
    - Call `bf_hmac_encryption::decrypt` with the encrypted object, the verified derived keys, and the vector of public keys
    - The function returns an `Option<vector<u8>>`. If decryption fails, the return value will be `None`.

!!! note
    On-chain decryption currently works only with HMAC-CTR mode, _not_ AES.

#### On-chain decryption with the TypeScript SDK

You can use the TypeScript SDK to build a transaction that calls Seal’s on-chain decryption functions. 

Before you decrypt (see [Decryption](#decryption)), gather the following:

- `encryptedBytes`: BCS-serialized encrypted object.
- `txBytes`: a valid transaction block that calls the relevant `seal_approve*` policy function.
- `client`: an initialized `SealClient`. 
- `sessionKey`: an initialized `SessionKey`.
- `SEAL_PACKAGE_ID`: the Seal package ID for the network. 

```typescript
// 1. Parse the encrypted object.
const encryptedObject = EncryptedObject.parse(encryptedBytes);

// 2. Get derived keys from key servers for the encrypted object's ID. 
const derivedKeys = await client.getDerivedKeys({
  id: encryptedObject.id,
  txBytes,
  sessionKey,
  threshold: encryptedObject.threshold,
});

// 3. Get the public keys corresponding to the derived keys.
const publicKeys = await client.getPublicKeys(encryptedObject.services.map(([service, _]) => service));
const correspondingPublicKeys = derivedKeys.keys().map((objectId) => {
  const index = encryptedObject.services.findIndex(([s, _]) => s === objectId);
  return tx.moveCall({
    target: `${seal_package_id}::bf_hmac_encryption::new_public_key`,
    arguments: [
      tx.pure.address(objectId),
      tx.pure.vector("u8", publicKeys[index].toBytes())
    ],
  });
}).toArray();

// 4. Convert the derived keys to G1 elements.
const derivedKeysAsG1Elements = Array.from(derivedKeys).map(([_, value]) =>
tx.moveCall({
  target: `0x2::bls12381::g1_from_bytes`,
  arguments: [ tx.pure.vector("u8", fromHex(value.toString())) ],
})
);

// 5. Call the Move function verify_derived_keys. This should be cached if decryption for the same ID is performed again. 
const verifiedDerivedKeys = tx.moveCall({
  target: `${seal_package_id}::bf_hmac_encryption::verify_derived_keys`,
  arguments: [
  tx.makeMoveVec({ elements: derivedKeysAsG1Elements, type: '0x2::group_ops::Element<0x2::bls12381::G1>' }),
  tx.pure.address(encryptedObject.packageId),
  tx.pure.vector("u8", fromHex(encryptedObject.id)),
    tx.makeMoveVec({ elements: correspondingPublicKeys, type: `${SEAL_PACKAGE_ID}::bf_hmac_encryption::PublicKey` }),
  ],
});

// 6. Construct the parsed encrypted object onchain.
const parsedEncryptedObject = tx.moveCall({
  target: `${seal_package_id}::bf_hmac_encryption::parse_encrypted_object`,
  arguments: [tx.pure.vector("u8", encryptedBytes)],
});

// 7. Construct a list of public key objects. 
const allPublicKeys = publicKeys.map((publicKey, i) => tx.moveCall({
  target: `${seal_package_id}::bf_hmac_encryption::new_public_key`,
  arguments: [
    tx.pure.address(encryptedObject.services[i][0]),
    tx.pure.vector("u8", publicKey.toBytes())
  ],
}));

// 7. Perform decryption with verified derived keys. 
const decrypted = tx.moveCall({
  target: `${seal_package_id}::bf_hmac_encryption::decrypt`,
  arguments: [
    parsedEncryptedObject,
    verifiedDerivedKeys,
    tx.makeMoveVec({ elements: allPublicKeys, type: `${SEAL_PACKAGE_ID}::bf_hmac_encryption::PublicKey` }),
  ],
});

// The decryption result is in an option to be consumed if successful, `none` otherwise. 
```

## Optimizing performance

To reduce latency and improve efficiency when using the Seal SDK, apply the following strategies based on your use case:

- **Reuse the `SealClient` instance**: The client caches retrieved keys and fetches necessary onchain objects during initialization. Reusing it prevents redundant setup work.
- **Reuse the `SessionKey`**: You can keep a session key active for a fixed duration to avoid prompting users multiple times. This also reuses previously fetched objects.
- **Disable key server verification when not required**: Set `verifyKeyServers: false` unless you explicitly need to validate key server URLs. Skipping verification saves round-trip latency during initialization.
- **Include fully specified objects in PTBs**:  When creating programmable transaction blocks, pass complete object references (with versions). This reduces object resolution calls by a key server to the Sui Full node.
- **Avoid unnecessary key retrievals**: Reuse existing encrypted keys whenever possible and rely on the SDK’s internal caching to reduce overhead.
- **Use `fetchKeys()` for batch decryption**: Call `fetchKeys()` when retrieving multiple decryption keys. This groups requests and minimizes interactions with key servers.
