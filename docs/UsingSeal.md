# Using Seal

!!! tip
    Read the [Seal Design document](Design.md) first to understand the underlying architecture and concepts before using this guide.

## For dapp developers

### Access control management

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

**Limitations**

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

### Encryption

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

### Decryption

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

Check out our [integration tests](https://github.com/MystenLabs/ts-sdks/blob/main/packages/seal/test/unit/integration.test.ts)  for a full end-to-end example. You can also explore the [example app](./examples/) to see how to implement allowlist and NFT-gated content access in practice.

!!! tip
    If a key server request fails with an `InvalidParameter` error, the cause may be a recently created on-chain object in the PTB input. The key server's full node may not have indexed it yet. Wait a few seconds and retry the request, as subsequent attempts should succeed once the node is in sync.

#### On-chain decryption

Seal supports on-chain decryption in Move through the [`seal::bf_mac_encryption`](https://github.com/MystenLabs/seal/tree/main/move/seal/sources/bf_hmac_encryption.move) package. This enables Move packages to decrypt Seal-encrypted objects and use the results in on-chain logic such as auctions, secure voting (see [voting.move](https://github.com/MystenLabs/seal/tree/main/move/patterns/sources/voting.move)), or other verifiable workflows.

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

**On-chain decryption with the TypeScript SDK**

You can use the TypeScript SDK to build a transaction that calls Seal’s on-chain decryption functions. 

Before encrypting, make the public keys available on-chain so clients can verify them if needed. For each public key, create a corresponding Move object:
```typescript
const publicKey = tx.moveCall({
  target: `${SEAL_PACKAGE_ID}::bf_hmac_encryption::new_public_key`,
  arguments: [
    tx.pure.address(keyserverId),
    tx.pure.vector("u8", Array.from(publicKeyBytes))
  ],
});
```

Assume you have:

- `encryptedBytes`: a BCS-serialized encrypted object,
- `txBytes`: a transaction block that calls a `seal_approve*` function (see [Decryption](#decryption)).
- `allPublicKeys`: an array of Move objects for all public keys in the encryption,
- `correspondingPublicKeys`: the public keys that correspond to the derived keys.

A transaction for on-chain decryption could look like this:
```typescript
// Parse BCS serialized encrypted object
const encryptedObject = EncryptedObject.parse(encryptedBytes);

// Get derived keys from key servers
const derivedKeys = await sealClient.getDerivedKeys({
  id: encryptedObject.id,
  txBytes, // Should contain call to seal_approve as discussed in the [decryption](#Decryption) section
  sessionKey,
  threshold: encryptedObject.threshold,
});

// Parse encrypted object as Move object
// For some applications, this object should be stored on-chain (e.g., encrypted votes should be stored before the deadline, and decrypted after).
const tx = new Transaction();
const parsedEncryptedObject = tx.moveCall({
  target: `${SEAL_PACKAGE_ID}::bf_hmac_encryption::parse_encrypted_object`,
  arguments: [tx.pure.vector("u8", Array.from(encryptedObject.))],
});


// Convert the derived keys to G1 elements
const derivedKeysAsG1Elements = Array.from(derivedKeys).map(([derivedKey]) => 
  tx.moveCall({
    target: `0x2::bls12381::g1_from_bytes`,
    arguments: [tx.pure.vector("u8", fromHex(derivedKey.toString()))],
  }),
);

// Verify the derived keys. This can be cached if decryption for the same ID is done again
const verifiedDerivedKeys = tx.moveCall({
  target: `${SEAL_PACKAGE_ID}::bf_hmac_encryption::verify_derived_keys`,
  arguments: [
    tx.makeMoveVec({ elements: derivedKeysAsG1Elements }),
    tx.pure.address(encryptedObject.packageId),
    tx.pure.vector("u8", fromHex(encryptedObject.id)),
    tx.makeMoveVec({ elements: correspondingPublicKeys }),
  ],
});

// Add call to decryption
tx.moveCall({
  target: `${SEAL_PACKAGE_ID}::bf_hmac_encryption::decrypt`,
  arguments: [
    parsedEncryptedObject,
    verifiedDerivedKeys,
    tx.makeMoveVec({ elements: allPublicKeys }),
  ],
});
```

Use one of the published Seal package IDs as the `SEAL_PACKAGE_ID`:

| <NETWORK> | <PACKAGE_ID> |
| -------- | ------- |
| Testnet | 0x4614e5da0136ee7d464992ddd3719d388ae2bfdb48dfec6d9ad579f87341f2e1 |
| Mainnet | 0xbfc8d50ed03d52864779e5bc9bd2a9e0417a03c42830d3757c99289c779967b7 | 

### Optimizing performance

To reduce latency and improve efficiency when using the Seal SDK, apply the following strategies based on your use case:

- **Reuse the `SealClient` instance**: The client caches retrieved keys and fetches necessary onchain objects during initialization. Reusing it prevents redundant setup work.
- **Reuse the `SessionKey`**: You can keep a session key active for a fixed duration to avoid prompting users multiple times. This also reuses previously fetched objects.
- **Disable key server verification when not required**: Set `verifyKeyServers: false` unless you explicitly need to validate key server URLs. Skipping verification saves round-trip latency during initialization.
- **Include fully specified objects in PTBs**:  When creating programmable transaction blocks, pass complete object references (with versions). This reduces object resolution calls by a key server to the Sui Full node.
- **Avoid unnecessary key retrievals**: Reuse existing encrypted keys whenever possible and rely on the SDK’s internal caching to reduce overhead.
- **Use `fetchKeys()` for batch decryption**: Call `fetchKeys()` when retrieving multiple decryption keys. This groups requests and minimizes interactions with key servers.

## For key server operators

Use the relevant package ID `<PACKAGE_ID>` to register your key server on the Sui network `<NETWORK>`:

| <NETWORK> | <PACKAGE_ID> | 
| -------- | ------- |
| Testnet | 0x4614e5da0136ee7d464992ddd3719d388ae2bfdb48dfec6d9ad579f87341f2e1 |
| Mainnet | 0xbfc8d50ed03d52864779e5bc9bd2a9e0417a03c42830d3757c99289c779967b7 | 

A Seal key server can operate in one of two modes: `Open` or `Permissioned`:

- **Open mode**: In open mode, the key server accepts decryption requests for *any* onchain package. It uses a single master key to serve all access policies across packages. This mode is suitable for public or general-purpose deployments where package-level isolation is not required.
- **Permissioned mode**: In permissioned mode, the key server restricts access to a manually approved list of packages associated with specific clients or applications. Each client is served using a dedicated master key.
  - This mode also supports importing or exporting the client-specific key if needed, for purposes such as disaster recovery or key server rotation.

You can choose the mode that best fits your deployment model and security requirements. The following sections provide more details on both options.

### Open mode

In `Open` mode, the key server allows decryption requests for Seal policies from any package. This mode is ideal for testing or for deployments where the key server is operated as a best-effort service without direct user liability.

Before starting the key server, you must generate a BLS master key pair. This command outputs both the master secret key and the public key.

```shell
$ cargo run --bin seal-cli genkey
Master key: <MASTER_KEY>
Public key: <MASTER_PUBKEY>
```

To make the key server discoverable by Seal clients, register it on-chain.
Call the `create_and_transfer_v1` function from the `seal::key_server` module like following:

```shell
$ sui client switch --env <NETWORK>
$ sui client active-address # fund this if necessary
$ sui client call --function create_and_transfer_v1 --module key_server --package <PACKAGE_ID> --args <YOUR_SERVER_NAME> https://<YOUR_URL> 0 <MASTER_PUBKEY>

# outputs object of type key_server::KeyServer <KEY_SERVER_OBJECT_ID>
```

To start the key server in `Open` mode, run the command `cargo run --bin key-server`, but before running the server, set the following environment variables:

- `MASTER_KEY`: The master secret key generated using the `seal-cli` tool.
- `CONFIG_PATH`: The path to a .yaml configuration file that specifies key server settings. For the configuration file format, see the [example config](https://github.com/MystenLabs/seal/tree/main/crates/key-server/key-server-config.yaml).

In the config file, make sure to:

- Set the network, e.g. `Testnet`, `Mainnet`, or `!Custom` for custom RPC endpoints.
  - For `!Custom` network, you can either specify `node_url` in the config or set the `NODE_URL` environment variable.
- Set the mode to `!Open`.
- Set the `key_server_object_id` field to <KEY_SERVER_OBJECT_ID>, the ID of the key server object you registered on-chain. 

```shell
$ CONFIG_PATH=crates/key-server/key-server-config.yaml MASTER_KEY=<MASTER_KEY> cargo run --bin key-server

# Or with a custom RPC endpoint via environment variable:
# $ NODE_URL=https://your-custom-rpc.example.com CONFIG_PATH=crates/key-server/key-server-config.yaml MASTER_KEY=<MASTER_KEY> cargo run --bin key-server
```

Alternatively, run with docker:

```shell
$ docker build -t seal-key-server . --build-arg GIT_REVISION="$(git describe --always --abbrev=12 --dirty --exclude '*')" 

$ docker run -p 2024:2024 -v $(pwd)/crates/key-server/key-server-config.yaml:/config/key-server-config.yaml \
  -e CONFIG_PATH=/config/key-server-config.yaml \
   -e MASTER_KEY=<MASTER_KEY> \
   seal-key-server
```

### Permissioned mode

In `Permissioned` mode, the key server only allows decryption requests for Seal policies from explicitly allowlisted packages. This is the recommended mode for B2B deployments where tighter access control and client-specific key separation are required.

Start by generating a master seed for the key server. Use the `seal-cli` tool as `cargo run --bin seal-cli gen-seed`. This command outputs the secret master seed which should be stored securely.

```shell
$ cargo run --bin seal-cli gen-seed
Seed: <MASTER_SEED>
```

Next, create a configuration file in .yaml format following the instructions in the [example config](https://github.com/MystenLabs/seal/tree/main/crates/key-server/key-server-config.yaml) and with the following properties:

- Set the mode to `!Permissioned`.
- Initialize with an empty client configs (clients can be added later).

```yaml
  server_mode: !Permissioned
    client_configs:
```

Set the environment variable `MASTER_KEY` to the master secret seed generated by the `seal-cli` tool, and the environment variable `CONFIG_PATH` pointing to a .yaml configuration file. Run the server using `cargo run --bin key-server`. It should abort after printing a list of unassigned derived public keys (search for logs with the text `Unassigned derived public key`).

```shell
# MASTER_KEY=<MASTER_SEED> CONFIG_PATH=crates/key-server/key-server-config.yaml cargo run --bin key-server 

$ MASTER_KEY=0x680d7268095510940a3cce0d0cfdbd82b3422f776e6da46c90eb36f25ce2b30e CONFIG_PATH=crates/key-server/key-server-config.yaml cargo run --bin key-server 
```

```shell
2025-06-15T02:02:56.303459Z  INFO key_server: Unassigned derived public key with index 0: "<PUBKEY_0>"
2025-06-15T02:02:56.303957Z  INFO key_server: Unassigned derived public key with index 1: "<PUBKEY_1>"
2025-06-15T02:02:56.304418Z  INFO key_server: Unassigned derived public key with index 2: "<PUBKEY_2>"
```

Each supported client must have a registered on-chain key server object to enable discovery and policy validation.

#### Register a client

- Register a new key server on-chain by calling the `create_and_transfer_v1` function from the `seal::key_server` module with an unassigned derived public key. 
  - The derivation index for first client is `0` and its derived public key placeholder is `<PUBKEY_0>`. Similarly, the derivation index for nth client is `n-1` and its derived public key placeholder is `<PUBKEY_n-1>`.

```shell
-- Replace `0` with the appropriate derivation index and derived public key for the nth client.

$ sui client call --function create_and_transfer_v1 --module key_server --package <PACKAGE_ID> --args <YOUR_SERVER_NAME> https://<YOUR_URL> 0 <PUBKEY_0>

# outputs object of type key_server::KeyServer <KEY_SERVER_OBJECT_ID_0>
```

- Add an entry in config file:
  - Set `client_master_key` to type `Derived` with `derivation_index` as `n-1` for the nth client. 
  - Set <KEY_SERVER_OBJECT_ID_0> from the output above. 
  - Include the list of packages this client will use.

For example: 

```yaml
    - name: "alice"
      client_master_key: !Derived
        derivation_index: 0
      key_server_object_id: "<KEY_SERVER_OBJECT_ID_0>"
      package_ids:
        - "0x1111111111111111111111111111111111111111111111111111111111111111"
```

- Restart the key server to apply the config changes.

```shell
$ MASTER_KEY=<MASTER_SEED> CONFIG_PATH=crates/key-server/key-server-config.yaml cargo run --bin key-server 
```

Or with Docker:

```shell
$ docker run -p 2024:2024 \
  -v $(pwd)/crates/key-server/key-server-config.yaml:/config/key-server-config.yaml \
  -e CONFIG_PATH=/config/key-server-config.yaml \
  -e MASTER_KEY=<MASTER_SEED> \
  seal-key-server
```

To add more clients, repeat the above steps with unassigned public keys, e.g `<PUBKEY_1>, <PUBKEY_2>`.

#### Export and Import Keys

In rare cases where you need to export a client key:

- Use the `seal-cli` tool as `cargo run --bin seal-cli derive-key --seed $MASTER_SEED --index X`. Replace `X` with the `derivation_index` of the key you want to export. The tool will output the corresponding master key, which can be imported by another key server if needed.

Here's an example command assuming the key server owner is exporting the key at index 0:

```shell
$ cargo run --bin seal-cli derive-key --seed <MASTER_SEED> --index 0

Master key: <CLIENT_MASTER_KEY>
Public key: <CLIENT_MASTER_PUBKEY>
```

- Disable this key on the current server:
  - Change the client's `client_master_key` type to `Exported`.
  - Set the `deprecated_derivation_index` field with the derivation index.

For example: 

```yaml
     - name: "bob"
       client_master_key: !Exported
         deprecated_derivation_index: 0
```

- To import a client master key into a different key server, first transfer the existing key server object to the target server’s owner. After completing the transfer, the new owner should update the object’s URL to point to their key server.

Here's an example `Sui CLI` command assuming we are exporting <KEY_SERVER_OBJECT_ID_0>:

```shell
$ sui transfer --object-id <KEY_SERVER_OBJECT_ID_0> --to <NEW_OWNER_ADDRESS>
```

The owner of <NEW_OWNER_ADDRESS> can now run:

```shell
$ sui client call --function update --module key_server --package <PACKAGE_ID> --args <KEY_SERVER_OBJECT_ID_0> https://<NEW_URL>
```

- The new key server owner can now add it to their config file:
  - `client_master_key` set to type `Imported`.
  - The name of the environment variable containing the key, e.g. `BOB_BLS_KEY`. This name will be used later.
  - The key server object registered on-chain for this client earlier, e.g. <KEY_SERVER_OBJECT_ID_0>.
  - The list of packages associated with the client.

For example: 

```yaml
     - name: "bob"
       client_master_key: !Imported
         env_var: "BOB_BLS_KEY"
       key_server_object_id: "<KEY_SERVER_OBJECT_ID_0>"
       package_ids:
         - "0x2222222222222222222222222222222222222222222222222222222222222222"
```

- Run the key server using the client master key as the configured environment variable. 

```shell
$ CONFIG_PATH=crates/key-server/key-server-config.yaml BOB_BLS_KEY=<CLIENT_MASTER_KEY> MASTER_KEY=<MASTER_SEED> cargo run --bin key-server
```

Or run with docker: 

```shell
$ docker run -p 2024:2024 \
  -v $(pwd)/crates/key-server/key-server-config.yaml:/config/key-server-config.yaml \
  -e CONFIG_PATH=/config/key-server-config.yaml \
  -e BOB_BLS_KEY=<CLIENT_MASTER_KEY> \
  -e MASTER_KEY=<MASTER_SEED> \
  seal-key-server
```

### Infrastructure requirements

The Seal key server is a lightweight, stateless service designed for easy horizontal scaling. Because it doesn’t require persistent storage, you can run multiple instances behind a load balancer to increase availability and resilience. Each instance must have access to a trusted [Sui Full node](https://docs.sui.io/guides/operator/sui-full-node) — ideally one that’s geographically close to reduce latency during policy checks and key operations.

The server is initialized with a master key (or seed), which must be kept secure. You can store this key using a cloud-based Key Management System (KMS), or in a self-managed software or hardware vault. If you’re importing keys, those should be protected using the same secure storage approach.

To operate the key server securely, it's recommended to place it behind an API gateway or reverse proxy. This allows you to:

- Expose the service over HTTPS and terminate SSL/TLS at the edge
- Enforce rate limiting and prevent abuse
- Authenticate requests using API keys or access tokens
- Optionally integrate usage tracking for commercial or billable offerings, such as logging access frequency per client or package

For observability, the server exposes Prometheus-compatible metrics on port `9184`. You can access raw metrics by running `curl http://0.0.0.0:9184`. These metrics can also be visualized using tools like Grafana. The key server also includes a basic health check endpoint on port `2024`: `curl http://0.0.0.0:2024/health`.

#### CORS configuration
Configure Cross-Origin Resource Sharing (CORS) on your key server to allow applications to make requests directly from the browser. Use the following recommended headers:

```shell
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Request-Id, Client-Sdk-Type, Client-Sdk-Version
Access-Control-Expose-Headers: x-keyserver-version
```
If your key server requires an API key, make sure to include the corresponding HTTP header name in `Access-Control-Allow-Headers` as well.

## The CLI

We provide a CLI tool `seal-cli` for generating keys, encrypting and decrypting messages.
In the following we demonstrate how to use the CLI to encrypt and decrypt messages.

First, we generate three random key pairs.
In Seal, these would be held by three different key servers by running `cargo run --bin seal-cli genkey`.
The output is random and will be different each time, but for this demo, we assume that we get the following three outputs:
```shell
Masterkey: 6b2eb410ad729f5b2ffa54ca5a2186ef95a1e31df3cccdd346b24f2262279440
Publickey: aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62

Masterkey: 54152de3b08708b18ce5cd69b0c4d732f093cba2ba5c102c4f26e0f210daab75
Publickey: b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f

Masterkey: 2ea9ccdaa224e9fc34ef1458fced17562b2d3757c1ebb223c627173ac6f93806
Publickey: 95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623
```

For this example, assume that the onchain object ids for the three `KeyServer`s are `0x1`, `0x2`, and `0x3` respectively.
Also, assume that the package id is `0x0` and the threshold in use is 2.
Using the above public keys, we can now encrypt the message `54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c` under the id `53e66d756e6472206672f3f069`.  

```shell
$ cargo run --bin seal-cli encrypt-aes --message 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c --package-id 0x0 --id 53e66d756e6472206672f3f069 --threshold 2 aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62 b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f 95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623 -- 0x1 0x2 0x3
```

which gives an output like the following:

```shell
Encrypted object (bcs): 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800
Symmetric key: e39651e5aa01949ba5174c67a2c37f58ee8217392ba2275a5789f0ac2c3540d8
```

!!! tip
    The encryption is randomized, so the output will be different each time you run the command, even with the same input message and keys.

Note that the output contains both the encrypted object in BCS format and the symmetric key, that was used to encrypt the message.
The encrypted object can be shared, e.g., onchain or using Walrus, but the symmetric key should be kept secret because it can be used to decrypt the message directly as follows:

```shell
$ cargo run --bin seal-cli symmetric-decrypt --key e39651e5aa01949ba5174c67a2c37f58ee8217392ba2275a5789f0ac2c3540d8 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800
```
which returns the original message:

```shell
Decrypted message: 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c
```

To decrypt the message, we extract user secret keys for the key servers using their master keys. In practice, those would be retrieved from the key servers as described above.

For the first key server, the command is as follows:

```shell
$ cargo run --bin seal-cli extract --package-id 0x0 --id 53e66d756e6472206672f3f069 --master-key 6b2eb410ad729f5b2ffa54ca5a2186ef95a1e31df3cccdd346b24f2262279440
```

and doing this for all three servers, we get the following outputs:

```shell
User secret key: b882fccc1f021c3b995e63a1f7329fcf71f750844195125e6a6b319dde9a7afc24b0c1a29d5a55f5908cf440dd7b3da3

User secret key: 97c30ec9dd6dafa187b732004a4d33414446115af35a1b1c0eb78af094f6e0d4d06830d5d7be9140cbcb05c63aaf7e28

User secret key: 8547bf7a70f7c1f3ad4070af8bc969f4afb82eddfcdca129fcedd6b7df1c91527ccd8d35dd33d0552cd95ba302ee6166
```

Using these extracted keys, we can now decrypt the encrypted object. Since we set the threshold to 2, we need to provide the keys from two servers, and here, we use the first two. 
```shell
$ cargo run --bin seal-cli decrypt 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800 b882fccc1f021c3b995e63a1f7329fcf71f750844195125e6a6b319dde9a7afc24b0c1a29d5a55f5908cf440dd7b3da3 97c30ec9dd6dafa187b732004a4d33414446115af35a1b1c0eb78af094f6e0d4d06830d5d7be9140cbcb05c63aaf7e28 -- 0x1 0x2
```

which should give the following output:

```shell
Decrypted message: 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c
```
which, as expected, is the same as the original message.

The content of an encrypted object can be viewed using the `parse` command. Calling it using the object used in the example above:

```shell
$ cargo run --bin seal-cli parse 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800
```

shows the content of the encrypted object in a human-readable format:

```shell
Version: 0
Package ID: 0x0000000000000000000000000000000000000000000000000000000000000000
ID: 53e66d756e6472206672f3f069
Services: share index:
  0x0000000000000000000000000000000000000000000000000000000000000001: 1
  0x0000000000000000000000000000000000000000000000000000000000000002: 2
  0x0000000000000000000000000000000000000000000000000000000000000003: 3
Threshold: 2
Ciphertext:
  Type: AES-256-GCM
  Blob: 3b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e77728
  AAD: None

Encrypted shares:
  Type: Boneh-Franklin BLS12-381
  Shares:
    b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd17
    48b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aa
    da89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d36
  Encapsulation: 841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf7
```

