## Table of Contents:

- [Introduction](README.md)
- [Seal Design](Design.md)
- [Security Best Practices and Risk Mitigations](SecurityBestPractices.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Using Seal

## For Dapp Developers

**Access control management**

Packages should define `seal_approve*` functions in their modules to control access to the keys associated with their identity namespace. Guidelines for defining `seal_approve*` functions::
- A package can include multiple `seal_approve*` functions, each implementing different access control logic and accepting different input parameters.
- The first parameter must be the requested identity, excluding the package ID prefix. For example: `id: vector<u8>`.
- If access is not granted, the function should abort without returning a value.
- To support future upgrades and maintain backward compatibility, define `seal_approve*` functions as non-public `entry` functions when possible, and either version your shared objects or use a shared global object with the latest version (see [whitelist](./move/patterns/sources/whitelist.move) and [subscription](./move/patterns/sources/subscription.move) examples).

See [move/patterns](./move/patterns) for examples and useful patterns.

As `seal_approve*` functions are standard Move functions, they can be tested locally using Move tests.
Building and publishing the code can be done using the [`Sui CLI`](https://docs.sui.io/references/cli), e.g.,: 
```shell
cd examples/move
sui move build
sui client publish --gas-budget 100000000
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

**Encryption and decryption**

The recommended way to encrypt and decrypt the data is to use the [Seal SDK](https://www.npmjs.com/package/@mysten/seal).

First, the app must select the set of key servers it intends to use. Each key server registers its name, public key, and URL onchain by creating a `KeyServer` object. To reference a key server, use the object ID of its corresponding `KeyServer`. A common approach for app developers is to use a fixed, preconfigured set of key servers within their app. Alternatively, the app can support a dynamic selection of key servers, for example, allowing users to choose which servers to use. In this case, the app should display a list of available key servers along with their URLs. After the user selects one or more servers, the app must verify that each provided URL corresponds to the claimed key server.

A key server may be used multiple times to enable weighting, which allows the app to specify how many times a key server can contribute towards reaching the decryption threshold. This is useful for scenarios where some key servers are more reliable or trusted than others, or when the app wants to ensure that certain key servers are always included in the decryption process.

> [!IMPORTANT]
> Anyone can create an onchain `KeyServer` object that references a known URL (such as `seal.mystenlabs.com`) but uses a different public key. To prevent impersonation, the SDK performs a verification step: it fetches the object ID from the server’s `/v1/service` endpoint and compares it with the object ID registered onchain.

Apps can retrieve a list of trusted (allowlisted) Seal key servers using the `getAllowlistedKeyServers()` function, or use a custom app-defined or user-defined list.

Next, the app should create a `SealClient` object for the selected key servers.
```typescript
const suiClient = new SuiClient({ url: getFullnodeUrl('testnet') });
const client = new SealClient({
  suiClient,
  serverConfigs: getAllowlistedKeyServers('testnet').map((id) => ({
    objectId: id,
    weight: 1,
  })),
  verifyKeyServers: false,
});
```
The `serverConfigs` is a list of objects, where each object contains a key server object ID and its weight. Recall that the weight indicates how many times the key server can contribute towards reaching the decryption threshold. In this example, all key servers are given equal weight 1. The object may contain also the fields `apiKeyName` and `apiKey` for sending the HTTP header `apiKeyName: apiKey` in case a key server expects an API key.

Set `verifyKeyServers` to `true` if the app or user needs to confirm that the provided URLs correctly correspond to the claimed key servers, as described above. Note that enabling verification introduces additional round-trip requests to the key servers. For best performance, use this option primarily when verifying key servers at app startup. Set `verifyKeyServers` to `false` when verification is not required.

Next, the app can call the `encrypt` method on the `client` instance. This function requires the following parameters:
- the encryption threshold
- the package id of the deployed contract containing the `seal_approve*` functions
- the id associated with the access control policy
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

> [!NOTE]
> Seal supports encrypting an ephemeral symmetric key, which you can use to encrypt your actual content. This approach is useful when storing encrypted data immutably on Walrus while keeping the encrypted key separately on Sui. By managing the key separately, you can update access policies or rotate key servers without modifying the stored content.

> [!TIP]
> The `encryptedBytes` returned from the encryption call can be parsed using `EncryptedObject.parse(encryptedBytes)`. It returns an EncryptedObject instance that includes metadata such as the ID and other associated fields.

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

> [!NOTE]
> Notes on Session Key
> 1. You can also optionally initialize a `SessionKey` with a passed in Signer in the constructor. This is useful for classes that extend `Signer`, e.g. `EnokiSigner`.
> 2. You can optionally set an `mvr_name` value in the `SessionKey`. This should be the [Move Package Registry](https://www.moveregistry.com/) name for the package. Seal requires the MVR name to be registered to the first version of the package for this to work. If this is set, the message shown to the user in the wallet would use the much more readable MVR package name instead of `packageId`.
> 3. You can optionally store the `SessionKey` object in [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) instead of localStorage if you would like to persist the SessionKey across tabs. See usage for `import` and `export` methods in the SessionKey class. 

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

> [!TIP]
> To debug a transaction, call `dryRunTransactionBlock` directly with the transaction block.

The `SealClient` caches keys retrieved from Seal key servers to optimize performance during subsequent decryptions, especially when the same id is used across multiple encryptions. 

To retrieve multiple keys efficiently, use the `fetchKeys` function with a multi-command PTB. This approach is recommended when multiple keys are required, as it reduces the number of requests to the key servers. Because key servers may apply rate limiting, developers should design their applications and access policies to minimize the frequency of key retrieval requests.

```typescript
await client.fetchKeys({
    ids: [id1, id2],
    txBytes: txBytesWithTwoSealApproveCalls,
    sessionKey,
    threshold: 2,
});
```

See our [integration tests](https://github.com/MystenLabs/ts-sdks/blob/main/packages/seal/test/unit/integration.test.ts) for an E2E example. Also, see our [example app](https://seal-example.vercel.app/) for a demonstration of allowlist/NFT gated content access.

On-chain decryption in Move is supported using derived keys. For an example, see [voting.move](./move/patterns/sources/voting.move).

> [!TIP]
> If a key server request fails with an `InvalidParameter` error, the cause may be a recently created on-chain object in the PTB input. The key server's full node may not have indexed it yet. Wait a few seconds and retry the request, as subsequent attempts should succeed once the node is in sync.

**Mysten Labs Key Servers**

Mysten Labs maintains a set of key servers for the Seal project:
- mysten-testnet-1: https://seal-key-server-testnet-1.mystenlabs.com
- mysten-testnet-2: https://seal-key-server-testnet-2.mystenlabs.com

Currently, access to above key servers is permissive. However, rate limiting is planned for the future, with a target of 4–5 requests per second per user.

## For key server operators

### Setup
Use the `seal-cli` tool to generate a new master key using `cargo run --bin seal-cli genkey`.

Key servers can be registered onchain to enable discoverability. To register a key server, call the `create_and_transfer_v1` function in the `seal::key_server` module. For example:

```shell
sui client call --function create_and_transfer_v1 --module key_server --package 0x62c79dfeb0a2ca8c308a56bde530ccf3846535e1623949d45c90d23128afff52 --args mysten-dev-1 https://seal-key-server-testnet-1.mystenlabs.com 0 0xa023acbf600401017ee17bf918106ea9911914ca017aa3ab9ab5c64beb9bb5236fd9d4d5b5645dc3bc0d4f732ed04fc60d14b9f37987fe5eeb4db07fc0982904ce1ed0b07607ae2e99086e141f6c6a1df6def5f5d434ca7c09856a3750c92969 --gas-budget 10000000
```

Run the server using `cargo run --bin key-server` either with the environment variable `CONFIG_PATH` pointing to a .yaml configuration file (see [crates/key-server/key-server-config.yaml] for an example) or by setting the required environment variables directly:
- `MASTER_KEY` is the master secret key generated by the `seal-cli` tool.
- `KEY_SERVER_OBJECT_ID` is the object id of the registered key server.
- `NETWORK` specifies the network to connect to, such as `testnet`, `mainnet`, or other supported environments. To use a custom full node, set `NETWORK` to `custom`. When using the `custom` option, you must also set the `NODE_URL` and `GRAPHQL_URL` environment variables with the URLs of your full node and GraphQL endpoint, respectively. Note that the GraphQL support is deprecated and will be removed in a future release.

Example:
```shell
export MASTER_KEY="KYinoC5hVWeWqOUU9dw7PVHiROYFWB/nQZ55Kmytjig="
export KEY_SERVER_OBJECT_ID="0x1ee708e0d09c31593a60bee444f8f36a5a3ce66f1409a9dfb12eb11ab254b06b"
export NETWORK="testnet"
cargo run --bin key-server
```

Alternatively, Docker can be used to run the key server. For example:

```shell
docker build -t seal-key-server .
docker run -p 2024:2024 -e MASTER_KEY="KYinoC5hVWeWqOUU9dw7PVHiROYFWB/nQZ55Kmytjig=" -e KEY_SERVER_OBJECT_ID="0x1ee708e0d09c31593a60bee444f8f36a5a3ce66f1409a9dfb12eb11ab254b06b" -e NETWORK="testnet" seal-key-server
```
<!-- 
Example of a request:
```
curl http://0.0.0.0:2024/health

curl http://0.0.0.0:2024/v1/service

curl -H 'Content-Type: application/json' -d '{"ptb":"AwAgv7n4Pj/owIGk+nMEXJ4KbXvVytgdurspb4BZJ8RdY6MAISDAbM35ybJGgprxCy0H1MuWKsGvRO5zQfk4jn+oAcufAwEBwGzN+cmyRoKa8QstB9TLlirBr0Tuc0H5OI5/qAHLnwOtCKsRAAAAAAABAG0lMvMLkGCIOUyRinodOfXWx1Bxm0JCFS/6RhBLoEUxCXdoaXRlbGlzdAtrbXNfYXBwcm92ZQADAQAAAQEAAQIA","enc_key":"lR69cNXFuB3zyjDI12syH1XC4sfaTo63Ylms/I8yO39OTvuDmngPln8pMTJEwq9v","request_signature":"Ut6iy+f+l/FeMgcim+s3jkQO86nxgqhWweOfqFWwQGi3gercjBnzhoMmzrb0i0Z79iXUwE56GwM/2mgHDRz+CA==","certificate":{"session_vk":"w+xC1R2fZDJeQW4lERxYsd3XVAYy7wOx5sKsIWdwlWw=","creation_time":1737671115293,"ttl_min":9,"signature":"APDPqXOr+HqHMw48qNwDMPezgvwDzojcIaBztBdOYuTaomY2pWBVyXbaFyNN+huz5f44ZgMG1D6PnF/H/OGgkADgFHRr36qyRWIXLGJ/iArkqpw1lMzlikMeDlBjTOheIw=="}}' -X POST http://0.0.0.0:2024/v1/fetch_key
``` -->

Key servers expose a set of metrics via a Prometheus server running on port 9184. They can be viewed in raw form by calling
```shell
curl http://0.0.0.0:9184
```
or used in a data visualization and analytics tool like Grafana.

### Infrastructure requirements

The key server is a lightweight, stateless service that does not require persistent storage. Its stateless design supports horizontal scalability. The service must have access to a trusted full node, ideally one located nearby to reduce latency.

The key server is initialized with an IBE master key, which must be securely stored and accessible only to the service, for example, using a cloud-based key management system (KMS), or a self-managed software or hardware vault.

To protect the service against denial-of-service (DoS) attacks, implement standard mitigations such as rate limiting at the API gateway layer.

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
cargo run --bin seal-cli encrypt-aes --message 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c --package-id 0x0 --id 53e66d756e6472206672f3f069 --threshold 2 aeb258b9fb9a2f29f74eb0a1a895860bb1c6ba3f9ea7075366de159e4764413e9ec0597ac9c0dad409723935440a45f40eee4728630ae3ea40a68a819375bba1d78d7810f901d8a469d785d00cfed6bd28f01d41e49c5652d924e9d19fddcf62 b1076a26f4f82f39d0e767fcd2118659362afe40bce4e8d553258c86756bb74f888bca79f2d6b71edf6e25af89efa83713a223b48a19d2e551897ac92ac7458336cd489be3be025e348ca93f4c94d22594f96f0e08990e51a7de9da8ff29c98f 95fcb465af3791f31d53d80db6c8dcf9f83a419b2570614ecfbb068f47613da17cb9ffc66bb052b9546f17196929538f0bd2d38e1f515d9916e2db13dc43e0ccbd4cb3d7cbb13ffecc0b68b37481ebaaaa17cad18096a9c2c27a797f17d78623 -- 0x1 0x2 0x3
```
which gives an output like the following:
```shell
Encrypted object (bcs): 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800
Symmetric key: e39651e5aa01949ba5174c67a2c37f58ee8217392ba2275a5789f0ac2c3540d8
```

> [!TIP]
> The encryption is randomized, so the output will be different each time you run the command, even with the same input message and keys.

Note that the output contains both the encrypted object in BCS format and the symmetric key, that was used to encrypt the message.
The encrypted object can be shared, e.g., onchain or using Walrus, but the symmetric key should be kept secret because it can be used to decrypt the message directly as follows:
```shell
cargo run --bin seal-cli symmetric-decrypt --key e39651e5aa01949ba5174c67a2c37f58ee8217392ba2275a5789f0ac2c3540d8 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800
```
which returns the original message:
```shell
Decrypted message: 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c
```

To decrypt the message, we extract user secret keys for the key servers using their master keys. In practice, those would be retrieved from the key servers as described above.

For the first key server, the command is as follows:
```shell
cargo run --bin seal-cli extract --package-id 0x0 --id 53e66d756e6472206672f3f069 --master-key 6b2eb410ad729f5b2ffa54ca5a2186ef95a1e31df3cccdd346b24f2262279440
```
and doing this for all three servers, we get the following outputs:
```shell
User secret key: b882fccc1f021c3b995e63a1f7329fcf71f750844195125e6a6b319dde9a7afc24b0c1a29d5a55f5908cf440dd7b3da3

User secret key: 97c30ec9dd6dafa187b732004a4d33414446115af35a1b1c0eb78af094f6e0d4d06830d5d7be9140cbcb05c63aaf7e28

User secret key: 8547bf7a70f7c1f3ad4070af8bc969f4afb82eddfcdca129fcedd6b7df1c91527ccd8d35dd33d0552cd95ba302ee6166
```

Using these extracted keys, we can now decrypt the encrypted object. Since we set the threshold to 2, we need to provide the keys from two servers, and here, we use the first two. 
```shell
cargo run --bin seal-cli decrypt 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800 b882fccc1f021c3b995e63a1f7329fcf71f750844195125e6a6b319dde9a7afc24b0c1a29d5a55f5908cf440dd7b3da3 97c30ec9dd6dafa187b732004a4d33414446115af35a1b1c0eb78af094f6e0d4d06830d5d7be9140cbcb05c63aaf7e28 -- 0x1 0x2
```
which should give the following output:
```shell
Decrypted message: 54686520646966666572656e6365206265747765656e2061204d697261636c6520616e64206120466163742069732065786163746c792074686520646966666572656e6365206265747765656e2061206d65726d61696420616e642061207365616c
```
which, as expected, is the same as the original message.

The content of an encrypted object can be viewed using the `parse` command. Calling it using the object used in the example above,
```shell
cargo run --bin seal-cli parse 0000000000000000000000000000000000000000000000000000000000000000000d53e66d756e6472206672f3f069030000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000003030200841b3a59241e099e8b8d9cec1d531b1e8fe4b4170433e30d9aaa9fc764201f69e589a0b2a0e65bfb279d4b25ee1ce8141812bfb785abdb05134c3958f53c2e81e7bc06e5c1f1ebd7e489b5cf652216b13e6b7c2b13da70a4a7c05c3544a1ddf703b627cb3268d74c74ead83fb827c60fa23c1d192fb8a7db50ea8721bf7c95bd1748b5ed7da6873f4a5b539cb16085e5cd174206db776c04902c7d8c02d6fa47aada89c2fa0692973a83a7a900f2b0dd7f7475e55095d0df7b0483ae1192761d368985e51d72597df02764c654536130c905a8de4a6c9169643e9dd01efab17a9200723b7d7b2ede8924cfb3687a0c41599b87bebc9d913d8eb81a2027ba8286a7b2cd9f5303b6b551fa545189e2f13cb65642b66595ca4256f42cdda2ac78af39abde06184da29131437e1417ebb35c7136d2c74b8ab9fa4147077bbcdbfafc2b05458792eefe0424fedef10247b8b3c787e7772800
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

[Back to table of contents](#table-of-contents)
