# Key server operations

Use this guide to operate a Seal key server in either of the following scenarios:

- **As a service provider:** run a key server as a service for developers.
- **As a developer:** run a key server for your own development and testing.

Use the relevant package ID `<PACKAGE_ID>` to register your key server on the Sui network `<NETWORK>`:

| <NETWORK> | <PACKAGE_ID> | 
| -------- | ------- |
| Testnet | 0x927a54e9ae803f82ebf480136a9bcff45101ccbe28b13f433c89f5181069d682 |
| Mainnet | 0xa212c4c6c7183b911d0be8768f4cb1df7a383025b5d0ba0c014009f0f30f5f8d | 

A Seal key server can operate in one of two modes - `Open` or `Permissioned`:

- **Open mode**: In open mode, the key server accepts decryption requests for *any* onchain package. It uses a single master key to serve all access policies across packages. This mode is suitable for public or general-purpose deployments where package-level isolation is not required.
- **Permissioned mode**: In permissioned mode, the key server restricts access to a manually approved list of packages associated with specific clients or applications. Each client is served using a dedicated master key.
    - This mode also supports importing or exporting the client-specific key if needed, for purposes such as disaster recovery or key server rotation.
    - The approved package ID for a client **must** be the package’s **first published version**. This ensures that the key server continues to recognize the package after upgrades. One does not need to add new versions of the package to a client's allowlist.

You can choose the mode that best fits your deployment model and security requirements. The following sections provide more details on both options. Also see [Seal CLI](./SealCLI.md) for reference.

## Open mode

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
- Set the `key_server_object_id` field to `<KEY_SERVER_OBJECT_ID>`, the ID of the key server object you registered on-chain. 

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

## Permissioned mode

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

### Register a client

- Register a new key server on-chain by calling the `create_and_transfer_v1` function from the `seal::key_server` module with an unassigned derived public key. 
    - The derivation index for first client is `0` and its derived public key placeholder is `<PUBKEY_0>`. Similarly, the derivation index for nth client is `n-1` and its derived public key placeholder is `<PUBKEY_n-1>`.

```shell
-- Replace `0` with the appropriate derivation index and derived public key for the nth client.

$ sui client call --function create_and_transfer_v1 --module key_server --package <PACKAGE_ID> --args <YOUR_SERVER_NAME> https://<YOUR_URL> 0 <PUBKEY_0>

# outputs object of type key_server::KeyServer <KEY_SERVER_OBJECT_ID_0>
```

- Add an entry in config file:
    - Set `client_master_key` to type `Derived` with `derivation_index` as `n-1` for the nth client. 
    - Set `<KEY_SERVER_OBJECT_ID_0>` from the output above. 
    - Include the list of packages this client will use.

!!! info
    You can map multiple different packages from a developer to the same client (e.g., for different features or apps). However, if the developer later decides to [export the client key](#export-and-import-keys), access will be revoked for **all** packages mapped to that client. Confirm whether they prefer separate client per package (allowing for granular revocation) or a single consolidated client (allowing for simpler operations).

!!! info
    When adding a package for a feature or app, you must add the package ID of the package’s **first published version**. This ensures that the key server continues to recognize the package after upgrades. You do not need to add new versions of a package to a client's allowlist.

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

### Export and Import Keys

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

Here's an example `Sui CLI` command assuming we are exporting `<KEY_SERVER_OBJECT_ID_0>`:

```shell
$ sui transfer --object-id <KEY_SERVER_OBJECT_ID_0> --to <NEW_OWNER_ADDRESS>
```

The owner of `<NEW_OWNER_ADDRESS>` can now run:

```shell
$ sui client call --function update --module key_server --package <PACKAGE_ID> --args <KEY_SERVER_OBJECT_ID_0> https://<NEW_URL>
```

- The new key server owner can now add it to their config file:
    - `client_master_key` set to type `Imported`.
    - The name of the environment variable containing the key, e.g. `BOB_BLS_KEY`. This name will be used later.
    - The key server object registered on-chain for this client earlier, e.g. `<KEY_SERVER_OBJECT_ID_0>`.
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

## Infrastructure requirements

The Seal key server is a lightweight, stateless service designed for easy horizontal scaling. Because it doesn’t require persistent storage, you can run multiple instances behind a load balancer to increase availability and resilience. Each instance must have access to a trusted [Sui Full node](https://docs.sui.io/guides/operator/sui-full-node) — ideally one that’s geographically close to reduce latency during policy checks and key operations.

The server is initialized with a master key (or seed), which must be kept secure. You can store this key using a cloud-based Key Management System (KMS), or in a self-managed software or hardware vault. If you’re importing keys, those should be protected using the same secure storage approach.

To operate the key server securely, it's recommended to place it behind an API gateway or reverse proxy. This allows you to:

- Expose the service over HTTPS and terminate SSL/TLS at the edge
- Enforce rate limiting and prevent abuse
- Authenticate requests using API keys or access tokens
- Optionally integrate usage tracking for commercial or billable offerings, such as logging access frequency per client or package

For observability, the server exposes Prometheus-compatible metrics on port `9184`. You can access raw metrics by running `curl http://0.0.0.0:9184`. These metrics can also be visualized using tools like Grafana. The key server also includes a basic health check endpoint on port `2024`: `curl http://0.0.0.0:2024/health`.

### CORS configuration
Configure Cross-Origin Resource Sharing (CORS) on your key server to allow applications to make requests directly from the browser. Use the following recommended headers:

```shell
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Request-Id, Client-Sdk-Type, Client-Sdk-Version
Access-Control-Expose-Headers: x-keyserver-version
```
If your key server requires an API key, make sure to include the corresponding HTTP header name in `Access-Control-Allow-Headers` as well.
