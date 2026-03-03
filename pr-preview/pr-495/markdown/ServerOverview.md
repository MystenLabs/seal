Seal supports two server types for key management: **Committee** and **Independent**.

## Committee server type

A committee server appears onchain as a single logical key server — one object ID and public key — while internally being operated by multiple independent providers coordinating through threshold cryptography. The committee maintains a stable public key with rotatable membership, allowing operators to be added, removed, or replaced over time without client updates or data re-encryption.

Behind the scenes, operators participate in a Distributed Key Generation (DKG) ceremony that produces distributed key shares. Each operator runs a key server that holds only its partial share. When a client requests a decryption key, the request flows through an aggregator, which collects encrypted partial responses from operators and combines them into a single encrypted result. The client then decrypts the final key locally.

Importantly, no single operator ever holds the full master key. The aggregator cannot decrypt data. And the public key exposed onchain remains stable even if membership changes.

Distributed trust becomes infrastructure-native, while your integration remains unchanged.

### How it works

**Open deployment**
- Anyone can set up a committee with its own operators.
- Operators participate in a DKG ceremony and run their key servers with the generated key shares.
- Membership can be added, removed, or replaced through coordinated rotation ceremonies.
- The onchain object ID and public key remain stable, so clients are unaware of membership changes and existing encrypted data and configurations remain valid.

**Aggregator gateway**
- Clients send requests to an aggregator, which coordinates partial key responses from committee member key servers and returns a single aggregated response.
- Committee members return partial responses encrypted under the user's public key.
- The aggregator is trustless — it holds no key material and cannot decrypt data on its own. Anyone can run one.

## Key properties

- The onchain object ID and public key remain stable even as membership changes — no client updates or data re-encryption required.
- Clients connect to a single aggregator rather than individual committee member key servers, simplifying client integration.
- No single entity holds the complete master key — the key is distributed across committee members.
- All packages are supported without requiring an allowlist or per-client approval.

### Use cases

- Deployments requiring distributed key management across multiple parties.
- Multi-party governance scenarios with changing membership.
- Long-term deployments where operator membership may change over time.

## Independent server type

Independent servers are operated by a single entity. They offer two modes: **Open**, which anyone can use for any package, and **Permissioned**, which provides per-client access control with approved package IDs.

### How it works

An independent server is registered with one object ID and one server URL. Clients configure the threshold and communicate directly with the key servers. Each independent server counts as one server in your threshold configuration. Changing the selection of key servers requires re-encryption of existing data, since public keys change.

**Open mode**
- Uses a single master key to serve all access policies across all packages.
- Accepts decryption requests for any on-chain package without restrictions.
- No client management or API keys required.

**Permissioned mode**
- Restricts access to a manually approved list of packages.
- Each client gets its own key server object ID and is served using a dedicated master key derived from a master seed.
- Each client is associated with specific package IDs.
- Clients must obtain API keys for access.
- Supports key import and export for disaster recovery or key server rotation.

### Key properties

- A single entity operates the server.
- Changing the selection of key servers requires data re-encryption, since public keys change.

**Open mode**
- Single master key serves all packages; no package-level access control.
- No client management or API keys required.

**Permissioned mode**
- Each client must be added to the key server configuration by the operator, with specific package IDs allowlisted.
- Upon approval, the client receives their own key server object ID and API keys.
- Supports key export/import for disaster recovery or key server rotation.

### Use cases

**Open mode**
- Development and testing environments
- Public or general-purpose deployments

**Permissioned mode**
- B2B deployments with multiple clients
- Multi-tenant scenarios requiring client isolation
- Deployments with per-package access control requirements

## Next steps

For client usage, see [Using Seal](/UsingSeal) to learn how to integrate different Seal server types into your application.

For server operators:

- **Independent key server**: See [Key Server Operations for Independent Server Type](/KeyServerOps) for detailed instructions on Open and Permissioned mode setup.
- **Committee key server**: See [Key Server Operations for Committee Server Type](/KeyServerCommitteeOps) for detailed setup instructions including DKG ceremonies, key rotation, and key server setup.
- **Aggregator server** (Committee server type only): See [Aggregator Server](/Aggregator) for aggregator configuration and setup.