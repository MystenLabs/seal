Seal supports two fundamentally different server types for key management: **Committee** (requires an aggregator server) and **Independent**.

## Committee server type

A committee server appears to clients as a single key server, but multiple independent key servers with distributed key shares operate it. The committee's internal threshold provides built-in distributed trust, and committee members can rotate without changing the public key or requiring data re-encryption.

### How it works

From the client perspective, a committee server appears as one key server configured with one object ID and one aggregator URL. You can use it in threshold configurations alongside independent servers.

Clients have no knowledge of or interaction with individual committee members. The committee's internal threshold (for example, 3-of-5 members) is completely transparent.

From the operator perspective, multiple operators participate in a distributed key generation (DKG) ceremony to generate individual master shares without any single party ever holding the complete master key. **An aggregator server is required** to coordinate with individual committee member key servers using API keys.

Each committee member runs their own key server using their master share. The aggregator collects partial keys from the committee key servers and combines them to serve the client. Clients send decryption requests to the aggregator server.

Committee servers support all packages without requiring an allowlist or per-client approval.

Committee members can be added, removed, or replaced through a key rotation ceremony while maintaining the following properties:

- The key server's public key remains constant throughout its lifetime.
- Existing encrypted data remains accessible without re-encryption.
- Clients continue using the same key server object without any changes.

### Benefits

Using a committee server provides enhanced security through distributed key management, as no single entity holds the complete master key. Committee servers are resilient to individual member compromise and offer simplified client configuration where clients only need to communicate with the aggregator, not individual committee members.

Committee member rotation occurs while maintaining the same public key, meaning you can add, remove, or replace members without affecting clients or requiring data re-encryption. Flexible governance allows committee membership changes over time.

### Use cases

Use cases for the committee server include:

- High-security deployments requiring distributed trust and avoiding single points of failure.
- Multi-party governance scenarios with changing membership.
- Long-term deployments needing operator flexibility without re-encryption.

### Considerations

When using committee servers, consider the following:

- Key share setup and rotation require coordination among parties.
- The setup requires an additional aggregator server component for client communication. The aggregator is trustless and no key storage is required.

## Independent server type

Independent servers are operated by a single entity. They offer two modes: **Open**, which anyone can use for any package, and **Permissioned**, per-client access control with approved package IDs.

### How it works

From the client perspective, the independent server appears as one key server configured with one object ID and one server URL. It can be used in threshold configurations alongside other independent servers or committee servers. It uses direct client-to-key-server communication.

From the operator perspective, a single entity operates the key server with two operating modes available:
  - **Open mode**: Uses a single master key to serve all access policies across all packages; accepts decryption requests for any on-chain package without restrictions; no client management or API keys required
  - **Permissioned mode**: Restricts access to a manually approved list of packages; each client is associated with specific package IDs; each client is served using a dedicated master key derived from a master seed; clients must obtain API keys for access; supports key import and export for disaster recovery or key server rotation

### Benefits

**Open mode**: Simple setup and configuration, no client management required

**Permissioned mode**: Client-level isolation with dedicated keys, fine-grained access control per package, supports key export/import for flexibility

### Use cases 

Use cases for the independent server include:

#### Open mode

- Development and testing environments
- Public or general-purpose deployments

#### Permissioned mode

- B2B deployments with multiple clients
- Multi-tenant scenarios requiring client isolation
- Production environments with access control requirements

### Considerations

Consider the following when using independent servers:

- Single point of operation (single entity operates the server)
- No rotation support: Changing selection of key servers requires data re-encryption since public keys change
- Open mode: No package-level access control, single master key serves all packages, not suitable for B2B or multi-tenant scenarios requiring isolation
- Permissioned mode: Requires client registration and management, manual approval process for new packages, higher operational overhead

Learn more about [key server operations for independent server types](/KeyServerOps).

## Next steps

For client usage, see [Using Seal](/UsingSeal) to learn how to integrate Seal into your application.

For server operators:

- **Independent key server**: See [Key Server Operations for Independent Server Type](/KeyServerOps) for detailed instructions on Open and Permissioned mode setup.
- **Committee key server**: See [Key Server Operations for Committee Server Type](/KeyServerCommitteeOps) for detailed setup instructions including DKG ceremonies, key rotation, and key server setup.
- **Aggregator server** (Committee server type only): See [Aggregator Server](/Aggregator) for aggregator configuration and setup.