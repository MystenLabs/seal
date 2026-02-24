# SEAL DKG Protocol Design

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [On-chain Smart Contract Design](#on-chain-smart-contract-design)
4. [State Machine](#state-machine)
5. [Fresh DKG Flow](#fresh-dkg-flow)
6. [Key Rotation Flow](#key-rotation-flow)
7. [Upgrade Management](#upgrade-management)
8. [Security Properties](#security-properties)

## Overview

SEAL implements a distributed threshold cryptography system using committee-based key servers on the Sui blockchain. The Move smart contract (`seal_committee::seal_committee`) orchestrates a Distributed Key Generation (DKG) protocol where:

- **No single party knows the master private key**
- **Threshold `t-of-n` members required for decryption**
- **Committee can rotate while preserving master public key**
- **On-chain governance for package upgrades**

### Key Design Principles

1. **Trustless Coordination**: Smart contract enforces protocol rules without trusted coordinator
2. **Unanimous Approval**: All `n` members must verify and approve DKG results
3. **Cryptographic Verification**: VSS commitments and NIZK proofs ensure correctness
4. **Atomic Rotation**: Old committee destroyed only after new committee finalized

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Sui Blockchain Layer                        │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │              Committee Object (Shared)                   │ │
│  │  ┌────────────────────────────────────────────────────┐  │ │
│  │  │ State: Init | PostDKG | Finalized                  │  │ │
│  │  │ • members: vector<address>  (party_id = index)     │  │ │
│  │  │ • threshold: u16                                   │  │ │
│  │  │ • old_committee_id: Option<ID>  (for rotation)     │  │ │
│  │  └────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  Dynamic Object Fields:                                   │ │
│  │  ┌────────────────────────────────────────────────────┐  │ │
│  │  │ KeyServer (key = committee_id)                     │  │ │
│  │  │ • pk: vector<u8>  (Master public key, G2Element)   │  │ │
│  │  │ • threshold: u16                                   │  │ │
│  │  │ • partial_key_servers: VecMap<address, PKS>        │  │ │
│  │  │ • version: u64  (for rotation tracking)            │  │ │
│  │  └────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌────────────────────────────────────────────────────┐  │ │
│  │  │ UpgradeManager (key = UpgradeManagerKey())         │  │ │
│  │  │ • cap: UpgradeCap                                  │  │ │
│  │  │ • upgrade_proposal: Option<UpgradeProposal>        │  │ │
│  │  └────────────────────────────────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
└────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Transactions
                              │
┌────────────────────────────────────────────────────────────────┐
│                    Off-chain Layer                             │
│                                                                │
│  • DKG message exchange (via coordinator)                     │
│  • Cryptographic computation (VSS, shares, proofs)            │
│  • Member verification before on-chain proposal               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## On-chain Smart Contract Design

### Core Data Structures

#### Committee (lines 88-97)

The Committee object is a **shared object** that tracks the state of the DKG protocol:

```move
public struct Committee has key {
    id: UID,
    threshold: u16,
    /// Ordered vector where index = party_id
    members: vector<address>,
    state: State,
    /// For rotation: links to the committee being replaced
    old_committee_id: Option<ID>,
}
```

**Design Rationale:**
- **Shared object**: Allows all members to mutate state via transactions
- **Ordered members**: Vector index serves as deterministic `party_id`
- **Immutable members/threshold**: Cannot change after creation (must rotate to new committee)
- **Old committee link**: Enables verification during rotation

#### State Enum (lines 67-85)

The committee transitions through three states:

```move
public enum State has drop, store {
    /// Initial state: members register their public keys
    Init {
        members_info: VecMap<address, MemberInfo>,
    },

    /// Post-DKG state: first member proposed, others must verify and approve
    PostDKG {
        members_info: VecMap<address, MemberInfo>,
        partial_pks: vector<vector<u8>>,     // G2Element[] (BCS-encoded)
        pk: vector<u8>,                       // Master PK (G2Element, BCS)
        messages_hash: vector<u8>,            // Blake2b256 consistency hash
        approvals: VecSet<address>,           // Members who verified and approved
    },

    /// Final state: KeyServer created and attached
    Finalized,
}
```

**State Invariants:**
- `Init`: `members_info.length() ≤ members.length()`
- `PostDKG`: `members_info.length() == members.length()` (all registered)
- `PostDKG`: `partial_pks.length() == members.length()` (one per member)
- `PostDKG`: `approvals.length() ≤ members.length()`
- `Finalized`: KeyServer object exists at `dof[committee_id]`

#### MemberInfo (lines 55-64)

Registered information for each committee member:

```move
public struct MemberInfo has copy, drop, store {
    enc_pk: vector<u8>,        // ECIES encryption PK (G1Element, BCS)
    signing_pk: vector<u8>,    // BLS signing PK (BCS)
    url: String,               // Partial key server URL
    name: String,              // Server name (must be unique)
}
```

**Used for:**
- Off-chain: Encrypt DKG shares during protocol
- Off-chain: Authenticate DKG messages via BLS signatures
- On-chain: Build PartialKeyServer objects with URL/name
- Post-DKG: Clients query partial key servers for decryption

### Dynamic Object Fields

The Committee object uses dynamic object fields to attach related objects:

#### KeyServer (accessed via `committee_id` key)

```move
// From seal package, stored as DOF on Committee
public struct KeyServer has key, store {
    id: UID,
    pk: vector<u8>,  // Master public key (G2Element)
    threshold: u16,
    server_type: ServerType::Committee { version: u64, ... },
    // partial_key_servers stored as inner DOFs
}
```

**Lifecycle:**
- **Fresh DKG**: Created when committee transitions to Finalized (line 469)
- **Rotation**: Transferred from old committee to new committee (line 514)

#### UpgradeManager (lines 126-131)

```move
public struct UpgradeManager has key, store {
    id: UID,
    cap: UpgradeCap,                         // Package upgrade capability
    upgrade_proposal: Option<UpgradeProposal>,
}
```

**Lifecycle:**
- **Fresh DKG**: Created during `init_committee` (line 168)
- **Rotation**: Transferred from old to new committee (line 517)

## State Machine

### State Transition Diagram

```
                    init_committee() / init_rotation()
                              │
                              ▼
                    ┌─────────────────┐
                    │      INIT       │
                    │                 │
                    │  All members    │
                    │  register()     │
                    │  their PKs      │
                    └────────┬────────┘
                             │
                             │ All n members registered
                             │
                             ▼
                    ┌─────────────────┐
             ┌─────►│    PostDKG      │◄─────┐
             │      │                 │      │
             │      │  First member   │      │ Subsequent members
             │      │  propose()      │      │ verify exact match
             │      │                 │      │ and approve
             │      └────────┬────────┘      │
             │               │               │
             │               └───────────────┘
             │
             │               All n members approved?
             │                     │
             │                     ▼
             │      ┌─────────────────────┐
             │      │     FINALIZED       │
             │      │                     │
             │      │  • KeyServer created│
             │      │  • Ready to serve   │
             │      └─────────────────────┘
             │
             │ For rotation only:
             │
             └──────────────────────┘
                Old committee destroyed,
                KeyServer + UpgradeManager transferred
```

### State Transition Functions

#### 1. INIT → PostDKG (First Proposal)

**Triggered by**: `propose()` or `propose_for_rotation()` - first member

**Implementation** (lines 415-428):
```move
State::Init { members_info } => {
    // Verify all members registered
    assert!(members_info.length() == committee.members.length(), ENotRegistered);

    // Transition to PostDKG with proposal
    committee.state = State::PostDKG {
        members_info: *members_info,
        approvals: vec_set::singleton(ctx.sender()),
        partial_pks,
        pk,
        messages_hash,
    };
}
```

**Preconditions:**
- All `n` members have called `register()`
- Caller is a committee member
- `partial_pks.length() == members.length()`
- All `partial_pks` and `pk` are valid G2Element (checked on line 407-410)

#### 2. PostDKG → PostDKG (Subsequent Approvals)

**Triggered by**: `propose()` or `propose_for_rotation()` - other members

**Implementation** (lines 430-447):
```move
State::PostDKG {
    approvals,
    members_info: _,
    partial_pks: existing_partial_pks,
    pk: existing_pk,
    messages_hash: existing_messages_hash,
} => {
    // Exact match verification
    assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
    assert!(pk == *existing_pk, EInvalidProposal);
    assert!(messages_hash == *existing_messages_hash, EInvalidProposal);

    // No double approval
    assert!(!approvals.contains(&ctx.sender()), EAlreadyProposed);
    approvals.insert(ctx.sender());
}
```

**Critical Property**: **Unanimous consensus** - all members must propose identical values

**Why unanimous (n-of-n) instead of threshold (t-of-n)?**
- **Security**: Prevents minority from finalizing incorrect keys
- **Accountability**: Every member verifies DKG correctness before commitment
- **Simplicity**: No need for complaint resolution mechanism on-chain

#### 3. PostDKG → FINALIZED (Fresh DKG)

**Triggered by**: Any `propose()` when `approvals.length() == members.length()`

**Implementation** (lines 452-482):
```move
fun try_finalize(committee: &mut Committee, ctx: &mut TxContext) {
    match (&committee.state) {
        State::PostDKG { approvals, members_info, partial_pks, pk, .. } => {
            // Check unanimous approval
            if (approvals.length() != committee.members.length()) {
                return  // Not ready yet
            };

            // Build partial key servers
            let partial_key_servers = committee.build_partial_key_servers(
                members_info,
                partial_pks,
            );

            // Create KeyServer object
            let ks = create_committee_v2(
                committee.id.to_address().to_string(),
                committee.threshold,
                *pk,
                partial_key_servers,
                ctx,
            );

            // Attach as dynamic object field
            let committee_id = object::id(committee);
            dof::add<ID, KeyServer>(&mut committee.id, committee_id, ks);

            committee.state = State::Finalized;
        },
        _ => abort EInvalidState,
    }
}
```

**Effects:**
- KeyServer object created with master PK and partial key server info
- Committee state set to Finalized
- Committee cannot transition to any other state (terminal)

#### 4. PostDKG → FINALIZED (Rotation)

**Triggered by**: Any `propose_for_rotation()` when all approved

**Implementation** (lines 487-530):
```move
fun try_finalize_for_rotation(
    committee: &mut Committee,
    mut old_committee: Committee,  // Takes ownership
    mut key_server: KeyServer,     // Borrowed from old committee
) {
    match (&committee.state) {
        State::PostDKG { approvals, members_info, partial_pks, .. } => {
            let old_committee_id = object::id(&old_committee);

            // Not ready - return objects to old committee
            if (approvals.length() != committee.members.length()) {
                dof::add(&mut old_committee.id, old_committee_id, key_server);
                transfer::share_object(old_committee);
                return
            };

            // Build new partial key servers
            let partial_key_servers = committee.build_partial_key_servers(
                members_info,
                partial_pks,
            );

            // Update KeyServer with new threshold and partial servers
            key_server.update_partial_key_servers(
                committee.threshold,
                partial_key_servers,
            );

            // Transfer KeyServer to new committee
            let committee_id = object::id(committee);
            dof::add(&mut committee.id, committee_id, key_server);

            // Transfer UpgradeManager
            let upgrade_manager: UpgradeManager = dof::remove(
                &mut old_committee.id,
                UpgradeManagerKey(),
            );
            dof::add(&mut committee.id, UpgradeManagerKey(), upgrade_manager);

            committee.state = State::Finalized;

            // Destroy old committee
            let Committee { id, .. } = old_committee;
            id.delete();
        },
        _ => abort EInvalidState,
    }
}
```

**Critical Operations:**
1. **KeyServer update**: New partial servers, same master PK
2. **Object transfer**: KeyServer and UpgradeManager moved atomically
3. **Old committee deletion**: Ensures single source of truth

## Fresh DKG Flow

### Phase A: Initialization and Registration

**On-chain Initialization**

Coordinator calls `init_committee()` (lines 148-176):

```move
public fun init_committee(
    init_cap: InitCap,        // One-time capability from init()
    cap: UpgradeCap,          // Package upgrade capability
    threshold: u16,
    members: vector<address>,
    ctx: &mut TxContext,
) {
    // Verify UpgradeCap belongs to this package (line 158-159)
    assert!(cap.package().to_address() == *publisher.package(), EWrongUpgradeCap);

    // Create committee object (line 165)
    let mut committee = init_internal(threshold, members, option::none(), ctx);

    // Attach UpgradeManager (lines 167-173)
    let upgrade_manager = UpgradeManager {
        id: object::new(ctx),
        cap,
        upgrade_proposal: option::none(),
    };
    dof::add(&mut committee.id, UpgradeManagerKey(), upgrade_manager);

    // Make committee shared (line 175)
    transfer::share_object(committee);
}
```

**Validation** in `init_internal()` (lines 376-396):
```move
assert!(threshold > 1, EInvalidThreshold);
assert!(members.length() as u16 >= threshold, EInvalidThreshold);
assert!(members.length() as u16 < std::u16::max_value!(), EInvalidMembers);

// Throws EKeyAlreadyExists if duplicates found
let _ = vec_set::from_keys(members);
```

**Result**: Committee object created in `Init` state with empty `members_info`

---

**Member Registration**

Each member calls `register()` (lines 201-229):

```move
public fun register(
    committee: &mut Committee,
    enc_pk: vector<u8>,      // G1Element for ECIES encryption
    signing_pk: vector<u8>,  // G2Element for BLS signatures
    url: String,
    name: String,
    ctx: &mut TxContext,
) {
    // Validate keys are valid curve points (lines 210-211)
    let _ = g1_from_bytes(&enc_pk);
    let _ = g2_from_bytes(&signing_pk);

    assert!(committee.members.contains(&ctx.sender()), ENotMember);

    match (&mut committee.state) {
        State::Init { members_info } => {
            let sender = ctx.sender();
            assert!(!members_info.contains(&sender), EAlreadyRegistered);

            // Enforce unique names (lines 220-223)
            members_info.keys().do!(|member_addr| {
                let existing_info = members_info.get(&member_addr);
                assert!(existing_info.name != name, ENameAlreadyTaken);
            });

            members_info.insert(sender, MemberInfo {
                enc_pk, signing_pk, url, name
            });
        },
        _ => abort EInvalidState,
    }
}
```

**Result**: When all `n` members register, `members_info.length() == members.length()`

### Phase B: Off-chain DKG Message Exchange

**Off-chain only** - members:
1. Fetch `members_info` from on-chain committee state
2. Run DKG protocol locally using each other's `enc_pk` for encryption
3. Generate VSS commitments and NIZK proofs
4. Sign messages with their `signing_sk`
5. Exchange signed messages via coordinator

**Not visible on-chain** - this phase is purely cryptographic computation

### Phase C: Proposal and Finalization

**First Member Proposes**

Calls `propose()` (lines 236-247):

```move
public fun propose(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,  // One G2Element per member
    pk: vector<u8>,                    // Master public key (G2Element)
    messages_hash: vector<u8>,         // Blake2b256 hash for consistency
    ctx: &mut TxContext,
) {
    // Only for fresh DKG (line 244)
    assert!(committee.old_committee_id.is_none(), EInvalidState);

    committee.propose_internal(partial_pks, pk, messages_hash, ctx);
    committee.try_finalize(ctx);  // Attempt finalization
}
```

`propose_internal()` validates and transitions state (lines 399-448):

```move
fun propose_internal(...) {
    // Validate all PKs are valid G2 elements (lines 407-410)
    let _ = g2_from_bytes(&pk);
    partial_pks.do_ref!(|partial_pk| {
        let _ = g2_from_bytes(partial_pk);
    });

    assert!(committee.members.contains(&ctx.sender()), ENotMember);
    assert!(partial_pks.length() == committee.members.length(), EInvalidProposal);

    match (&mut committee.state) {
        State::Init { members_info } => {
            // All members must be registered (line 418)
            assert!(members_info.length() == committee.members.length(), ENotRegistered);

            // INIT → PostDKG transition (lines 421-428)
            committee.state = State::PostDKG {
                members_info: *members_info,
                approvals: vec_set::singleton(ctx.sender()),
                partial_pks,
                pk,
                messages_hash,
            };
        },
        // ... PostDKG case handled below
    }
}
```

**Subsequent Members Approve**

Each remaining member calls `propose()` with **identical values**:

```move
State::PostDKG {
    approvals,
    partial_pks: existing_partial_pks,
    pk: existing_pk,
    messages_hash: existing_messages_hash,
    ...
} => {
    // Exact match required (lines 438-440)
    assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
    assert!(pk == *existing_pk, EInvalidProposal);
    assert!(messages_hash == *existing_messages_hash, EInvalidProposal);

    // Add to approvals (lines 443-444)
    assert!(!approvals.contains(&ctx.sender()), EAlreadyProposed);
    approvals.insert(ctx.sender());
}
```

**Automatic Finalization**

When the last member proposes, `try_finalize()` triggers (lines 452-482):

```move
if (approvals.length() != committee.members.length()) {
    return  // Not all members approved yet
};

// Build partial key servers from members_info and partial_pks (lines 464-467)
let partial_key_servers = committee.build_partial_key_servers(
    members_info,
    partial_pks,
);

// Create KeyServer (lines 469-475)
let ks = create_committee_v2(
    committee.id.to_address().to_string(),
    committee.threshold,
    *pk,
    partial_key_servers,
    ctx,
);

// Attach to committee (lines 476-477)
let committee_id = object::id(committee);
dof::add<ID, KeyServer>(&mut committee.id, committee_id, ks);

committee.state = State::Finalized;
```

**Result**: KeyServer object created, committee finalized

### Helper: Building Partial Key Servers

`build_partial_key_servers()` (lines 534-559):

```move
fun build_partial_key_servers(
    committee: &Committee,
    members_info: &VecMap<address, MemberInfo>,
    partial_pks: &vector<vector<u8>>,
): VecMap<address, PartialKeyServer> {
    let members = committee.members;

    // Validation
    assert!(members.length() == partial_pks.length(), EInvalidMembers);
    assert!(members.length() == members_info.length(), EInvalidMembers);

    let mut partial_key_servers = vec_map::empty();
    let mut i = 0;

    members.do!(|member| {
        partial_key_servers.insert(
            member,
            create_partial_key_server(
                members_info.get(&member).name,
                members_info.get(&member).url,
                partial_pks[i],     // Partial PK for this member
                i as u16,           // party_id = index
            ),
        );
        i = i + 1;
    });

    partial_key_servers
}
```

**Key Insight**: The `party_id` is deterministic based on position in `members` vector

## Key Rotation Flow

### Rotation Constraints

Before rotation can begin, the new committee must satisfy:

```move
// From init_rotation (lines 179-198)
public fun init_rotation(
    old_committee: &Committee,
    threshold: u16,
    members: vector<address>,
    ctx: &mut TxContext,
) {
    // Old committee must be finalized (line 188)
    assert!(old_committee.is_finalized(), EInvalidState);

    // Count continuing members (lines 190-193)
    let mut continuing_members = 0;
    members.do!(|member| if (old_committee.members.contains(&member)) {
        continuing_members = continuing_members + 1;
    });

    // Must have at least old threshold continuing members (line 194)
    assert!(continuing_members >= old_committee.threshold, EInsufficientOldMembers);

    // Create new committee linked to old (line 196)
    let committee = init_internal(
        threshold,
        members,
        option::some(object::id(old_committee)),  // Link to old committee
        ctx
    );
    transfer::share_object(committee);
}
```

**Why this constraint?**
- Ensures continuity: `t` members from old committee can reconstruct master key
- Prevents malicious minority from losing access to encrypted data
- Allows master PK to remain unchanged

### Phase A & B: Same as Fresh DKG

Members register their new keys and exchange DKG messages off-chain. The difference:
- Only **continuing members** (those in both committees) create messages
- They include their old shares in the DKG computation
- New members initialize state but don't create messages

### Phase C: Rotation Proposal

Members call `propose_for_rotation()` (lines 253-265):

```move
public fun propose_for_rotation(
    committee: &mut Committee,
    partial_pks: vector<vector<u8>>,
    messages_hash: vector<u8>,
    mut old_committee: Committee,    // Takes ownership!
    ctx: &mut TxContext,
) {
    // Verify rotation consistency (line 260)
    committee.check_rotation_consistency(&old_committee);

    // Extract KeyServer from old committee (lines 261-262)
    let old_committee_id = object::id(&old_committee);
    let key_server: KeyServer = dof::remove(&mut old_committee.id, old_committee_id);

    // Propose using old key server's PK (line 263)
    committee.propose_internal(partial_pks, *key_server.pk(), messages_hash, ctx);

    // Attempt finalization (line 264)
    committee.try_finalize_for_rotation(old_committee, key_server);
}
```

**Critical**: Master PK (`key_server.pk()`) is **reused**, not recomputed

**Rotation Consistency Check** (lines 562-566):
```move
fun check_rotation_consistency(self: &Committee, old_committee: &Committee) {
    assert!(self.old_committee_id.is_some(), EInvalidState);
    assert!(object::id(old_committee) == *self.old_committee_id.borrow(), EInvalidState);
    assert!(old_committee.is_finalized(), EInvalidState);
}
```

### Rotation Finalization

`try_finalize_for_rotation()` (lines 487-530):

**Not Ready Case** (lines 498-503):
```move
if (approvals.length() != committee.members.length()) {
    // Return KeyServer to old committee
    dof::add<ID, KeyServer>(&mut old_committee.id, old_committee_id, key_server);
    transfer::share_object(old_committee);
    return  // Old committee remains finalized and operational
}
```

**Finalization Case** (lines 505-530):
```move
// Build new partial key servers (lines 506-510)
let partial_key_servers = committee.build_partial_key_servers(
    members_info,
    partial_pks,
);

// Update KeyServer with new threshold and partial servers (line 511)
key_server.update_partial_key_servers(committee.threshold, partial_key_servers);

// Transfer KeyServer to new committee (lines 513-514)
let committee_id = object::id(committee);
dof::add<ID, KeyServer>(&mut committee.id, committee_id, key_server);

// Transfer UpgradeManager (lines 517-521)
let upgrade_manager: UpgradeManager = dof::remove(
    &mut old_committee.id,
    UpgradeManagerKey(),
);
dof::add(&mut committee.id, UpgradeManagerKey(), upgrade_manager);

committee.state = State::Finalized;

// Destroy old committee object (lines 525-527)
let Committee { id, .. } = old_committee;
id.delete();
```

**Atomicity Guarantee**:
- Transaction either succeeds (new finalized, old destroyed) or fails (old remains unchanged)
- No intermediate state where both committees coexist finalized
- KeyServer and UpgradeManager transferred atomically

## Upgrade Management

### Data Structures

**UpgradeProposal** (lines 115-122):
```move
public struct UpgradeProposal has drop, store {
    digest: PackageDigest,           // SHA256 digest of package
    version: u64,                    // Target version (cap.version + 1)
    votes: VecMap<address, Vote>,    // Member votes
}

public enum Vote has drop, store {
    Approve,
    Reject,
}
```

**PackageDigest** (lines 105-609):
```move
public struct PackageDigest(vector<u8>) has drop, store;

macro fun package_digest($digest: vector<u8>): PackageDigest {
    let digest = $digest;
    assert!(digest.length() == 32, EInvalidPackageDigest);
    PackageDigest(digest)
}
```

### Upgrade Flow

**1. Vote on Upgrade**

Members vote by calling `approve_digest_for_upgrade()` or `reject_digest_for_upgrade()` (lines 279-295):

```move
public fun approve_digest_for_upgrade(
    committee: &mut Committee,
    digest: vector<u8>,
    ctx: &TxContext,
) {
    vote_for_upgrade(committee, digest, Vote::Approve, ctx);
}
```

`vote_for_upgrade()` implementation (lines 570-602):

```move
fun vote_for_upgrade(
    committee: &mut Committee,
    digest: vector<u8>,
    vote: Vote,
    ctx: &TxContext
) {
    assert!(committee.members.contains(&ctx.sender()), ENotAuthorized);
    assert!(committee.is_finalized(), EInvalidState);

    let upgrade_manager = committee.borrow_upgrade_manager_mut();
    let cap_version = upgrade_manager.cap.version();

    // Create proposal if doesn't exist (lines 579-587)
    if (upgrade_manager.upgrade_proposal.is_none()) {
        let parsed_digest = package_digest!(digest);
        upgrade_manager.upgrade_proposal = option::some(UpgradeProposal {
            digest: parsed_digest,
            version: cap_version + 1,
            votes: vec_map::empty(),
        });
    };

    let proposal = upgrade_manager.upgrade_proposal.borrow_mut();

    // Validate digest and version match (lines 592-594)
    let parsed_digest = package_digest!(digest);
    assert!(proposal.digest.0 == parsed_digest.0, ENoProposalForDigest);
    assert!(proposal.version == cap_version + 1, EWrongVersion);

    // Update vote (members can change vote) (lines 597-601)
    if (proposal.votes.contains(&ctx.sender())) {
        proposal.votes.remove(&ctx.sender());
    };
    proposal.votes.insert(ctx.sender(), vote);
}
```

**Key Properties**:
- Only one active proposal at a time
- Members can change their vote
- Digest and version must match across all votes

**2. Authorize Upgrade**

When `t` members approve, any member can call `authorize_upgrade()` (lines 299-326):

```move
public fun authorize_upgrade(committee: &mut Committee, ctx: &TxContext): UpgradeTicket {
    assert!(committee.members.contains(&ctx.sender()), ENotAuthorized);
    assert!(committee.is_finalized(), EInvalidState);

    let threshold = committee.threshold;
    let upgrade_manager = committee.borrow_upgrade_manager_mut();

    assert!(upgrade_manager.upgrade_proposal.is_some(), ENoProposalForDigest);

    // Extract proposal (clears it) (line 309)
    let proposal = upgrade_manager.upgrade_proposal.extract();

    // Validate version (line 312)
    assert!(proposal.version == upgrade_manager.cap.version() + 1, EWrongVersion);

    // Count approvals (lines 315-321)
    let mut approval_count = 0u16;
    proposal.votes.keys().do!(|member| {
        match (proposal.votes.get(&member)) {
            Vote::Approve => approval_count = approval_count + 1,
            Vote::Reject => {},
        };
    });
    assert!(approval_count >= threshold, ENotEnoughVotes);

    // Return upgrade ticket (lines 324-325)
    let policy = upgrade_manager.cap.policy();
    upgrade_manager.cap.authorize(policy, proposal.digest.0)
}
```

**3. Commit Upgrade**

After package upgrade succeeds, member calls `commit_upgrade()` (lines 330-336):

```move
public fun commit_upgrade(
    committee: &mut Committee,
    receipt: UpgradeReceipt,
    ctx: &TxContext
) {
    assert!(committee.members.contains(&ctx.sender()), ENotAuthorized);
    assert!(committee.is_finalized(), EInvalidState);

    let upgrade_manager = committee.borrow_upgrade_manager_mut();
    upgrade_manager.cap.commit(receipt)
}
```

**4. Reset Proposal**

If `t` members reject, any member can reset (lines 340-363):

```move
public fun reset_proposal(committee: &mut Committee, ctx: &TxContext) {
    assert!(committee.members.contains(&ctx.sender()), ENotAuthorized);
    assert!(committee.is_finalized(), EInvalidState);

    let threshold = committee.threshold;
    let upgrade_manager = committee.borrow_upgrade_manager_mut();
    assert!(upgrade_manager.upgrade_proposal.is_some(), ENoProposalForDigest);

    let proposal = upgrade_manager.upgrade_proposal.borrow();

    // Count rejections (lines 351-358)
    let mut rejection_count = 0u16;
    proposal.votes.keys().do!(|member| {
        match (proposal.votes.get(&member)) {
            Vote::Reject => rejection_count = rejection_count + 1,
            Vote::Approve => {},
        };
    });
    assert!(rejection_count >= threshold, ENotEnoughVotes);

    // Clear proposal (line 362)
    upgrade_manager.upgrade_proposal.extract();
}
```

### Upgrade Continuity During Rotation

The `UpgradeManager` is transferred atomically during rotation (lines 517-521):

```move
// Transfer upgrade manager from old to new committee
let upgrade_manager: UpgradeManager = dof::remove(
    &mut old_committee.id,
    UpgradeManagerKey(),
);
dof::add(&mut committee.id, UpgradeManagerKey(), upgrade_manager);
```

**Implications**:
- Active proposals survive rotation
- New committee inherits upgrade governance
- Package version increments continuously

## Security Properties

### 1. Unanimous Approval Requirement

**Property**: All `n` members must verify and approve DKG results before finalization

**Enforcement** (line 459):
```move
if (approvals.length() != committee.members.length()) {
    return  // Cannot finalize
}
```

**Rationale**:
- Prevents malicious minority from finalizing incorrect keys
- Every member verifies off-chain computation before on-chain commitment
- Ensures all members have valid shares before serving requests

### 2. Exact Match Verification

**Property**: All members must propose identical `partial_pks`, `pk`, and `messages_hash`

**Enforcement** (lines 438-440):
```move
assert!(partial_pks == *existing_partial_pks, EInvalidProposal);
assert!(pk == *existing_pk, EInvalidProposal);
assert!(messages_hash == *existing_messages_hash, EInvalidProposal);
```

**Rationale**:
- `partial_pks`: Each member has correct public key share
- `pk`: Master public key is agreed upon
- `messages_hash`: All members processed same messages (consistency)

### 3. Cryptographic Validation

**Property**: All public keys are valid BLS12-381 curve points

**Enforcement**:
- Registration (lines 210-211):
  ```move
  let _ = g1_from_bytes(&enc_pk);
  let _ = g2_from_bytes(&signing_pk);
  ```
- Proposal (lines 407-410):
  ```move
  let _ = g2_from_bytes(&pk);
  partial_pks.do_ref!(|partial_pk| {
      let _ = g2_from_bytes(partial_pk);
  });
  ```

**Rationale**: Prevents invalid curve points from being stored

### 4. Rotation Continuity

**Property**: New committee must have ≥ `old_threshold` continuing members

**Enforcement** (lines 190-194):
```move
let mut continuing_members = 0;
members.do!(|member| if (old_committee.members.contains(&member)) {
    continuing_members = continuing_members + 1;
});
assert!(continuing_members >= old_committee.threshold, EInsufficientOldMembers);
```

**Rationale**: Ensures `t` members can reconstruct old key to prove continuity

### 5. Master PK Preservation

**Property**: During rotation, master public key must remain unchanged

**Enforcement** (line 263):
```move
// Reuse old key server's PK, not a new one
committee.propose_internal(partial_pks, *key_server.pk(), messages_hash, ctx);
```

**Off-chain verification**: CLI verifies computed PK matches on-chain old PK (main.rs:836-845)

**Rationale**: Encrypted data remains decryptable after rotation

### 6. Atomic State Transitions

**Property**: Committee state changes are atomic and irreversible

**Enforcement**:
- Fresh DKG: Single transaction creates KeyServer and sets Finalized
- Rotation: Single transaction transfers objects and destroys old committee
- No partial state: Transaction succeeds completely or reverts

**Rationale**: Prevents inconsistent state across committee objects

### 7. Threshold Governance for Upgrades

**Property**: Package upgrades require `t-of-n` approvals

**Enforcement** (line 322):
```move
assert!(approval_count >= threshold, ENotEnoughVotes);
```

**Rationale**: Prevents single member from malicious upgrades

### 8. No Double Approval

**Property**: Each member can approve proposal at most once

**Enforcement** (line 443):
```move
assert!(!approvals.contains(&ctx.sender()), EAlreadyProposed);
```

**Rationale**: Prevents vote amplification attacks

### 9. Unique Server Names

**Property**: No two members can register the same server name

**Enforcement** (lines 220-223):
```move
members_info.keys().do!(|member_addr| {
    let existing_info = members_info.get(&member_addr);
    assert!(existing_info.name != name, ENameAlreadyTaken);
});
```

**Rationale**: Prevents confusion in client-side partial key server discovery

### 10. Access Control

**Property**: Only committee members can call sensitive functions

**Enforcement**: All state-modifying functions check membership:
```move
assert!(committee.members.contains(&ctx.sender()), ENotMember);
// or for upgrades:
assert!(committee.members.contains(&ctx.sender()), ENotAuthorized);
```

**Rationale**: Prevents external parties from interfering with protocol

---

## Comparison: Fresh DKG vs Rotation

| Aspect | Fresh DKG | Key Rotation |
|--------|-----------|--------------|
| **Initialization** | `init_committee()` with InitCap | `init_rotation()` with old committee reference |
| **Old committee link** | `old_committee_id = None` | `old_committee_id = Some(old_id)` |
| **Proposal function** | `propose()` | `propose_for_rotation()` |
| **Master PK** | Computed from DKG | Reused from old KeyServer (`*key_server.pk()`) |
| **Old committee argument** | Not required | Must pass `old_committee: Committee` |
| **Finalization** | `try_finalize()` - creates KeyServer | `try_finalize_for_rotation()` - updates KeyServer |
| **Old committee fate** | N/A | Destroyed (`id.delete()`) |
| **KeyServer lifecycle** | Created | Transferred and updated |
| **UpgradeManager** | Created | Transferred |
| **Continuing members constraint** | N/A | Must have ≥ `old_threshold` |

---

## Summary

The SEAL committee smart contract implements a sophisticated DKG protocol with the following key design decisions:

1. **Three-phase protocol**: Init (registration) → PostDKG (verification) → Finalized (serving)

2. **Unanimous approval**: All `n` members must verify DKG correctness before finalization, preventing malicious minorities

3. **Exact match consensus**: Members must propose identical values, enforcing cryptographic verification off-chain

4. **Atomic rotation**: Old committee destroyed only after new committee fully operational, preventing service interruption

5. **Master PK preservation**: Rotation updates shares but preserves master public key, maintaining backward compatibility

6. **Dynamic object fields**: KeyServer and UpgradeManager attached to committee, enabling clean ownership transfer

7. **Threshold governance**: Package upgrades require `t-of-n` member approval

8. **Immutable membership**: Committee members/threshold cannot change; must rotate to new committee

This design provides a trustless, decentralized threshold cryptography system with strong security guarantees and smooth operational transitions.
