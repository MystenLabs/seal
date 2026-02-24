# SEAL Committee DKG Protocol - Move Contract Design

## Overview

The `seal_committee` Move module manages a distributed key generation (DKG) protocol on-chain. The contract enforces a state machine that coordinates multiple parties to collectively create threshold cryptographic keys, with support for key rotation.

**Key Responsibilities:**
- Enforce state transitions through a three-phase protocol
- Validate cryptographic commitments from all parties
- Require unanimous approval before finalization
- Support atomic committee rotation with continuity guarantees
- Manage package upgrade governance through threshold voting

**Trust Model:**
- Off-chain coordination handles cryptographic computation
- Move contract validates all outputs and enforces consensus
- No trusted coordinator - all security properties enforced on-chain

---

## Contract Architecture

### Core Objects

**Committee** (shared object)
- Tracks committee state through DKG protocol
- Contains ordered list of member addresses
- Holds threshold parameter (t-of-n)
- Links to old committee during rotation
- Owns KeyServer and UpgradeManager as dynamic object fields

**KeyServer** (dynamic object field)
- Stores master public key for threshold encryption
- Contains threshold parameter
- Maps each member address to their partial key server information
- Versioned to support rotation tracking

**UpgradeManager** (dynamic object field)
- Holds package UpgradeCap
- Manages single active upgrade proposal at a time
- Tracks member votes (approve/reject)

---

## State Machine

### States

**Init**
- Initial state after committee creation
- Members register their public keys
- Stores `members_info` mapping (address → MemberInfo)
- Transitions to PostDKG when first member proposes

**PostDKG**
- First member has proposed DKG results
- Stores proposed values: partial_pks, master pk, messages_hash
- Tracks set of members who have approved
- Validates subsequent proposals match exactly
- Transitions to Finalized when all members approve

**Finalized**
- Terminal state - committee is operational
- KeyServer object created and attached
- Cannot transition to any other state
- Only exit is through rotation (creates new committee)

### State Transitions

```
                 init_committee()
                 init_rotation()
                        │
                        ▼
                  ┌──────────┐
                  │   INIT   │◄─── register() (×n times)
                  └────┬─────┘
                       │
                       │ propose() / propose_for_rotation() (first)
                       │
                       ▼
                  ┌──────────┐
                  │ PostDKG  │◄─── propose() (×n-1 times)
                  └────┬─────┘       (must match exactly)
                       │
                       │ (automatic when all approved)
                       │
                       ▼
                  ┌──────────┐
                  │Finalized │
                  └──────────┘
```

---

## Protocol Flows

### Fresh DKG

**Purpose**: Initialize a new committee from scratch

**Step 1: Initialize Committee**
- Function: `init_committee()`
- Consumes one-time InitCap from package deployment
- Creates Committee in Init state with empty members_info
- Attaches UpgradeManager with provided UpgradeCap
- Committee becomes shared object

**Validations:**
- Threshold must be > 1
- Member count must be ≥ threshold
- Member count must be < u16::MAX
- No duplicate member addresses

**Step 2: Member Registration**
- Function: `register()`
- Each member registers their public keys and server info
- Validates caller is in members list
- Validates public keys are valid curve points
- Enforces unique server names
- Prevents double registration

**MemberInfo Contents:**
- ECIES encryption public key (G1Element)
- BLS signing public key (G2Element)
- Server URL
- Server name (unique identifier)

**Step 3: First Proposal**
- Function: `propose()`
- First member submits DKG results
- Requires all members have registered
- Transitions Init → PostDKG
- Proposer automatically added to approvals set

**Proposal Contents:**
- `partial_pks`: Vector of partial public keys (one per member)
- `pk`: Master public key
- `messages_hash`: Consistency hash over DKG messages

**Validations:**
- Caller is committee member
- All members registered (members_info full)
- partial_pks length equals members length
- All public keys are valid G2 curve points
- For fresh DKG: old_committee_id must be None

**Step 4: Subsequent Approvals**
- Function: `propose()` (×n-1 times)
- Each remaining member submits identical proposal
- Contract enforces exact match of all fields
- Member added to approvals set
- Prevents double approval by same member

**Critical Property**: Unanimous consensus required - all values must match exactly

**Step 5: Automatic Finalization**
- Triggered when approvals set equals full member count
- Builds partial key server objects from members_info and partial_pks
- Creates KeyServer with master PK and partial key servers
- Attaches KeyServer as dynamic object field (keyed by committee_id)
- Sets state to Finalized

**Result**: Operational committee ready to serve encryption/decryption requests

---

### Key Rotation

**Purpose**: Update committee membership while preserving master public key

**Rotation Constraint**: New committee must contain at least `old_threshold` members from old committee

**Step 1: Initialize Rotation**
- Function: `init_rotation()`
- Takes reference to old committee
- Validates old committee is Finalized
- Counts continuing members (present in both committees)
- Enforces continuing_members ≥ old_threshold
- Creates new Committee with old_committee_id set
- New committee starts in Init state

**Rationale**: Ensures enough members can prove knowledge of old key

**Step 2: Member Registration**
- Same as Fresh DKG Step 2
- Both continuing and new members register
- All members generate fresh keys for new committee

**Step 3: First Rotation Proposal**
- Function: `propose_for_rotation()`
- Takes ownership of old committee object
- Extracts KeyServer from old committee
- Reuses master PK from old KeyServer
- Transitions Init → PostDKG (with old PK)
- Attempts finalization

**Critical Difference**: Master PK is **not recomputed** - it's extracted from old KeyServer

**Validations:**
- Same as regular propose, plus:
- new_committee.old_committee_id matches provided old committee
- old_committee.state is Finalized

**Step 4: Subsequent Rotation Approvals**
- Function: `propose_for_rotation()` (×n-1 times)
- Each member submits identical proposal
- Master PK must match old committee's PK
- Members added to approvals set

**Step 5: Automatic Rotation Finalization**

**If Not All Approved:**
- KeyServer returned to old committee
- Old committee re-shared (remains operational)
- New committee stays in PostDKG state
- Process can continue when more members approve

**If All Approved:**
- Builds new partial key server objects
- Updates KeyServer with new threshold and partial servers
- KeyServer master PK remains unchanged
- Transfers KeyServer to new committee
- Transfers UpgradeManager to new committee
- Sets new committee state to Finalized
- Destroys old committee object

**Result**: New committee operational, old committee destroyed, master PK preserved

---

## Security Properties

### 1. Unanimous Approval Requirement

**Property**: All n members must approve before finalization

**Enforcement**: Finalization only triggers when `approvals.length() == members.length()`

**Rationale**:
- Prevents malicious minority from finalizing incorrect keys
- Every member independently verifies off-chain computation
- Ensures all members have valid shares before serving

### 2. Exact Match Consensus

**Property**: All proposals must have identical partial_pks, pk, and messages_hash

**Enforcement**: Each subsequent proposal compared byte-for-byte with first proposal

**Rationale**:
- Binds on-chain state to specific off-chain DKG execution
- Ensures all members processed same inputs
- Prevents inconsistent key derivation

### 3. Cryptographic Validation

**Property**: All public keys must be valid BLS12-381 curve points

**Enforcement**:
- Registration validates G1 and G2 points
- Proposals validate all partial_pks and master pk

**Rationale**: Prevents invalid cryptographic material from being stored

### 4. No Double Operations

**Property**: Each member can only register/approve once

**Enforcement**:
- Registration checks member not in members_info
- Approval checks member not in approvals set

**Rationale**: Prevents vote amplification or duplicate registration

### 5. Member Authorization

**Property**: Only committee members can modify state

**Enforcement**: All state-modifying functions check `members.contains(&ctx.sender())`

**Rationale**: Prevents external interference with protocol

### 6. Rotation Continuity

**Property**: New committee must have ≥ old_threshold continuing members

**Enforcement**: `init_rotation()` counts and validates continuing members

**Rationale**: Ensures sufficient knowledge of old key to prove continuity

### 7. Master PK Preservation

**Property**: Rotation must preserve master public key

**Enforcement**: `propose_for_rotation()` extracts and reuses old KeyServer's pk

**Rationale**: Ensures encrypted data remains decryptable after rotation

### 8. Atomic State Transitions

**Property**: State changes are atomic and irreversible

**Fresh DKG**: Single transaction creates KeyServer and finalizes

**Rotation**: Single transaction transfers objects and destroys old committee

**Rationale**: Prevents inconsistent state or service interruption

### 9. Single Active Committee

**Property**: Only one finalized committee per key at any time

**Enforcement**: Rotation destroys old committee atomically with new finalization

**Rationale**: Prevents ambiguity about which committee serves requests

### 10. Unique Server Names

**Property**: No two members can have the same server name

**Enforcement**: Registration checks existing members for name collision

**Rationale**: Enables unambiguous client-side server discovery

---

## Upgrade Management

### Upgrade Governance

**Model**: Threshold voting (t-of-n members must approve)

**Single Active Proposal**: Only one upgrade proposal exists at a time

### Upgrade Flow

**1. Proposal Creation**
- Any member submitting vote creates proposal if none exists
- Proposal contains: package digest, target version, votes mapping

**2. Voting**
- Members call `approve_digest_for_upgrade()` or `reject_digest_for_upgrade()`
- Each member has one active vote (can change vote)
- Vote must be for same digest and version as existing proposal
- Only available when committee is Finalized

**3. Authorization**
- When approval_count ≥ threshold, any member can call `authorize_upgrade()`
- Validates sufficient approvals
- Clears proposal from state
- Returns UpgradeTicket from UpgradeCap

**4. Execution and Commit**
- Upgrade performed off-chain using ticket
- Member calls `commit_upgrade()` with UpgradeReceipt
- Updates UpgradeCap version

**5. Proposal Reset**
- If rejection_count ≥ threshold, any member can call `reset_proposal()`
- Clears proposal to allow new proposal

### Upgrade Continuity

**During Rotation**: UpgradeManager transferred atomically with KeyServer

**Implication**: Active proposals survive rotation, new committee inherits governance

---

## State Invariants

### Init State
- `0 ≤ members_info.length() ≤ members.length()`
- All addresses in members_info are in members list
- All server names are unique
- All registered keys are valid curve points

### PostDKG State
- `members_info.length() == members.length()` (all registered)
- `partial_pks.length() == members.length()`
- `1 ≤ approvals.length() ≤ members.length()`
- All addresses in approvals are in members list
- All partial_pks and pk are valid curve points
- For rotation: pk equals old committee's master pk

### Finalized State
- KeyServer exists at dynamic field `committee_id`
- KeyServer contains n partial key server entries
- State cannot transition further (terminal)
- For rotation: old_committee must be destroyed

---

## Critical Edge Cases

### Rotation Finalization Interrupted

**Scenario**: Not all members approve rotation proposal

**Behavior**:
- KeyServer returned to old committee
- Old committee re-shared and remains operational
- New committee stays in PostDKG state
- Can resume when more members approve

**Safety**: Old committee never destroyed until new committee finalized

### Member Count Changes in Rotation

**Scenario**: New committee has different size or threshold

**Validation**: New committee must have ≥ old_threshold continuing members

**Behavior**:
- KeyServer updated with new threshold
- Partial key servers rebuilt for new member set
- Master PK remains unchanged

### Proposal Mismatch

**Scenario**: Member proposes different values in PostDKG state

**Behavior**: Transaction aborts with EInvalidProposal

**Safety**: Cannot proceed until all members agree on identical values

### Double Approval Attempt

**Scenario**: Member calls propose() twice

**Behavior**: Second call aborts with EAlreadyProposed

**Safety**: Cannot amplify votes or change approval once given

---

## Comparison: Fresh vs Rotation

| Aspect | Fresh DKG | Rotation |
|--------|-----------|----------|
| Init function | `init_committee()` | `init_rotation()` |
| InitCap required | Yes | No |
| old_committee_id | None | Some(old_id) |
| Continuing members constraint | N/A | Must have ≥ old_threshold |
| Proposal function | `propose()` | `propose_for_rotation()` |
| Old committee argument | Not required | Must pass old committee object |
| Master PK source | Computed from DKG | Extracted from old KeyServer |
| Finalization | Creates KeyServer | Updates and transfers KeyServer |
| Old committee fate | N/A | Destroyed atomically |
| UpgradeManager | Created | Transferred |

---

## Audit Focus Areas

### State Transition Logic
- Verify state transitions are one-way and irreversible
- Check finalization only occurs with full approval
- Ensure old committee not destroyed prematurely during rotation

### Validation Coverage
- All public keys validated as curve points
- Member authorization checked on all state mutations
- Proposal values validated for exact match
- Rotation continuity constraint enforced

### Dynamic Object Field Management
- KeyServer correctly attached/transferred
- UpgradeManager correctly attached/transferred
- No orphaned objects after rotation

### Atomicity Guarantees
- Rotation either fully succeeds or fully reverts
- No partial state between old and new committee
- Object transfers are atomic within transaction

### Access Control
- Only members can register/propose/vote
- Only members can trigger upgrade operations
- UpgradeCap cannot be extracted or misused

### Upgrade Governance
- Threshold correctly enforced for authorization
- Vote changes handled correctly
- Single active proposal constraint maintained
- Proposal cleared after authorization
