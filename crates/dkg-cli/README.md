# DKG CLI Tool

** WARNING: This is WIP. Do not use. **

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols. A DKG process involves a coordinator and a set of participating members. Here we describe the processes for both a fresh DKG and a key rotation.

Both fresh DKG and key rotation has 3 phases. 

- **Phase 1 (Registration)**: Members generate and register their encryption keys onchain.- **Phase 2 (Message Creation)**: Members create and share DKG messages offchain.
- **Phase 3 (Finalization)**: Members process messages, propose committee onchain. 

The coordinator signals when to proceed from one phase to the next.

## Prerequisites

1. Install Sui (See [more](https://docs.sui.io/guides/developer/getting-started/sui-install)).
2. Clone the [Seal](https://github.com/MystenLabs/seal) repo locally and set to working directory. 
3. Install python and the dependencies in `/seal`. 

```bash
brew install python # if needed
cd seal/

# for the first time
python -m venv .venv
source .venv/bin/activate
pip install -r crates/dkg-cli/scripts/requirements.txt
```

### Fresh DKG Process

#### Coordinator Runbook

1. Gather all members' addresses and create a `dkg.yaml`.

```yaml
NETWORK: Testnet # expected network
THRESHOLD: 2 # expected threshold
# your address, make sure you have enough gas for subsequent onchain calls for the network
COORDINATOR_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
MEMBERS: # gathered from participating members
  - 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
  - 0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
  - 0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9
```

2. Run the publish-and-init script.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py publish-and-init -c crates/dkg-cli/scripts/dkg.yaml
```

This publishes the `seal_committee` package and initializes the committee onchain. The script also appends the following to `dkg.yaml`. 

```yaml
COMMITTEE_PKG: 0x3358b7f7150efe9a0487ad354e5959771c56556737605848231b09cca5b791c6
COMMITTEE_ID: 0x46540663327da161b688786cbebbafbd32e0f344c85f8dc3bfe874c65a613418
```

3. Share the `dkg.yaml` file with all members. Announce to all members to begin Phase 1.

4. Monitor onchain state until all members are registered using the check-committee script.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py check-committee -c crates/dkg-cli/scripts/dkg.yaml
```

This will show which members have registered and which are still missing.

5. Announce to all members to begin Phase 2 when all members registered. Monitor offchain storage until all members upload their messages.

6. Collect all messages into a directory (e.g., `./dkg-messages`) and share it. Announce to all members to begin Phase 3.

7. Monitor the committee onchain object for finalized state when all members had proposed. Run the check-committee command to get the key server object ID.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py check-committee -c crates/dkg-cli/scripts/dkg.yaml
```

Share `KEY_SERVER_OBJ_ID` from output all members to configure their key servers. 

#### Member Runbook

1. Share with the coordinator your address (`MY_ADDRESS`). This is the wallet used for the rest of the onchain commands. Make sure you are on the right network with wallet with enough gas.

2. Wait till the coordinator annouces Phase 1 and receive the `dkg.yaml` file containing `COMMITTEE_PKG` and `COMMITTEE_ID`. Verify its parameters (members addresses and threshold) on Sui Explorer. Add the following member specific fields to `dkg.yaml`:

```yaml
MY_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
MY_SERVER_URL: https://myserver.example.com
```

And run the following to generate keys locally and register onchain.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py genkey-and-register -c crates/dkg-cli/scripts/dkg.yaml
```

This script:
- Generates DKG keys (creates `./dkg-state/` directory with sensitive private keys - keep it secure!).
- Appends `DKG_ENC_PK` and `DKG_SIGNING_PK` to your yaml.
- Registers your public keys onchain.

3. Wait till the coordinator annouces Phase 2. Run the following to initialize DKG state and create your message. 

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message \
    -c crates/dkg-cli/scripts/dkg.yaml

# This creates a file: message_P.json (where P is your party ID).
```

Share the output `message_P.json` file with the coordinator.

4. Wait for the coordinator to announce Phase 3 and receive the `./dkg-messages` directory containing all messages from the coordinator. Run the following:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py process-all-and-propose \
    -c crates/dkg-cli/scripts/dkg.yaml \
    -m ./dkg-messages
```

This script:
- Processes all messages from `./dkg-messages` directory.
- Appends to `dkg.yaml`: `KEY_SERVER_PK` (new key server public key), `PARTIAL_PKS_V0` (partial public keys for all members), and `MASTER_SHARE_V0` (your secret master share - keep secure!).
- Proposes the committee onchain by calling the `propose` function.

5. Wait for the coordinator to announce that the DKG is completed and receive `KEY_SERVER_OBJ_ID`. Create `key-server-config.yaml` with `MY_ADDRESS` and `KEY_SERVER_OBJ_ID` and set Active mode. Start the server with `MASTER_SHARE_V0` (version 0 for fresh DKG).

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Active
```

Example command to start server:
```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml MASTER_SHARE_V0=0x208cd48a92430eb9f90482291e5552e07aebc335d84b7b6371a58ebedd6ed036 cargo run --bin key-server
```

### Key Rotation Process

A key rotation process is needed when a committee wants to rotate a portion of its members. The continuing members (in both current and next committee) must meet the threshold of the current committee.

Assuming the key server committee mode version onchain is currently X and it is being rotated to X+1.

#### Coordinator Runbook

The process follows the same three phases as fresh DKG, with the following differences:

1. Create `dkg-rotation.yaml` with `CURRENT_COMMITTEE_ID` specified:

```yaml
NETWORK: Testnet
THRESHOLD: 3  # New threshold for rotated committee
COORDINATOR_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
CURRENT_COMMITTEE_ID: 0x984d6edd224af9b67c1abd806aee5f7f85e7f5b33f37851c3daa3949f1bb5d3c  # Current committee
COMMITTEE_PKG: 0x3d7fbd0db6b200970c438dfc9ec6d61d0d5b0d8f318fd9cdae7c204597ca88e4  # Reuse existing package
MEMBERS:  # New committee members (can include continuing members)
  - 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
  - 0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
  - 0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb
  - 0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2
```

Instead of `publish-and-init`, run `init-rotation`.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py init-rotation -c crates/dkg-cli/scripts/dkg-rotation.yaml
```

This will initialize rotation and append the new `COMMITTEE_ID` to your config. Share this file with all members.

2. Phase 1, 2, 3: Follow the same steps as fresh DKG. Announce each phase to members and monitor progress. Also announce key rotation completion. 

#### Member Runbook

1. Share with the coordinator your address (`MY_ADDRESS`). This is the wallet used for the rest of the onchain commands. Make sure you are on the right network with wallet with enough gas.

2. Wait till the coordinator annouces Phase 1 and receive the `dkg-rotation.yaml` file containing `COMMITTEE_PKG`, `CURRENT_COMMITTEE_ID` and `COMMITTEE_ID` (next committee ID). Verify its parameters (members addresses, threshold, the current committee ID) on Sui Explorer. Add the following member specific fields to `dkg-rotation.yaml`:

```yaml
MY_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
MY_SERVER_URL: https://myserver.example.com
```

And run the script to generate keys locally and register onchain.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py genkey-and-register -c crates/dkg-cli/scripts/dkg-rotation.yaml
```

3. Wait for the coordinator to announce Phase 2 and run the following: 

**For continuing members**: Required to pass your old master share as an argument. 

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message \
    -c crates/dkg-cli/scripts/dkg-rotation.yaml \
    --old-share <your MASTER_SHARE_VX from previous committee version>

# This creates a file: message_P.json (where P is your party ID).
```

Share the output `message_P.json` file with the coordinator.

**For new members**: Just run the command without old share. 

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message \
    -c crates/dkg-cli/scripts/dkg-rotation.yaml

# No message file is created for new members.
```

4. Wait for the coordinator to announce Phase 3 and receive the messages directory `./dkg-rotation-messages`. Process the directory locally and propose onchain:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py process-all-and-propose \
    -c crates/dkg-cli/scripts/dkg-rotation.yaml \
    -m ./dkg-rotation-messages
```

This script:
- Processes all messages from `./dkg-rotation-messages` directory.
- Appends to your config: `PARTIAL_PKS_VX+1` (new partial public keys for all members) and `MASTER_SHARE_VX+1` (your new secret master share - keep secure!).
- Proposes the rotation onchain by calling the `propose_for_rotation` function.

5. Update `key-server-config.yaml` to Rotation mode with target version `X+1`.

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Rotation
    target_version: <X+1>
```

a. For continuing members:

i. Restart server with both `MASTER_SHARE_VX` and `MASTER_SHARE_VX+1`:

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX=<MASTER_SHARE_VX> \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1_OUTPUT_FROM_STEP_5> \
  cargo run --bin key-server
```

ii. Wait for coordinator to announce the DKG rotation is completed. Update the config to Active mode
 and restart with only `MASTER_SHARE_VX+1`:

```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Active
```

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1_OUTPUT_FROM_STEP_5> \
  cargo run --bin key-server
```

Store your old master share securely. It is needed for future rotation. 

b. For new members, since `X+1` is the first known key, so just need to start the server with it: 

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1_OUTPUT_FROM_STEP_5> \
  cargo run --bin key-server
```
