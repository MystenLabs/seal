# DKG CLI Tool

** WARNING: This is WIP. Do not use. **

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols. A DKG process involves a coordinator and a set of participating members. Here we describe the processes for both a fresh DKG and a key rotation.

Both fresh DKG and key rotation has 3 phases. The coordinator signals the members when to proceed from one phase to the next.

- **Phase 1 (Registration)**: Members generate and register their encryption keys onchain.
- **Phase 2 (Message Creation)**: Members create and share DKG messages offchain.
- **Phase 3 (Finalization)**: Members process messages, propose committee onchain. 

There are 4 sections:

- Fresh DKG coordinator runbook
- Fresh DKG member runbook
- Key rotation coordinator runbook
- Key rotation member runbook

## Prerequisites

The coordinator and all members are required to complete the following in order to run the scripts.

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

1. Make directory`dkg-state` and copy `crates/dkg-cli/scripts/dkg.example.yaml` to `dkg-state/dkg.yaml`:

```bash
rm -rf dkg-state & mkdir dkg-state
cp crates/dkg-cli/scripts/dkg.example.yaml dkg-state/dkg.yaml
```

Gather all members' addresses. Edit the following fields:

```yaml
NETWORK: Testnet # Expected network
THRESHOLD: 2 # Expected threshold
# Your address, make sure you have enough gas for subsequent onchain calls for the network
COORDINATOR_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
MEMBERS: # Gathered from participating members
  - 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
  - 0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
  - 0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9
```

2. Run the publish-and-init script.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py publish-and-init -c dkg-state/dkg.yaml
```

This publishes the `seal_committee` package and initializes the committee onchain. The script also appends the following to `dkg.yaml`. 

```yaml
COMMITTEE_PKG: 0x3358b7f7150efe9a0487ad354e5959771c56556737605848231b09cca5b791c6
COMMITTEE_ID: 0x46540663327da161b688786cbebbafbd32e0f344c85f8dc3bfe874c65a613418
```

3. Share the updated `dkg.yaml` file with all members. Announce to all members to begin Phase 1.

4. Monitor onchain state until all members are registered using the check-committee script.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py check-committee -c dkg-state/dkg.yaml
```

This will show which members have registered and which are still missing.

5. Announce to all members to begin Phase 2 when all members registered. Monitor offchain storage until all members upload their messages.

6. Collect all messages files into a directory (e.g., `./dkg-messages`) and share it. Announce to all members to begin Phase 3.

```bash
mkdir dkg-messages
mv message_0.json dkg-messages/
mv message_1.json dkg-messages/
mv message_2.json dkg-messages/
```

7. Monitor onchain state until all members had proposed and the committee state is finalized.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py check-committee -c dkg-state/dkg.yaml
```

This will show which members had proposed and which are still missing. If all members had proposed and the committee is finalized, it will show the key server object ID (`KEY_SERVER_OBJ_ID`). Share it with all members to configure their key servers. 

#### Member Runbook

1. Share with the coordinator your address (`MY_ADDRESS`). This is the wallet used for the rest of the onchain commands. Make sure you are on the right network with wallet with enough gas.

2. Wait till the coordinator annouces Phase 1 and receive the `dkg.yaml` file containing `COMMITTEE_PKG` and `COMMITTEE_ID`. Verify its parameters (members addresses and threshold) on Sui Explorer. Add your member specific fields to `dkg.yaml`:

```yaml
MY_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
MY_SERVER_URL: https://myserver.example.com
```

Download the `dkg.yaml` and run the following to generate keys locally and register onchain.

```bash
rm -rf dkg-state & mkdir dkg-state
mv path/to/dkg.yaml dkg-state/
python crates/dkg-cli/scripts/dkg-scripts.py genkey-and-register -c dkg-state/dkg.yaml
```

This script:
- Generates sensitive keys and saved `/dkg-state/` directory. Keep it secure.
- Appends `DKG_ENC_PK` and `DKG_SIGNING_PK` to `dkg.yaml`.
- Registers your public keys onchain.

3. Wait till the coordinator annouces Phase 2. Run the following to initialize DKG state and outputs a message file at `dkg-state/message_P.json` (where P is your party ID).

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message -c dkg-state/dkg.yaml
```

Share the file `message_P.json` with the coordinator.

4. Wait for the coordinator to announce Phase 3 and download the directory `path/to/dkg-messages` containing all messages from the coordinator. Run the following:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py process-all-and-propose \
    -c dkg-state/dkg.yaml \
    -m path/to/dkg-messages
```

This script:
- Processes all messages from `path/to/dkg-messages` directory.
- Appends to `dkg.yaml`: `KEY_SERVER_PK` (new key server public key), `PARTIAL_PKS_V0` (partial public keys for all members), and `MASTER_SHARE_V0` (This is used at next step to start your server with).
- Proposes the committee onchain by calling the `propose` function.

5. Wait for the coordinator to announce that the DKG is completed and receive `KEY_SERVER_OBJ_ID`. Now you are ready to configure and run the key server: 

- Create `key-server-config.yaml` with `MY_ADDRESS` and `KEY_SERVER_OBJ_ID` and set Active mode. 
- Start the server with environment variable config path and `MASTER_SHARE_V0` (0 is used for fresh DKG) set to the value from `dkg.yaml`. 

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

6. Now it is safe to delete `./dkg-state` directory (containing `dkg.yaml`, `dkg.key` and `state.json`) completely.

### Key Rotation Process

A key rotation process is needed when a committee wants to update a portion of its members. The count of continuing members (those who are in both the current and next committee) must meet the threshold of the current committee.

Assuming the key server committee mode version onchain is currently at `X`. It is being rotated to next version at `X+1`.

#### Coordinator Runbook

The process follows the same three phases as fresh DKG, with the following differences:

1. Make `dkg-directory` and copy `crates/dkg-cli/scripts/dkg-rotation.example.yaml` to `dkg-state/dkg.yaml`:

```bash
rm -rf dkg-state & mkdir dkg-state
cp crates/dkg-cli/scripts/dkg-rotation.example.yaml dkg-state/dkg.yaml
```

Gather all members' addresses. Edit the following fields. `KEY_SERVER_OBJ_ID` that can be found in any continuing members' key server's config file. 

```yaml
NETWORK: Testnet
THRESHOLD: 3  # New threshold for new committee
COORDINATOR_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
KEY_SERVER_OBJ_ID: 0x0688650cf0b28882e607ae43df1e95e769f9b2f689cf90d68c715b3e08e28c70  # Key server object from current committee
MEMBERS:  # New committee members (can include continuing members)
  - 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
  - 0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
  - 0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb
  - 0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2
```

2. Instead of `publish-and-init`, run `init-rotation`.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py init-rotation -c dkg-state/dkg.yaml
```

This script will:
- Fetch the key server object to determine the current committee ID and committee package ID.
- Initialize the new committee object and append its object ID `COMMITTEE_ID`, along with `COMMITTEE_PKG` and `CURRENT_COMMITTEE_ID` to `dkg.yaml`.

Share the updated `dkg.yaml` with all members.

3. Phase 1, 2, 3: Follow the same steps as fresh DKG. Announce each phase to members and monitor progress. Also announce key rotation completion. 

#### Member Runbook

1. Share with the coordinator your address (`MY_ADDRESS`). This is the wallet used for the rest of the onchain commands. Make sure you are on the right network with wallet with enough gas.

2. Wait till the coordinator annouces Phase 1 and receive the `dkg.yaml` file containing `COMMITTEE_PKG`, `CURRENT_COMMITTEE_ID` and `COMMITTEE_ID`. Verify its parameters (member addresses, threshold, the current committee ID) on Sui Explorer. Add your member specific fields to `dkg.yaml`:

```yaml
MY_ADDRESS: 0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
MY_SERVER_URL: https://myserver.example.com
```

Download the `dkg.yaml` and run the following to generate keys locally and register onchain.

```bash
mkdir dkg-state/
mv path/to/dkg.yaml dkg-state/
python crates/dkg-cli/scripts/dkg-scripts.py genkey-and-register -c dkg-state/dkg.yaml
```

This script:
- Generates sensitive keys and saved `/dkg-state/` directory. Keep it secure.
- Appends `DKG_ENC_PK` and `DKG_SIGNING_PK` to `dkg.yaml`.
- Registers your public keys onchain.

3. Wait for the coordinator to announce Phase 2 and run the following: 

**For continuing members**: Run the following to initialize DKG state and outputs a message file at `dkg-state/message_P.json` (where `P` is your party ID). Must pass your current master share `MASTER_SHARE_VX` as an argument. 

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message \
    -c dkg-state/dkg.yaml \
    --old-share <MASTER_SHARE_VX>
```

Share the file `message_P.json` with the coordinator.

**For new members**: Just run the command without old share to initialize DKG state. No file is outputed or needed to be shared.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py init-state -c dkg-state/dkg.yaml
```

4. Wait for the coordinator to announce Phase 3 and download the directory `path/to/dkg-messages` containing all messages from the coordinator. Run the following:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py process-all-and-propose \
    -c dkg-state/dkg.yaml \
    -m path/to/dkg-messages
```

This script:
- Processes all messages from `path/to/dkg-messages` directory.
- Appends to your config: `PARTIAL_PKS_VX+1` (new partial public keys for all members) and `MASTER_SHARE_VX+1` (This is used at next step to start your server with).
- Proposes the rotation onchain by calling the `propose_for_rotation` function.

5. Now you are ready to run your key server. Update `key-server-config.yaml` to Rotation mode with target version `X+1`. Leave other configs unchanged. 

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Rotation
    target_version: <X+1> # Increment this
```

a. For continuing members:

i. Restart server with both `MASTER_SHARE_VX` and `MASTER_SHARE_VX+1`. Now your server will monitor onchain periodically to determine which master share to use to serve requests.

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX=<MASTER_SHARE_VX> \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1> \
  cargo run --bin key-server
```

ii. Wait for the coordinator to announce the DKG rotation is completed. Update the config to Active mode and restart with only `MASTER_SHARE_VX+1`:

```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Active
```

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1> \
  cargo run --bin key-server
```

b. For new members, since `X+1` is the first known key, so just need to start the server with `MASTER_SHARE_VX+1` and the config file set to active: 

```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Active
```

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1> \
  cargo run --bin key-server
```

6. Now it is safe to delete `./dkg-state` directory (containing `dkg.yaml`, `dkg.key` and `state.json`) completely.
