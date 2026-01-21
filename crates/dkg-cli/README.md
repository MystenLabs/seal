# Key Server Operations for Committee Mode

This guide explains how to set up and operate a key server in committee mode. It walks you through participating in a Distributed Key Generation (DKG) ceremony to generate cryptographic key shares, and then shows you how to configure and run a key server using those shares. If the committee later needs to change membership, the guide also covers key rotation and how to update a running key server accordingly.

In addition to the committee and individual key servers, committee mode requires an **aggregator server**. The aggregator collects partial key shares from committee members and combines them into a usable decryption key for clients. For details on configuring and running the aggregator, see [Aggregator doc](../../docs/Aggregator.md).

A DKG process involves two roles: a **coordinator**, which orchestrates the workflow, and a set of **committee members**, which participate in key generation and key rotation.

This document covers the following tasks:

- Running a fresh DKG to initialize a new committee and generate an initial key share (`MASTER_SHARE_V0`)
- How to configure and start your key server using the key share from the DKG output
- Performing key rotation to update committee membership or keys and generate a new key share (`MASTER_SHARE_VX+1`)
-  Updating a running key server to transition to the new key share after rotation

Both fresh DKG and key rotation follow the same three-phase process. The coordinator signals members when to move from one phase to the next:

- **Phase 1 — Registration:** Members generate encryption keys and register them onchain.
- **Phase 2 — Message Creation:** Members create and exchange DKG messages offchain.
- **Phase 3 — Finalization:** Members process messages and propose the committee configuration onchain.

The guide is organized into four sections:

- Fresh DKG coordinator runbook
- Fresh DKG member runbook (includes key server setup)
- Key rotation coordinator runbook
- Key rotation member runbook (includes key server configuration updates)

## Prerequisites

Before running the DKG or key rotation workflows, both the coordinator and all committee members must complete the following steps.

1. Install Sui: follow the [official installation guide](https://docs.sui.io/guides/developer/getting-started/sui-install).
2. Clone the [Seal repository](https://github.com/MystenLabs/seal) and set it as your working directory.

```bash
git clone https://github.com/MystenLabs/seal.git
cd seal
```

3. Install Python and required dependencies.

```bash
brew install python # if needed

# create a virtual environment (first-time setup)
python -m venv .venv
source .venv/bin/activate

# install dependencies
pip install -r crates/dkg-cli/scripts/requirements.txt
```

## Fresh DKG Process

### Coordinator Runbook

Follow these steps to initialize a new MPC committee using a fresh DKG.

1. **Prepare the DKG state directory**

Create a clean working directory named `dkg-state` and copy the example configuration file:

```bash
rm -rf dkg-state & mkdir dkg-state
cp crates/dkg-cli/scripts/dkg.example.yaml dkg-state/dkg.yaml
```

Collect the on-chain addresses of all participating members. Then open `dkg-state/dkg.yaml` and update the following fields:

```yaml
NETWORK: Testnet # Target network
THRESHOLD: 2 # Committee threshold (t of n)
COORDINATOR_ADDRESS: 0x... # Your address (must have sufficient gas for subsequent steps on the target network)
MEMBERS: # Addresses of all participating members
  - 0x...
  - 0x...
  - 0x...
```

2. **Publish and initialize the committee**

Run the publish-and-init script:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py publish-and-init -c dkg-state/dkg.yaml
```

This script publishes the `seal_committee` package onchain and initializes the committee state. It also appends the committee identifiers to `dkg.yaml`, for example: 

```yaml
COMMITTEE_PKG: 0x3358b7f7150efe9a0487ad354e5959771c56556737605848231b09cca5b791c6
COMMITTEE_ID: 0x46540663327da161b688786cbebbafbd32e0f344c85f8dc3bfe874c65a613418
```

3. **Distribute configuration and start Phase 1**

Share the updated dkg.yaml file with all committee members. Notify members to begin **Phase 1 (Registration)**.

4. **Monitor member registration**

Check on-chain registration status:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py check-committee -c dkg-state/dkg.yaml
```

The output shows which members have registered and which are still pending.

5. **Start Phase 2 after registration completes**

Once all members are registered:

- Notify members to begin **Phase 2 (Message Creation)**.
- Monitor the offchain storage location until all members upload their DKG message files.

6. **Collect and share DKG messages**

Collect all message files into a single directory and share it with members:

```bash
mkdir dkg-messages
mv message_0.json dkg-messages/
mv message_1.json dkg-messages/
mv message_2.json dkg-messages/
```

Notify members to begin **Phase 3 (Finalization)**.

7. **Confirm committee finalization**

Monitor onchain state until all members have proposed and the committee is finalized:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py check-committee -c dkg-state/dkg.yaml
```

When finalization completes, the output includes the `KEY_SERVER_OBJ_ID`. Share this object ID with all members so they can configure their key servers.

8. **Set up the aggregator server**

After all committee members have their key servers running, complete the aggregator setup.

The coordinator shares the following information with the aggregator operator:

- API credentials for each committee member, including:
    - the on-chain server name (the `PartialKeyServer.name` field)
    - the API key header name
    - the API key value
- The committee’s `KEY_SERVER_OBJ_ID` from the previous step.

With this information, the aggregator operator can deploy and run the aggregator server. For configuration and startup instructions, see the [Aggregator doc](https://github.com/MystenLabs/seal/docs/Aggregator.md).

### Member Runbook

Follow these steps to participate as a member in a fresh DKG.

1. **Share your address with the coordinator**

Share your wallet address (`MY_ADDRESS`) with the coordinator. This address is used for all onchain actions during the DKG.

Make sure:

- Your wallet is connected to the correct network.
- You have enough gas to submit transactions.

```bash
# check values
sui client active-address
sui client active-env
sui client gas

# switch values if needed
sui client switch --address <MY_ADDRESS>
sui client switch --env testnet
```

2. **Prepare your local DKG state (Phase 1)**

Wait for the coordinator to announce **Phase 1 (Registration)** and send you the `dkg.yaml` file containing `COMMITTEE_PKG` and `COMMITTEE_ID`. Create a local working directory named `dkg-state` and move the file there:

```bash
rm -rf dkg-state & mkdir dkg-state
mv path/to/dkg.yaml dkg-state/
```

Open `dkg.yaml` and verify the committee configuration (member addresses, threshold, committee ID) using a Sui Explorer.

Then generate your keys and register them onchain by providing your server URL and name:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py genkey-and-register -c dkg-state/dkg.yaml -u <MY_SERVER_URL> -n <MY_SERVER_NAME>
```

This command:

- Generates sensitive key material and stores it in `dkg-state/`. Keep this directory secure.
- Appends `DKG_ENC_PK`, `DKG_SIGNING_PK`, `MY_SERVER_URL`, `MY_SERVER_NAME` and `MY_ADDRESS` (from `sui client active-address`) to `dkg.yaml`.
- Registers your public keys onchain.

3. **Create and share your DKG message (Phase 2)**

Wait for the coordinator to announce **Phase 2 (Message Creation)**. Then initialize your local DKG state and generate your message file:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message -c dkg-state/dkg.yaml
```

This command outputs a file named `dkg-state/message_P.json`, where `P` is your party ID. Share this file with the coordinator.

4. **Process messages and propose the committee (Phase 3)**

Wait for the coordinator to announce **Phase 3 (Finalization)** and provide a directory containing all members’ messages (for example, `path/to/dkg-messages`).

Move the directory into `dkg-state` and process the messages:

```bash
mv path/to/dkg-messages dkg-state/

python crates/dkg-cli/scripts/dkg-scripts.py process-all-and-propose \
    -c dkg-state/dkg.yaml \
    -m dkg-state/dkg-messages
```

This command:

- Processes all DKG messages from the directory.
- Appends the following fields to `dkg.yaml`: 
  - `KEY_SERVER_PK` (new key server public key)
  - `PARTIAL_PKS_V0` (partial public keys for all members) 
  - `MASTER_SHARE_V0` (your local key share, used to start the key server).
- Proposes the committee onchain by calling the `propose` function.

5. **Configure and start your key server**

Wait for the coordinator to confirm that the DKG is complete and share the `KEY_SERVER_OBJ_ID`.

Create a `key-server-config.yaml` file with your address (`MY_ADDRESS`) and the key server object ID (`KEY_SERVER_OBJ_ID`), and set the committee state to active:

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Active
```

Start the key server, setting the config path and your master key share from `dkg.yaml` (use `MASTER_SHARE_V0` for a fresh DKG):

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml MASTER_SHARE_V0=0x... cargo run --bin key-server
```

6. **Generate API credentials for the aggregator**

After your key server is running successfully, generate API credentials for aggregator access and share them with the coordinator.

- Generate an **API key name** and **API key** for your key server.
- Share the following details with the coordinator:
   - Your server name (`MY_SERVER_NAME` from `dkg.yaml`, corresponding to the onchain `PartialKeyServer.name`)
   - API key name
   - API key

The coordinator will provide these credentials to the aggregator operator for authentication.

7. **Clean up local DKG state**

Once your key server is running successfully, you can safely delete the local DKG state directory:

```bash
rm -rf dkg-state
```

## Key Rotation Process

Use key rotation to update the committee membership. When rotating a committee, the set of continuing members, including those present in both the current and next committee, must be large enough to meet the threshold of the current committee.

This guide assumes:

- the current onchain committee version is X, and
- the rotation produces the next committee version X + 1.

### Coordinator Runbook

Key rotation follows the same three-phase flow as a fresh DKG, with a few important differences outlined below.

1. **Prepare the DKG state directory**

Create a clean working directory named `dkg-state` and copy the rotation example configuration:

```bash
rm -rf dkg-state & mkdir dkg-state
cp crates/dkg-cli/scripts/dkg-rotation.example.yaml dkg-state/dkg.yaml
```

Collect the addresses of all members in the **new committee** (including continuing members). Open `dkg-state/dkg.yaml` and update the following fields. 

You can obtain `KEY_SERVER_OBJ_ID` from the key server configuration of any continuing member in the current committee.

```yaml
NETWORK: Testnet # Target network
THRESHOLD: 3  # Threshold for the new committee (t of n)
COORDINATOR_ADDRESS: 0x... # Your address (must have sufficient gas for subsequent steps on the target network)
KEY_SERVER_OBJ_ID: 0x...  # Key server object ID from the current committee
MEMBERS:  # New committee members (may include continuing members)
  - 0x...
  - 0x...
  - 0x...
  - 0x..
```

2. **Initialize the rotation**

Instead of running `publish-and-init`, initialize the key rotation:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py init-rotation -c dkg-state/dkg.yaml
```

This command:

- Fetches the current key server object to determine the existing committee ID and package ID.
- Initializes the new committee object onchain.
- Appends the following fields to `dkg.yaml`:
  - `COMMITTEE_ID`
  - `COMMITTEE_PKG`
  - `CURRENT_COMMITTEE_ID`

After the command completes, share the updated `dkg.yaml` file with all members.

3. **Run Phases 1–3**

Proceed through **Phase 1 (Registration)**, **Phase 2 (Message Creation)**, and **Phase 3 (Finalization)** using the **same steps as a fresh DKG**.

As the coordinator:

- Announce the start of each phase to all members.
- Monitor progress during each phase.
- Announce completion once the key rotation finalizes onchain.

4. **Update the aggregator configuration**

If new members joined the committee during rotation, the coordinator shares with the aggregator operator the following:

1. API credentials from each new member: their onchain server name (the `PartialKeyServer.name` field), API key name, and API key.

The aggregator operator can now update the aggregator configuration and restart the server. See [Aggregator.md](../../docs/Aggregator.md) for more details.

### Member Runbook

Follow these steps to participate as a member in a key rotation.

1. **Share your address with the coordinator**

Share your wallet address (`MY_ADDRESS`) with the coordinator. This address is used for all onchain actions during the rotation.

Make sure:

- Your wallet is connected to the correct network.
- You have enough gas to submit transactions.

2. **Prepare your local DKG state (Phase 1)**

Wait for the coordinator to announce **Phase 1 (Registration)** and send you the `dkg.yaml` file. The file includes `COMMITTEE_PKG`, `CURRENT_COMMITTEE_ID`, and `COMMITTEE_ID`.

Create a local working directory named `dkg-state` and move the file there:

```bash
rm -rf dkg-state & mkdir dkg-state
mv path/to/dkg.yaml dkg-state/
```

Open `dkg.yaml` and verify the committee parameters (member addresses, threshold, current committee ID) using a Sui Explorer.

Then generate your keys and register them onchain by providing your server URL and name:

```bash
python crates/dkg-cli/scripts/dkg-scripts.py genkey-and-register -c dkg-state/dkg.yaml -u <MY_SERVER_URL> -n <MY_SERVER_NAME>
```

This command:

- Generates sensitive key material and stores it in `dkg-state/`. Keep this directory secure.
- Appends `DKG_ENC_PK`, `DKG_SIGNING_PK`, `MY_SERVER_URL`, `MY_SERVER_NAME` and `MY_ADDRESS` (from `sui client active-address`) to `dkg.yaml`.
- Registers your public keys onchain.

3. **Initialize DKG state and create messages (Phase 2)**

Wait for the coordinator to announce **Phase 2 (Message Creation)**.

**For continuing members**:

Initialize your DKG state and generate your message file. You must pass your current master share (`MASTER_SHARE_VX`):

```bash
python crates/dkg-cli/scripts/dkg-scripts.py create-message \
    -c dkg-state/dkg.yaml \
    --old-share <MASTER_SHARE_VX>
```

This command outputs `dkg-state/message_P.json`, where `P` is your party ID. Share this file with the coordinator.

**For new members**:

Initialize your DKG state without providing an old share. No message file is generated.

```bash
python crates/dkg-cli/scripts/dkg-scripts.py init-state -c dkg-state/dkg.yaml
```

4. **Process messages and propose the rotation (Phase 3)**

Wait for the coordinator to announce **Phase 3 (Finalization)** and provide a directory containing all DKG messages (for example, `path/to/dkg-messages`).

Move the directory into `dkg-state` and process the messages:

```bash
mv path/to/dkg-messages dkg-state/

python crates/dkg-cli/scripts/dkg-scripts.py process-all-and-propose \
    -c dkg-state/dkg.yaml \
    -m dkg-state/dkg-messages
```

This command:

- Processes all messages from the directory.
- Appends the following fields to `dkg.yaml`: 
  - `PARTIAL_PKS_VX+1` (new partial public keys for all members)
  - `MASTER_SHARE_VX+1` (your new master share, used to start the key server)
- Proposes the rotation onchain by calling `propose_for_rotation`.

5. **Start or update your key server**

Update `key-server-config.yaml` to **Rotation** mode and set the target committee version to `X + 1`. Leave other settings unchanged.

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  committee_state: !Rotation
    target_version: <X+1> # Increment this
```

**For continuing members:**

a. Restart the key server with both the old and new master shares. The server monitors onchain state and selects the correct share automatically.

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX=<MASTER_SHARE_VX> \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1> \
  cargo run --bin key-server
```

b. Wait for the coordinator to confirm that rotation is complete. Then update the config to **Active** mode and restart the server with only the new master share:

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

**For new members:**

Since `X + 1` is your first committee version, start the key server directly in **Active** mode using only `MASTER_SHARE_VX+1`:

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

6. **Generate API credentials for the aggregator (new members only)**

If you are a new member joining during rotation, once your key server is up and running, generate API credentials and share them with the coordinator:

1. Generate an API key name and API key for your key server.
2. Share the following with the coordinator:
   - Your server name (`MY_SERVER_NAME` from `dkg.yaml` - this is the `PartialKeyServer.name` field registered onchain)
   - API key name
   - API key

The coordinator forwards these credentials to the aggregator operator to update the aggregator configuration.

**Note:** Continuing members typically do not need to share new credentials, since their existing API keys should already be configured in the aggregator. Share new credentials only if you are rotating your API keys.

7. **Clean up local DKG state**

After your key server is running successfully, you can safely delete the local DKG state directory:

```bash
rm -rf dkg-state
```

## Quick reference: Fresh DKG vs Key rotation

| Aspect | Fresh DKG | Key Rotation |
| -------- | ------- | ------- |
| Purpose | Create a brand-new committee and keys | Update committee membership or threshold |
| Committee version | Starts at `V0` | Rotates from `VX` to `VX+1` |
| Coordinator init command | `publish-and-init` | `init-rotation` |
| Continuing members required | N/A | Must meet current threshold |
| Member Phase 2 action | All members create messages | Only continuing members create messages |
| Old master share needed | N/A | Yes (for continuing members) |
| Key server startup | Start with `MASTER_SHARE_V0` | Transition from `MASTER_SHARE_VX` to `MASTER_SHARE_VX+1` |
| Onchain proposal function | `propose` | `propose_for_rotation` |
| Result | New key server object | Updated key server object's version |
