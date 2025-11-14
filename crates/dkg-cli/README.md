# DKG CLI Tool

** WARNING: This is WIP. Do not use. **

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols. A DKG process involves a coordinator and a set of participating members. Here we describe the processes for both a fresh DKG and a DKG key rotation. 

### Fresh DKG Process

#### Coordinator Runbook

1. Deploy the `seal_committee` package in the Seal repo. Make sure you are on the right network with wallet with enough gas. Find the package ID in output, set it to env var `COMMITTEE_PKG`. Share this with members later. 

```bash
NETWORK=testnet
sui client switch --env $NETWORK
cd move/committee
sui client publish

COMMITTEE_PKG=0x3358b7f7150efe9a0487ad354e5959771c56556737605848231b09cca5b791c6
```

2. Gather all members' addresses. 
3. Initialize the committee onchain. Notify members:

- Committee package ID (`COMMITTEE_PKG`)
- Committee object ID (`COMMITTEE_ID`)

Then announce phase 1. 

```bash
NETWORK=testnet
THRESHOLD=2 # Replace this with your threshold. 
ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d # Replace these with the members' addresses. 
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_committee \
  --args $THRESHOLD "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"

# Find the created committee object in output and share this with members. 
COMMITTEE_ID=0x46540663327da161b688786cbebbafbd32e0f344c85f8dc3bfe874c65a613418
```

4. Watch the onchain state until all members registered. Check the committee object state members on Explorer containing entries of all members' addresses. 
5. Notify all members to run phase 2. 
6. Watch the offchain storage until all members upload their messages. 
7. Make a directory containing all messages and share it. Notify all members to run phase 3 with this directory.
8. Monitor the committee onchain object for finalized state when all members approve. Notify the members the DKG process is completed and the created key server object ID. 

#### Member Runbook

1. Share with the coordinator your address (`MY_ADDRESS`). This is the wallet used for the rest of the onchain commands. 
2. Receive from coordinator the committee package ID and committee object ID. Verify its parameters (members addresses and threshold) on Sui Explorer. Set environment variables. 

```bash
COMMITTEE_PKG=0x3358b7f7150efe9a0487ad354e5959771c56556737605848231b09cca5b791c6
COMMITTEE_ID=0x46540663327da161b688786cbebbafbd32e0f344c85f8dc3bfe874c65a613418
```

3. Wait for the coordinator to announce phase 1. Run the CLI below to generate keys locally and register the public keys onchain. Make sure you are on the right network with wallet with enough gas. 

```bash
# A directory (default to `./dkg-state/`) containing sensitive private keys is created. Keep it secure till DKG is completed.
cargo run --bin dkg-cli generate-keys

export DKG_ENC_PK=$(jq -r '.enc_pk' dkg-state/dkg.key)
export DKG_SIGNING_PK=$(jq -r '.signing_pk' dkg-state/dkg.key)

# Register onchain. 
sui client switch --env $NETWORK
YOUR_SERVER_URL="replace your url here"
MY_ADDRESS=$ADDRESS_0 # Replace your address here.

sui client switch --address $MY_ADDRESS
sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "$YOUR_SERVER_URL"
```

4. Wait for the coordinator to announce phase 2. Initialize the DKG state locally and create your message file. Share the output file with the coordinator.

```bash
cargo run --bin dkg-cli create-message --my-address $MY_ADDRESS --committee-id $COMMITTEE_ID --network $NETWORK

# This creates a file: ./message_P.json (where P is your party ID).
```

5. Wait for the coordinator to announce phase 3 and share a directory `./dkg-messages` containing all messages. Process the directory locally.

```bash
cargo run --bin dkg-cli process-all --messages-dir ./dkg-messages

# Outputs key server public key and partial public keys, used for onchain proposal. 
============KEY SERVER PK AND PARTIAL PKS=====================
KEY_SERVER_PK=0xb43c7a03bae03685d6411083d34d2cc3efd997274ac9ca1fdee37d592bb9c8e6ed4576c68031477d2f19296f8ce1590d022c60d0a82a56c0c1018551648978f193c5fa5737a50415a3391311decafc6224d7632253a92d142dcd62c85fcc09f7
PARTY_0_PARTIAL_PK=0x8ef79f15defb1ea58b5644aa1fccc79f6235d3fff425ebe9140c3fda8e493d23ea6575bbe63af0204a14343f04f7d3d70d0bb51e044d87b03e251ee388f3837d87c6973e53af50602805110b2ec0f365de51bd046c38ce6e433e663cd8aaff1e
PARTY_1_PARTIAL_PK=0x810b3577cb1e6dd011f1f8e2561f0e4f3c05eb0918f388817156de1a87a00b2b43f1e892da1efd09192fa85d62f83c1308b04beba3ed4d42ce01865bbd4eed24942a9504df90dce40575b05014a7b953ca4ec17530fe4367c1815cb7aca10261
PARTY_2_PARTIAL_PK=0x92bb786ec791646fe63e99917b88c33966c9380b61dac70e4518d4a95834b42cc9163eb2cb6d067279525400bc59d91b05e52d19846bdd55a143e2d7cc7365355563a0a4d2004c6d5511da2d102d64bf0b4a518597b01af1984bfe69e2f13da5

# Outputs new share, use it for MASTER_SHARE_V0 environment variable for step 7.
============YOUR PARTIAL KEY SHARE, KEEP SECRET=====================
MASTER_SHARE_V0=0x208cd48a92430eb9f90482291e5552e07aebc335d84b7b6371a58ebedd6ed036
```

6. Propose the committee onchain with locally finalized key server public key and partial public keys. 

```bash
sui client call --package $COMMITTEE_PKG --module seal_committee \
    --function propose \
    --args $COMMITTEE_ID "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\", x\"$PARTY_2_PARTIAL_PK\"]" x"$KEY_SERVER_PK"
```

7. Wait for the coordinator to announce that the DKG process is completed and share the created key server object ID `KEY_SERVER_OBJ_ID`. Update `key-server-config.yaml` containing `MY_ADDRESS` and `KEY_SERVER_OBJ_ID` and start the server with `MASTER_SHARE_V0` (version 0 for fresh DKG).

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  target_key_server_version: 0
```

Example command to start server:
```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml MASTER_SHARE_V0=0x208cd48a92430eb9f90482291e5552e07aebc335d84b7b6371a58ebedd6ed036 cargo run --bin key-server
```

### Key Rotation Process

A key rotation process is needed when a committee wants to rotate a portion of its members. The continuing members (in both current and next committee) must meet the threshold of the current committee. 

Assuming the key server committee mode version onchain is currently X and it is being rotated to X+1. 

#### Coordinator Runbook

All steps are the same as the runbook for fresh DKG. Except:
- Modified step 2: Instead of calling `init_committee`, call `init_rotation`, where `CURRENT_COMMITTEE_ID` is the object ID of the current committee (e.g., `CURRENT_COMMITTEE_ID=0xaf2962d702d718f7b968eddc262da28418a33c296786cd356a43728a858faf80`).

```bash
# Example new members for rotation, along with ADDRESS_1, ADDRESS_0. Replace with your own. 
ADDRESS_3=0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb
ADDRESS_4=0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2
THRESHOLD=3 # New committee threshold, replace with your own. 

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_rotation \
  --args $CURRENT_COMMITTEE_ID $THRESHOLD "[\"$ADDRESS_1\", \"$ADDRESS_0\", \"$ADDRESS_3\", \"$ADDRESS_4\"]"

# New committee ID, share with all members. 
COMMITTEE_ID=0x82283c1056bb18832428034d20e0af5ed098bc58f8815363c33eb3a9b3fba867
```

- Added step 9: Monitor onchain that the new committee is finalized. Then announce DKG rotation is completed. 

#### Member Runbook

1. Share with the coordinator your address (`MY_ADDRESS`). This is the wallet used for the rest of the onchain commands. 
2. Receive from the coordinator the next committee ID. Verify its parameters (members addresses, threshold, the current committee ID) on Sui Explorer. Set environment variable.

```bash
# Next committee ID
COMMITTEE_ID=0x1614a8a2597e4ce6db9e8887386957b1d47fd36d58114034b511260f62fe539b
``` 

3. Wait for the coordinator to announce phase 1. Run the CLI below to generate keys locally and register the public keys onchain. Make sure you are on the right network with wallet with enough gas. 

```bash
# A directory (default to `./dkg-state/`) containing sensitive private keys is created. Keep it secure till DKG is completed.
cargo run --bin dkg-cli generate-keys

export DKG_ENC_PK=$(jq -r '.enc_pk' dkg-state/dkg.key)
export DKG_SIGNING_PK=$(jq -r '.signing_pk' dkg-state/dkg.key)

# Register onchain. 
sui client switch --env $NETWORK
YOUR_SERVER_URL="replace your url here"
MY_ADDRESS=$ADDRESS_0 # Replace your address here.

sui client switch --address $MY_ADDRESS
sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "$YOUR_SERVER_URL"
```

4. Wait for the coordinator to announce phase 2.

a. For continuing members, run the CLI below to initialize the local state and create your message file. Must provide `--old-share` arg with your current version `X` master share. Share the output file with the coordinator.

```bash
cargo run --bin dkg-cli create-message --my-address $MY_ADDRESS --committee-id $COMMITTEE_ID --network $NETWORK --old-share $MASTER_SHARE_VX

# This creates a file: ./message_P.json (where P is your party ID).
```

b. For new members, run the CLI below that initializes the local state. Do not provide old share.

```bash
cargo run --bin dkg-cli create-message --my-address $MY_ADDRESS --committee-id $COMMITTEE_ID --network $NETWORK

# No file is created or needed to be shared with the coordinator. 
```

5. Wait for the coordinator to announce phase 3 and share a directory `./dkg-messages` containing all messages. Process the directory locally.

```bash
cargo run --bin dkg-cli process-all --messages-dir ./dkg-messages

# Outputs partial public keys, used for onchain proposal.
PARTY_0_PARTIAL_PK=<...>
PARTY_1_PARTIAL_PK=<...>
PARTY_2_PARTIAL_PK=<...>
PARTY_3_PARTIAL_PK=<...>

# Outputs new share (version X+1), to be used to start server at step 7.
MASTER_SHARE_VX+1=0x03899294f5e6551631fcbaea5583367fb565471adeccb220b769879c55e66ed9
```

6. Propose the committee onchain with locally finalized partial public keys. 

```bash
sui client call --package $COMMITTEE_PKG --module seal_committee \
    --function propose_for_rotation \
    --args $COMMITTEE_ID "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\", x\"$PARTY_2_PARTIAL_PK\", x\"$PARTY_3_PARTIAL_PK\"]" $CURRENT_COMMITTEE_ID
```

7. Increment the version in `key-server-config.yaml` by 1, from `X` to `X+1`. 

Example config file:
```yaml
server_mode: !Committee
  member_address: '<MY_ADDRESS>'
  key_server_obj_id: '<KEY_SERVER_OBJ_ID>'
  target_key_server_version: <X+1>
```

a. For continuing members:

i. Restart server with both versioned keys (the current version onchain is still `X`, target is `X+1`). During this transition, the server watches for the current version onchain: If it is still `X`, serve request with `MASTER_SHARE_VX`. If onchain transitions to `X+1`, serve request with `MASTER_SHARE_VX+1`. 

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX=<MASTER_SHARE_VX> \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1_OUTPUT_FROM_STEP_5> \
  cargo run --bin key-server
```

ii. Wait for coordinator to announce the DKG rotation is completed. Since now onchain version is indeed `X+1`, restart with only the version `X+1` key is sufficient:

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1_OUTPUT_FROM_STEP_5> \
  cargo run --bin key-server
```

iii. Delete the old key `MASTER_SHARE_VX` from storage permanently.

b. For new members, since `X+1` is the first known key, so just need to start the server with it: 

```bash
CONFIG_PATH=crates/key-server/key-server-config.yaml \
  MASTER_SHARE_VX+1=<MASTER_SHARE_VX+1_OUTPUT_FROM_STEP_5> \
  cargo run --bin key-server
```
