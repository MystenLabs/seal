# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols. A DKG process involves a coordinator and a set of participating members. Here we describe the processes for both a fresh DKG and a DKG key rotation. 

### Fresh DKG Process

#### Coordinator Runbook

1. Deploy the `seal_committee` package in the Seal repo. Make sure you are on the right network with wallet with enough gas. Find the package ID in output, set it to env var. Share this with members later. 

```bash
NETWORK=testnet
sui client switch --env $NETWORK
cd move/committee
sui client publish

COMMITTEE_PKG=0x4563316d2b647263737bbab1afb32495397bd36eefdcd3b1ca42c3c95ebb2fb3
```

2. Gather all members' addresses. 
3. Initialize the committee onchain. Notify members:

- Committee package ID
- Created committee object ID

Then announce phase 1. 

```bash
THRESHOLD=2 # Replace this with your threshold. 
ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d # Replace these with the members' addresses. 
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_committee \
  --args $THRESHOLD "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"

# Find the created committee object in output and share this with members. 
COMMITTEE_ID=0x210f1a2157d76e5c32a5e585ae3733b51105d553dc17f67457132af5e2dae7a5
```

4. Watch the onchain state until all members registered. Check the committee object state members on Explorer containing entries of all members' addresses. 
5. Notify all members to run phase 2. 
6. Watch the offchain storage until all members upload their messages. 
7. Notify all members to run phase 3.
8. Monitor the committee for finalized state when all members approves. 

#### Member Runbook

1. Share with the coordinator its address. This is the wallet used for the rest of the onchain commands. 
2. Receive from coordinator the committee package ID and committee ID. Verify its parameters (members addresses and threshold) on Sui Explorer. Set environment variables. 

```bash
COMMITTEE_PKG=0x4563316d2b647263737bbab1afb32495397bd36eefdcd3b1ca42c3c95ebb2fb3
COMMITTEE_ID=0x210f1a2157d76e5c32a5e585ae3733b51105d553dc17f67457132af5e2dae7a5
```

3. Wait for the coordinator to announce phase 1. Run the CLI below to generate keys locally and register the public keys onchain. Notify the coordinator when finished. 

```bash
# A file `.dkg.key` containing sensitive private keys is created locally. Keep it secure till DKG is completed. 
cargo run --bin dkg-cli generate-keys

export DKG_ENC_PK=$(jq -r '.enc_pk' .dkg.key)
export DKG_SIGNING_PK=$(jq -r '.signing_pk' .dkg.key)

# Register onchain. 
sui client switch --env $NETWORK
YOUR_SERVER_URL="replace your url here"
MY_ADDRESS=$ADDRESS_0 # Replace your address here.

sui client switch --address $MY_ADDRESS
sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "$YOUR_SERVER_URL"
```

4. Wait for the coordinator to announce phase 2. Initialize the DKG state locally, create your message and upload it to offchain storage. 

```bash
# The `/dkg-state` directory is created, containing sensitive private keys. Keep it secure till DKG is completed. 
cargo run --bin dkg-cli init --my-address $MY_ADDRESS --committee-id $COMMITTEE_ID --network $NETWORK
```

5. TODO: Wait for the coordinator to announce phase 3. Process all messages locally and propose the committee onchain.

### Key Rotation Process

A key rotation process is needed when a committee wants to rotate a portion of its members. The contuning members (in both current and next committee) must meet the threshold of the current committee. 

#### Coordinator Runbook

1. Gather all members' addresses for the next committee, including continuing members and new members. 

2. Initialize the next committee onchain with the current committee object ID. Notify members the next committee object ID and announce phase 1. 

```bash
THRESHOLD=3 # Replace with the new threshold. 
ADDRESS_3=0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb # Replace with your members' addresses
ADDRESS_4=0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2
CURRENT_COMMITTEE_ID=0x210f1a2157d76e5c32a5e585ae3733b51105d553dc17f67457132af5e2dae7a5 # Replace with the current committee ID. 

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_rotation \
  --args $CURRENT_COMMITTEE_ID $THRESHOLD "[\"$ADDRESS_1\", \"$ADDRESS_0\", \"$ADDRESS_3\", \"$ADDRESS_4\"]"

# Find the created next committee object in output and share this with members.
COMMITTEE_ID=0x15c4b9560ffd4922b3de98ea48cca427a376236fea86828944b3eb7e8719f856
```

4. Watch the onchain state until all members registered. 
5. Notify all members to run phase 2. 
6. Watch the offchain storage until all members upload their messages. 
7. Notify all members to run phase 3.
8. Monitor the committee for finalized state when all members approves. 

#### Member Runbook

1. Share with the coordinator its address. This is the wallet used for the rest of the onchain commands. 
2. Receive from coordinator the next committee ID. Verify its parameters (members addresses, threshold, the current committee ID) on Sui Explorer. Set environment variable.

```bash
# next committee ID
COMMITTEE_ID=0x210f1a2157d76e5c32a5e585ae3733b51105d553dc17f67457132af5e2dae7a5
``` 

3. Wait for the coordinator to announce phase 1. Run the CLI below to generate keys locally and register the public keys onchain. Make sure you are on the right network with wallet with enough gas. 

```bash
# A file `.dkg.key` containing sensitive private keys is created locally. Keep it secure till DKG is completed. 
cargo run --bin dkg-cli generate-keys

export DKG_ENC_PK=$(jq -r '.enc_pk' .dkg.key)
export DKG_SIGNING_PK=$(jq -r '.signing_pk' .dkg.key)

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

a. For continuing members, run the CLI below to initialize the local state, create your message and upload it to offchain storage. Must provide `--old-share` arg. 

```bash
cargo run --bin dkg-cli init --my-address $MY_ADDRESS --old-share $DKG_OLD_SHARE --committee-id $COMMITTEE_ID --network $NETWORK
```

b. For new members, run the CLI below that initialize the local state. Do not provide old share. 

```bash
cargo run --bin dkg-cli init --my-address $MY_ADDRESS --committee-id $COMMITTEE_ID --network $NETWORK
```

5. TODO: Wait for the coordinator to announce phase 3. Process all messages locally and propose the committee onchain.