# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols.

### Fresh DKG Steps

1. Initization

a. Initialize a committee, assuming a coordinator and members. 

- The coordinator deploys the `seal_committee` package.

- Members to participate share their wallet addresses with the coordinator. This is the wallet to 
use to complete the rest of the DKG onchain steps for registering and proposing. 

- The coordinator creates a Committee object with a threshold and members addresses. This outputs 
the committee object ID. Share `COMMITTEE_ID` with all members. 

```bash
SEAL_PKG=0x3e1b48f61a4db6f1423bc4d966be318476ac15110798637d1bc019da087ffcbd
COMMITTEE_PKG=0x916cfe92daf53c838a4ace2f5bd17245bdacab78f1c122042e4f38683c55c5e1
NETWORK=testnet

ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client switch --env $NETWORK
sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_committee \
  --args 2 "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"

# share this with members. 
COMMITTEE_ID=0x1d8e07b865da82d86c71bb0ac8adf174996fd780ccae8237dd5f6ea38d9fe903
```

b. Members verify that the Committee object is initialized with the expected parameters (e.g., 
using Sui explorer). Then, they generate encryption and signing keypairs using CLI. A `.dkg.key` 
with sensitive DKG private keys is generated locally. Export the public keys into environment 
variables for next step. 

```bash
cargo run --bin dkg-cli generate-keys

# env vars used for next step.
export DKG_ENC_PK=$(jq -r '.enc_pk' .dkg.key)
export DKG_SIGNING_PK=$(jq -r '.signing_pk' .dkg.key)
```

c. Members register the encryption and signing public keys, and the URL of their key server.

```bash
YOUR_SERVER_URL="replace your url here"
sui client switch --address $ADDRESS_0 # replace your address

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "$YOUR_SERVER_URL"
```

d. Admin notifies all members once registration is done.

e. Each member initialize the DKG protocol locally. The `/dkg-state` directory created is sensitive
 and contains the private keys that will be used till DKG is completed. 

```bash
cargo run --bin dkg-cli init --my-address $ADDRESS_0 --committee-id $COMMITTEE_ID --network $NETWORK
```

2. TODO: create message, process message and finalize DKG. 
3. TODO: propose onchain. 

### Key Rotation Steps

1. The coordinator proposes a list of new members and new threshold for the new committee, and pass 
in the old committee object ID. Share the new committee ID in output with all members. 

```bash
ADDRESS_3=0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb
ADDRESS_4=0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2
OLD_COMMITTEE_ID=0xeb27a1a8ec75a717522659e0ded17b46a5d92c6e6b729a19c5d3e2976aeb25a6

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_rotation \
  --args $OLD_COMMITTEE_ID 3 "[\"$ADDRESS_1\", \"$ADDRESS_0\", \"$ADDRESS_3\", \"$ADDRESS_4\"]"

# share this with all members. 
COMMITTEE_ID=0x15c4b9560ffd4922b3de98ea48cca427a376236fea86828944b3eb7e8719f856
```

b. Members generate their ECIES and signing keypairs using CLI and set the environment variables. 
Same as before. 

```bash
cargo run --bin dkg-cli generate-keys

# env vars used for next step.
export DKG_ENC_PK=$(jq -r '.enc_pk' .dkg.key)
export DKG_SIGNING_PK=$(jq -r '.signing_pk' .dkg.key)
```

c. Members register the ECIES public key, signing public key and URL onchain. Same as before. 

```bash
sui client switch --address $ADDRESS_0 # your address
SERVER_URL=<your_server_url>

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "$SERVER_URL"
```

d. Admin notifies all members once registration is done.

e. Each member initialize the DKG protocol locally with new committee ID. The `./dkg-state` 
directory created is sensitive and contains the private keys that will be used till DKG is completed.

- For continuing member, provide the old share arg. 

```bash
cargo run --bin dkg-cli init --my-address $ADDRESS_0 --old-share $DKG_OLD_SHARE --committee-id $COMMITTEE_ID --network $NETWORK
```

- For new member. 

```bash
cargo run --bin dkg-cli init --my-address $ADDRESS_3 --committee-id $COMMITTEE_ID --network $NETWORK
```

2. TODO: create message, process message and finalize DKG. 
3. TODO: propose rotation onchain. 