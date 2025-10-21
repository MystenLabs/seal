# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols.

### Fresh DKG Steps

1. Initization

a. Initialize a committee, assuming an admin and members. 

- The admin deploys its own `seal_ommittee` package.

- Members to participate share their wallet addresses with the admin. This is the wallet to use to 
complete the rest of the DKG onchain steps for registering and proposing. 

- The admin initializes the Committee with a threshold and members addresses. This outputs the 
committee object ID. Share `COMMITTEE_ID` with all members. 

```bash
SEAL_PKG=0x6af07f531232b02c14058d6f980169180d60eecfda69d5267cfabb282f42ff94
COMMITTEE_PKG=0x434d924fd0b6d73b5de5791556a43820c98cb977396e4604e0166d9f3bb0bc8f

ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_committee \
  --args 2 "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"

# share this with members. 
COMMITTEE_ID=0xaa2e3cc1637ec725f3e4633f253d24e6f000f2c4a4c110f6c0bc38df1355b034
```

b. Members generate their ECIES and signing keypairs using CLI and export the environment variables.

```bash
cargo run --bin dkg-cli generate-keys

export DKG_ENC_SK=$(grep enc_sk .dkg-keys | cut -d: -f2 | xargs)
export DKG_SIGNING_SK=$(grep signing_sk .dkg-keys | cut -d: -f2 | xargs)

export DKG_ENC_PK=0x...
export DKG_SIGNING_PK=0x...
```

c. Members register the ECIES public key, signing public key and URL for the key server onchain.

```bash
sui client switch --address $ADDRESS_0 # your address
sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "<your_url>"
```

d. All members finished registration. Each member initialize the DKG protocol locally. 

```bash
cargo run --bin dkg-cli init \
    --my-address $ADDRESS_0 \
    --committee-id $COMMITTEE_ID \
    --state-dir ./state
```

2. TODO: create message, process message and finalize DKG. 
3. TODO: propose onchain. 
```bash
# test data

KEY_SERVER_PK=0x89afbc467fa40b71a19fd7c5fdc8cc1ded090fadc53d0e9e60ffa78e99e8181b233af3bd1f39406242729a22a73deb861644986946c5b9538f087b50832f454b0bdcf252fe3b81b9c33912398aa9774bdcec446da4e158ece7bb1b37baf49588
PARTY_0_PARTIAL_PK=0xb751ce15b11f71cc675f66cc490cea6151d0aa6ec2eb510969e4dfe125147a1dfe93c6b10ef6e19e7ec9a286ec5040330c08c223207379758bb742dc811885b2dcaed468650793d9486e647d2f9fb31c59b91945757f8eeb5fead34b6d353332
PARTY_1_PARTIAL_PK=0xb9b384f181c3b1fa00ac087ceb22f24e3468a320fc284ff87bd37a1c44b531679f18ad8cac1c4371736d4eadcb07a7281643f223f7cc7f9887f9cf0f5d69c2c30f2672511b4e80d00a66d34a18b0256eda999f91de53f9efd8c062025091bc30
PARTY_2_PARTIAL_PK=0x8cd739c5febbb942988e66525ff09ec3e29a746f44927069bb8e23f983cd6ee4a8f7a44b434178f7fd2951f89bae5ee70392911c0756b0339184be3f58b1de4966b8f6caa1e0a9c84429b043071fc8948935efca942f3c13fd3a115805fedd08

PARTY_0_SK=0x1d74e9fbd721d7c708d08e68c29cf57eebd491c7484747a5bc839739fa878b3a 
PARTY_1_SK=0x14086eb3e5f8531016c7fa7d1d33f95cf5b69f691e10f07d72501e9026216693
PARTY_2_SK=0x0a9bf36bf4cece5924bf669177cafd3aff98ad0af3da9955281ca5e651bb41ec

sui client switch --address $ADDRESS_0 # repeat for ADDRESS_1, ADDRESS_2
sui client call --package $COMMITTEE_PKG --module seal_committee \
    --function propose \
    --args $COMMITTEE_ID "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\", x\"$PARTY_2_PARTIAL_PK\"]" x"$KEY_SERVER_PK"

KEY_SERVER_ID=0xead654190b74da9c0d8fc80f7712925d268aa5e074e3cd4e6440a2af2adade67
```

### Key Rotation Steps

1. Admin proposes a list of new members and new threshold for the new committee, and pass in the 
old committee object ID. Share the new committee ID in output with all members. 

```bash
ADDRESS_3=0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb
ADDRESS_4=0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2
OLD_COMMITTEE_ID=0xeb27a1a8ec75a717522659e0ded17b46a5d92c6e6b729a19c5d3e2976aeb25a6

sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function init_rotation \
  --args $OLD_COMMITTEE_ID 3 "[\"$ADDRESS_1\", \"$ADDRESS_0\", \"$ADDRESS_3\", \"$ADDRESS_4\"]"

COMMITTEE_ID=0x15c4b9560ffd4922b3de98ea48cca427a376236fea86828944b3eb7e8719f856
```

b. Members generate their ECIES and signing keypairs using CLI and set the environment variables. 
Same as before. 

```bash
cargo run --bin dkg-cli generate-keys
```

c. Members register the ECIES public key, signing public key and URL onchain. Same as before. 

```bash
sui client switch --address $ADDRESS_0 # your address
sui client call --package $COMMITTEE_PKG --module seal_committee \
  --function register \
  --args $COMMITTEE_ID x"$DKG_ENC_PK" x"$DKG_SIGNING_PK" "<your_url>"
```

d. All members finished registration. Each member initialize the DKG protocol locally. 

- For continuing member, set the old share to `DKG_OLD_SHARE` environment variable. Also pass in 
the new committeee ID and the key server object ID. 

```bash
export DKG_OLD_SHARE=$PARTY_0_SK
sui client switch --address $ADDRESS_0

cargo run --bin dkg-cli init \
    --my-address $ADDRESS_0 \
    --committee-id $NEW_COMMITTEE_ID \
    --key-server-id $KEY_SERVER_ID \
    --state-dir ./state-rotate-0
```

- For new member, just pass in the new committeee ID and the key server object ID. 

```bash
sui client switch --address $ADDRESS_3

cargo run --bin dkg-cli init \
    --my-address $ADDRESS_3 \
    --committee-id $NEW_COMMITTEE_ID \
    --key-server-id $KEY_SERVER_ID \
    --state-dir ./state-rotate-3
```