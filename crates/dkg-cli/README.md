# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols.

## Initial Committee Step

### Overview

1. Deploy the `move/committee` contract. Call `init_committee` to create a new Committee object with members and threshold. This should be done once per committee. 

2. Each member runs `dkg-cli generate-keys` in CLI and calls `register` to register their `CandidateData` containing the ECIES and signing public key and server URL. 
- The ECIES and signing private keys are kept secret for later. 
- The Committee object is transitioned from `State::Init` to `State::PreDKG` with a list of members and their `CandidateData`. 

4. Each party runs `dkg-cli init` to initialize local states with ECIES and signing keys. 

5. Each party runs `dkg-cli create-message` and post the message. 

6. Once all messages are posted, each party runs `dkg-cli process-all-messages` using all messages. If there is no complaint and threshold is met, DKG is finalized with outputs: 
- The partial secret key
- All parties partial public keys
- The aggregated public key of the key server

7. All parties should call `propose_committee` to submit the partial public keys and key server public key and append the approvals. The Committee object is transitioned to `State::PostDKG`. 

9. Any party can call `finalize_committee`. If all members had approved, the `KeyServer` object and `PartialKeyServer` objects are created. The Committee object is transitioned to `State::Finalized`.

10. Each party can call `update_partial_ks_url` to update their registered URL if needed. 

### Steps

1. Initization

a. Initialize a committee. 

- For a member to participate in the committee, send your wallet address with the admin who initiates the DKG, this is the same wallet you use to complete the rest of the DKG onchain steps for registering and proposing. 
- An admin can now create a Committee with threshold and members. This outputs the committee object ID. Share this with all members. 

```bash
# Create the Committee with threshold 2 and members
SEAL_PKG=0xcc40a009c7ff746c0485a8178edb07b9419f274603d918de2fddee351fecf8bf
COMMITTEE_PKG=0xfb6c20af70c873ab4f0731f7559202887fe28aa630f9682bcf06ef912fea23b6

ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client call --package $COMMITTEE_PKG --module committee \
  --function init_committee \
  --args 2 "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"

COMMITTEE_ID=0x07501cfc2da7378cffcda8d389d5a084fde206ee00f16940b07398204e3ef7ff
```

b. The committee members can now generate their ECIES and signing keypairs using CLI. 

```bash
cargo run --bin dkg-cli generate-keys
```
// todo: put secrets in a file and think about combining with dkg init
This outputs:
- ECIES Public Key: For onchain registration
- Signing Public Key: For message verification
- ECIES Private Key: Keep SECRET, needed for DKG
- Signing Private Key: Keep SECRET, for signing messages

c. Each member registers themselves to the Committee using their generated ECIES and signing public keys and URL where the key server will be ran. 

```bash
# party 0 registers
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $COMMITTEE_ID x"$PARTY_0_ECIES_PK" x"$PARTY_0_SIGNING_PK" "https://party0.com"

# party 1 registers
sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $COMMITTEE_ID x"$PARTY_1_ECIES_PK" x"$PARTY_1_SIGNING_PK" "https://party1.com"

# party 2 registers
sui client switch --address $ADDRESS_2
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args  $COMMITTEE_ID x"$PARTY_2_ECIES_PK" x"$PARTY_2_SIGNING_PK" "https://party2.com"
```

3. Offchain DKG

a. Each party initializes by fetching Committee from onchain. The CLI fetches the Committee candidates from chain (stored as dynamic fields), then determines your party ID based on sorted address position. Initialize in a local state file with the full node set with all parties' public keys.

```bash
# Party 0
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_0 \
  --committee-id $COMMITTEE_ID \
  --signing-sk $PARTY_0_SIGNING_SK \
  --ecies-sk $PARTY_0_ECIES_SK \
  --state-dir .dkg-state-0

# Party 1
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_1 \
  --committee-id $COMMITTEE_ID \
  --signing-sk $PARTY_1_SIGNING_SK \
  --ecies-sk $PARTY_1_ECIES_SK \
  --state-dir .dkg-state-1

# Party 2
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_2 \
  --committee-id $COMMITTEE_ID \
  --signing-sk $PARTY_2_SIGNING_SK \
  --ecies-sk $PARTY_2_ECIES_SK \
  --state-dir .dkg-state-2
```

b. Each party creates their DKG message.

```bash
# all parties create message
cargo run --bin dkg-cli create-message --state-dir .dkg-state-0
cargo run --bin dkg-cli create-message --state-dir .dkg-state-1  
cargo run --bin dkg-cli create-message --state-dir .dkg-state-2

MESSAGE_0=<MESSAGE_0>
MESSAGE_1=<MESSAGE_1>
MESSAGE_2=<MESSAGE_2>

c. Each party processes all messages. If no complaints are found, finalize and output. 

```bash
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-0
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-1
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-2

# All parties' local output should all contain the key server pk and all partial pks. 
KEY_SERVER_PK=0x89afbc467fa40b71a19fd7c5fdc8cc1ded090fadc53d0e9e60ffa78e99e8181b233af3bd1f39406242729a22a73deb861644986946c5b9538f087b50832f454b0bdcf252fe3b81b9c33912398aa9774bdcec446da4e158ece7bb1b37baf49588
PARTY_0_PARTIAL_PK=0xb751ce15b11f71cc675f66cc490cea6151d0aa6ec2eb510969e4dfe125147a1dfe93c6b10ef6e19e7ec9a286ec5040330c08c223207379758bb742dc811885b2dcaed468650793d9486e647d2f9fb31c59b91945757f8eeb5fead34b6d353332
PARTY_1_PARTIAL_PK=0xb9b384f181c3b1fa00ac087ceb22f24e3468a320fc284ff87bd37a1c44b531679f18ad8cac1c4371736d4eadcb07a7281643f223f7cc7f9887f9cf0f5d69c2c30f2672511b4e80d00a66d34a18b0256eda999f91de53f9efd8c062025091bc30
PARTY_2_PARTIAL_PK=0x8cd739c5febbb942988e66525ff09ec3e29a746f44927069bb8e23f983cd6ee4a8f7a44b434178f7fd2951f89bae5ee70392911c0756b0339184be3f58b1de4966b8f6caa1e0a9c84429b043071fc8948935efca942f3c13fd3a115805fedd08

# Each party's output contains their own partial secret key.
PARTY_0_SK=0x1d74e9fbd721d7c708d08e68c29cf57eebd491c7484747a5bc839739fa878b3a 
PARTY_1_SK=0x14086eb3e5f8531016c7fa7d1d33f95cf5b69f691e10f07d72501e9026216693
PARTY_2_SK=0x0a9bf36bf4cece5924bf669177cafd3aff98ad0af3da9955281ca5e651bb41ec
```

4. Finalize Onchain

a. Any party proposes a committee with partial public keys and aggregated public key from their local DKG output. A threshold of parties also proposes to add their approvals. 

```bash
sui client switch --address $ADDRESS_0 # repeat for ADDRESS_1, ADDRESS_2
sui client call --package $COMMITTEE_PKG --module committee \
    --function propose \
    --args $COMMITTEE_ID "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\", x\"$PARTY_2_PARTIAL_PK\"]" x"$KEY_SERVER_PK"
```

c. Any member of the committee can finalize the committee when the threshold is met. This creates the key server with all partial key servers (as dynamic fields) and transfers it to the committee object.

```bash
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize \
  --args $COMMITTEE_ID

# The KeyServer is created and transferred to the Committee obj
KEY_SERVER_OBJECT_ID=0xe2974ab332c5625bf1ce501bd33f518c39a3b1c788b88e996aaa3f90b8fe27e7
```

d. Each member may update their partial key server URL if needed.

```bash
sui client switch --address $ADDRESS_0 # repeat for ADDRESS_1, ADDRESS_2
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_partial_ks_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party0-keyserver.com"'
```

## Key Rotation

### Overview

1. Call `init_committee_for_rotation` to create a new Committee object with members and threshold. 
2. All members generate ECIES and signing keys, and `register` with their ECIES and signing public keys and URL. Now the Committee in State::PreDKG. 
3. Old members run `dkg-cli init-rotation` with their old partial secret key, old partial public key, the old to new party ID mapping. New members run `dkg-cli init-rotation` without old shares.
4. Old members run `dkg-cli create-message` and post their messages. 
5. All members run `dkg-cli process-all-messages`. This outputs their new partial secret key. Also outputs the key server public key and all partial public keys. The key server pk should remain the same as the one from the old committee. 
6. Any member can now call `propose_committee` to submit the new partial pks and their approvals. 
7. Any member can call `finalize_committee`. If all members had approved, the old committee is destroyed, the new committee is finalized. The key server object is transferred to the new committee, and all the partial key servers are created with new partial public keys. 
8. All members can now update their own partial key server's url. 

### Steps

1. Initialize a committee with new members that has a pointer to old committee object ID. 

Example: 2 out 3 committee rotates to 3 out of 4. The old party 0 and old party 1 are now party 1 and party 0 in the new committee. 
```shell
ADDRESS_3=0x2aaadc85d1013bde04e7bff32aceaa03201627e43e3e3dd0b30521486b5c34cb
ADDRESS_4=0x8b4a608c002d969d29f1dd84bc8ac13e6c2481d6de45718e606cfc4450723ec2

sui client call --package $COMMITTEE_PKG --module committee \
  --function init_rotation \
  --args $COMMITTEE_ID 3 "[\"$ADDRESS_1\", \"$ADDRESS_0\", \"$ADDRESS_3\", \"$ADDRESS_4\"]"

NEW_COMMITTEE_ID=0x0cfe8e0d69cd071de06eb2a7880c4adb01c1fb33b8835bec8d3a63e97b225ea4
```

2. All parties register their public keys and URL. 

```shell
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $NEW_COMMITTEE_ID x"$PARTY_0_ECIES_PK" x"$PARTY_0_SIGNING_PK" "https://party0.com"

sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $NEW_COMMITTEE_ID x"$PARTY_1_ECIES_PK" x"$PARTY_1_SIGNING_PK" "https://party1.com"

sui client switch --address $ADDRESS_3
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $NEW_COMMITTEE_ID x"$PARTY_3_ECIES_PK" x"$PARTY_3_SIGNING_PK" "https://party3.com"

sui client switch --address $ADDRESS_4
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $NEW_COMMITTEE_ID x"$PARTY_4_ECIES_PK" x"$PARTY_4_SIGNING_PK" "https://party4.com"
```

3. All members run DKG CLI `init-rotation`. The continuing members from the old committee need to pass in their `old-share`, `old-party-id`, and the old `key-server-id` to fetch the old partial public keys from the blockchain. 

```
cargo run --bin dkg-cli init-rotation \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_1_ECIES_SK \
  --signing-sk $PARTY_1_SIGNING_SK \
  --old-share $PARTY_1_SK \
  --state-dir ./rotation-state-party-0 \
  --key-server-id $KEY_SERVER_OBJECT_ID \
  --network testnet

cargo run --bin dkg-cli init-rotation \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_0_ECIES_SK \
  --signing-sk $PARTY_0_SIGNING_SK \
  --old-share $PARTY_0_SK \
  --state-dir ./rotation-state-party-1 \
  --key-server-id $KEY_SERVER_OBJECT_ID \
  --network testnet
```

New members run without `old-share` and `old-party-id`. 

```
cargo run --bin dkg-cli init-rotation \
  --party-id 2 \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_2_ECIES_SK \
  --signing-sk $PARTY_2_SIGNING_SK \
  --threshold 3 \
  --old-threshold 2 \
  --state-dir ./rotation-state-party-2 \
  --party-mapping 0:1,1:0 \
  --key-server-id $KEY_SERVER_OBJECT_ID \
  --network testnet

cargo run --bin dkg-cli init-rotation \
  --party-id 3 \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_3_ECIES_SK \
  --signing-sk $PARTY_3_SIGNING_SK \
  --threshold 3 \
  --old-threshold 2 \
  --state-dir ./rotation-state-party-3 \
  --party-mapping 0:1,1:0 \
  --key-server-id $KEY_SERVER_OBJECT_ID \
  --network testnet
```

4. The two continuing parties run `create-message`. 

```shell
cargo run --bin dkg-cli create-message --state-dir ./rotation-state-party-0
cargo run --bin dkg-cli create-message --state-dir ./rotation-state-party-1

MESSAGE_0=<MESSAGE_0>
MESSAGE_1=<MESSAGE_1>
```

5. All parties run `process-all-messages`. 

```shell
cargo run --bin dkg-cli process-all-messages \
  --messages $MESSAGE_0,$MESSAGE_1 \
  --state-dir ./rotation-state-party-0

cargo run --bin dkg-cli process-all-messages \
  --messages $MESSAGE_0,$MESSAGE_1 \
  --state-dir ./rotation-state-party-1

cargo run --bin dkg-cli process-all-messages \
  --messages $MESSAGE_0,$MESSAGE_1 \
  --state-dir ./rotation-state-party-2

cargo run --bin dkg-cli process-all-messages \
  --messages $MESSAGE_0,$MESSAGE_1 \
  --state-dir ./rotation-state-party-3
```

```shell
# Each party should see the key server public key (unchanged from the last committee). The new set of partial public keys from all parties. 
KEY_SERVER_PK=0x89afbc467fa40b71a19fd7c5fdc8cc1ded090fadc53d0e9e60ffa78e99e8181b233af3bd1f39406242729a22a73deb861644986946c5b9538f087b50832f454b0bdcf252fe3b81b9c33912398aa9774bdcec446da4e158ece7bb1b37baf49588
NEW_PARTY_0_PK=0xa902797f71d15e5410686b29019cdfd09fa641f8069815f0f122a5a564b60ddf6f8c408c30c95b30967e13f10c96f8271423ddb64efe3527e171d5057501b78c70bc2f37d538f851b2f01fd67d018d233ec90fbe12762e2ba3e353dfcf935880
NEW_PARTY_1_PK=0xa3359770d9c57203a06f94cb87b4556498f7a8d192d5996283b3b0bfb90412fadfe957ef248952c637b8fd29fe556bd20d1d9778fb1b956efb4d0749be4fd49e15881648ec9d558a88e4a2f3949c2147db53c611c2ef5e0fc6f897a7b8a692eb
NEW_PARTY_2_PK=0x94dc2adcf38b2c41e84094696181536b957f039cd491cc9816e278658c07d745a4b235185198e4e2448af43ba2403447154f7d55769c94dd0a456bf30ca34718a567cbed94998dd4d459957a5425393face7a02e78e58deca9a8df2cd3b132e7
NEW_PARTY_3_PK=0x88bd931e9308b4f2e5dce359b1180da67e81ee40f0b607929d78c4403f0a3c1c5fbc78117d4cd5b17d38d78a3b49bf94101090bba00327f6962f6e977e07d90f8098de133f9e6344b34e2c5f291a482cb92abc5eeb5f00247a782d523a3b97ba

# Each party should see their own partial secret keys individually. 
NEW_PARTY_0_SK=0x6c1f3b906facd41526185722eb2fd875e82f7a20cfc91c45f13d47223a93274f
NEW_PARTY_1_SK=0x3afaf1cbc552b3306d03c3b1dfa423101825be8af1195e6b30f946a6f8a4d08a
NEW_PARTY_2_SK=0x07622f48f2da771802d540094f04a974c592f566d66cc13cc5eb0e710922ab93
NEW_PARTY_3_SK=0x45429b5b21e19d141ac6a43142f343a94434c2b77fc1a0b9b0129e7f6c0cb86b
```

6. All members must propose all partial pks and key server pk for rotation to append their approvals. 

```shell
sui client switch --address $ADDRESS_0 # repeat for $ADDRESS_1, $ADDRESS_3, $ADDRESS_4
sui client call --package $COMMITTEE_PKG --module committee \
    --function propose_for_rotation \
    --args $NEW_COMMITTEE_ID $COMMITTEE_ID "[x\"$NEW_PARTY_0_PK\", x\"$NEW_PARTY_1_PK\", x\"$NEW_PARTY_2_PK\", x\"$NEW_PARTY_3_PK\"]"
```

7. Any member can now finalize the committee once all approvals are submitted. 

```shell 
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize_for_rotation \
  --args $NEW_COMMITTEE_ID $COMMITTEE_ID $KEY_SERVER_OBJECT_ID
```

8. Members in the new committee can update their corresponding partial key server's URL if needed. 

```shell
sui client switch --address $ADDRESS_0
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_partial_ks_url @$KEY_SERVER_OBJECT_ID @$NEW_COMMITTEE_ID '"https://rotation0-keyserver.com"'
```