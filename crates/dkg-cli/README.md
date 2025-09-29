# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols.

## Initial Committee Step

### Overview

1. Call `init_committee` to create new Committee object with members and threshold. 

2. Each member runs `dkg-cli generate-keys` in CLI and call `register` to reggister their `CandidateData` containing the ECIES and signing public key. 
- The ECIES and signing private keys are kept secret for later. 
- The Committee object is transitioned from `State::Init` to `State::PreDKG` with a list of members and their `CandidateData`. 

4. Each party runs `dkg-cli init` to initialize local state with ECIES and signing private keys. 

5. Each party runs `dkg-cli create-message` and post the message. 

6. Once all messages are posted, each party runs `dkg-cli process-all-messages` using all messages. If there is no complaint and threshold is met, DKG is finalized with outputs: 
- The partial secret key
- All parties partial public keys
- The aggregated public key of the key server

7. All parties can call `propose_committee` to submit the partial public keys and key server public key and append the approvals. Committee object is transitioned to `State::PostDKG`. 

9. Any party can call `finalize_committee`. If all members had approved, the `KeyServer` object and `PartialKeyServer` objects are created. Committee object is transitioned to `State::Finalized`.

10. Each party can call `update_url` to update their own partial key server object. 

### Steps

1. Initization

a. Create a Committee with threshold and members (anyone can call this). This outputs the committee object ID.

```bash
# Create the Committee with threshold 2 and members
SEAL_PKG=0xa77969b0f2ea1b197a87771f459f07afc6629ab1540d5eef3340674fa422825e
COMMITTEE_PKG=0xdef53cec49f7ff565c4834b0da66bf2d0de421eee0bca71d88dcc4efa1362796

ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client call --package $COMMITTEE_PKG --module committee \
  --function init_committee \
  --args 2 "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"

COMMITTEE_ID=0xcc469719f04d95e7f78d126bf0e61fc875ef367f42430731158b5a01c55b44d2
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

c. Each party registers themselves to the Committee using their generated ECIES and signing public keys.

```bash
# party 0 registers
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_0_ECIES_PK" x"$PARTY_0_SIGNING_PK" $COMMITTEE_ID

# party 1 registers
sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_1_ECIES_PK" x"$PARTY_1_SIGNING_PK" $COMMITTEE_ID

# party 2 registers
sui client switch --address $ADDRESS_2
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_2_ECIES_PK" x"$PARTY_2_SIGNING_PK" $COMMITTEE_ID
```

3. Offchain DKG

a. Each party initializes by fetching Committee from chain. The CLI fetches the Committee candidates from chain (stored as dynamic fields), then determines your party ID based on sorted address position. Initialize in a local state file with the full node set with all parties' public keys.

```bash
# Party 0
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_0 \
  --committee-id $COMMITTEE_ID \
  --signing-sk $PARTY_0_SIGNING_SK \
  --ecies-sk $PARTY_0_ECIES_SK \
  --threshold 2

# Party 1
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_1 \
  --committee-id $COMMITTEE_ID \
  --signing-sk $PARTY_1_SIGNING_SK \
  --ecies-sk $PARTY_1_ECIES_SK \
  --threshold 2 \
  --state-dir .dkg-state-1

# Party 2
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_2 \
  --committee-id $COMMITTEE_ID \
  --signing-sk $PARTY_2_SIGNING_SK \
  --ecies-sk $PARTY_2_ECIES_SK \
  --threshold 2 \
  --state-dir .dkg-state-2
```

b. Each party creates their DKG message.

```bash
# all parties create message
cargo run --bin dkg-cli create-message
cargo run --bin dkg-cli create-message --state-dir .dkg-state-1  
cargo run --bin dkg-cli create-message --state-dir .dkg-state-2

MESSAGE_0=<MESSAGE_0>
MESSAGE_1=<MESSAGE_1>
MESSAGE_2=<MESSAGE_2>

c. Each party processes all messages. If no complaints found, finalize and output. 

```bash
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-1
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-2

# All parties' local output should all contain the key server pk and all partial pks. 
KEY_SERVER_PK=0x875ada4cb0a7b0ecf3b589412088bc280ba08b5dee837fc134ed40b657217e574093d04e56b07aced06cf2f336f2c18f18be9fe65652f13a21cef7fc5a21088197b9c774686eddeca250fdf354a63502fd8a9bada477da05f2aa29cae6ae3c7b
PARTY_0_PARTIAL_PK=0x84086404b1198649e62c3575e99e727d987e11d11b2905478441cac2fb740fa69d5da249300597d45d54574e6b4aff32111c98720974abd83268d44d35691016f371003f0f5bcc10628edc95e5df52caf58ffbb6846e4abff4ad81a533c09488
PARTY_1_PARTIAL_PK=0xb4972fe57609945bc6c03fe920cfdeea42bd26a88051449c81a2987b261d3e08c7326862e3688efa7a147bab8ad7dc4c0a773c251e620410be991b4224c2630a3ba1a5180858a02fa78a0e48f14e14966e1f227a574fa277b88391697e9be49c
PARTY_2_PARTIAL_PK=0x89392ff99800e940243afd550d91c89bb74e690ee64c94a3d77ca4eb1d8bc17483ce70e0d54aa4cbb3f2a14f7f62b0ae129c68b997c42bd93e947e4e6dae23194280a387d239525f40ccbc1f41f77fe54add85ef2f9d6d84324f398684bc11cb

# Each party's output contains their own partial secret key.
PARTY_0_SK=0x2433cc534f1a25dbc954b156e1d8fac7538acc26130e059ed5893bc8f66842df 
PARTY_1_SK=0x23424fa6a67ecf3160767018fa7b054a584b8feb6612cd394ce84b786ae44162
PARTY_2_SK=0x2250d2f9fde37886f7982edb131d0fcd5d0c53b0b91794d3c4475b27df603fe5
```

4. Finalize Onchain

a. Any party proposes committee with partial public keys and aggregated public key from DKG output. A threshold of parties also calls propose to add their approvals. 

```bash
sui client switch --address $ADDRESS_0 # repeat for ADDRESS_1, ADDRESS_2
sui client call --package $COMMITTEE_PKG --module committee \
    --function propose \
    --args $COMMITTEE_ID "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\", x\"$PARTY_2_PARTIAL_PK\"]" x"$KEY_SERVER_PK"
```

c. Any member of the committee can finalize the committee when threshold is met. This creates the key server with all partial key servers (as dynamic fields) and transfers it to the committee object.

```bash
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize_committee \
  --args $COMMITTEE_ID

# The KeyServer is created and transferred to the Committee obj
KEY_SERVER_OBJECT_ID=0x08e8fba5681c30a7f8adca5598164fae670da052010736286993efc7bb849b53
```

d. Each member can update their partial key server URL. The update_url function receives the KeyServer through the Receiving pattern.

```bash
sui client switch --address $ADDRESS_0 # repeat for ADDRESS_1, ADDRESS_2
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_partial_ks_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party0-keyserver.com"'
```

## Key Rotation

### Overview

1. Call `init_committee_for_rotation` to create new Committee object with members and threshold. 
2. All members generate ECIES and signing keys, and `register` with their ECIES and signing public keys. Now Committee in State::PreDKG. 
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
sui client call --package $COMMITTEE_PKG --module committee \
  --function init_committee_for_rotation \
  --args 3 "[\"$ADDRESS_1\", \"$ADDRESS_0\", \"$ADDRESS_3\", \"$ADDRESS_4\"]" $COMMITTEE_ID 

NEW_COMMITTEE_ID=0x708e2b34e477f8f0f48697368ace9a7b7f513075501502212618b6458b274f11
```

2. All parties register their public keys. 

```shell
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_0_ECIES_PK" x"$PARTY_0_SIGNING_PK" $NEW_COMMITTEE_ID

sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_1_ECIES_PK" x"$PARTY_1_SIGNING_PK" $NEW_COMMITTEE_ID

sui client switch --address $ADDRESS_3
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_3_ECIES_PK" x"$PARTY_3_SIGNING_PK" $NEW_COMMITTEE_ID

sui client switch --address $ADDRESS_4
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args x"$PARTY_4_ECIES_PK" x"$PARTY_4_SIGNING_PK" $NEW_COMMITTEE_ID
```

3. All members run DKG CLI `init-rotation`. The continuing members from old committee needs to pass in their `old-share` and `old-party-id`. 

```
cargo run --bin dkg-cli init-rotation \
  --party-id 0 \
  --old-party-id 1 \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_1_ECIES_SK \
  --signing-sk $PARTY_1_SIGNING_SK \
  --threshold 3 \
  --old-threshold 2 \
  --old-share $PARTY_1_SK \
  --state-dir ./rotation-state-party-0 \
  --party-mapping 0:1,1:0

cargo run --bin dkg-cli init-rotation \
  --party-id 1 \
  --old-party-id 0 \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_0_ECIES_SK \
  --signing-sk $PARTY_0_SIGNING_SK \
  --threshold 3 \
  --old-threshold 2 \
  --old-share $PARTY_0_SK \
  --state-dir ./rotation-state-party-1 \
  --party-mapping 0:1,1:0
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
  --party-mapping 0:1,1:0

cargo run --bin dkg-cli init-rotation \
  --party-id 3 \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_3_ECIES_SK \
  --signing-sk $PARTY_3_SIGNING_SK \
  --threshold 3 \
  --old-threshold 2 \
  --state-dir ./rotation-state-party-3 \
  --party-mapping 0:1,1:0
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
KEY_SERVER_PK=0x875ada4cb0a7b0ecf3b589412088bc280ba08b5dee837fc134ed40b657217e574093d04e56b07aced06cf2f336f2c18f18be9fe65652f13a21cef7fc5a21088197b9c774686eddeca250fdf354a63502fd8a9bada477da05f2aa29cae6ae3c7b
NEW_PARTY_0_PK=0x8fbd7dcfa3a83de1fe9687e4e0062f58d454163ffe5bd60b30be83316dbe7beb3d4099edf8d77bfbbf077df2efc42ab70d86581077f2656ae58f9c84e339e7de91ad48c9a689c7991232f3e69e03db1fb3fcb322d910c9b2b6282d92f3d399bc
NEW_PARTY_1_PK=0x81a9f6f5c5e8a00bd1b4efa713495a4d2496842f18886cffd39c88f3fd41b182c64515b8a1cd6036eadf5d02a2aa08d60b71ab58a70d722f4628a4a7260d0581b35f2af89dc6609686bf6006c6d3b719146b215abd9d58b9d7770aa9e2ce4f66
NEW_PARTY_2_PK=0x8d9df4759f87b002ba83912a6df3c9626513b80c3ace0d7f663d2e3a59132722cdfdeaa6396215a49f2ba96260946b750f81ad3922f62ad8b3bac2e3d99e47b5fe07fb232aff08d290b28f2e40a1cad1c60a040caf79a75d96f53f12d834e49d
NEW_PARTY_3_PK=0xa49843746f0cf27bb848f6514140a66c1d288d4a2389ebed93ec661bea3dff27ba1935af022b0c5baeaaf5ca53c2967d187a15c5ebd5a90fbca5d29ac4b43e3e5b6a536f46b271827561b7bb2ea6ac3ae1ee8f810e37c7e924baa1590b5c5971

# Each party should see their own partial secret keys individially. 
NEW_PARTY_0_SK=0x718e3b24eeeec48c4d55d1061b6ad3914d1293ed1b000f3c9eb35e9eaa9afb0c
NEW_PARTY_1_SK=0x0a6365fbfffd5117aca6b7a800adc2a15044b6573287d375df22edfd35f3bafd
NEW_PARTY_2_SK=0x4b6dbf7ea7b99a00e9d32e9295e5458453995ba8069b9ead1f78da3223f68432
NEW_PARTY_3_SK=0x4cd1f90692e8a4b79e6785b5c7cdac2faf953bd9973eb8e45fb5233f74a356a9
```

6. All member must propose all partial pks and key server pk for rotation to append their approvals. 

```shell
sui client switch --address $ADDRESS_0 # repeat for $ADDRESS_1, $ADDRESS_3, $ADDRESS_4
sui client call --package $COMMITTEE_PKG --module committee \
    --function propose_for_rotation \
    --args $COMMITTEE_ID $NEW_COMMITTEE_ID "[x\"$NEW_PARTY_0_PK\", x\"$NEW_PARTY_1_PK\", x\"$NEW_PARTY_2_PK\", x\"$NEW_PARTY_3_PK\"]"
```

8. Any member can now finalize the committee once all approvals are submitted. 

```shell 
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize_committee_for_rotation \
  --args $NEW_COMMITTEE_ID $COMMITTEE_ID $KEY_SERVER_OBJECT_ID
```

9. All members in new committee can update their corresponding partial key server's URL. 

```shell
sui client switch --address $ADDRESS_0
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_partial_ks_url @$KEY_SERVER_OBJECT_ID @$NEW_COMMITTEE_ID '"https://rotation0-keyserver.com"'
```