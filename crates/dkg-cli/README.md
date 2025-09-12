# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols.

## Workflow

### 1. Generate Keys

Each party generates their ECIES and signing keypairs.

```bash
cargo run --bin dkg-cli generate-keys
```

This outputs:
- ECIES Public Key: For onchain registration
- Signing Public Key: For message verification
- ECIES Private Key: Keep SECRET, needed for DKG
- Signing Private Key: Keep SECRET, for signing messages

### 2. Onchain Registration

```bash
# test data
SEAL_PKG=0xe4d97606e5859354469c5d26dfb1fcef5815b74f5dca57534c1172ffd4a03181
COMMITTEE_PKG=0xa9ee17f93525cead984698c7dd420b2eaa6ce507333e9a040bdaecb995437407

ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6

PARTY_0_ECIES_PK=0x886d98eddd9f4e66e69f620dff66b6ed3c21f3cf5bde3b42d1e18159ad2e7b59ed5eb994b2bdcc491d29a1c5d4d492fc0c549c8d20838c6adaa82945a60908f3a481c78273eadbc51d94906238d6fe2f16494559556b074e7bb6f36807f8462c
PARTY_0_SIGNING_PK=0x8b7ec45bd1c601bb969a9653835f273fab4192a9bccc4f3f662d72a5bbf3a8e9f6837a35175eb656488ea72ce3c3cddc14a86c0f8fa319cf82a5641ed75d7fd7613510d28fb2dc6ef39309f86f0da521985cffa23263b993ade6443be6662397

PARTY_0_ECIES_SK=0x1118442222387aba62557b99478b34e7ea431e9b03b7e54464c8e482651c7861
PARTY_0_SIGNING_SK=0x1d5b4ea73bb2d3de4a90f55d9074d2bc9e59b2eb5be0bda994bbbf385d83e3b6

PARTY_1_ECIES_PK=0xab5603f3cfaef06c0994f289bf8f1519222edd6ed48b49d9ebb975312dfbcd513dca31c83f6d1d1f45188f373aff95ae06f81dfd2cfafd69f679ce22d311ad4d34725277b369ece21f98e8f3ac257a589c0075d7533487862170760c69aedf4e
PARTY_1_SIGNING_PK=0x88683e75cda13f18d1992491abc6de10aa85b400fd59dd5529e0bc35082656482910364e2c1ae39ebc401a2aed7d502d0fabced6e78f3009edc21f39400a4efe20d35ee3e066777e7d3618a333c9d73db5d6421ac33985a98d1379bfdb010d45

PARTY_1_ECIES_SK=0x70e711dea2ce46ca3e3f8cecbb4c9db0c938db5c1dc977bd37d9bd5b845debef
PARTY_1_SIGNING_SK=0x017942aa1ea9c2684de8ba6a95b3ee47306ada75a443e1023fc0efdeada447fa
```

a. Create a Committee with threshold and members (anyone can call this). This outputs the committee object ID.

```bash
# Create the Committee with threshold 2 and members
ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
sui client call --package $COMMITTEE_PKG --module committee \
  --function init_committee \
  --args 2 "[\"$ADDRESS_0\", \"$ADDRESS_1\"]"

COMMITTEE_ID=0x52a66d0da05d79054ce764ee414b6d8c53e14e6474f2083db9fe5f76d2a4388b
```

b. Each party registers themselves to the Committee using their generated ECIES and signing public keys.

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
```

### 3. Offchain DKG

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
```

b. Each party creates their DKG message.

```bash
# Party 0:
cargo run --bin dkg-cli create-message
MESSAGE_0=qAUAAAKJuvjHBpr53oY1ODTG/3AJKjtmK3KQllibzhWlqcgoFN/pcWFGjwDCpHUc4WRAjegNkg0v2+66i4Hy0fP9dEBksUguD4kwOeryq+bY5n0rHn3VGrQO9WqEDSaRGHthZO+ZB6hg6tsR+PL8mbSi1FJZ2/lP1MlAxHgC648jgmoZB5fschmghqsues4HLavPcB0XPldTsNAgZz4rQOSIOy6dbVlI4XJ+fGRFgLFhYarz3uJpH/IRZMCmP2v8aWm3wAiqUHxzDGbg69KA9UGyosQxdrBuAL1g2JwFlDvEGPxyHcOuPEzETbNXuUSHlGhjOPQM/f9bqfH7wZ3zxvexQxjS13M/64uTxkThHGCbmRJhW1iXHB2gVj4bww3PWJDhO4GyoosidTs5gANExICT9VJKKR/JHcvgT9BG/+NcJtGWO2SQvx6hc/sgY3UEUJnmUWETn6OU83e268l8dZqXKc4Zk7miOafVwV+NK4Fyb4rDD8TZMQpoFaBRxMuoGpvYCoICIRVsIbm5AYIgNnm7xb9ZgLysgy95Yibp0vcN8M8NVai4ziE1pgUbm9yIa4nu3SwMort55j4HXauvkP7V2+sm2jnPwyqw6fstIFKUep/2Sn98dXdSar/FB0M1KWHZaCE2ENSpyWvRzrd7xzHgCctKLlaWYYQAwuoyMs9dJUbkTyZfxm6oFRj1GjE8O9/otnZq82HSGVlnsD+Q9nZ+fTFtKFwVQ+GCnCbbRX+1PfXFgObXsdrjZcTuoyRXepWYCzNL57Ia1YXYnzrb0YEg6d1B+BaLlzcPfoMn3gvrgnksJy7vdQ0QHGo0gINqgG+2QpHnAwD4xI4GKvvbvZ5A5NLXcEaCY2QMmkNmI2oV9F/FwJbQRqS67qUqid9WSZjprCmeP4H/x2CS+6LN5fvTp4HNLxdfSoybRZ9Z05yYAgo3b06WGZitwzI10Gpse9sTFQjYqF/xu5sWE6IbcsSwlyzjudaj2FZzplf2fVpNtanBD89uywv7tPnT2CIhOQfjLxtqLKNHXPWLfsRb0cYBu5aallODXyc/q0GSqbzMTz9mLXKlu/Oo6faDejUXXrZWSI6nLOPDzdwUqGwPj6MZz4KlZB7XXX/XYTUQ0o+y3G7zkwn4bw2lIZhc/6IyY7mTreZEO+ZmI5c=

# Party 1:
cargo run --bin dkg-cli create-message --state-dir .dkg-state-1  

MESSAGE_1=qAUBAAKL9jZ1Fd9uKl4SIDnJmauYwSVCyXhIg6tNRiEcFtfF0tCLPjbAIdKuDcB7yCZTDx8MRK4h3mjyNopwlH+C/EcOC2wZoCor/yjVvr+OiahxXgLmQw6gJi00wfO6oJE/Tdm2lfoDyQst/Vj7LVWRhqj6f8pwMAtiHeW69jN0+WqH+2uxV4AjNALlvWNcjgbj4qEOLnkyf289RKujOS6elqy8PahIATEkuVJ90jp39/25FQqp8I7HO/0Euvf6vK72+Za4rljzbsi7Oj3L8A2qNy994FF2wfxNihGavatK4gpOuyZwDJkdhLm5OoaeRDbVgQAOuV69m85at/ciUaWvfMxdgghP4aKXChcm3Di1nZ+2rN61aKZLyw9Bs65tXkSAmIiWWQASuu/tKOxTo0gfR05VFxif7CVZ3yTzO7hz2x7/8XWyNaYhkTGK0YN0XFzEOVIIu0A+rG2NlLTGevmqWn5jUUh5UeVyT+PWdKokJfM5ZO8q1JvtN0KFHEkc08kOo1QCIfSREEtwkiI8wd8Qnn2TKIdUitJEFvgEf8nIC+5LrGwlDiEtir30kfcmURshr8NDk8vl4XJDTIGOKUfiX+ZWGX5VCvOEeJ46butVVs6jMqYQ9lONRyNzlGDJDYg9M0OrLlTSrGBeOBQx9AdEMips8gwSNakAiohHPH+UU5rE8pRPfFc3ITRI20/+sXT2ugjIG/qTT0ThgYYwRbexoSpX9iGU8QmsKGd36cUdHS75Alxh1fy6J4AAmLmckXDmE/+XQMufJBDtHQRzakoCL/1FyvGC03sK6hQiBWHAI3yb65XxxK35XfACBF1S6SuEP6Sp/7AlNTWYzFWaA/A/y3p7F0Ujiu1FekebwF05uwkZwGW+LI3LbBAyYTGpf/13CP0L7DKZ1mCytwCIs6vNttpo7AHFfhCKYyYyLR8ZcEgVhtMxn0D3qXYVosX6zCAZxKw/uFvt9HIXpPcCVY+vqieKheg4RT6I8J4+gOUIip0hi92RrpmwfpzvcMfmB8+nyhFjbCz70xCIaD51zaE/GNGZJJGrxt4QqoW0AP1Z3VUp4Lw1CCZWSCkQNk4sGuOevEAaKu19UC0Pq87W548wCe3CHzlACk7+INNe4+Bmd359NhijM8nXPbXWQhrDOYWpjRN5v9sBDUU=
```

c. Each party processes ALL n messages (including their own). If no complaints found, finalize and output. 

```bash
# Party 0
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1

# Party 1
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1 --state-dir .dkg-state-1

# Outputs from DKG:
KEY_SERVER_PK=0x87878d91624465268254e979d94b5eba904d5a1c5383c77d06d1b01fe3d895241d8bf289ac1d1ff707fdf94f3eac1324036c5399d3cabebb78481ed2692c12af0d492a3c620c94c37e6d642f26fc8def63429f5a3b4630e785931a985ca1371f
PARTY_0_PARTIAL_PK=0x8d9606ca8ac90128d4305668714d3f3dd228bff87d4f3a86d6d3b936351d40ce5b13a6c24ee23f10e979bbc2b6bef39d129926c098d5e1f20508b8ed9c152181308f3f67e24a05f0ab2398930a44ee34a2b69ea2bdad58f475b7e686d77807e4
PARTY_1_PARTIAL_PK=0x8708809f876db8dc7672f13c0a15f7ea268d0a6cfdba5588381e1350be147d53e09254e8d52ded099cbf48eb4c99bacf18be580f523647bca12c5c228b9d34bda9cb85080fc42c3ab3242af9f3ebcc93f09424b99395ab0a26fd9a3c292d6c13

# Master keys for key servers (keep SECRET)
PARTY_0_SK=0x14aad9ceaaff36716f83e46373d5596ff45efb132bc0e539c93d3ceb0da9f417 
PARTY_1_SK=0x1cb443d59c0c10cf5439a596189c2b6eb83225b38406f462ebd663ad74f4a38f
```

### 4. Finalize Onchain

a. Any party proposes committee with partial public keys and aggregated public key from DKG output.

```bash
sui client call --package $COMMITTEE_PKG --module committee \
    --function propose_committee \
    --args $COMMITTEE_ID "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\"]" x"$KEY_SERVER_PK"
```

b. All members approve the committee after checking the onchain partial public keys match their local ones after DKG finalization.

```bash
# Party 0
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function approve_committee \
  --args $COMMITTEE_ID

# Party 1
sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function approve_committee \
  --args $COMMITTEE_ID
```

c. Any member of the committee can finalize the committee when threshold is met. This creates the key server with all partial key servers (as dynamic fields) and transfers it to the committee object.

```bash
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize_committee \
  --args $COMMITTEE_ID

# The KeyServer is created and transferred to the Committee address
KEY_SERVER_OBJECT_ID=0xa847371f5aed503ee6dc0fce0b7651175fe80512f84a269238a79ca4a256be5e
```

d. Each member can update their partial key server URL. The update_url function receives the KeyServer through the Receiving pattern.

```bash
# First, need to get the receiving ticket for the KeyServer
# This is typically done in a programmable transaction

# Party 0:
sui client switch --address $ADDRESS_0
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party0-keyserver.com"'

# Party 1:
sui client switch --address $ADDRESS_1
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party1-keyserver.com"'
```

## Key Rotation

TODO