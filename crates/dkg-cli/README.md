@ -0,0 +1,214 @@
# DKG CLI Tool

Command-line tool for Distributed Key Generation (DKG) and key rotation protocols.

## Workflow

### 1. Generate Keys

a. Each party generates their ECIES and signing keypairs.

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
SEAL_PKG=0x7d3ef4f7d3a71728cafc71c22b1c2a7e9836d095070d7c0ecdab1f63acc58f20
COMMITTEE_PKG=0x3a1ceb5fea16fdcd393e1bbe894504bcd8a5fb386388801155cb4847086ee613

PARTY_0_ECIES_PK=0x886d98eddd9f4e66e69f620dff66b6ed3c21f3cf5bde3b42d1e18159ad2e7b59ed5eb994b2bdcc491d29a1c5d4d492fc0c549c8d20838c6adaa82945a60908f3a481c78273eadbc51d94906238d6fe2f16494559556b074e7bb6f36807f8462c
PARTY_0_SIGNING_PK=0x8b7ec45bd1c601bb969a9653835f273fab4192a9bccc4f3f662d72a5bbf3a8e9f6837a35175eb656488ea72ce3c3cddc14a86c0f8fa319cf82a5641ed75d7fd7613510d28fb2dc6ef39309f86f0da521985cffa23263b993ade6443be6662397

PARTY_0_ECIES_SK=0x1118442222387aba62557b99478b34e7ea431e9b03b7e54464c8e482651c7861
PARTY_0_SIGNING_SK=0x1d5b4ea73bb2d3de4a90f55d9074d2bc9e59b2eb5be0bda994bbbf385d83e3b6

PARTY_1_ECIES_PK=0xab5603f3cfaef06c0994f289bf8f1519222edd6ed48b49d9ebb975312dfbcd513dca31c83f6d1d1f45188f373aff95ae06f81dfd2cfafd69f679ce22d311ad4d34725277b369ece21f98e8f3ac257a589c0075d7533487862170760c69aedf4e
PARTY_1_SIGNING_PK=0x88683e75cda13f18d1992491abc6de10aa85b400fd59dd5529e0bc35082656482910364e2c1ae39ebc401a2aed7d502d0fabced6e78f3009edc21f39400a4efe20d35ee3e066777e7d3618a333c9d73db5d6421ac33985a98d1379bfdb010d45

PARTY_1_ECIES_SK=0x70e711dea2ce46ca3e3f8cecbb4c9db0c938db5c1dc977bd37d9bd5b845debef
PARTY_1_SIGNING_SK=0x017942aa1ea9c2684de8ba6a95b3ee47306ada75a443e1023fc0efdeada447fa
```

a. Create an InitCommittee (anyone can call this). This outputs the init committee object ID.

```bash
# Create the InitCommittee with threshold
sui client call --package $COMMITTEE_PKG --module committee \
  --function new_init_committee \
  --args 2

INIT_COMMITTEE_ID=0x7a8ffc78b424eab48639d45156384d75e4bb0d6304b884801e86616aff32fa86
```

b. Each party registers themselves to the InitCommittee using their generated ECIES public key.

```bash
ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6

# party 0 registers
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $PARTY_0_ECIES_PK $PARTY_0_SIGNING_PK $INIT_COMMITTEE_ID

# party 1 registers
sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function register \
  --args $PARTY_1_ECIES_PK $PARTY_1_SIGNING_PK $INIT_COMMITTEE_ID
```

### 3. Offchain DKG

a. Each party initializes by fetching InitCommittee from chain. The CLI fetches the InitCommittee candidates from chain, then determines your party ID based on sorted address position. Initialize in a local state file with the full node set with all parties' public keys.

```bash
# Party 0
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_0 \
  --committee-id $INIT_COMMITTEE_ID \
  --signing-sk $PARTY_0_SIGNING_SK \
  --ecies-sk $PARTY_0_ECIES_SK \
  --threshold 2

# Party 1
cargo run --bin dkg-cli init \
  --my-address $ADDRESS_1 \
  --committee-id $INIT_COMMITTEE_ID \
  --signing-sk $PARTY_1_SIGNING_SK \
  --ecies-sk $PARTY_1_ECIES_SK \
  --threshold 2 \
  --state-dir .dkg-state-1
```

b. Each party creates their DKG message.

```bash
# Party 0:
cargo run --bin dkg-cli create-message
MESSAGE_0=qAUAAAKo8EPkzgvNt1obrToD6xqsO+fohHAaPC9tvbSmoQgfU9IIULZ/ztjYh4qqOsfXdakJm9rkaxyJrsl3Y4weLFXM3LWZv31zC1pl8l4xG3We4nJHdPAAhnkTfG+8/wtLORKht0eba4V4RbcZwvO1GY/fp75xkaSa1Oa7SqCQ5m02CXV2Po6pTuYuTu/jPoTZ+TgC3VsN/VoHZFwtIf7qEe8rHyLO2NUn18aFaEntjhTArZFSzXgZJbCwiAqdSrmqC86lKTJLkOAXBd0yajGH8fyuVowb9VmClgaOpGlLvI7KKl8pYSh7gHUyzaAnHY1MaG8RyPLdGarr/aw0lh0dMmQnqqwAzmuSvPzIzekL0UCVVB7LdO98J0wGUQJZ3ErS3DWoohpSlPPTnCqH8bBjZshz0aUJjraGl+V9zqk+bexbwxR8pJv4YJm1D6E0RKb8sOsWa5lPgoiqCa6hL85bD9PFbQLwzxXFlyUWV6eToqUmep9jBlVC5FgwbzjLXMoI89gCIboGbIfOnqSDKh2GZf4Tn3+xcFqevY6ELNoR0BdKOHK2hCGw7AjUDdSVyqnt3uhsF1Nn9CDoQYrCa85UXnj+k6dlJZ6wANk5IKPyaiozoPkTuYbjNed+btSecf+XHvYDR5NzwaNW9Vk5reoEHsjexcDQyP4FdEIO2jBtnl8Xj+Vsm83FHnRPuKdTSx2m9nzuhJNh3ypS5vPt/7CkkvYltSL8jMSJvHxJrq50q1q4HFPzpxs7T70ljnQMMTfHXfthlJcqBhjOD5uOMWKyHwoh1wZXHfsORLKUwFZoqwux13npDvsH9v3eNAiq0HYkJsHjyiHy6f4BOZVJR2bohKPWY1Vv5f1QDt3dcWt8Y3FVwsRn6lhLL5SDFWlkUsvGCeroEp+O/WCVJeZAMsOks5uAnDqXfORLXpywsDKZsVbCKLZjQ0e+SQaq0kSQpA6K9eLAIqbcKaQQ6VL8dPOWOUfnB5nBEqngJn/oStjePLpYMssnAtb8/Lr79dJqZDCnOH0jJRVTmviLfsRb0cYBu5aallODXyc/q0GSqbzMTz9mLXKlu/Oo6faDejUXXrZWSI6nLOPDzdwUqGwPj6MZz4KlZB7XXX/XYTUQ0o+y3G7zkwn4bw2lIZhc/6IyY7mTreZEO+ZmI5c=

# Party 1:
cargo run --bin dkg-cli create-message --state-dir .dkg-state-1  

MESSAGE_1=qAUBAAKg4dqcW0lB7fbfHQVoDT9FNVKOF1yt8MAFTTVkaBDy+/iHv9AXRZaYuCJmU01SLDIDK/f+G0VYRXBWCfFeHUPr9GDUy1tuGkY/0syBRjMOMdItxkoVCC31JVeRb5zJWiCr2qzq+7goEh02JYZ9BBq0LOfey1pFaTOceirQi4XfFVbhHlcTjLsb5SG4yuDnYa4CMqfkmERFwKkFwcV7F2c/CuDfyRnCuDlviVUUNTsFL8BE4OZdX1Tr4XM1Z/TH6m6Akr7Mwr9ud656oQwhUVNbOjDs+g185MH+zMivHv3ostMV/vU6NoFgZicKpWX/onsQvbrRYdIY5vN43FjSvdsSGYJUbLw83By7oms4Noi/QtoFrRF4kMAh69OPA2afqLeYOjEhMSgnhkcPl69IpaQBuuTl3m59EPMXzFibgzTM2Vd2fsVfpX48e264pHdJO40PFZ1XRYk5gHOL2bU9hujxouHz6auyrx1VGvU3e3p8Lr9pmMIPXHGcxI8zCR1aZhICITp6gcsJ9/lOT3BIiy0b8lg/77g+Kww3MWorzGJVU6Qo6yHoy+cZ8whrPOrUXuEj1pSWSPvZupDutJ8K0eXZXivksEKBa8CeLvTrF1NHxPSLFL2dyuLo5OYRdhMuxy+Z+uTMuPP+czRTa9tJo7xjrreQ1EcVg7PmnwzuUrMrAVZrycFgnDuTaMmRSwgDI4Q6dusmS9tRf2Ne2n91X2liiJECa1GmRjMGtcco4Sgv0qX0OaHcftSjMequ6IogqaxPI46O1LITn12xjsjF4puPpncBTngBQ49q+3H9rmHJnDwPlvLGZOofWHz0kESPNmZrSVXBiCO3Ee8MPgnUmoq/tzyXrsFJHE10m7U6Rfdu7dc3144GOzo27xISuG+HY9quAJvA/mCiiYVoLOGVGoQk1lH6nJh310dDhVEM/VY4bKUgGDjGCIq0MujqARwToX2SS8+qnCkLQr2QBZGxtCsY7wLnJjMYsbq/TKSVg5ppmhG4Q6vwUyZXSK8Z3+vWrWtu07660ziIaD51zaE/GNGZJJGrxt4QqoW0AP1Z3VUp4Lw1CCZWSCkQNk4sGuOevEAaKu19UC0Pq87W548wCe3CHzlACk7+INNe4+Bmd359NhijM8nXPbXWQhrDOYWpjRN5v9sBDUU=
```

c. Each party processes ALL n messages (including their own). If no complaints found, finalize and output. 

```bash
# Party 0
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1

# Party 1
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1 --state-dir .dkg-state-1

PARTY_0_PARTIAL_PK=0xb830919bc7923f85bc598059a4b519ed1dee1ad0c3b6b2e60760c866e07e0185a0e5f85694523107318c7668c04f79a917390e1f7caf35abb4dacc18af6073696dcbcd2d95f68054df092fb29fab55290acb098a883069d2dbc6338ddc318c58
PARTY_1_PARTIAL_PK=0x8d063d92aa957bada57eb4c4138eb3c92ed6c0f2cbc7f124080f898dc7d294950c19fb24879b3c2c49401023673c31f40a2deb80a289e97a81d724f9080164a7fad81925bc823038e256a9aefe94b051b185ec1e1bf76c470015bbbb4772d2b9

# master key for key server
PARTY_0_SK=0x6b5caf683122e6b8a44452cc72240b162964ec02345c3e70277caa8e1f397edf 
PARTY_1_SK=0x3b79374c278a3edc54a1c218beaa19f654ff778b478aaac51167755b954403ef
```

### 4. Finalize Onchain

a. Any party proposes committee with members and their partial public keys from DKG output.

```bash
sui client call --package $COMMITTEE_PKG --module committee \
    --function propose_committee \
    --args $INIT_COMMITTEE_ID "[\"$ADDRESS_0\", \"$ADDRESS_1\"]" "[x\"$PARTY_0_PARTIAL_PK\", x\"$PARTY_1_PARTIAL_PK\"]"

COMMITTEE_ID=0x7516ea415cd2a8c6c5fdd4cc17fc86ce5b6cfb66640a0aaaf9eb78d2884e0c55
```

b. All members approve the committee after checking the onchain partial public keys match their locally  ones after DKG finalization.

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

c. Any member of the committee can finalize the committee when threshold is met. This creates the key server with all partial key servers and transfers it to the committee object.

```bash
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize_committee \
  --args $COMMITTEE_ID

# The KeyServer is created and transferred to the Committee address
KEY_SERVER_OBJECT_ID=0x31705a8e4ccbb0959d71781f02b518616062647f415b38f4c6be70572001d8fd
```

d. Each member can update their partial key server URL.

```bash
# Party 0:
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function update_url \
  --args $KEY_SERVER_OBJECT_ID $COMMITTEE_ID '"https://party0-keyserver.com"'

# Party 1:
sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function update_url \
  --args $KEY_SERVER_OBJECT_ID $COMMITTEE_ID '"https://party1-keyserver.com"'
```

## Key Rotation

TODO