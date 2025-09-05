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
SEAL_PKG=0x91578a5678dc957a522fec5beeda6819218804678d9229dd3a7b9c9bf2bbd855
COMMITTEE_PKG=0xeefcf21e0ac2673186037c75010f019158953465aec65bfa226da38fb8284f99

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

INIT_COMMITTEE_ID=0x80c620ae220eb0b0b5d3e3a63350fd0f1208560c40579dc7a886c3150a8041df
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
MESSAGE_0=qAUAAAKvynvdFpj2fQIVwilNaOmyx2fq1sddeRShuiUnjEzGwQMeO2y7P+Wvx1HHUIsMjTEP9nJ4KWCL3EvUhtzILco5nCw8iG6lmUHkuEiavhpkOQYIXHUETdeL0Wh3Y4VDFKehjSzbFq5ENjJU0CAb7urTIqjhaKBkwAbXCfDbb0ei0v+6m+maUpWG8nZ5jfu7zEQYlFMD8JBtsLajfxBGTt91JlDXyYvgMv5qvN8DMBb7RbfUucZa2BPGnzYo9b9zbDuC0eFA6mNFzyrInI3x1bpnUwVamdEQuXgTZcnLOmQUHZvlqtsl+G1xWdoZJxQ0Z5oH5AJArlRQH4Kqn9xllxUS9CdyU0EqIk/MDPxffIg/xoMzwnG+eVNdwEcsobg97a6rYgh6VKesz7QWWDpC9PmpmPcdy7RItUFfuVRX5Dn9BOagb+VSRJH88voP8fL4ZYgGMVWjOquId1Lh8+dQvMpHw+vyCrHlBAEBu5/9SdCiB/UjU+S7co4pjLBuIFh/Iw8CIQ9nAPBGjMrGBcmR+0CsA69RQY8WVMkGRyC/FmCoGwaeASFj9A67jR7PNnWG9r/mFMgA2qO3fpRqfHbggTmnd7j0MduNYiyJTzxg+h6Ub/DS1W3P6bF+O4NApA3xAf8KfjORglUVIRURZhAHbjTPLgf1E7sE7w5rZaqhTHObyMZE8wVhhuHkLRiZwU97caSY+yqQbREMYGk5GQg1VsoisD1F34+INIETB1U5zwitntHtYbPIMsGjCNi+iiYhWnca+B7dPUy+SOFk/AmT0H8RyZ549LAWXz1/EVVQ4vKw+Co6syKBwMa/cqP2UMsJ8HU57A69RueyJm0fd61n+QsqZsmEAIUvpKAMMWO8rIgwCWsnoHnc9174JNk22NyAywzx77oxV2Cp53csPz5yZQSdPPvPiYwHF7TfQwnyksCpc66AK01TotpcfSHIiezZDoFRk8w8cmQVoxqAVYz4t3WejFLXvj2zPxoelvG08WR4NtQobbNIw+H4+Nb6UaX2+0XrXw9C5d6LfsRb0cYBu5aallODXyc/q0GSqbzMTz9mLXKlu/Oo6faDejUXXrZWSI6nLOPDzdwUqGwPj6MZz4KlZB7XXX/XYTUQ0o+y3G7zkwn4bw2lIZhc/6IyY7mTreZEO+ZmI5c=

# Party 1:
cargo run --bin dkg-cli create-message --state-dir .dkg-state-1  

MESSAGE_1=qAUBAAKkFZ68+wXyCSplSZdz6KTaayjyqSKuiHELdUDpXJdm/C7QHgFDeTADMeWiFJ6DAwME+ZJqNbnJguiic+1w7dUIQVLqb5vH8UqqEwFXK15DhxgFxzjw9ebCU2FVz06HPA2N1pXGaNDX3fnQj359VXI7vySfszlcZPdf0Pd7Wt+xjrdPkVAhi8yjIElybeqy+8ENtB8KLX8LKP+cEEBTNsbtpuhL/XLwKBwEjmxyDUEOD8XMbjWuoXgBN966xThPJ9eseeReLcN/bWGzrMb1mexnSiPDv+hbjkrNM3hejj+yp/bqVC77RrT88ejVU77YeCsPq4tll6eBIGD0GT8FAgVoIQ0LAqpVlN/+3b2yGzqvXy6MryzYTtOwWVEsyBlgmjKRYuOa5tgAVf3oygYJsUVYKqXOVf98dXakw0r5LwI3z18agf0Wr3MEK7L16WV0LuQJJ+GblNZq+3apIXSVBI9D3/7HL4KMW+FJBmIueEORuA4JS/WoE613y6wElX3hSL4CIdy/Ie2rEiluUvGSwHDB6RFr7nMs81O2hVKqhNpTJl4EaSG0GyIuvwdQOOz0EKJK7UEzLIUHwTRBmcAGWG8moC1S2xWT4eIMlVMFG0JRH1NGi10+kcv4f/601DEiIZeGTGH4c4iOXhaoOx0hQKuUczHyqIoFFagPgpaV+tmQMUrARMxhSu4vBIgM5WuIr1g5yPsQyjJNL2xsi/7cWWtc01rYMiGnSpQrX10bo+GFdKqQzG0w6WOXqLlfb8PyF6EzgQqRc9I6fYuEEtjHCatq9TI1nH8Qm7qSD7t56XTzirPTkyZvvcmr3CWunYYMtI2eWycwR+EXBYciqyEY3Y4G3nn0jFYJNqKLuVFhPf22wxsHAssI3KHFGQji5OoYPbdDRXNwCGCowXzcp1lJ5Dz+nxpwuDhqw+eKOOcqYsvoAs6P9qVpuHF5Yer58Oi1b88gUZAZH3QU4EKefApoouJUroJSsgOmfNIXfsJqlVVCyLNZRy+3viSvkHIkktuS23UpJKzxyfCIaD51zaE/GNGZJJGrxt4QqoW0AP1Z3VUp4Lw1CCZWSCkQNk4sGuOevEAaKu19UC0Pq87W548wCe3CHzlACk7+INNe4+Bmd359NhijM8nXPbXWQhrDOYWpjRN5v9sBDUU=
```

c. Each party processes ALL n messages (including their own).

```bash
# Party 0
cargo run --bin dkg-cli process-message --messages $MESSAGE_0,$MESSAGE_1

# Party 1
cargo run --bin dkg-cli process-message --messages $MESSAGE_0,$MESSAGE_1 --state-dir .dkg-state-1
```

d. Each party completes DKG.

```bash
# Party 0:
cargo run --bin dkg-cli finalize

# Party 1:
cargo run --bin dkg-cli finalize --state-dir .dkg-state-1

VSS_PK=0xac4632cbde86fd0e6be06e5d999d63d667d903462cc013b75452e058c7e0c6fc49ac2b30a9f70b562e75600480efa9cb0d7720f2b2b68bb4f86b13fd008fd412a0fc2f643429b7b8b61359915f1bea40832285637023faf4732ddcaa784cc483
PARTY_0_PARTIAL_PK=0x87db3a229bd534eaa0cd10e886b72be596e60f4ea686336cd216ed0291a0422aa307e8c39158c7f5dd1254338fb90f730545d0a5ebe7661e1ca426b6b933f126b3aaf21ad1e806e54dafe617ada79e19360ecc52de4ff039102921527280bd34
PARTY_0_SK=0x63ab01f2825e06959c26eb2771417849ace9d1015ea4166e2761250ca4815aef
PARTY_1_PARTIAL_PK=0xb2249064fb7c4686b08530717114b8f2a3b818424f61a00d08b3d54636ae60b7cbf418c36e1e06d5934ac8e4f06a834e046fea83733fc11064455c67fd9f36abdf83acc705704b5a40609c080af57a00c24fa5dbae8b7386ad970fb66bf561a9
PARTY_1_SK=0x082c6f169cee83d073847893fc9e0199abe655c1dc5be7e256a4d903bf0be5b0
```

### 4. Finalize Onchain

a. Any party proposes committee with DKG output (VSS public key). 
# all parties pk are known. 

```bash
sui client call --package $COMMITTEE_PKG --module committee \
  --function propose_committee \
  --args $INIT_COMMITTEE_ID $VSS_PK 
  #todo: all the public keys

COMMITTEE_ID=0xaaf6f7b9665e7b5e3081cd61a064fee1808f1ca94180404d97df94b94bdb4fec
```

b. All members approves the committee after checking vss_pk is the same as the locally derived one. 

```bash
# Party 0
sui client switch --address $ADDRESS_0
sui client call --package $COMMITTEE_PKG --module committee \
  --function approve_committee \
  --args $COMMITTEE_ID $VSS_PK

# Party 1
sui client switch --address $ADDRESS_1
sui client call --package $COMMITTEE_PKG --module committee \
  --function approve_committee \
  --args $COMMITTEE_ID $VSS_PK
```

c. Any party finalizes the committee when threshold is met, that creates and transfer the key server to the committee object. 

```bash
sui client call --package $COMMITTEE_PKG --module committee \
  --function finalize_committee \
  --args $COMMITTEE_ID
including all partial key server
KEY_SERVER_OBJECT_ID=0x11f6352a2c5915b747643b36a52f5500d5fd59709e6934151d968aba4813e3c4
```

each party can update the url with cap
d. Each party creates their partial key server through the committee (since KeyServer is owned by Committee via TTO). Use PTB to handle the returned object.

```bash
# Party 0:
sui client switch --address $ADDRESS_0
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::create_partial_key_server @$COMMITTEE_ID @$KEY_SERVER_OBJECT_ID 0 "$PARTY_0_PARTIAL_PK" '"https://party0-keyserver.com"' \
  --transfer-objects "[0]" @$ADDRESS_0

# Party 1:
sui client switch --address $ADDRESS_1
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::create_partial_key_server @$COMMITTEE_ID @$KEY_SERVER_OBJECT_ID 1 x"$PARTY_1_PARTIAL_PK" '"https://party1-keyserver.com"' \
  --transfer-objects "[0]" @$ADDRESS_1
```

## Key Rotation

TODO