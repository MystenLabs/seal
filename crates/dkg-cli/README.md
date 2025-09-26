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
SEAL_PKG=0xac4d9fb8dd1244b22dd7a848c3478495a8909d18fe807f588e18a61763b7a086
COMMITTEE_PKG=0x968b2c500c619753a0aaa6ae89d3b9ff25866d27bbeb91d1f911e5d6c4161c61

ADDRESS_0=0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d
ADDRESS_1=0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6
ADDRESS_2=0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9

sui client call --package $COMMITTEE_PKG --module committee \
  --function init_committee \
  --args 2 "[\"$ADDRESS_0\", \"$ADDRESS_1\", \"$ADDRESS_2\"]"
```

b. The committee members can now generate their ECIES and signing keypairs using CLI. 

```bash
cargo run --bin dkg-cli generate-keys
```

This outputs:
- ECIES Public Key: For onchain registration
- Signing Public Key: For message verification
- ECIES Private Key: Keep SECRET, needed for DKG
- Signing Private Key: Keep SECRET, for signing messages

c. Each party registers themselves to the Committee using their generated ECIES and signing public keys.

```bash
COMMITTEE_ID=0xe1680e2b750562a5b1bbbc1461bdb2beddd6620d1f56853a2b51065add1dec9b

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

MESSAGE_0=ygUAAAK454b99/W8G7QzHEVYyVZaJpHO6+17V0687eLfc8Y1JiYLWMJkQsi2rGuVob3aLDkV41cLgkh6jUsFZxY3afZT/hBZOBBgVsYqsCui8fQKtKOmHPCMTW2Y6e4cJyJiAvCqbfc1lNlbmkma8UbFKo14k5iE3p8pDvmWQHhMaberQPFoEzYzwk2qN+klsiAN0QgB2UN2risU9s+p6udJJ8nCFfWres0IkTOLKO+GLx/Kc1yEPSrlZqQT/G78twgwuA+RWKjrviN0s/5Ab81mYte9y7V34hIiT9gQ0kILO/UkVNuYiEcT1i+sOuxx/Js5zlAWP2sIvVPitK4uPGAJPn//t60D5dv2cQ1qcz4K9yj63VJgr9TuWj6vE7nKcU378tKTUuKpVItP+5LhBeUbo2BNfw1RFlHxF+7ikmHglpDn7BxAmK7DydOW6ctmkQIurYEN96ywQUv0yCMiTtbTWxT3Ksk3jm7Cr1eA5ZlTX/akWlWa9nNLZTC9fDkt5niBAQUDIdYVpNNJ8pqG7ahj8B46fFLaOKdWJqd2fInyg8yunq/E9yH5Dc2oGYmukNONdUiNreT0lIxv/R/fqk8kpXfKOYS6UMEhAKjuGPyxYgtgJRDSDJkZ5WoH5QyOJA/Ei67mncv9SyeFrJYFh3al1+c14B6jzZFYgp9+RD95DmlAV7ApC/mYcim9sqW6iR80z4SFDHo6jqvYAuHi+mqEZRNIyqMGUEX+LuZOEjAM73c3vcKpUySTrzZJ6xgImTcy3fJa9y4MeXB2hl/b4FPxICLRXdB0LNA1NYcG7qe2Cuk0KOyNwr+banAl8MedRhr9uO3RHY5aajO9B3V8dPse6os+vkQE9fpoH0sBjmY4SzWtGgkJwPqySQyqSIRfItIWIn8NuSqEPVjebYYL2bxolGBkWzZK0DasYdzygkI+jNsNum3K5hcIO+NgiHDPHMD6HQjj7ANU3j9YWxQD/ay5XcVZZUUxe8Mj91SgBaziMlYMQWhUAFO0BhVuAnEzuFtl4jDKkPjXP1AdfAXvbuTbZAbsFytPzXQwXWzkEsqXg+El9HczOO7UYb1ki37EW9HGAbuWmpZTg18nP6tBkqm8zE8/Zi1ypbvzqOn2g3o1F162VkiOpyzjw83cFKhsD4+jGc+CpWQe111/12E1ENKPstxu85MJ+G8NpSGYXP+iMmO5k63mRDvmZiOX
MESSAGE_1=ygUBAAKO9YivmgxrwtfU3GtNboTbTxS0hqgkTea+wXMx63fN7P4uAtkQjHElR+lkpmk+ruEMqAN/sy6HovOJkT6iRHHYrt8cdnN5parUrY9RIj6gtNQQ3c7rOs1cgjfDqVFjgv2j6aD5okH6A07Xa5SkyTOhnmeEb4xzDtdn/3WjEYD6Yf2kElNca1dqQFmSppBdE58UXo1MpePHtoWK2rkypP/SQvTDshEYm8gMpIIZOsYjGylsBEGbBT/jAhOIAxkE0xWpc7SdWwow9rvhtuIsItVGyDWUUe0SR40kfoBhC0nkEBdQmlFQIvRhj9sIEzb3cncQAmISU3TglLNnMCeCqj1zQFy95cwnad92q5QF1xd0MAa8F17jSJqgjgr0cO/txmCKgCpFDkwuxpW1KqOVD/zzBxOvhqJKZsUcUtNMYfEhyiOsXxbsj1TN0HwsTN59zwIONOc7jXPtXolRRbc1VfGHI7+xUNOWpeMoU5f9fFJ2JMSwWqyJVfW32Lbj43zn5Q0DIUMZ8BmUU/ksFfUZgGq3uOpyGs7iW21IgEzVt8p/fbaRUSEkUM3As6DZOXAWS/r20XgXboyKfFPfdbXwXmf5ur9f2BchS18PTio9xaKBNT4adbDxzTLFwuWwk398j4KwtCMsdr+EltriQSJD+iajtiGvKqSrJDMitNPp2x8q4GPELyYbsveBMSMq586t7KngTyn+vZlICBccTynfgt0WsZMVaC9pTuFTp2LYS7u8oka71d0KF4rwQ3IawjVZCEGlKnQSpTycqKrCd3M6Kc2DAo5FmGlQvPB7HMzy4zwubyM8AM6X3QUHxctieF9QvAIVHGWOcLdBAox4sBmKCZfoiCOvAcdn1fNEEcQ2+V893pb8MSaNdS1jCGl8y4Sr/k/hm3a9Y4xXPrJvMAicvZsokyXsF5bExVtXuG+CHmklCHlOqdYwZKpgoiCft0X3ZpZKCljIh0YeJPUrmd2H8uTgthQ2KmqdsdqyXIB54nOeMhG540G391myFgFrS7nPagr14QyqUo3Rw/9oURrgj44WWEsPC9uZrSOIAn3+w8Nuj/MePxFrpsmniGg+dc2hPxjRmSSRq8beEKqFtAD9Wd1VKeC8NQgmVkgpEDZOLBrjnrxAGirtfVAtD6vO1uePMAntwh85QApO/iDTXuPgZnd+fTYYozPJ1z211kIawzmFqY0Teb/bAQ1F
MESSAGE_2=ygUCAAK5gyod0YOcaWccvWIE70Q3Nl0+H7OictIPjEBPx081AgoutVlLDudvnsopLLK5W/kWgegZKYLe5c7/dFJ4YAZxgb/4IiNdZrTrmiDscR+K4qwGHjyGYDcrPKehPylsftitNDPYkaxHCrfmkL1v17eRcOP3hDRfxYaOfGwJirSSO2KqZuCXDWf+TAg+wg93BdwVuJ9UMls7nkkZJDnwFqc0N4g9hOM/KKz0QO9AdHwkaSFw49D2kuHoS9XVY51rOeaD3w3ezfUt2FCGVaVmB+RoIHENWhaU9hdCfNacgnVBVxYnDJmuo7FbnS49Vv54pNUYf0yr4L5uD72dd0BrNjXEqE0uwwo40u5UT6PxfDQQPnWCeRlCXgrNKA6DHttI0LGn6u1makhQ4maWu0g/Rj+fEFOaNkJ6lEJYQzczRoTCTZkCEc0gT/2vzYqEPCr+otIWRTnQTZRFDa6WXQitkO228Sush6XQhgLbqxIlgxOCAhG+laxI3/HM8oVJM31+TIYDISwMWywdmaFi5Znk2gohdr9QDuBEgCDYhecvR7b9gzoZnSFlkTXDk30itZqNu2pUXtWHn23gqoE4Ixyxe+PxZMj39CUhhV73cysZHqtEXH0P/VlZLdAsKGGR3i5/GbgdvLjm6AvFoqmHc7iBZZ0MWC2cPD/dfb/AIn9w26aRPER7pWOHbJmUi5oiLqYuCnXuWipMYU/eFkB7RiTxTMOuruD/Ba5LxfAuudSnwRU0gN8fmRgcMSPY/LGffjb9JvZz/2oNycDbsqnf3oMtN0arpDAX0qrUeah8DO1vc5mZEF0ve/0ZG6WqrC2VB4vIkZG+ASUsb/ZgCV45qvibi9Ila0ALsEFFZUuK8fQHB14b4uG+R0p7/nBXvKboyHvXdG8HLxPARFIwNUt0322+nM3tFJFdTE7PP777rt9vNCeYGVc6wfs6LB1giIhMq4lU9ckW0Me/PnR9YdSd3A9PbTGhyy6reuV8vt89mhIq8l9Vq9ojMeCJKC2DFx1Zbs9RgJqyZQ3cT121+X6dqnyynF58EPv3XM5c9SKqMDLf+gEu2ibFd7/Xg4vugu5JMY9U4wbany5uOOk2B7oJPD6A1JWUg+ZgrnL9p1smiFDDzl+OHucXN2Onlb2+FPr7rvNLF88y+YhoYEgrwmNV9KoI4vTwcV0mghLQ033R30zXTnyEjOUeTSu/H2wR

c. Each party processes all messages. If no complaints found, finalize and output. 

```bash
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-1
cargo run --bin dkg-cli process-all-messages --messages $MESSAGE_0,$MESSAGE_1,$MESSAGE_2 --state-dir .dkg-state-2

# All parties' local output should all contain the key server pk and all partial pks. 
KEY_SERVER_PK=0x94d64ca6b2e72d1b83202bb4b0f483928e6b53e2392e510db24e879a54a12095c951cb8fd9362966f76069ee3af1ed0d0ab1011127436ddcc505d51b46d672537ebce6ef2ed498401e44669cb770e983d43134167a6e21d2e7931b6e7cb7ab56
PARTY_0_PARTIAL_PK=0x856fb1a010d474fa1b8dda76dde2147971c926d531edd22c637b24a782efa190341104dc9de98f0d2dfd500dec4ea8af112082c2ac8b5cf42e217c3633b4e57b9bc69bf07cfacc51275e60b92f7e7f21ca764a0c186dc9e8256f2c44f2300427
PARTY_1_PARTIAL_PK=0xae5d3589de5651c18f829b0d4aa8b1b3f644031a3c2bce5e29201e05f091cf7cb2edac09c628c21fce964268f43f903a038f99ad059a422bd3f9803f6e94410da4c2ce367ef8016b23cc32f140547b1a37ba68db35a976ce1f518ccb50ca4397
PARTY_2_PARTIAL_PK=0x98d21682abc4759619ebd6d679617cdacf2083bd746047277ec099e06ca96321dcd793135b82cb4180778a0b551fbb191543913545682f728d9ff4bd907396e9128210863bc15b1fe06bfa98f5909223399aff74630383f38ac99a82b940bc00

# Each party's output contains their own partial secret key.
PARTY_0_SK=0x7159148266a389a2da7056acb4a322a49ad40d32597963f02994c1cc8b5b779e 
PARTY_1_SK=0x09e0c1f70b9974f19930a83a8ed30f47fb09ab6ddd7f5d3990171f8911353d69
PARTY_2_SK=0x165616beda2cdd888b2ad1d072a4d3f0aefcedac6183b281f6997d44970f0335
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
KEY_SERVER_OBJECT_ID=0xae73decc85fd7687a7d0d906af8005aaa7bf57bb9ef76c6c045cb2b0d8ad0ee2
```

d. Each member can update their partial key server URL. The update_url function receives the KeyServer through the Receiving pattern.

```bash
# Party 0:
sui client switch --address $ADDRESS_0
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party0-keyserver.com"'

# Party 1:
sui client switch --address $ADDRESS_1
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party1-keyserver.com"'

sui client switch --address $ADDRESS_2
sui client ptb \
  --move-call $COMMITTEE_PKG::committee::update_url @$KEY_SERVER_OBJECT_ID @$COMMITTEE_ID '"https://party2-keyserver.com"'
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

NEW_COMMITTEE_ID=0x2ebc9d6b5cff83a160c1d16009f7f1590e43145c6191b9814344cbc629891599
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
  --state-dir ./rotation-state-party-1 \
  --party-mapping 0:1,1:0

cargo run --bin dkg-cli init-rotation \
  --party-id 1 \
  --old-party-id 0 \
  --committee-id $NEW_COMMITTEE_ID \
  --ecies-sk $PARTY_0_ECIES_SK \
  --signing-sk $PARTY_0_ECIES_SK \
  --threshold 3 \
  --old-threshold 2 \
  --old-share $PARTY_0_SK \
  --state-dir ./rotation-state-party-0 \
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

MESSAGE_0=zAYBAAOFb7GgENR0+huN2nbd4hR5cckm1THt0ixjeySngu+hkDQRBNyd6Y8NLf1QDexOqK8RIILCrItc9C4hfDYztOV7m8ab8Hz6zFEnXmC5L35/Icp2SgwYbcnoJW8sRPIwBCen/RXrWqzK5EoySEnke+XQCLi7yp9rRPgnLcDFim1M0+Hm7ngctjBqTK7R9YuP4KgK6YVxiG7qzbbSGyk0eYf7gEXenoA3kYGF9L5DXL+fFwAsBZRToQPnnegGSJwLv2mNRyvukWog8kRKFR/dimthty5H+Lwfx1VMq6x+VplgRUngOONNrIRFCJ381i7fV/YCeraxHVmRUGYDuYzX3cqVpZ/S9oX9r3f75IhLcv7BJRY2769Mcp2/O3U5/fAOpAmEWafD+xcOKITmPqqA6VsBRsCsx+PVGN6XDilVuJk0WVswFDsU++RVx5nE65d8As8SZrtAsUmdZGwlWLCkCqZvnPuSVsKCXpnscf3oXwJkEuVIZy5KiAmpIzrWz7PeNWSnJrXmEfioPsrxU1PWWJBvPz/Fh8TJcBGg+05PLCPI7duVGfmDPAj4nycuBq3Vf1cY5bVJfpIAb5fi0kMdcnc8dAIVy0ZvW4gXQMjcjc7IM1JNJsnRA3OfDba7q9pCTiIEIb2bfORrlSpYDXnHIV+aXRz2gc4/4NMT/DhpEzPGeeP3pSHJXbdsksEn5Zebin9l9zQWG/iub/DbHk2CYGcxpWukcgoh1Q9X8ExRep4c3WKTODfnEGNR8AK/3hoGey2xKIQ8EvjUIedIxcNl9fYDqjrvmYMAsnA/fXIazLjwJRyDKS59TBvXtq927pIaYQNenWVToCJaLcWuP+P9Unxxlm7QhA5q2CEbCSUKcnD0dtxV/GffwPVeLxm8i4xRuxhUfYQTQpw5Sc3YuYaiUkrnW6FBR6f4bh+zy5A+oyvvIF1p5bbdB/JpioS5LSpqud//Y5Po3lCAVMTH6yDwTTkqJQi9pmVajLN5rHlvquKefh/MD+BmPlxyzwFAUsO6TEzOqkF4SkI2lFMJWe5qqZzf8V/KuL9uqeHQrSKFpfvXnPHd+xuDvVII+Ck+DkAfVggUKQPyj7nESKLhAXNrKAKt31QBZbIbxkkaYIvaSLYVuEpkbpzdg36UXRnfMeShVTu9xmNfdjb44Qb+6FWwoEfpmzh/F1raQniTXRdjORBp/2yrc1H57GxEVUzjPuSj92xfsPuiUSs2ZuZjA9UdgfCLwVdmAGxC8CEbYIhtmO3dn05m5p9iDf9mtu08IfPPW947QtHhgVmtLntZ7V65lLK9zEkdKaHF1NSS/AxUnI0gg4xq2qgpRaYJCPOkgceCc+rbxR2UkGI41v4vFklFWVVrB057tvNoB/hGLA==

MESSAGE_1=zAYAAAOuXTWJ3lZRwY+Cmw1KqLGz9kQDGjwrzl4pIB4F8JHPfLLtrAnGKMIfzpZCaPQ/kDoDj5mtBZpCK9P5gD9ulEENpMLONn74AWsjzDLxQFR7Gje6aNs1qXbOH1GMy1DKQ5e0McYN9AxNiQ22UQydmyBVs9asIKBfTaFJecPiWpyzD49CvJFFYfIb0thZxy6U35kDxP6W/OZXi9q/Sbm97e5yMRLorePgEGpDeu1192hWsrRO5OtEZA2f5IG8nBk2r+aAfqG6DkmjtcANWwLU528pi1EA/KOo6lcAfBQ30bSCGQcB+WQ7JVHB38ga8XKafBAZwJU8aQK/07rkfK1BTIYB7aeH1XdvMCpJFr62AWmhcjBZdZbC1Z1ZMB+MeuuEO5yQaeQTy/5TdD/XTsW4pFASE43WVhnnjTimp9lkMDvf2TnRA0+fDNhbnEcF0iQeY0cOVboiAllJR/0OxetrXsKF5q8Zzbfx/P1Sv23FbqfHFYzXclVAjUmafEYg/tQoehat542MMlTeBDXiRXJQfnCoaouDp96OmPhaTVb8k5hgNGoxTWNQOg41H0DMPTaIFwwY/wzcSroTgozwpUrOk9WpyJxS/aYiPi3xzKSWyxm436D53ccSDo03nFdAWT1Ff1QEITTE4VOw2qT8QR/TwMrqJcpKAzrDUL83LyGw9Cr7tRUm2CGjUYIPkEVEFHdJVB8Iwnbflxp+aCIjgixaCIz5wsUshQ4hhgypKF1n7K2g1EOuE1mfcQiPfhyDSPdoS6jR15TFg8vRIdamDATdG1seZzOwvPeIfSbGwFBnSnu9Q1pc2IoDMuXXx6UYcZpSRavyEwxwDy80aggDprO1Fyd+9K2j1PAhlZEQfdUlZbPY0Q2yHvraG862nRTHIMpzvmswGnCaAbXrXvoI7FUSz+GSaqpJzrvwTohSpCUdzhh16Rqtn0xhKiKgQJJWAzVr+YARDQl7oLIFIryPD9VnZ5xnfRRSYNDqAuD2mS78ee3W8OU0l90cS1ngpRlQMX7903+SsqJys47L8hsBEXoiWjKx84Z5ETt1S+9XTrzIbKYSyt1sIXbotxixGSp8FnCxKQea5FJKidcrlJQ674TQakI90QzBThQxpSJlYLTv9sq+PhUG3Hn9QOJ4mn2cxXag6M6Q02Oez2r2No5Sxv5HNTCnR1bHeuSm6zhAyAOWsl8l2RqczbpyOJMZ5cwZXBA0ugRZeuGWLJgBf7cI5CZ8e+I8U7/9CZIS+vIHxIhoPnXNoT8Y0ZkkkavG3hCqhbQA/VndVSngvDUIJlZIKRA2Tiwa4568QBoq7X1QLQ+rztbnjzAJ7cIfOUAKTv4g017j4GZ3fn02GKMzydc9tdZCGsM5hamNE3m/2wENRQ==
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
KEY_SERVER_PK=0x94d64ca6b2e72d1b83202bb4b0f483928e6b53e2392e510db24e879a54a12095c951cb8fd9362966f76069ee3af1ed0d0ab1011127436ddcc505d51b46d672537ebce6ef2ed498401e44669cb770e983d43134167a6e21d2e7931b6e7cb7ab56
NEW_PARTY_0_PK=0xa4637cf1e457c1b0092e4d149952cd841a4ea850f0c532791772c84c5d755a2b6466d32d4d525916c995b29fe1740da5072213bb34aec05eaa5514b568128d48a7d463d404aff17eae2566ce42016a319eb2016ad4688286e7e503e5edba5e42
NEW_PARTY_1_PK=0x96ae8d853217e84a09ac3d071513f60f1d606b2e1773b783f5389828cb0c5524b490502daa9ea990ffc386c73ef7dd581730207a97a1288a3e3e0b37e81ad095071bb1b7d27cef2c5bd78063ebf05cb0b939f9a908fe940288ca0a0b823bba06
NEW_PARTY_2_PK=0xb753521a2559e5c13a1af057f1f00c4ae9b5f64007af9cd67331f33d56a76249abf07c623d08df56cad45b4a9d3437a605687825212fc33fb13e8be5ae5853bf165fef68e369f157e6920e23070b48cabf9adb208c32c1a1dc23552f6d6c2f33
NEW_PARTY_3_PK=0x83047f6ba74f45c75d310b7dd8a393925316a674248ab3f0dbfcc2988c5891778814420c1d203f5848bbdebf9a4509c3155099351ca55f3f188ce9e3e7f6a2b0af9f146d0de3b2ab845858a9daff0837d3a9f170bb494ac5f051b8faa91c38e5

# Each party should see their own partial secret keys individially. 
NEW_PARTY_0_SK=0x6124e4bda6b01644c10aa64457c2587c7a416d87b41eea00e37001b3c1a9e215
NEW_PARTY_1_SK=0x00c40e198861c58e0693064d0e54b77962b099ad5fa207fe7fd3e2c807044efd
NEW_PARTY_2_SK=0x2a3d4dad76229b577e2f84e49034b8f5325a5a79d2f0a0b1ede6c0d735726b17
NEW_PARTY_3_SK=0x43e8978f49f44f56a475523dcaef88ee3276a889bc13e40f9f382030625dea05
```

6. All member must propose all partial pks and key server pk for rotation to append their approvals. 

```shell
sui client switch --address $ADDRESS_0 # repeat for $ADDRESS_1, $ADDRESS_2, $ADDRESS_3
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
  --move-call $COMMITTEE_PKG::committee::update_url @$KEY_SERVER_OBJECT_ID @$NEW_COMMITTEE_ID '"https://rotation0-keyserver.com"'
```