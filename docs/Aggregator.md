# Aggregator Server

The Aggregator Server supports a Seal MPC committee. It collects encrypted partial keys from committee members, verifies their encrypted signatures, and returns an aggregated encrypted key to clients. The server also uses private API keys to authenticate with committee member key servers.

## Overview

The aggregator server performs the following tasks:

1. Loads the committee's configuration from the network, including the threshold, member URLs, and partial public keys.
2. Receives fetch key requests from clients. 
3. Fans out each request to committee member servers until it collects responses from enough members to satisfy the threshold.
4. Verifies each encrypted signature using the corresponding partial public key.
5. Aggregates the encrypted partial responses using Lagrange interpolation.
6. Returns the aggregated encrypted key to the client. 

## Setup

The aggregator authenticates with each committee member's key server using private API keys.

### Initial Setup (Fresh DKG)

After a fresh DKG completes, the coordinator should share the following with the aggregator operator:

1. **Key server object ID** (`KEY_SERVER_OBJ_ID`): Obtained after DKG finalization.
2. **API credentials from all committee members**: Each committee member provides their onchain server name, API key name, and API key.

The aggregator operator should then configure these values in `aggregator-config.yaml` and deploy the server.

### Key Rotation

During key rotation, if new members join the committee, the coordinator should share the new members' API credentials with the aggregator operator. The aggregator operator should add the new credentials to `aggregator-config.yaml` and restart the server.

The aggregator configuration can include credentials for both old and new member names. The aggregator periodically fetches the current committee from onchain to get the latest member names.

## Running the Server

Edit the configuration file at `aggregator-config.yaml` to match your environment. Set the network, key server object ID (provided by the coordinator), and the API credentials for all committee members:

```yaml
# The network for the object.
network: !Testnet
# The committee server object ID.
key_server_object_id: '0x0000000000000000000000000000000000000000000000000000000000000000'

# API credentials for committee members.
api_credentials:
    server1: # onchain server name
      api_key_name: keyname1
      api_key: key1
    server2:
      api_key_name: keyname2
      api_key: key2
```

Then run:

```shell
$ CONFIG_PATH=crates/key-server/src/aggregator/aggregator-config.yaml cargo run --bin aggregator-server
```


### Running with Docker

1. Build the image:

```shell
$ docker build -f Dockerfile.aggregator -t aggregator-server:latest .
```

2. Run the server:

```shell
$ docker run -p 2024:2024 \
  -v $(pwd)/crates/key-server/src/aggregator/aggregator-config.yaml:/config/aggregator-config.yaml \
  -e CONFIG_PATH=/config/aggregator-config.yaml \
  aggregator-server
```