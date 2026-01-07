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

### Running the Server

Edit the example configuration file at `aggregator-config.yaml` to match your environment.

```yaml
# The network for the object.
network: !Testnet
# The committee server object ID.
key_server_object_id: '0x0000000000000000000000000000000000000000000000000000000000000000'
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