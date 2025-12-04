# Aggregator Server

Aggregator server for Seal committee mode. It fetches encrypted partial keys from committee member servers, verifies encrypted signatures.

## Overview

The aggregator server:
1. Loads committee configuration from onchain (threshold, member URLs, partial public keys)
2. Receives fetch key requests from clients. 
3. Fans out requests to all committee member servers till threshold is met. 
5. Verifies encrypted signatures from each member using their partial public key. 
6. Aggregates encrypted responses using Lagrange interpolation. 
7. Returns the aggregated encrypted key to the client. 

### Running the Server

See example configuration file at `aggregator-config.yaml` and modify as needed. Then run:

```shell
CONFIG_PATH=crates/aggregator-server/aggregator-config.yaml cargo run --bin aggregator-server
```


## Running with Docker
```shell
docker build -f Dockerfile.aggregator -t aggregator-server:latest .

docker run -p 2024:2024 \
  -v $(pwd)/crates/aggregator-server/aggregator-config.yaml:/config/aggregator-config.yaml \
  -e CONFIG_PATH=/config/aggregator-config.yaml \
  aggregator-server
```
