## Description 

This crate contains 2 components 

### 1. `seal-proxy`

#### Proxy and Processor: [location](./src/main.rs)
A public-facing HTTP proxy server that accepts metrics packets. It:

- Authenticates requests using bearer tokens (securely encrypted and stored internally)
- **Encodes the metrics into a Protobuf format**
- Relays them to an **Alloy sidecar container**, which forwards the data to the **Mimir metrics cluster**
- usage: `seal-proxy --config=seal-proxy.yaml --bearer-tokens-path=bearer-tokens.yaml`
    - [sample config file](../../docker/seal-proxy/local-test/seal-proxy.yaml)
    - [sample bearer token file](../../docker/seal-proxy/local-test/bearer-tokens.yaml)

#### Client Library: [location](./src/client.rs)
A reusable library that allows clients to:

- Push metrics to the `seal-proxy`
- Authenticate via bearer tokens
- please refer to Sample Client Setup for more details.

---

### 2. Sample Client Setup: [location](../../docker/seal-proxy/local-test/metrics-generator/src/main.rs)

#### Metrics Generator
- A sample application that uses the client library to generate and push metrics.

#### Seal-Proxy Instance
- Receives, authenticates, and processes metrics.

#### Alloy Sidecar
- Collects histogram metrics from seal-proxy instance due to lack of support of native histogram in prometheus rust library.

#### Mimir Cluster
- Stores the incoming metrics.

#### Grafana
- Visualizes metrics data stored in Mimir.

---

**Data Flow Summary:**  
`Auth → Encode → Relay → Store → Visualize`


## Test plan 

local end-to-end testing
- `cd docker/seal-proxy/local-test`
- `docker compose up --build`
- navigate to `localhost:3000` to access grafana

## if provided with incorrect Bearer token
```
seal-proxy  | 2025-07-18T21:51:50.471395Z  INFO tower_http::trace::on_response: finished processing request latency=0.000157083 s status=401
seal-proxy  | 2025-07-18T21:51:55.462979Z  INFO seal_proxy::middleware: auth_header: "Bearer 1234567890"
seal-proxy  | 2025-07-18T21:51:55.462995Z  INFO seal_proxy::allowers: Rejected Bearer Token: "1234567890"
seal-proxy  | 2025-07-18T21:51:55.462996Z  INFO seal_proxy::middleware: invalid token, rejecting request
```

## with correct Bearer token, it shows the corresponding name of the token
```
seal-proxy  | 2025-07-18T21:55:17.199397Z  INFO tower_http::trace::on_response: finished processing request latency=0.001276666 s status=200
seal-proxy  | 2025-07-18T21:55:22.193788Z  INFO seal_proxy::middleware: auth_header: "Bearer abcdefghijklmnopqrstuvwxyz"
seal-proxy  | 2025-07-18T21:55:22.193805Z  INFO seal_proxy::allowers: Accepted Request from: "sample-token"
```

the `metrics-generator` creates some `int_gauge`, `int_gauge_vec` and `histogram` metrics
