FROM rust:1.90-bullseye  AS builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./
COPY docker/seal-proxy/local-test/metrics-generator docker/seal-proxy/local-test/metrics-generator
RUN cargo build --release -p metrics-generator

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3

COPY --from=builder /usr/src/app/target/release/metrics-generator /usr/local/bin/metrics-generator

EXPOSE 8000
CMD ["metrics-generator"]
