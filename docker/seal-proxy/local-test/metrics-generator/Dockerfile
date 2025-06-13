FROM rust:1.86-bookworm as builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./
COPY crates/seal-proxy crates/seal-proxy

COPY docker/seal-proxy/local-test/metrics-generator docker/seal-proxy/local-test/metrics-generator
RUN cd docker/seal-proxy/local-test/metrics-generator && cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/docker/seal-proxy/local-test/metrics-generator/target/release/metrics-generator /usr/local/bin/metrics-generator

EXPOSE 8000
CMD ["metrics-generator"] 