FROM rust:1.86-bookworm as builder

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./
COPY crates/seal-proxy crates/seal-proxy

COPY docker/seal-proxy/local-test/metrics-generator crates/metrics-generator
RUN cd crates/metrics-generator && cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/target/release/metrics-generator /usr/local/bin/metrics-generator

EXPOSE 8000
CMD ["metrics-generator"] 