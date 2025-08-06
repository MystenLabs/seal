FROM rust:1.86-bookworm AS build

ARG PROFILE=release
WORKDIR /work

RUN apt-get update && apt-get install -y cmake clang ca-certificates curl && update-ca-certificates

COPY .git/ .git/
COPY Cargo.toml Cargo.lock ./
COPY crates/seal-proxy crates/seal-proxy

RUN cargo build --profile ${PROFILE} --bin seal-proxy

FROM debian:bookworm-slim as prod
RUN apt-get update && apt install -y openssl ca-certificates && update-ca-certificates
COPY --from=build --chmod=755 /work/target/release/seal-proxy /opt/seal-proxy/bin/seal-proxy
