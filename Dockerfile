# Start with a Rust base image
FROM rust:1.87-bullseye  AS builder

ARG PROFILE=release

WORKDIR work

COPY ./crates ./crates
COPY ./Cargo.toml ./

ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION

RUN cargo build --bin key-server --profile $PROFILE --config net.git-fetch-with-cli=true
FROM debian:bullseye-slim AS runtime
ARG master_key
ARG key_server_object_id
# TODO: remove this when the legacy key server is no longer needed
ARG legacy_key_server_object_id
ARG network

EXPOSE 2024

RUN apt-get update && apt-get install -y cmake clang libpq5 ca-certificates libpq-dev postgresql

COPY --from=builder /work/target/release/key-server /opt/key-server/bin/

ENV MASTER_KEY=$master_key
ENV KEY_SERVER_OBJECT_ID=$key_server_object_id
ENV NETWORK=$network

# TODO: remove this when the legacy key server is no longer needed
ENV LEGACY_KEY_SERVER_OBJECT_ID=$legacy_key_server_object_id

ENTRYPOINT ["/opt/key-server/bin/key-server"]
