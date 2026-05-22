# Start with a Rust base image
FROM rust:1.90-bullseye  AS builder

ARG PROFILE=release

WORKDIR work

COPY ./crates ./crates
COPY ./Cargo.toml ./Cargo.lock ./

ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION

# BuildKit cargo cache mounts: registry/git/target persist on the mp3
# stateful-pool PVC across commits. Cache-mount contents aren't committed to
# the image layer, so copy the binary out to a stable path in the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/work/target,sharing=locked \
    cargo build --bin key-server --profile $PROFILE --config net.git-fetch-with-cli=true \
    && cp /work/target/release/key-server /work/key-server
FROM debian:bullseye-slim AS runtime

EXPOSE 2024

RUN apt-get update && apt-get install -y cmake clang libpq5 ca-certificates libpq-dev postgresql

COPY --from=builder /work/key-server /opt/key-server/bin/

# Handle all environment variables
RUN echo '#!/bin/bash\n\
# Export all environment variables\n\
for var in $(env | cut -d= -f1); do\n\
    export "$var"\n\
done\n\
\n\
exec /opt/key-server/bin/key-server "$@"' > /opt/key-server/entrypoint.sh && \
    chmod +x /opt/key-server/entrypoint.sh

ENTRYPOINT ["/opt/key-server/entrypoint.sh"]
