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

EXPOSE 2024

RUN apt-get update && apt-get install -y cmake clang libpq5 ca-certificates libpq-dev postgresql

COPY --from=builder /work/target/release/key-server /opt/key-server/bin/

# Pass GIT_REVISION from builder stage to runtime stage
ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION

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
