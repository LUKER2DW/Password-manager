# vault-server in a small image without a shell. Build from the repository root:
#   docker build -f apps/server/Dockerfile -t vault-server .
# or with apps/server/compose.yaml. See docs/SERVER.md.

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p vault-server \
    && mkdir /data-dir

# Distroless: the binary, its C runtime, CA roots, nothing else; runs as a non-root user.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/vault-server /usr/local/bin/vault-server
# A named volume mounted here starts out owned by the non-root user.
COPY --from=build --chown=65532:65532 /data-dir /data
ENV VAULT_SERVER_DATA=/data \
    VAULT_SERVER_LISTEN=0.0.0.0:8750
EXPOSE 8750
VOLUME /data
USER nonroot
ENTRYPOINT ["/usr/local/bin/vault-server"]
CMD ["serve"]
