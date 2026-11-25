# vault-server in a small image without a shell. Build from the repository root:
#   docker build -f apps/server/Dockerfile -t vault-server .
# or with apps/server/compose.yaml. See docs/SERVER.md.

# Both stages on Debian 12 (bookworm): a binary built against a newer C library than the
# runtime image has would not start. Each image is pinned by its digest (Dependabot moves
# the pins), so a tag moved on the registry changes nothing here until it is reviewed.
FROM rust:1-slim-bookworm@sha256:bb875b0f8ce726053e259034848c471840e96bfe591fd52556178ae9a05e6126 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p vault-server \
    && mkdir /data-dir

# Distroless: the binary, its C runtime, CA roots, nothing else; runs as a non-root user.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
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
