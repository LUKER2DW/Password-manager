# The server's release image (ghcr.io/<owner>/vault-server), made by .github/workflows/release.yml
# from the Linux binaries the release built and attested: the same small image as Dockerfile
# (which builds from source), for amd64 and arm64. Its build context is a folder holding
# vault-server-amd64, vault-server-arm64 and an empty data/.
#
# The binaries are built on Ubuntu 22.04, whose C library is older than Debian 12's, so they
# start here. The base is pinned by its digest (a list for every platform; Dependabot moves it).
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG TARGETARCH
COPY --chmod=0755 vault-server-${TARGETARCH} /usr/local/bin/vault-server
# A named volume mounted here starts out owned by the non-root user.
COPY --chown=65532:65532 data /data
ENV VAULT_SERVER_DATA=/data \
    VAULT_SERVER_LISTEN=0.0.0.0:8750
EXPOSE 8750
VOLUME /data
USER nonroot
ENTRYPOINT ["/usr/local/bin/vault-server"]
CMD ["serve"]
