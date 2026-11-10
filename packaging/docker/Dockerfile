# syntax=docker/dockerfile:1.7

ARG BRIDGE_BINARY=source

FROM rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS build
ENV CARGO_BUILD_JOBS=8 \
    CARGO_TERM_COLOR=never
WORKDIR /src/Aster-Bridge
COPY .github/source_pins.env .github/source_pins.env
COPY scripts/fetch_pinned_sources.sh scripts/fetch_pinned_sources.sh
RUN sed -i 's/\r$//' scripts/fetch_pinned_sources.sh .github/source_pins.env \
    && bash scripts/fetch_pinned_sources.sh mail
COPY src-tauri src-tauri
RUN cd src-tauri \
    && cargo build --release --locked -p aster-bridge-cli \
    && install -D -m 0755 target/release/aster-bridge /out/aster-bridge \
    && rm -rf target

FROM scratch AS source
COPY --from=build /out/aster-bridge /aster-bridge

FROM scratch AS prebuilt
ARG TARGETARCH
COPY dist/${TARGETARCH}/aster-bridge /aster-bridge

FROM ${BRIDGE_BINARY} AS binary

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ARG VERSION=dev
LABEL org.opencontainers.image.title="Aster Bridge" \
      org.opencontainers.image.description="Aster Bridge command-line server for IMAP, SMTP, POP3, JMAP, and CardDAV mail apps" \
      org.opencontainers.image.source="https://github.com/Aster-Privacy/Aster-Bridge" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 aster \
    && useradd --system --uid 10001 --gid aster --home-dir /data --shell /usr/sbin/nologin aster \
    && install -d -m 0700 -o aster -g aster /data /run/secrets
COPY --from=binary --chmod=0755 /aster-bridge /usr/local/bin/aster-bridge
ENV ASTER_BRIDGE_DATA_DIR=/data \
    ASTER_BRIDGE_SECRET_BACKEND=file \
    ASTER_BRIDGE_SECRET_KEY_FILE=/run/secrets/aster_bridge_secret_key \
    ASTER_BRIDGE_LISTEN=0.0.0.0 \
    ASTER_BRIDGE_COLOR=never \
    HOME=/data
USER aster:aster
VOLUME ["/data", "/run/secrets"]
EXPOSE 1143 1993 1025 1465 1110 1995 1080 1081
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["aster-bridge", "status"]
ENTRYPOINT ["/usr/bin/tini", "--", "aster-bridge"]
CMD ["serve", "--service"]
