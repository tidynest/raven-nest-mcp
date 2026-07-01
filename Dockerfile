# Multi-stage: build the server on debian, run it on Kali (which already packages
# 20 of the 22 wrapped tools as apt packages - far less upkeep than hand-building
# the Go/Rust tools on debian-slim).
#
# ponytail: COPY . . busts the cargo layer on any source change, so each release
# does a full compile. Fine for a tag-triggered build; add cargo-chef only if the
# image build time actually hurts.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin raven-server

# katana + dalfox are NOT in the Kali apt repo (verified against pkg.kali.org) -
# build them in a throwaway Go stage so the toolchain stays out of the runtime image.
# ponytail: @latest is non-reproducible; pin @vX.Y.Z if you need deterministic builds.
FROM golang:1-bookworm AS gobuild
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/hahwul/dalfox/v2@latest

FROM kalilinux/kali-rolling AS runtime
ENV DEBIAN_FRONTEND=noninteractive
# 20 apt tools + iputils-ping (ping_target) + libssl3 (raven-server links OpenSSL
# via native-tls) + CA roots. katana/dalfox come from the Go stage. MSF excluded -
# roughly doubles image size (see distribution plan); ship a ':full' tag if wanted.
#
# Kali packages ProjectDiscovery httpx as `httpx-toolkit` because python3-httpx
# (an apt dependency of other tools here) owns `/usr/bin/httpx`. The server calls
# `httpx`, so symlink the PD binary into /usr/local/bin, which precedes /usr/bin
# on PATH - keeps the server's command name portable across non-Kali installs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan nuclei nikto sqlmap hydra john ffuf feroxbuster wpscan \
      whatweb subfinder httpx-toolkit dnsx dnsrecon \
      enum4linux-ng netexec gitleaks trufflehog testssl.sh \
      iputils-ping libssl3 ca-certificates \
    && ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gobuild /go/bin/katana /go/bin/dalfox /usr/local/bin/
COPY --from=build /src/target/release/raven-server /usr/local/bin/raven-server

# Ship the docs + default config inside the image so they travel with the package
# and are readable without the repo, e.g.:
#   docker run --rm --entrypoint cat ghcr.io/tidynest/raven-nest-mcp:latest \
#     /usr/share/doc/raven-nest-mcp/USAGE.md
COPY README.md LICENSE CHANGELOG.md SECURITY.md \
     docs/USAGE.md docs/METASPLOIT.md docs/LOCAL_AI_INTEGRATION.md docs/DATA_FLOW.md \
     config/default.toml \
     /usr/share/doc/raven-nest-mcp/

# Static OCI labels so any build (incl. local `docker build`) is well-described on
# the package page. CI additionally injects version/revision/created via
# docker/metadata-action (see release.yml). The mcp-name label is required by the
# MCP registry's oci ownership check - keep it == server.json `name`.
LABEL org.opencontainers.image.source="https://github.com/tidynest/raven-nest-mcp" \
      org.opencontainers.image.title="Raven Nest MCP" \
      org.opencontainers.image.description="AI-driven penetration testing - 22 bundled security tools behind 43 safety-hardened MCP endpoints (Metasploit tools require a separate msfrpcd)." \
      org.opencontainers.image.documentation="https://github.com/tidynest/raven-nest-mcp/blob/main/docs/USAGE.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.modelcontextprotocol.server.name="io.github.tidynest/raven-nest-mcp"

ENTRYPOINT ["raven-server"]
