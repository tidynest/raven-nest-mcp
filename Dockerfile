# Multi-stage: build the server on debian, run it on Kali (which already packages
# 20 of the 22 wrapped tools as apt packages — far less upkeep than hand-building
# the Go/Rust tools on debian-slim).
#
# ponytail: COPY . . busts the cargo layer on any source change, so each release
# does a full compile. Fine for a tag-triggered build; add cargo-chef only if the
# image build time actually hurts.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin raven-server

# katana + dalfox are NOT in the Kali apt repo (verified against pkg.kali.org) —
# build them in a throwaway Go stage so the toolchain stays out of the runtime image.
# ponytail: @latest is non-reproducible; pin @vX.Y.Z if you need deterministic builds.
FROM golang:1-bookworm AS gobuild
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/hahwul/dalfox/v2@latest

FROM kalilinux/kali-rolling AS runtime
ENV DEBIAN_FRONTEND=noninteractive
# 20 apt tools + libssl3 (raven-server links OpenSSL via native-tls) + CA roots.
# katana/dalfox come from the Go stage. MSF excluded — roughly doubles image size
# (see distribution plan); ship a ':full' tag or document the apt line if wanted.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan nuclei nikto sqlmap hydra john ffuf feroxbuster wpscan \
      whatweb subfinder httpx-toolkit dnsx dnsrecon \
      enum4linux-ng netexec gitleaks trufflehog testssl.sh \
      libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gobuild /go/bin/katana /go/bin/dalfox /usr/local/bin/
COPY --from=build /src/target/release/raven-server /usr/local/bin/raven-server

LABEL org.opencontainers.image.source="https://github.com/tidynest/raven-nest-mcp" \
      io.modelcontextprotocol.server.name="io.github.tidynest/raven-nest-mcp"

ENTRYPOINT ["raven-server"]
