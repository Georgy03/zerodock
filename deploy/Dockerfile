# syntax=docker/dockerfile:1
#
# This image is not meant to be run as a normal container on its own —
# `make eif` (see the Makefile) feeds it to `nitro-cli build-enclave`,
# which turns it into an Enclave Image File (.eif): the actual thing an
# AWS Nitro Enclave boots from. Whatever this image's ENTRYPOINT is
# becomes the ONLY program that runs inside the enclave.

# --- Build stage ---------------------------------------------------------
# Compile the scanner into a single, fully static Linux binary:
#   CGO_ENABLED=0 -> no C libraries linked in, so it doesn't depend on any
#                    system library being present at runtime
#   GOOS=linux GOARCH=amd64 -> the enclave always runs Linux on amd64,
#                    regardless of what OS/CPU you're building on
#   -trimpath        -> strips local filesystem paths (e.g. /Users/you/...)
#                    out of the compiled binary, so the build doesn't leak
#                    details about the machine that built it
FROM golang:1.25-bookworm AS builder

# Release builds pass the immutable Git tag (for example v0.1.0). "dev"
# keeps ordinary local builds usable, but the browser deliberately refuses to
# treat it as a published release tag.
ARG SCANNER_VERSION=dev
ARG SUPABASE_SECRET_ARN=
ARG GCP_WIF_AUDIENCE=
ARG GCP_SERVICE_ACCOUNT_KEY_SECRET_ARN=

WORKDIR /src

# Copying just the dependency manifests first (before the rest of the
# source) lets Docker reuse this layer, and skip re-downloading
# dependencies, as long as go.mod/go.sum haven't changed — even if
# application code has.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-s -w -X github.com/Georgy03/zerodock/internal/buildinfo.Version=${SCANNER_VERSION}" \
      -o /out/scanner ./cmd/scanner

# --- Final stage -----------------------------------------------------------
# `scratch` is Docker's literal "empty" base image: no shell, no package
# manager, no libc — nothing except what we explicitly copy in below. For
# an enclave, smaller is better: less code inside means less attack
# surface to reason about, and our statically-linked, CGO-free binary
# doesn't need a normal Linux userspace to run.
FROM scratch

ARG SUPABASE_SECRET_ARN
ARG GCP_WIF_AUDIENCE
ARG GCP_SERVICE_ACCOUNT_KEY_SECRET_ARN
# This is an ARN, never the Supabase token. The scanner fetches the token from
# the vendor's own AWS Secrets Manager only after it starts inside the enclave.
ENV ZERODOCK_SUPABASE_SECRET_ARN=${SUPABASE_SECRET_ARN}
# WIF audience and fallback ARN are configuration identifiers, never GCP
# credentials. The scanner exchanges AWS credentials for a short-lived token.
ENV ZERODOCK_GCP_WIF_AUDIENCE=${GCP_WIF_AUDIENCE}
ENV ZERODOCK_GCP_SERVICE_ACCOUNT_KEY_SECRET_ARN=${GCP_SERVICE_ACCOUNT_KEY_SECRET_ARN}

# TLS root certificates, so the scanner can validate AWS's HTTPS
# certificates once it has network access (not yet — that's a later
# week). Copied straight from the builder image instead of maintained by
# hand.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /out/scanner /scanner

# For week 3: run one scan and exit. No --mock-attest, so it uses the
# real NSM attester by default (see cmd/scanner/main.go).
ENTRYPOINT ["/scanner"]
