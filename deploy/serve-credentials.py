#!/usr/bin/env python3
"""Reference implementation of the PARENT side of the credentials handoff.

Run this on the parent EC2 instance (the one hosting the enclave) — NOT
inside the enclave. It listens on the dedicated credentials vsock port
(must match transport.VsockPortCredentials in
internal/transport/endpoints.go, currently 8200) and, every time the
enclave connects, fetches a fresh copy of the parent's own temporary AWS
credentials from the instance's IMDSv2 metadata service and sends them
down as one JSON blob before closing the connection.

WHY THIS IS SAFE TO DO, EVEN THOUGH IT HANDS A LIVE AWS SECRET ACROSS THE
vsock BOUNDARY: this connection is the ONLY thing the parent controls that
touches AWS credentials. Every actual AWS API call made with those
credentials happens entirely INSIDE the enclave, over TLS that terminates
inside the enclave — the parent's vsock-proxy processes (see
start-proxies.sh) only ever relay opaque, already-encrypted TLS bytes they
cannot read or modify. So compromising this script gets an attacker a copy
of the temporary credentials (bad, but time-limited — IMDS credentials
expire), never a way to see or alter what the enclave actually does with
them.

Python (3.9+, Linux only) is used here purely because it has AF_VSOCK
support built into the standard `socket` module — no extra dependency
needed on the parent instance for a script this small.
"""

import json
import socket
import sys
import urllib.request

# Must match transport.VsockPortCredentials in
# internal/transport/endpoints.go.
CREDENTIALS_PORT = 8200

IMDS_BASE = "http://169.254.169.254/latest"
IMDS_TOKEN_TTL_SECONDS = "21600"  # 6 hours; IMDSv2 requires a token at all


def fetch_instance_role_credentials() -> dict:
    """Fetch this instance's own IAM role credentials from IMDSv2, and
    reshape them into the JSON schema transport.Credentials expects (see
    internal/transport/credentials.go) — snake_case field names, not the
    PascalCase IMDS itself uses.
    """
    token_req = urllib.request.Request(
        f"{IMDS_BASE}/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": IMDS_TOKEN_TTL_SECONDS},
    )
    with urllib.request.urlopen(token_req, timeout=5) as resp:
        token = resp.read().decode("utf-8")

    headers = {"X-aws-ec2-metadata-token": token}

    # An instance can only ever have one attached role, but IMDS still
    # exposes it as a "list role names" endpoint — read the (single) name
    # back to build the next URL.
    role_req = urllib.request.Request(
        f"{IMDS_BASE}/meta-data/iam/security-credentials/", headers=headers
    )
    with urllib.request.urlopen(role_req, timeout=5) as resp:
        role_name = resp.read().decode("utf-8").strip()

    creds_req = urllib.request.Request(
        f"{IMDS_BASE}/meta-data/iam/security-credentials/{role_name}",
        headers=headers,
    )
    with urllib.request.urlopen(creds_req, timeout=5) as resp:
        imds_creds = json.loads(resp.read())

    return {
        "access_key_id": imds_creds["AccessKeyId"],
        "secret_access_key": imds_creds["SecretAccessKey"],
        "session_token": imds_creds["Token"],
        # IMDS already returns this as an RFC3339 timestamp (e.g.
        # "2026-01-01T00:00:00Z"), which is exactly what Go's
        # encoding/json expects to unmarshal into a time.Time — no
        # reformatting needed.
        "expiration": imds_creds["Expiration"],
    }


def main() -> None:
    # socket.AF_VSOCK is Linux-only and requires Python 3.9+; this script
    # is only ever meant to run on the parent EC2 instance, which
    # satisfies both.
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.VMADDR_CID_ANY, CREDENTIALS_PORT))
    server.listen()
    print(f"serve-credentials: listening on vsock port {CREDENTIALS_PORT}", file=sys.stderr)

    while True:
        conn, addr = server.accept()
        print(f"serve-credentials: connection from {addr}, fetching fresh credentials", file=sys.stderr)
        try:
            creds = fetch_instance_role_credentials()
            conn.sendall(json.dumps(creds).encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - a single failed handoff must not kill the server
            print(f"serve-credentials: failed to serve credentials: {exc}", file=sys.stderr)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
