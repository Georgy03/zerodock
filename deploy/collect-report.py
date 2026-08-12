#!/usr/bin/env python3
"""Reference implementation of the PARENT side of the report handoff.

Run this on the parent EC2 instance (the one hosting the enclave) — NOT
inside the enclave. It listens on the dedicated report vsock port (must
match transport.VsockPortReport in internal/transport/endpoints.go,
currently 8300), accepts exactly ONE connection, reads whatever the
enclave sends until it closes the connection (EOF), writes that payload to
a timestamped file under ./reports/, and prints a one-line summary (scan
ID, account, pass/fail/error counts) so a human watching `make run-enclave`
can immediately see whether the scan looks right without having to open
the file.

Unlike serve-credentials.py (which loops forever, serving fresh
credentials on every connection), this script handles ONE report and then
exits — that matches how it's used: deploy/run-enclave.sh starts one of
these per enclave run and waits for it to finish as the signal that the
report has arrived.
"""

import datetime
import json
import os
import socket
import sys

# Must match transport.VsockPortReport in internal/transport/endpoints.go.
REPORT_PORT = 8300

DEFAULT_REPORTS_DIR = "reports"


def receive_one_report(port: int) -> bytes:
    """Listen on the given vsock port, accept exactly one connection, and
    read from it until the sender closes the connection (EOF). Returns the
    complete payload as bytes.
    """
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.VMADDR_CID_ANY, port))
    server.listen()
    print(f"collect-report: listening on vsock port {port}", file=sys.stderr)

    conn, addr = server.accept()
    print(f"collect-report: connection from {addr}, receiving report", file=sys.stderr)
    try:
        chunks = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:  # empty read = the other end closed the connection (EOF)
                break
            chunks.append(chunk)
    finally:
        conn.close()
        server.close()

    return b"".join(chunks)


def write_report(payload: bytes, reports_dir: str) -> str:
    """Save the raw payload to a timestamped file under reports_dir, and
    return the path it was written to."""
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(reports_dir, f"report-{timestamp}.json")
    with open(path, "wb") as f:
        f.write(payload)
    return path


def print_summary(payload: bytes, path: str) -> None:
    """Print one line summarizing the report: scan ID, account, and how
    many checks came back pass/fail/error. If the payload isn't valid
    JSON, say so explicitly instead of crashing — the file is still saved
    either way, so nothing is lost.
    """
    try:
        report = json.loads(payload)
    except json.JSONDecodeError as exc:
        print(f"collect-report: saved {path} ({len(payload)} bytes) but it is not valid JSON: {exc}")
        return

    scan_id = report.get("scan_id", "?")
    account_id = report.get("account_id", "?")

    counts = {"pass": 0, "fail": 0, "error": 0}
    for check in report.get("checks", {}).values():
        status = check.get("result", {}).get("status")
        if status in counts:
            counts[status] += 1
        else:
            # A status we don't recognize is itself worth surfacing,
            # rather than silently dropping it from the tally.
            counts[f"unknown({status})"] = counts.get(f"unknown({status})", 0) + 1

    counts_str = " ".join(f"{name}={n}" for name, n in counts.items())
    print(f"collect-report: saved {path} | scan_id={scan_id} account_id={account_id} | {counts_str}")


def main() -> None:
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_REPORTS_DIR

    payload = receive_one_report(REPORT_PORT)
    path = write_report(payload, reports_dir)
    print_summary(payload, path)


if __name__ == "__main__":
    main()
