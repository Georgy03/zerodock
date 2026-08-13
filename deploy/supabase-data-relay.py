#!/usr/bin/env python3
"""Capability-scoped relay for Supabase's public Data API.

This runs on the Nitro parent, never in the enclave.  The enclave sends one
hostname line before TLS starts; this process validates it, resolves it once,
rejects non-public answers, then connects to that exact resolved address.
It therefore cannot be turned into a general proxy by DNS rebinding.

The relay sees encrypted HTTPS bytes after the one hostname line.  It never
receives a Supabase Management token or an anon/publishable key.
"""
import ipaddress
import logging
import re
import selectors
import socket
import threading

PORT = 8400
MAX_CONNECTIONS = 8
MAX_TOTAL_CONNECTIONS = 500
REF_HOST = re.compile(r"^[a-z0-9]{20}\.supabase\.co$")
active = threading.BoundedSemaphore(MAX_CONNECTIONS)
total_lock = threading.Lock()
total = 0


def read_hostname(conn):
    value = b""
    while not value.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk or len(value) >= 64:
            raise ValueError("invalid relay request")
        value += chunk
    host = value[:-1].decode("ascii")
    if not REF_HOST.fullmatch(host):
        raise ValueError("destination is not a canonical Supabase project host")
    return host


def resolve_public(host):
    # getaddrinfo happens exactly once.  We connect to this numeric address,
    # never the hostname, so a later DNS answer cannot redirect the relay.
    addresses = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ValueError("destination resolved to a non-public address")
        addresses.append((family, sockaddr))
    if not addresses:
        raise ValueError("destination did not resolve")
    return addresses


def copy_bidirectional(left, right):
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    try:
        while True:
            for key, _ in selector.select():
                data = key.fileobj.recv(65536)
                if not data:
                    return
                key.data.sendall(data)
    finally:
        selector.close()


def handle(conn):
    global total
    upstream = None
    acquired = False
    try:
        if not active.acquire(blocking=False):
            raise ValueError("concurrent connection limit reached")
        acquired = True
        with total_lock:
            if total >= MAX_TOTAL_CONNECTIONS:
                raise ValueError("per-scan connection limit reached")
            total += 1
        host = read_hostname(conn)
        addresses = resolve_public(host)
        last_error = None
        for family, sockaddr in addresses:
            try:
                upstream = socket.socket(family, socket.SOCK_STREAM)
                upstream.settimeout(15)
                upstream.connect(sockaddr)
                upstream.settimeout(None)
                logging.info("supabase-data-relay destination=%s address=%s", host, sockaddr[0])
                copy_bidirectional(conn, upstream)
                return
            except OSError as error:
                last_error = error
                if upstream:
                    upstream.close()
                    upstream = None
        raise ValueError("could not connect to validated destination: %s" % last_error)
    except Exception as error:
        logging.warning("supabase-data-relay denied: %s", error)
    finally:
        if upstream:
            upstream.close()
        conn.close()
        if acquired:
            active.release()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen(MAX_CONNECTIONS)
    logging.info("supabase-data-relay listening on vsock port %d", PORT)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
