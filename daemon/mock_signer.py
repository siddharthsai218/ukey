#!/usr/bin/env python3
"""Software P-256 signer used to emulate the Android phone in Phase 1.

This is deliberately a *test* signer: private keys live only in this process's
memory and are lost when it exits. It speaks the same newline-delimited JSON
protocol that the real Android bridge will speak.

Protocol (one JSON object per line):
    request  -> {"id": 1, "action": "make_credential",
                 "rp_id": "example.com", "client_hash": "<64 hex chars>"}
    response -> {"id": 1, "pub_key_x": "<64 hex>", "pub_key_y": "<64 hex>",
                 "cred_id": "<hex>"}

    request  -> {"id": 2, "action": "get_assertion",
                 "rp_id": "example.com", "cred_id": "<hex>",
                 "digest": "<64 hex chars>"}
    response -> {"id": 2, "raw_sig": "<128 hex chars>"}  # r || s, 64 bytes

The ECDSA implementation below is intentionally small and readable. It is NOT
constant-time and must never be used for real credentials. Python's standard
library has no ECDSA primitive, so this avoids adding a runtime dependency on
`cryptography` for the mock.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import secrets
import signal
import socket
import sys
import threading
import time
from typing import Any, Optional

LOG = logging.getLogger("mock-signer")

# NIST P-256 (secp256r1) domain parameters.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

Point = Optional[tuple[int, int]]


def _inv(value: int) -> int:
    """Inverse modulo the field prime (for point arithmetic)."""
    return pow(value % P, -1, P)


def _inv_n(value: int) -> int:
    """Inverse modulo the group order (for ECDSA)."""
    return pow(value % N, -1, N)


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = ((3 * x1 * x1) + A) * _inv(2 * y1) % P
    else:
        slope = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def _scalar_mult(k: int, point: Point) -> Point:
    if k % N == 0 or point is None:
        return None
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def generate_key() -> tuple[int, Point]:
    private = secrets.randbelow(N - 1) + 1
    public = _scalar_mult(private, (GX, GY))
    if public is None:  # pragma: no cover - astronomically unlikely
        raise RuntimeError("point at infinity")
    return private, public


def sign_digest(private: int, digest: bytes) -> bytes:
    """Sign a 32-byte digest and return fixed-width r || s (64 bytes)."""
    if len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(N - 1) + 1
        point = _scalar_mult(k, (GX, GY))
        if point is None:
            continue
        r = point[0] % N
        if r == 0:
            continue
        s = (_inv_n(k) * (z + r * private)) % N
        if s == 0:
            continue
        # Low-S form is what libfido2/OpenSSL produce and avoids malleability.
        if s > N // 2:
            s = N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class MockSigner:
    """In-memory key store implementing the two signer actions."""

    def __init__(self, delay_ms: int = 0) -> None:
        self.delay_ms = max(0, delay_ms)
        # cred_id hex -> (private scalar, rp_id)
        self._keys: dict[str, tuple[int, str]] = {}

    def _maybe_delay(self) -> None:
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000.0)

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        request_id = request.get("id")

        if action == "make_credential":
            rp_id = request.get("rp_id")
            client_hash = request.get("client_hash")
            if not isinstance(rp_id, str) or not rp_id:
                raise ValueError("rp_id must be a non-empty string")
            if not isinstance(client_hash, str) or len(client_hash) != 64:
                raise ValueError("client_hash must be 32 bytes of hex")
            bytes.fromhex(client_hash)  # validate

            self._maybe_delay()
            private, public = generate_key()
            cred_id = secrets.token_bytes(16)
            self._keys[cred_id.hex()] = (private, rp_id)
            return {
                "id": request_id,
                "pub_key_x": public[0].to_bytes(32, "big").hex(),
                "pub_key_y": public[1].to_bytes(32, "big").hex(),
                "cred_id": cred_id.hex(),
            }

        if action == "attest":
            # Self-attestation: sign the MakeCredential authData digest with
            # the same credential key. The daemon includes the result in a
            # packed attStmt so libfido2's fido2-cred can print the credential
            # (its CLI cannot format a "none" attestation with no signature).
            cred_id_hex = request.get("cred_id")
            digest_hex = request.get("digest")
            if not isinstance(cred_id_hex, str):
                raise ValueError("cred_id must be hex")
            if not isinstance(digest_hex, str) or len(digest_hex) != 64:
                raise ValueError("digest must be 32 bytes of hex")
            entry = self._keys.get(cred_id_hex)
            if entry is None:
                raise KeyError("unknown credential")
            private, _bound_rp = entry
            self._maybe_delay()
            digest = bytes.fromhex(digest_hex)
            return {"id": request_id, "raw_sig": sign_digest(private, digest).hex()}

        if action == "get_assertion":
            rp_id = request.get("rp_id")
            cred_id_hex = request.get("cred_id")
            digest_hex = request.get("digest")
            if not isinstance(rp_id, str) or not rp_id:
                raise ValueError("rp_id must be a non-empty string")
            if not isinstance(cred_id_hex, str):
                raise ValueError("cred_id must be hex")
            if not isinstance(digest_hex, str) or len(digest_hex) != 64:
                raise ValueError("digest must be 32 bytes of hex")
            digest = bytes.fromhex(digest_hex)

            entry = self._keys.get(cred_id_hex)
            if entry is None:
                raise KeyError("unknown credential")
            private, bound_rp = entry
            if bound_rp != rp_id:
                raise ValueError("credential is bound to a different rp_id")

            self._maybe_delay()
            return {"id": request_id, "raw_sig": sign_digest(private, digest).hex()}

        raise ValueError(f"unknown action: {action!r}")


def _serve_connection(conn: socket.socket, signer: MockSigner, stop: threading.Event) -> None:
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # A timeout lets the receive loop observe the stop event. Without it a
    # SIGTERM while the connection is idle sets the event but recv() is
    # restarted by Python and the process never exits.
    conn.settimeout(0.5)
    buffer = b""
    with conn:
        while not stop.is_set():
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            if not data:
                return
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    request = json.loads(line)
                    response = signer.handle(request)
                except Exception as exc:  # report the error to the daemon
                    request_id = None
                    try:
                        request_id = json.loads(line).get("id")
                    except Exception:
                        pass
                    response = {"id": request_id, "error": f"{type(exc).__name__}: {exc}"}
                try:
                    conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
                except OSError:
                    return


def main() -> int:
    parser = argparse.ArgumentParser(description="uKey Phase 1 software signer")
    parser.add_argument("--host", default="127.0.0.1", help="daemon address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="daemon port (default 8443)")
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=int(os.environ.get("UKEY_SIGNER_DELAY_MS", "0")),
        help="artificial delay before signing, useful for testing KEEPALIVE",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    stop = threading.Event()

    def _stop(_signum: int, _frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    signer = MockSigner(delay_ms=args.delay_ms)
    LOG.info("mock signer starting (delay=%dms), target %s:%d", args.delay_ms, args.host, args.port)

    while not stop.is_set():
        try:
            conn = socket.create_connection((args.host, args.port), timeout=5.0)
        except OSError as exc:
            LOG.warning("cannot reach daemon at %s:%d: %s; retrying", args.host, args.port, exc)
            stop.wait(1.0)
            continue

        LOG.info("connected to daemon")
        conn.settimeout(None)
        try:
            _serve_connection(conn, signer, stop)
        except OSError as exc:
            LOG.warning("signer connection lost: %s", exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass
        if not stop.is_set():
            LOG.info("reconnecting in 1s")
            stop.wait(1.0)

    LOG.info("mock signer stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
