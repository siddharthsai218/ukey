#!/usr/bin/env python3
"""uKey Phase 1: virtual FIDO2/CTAP2 authenticator over /dev/uhid.

This daemon creates a virtual USB HID device, implements the CTAPHID transport
and the CTAP2 commands needed for WebAuthn / libfido2 Phase 1:

    authenticatorGetInfo        (0x04)
    authenticatorMakeCredential (0x01)
    authenticatorGetAssertion   (0x02)

Cryptographic work is delegated to a signer connected over a local TCP socket
(see daemon/mock_signer.py for the Phase 1 software implementation).
"""

from __future__ import annotations

import argparse
import ctypes
import glob
import hashlib
import json
import logging
import os
import secrets
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Optional

import cbor2

LOG = logging.getLogger("ukey")

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

HID_REPORT_DESCRIPTOR = bytes.fromhex(
    "06D0F10901A1010920150026FF007508954081020921150026FF00750895409102C0"
)
HID_REPORT_SIZE = 64
CTAPHID_INIT_PAYLOAD = 57
CTAPHID_CONT_PAYLOAD = 59
CTAPHID_MAX_MESSAGE = 7609
CTAPHID_BROADCAST = 0xFFFFFFFF

# CTAPHID commands (the high bit is part of the wire byte).
CTAPHID_PING = 0x01
CTAPHID_MSG = 0x03
CTAPHID_LOCK = 0x04
CTAPHID_INIT = 0x06
CTAPHID_WINK = 0x08
CTAPHID_CBOR = 0x10
CTAPHID_CANCEL = 0x11
CTAPHID_KEEPALIVE = 0x3B
CTAPHID_ERROR = 0x3F

# CTAPHID capabilities.
CTAPHID_CAP_WINK = 0x01
CTAPHID_CAP_CBOR = 0x04
CTAPHID_CAP_NMSG = 0x08

# CTAPHID error statuses.
CTAPHID_ERR_INVALID_CMD = 0x01
CTAPHID_ERR_INVALID_PAR = 0x02
CTAPHID_ERR_INVALID_LEN = 0x03
CTAPHID_ERR_INVALID_SEQ = 0x04
CTAPHID_ERR_MSG_TIMEOUT = 0x05
CTAPHID_ERR_CHANNEL_BUSY = 0x06
CTAPHID_ERR_LOCK_REQUIRED = 0x0A
CTAPHID_ERR_INVALID_CHANNEL = 0x0B
CTAPHID_ERR_OTHER = 0x7F

# CTAPHID KEEPALIVE statuses.
CTAPHID_STATUS_PROCESSING = 0x01
CTAPHID_STATUS_UPNEEDED = 0x02

# CTAP2 commands and statuses.
CTAP2_CMD_MAKE_CREDENTIAL = 0x01
CTAP2_CMD_GET_ASSERTION = 0x02
CTAP2_CMD_GET_INFO = 0x04
CTAP2_CMD_CLIENT_PIN = 0x06
CTAP2_CMD_RESET = 0x07

CTAP2_OK = 0x00
CTAP2_ERR_INVALID_COMMAND = 0x01
CTAP2_ERR_INVALID_PARAMETER = 0x02
CTAP2_ERR_INVALID_LENGTH = 0x03
CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x0A
CTAP2_ERR_UNSUPPORTED_OPTION = 0x0D
CTAP2_ERR_INVALID_OPTION = 0x0E
CTAP2_ERR_KEEPALIVE_CANCEL = 0x0F
CTAP2_ERR_NO_CREDENTIALS = 0x10
CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19
CTAP2_ERR_REQUEST_TOO_LARGE = 0x1A
CTAP2_ERR_OTHER = 0x7F

# Fixed AAGUID for this project. It is intentionally not a FIDO-certified
# vendor AAGUID; RPs will display it as an unknown authenticator.
AAGUID = bytes.fromhex("fa83a1a960d94daabc6c092271928a11")

# Linux UHID ABI (see /usr/include/linux/uhid.h).
UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14
UHID_DATA_MAX = 4096
BUS_USB = 0x03


class _UhidCreate2Req(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("name", ctypes.c_uint8 * 128),
        ("phys", ctypes.c_uint8 * 64),
        ("uniq", ctypes.c_uint8 * 64),
        ("rd_size", ctypes.c_uint16),
        ("bus", ctypes.c_uint16),
        ("vendor", ctypes.c_uint32),
        ("product", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("country", ctypes.c_uint32),
        ("rd_data", ctypes.c_uint8 * 4096),
    ]


class _UhidInput2Req(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("size", ctypes.c_uint16),
        ("data", ctypes.c_uint8 * UHID_DATA_MAX),
    ]


class _UhidOutputReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("data", ctypes.c_uint8 * UHID_DATA_MAX),
        ("size", ctypes.c_uint16),
        ("rtype", ctypes.c_uint8),
    ]


class _UhidSetReportReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("rnum", ctypes.c_uint8),
        ("rtype", ctypes.c_uint8),
        ("size", ctypes.c_uint16),
        ("data", ctypes.c_uint8 * UHID_DATA_MAX),
    ]


class _UhidSetReportReplyReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("err", ctypes.c_uint16),
    ]


class _UhidGetReportReplyReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("err", ctypes.c_uint16),
        ("size", ctypes.c_uint16),
        ("data", ctypes.c_uint8 * UHID_DATA_MAX),
    ]


class _UhidUnion(ctypes.Union):
    _pack_ = 1
    _fields_ = [
        ("create2", _UhidCreate2Req),
        ("input2", _UhidInput2Req),
        ("output", _UhidOutputReq),
        ("set_report", _UhidSetReportReq),
        ("set_report_reply", _UhidSetReportReplyReq),
        ("get_report_reply", _UhidGetReportReplyReq),
    ]


class _UhidEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("u", _UhidUnion),
    ]


UHID_EVENT_SIZE = ctypes.sizeof(_UhidEvent)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CtapError(Exception):
    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(message or f"CTAP2 error 0x{code:02x}")
        self.code = code


class SignerError(Exception):
    pass


class SignerCancelled(Exception):
    pass


# ---------------------------------------------------------------------------
# Signer bridge
# ---------------------------------------------------------------------------


class SignerBridge:
    """Listens for one signer connection and performs request/response RPC."""

    def __init__(
        self,
        host: str,
        port: int,
        connect_timeout: float = 8.0,
        on_disconnect: Optional[Callable[[], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.on_disconnect = on_disconnect
        self._server: Optional[socket.socket] = None
        self._conn: Optional[socket.socket] = None
        self._conn_cond = threading.Condition()
        self._io_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._request_id = 0

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(2)
        server.settimeout(0.5)
        self._server = server
        self._thread = threading.Thread(target=self._accept_loop, name="signer-accept", daemon=True)
        self._thread.start()
        LOG.info("signer socket listening on %s:%d", self.host, self.port)

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self._conn_cond:
                old = self._conn
                self._conn = conn
                self._conn_cond.notify_all()
            if old is not None:
                try:
                    old.close()
                except OSError:
                    pass
            LOG.info("signer connected from %s:%d", *addr)

    def _drop_conn(self, conn: Optional[socket.socket] = None) -> None:
        with self._conn_cond:
            if conn is None or self._conn is conn:
                current = self._conn
                self._conn = None
            else:
                current = None
            self._conn_cond.notify_all()
        if current is not None:
            try:
                current.close()
            except OSError:
                pass
            if self.on_disconnect is not None:
                try:
                    self.on_disconnect()
                except Exception as exc:
                    LOG.error("on_disconnect callback failed: %s", exc)

    def _wait_for_conn(
        self,
        cancel: threading.Event,
        keepalive: Callable[[], None],
    ) -> socket.socket:
        deadline = time.monotonic() + self.connect_timeout
        while True:
            if cancel.is_set():
                raise SignerCancelled()
            with self._conn_cond:
                if self._conn is not None:
                    return self._conn
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SignerError("no signer connected")
                self._conn_cond.wait(min(0.1, remaining))
            keepalive()

    def request(
        self,
        payload: dict[str, Any],
        cancel: threading.Event,
        keepalive: Callable[[], None],
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        with self._io_lock:
            conn = self._wait_for_conn(cancel, keepalive)
            self._request_id = (self._request_id + 1) & 0xFFFFFFFF
            request_id = self._request_id
            message = dict(payload)
            message["id"] = request_id
            wire = json.dumps(message, separators=(",", ":")).encode() + b"\n"

            try:
                conn.sendall(wire)
            except OSError as exc:
                self._drop_conn(conn)
                raise SignerError(f"cannot send to signer: {exc}") from exc

            buffer = b""
            deadline = time.monotonic() + timeout
            try:
                while True:
                    if cancel.is_set():
                        raise SignerCancelled()
                    keepalive()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SignerError("timed out waiting for signer")
                    try:
                        readable, _, _ = select.select([conn], [], [], min(0.1, remaining))
                    except (OSError, ValueError) as exc:
                        raise SignerError(f"signer socket failed: {exc}") from exc
                    if not readable:
                        continue
                    data = conn.recv(65536)
                    if not data:
                        raise SignerError("signer disconnected")
                    buffer += data
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            response = json.loads(line)
                        except json.JSONDecodeError:
                            LOG.warning("discarding non-JSON signer response")
                            continue
                        if response.get("id") != request_id:
                            LOG.warning("discarding stale signer response id=%r", response.get("id"))
                            continue
                        if "error" in response:
                            raise SignerError(str(response["error"]))
                        return response
            except (SignerCancelled, SignerError, OSError):
                # Closing the connection is the only reliable way to abort a
                # request that the signer is still processing.
                self._drop_conn(conn)
                raise

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        self._drop_conn()
        if self._thread is not None:
            self._thread.join(timeout=1.0)


# ---------------------------------------------------------------------------
# CTAP2 engine
# ---------------------------------------------------------------------------


@dataclass
class Credential:
    cred_id: bytes
    rp_id: str
    x: bytes
    y: bytes
    created_at: float


def _as_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CtapError(CTAP2_ERR_INVALID_PARAMETER, f"{what} must be an integer")
    return value


def _as_bytes(value: Any, what: str, length: Optional[int] = None) -> bytes:
    if not isinstance(value, bytes):
        raise CtapError(CTAP2_ERR_INVALID_PARAMETER, f"{what} must be a byte string")
    if length is not None and len(value) != length:
        raise CtapError(CTAP2_ERR_INVALID_LENGTH, f"{what} must be {length} bytes")
    return value


def _as_text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise CtapError(CTAP2_ERR_INVALID_PARAMETER, f"{what} must be a non-empty string")
    return value


def _as_map(value: Any, what: str) -> dict[Any, Any]:
    if not isinstance(value, dict):
        raise CtapError(CTAP2_ERR_INVALID_PARAMETER, f"{what} must be a map")
    return value


def _der_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative DER integer")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def raw_ecdsa_to_der(raw: bytes) -> bytes:
    """Convert a 64-byte r||s ECDSA signature to ASN.1 DER.

    CTAP2/WebAuthn carry ES256 signatures as DER SEQUENCE(INTEGER r,
    INTEGER s). The signer protocol deliberately exposes the compact 64-byte
    form because it is easy to produce and verify, so the daemon converts at
    the CTAP2 boundary.
    """
    if len(raw) != 64:
        raise ValueError("raw ECDSA signature must be 64 bytes")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    body = _der_int(r) + _der_int(s)
    if len(body) > 127:
        raise ValueError("DER signature too long")
    return b"\x30" + bytes([len(body)]) + body


class Ctap2Engine:
    def __init__(
        self,
        signer: SignerBridge,
        aaguid: bytes = AAGUID,
        attestation: str = "self",
    ) -> None:
        if attestation not in ("self", "none"):
            raise ValueError("attestation must be 'self' or 'none'")
        self.signer = signer
        self.aaguid = aaguid
        self.attestation = attestation
        self.credentials: dict[bytes, Credential] = {}
        self._sign_count = 0
        self._engine_lock = threading.Lock()

    def _next_sign_count(self) -> int:
        with self._engine_lock:
            self._sign_count = (self._sign_count + 1) & 0xFFFFFFFF
            return self._sign_count

    def handle(
        self,
        request_bytes: bytes,
        cancel: threading.Event,
        keepalive: Callable[[], None],
    ) -> bytes:
        """Return a CTAP2 status byte plus optional CBOR response.

        CTAPHID_CBOR payloads are: one command byte, then an optional CBOR
        parameter map. Responses are: one status byte, then an optional CBOR
        result. A getInfo request is therefore exactly b"\x04".
        """
        if not request_bytes:
            return bytes([CTAP2_ERR_INVALID_LENGTH])
        command = request_bytes[0]
        try:
            if len(request_bytes) == 1:
                params: dict[Any, Any] = {}
            else:
                params = cbor2.loads(request_bytes[1:])
        except Exception as exc:
            LOG.warning("invalid CTAP2 CBOR: %s", exc)
            return bytes([CTAP2_ERR_INVALID_PARAMETER])
        if not isinstance(params, dict):
            return bytes([CTAP2_ERR_INVALID_PARAMETER])

        try:
            if command == CTAP2_CMD_GET_INFO:
                result = self._get_info()
            elif command == CTAP2_CMD_MAKE_CREDENTIAL:
                result = self._make_credential(params, cancel, keepalive)
            elif command == CTAP2_CMD_GET_ASSERTION:
                result = self._get_assertion(params, cancel, keepalive)
            elif command == CTAP2_CMD_CLIENT_PIN:
                return bytes([CTAP2_ERR_UNSUPPORTED_OPTION])
            elif command == CTAP2_CMD_RESET:
                # Phase 1 has no persistent credential database to reset.
                return bytes([CTAP2_OK])
            else:
                return bytes([CTAP2_ERR_INVALID_COMMAND])
            return bytes([CTAP2_OK]) + cbor2.dumps(result, canonical=True)
        except CtapError as exc:
            LOG.info("CTAP2 command 0x%02x failed: %s", command, exc)
            return bytes([exc.code])
        except SignerCancelled:
            LOG.info("CTAP2 command 0x%02x cancelled", command)
            return bytes([CTAP2_ERR_KEEPALIVE_CANCEL])
        except SignerError as exc:
            LOG.warning("signer error: %s", exc)
            return bytes([CTAP2_ERR_OTHER])
        except Exception:
            LOG.error("unhandled CTAP2 error:\n%s", traceback.format_exc())
            return bytes([CTAP2_ERR_OTHER])

    def _get_info(self) -> dict[int, Any]:
        return {
            1: ["FIDO_2_0"],
            2: [],
            3: self.aaguid,
            4: {"rk": False, "up": True, "uv": True},
            5: 1024,
            7: 8,      # maxCredentialCountInList
            8: 255,    # maxCredentialIdLength
            9: ["usb"],
            10: [{"type": "public-key", "alg": -7}],
        }

    def _make_credential(
        self,
        params: dict[Any, Any],
        cancel: threading.Event,
        keepalive: Callable[[], None],
    ) -> dict[int, Any]:
        client_hash = _as_bytes(params.get(1), "clientDataHash", 32)
        rp = _as_map(params.get(2), "rp")
        user = _as_map(params.get(3), "user")
        algorithms = params.get(4)
        exclude_list = params.get(5, [])
        options = params.get(7, {})

        rp_id = _as_text(rp.get("id"), "rp.id")
        if len(rp_id.encode("utf-8")) > 255:
            raise CtapError(CTAP2_ERR_INVALID_PARAMETER, "rp.id is too long")
        user_id = _as_bytes(user.get("id"), "user.id")
        if not user_id:
            raise CtapError(CTAP2_ERR_INVALID_PARAMETER, "user.id must not be empty")

        if not isinstance(algorithms, list) or not algorithms:
            raise CtapError(CTAP2_ERR_INVALID_PARAMETER, "pubKeyCredParams must be a non-empty array")
        supported = False
        for entry in algorithms:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "public-key" and entry.get("alg") == -7:
                supported = True
                break
        if not supported:
            raise CtapError(CTAP2_ERR_UNSUPPORTED_ALGORITHM, "only ES256 (-7) is supported")

        if not isinstance(options, dict):
            options = {}
        if options.get("rk") is True:
            raise CtapError(CTAP2_ERR_UNSUPPORTED_OPTION, "resident credentials are not implemented")

        if isinstance(exclude_list, list):
            for entry in exclude_list:
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") != "public-key":
                    continue
                excluded_id = entry.get("id")
                if isinstance(excluded_id, bytes) and excluded_id in self.credentials:
                    raise CtapError(CTAP2_ERR_CREDENTIAL_EXCLUDED, "credential already exists")

        if cancel.is_set():
            raise SignerCancelled()
        keepalive()
        response = self.signer.request(
            {
                "action": "make_credential",
                "rp_id": rp_id,
                "client_hash": client_hash.hex(),
            },
            cancel,
            keepalive,
        )
        if cancel.is_set():
            raise SignerCancelled()

        x = self._hex_field(response, "pub_key_x", 32)
        y = self._hex_field(response, "pub_key_y", 32)
        cred_id = self._hex_bytes(response, "cred_id")
        if not 1 <= len(cred_id) <= 1023:
            raise CtapError(CTAP2_ERR_OTHER, "signer returned an invalid credential id")

        cose_key = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: x, -3: y},
            canonical=True,
        )
        rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        auth_data = (
            rp_id_hash
            + bytes([0x45])  # UP | UV | AT
            + struct.pack(">I", self._sign_count)
            + self.aaguid
            + struct.pack(">H", len(cred_id))
            + cred_id
            + cose_key
        )

        self.credentials[cred_id] = Credential(
            cred_id=cred_id,
            rp_id=rp_id,
            x=x,
            y=y,
            created_at=time.time(),
        )
        LOG.info("registered credential %s for %s", cred_id.hex()[:16], rp_id)

        if self.attestation == "none":
            # Strict CTAP2 "none" attestation: empty attStmt.
            return {1: "none", 2: auth_data, 3: {}}

        # Packed self-attestation. This is valid CTAP2 and, unlike "none",
        # can be printed and verified by libfido2's fido2-cred(1): that tool
        # calls base64_encode(NULL, 0) for a none attestation and exits with
        # "output error" before writing any output.
        attestation_digest = hashlib.sha256(auth_data + client_hash).digest()
        keepalive()
        attest_response = self.signer.request(
            {
                "action": "attest",
                "rp_id": rp_id,
                "cred_id": cred_id.hex(),
                "digest": attestation_digest.hex(),
            },
            cancel,
            keepalive,
        )
        raw_sig = self._hex_bytes(attest_response, "raw_sig")
        if len(raw_sig) != 64:
            raise CtapError(CTAP2_ERR_OTHER, "signer returned a non-raw attestation signature")
        return {1: "packed", 2: auth_data, 3: {"alg": -7, "sig": raw_ecdsa_to_der(raw_sig)}}

    def _get_assertion(
        self,
        params: dict[Any, Any],
        cancel: threading.Event,
        keepalive: Callable[[], None],
    ) -> dict[int, Any]:
        rp_id = _as_text(params.get(1), "rpId")
        client_hash = _as_bytes(params.get(2), "clientDataHash", 32)
        allow_list = params.get(3)

        credential = self._select_credential(rp_id, allow_list)
        if credential is None:
            raise CtapError(CTAP2_ERR_NO_CREDENTIALS, "no matching credential")

        sign_count = self._next_sign_count()
        rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        auth_data = rp_id_hash + bytes([0x05]) + struct.pack(">I", sign_count)  # UP | UV
        digest = hashlib.sha256(auth_data + client_hash).digest()

        if cancel.is_set():
            raise SignerCancelled()
        keepalive()
        response = self.signer.request(
            {
                "action": "get_assertion",
                "rp_id": rp_id,
                "digest": digest.hex(),
                "cred_id": credential.cred_id.hex(),
            },
            cancel,
            keepalive,
        )
        if cancel.is_set():
            raise SignerCancelled()

        raw_sig = self._hex_bytes(response, "raw_sig")
        if len(raw_sig) != 64:
            raise CtapError(CTAP2_ERR_OTHER, "signer returned a non-raw ECDSA signature")

        LOG.info("assertion for %s using %s", rp_id, credential.cred_id.hex()[:16])
        return {
            1: {"type": "public-key", "id": credential.cred_id},
            2: auth_data,
            3: raw_ecdsa_to_der(raw_sig),
        }

    def _select_credential(self, rp_id: str, allow_list: Any) -> Optional[Credential]:
        if allow_list is not None and not isinstance(allow_list, list):
            raise CtapError(CTAP2_ERR_INVALID_PARAMETER, "allowList must be an array")

        if isinstance(allow_list, list) and allow_list:
            for entry in allow_list:
                if not isinstance(entry, dict) or entry.get("type") != "public-key":
                    continue
                cred_id = entry.get("id")
                if not isinstance(cred_id, bytes):
                    continue
                credential = self.credentials.get(cred_id)
                if credential is not None and credential.rp_id == rp_id:
                    return credential
            return None

        # No allowList: non-resident authenticators technically require one,
        # but choosing the newest credential for the RP makes hand testing and
        # tools that omit the list usable.
        candidates = [c for c in self.credentials.values() if c.rp_id == rp_id]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.created_at)

    @staticmethod
    def _hex_bytes(response: dict[str, Any], field: str) -> bytes:
        value = response.get(field)
        if not isinstance(value, str):
            raise CtapError(CTAP2_ERR_OTHER, f"signer response missing {field}")
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise CtapError(CTAP2_ERR_OTHER, f"signer response {field} is not hex") from exc

    @classmethod
    def _hex_field(cls, response: dict[str, Any], field: str, length: int) -> bytes:
        value = cls._hex_bytes(response, field)
        if len(value) != length:
            raise CtapError(CTAP2_ERR_OTHER, f"signer response {field} has wrong length")
        return value


# ---------------------------------------------------------------------------
# UHID transport
# ---------------------------------------------------------------------------


class UhidDevice:
    def __init__(self, path: str = "/dev/uhid", name: str = "uKey FIDO2 Authenticator") -> None:
        self.path = path
        self.name = name
        self.fd = -1
        self._write_lock = threading.Lock()

    def open(self) -> None:
        self.fd = os.open(self.path, os.O_RDWR | os.O_CLOEXEC)
        LOG.info("opened %s (fd=%d)", self.path, self.fd)
        self._create()

    def _create(self) -> None:
        req = _UhidCreate2Req()
        name = self.name.encode("utf-8")[:127]
        req.name[: len(name)] = name
        req.rd_size = len(HID_REPORT_DESCRIPTOR)
        req.bus = BUS_USB
        req.vendor = 0x1209
        req.product = 0x0001
        req.version = 0x0100
        req.country = 0
        req.rd_data[: len(HID_REPORT_DESCRIPTOR)] = HID_REPORT_DESCRIPTOR
        event = struct.pack("<I", UHID_CREATE2) + bytes(req)
        written = os.write(self.fd, event)
        if written != len(event):
            raise OSError(f"short UHID_CREATE2 write: {written}/{len(event)}")

    def write_input_report(self, report: bytes) -> None:
        if len(report) != HID_REPORT_SIZE:
            raise ValueError(f"report must be {HID_REPORT_SIZE} bytes")
        event = struct.pack("<I", UHID_INPUT2) + struct.pack("<H", len(report)) + report
        with self._write_lock:
            written = os.write(self.fd, event)
        if written != len(event):
            raise OSError(f"short UHID_INPUT2 write: {written}/{len(event)}")

    def reply_set_report(self, report_id: int, err: int = 0) -> None:
        event = struct.pack("<I", UHID_SET_REPORT_REPLY) + struct.pack("<IH", report_id, err)
        with self._write_lock:
            os.write(self.fd, event)

    def destroy(self) -> None:
        if self.fd < 0:
            return
        try:
            with self._write_lock:
                os.write(self.fd, struct.pack("<I", UHID_DESTROY))
        except OSError:
            pass

    def close(self) -> None:
        self.destroy()
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def read_event(self) -> tuple[int, _UhidEvent]:
        raw = os.read(self.fd, UHID_EVENT_SIZE)
        if len(raw) < 4:
            raise OSError("short UHID event read")
        if len(raw) < UHID_EVENT_SIZE:
            raw = raw + bytes(UHID_EVENT_SIZE - len(raw))
        event = _UhidEvent.from_buffer_copy(raw)
        return event.type, event


def find_hidraw_for_name(name: str) -> Optional[str]:
    for sys_path in glob.glob("/sys/class/hidraw/hidraw*"):
        # Real USB HID devices expose device/name. Virtual UHID devices on
        # current kernels only expose HID_NAME in the parent's uevent file.
        try:
            with open(os.path.join(sys_path, "device", "name"), "r", encoding="utf-8") as fh:
                if fh.read().strip() == name:
                    return "/dev/" + os.path.basename(sys_path)
        except OSError:
            pass
        try:
            with open(os.path.join(sys_path, "device", "uevent"), "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("HID_NAME=") and line.strip().split("=", 1)[1] == name:
                        return "/dev/" + os.path.basename(sys_path)
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Host Biometric Detection (Adaptive Hierarchy)
# ---------------------------------------------------------------------------


def detect_host_biometric() -> Optional[str]:
    """Check if the Linux host has a local hardware fingerprint sensor via fprintd."""
    try:
        proc = subprocess.run(
            ["fprintd-list", os.environ.get("USER", "")],
            capture_output=True,
            text=True,
            timeout=1.0,
        )
        if proc.returncode == 0 and "No devices available" not in proc.stdout:
            lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            for line in lines:
                if "device" in line.lower() or "sensor" in line.lower():
                    return line
            return lines[0] if lines else "Local fprintd device"
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------


class UKeyDaemon:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.device = UhidDevice(path=args.uhid, name=args.device_name)
        on_disconnect = self._on_signer_disconnect if getattr(args, "auto_lock", False) else None
        self.signer = SignerBridge(args.listen_host, args.port, on_disconnect=on_disconnect)
        self.ctap = Ctap2Engine(self.signer, attestation=args.attestation)
        self.channels: set[int] = set()
        self.pending: dict[int, dict[str, Any]] = {}
        self.stop_event = threading.Event()

        self._tx_lock = threading.Lock()
        self._active_cid: Optional[int] = None
        self._cancel: Optional[threading.Event] = None

    def _on_signer_disconnect(self) -> None:
        LOG.warning("Phone bridge disconnected — triggering Proximity Walk-Away Screen Lock")
        try:
            subprocess.run(["loginctl", "lock-session"], check=False)
        except Exception as exc:
            LOG.error("Failed to execute loginctl lock-session: %s", exc)

    # -- lifecycle ---------------------------------------------------------

    def run(self) -> int:
        LOG.info("uKey Linux Biometric Subsystem initializing...")
        local_bio = detect_host_biometric()
        if local_bio:
            LOG.info("Host hardware fingerprint sensor detected: %s", local_bio)
            LOG.info("Adaptive Hierarchy: PAM local sensor primary; uKey StrongBox ready for FIDO2/CTAP2 & fallback")
        else:
            LOG.info("Host has no built-in fingerprint sensor; uKey Android StrongBox bridge is primary authenticator")

        self.signer.start()
        try:
            self.device.open()
        except OSError as exc:
            LOG.error("cannot open %s: %s", self.args.uhid, exc)
            LOG.error("run setup_udev.sh first, or check that CONFIG_UHID is enabled")
            self.signer.stop()
            return 1

        LOG.info("virtual FIDO2 authenticator created")
        local_bio = detect_host_biometric()
        if local_bio:
            LOG.info("Host biometric hardware detected: %s", local_bio)
            LOG.info("Adaptive Biometric Hierarchy: PAM local sensor primary; uKey StrongBox ready for FIDO2/CTAP2 & fallback")
        else:
            LOG.info("No host fingerprint sensor found; uKey Android StrongBox bridge is primary authenticator")

        hidraw = None
        try:
            while not self.stop_event.is_set():
                if hidraw is None:
                    hidraw = find_hidraw_for_name(self.args.device_name)
                    if hidraw:
                        LOG.info("hidraw node: %s", hidraw)
                try:
                    readable, _, _ = select.select([self.device.fd], [], [], 0.2)
                except InterruptedError:
                    continue
                if not readable:
                    continue
                try:
                    event_type, event = self.device.read_event()
                except OSError as exc:
                    if self.stop_event.is_set():
                        break
                    LOG.error("UHID read failed: %s", exc)
                    break
                self._handle_uhid_event(event_type, event)
        finally:
            self.device.close()
            self.signer.stop()
            LOG.info("uKey daemon stopped")
        return 0

    def request_stop(self, signum: int, _frame: Any) -> None:
        LOG.info("received signal %d, stopping", signum)
        self.stop_event.set()

    # -- UHID events -------------------------------------------------------

    def _handle_uhid_event(self, event_type: int, event: _UhidEvent) -> None:
        if event_type == UHID_START:
            LOG.info("kernel acknowledged UHID device (START)")
        elif event_type == UHID_STOP:
            LOG.info("UHID device stopped by kernel")
        elif event_type == UHID_OPEN:
            LOG.info("hidraw consumer opened the device")
        elif event_type == UHID_CLOSE:
            LOG.info("hidraw consumer closed the device")
        elif event_type == UHID_OUTPUT:
            size = int(event.u.output.size)
            data = bytes(event.u.output.data[:size])
            self._handle_output_report(data)
        elif event_type == UHID_SET_REPORT:
            size = int(event.u.set_report.size)
            data = bytes(event.u.set_report.data[:size])
            self.device.reply_set_report(int(event.u.set_report.id), 0)
            self._handle_output_report(data)
        elif event_type == UHID_GET_REPORT:
            # The FIDO report descriptor defines no feature reports.
            LOG.debug("ignoring unsupported UHID_GET_REPORT")
        else:
            LOG.debug("unhandled UHID event type %d", event_type)

    def _handle_output_report(self, data: bytes) -> None:
        # The HID core prefixes an unnumbered output report with report ID 0
        # on this kernel. Accept both the canonical 64-byte report and the
        # 65-byte numbered form.
        if len(data) == HID_REPORT_SIZE + 1 and data[0] == 0:
            data = data[1:]
        if len(data) != HID_REPORT_SIZE:
            LOG.warning("ignoring %d-byte HID report (expected %d)", len(data), HID_REPORT_SIZE)
            return
        self._handle_packet(data)

    # -- CTAPHID -----------------------------------------------------------

    def _send_report(self, report: bytes) -> None:
        LOG.debug("HID input cid=0x%08x cmd=0x%02x len=%d", struct.unpack(">I", report[:4])[0], report[4], len(report))
        self.device.write_input_report(report)

    def _send_message(self, cid: int, command: int, payload: bytes) -> None:
        if len(payload) > CTAPHID_MAX_MESSAGE:
            raise ValueError("CTAPHID payload too large")
        cmd_byte = command | 0x80
        first = payload[:CTAPHID_INIT_PAYLOAD]
        report = struct.pack(">IBH", cid, cmd_byte, len(payload)) + first
        self._send_report(report.ljust(HID_REPORT_SIZE, b"\x00"))
        offset = len(first)
        seq = 0
        while offset < len(payload):
            chunk = payload[offset : offset + CTAPHID_CONT_PAYLOAD]
            report = struct.pack(">IB", cid, seq) + chunk
            self._send_report(report.ljust(HID_REPORT_SIZE, b"\x00"))
            offset += len(chunk)
            seq += 1

    def _send_error(self, cid: int, code: int) -> None:
        self._send_message(cid, CTAPHID_ERROR, bytes([code]))

    def _send_keepalive(self, cid: int, status: int = CTAPHID_STATUS_UPNEEDED) -> None:
        try:
            self._send_message(cid, CTAPHID_KEEPALIVE, bytes([status]))
        except OSError as exc:
            LOG.debug("failed to send keepalive: %s", exc)

    def _handle_packet(self, packet: bytes) -> None:
        cid = struct.unpack(">I", packet[:4])[0]
        command_byte = packet[4]
        LOG.debug("HID packet cid=0x%08x cmd=0x%02x", cid, command_byte)

        if command_byte & 0x80:
            command = command_byte & 0x7F
            length = struct.unpack(">H", packet[5:7])[0]
            data = packet[7:]
            self.pending.pop(cid, None)

            if cid == CTAPHID_BROADCAST and command != CTAPHID_INIT:
                self._send_error(cid, CTAPHID_ERR_INVALID_CHANNEL)
                return
            if command == CTAPHID_INIT:
                self._handle_init(cid, length, data)
                return
            if command == CTAPHID_CANCEL:
                self._handle_cancel(cid)
                return
            if cid not in self.channels:
                self._send_error(cid, CTAPHID_ERR_INVALID_CHANNEL)
                return

            if length > CTAPHID_MAX_MESSAGE:
                self._send_error(cid, CTAPHID_ERR_INVALID_LEN)
                return
            available = len(data)
            if length <= available:
                self._complete_message(cid, command, data[:length])
                return
            self.pending[cid] = {
                "command": command,
                "length": length,
                "data": bytearray(data),
                "seq": 0,
            }
            return

        # Continuation packet.
        if cid not in self.channels:
            self._send_error(cid, CTAPHID_ERR_INVALID_CHANNEL)
            return
        state = self.pending.get(cid)
        if state is None:
            self._send_error(cid, CTAPHID_ERR_INVALID_SEQ)
            return
        seq = packet[4]
        if seq != state["seq"]:
            self.pending.pop(cid, None)
            self._send_error(cid, CTAPHID_ERR_INVALID_SEQ)
            return
        state["data"].extend(packet[5:])
        state["seq"] += 1
        if len(state["data"]) >= state["length"]:
            data = bytes(state["data"][: state["length"]])
            command = state["command"]
            self.pending.pop(cid, None)
            self._complete_message(cid, command, data)

    def _handle_init(self, cid: int, length: int, data: bytes) -> None:
        if length != 8:
            self._send_error(cid, CTAPHID_ERR_INVALID_LEN)
            return
        nonce = data[:8]
        request_cid = cid
        if cid == CTAPHID_BROADCAST:
            cid = self._allocate_cid()
        self.channels.add(cid)
        response = (
            nonce
            + struct.pack(">I", cid)
            + bytes([2, 1, 0, 0, CTAPHID_CAP_CBOR | CTAPHID_CAP_NMSG])  # CTAPHID v2, fw 1.0.0, CAP_CBOR | CAP_NMSG
        )
        # INIT is answered on the channel it was received on; the allocated
        # channel is carried in the response payload. A broadcast INIT must
        # therefore be answered on 0xFFFFFFFF, not on the new CID.
        self._send_message(request_cid, CTAPHID_INIT, response)

    def _allocate_cid(self) -> int:
        while True:
            cid = struct.unpack(">I", secrets.token_bytes(4))[0]
            if cid not in (0, CTAPHID_BROADCAST) and cid not in self.channels:
                return cid

    def _complete_message(self, cid: int, command: int, payload: bytes) -> None:
        if command == CTAPHID_PING:
            self._send_message(cid, CTAPHID_PING, payload)
        elif command == CTAPHID_WINK:
            LOG.info("WINK requested")
            self._send_message(cid, CTAPHID_WINK, b"")
        elif command == CTAPHID_CBOR:
            self._dispatch_cbor(cid, payload)
        elif command == CTAPHID_MSG:
            LOG.info("CTAPHID_MSG received (%d bytes): %s", len(payload), payload.hex())
            self._send_message(cid, CTAPHID_MSG, bytes([0x6D, 0x00]))
        elif command == CTAPHID_LOCK:
            self._send_error(cid, CTAPHID_ERR_INVALID_CMD)
        else:
            self._send_error(cid, CTAPHID_ERR_INVALID_CMD)

    def _handle_cancel(self, cid: int) -> None:
        with self._tx_lock:
            if self._active_cid == cid and self._cancel is not None:
                LOG.info("cancelling active transaction on channel 0x%08x", cid)
                self._cancel.set()

    def _dispatch_cbor(self, cid: int, payload: bytes) -> None:
        if len(payload) > 1024:
            self._send_message(cid, CTAPHID_CBOR, bytes([CTAP2_ERR_REQUEST_TOO_LARGE]))
            return
        with self._tx_lock:
            if self._active_cid is not None:
                self._send_error(cid, CTAPHID_ERR_CHANNEL_BUSY)
                return
            self._active_cid = cid
            self._cancel = threading.Event()
            cancel = self._cancel

        thread = threading.Thread(
            target=self._run_ctap,
            args=(cid, payload, cancel),
            name="ctap2-worker",
            daemon=True,
        )
        thread.start()

    def _run_ctap(self, cid: int, payload: bytes, cancel: threading.Event) -> None:
        try:
            response = self.ctap.handle(payload, cancel, lambda: self._send_keepalive(cid))
            if cancel.is_set():
                response = bytes([CTAP2_ERR_KEEPALIVE_CANCEL])
            self._send_message(cid, CTAPHID_CBOR, response)
        except Exception:
            LOG.error("CTAP2 worker crashed:\n%s", traceback.format_exc())
            try:
                self._send_message(cid, CTAPHID_CBOR, bytes([CTAP2_ERR_OTHER]))
            except OSError:
                pass
        finally:
            with self._tx_lock:
                if self._active_cid == cid:
                    self._active_cid = None
                self._cancel = None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="uKey Phase 1 virtual FIDO2 authenticator")
    parser.add_argument("--uhid", default="/dev/uhid", help="UHID device path")
    parser.add_argument(
        "--device-name",
        default="uKey FIDO2 Authenticator",
        help="HID device name (must match the udev rule)",
    )
    parser.add_argument("--listen-host", default="127.0.0.1", help="signer bridge bind address")
    parser.add_argument("--port", type=int, default=8443, help="signer bridge port")
    parser.add_argument(
        "--attestation",
        choices=("self", "none"),
        default="self",
        help=(
            "MakeCredential attestation: 'self' is a packed self-attestation "
            "and works with fido2-cred(1); 'none' is the strict CTAP2 empty "
            "attestation (default: self)"
        ),
    )
    parser.add_argument(
        "--auto-lock",
        action="store_true",
        help="Proximity Walk-Away Lock: automatically lock the Linux screen via loginctl when the phone disconnects",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    handlers: list[logging.Handler] = [logging.StreamHandler(), logging.FileHandler("/tmp/ukey.log", mode="a")]
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )
    daemon = UKeyDaemon(args)
    signal.signal(signal.SIGINT, daemon.request_stop)
    signal.signal(signal.SIGTERM, daemon.request_stop)
    return daemon.run()


if __name__ == "__main__":
    sys.exit(main())
