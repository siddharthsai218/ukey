#!/usr/bin/env python3
"""In-process tests for the Phase 1 CTAPHID and CTAP2 code.

These tests do not touch /dev/uhid. They use a fake HID transport and the same
software P-256 implementation as mock_signer.py, then verify the ECDSA
signature independently.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import time
import unittest
from pathlib import Path

import cbor2

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "daemon"))

import mock_signer  # noqa: E402
import ukey_daemon as daemon_mod  # noqa: E402


def _verify(pub: tuple[int, int], digest: bytes, signature: bytes) -> bool:
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < mock_signer.N and 1 <= s < mock_signer.N):
        return False
    z = int.from_bytes(digest, "big")
    w = pow(s, -1, mock_signer.N)
    u1 = (z * w) % mock_signer.N
    u2 = (r * w) % mock_signer.N
    point = mock_signer._point_add(
        mock_signer._scalar_mult(u1, (mock_signer.GX, mock_signer.GY)),
        mock_signer._scalar_mult(u2, pub),
    )
    return point is not None and point[0] % mock_signer.N == r


def _der_to_raw(signature: bytes) -> bytes:
    if len(signature) < 8 or signature[0] != 0x30:
        raise ValueError("not a DER sequence")
    length = signature[1]
    if length & 0x80:
        raise ValueError("unexpected long-form DER length")
    body = signature[2 : 2 + length]
    if len(body) != length:
        raise ValueError("truncated DER signature")

    def read_int(offset: int) -> tuple[int, int]:
        if body[offset] != 0x02:
            raise ValueError("not a DER integer")
        size = body[offset + 1]
        value = int.from_bytes(body[offset + 2 : offset + 2 + size], "big")
        return value, offset + 2 + size

    r, offset = read_int(0)
    s, offset = read_int(offset)
    if offset != len(body):
        raise ValueError("trailing DER data")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class FakeSigner:
    def __init__(self) -> None:
        self.keys: dict[str, tuple[int, tuple[int, int], str]] = {}

    def request(self, payload, cancel, keepalive):
        keepalive()
        if payload["action"] == "make_credential":
            private, public = mock_signer.generate_key()
            cred_id = b"\x11" * 16
            self.keys[cred_id.hex()] = (private, public, payload["rp_id"])
            return {
                "pub_key_x": public[0].to_bytes(32, "big").hex(),
                "pub_key_y": public[1].to_bytes(32, "big").hex(),
                "cred_id": cred_id.hex(),
            }
        if payload["action"] == "attest":
            private, public, _rp_id = self.keys[payload["cred_id"]]
            signature = mock_signer.sign_digest(private, bytes.fromhex(payload["digest"]))
            return {"raw_sig": signature.hex()}
        if payload["action"] == "get_assertion":
            private, public, rp_id = self.keys[payload["cred_id"]]
            assert rp_id == payload["rp_id"]
            signature = mock_signer.sign_digest(private, bytes.fromhex(payload["digest"]))
            return {"raw_sig": signature.hex()}
        raise AssertionError(payload["action"])


class FakeHid:
    def __init__(self) -> None:
        self.reports: list[bytes] = []

    def write_input_report(self, report: bytes) -> None:
        assert len(report) == 64
        self.reports.append(report)


def initial_packet(cid: int, command: int, payload: bytes) -> bytes:
    body = payload[:57].ljust(57, b"\x00")
    return struct.pack(">IBH", cid, 0x80 | command, len(payload)) + body


def cont_packet(cid: int, seq: int, payload: bytes) -> bytes:
    return struct.pack(">IB", cid, seq) + payload[:59].ljust(59, b"\x00")


def decode_reports(reports: list[bytes]) -> tuple[int, int, bytes]:
    cid, cmd, length = struct.unpack(">IBH", reports[0][:7])
    payload = bytearray(reports[0][7:])
    for report in reports[1:]:
        payload.extend(report[5:])
    return cid, cmd & 0x7F, bytes(payload[:length])


class CtapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = FakeSigner()
        self.engine = daemon_mod.Ctap2Engine(self.signer)
        self.cancel = daemon_mod.threading.Event()

    def call(self, command: int, params: dict | None = None) -> dict:
        payload = bytes([command])
        if params is not None:
            payload += cbor2.dumps(params)
        response = self.engine.handle(payload, self.cancel, lambda: None)
        self.assertEqual(response[0], daemon_mod.CTAP2_OK, response)
        self.assertGreater(len(response), 1, response)
        return cbor2.loads(response[1:])

    def make_request(self) -> dict:
        return {
            1: b"c" * 32,
            2: {"id": "example.com", "name": "Example"},
            3: {"id": b"user-id", "name": "user", "displayName": "User"},
            4: [{"type": "public-key", "alg": -7}],
        }

    def test_get_info(self) -> None:
        info = self.call(daemon_mod.CTAP2_CMD_GET_INFO)
        self.assertEqual(info[1], ["FIDO_2_0"])
        self.assertEqual(info[3], daemon_mod.AAGUID)
        self.assertEqual(info[4]["uv"], True)
        self.assertEqual(info[9], ["usb"])

    def test_make_and_assert(self) -> None:
        result = self.call(daemon_mod.CTAP2_CMD_MAKE_CREDENTIAL, self.make_request())
        self.assertEqual(result[1], "packed")
        auth_data = result[2]
        self.assertEqual(auth_data[:32], hashlib.sha256(b"example.com").digest())
        self.assertEqual(auth_data[32], 0x45)
        self.assertEqual(auth_data[37:53], daemon_mod.AAGUID)
        cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
        cred_id = auth_data[55 : 55 + cred_id_len]
        cose_key = cbor2.loads(auth_data[55 + cred_id_len :])
        self.assertEqual(cose_key[1], 2)
        self.assertEqual(cose_key[3], -7)

        private, public, _ = self.signer.keys[cred_id.hex()]
        attest_digest = hashlib.sha256(auth_data + b"c" * 32).digest()
        self.assertEqual(result[3]["alg"], -7)
        self.assertEqual(result[3]["sig"][0], 0x30)
        self.assertTrue(_verify(public, attest_digest, _der_to_raw(result[3]["sig"])))

        assertion = self.call(
            daemon_mod.CTAP2_CMD_GET_ASSERTION,
            {
                1: "example.com",
                2: b"d" * 32,
                3: [{"type": "public-key", "id": cred_id}],
            },
        )
        self.assertEqual(assertion[1]["id"], cred_id)
        auth = assertion[2]
        self.assertEqual(auth[32], 0x05)
        digest = hashlib.sha256(auth + b"d" * 32).digest()
        private, public, _ = self.signer.keys[cred_id.hex()]
        self.assertEqual(assertion[3][0], 0x30)
        self.assertTrue(_verify(public, digest, _der_to_raw(assertion[3])))

    def test_exclude_list(self) -> None:
        result = self.call(daemon_mod.CTAP2_CMD_MAKE_CREDENTIAL, self.make_request())
        auth_data = result[2]
        cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
        cred_id = auth_data[55 : 55 + cred_id_len]
        request = self.make_request()
        request[5] = [{"type": "public-key", "id": cred_id}]
        response = self.engine.handle(
            bytes([daemon_mod.CTAP2_CMD_MAKE_CREDENTIAL]) + cbor2.dumps(request),
            self.cancel,
            lambda: None,
        )
        self.assertEqual(response, bytes([daemon_mod.CTAP2_ERR_CREDENTIAL_EXCLUDED]))

    def test_unknown_credential(self) -> None:
        response = self.engine.handle(
            bytes([daemon_mod.CTAP2_CMD_GET_ASSERTION])
            + cbor2.dumps(
                {
                    1: "example.com",
                    2: b"d" * 32,
                    3: [{"type": "public-key", "id": b"\x99" * 16}],
                }
            ),
            self.cancel,
            lambda: None,
        )
        self.assertEqual(response, bytes([daemon_mod.CTAP2_ERR_NO_CREDENTIALS]))

    def test_command_byte_is_required(self) -> None:
        response = self.engine.handle(b"", self.cancel, lambda: None)
        self.assertEqual(response, bytes([daemon_mod.CTAP2_ERR_INVALID_LENGTH]))

    def test_none_attestation_mode(self) -> None:
        engine = daemon_mod.Ctap2Engine(FakeSigner(), attestation="none")
        payload = bytes([daemon_mod.CTAP2_CMD_MAKE_CREDENTIAL]) + cbor2.dumps(self.make_request())
        response = engine.handle(payload, self.cancel, lambda: None)
        self.assertEqual(response[0], daemon_mod.CTAP2_OK)
        result = cbor2.loads(response[1:])
        self.assertEqual(result[1], "none")
        self.assertEqual(result[3], {})


class CtaphidTests(unittest.TestCase):
    def setUp(self) -> None:
        args = argparse.Namespace(
            uhid="/dev/uhid",
            device_name="uKey FIDO2 Authenticator",
            listen_host="127.0.0.1",
            port=18443,
            attestation="self",
            verbose=False,
        )
        self.daemon = daemon_mod.UKeyDaemon(args)
        self.hid = FakeHid()
        self.daemon.device = self.hid
        self.daemon.ctap = daemon_mod.Ctap2Engine(FakeSigner())

    def wait_reports(self, count: int, timeout: float = 3.0) -> list[bytes]:
        deadline = time.monotonic() + timeout
        while len(self.hid.reports) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        return self.hid.reports

    def test_init_ping_and_fragmented_ping(self) -> None:
        nonce = b"12345678"
        self.daemon._handle_packet(initial_packet(0xFFFFFFFF, daemon_mod.CTAPHID_INIT, nonce))
        cid, cmd, payload = decode_reports(self.wait_reports(1))
        self.assertEqual(cmd, daemon_mod.CTAPHID_INIT)
        self.assertEqual(payload[:8], nonce)
        allocated = struct.unpack(">I", payload[8:12])[0]
        self.assertNotIn(allocated, (0, 0xFFFFFFFF))
        self.assertEqual(payload[12], 2)
        self.assertEqual(payload[13:16], b"\x01\x00\x00")
        self.assertEqual(payload[16], daemon_mod.CTAPHID_CAP_CBOR | daemon_mod.CTAPHID_CAP_NMSG)
        self.assertEqual(cid, 0xFFFFFFFF)

        self.hid.reports.clear()
        ping = b"A" * 120
        self.daemon._handle_packet(initial_packet(allocated, daemon_mod.CTAPHID_PING, ping))
        self.daemon._handle_packet(cont_packet(allocated, 0, ping[57:116]))
        self.daemon._handle_packet(cont_packet(allocated, 1, ping[116:]))
        reports = self.wait_reports(3)
        cid2, cmd2, echoed = decode_reports(reports)
        self.assertEqual((cid2, cmd2, echoed), (allocated, daemon_mod.CTAPHID_PING, ping))

    def test_get_info_over_ctaphid(self) -> None:
        nonce = b"abcdefgh"
        self.daemon._handle_packet(initial_packet(0xFFFFFFFF, daemon_mod.CTAPHID_INIT, nonce))
        _, _, init_payload = decode_reports(self.wait_reports(1))
        cid = struct.unpack(">I", init_payload[8:12])[0]
        self.hid.reports.clear()
        request = bytes([daemon_mod.CTAP2_CMD_GET_INFO])
        self.daemon._handle_packet(initial_packet(cid, daemon_mod.CTAPHID_CBOR, request))
        deadline = time.monotonic() + 3
        while not self.hid.reports and time.monotonic() < deadline:
            time.sleep(0.01)
        _, cmd, payload = decode_reports(self.hid.reports)
        self.assertEqual(cmd, daemon_mod.CTAPHID_CBOR)
        self.assertEqual(payload[0], daemon_mod.CTAP2_OK)
        info = cbor2.loads(payload[1:])
        self.assertEqual(info[1], ["FIDO_2_0"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
