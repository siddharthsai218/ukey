#!/usr/bin/env python3
"""Tests for SignerBridge authentication handshake and master pause toggle."""

from __future__ import annotations

import json
import shutil
import socket
import tempfile
import threading
import time
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "daemon"))

from ukey_pairing import PairingManager
from ukey_daemon import (
    SignerBridge,
    Ctap2Engine,
    CtapError,
    CTAP2_ERR_NO_CREDENTIALS,
)


class TestSignerBridgeHandshake(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp())
        self.pairing_file = self.temp_dir / "pairing.json"
        self.pairing = PairingManager(path=self.pairing_file)

        # Allocate an ephemeral port for testing
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("127.0.0.1", 0))
        self.port = temp_sock.getsockname()[1]
        temp_sock.close()

        self.bridge = SignerBridge(
            host="127.0.0.1",
            port=self.port,
            pairing_manager=self.pairing,
        )
        self.bridge.start()

    def tearDown(self) -> None:
        self.bridge.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_localhost_unprompted_client_accepted(self) -> None:
        """Localhost clients (like test mock_signer) that send no handshake are accepted."""
        client = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
        try:
            # Wait briefly for bridge to accept
            time.sleep(0.3)
            self.assertTrue(self.bridge.connected)
        finally:
            client.close()

    def test_successful_pairing_handshake(self) -> None:
        pin = self.pairing.get_or_create_pin()
        client = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
        try:
            payload = json.dumps({"action": "pair", "pin": pin, "device_name": "Pixel 7"}).encode() + b"\n"
            client.sendall(payload)

            client.settimeout(2.0)
            resp_line = client.makefile().readline()
            data = json.loads(resp_line)

            self.assertEqual(data.get("status"), "ok")
            self.assertIn("token", data)
            self.assertEqual(len(data["token"]), 64)

            time.sleep(0.1)
            self.assertTrue(self.bridge.connected)
            self.assertTrue(self.pairing.verify_token(data["token"]))
        finally:
            client.close()

    def test_invalid_pin_rejected_and_dropped(self) -> None:
        self.pairing.get_or_create_pin()
        client = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
        try:
            payload = json.dumps({"action": "pair", "pin": "000000", "device_name": "Rogue Phone"}).encode() + b"\n"
            client.sendall(payload)

            client.settimeout(2.0)
            resp_line = client.makefile().readline()
            data = json.loads(resp_line)

            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error"), "invalid_pin")

            time.sleep(0.1)
            self.assertFalse(self.bridge.connected)
        finally:
            client.close()

    def test_subsequent_token_auth_handshake(self) -> None:
        pin = self.pairing.get_or_create_pin()
        token = self.pairing.pair_with_pin(pin, device_name="Galaxy S24")
        self.assertIsNotNone(token)

        client = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
        try:
            payload = json.dumps({"action": "auth", "token": token, "device_name": "Galaxy S24"}).encode() + b"\n"
            client.sendall(payload)

            client.settimeout(2.0)
            resp_line = client.makefile().readline()
            data = json.loads(resp_line)

            self.assertEqual(data.get("status"), "ok")
            time.sleep(0.1)
            self.assertTrue(self.bridge.connected)
        finally:
            client.close()

    def test_invalid_token_rejected(self) -> None:
        client = socket.create_connection(("127.0.0.1", self.port), timeout=2.0)
        try:
            payload = json.dumps({"action": "auth", "token": "invalid" * 8, "device_name": "Hacker Phone"}).encode() + b"\n"
            client.sendall(payload)

            client.settimeout(2.0)
            resp_line = client.makefile().readline()
            data = json.loads(resp_line)

            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error"), "unauthorized")

            time.sleep(0.1)
            self.assertFalse(self.bridge.connected)
        finally:
            client.close()


class TestMasterToggleInterception(unittest.TestCase):
    def test_get_assertion_bypassed_when_disabled(self) -> None:
        enabled = False
        ctap = Ctap2Engine(
            signer=None,  # type: ignore
            is_enabled=lambda: enabled,
        )

        cancel = threading.Event()
        with self.assertRaises(CtapError) as ctx:
            ctap._get_assertion({1: "example.com", 2: b"\x00" * 32}, cancel, lambda: None)
        self.assertEqual(ctx.exception.code, CTAP2_ERR_NO_CREDENTIALS)


if __name__ == "__main__":
    unittest.main()
