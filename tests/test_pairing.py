#!/usr/bin/env python3
"""Unit tests for the uKey device pairing and token authentication system."""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.ukey_pairing import PairingManager


class TestPairingManager(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp())
        self.pairing_file = self.temp_dir / "pairing.json"
        self.manager = PairingManager(path=self.pairing_file)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pin_generation_and_persistence(self) -> None:
        pin = self.manager.get_or_create_pin()
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isdigit())

        # Calling again should return the same active PIN
        pin2 = self.manager.get_or_create_pin()
        self.assertEqual(pin, pin2)

        # Force new PIN
        pin3 = self.manager.get_or_create_pin(force_new=True)
        self.assertEqual(len(pin3), 6)

    def test_successful_pairing_flow(self) -> None:
        pin = self.manager.get_or_create_pin()
        token = self.manager.pair_with_pin(pin, device_name="Test Phone Pixel 8")

        self.assertIsNotNone(token)
        self.assertEqual(len(token), 64)  # 32 bytes in hex

        # Token should now verify successfully
        self.assertTrue(self.manager.verify_token(token))

        # Re-using the same PIN must fail (single-use)
        second_attempt = self.manager.pair_with_pin(pin, device_name="Attacker Phone")
        self.assertIsNone(second_attempt)

    def test_invalid_pin_rejection(self) -> None:
        self.manager.get_or_create_pin()
        result = self.manager.pair_with_pin("000000", device_name="Rogue Device")
        self.assertIsNone(result)

    def test_pin_brute_force_lockout(self) -> None:
        valid_pin = self.manager.get_or_create_pin()
        # 4 failed attempts should not lock out
        for _ in range(4):
            self.assertIsNone(self.manager.pair_with_pin("999999", device_name="Attacker"))
        # 5th failed attempt triggers lockout and invalidates PIN
        self.assertIsNone(self.manager.pair_with_pin("999999", device_name="Attacker"))
        # Even the original valid PIN must now be rejected during lockout
        self.assertIsNone(self.manager.pair_with_pin(valid_pin, device_name="Legit Device"))

    def test_unknown_token_rejection(self) -> None:
        self.assertFalse(self.manager.verify_token("deadbeef" * 8))
        self.assertFalse(self.manager.verify_token(""))

    def test_device_persistence_across_reloads(self) -> None:
        pin = self.manager.get_or_create_pin()
        token = self.manager.pair_with_pin(pin, device_name="Galaxy S24")
        self.assertIsNotNone(token)

        # Reload manager from disk
        reloaded = PairingManager(path=self.pairing_file)
        self.assertEqual(reloaded.paired_count, 1)
        self.assertTrue(reloaded.verify_token(token))

        devices = reloaded.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["device_name"], "Galaxy S24")

    def test_device_revocation(self) -> None:
        pin = self.manager.get_or_create_pin()
        token = self.manager.pair_with_pin(pin, device_name="Old Phone")
        self.assertTrue(self.manager.verify_token(token))

        devices = self.manager.list_devices()
        dev_id = devices[0]["id"]

        self.assertTrue(self.manager.revoke_device(dev_id))
        self.assertFalse(self.manager.verify_token(token))
        self.assertEqual(self.manager.paired_count, 0)


if __name__ == "__main__":
    unittest.main()
