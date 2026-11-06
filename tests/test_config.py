#!/usr/bin/env python3
"""Tests for configuration loading and CLI precedence."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "daemon"))

import ukey_config  # noqa: E402


def _args(**overrides):
    values = {
        "enabled": None,
        "wireless": None,
        "auto_lock": None,
        "auto_lock_grace_seconds": None,
        "listen_host": None,
        "port": None,
        "device_name": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ukey" / "config.json"

    def test_defaults_are_safe(self) -> None:
        config = ukey_config.load_config(self.path)
        self.assertTrue(config.enabled)
        self.assertFalse(config.wireless)
        self.assertFalse(config.auto_lock)
        self.assertEqual(config.auto_lock_grace_seconds, 5)
        self.assertEqual(config.listen_host, "127.0.0.1")
        self.assertEqual(config.port, 8443)
        self.assertEqual(config.device_name, "uKey FIDO2 Authenticator")

    def test_create_writes_mode_0600(self) -> None:
        config = ukey_config.load_config(self.path, create=True)
        self.assertTrue(self.path.exists())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        data = json.loads(self.path.read_text())
        self.assertEqual(data["auto_lock"], False)
        self.assertEqual(data["wireless"], False)
        self.assertEqual(config.auto_lock, False)

    def test_unknown_key_is_rejected(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"wireles": True}))
        with self.assertRaises(ukey_config.ConfigError):
            ukey_config.load_config(self.path)

    def test_invalid_values_are_rejected(self) -> None:
        for data in (
            {"wireless": "yes"},
            {"auto_lock": 1},
            {"auto_lock_grace_seconds": -1},
            {"auto_lock_grace_seconds": True},
            {"port": 0},
            {"port": 65536},
            {"listen_host": ""},
            {"device_name": "two\nlines"},
        ):
            with self.subTest(data=data):
                with self.assertRaises(ukey_config.ConfigError):
                    ukey_config.validate_config(data)

    def test_cli_wireless_overrides_and_binds_all_interfaces(self) -> None:
        config = ukey_config.load_config(self.path)
        resolved = ukey_config.resolve_config(_args(wireless=True), path=self.path)
        self.assertFalse(config.wireless)
        self.assertTrue(resolved.wireless)
        self.assertEqual(resolved.listen_host, "0.0.0.0")

    def test_no_wireless_wins_over_config(self) -> None:
        ukey_config.save_config({"wireless": True, "listen_host": "0.0.0.0"}, self.path)
        resolved = ukey_config.resolve_config(_args(wireless=False), path=self.path)
        self.assertFalse(resolved.wireless)
        self.assertEqual(resolved.listen_host, "127.0.0.1")

        resolved = ukey_config.resolve_config(
            _args(wireless=False, listen_host="127.0.0.1"), path=self.path
        )
        self.assertFalse(resolved.wireless)
        self.assertEqual(resolved.listen_host, "127.0.0.1")

    def test_cli_values_override_file(self) -> None:
        ukey_config.save_config(
            {
                "auto_lock": False,
                "auto_lock_grace_seconds": 9,
                "port": 8443,
                "device_name": "from-file",
            },
            self.path,
        )
        resolved = ukey_config.resolve_config(
            _args(auto_lock=True, auto_lock_grace_seconds=0, port=9443, device_name="from-cli"),
            path=self.path,
        )
        self.assertTrue(resolved.auto_lock)
        self.assertEqual(resolved.auto_lock_grace_seconds, 0)
        self.assertEqual(resolved.port, 9443)
        self.assertEqual(resolved.device_name, "from-cli")

    def test_save_is_atomic_and_readable(self) -> None:
        ukey_config.save_config({"auto_lock": True}, self.path)
        raw = self.path.read_text()
        self.assertIn('"auto_lock": true', raw)
        self.assertFalse(any(self.path.parent.glob(".config-*")))

    def test_ukey_config_environment_selects_path(self) -> None:
        env = {ukey_config.CONFIG_ENV: str(self.path)}
        self.assertEqual(ukey_config.config_path(env), self.path)


if __name__ == "__main__":
    unittest.main()
