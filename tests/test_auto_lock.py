#!/usr/bin/env python3
"""Tests for the opt-in auto-lock behavior.

These tests use a fake loginctl in PATH and never touch the real session.
"""

from __future__ import annotations

import argparse
import os
import socket
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "daemon"))

import ukey_daemon as daemon_mod  # noqa: E402


class AutoLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)
        self.log_path = self.temp_path / "loginctl.log"
        self.fake_bin = self.temp_path / "bin"
        self.fake_bin.mkdir()
        fake = self.fake_bin / "loginctl"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"$UKEY_LOGINCTL_LOG\"\n"
            "if [[ \"$1\" == \"show-session\" ]]; then\n"
            "  echo \"${UKEY_SESSION_LOCKED:-no}\"\n"
            "fi\n"
            "exit 0\n"
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        self.env = mock.patch.dict(
            os.environ,
            {
                "PATH": f"{self.fake_bin}:{os.environ.get('PATH', '')}",
                "UKEY_LOGINCTL_LOG": str(self.log_path),
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self._old_session = os.environ.pop("XDG_SESSION_ID", None)

    def tearDown(self) -> None:
        if self._old_session is not None:
            os.environ["XDG_SESSION_ID"] = self._old_session

    def make_daemon(self, *, auto_lock: bool, grace: int = 0) -> daemon_mod.UKeyDaemon:
        args = argparse.Namespace(
            uhid="/dev/uhid",
            device_name="uKey Test",
            listen_host="127.0.0.1",
            port=18444,
            attestation="self",
            auto_lock=auto_lock,
            auto_lock_grace_seconds=grace,
            wireless=False,
            verbose=False,
        )
        daemon = daemon_mod.UKeyDaemon(args)
        self.addCleanup(daemon._cancel_auto_lock)
        return daemon

    def calls(self) -> list[str]:
        if not self.log_path.exists():
            return []
        return [line for line in self.log_path.read_text().splitlines() if line]

    def wait_for(self, predicate, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def test_disabled_does_not_call_loginctl(self) -> None:
        daemon = self.make_daemon(auto_lock=False)
        daemon._on_signer_connect()
        daemon._on_signer_disconnect()
        time.sleep(0.25)
        self.assertEqual(self.calls(), [])

    def test_disconnect_before_first_connection_does_not_lock(self) -> None:
        daemon = self.make_daemon(auto_lock=True)
        daemon._on_signer_disconnect()
        time.sleep(0.25)
        self.assertEqual(self.calls(), [])

    def test_grace_zero_calls_lock_once(self) -> None:
        daemon = self.make_daemon(auto_lock=True, grace=0)
        daemon._on_signer_connect()
        daemon._on_signer_disconnect()
        self.assertTrue(self.wait_for(lambda: self.calls().count("lock-session") == 1))
        time.sleep(0.1)
        self.assertEqual(self.calls().count("lock-session"), 1)

    def test_reconnect_within_grace_cancels_lock(self) -> None:
        daemon = self.make_daemon(auto_lock=True, grace=1)
        daemon._on_signer_connect()
        daemon._on_signer_disconnect()
        time.sleep(0.15)
        daemon._on_signer_connect()
        time.sleep(1.2)
        self.assertEqual(self.calls(), [])

    def test_duplicate_disconnect_is_debounced(self) -> None:
        daemon = self.make_daemon(auto_lock=True, grace=0)
        daemon._on_signer_connect()
        daemon._on_signer_disconnect()
        daemon._on_signer_disconnect()
        daemon._on_signer_disconnect()
        self.assertTrue(self.wait_for(lambda: self.calls().count("lock-session") == 1))
        time.sleep(0.15)
        self.assertEqual(self.calls().count("lock-session"), 1)

    def test_already_locked_session_is_not_locked_again(self) -> None:
        os.environ["XDG_SESSION_ID"] = "1"
        os.environ["UKEY_SESSION_LOCKED"] = "yes"
        daemon = self.make_daemon(auto_lock=True, grace=0)
        daemon._on_signer_connect()
        daemon._on_signer_disconnect()
        self.assertTrue(self.wait_for(lambda: any(line.startswith("show-session") for line in self.calls())))
        time.sleep(0.15)
        self.assertEqual(self.calls().count("lock-session"), 0)

    def test_shutdown_does_not_lock(self) -> None:
        daemon = self.make_daemon(auto_lock=True, grace=0)
        daemon._on_signer_connect()
        daemon._shutting_down = True
        daemon._on_signer_disconnect()
        time.sleep(0.25)
        self.assertEqual(self.calls(), [])


class SignerBridgeTests(unittest.TestCase):
    def start_bridge(self) -> tuple[daemon_mod.SignerBridge, list[str]]:
        events: list[str] = []
        bridge = daemon_mod.SignerBridge(
            "127.0.0.1",
            0,
            on_connect=lambda: events.append("connect"),
            on_disconnect=lambda: events.append("disconnect"),
        )
        bridge.start()
        self.addCleanup(bridge.stop)
        return bridge, events

    @staticmethod
    def wait_for(predicate, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def port(self, bridge: daemon_mod.SignerBridge) -> int:
        assert bridge._server is not None
        return bridge._server.getsockname()[1]

    def test_idle_disconnect_is_detected(self) -> None:
        bridge, events = self.start_bridge()
        client = socket.create_connection(("127.0.0.1", self.port(bridge)), timeout=2)
        self.addCleanup(client.close)
        self.assertTrue(self.wait_for(lambda: "connect" in events))
        self.assertTrue(bridge.connected)
        client.shutdown(socket.SHUT_WR)
        client.close()
        self.assertTrue(self.wait_for(lambda: "disconnect" in events))
        self.assertFalse(bridge.connected)

    def test_replacement_connection_is_a_reconnect_not_a_disconnect(self) -> None:
        bridge, events = self.start_bridge()
        first = socket.create_connection(("127.0.0.1", self.port(bridge)), timeout=2)
        self.addCleanup(first.close)
        self.assertTrue(self.wait_for(lambda: events.count("connect") == 1))

        second = socket.create_connection(("127.0.0.1", self.port(bridge)), timeout=2)
        self.addCleanup(second.close)
        self.assertTrue(self.wait_for(lambda: events.count("connect") == 2))
        self.assertEqual(events.count("disconnect"), 0)

        second.shutdown(socket.SHUT_WR)
        second.close()
        self.assertTrue(self.wait_for(lambda: events.count("disconnect") == 1))


if __name__ == "__main__":
    unittest.main()
