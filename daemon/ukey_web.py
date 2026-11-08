#!/usr/bin/env python3
"""Lightweight local web settings dashboard for uKey.

Runs on http://127.0.0.1:8444 to provide a user-friendly settings console on
the laptop to control:
- Master Toggle (Enable / Pause biometric interception)
- One-Time Device Pairing PIN & QR Code
- Authorized Paired Devices (with revocation)
- Live Security Audit Log & Enrolled Credentials

Security: Only binds to 127.0.0.1 (local machine). Not accessible over the network.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

LOG = logging.getLogger("ukey.web")

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uKey — Security Dashboard & Settings</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #090d16;
    --card: #111827;
    --border: rgba(255, 255, 255, 0.08);
    --text: #f3f4f6;
    --text-muted: #9ca3af;
    --accent: #10b981;
    --accent-glow: rgba(16, 185, 129, 0.2);
    --cyan: #38bdf8;
    --danger: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    padding: 32px 20px;
    min-height: 100vh;
  }
  .container { max-width: 820px; margin: 0 auto; }
  header {
    display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px; margin-bottom: 28px;
  }
  .logo {
    display: flex; align-items: center; gap: 10px;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 22px; font-weight: 700; color: #fff;
  }
  .logo span { color: var(--accent); }
  .badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 99px;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    background: var(--card); border: 1px solid var(--border);
  }
  .badge.connected { color: var(--accent); border-color: rgba(16, 185, 129, 0.3); }
  .badge.disconnected { color: var(--text-muted); }
  .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

  /* Master Switch Card */
  .switch-card {
    background: linear-gradient(135deg, #131d31 0%, #0c1220 100%);
    border: 1px solid rgba(56, 189, 248, 0.25);
    border-radius: 12px; padding: 22px 24px;
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 24px;
  }
  .switch-info h2 { font-size: 17px; font-weight: 700; margin-bottom: 4px; color: #fff; }
  .switch-info p { color: var(--text-muted); font-size: 12.5px; }
  .toggle-btn {
    padding: 10px 20px; border-radius: 8px; font-weight: 700;
    font-size: 13px; cursor: pointer; transition: all 0.2s;
    border: none;
  }
  .toggle-btn.active {
    background: var(--accent); color: #000;
    box-shadow: 0 0 16px var(--accent-glow);
  }
  .toggle-btn.paused {
    background: #374151; color: #fff;
  }

  /* Grid Layout */
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px; padding: 20px;
  }
  .card-title {
    font-size: 13px; font-weight: 700; color: #fff;
    text-transform: uppercase; letter-spacing: 0.5px;
    margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;
  }

  /* Pairing PIN Display */
  .pin-display {
    background: #090d16; border: 1px dashed rgba(16, 185, 129, 0.4);
    border-radius: 8px; padding: 14px; text-align: center;
    margin-bottom: 12px;
  }
  .pin-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 32px; font-weight: 700;
    letter-spacing: 8px; color: var(--accent);
  }
  .pin-note { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
  .btn-sm {
    background: #1f2937; border: 1px solid var(--border);
    color: var(--text); padding: 6px 12px; border-radius: 6px;
    font-size: 11px; font-weight: 600; cursor: pointer;
  }
  .btn-sm:hover { background: #374151; }

  /* Device List */
  .device-item {
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 12px; background: #090d16; border-radius: 6px;
    border: 1px solid var(--border); margin-bottom: 8px;
  }
  .device-meta { font-size: 11px; color: var(--text-muted); }
  .btn-danger {
    background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3);
    color: var(--danger); padding: 4px 8px; border-radius: 4px;
    font-size: 11px; cursor: pointer;
  }
  .btn-danger:hover { background: rgba(239, 68, 68, 0.25); }

  /* Audit Log */
  .log-box {
    background: #090d16; border-radius: 8px; border: 1px solid var(--border);
    padding: 12px; font-family: 'JetBrains Mono', monospace;
    font-size: 11px; max-height: 180px; overflow-y: auto;
  }
  .log-line { margin-bottom: 4px; color: var(--text-muted); }
  .log-line.ok { color: var(--accent); }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      uKey <span>Dashboard</span>
    </div>
    <div id="statusBadge" class="badge disconnected">
      <div class="dot"></div>
      <span id="statusText">Checking...</span>
    </div>
  </header>

  <!-- Master Interception Toggle -->
  <div class="switch-card">
    <div class="switch-info">
      <h2 id="masterStateTitle">uKey Biometric Interception</h2>
      <p id="masterStateDesc">When Active, sudo and WebAuthn prompt your phone. When Paused, sudo uses password directly.</p>
    </div>
    <button id="toggleBtn" class="toggle-btn active" onclick="toggleMaster()">ACTIVE</button>
  </div>

  <div class="grid">
    <!-- One-Time Pairing PIN -->
    <div class="card">
      <div class="card-title">
        <span>One-Time Pairing PIN</span>
        <button class="btn-sm" onclick="generateNewPin()">Generate New</button>
      </div>
      <p style="color:var(--text-muted); font-size:11.5px; margin-bottom:12px;">
        Enter this 6-digit PIN in your Android app <b>once</b>. Your phone will receive a permanent auth token and connect automatically forever after.
      </p>
      <div class="pin-display">
        <div class="pin-num" id="activePin">------</div>
        <div class="pin-note">Zero-PIN auto-connect active after first pairing</div>
      </div>
      <div style="font-size:11px; color:var(--text-muted);">
        Connection Target: <code id="hostTarget" style="color:var(--cyan); background:#090d16; padding:2px 6px; border-radius:4px;">10.59.72.79:8443</code>
      </div>
    </div>

    <!-- Authorized Paired Devices -->
    <div class="card">
      <div class="card-title">
        <span>Authorized Devices</span>
        <span id="deviceCount" style="color:var(--text-muted); font-size:11px;">0 Paired</span>
      </div>
      <p style="color:var(--text-muted); font-size:11.5px; margin-bottom:12px;">
        Only authorized devices can connect over Wi-Fi. Rogue strangers on the same network are dropped immediately.
      </p>
      <div id="deviceList">
        <div style="color:var(--text-muted); font-size:11.5px; font-style:italic;">No devices paired yet.</div>
      </div>
    </div>
  </div>

  <!-- Real-Time Audit Log -->
  <div class="card">
    <div class="card-title">
      <span>Hardware Security Audit Ledger</span>
      <span style="color:var(--cyan); font-size:11px;">Live / Real-Time</span>
    </div>
    <div class="log-box" id="auditLog">
      <div class="log-line ok">[Ready] Daemon listening on 0.0.0.0:8443</div>
      <div class="log-line">[System] Virtual HID security key (/dev/uhid) active</div>
    </div>
  </div>
</div>

<script>
let currentState = null;

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    currentState = data;
    render(data);
  } catch (err) {
    console.error("Failed to fetch status:", err);
  }
}

function render(data) {
  // Status Badge
  const badge = document.getElementById('statusBadge');
  const statusText = document.getElementById('statusText');
  if (data.connected) {
    badge.className = "badge connected";
    statusText.textContent = `Phone Connected (${data.peer_ip || 'USB'})`;
  } else {
    badge.className = "badge disconnected";
    statusText.textContent = "Waiting for phone";
  }

  // Master Toggle
  const toggleBtn = document.getElementById('toggleBtn');
  const masterTitle = document.getElementById('masterStateTitle');
  if (data.enabled) {
    toggleBtn.className = "toggle-btn active";
    toggleBtn.textContent = "ACTIVE";
    masterTitle.textContent = "uKey Biometric Interception: ACTIVE";
  } else {
    toggleBtn.className = "toggle-btn paused";
    toggleBtn.textContent = "PAUSED";
    masterTitle.textContent = "uKey Biometric Interception: PAUSED (Password Mode)";
  }

  // Active PIN
  document.getElementById('activePin').textContent = data.active_pin || "------";
  if (data.lan_ip) {
    document.getElementById('hostTarget').textContent = `${data.lan_ip}:${data.port || 8443}`;
  }

  // Paired Devices
  const deviceList = document.getElementById('deviceList');
  document.getElementById('deviceCount').textContent = `${data.paired_devices.length} Paired`;
  if (data.paired_devices.length === 0) {
    deviceList.innerHTML = `<div style="color:var(--text-muted); font-size:11.5px; font-style:italic;">No devices paired yet. Pair with the PIN above.</div>`;
  } else {
    deviceList.innerHTML = data.paired_devices.map(dev => `
      <div class="device-item">
        <div>
          <div style="font-weight:600; color:#fff;">${dev.device_name}</div>
          <div class="device-meta">ID: ${dev.id} • Last seen: ${dev.last_seen_at ? new Date(dev.last_seen_at * 1000).toLocaleTimeString() : 'Just now'}</div>
        </div>
        <button class="btn-danger" onclick="revokeDevice('${dev.id}')">Revoke</button>
      </div>
    `).join('');
  }
}

async function toggleMaster() {
  const next = !currentState?.enabled;
  await fetch('/api/toggle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: next })
  });
  fetchStatus();
}

async function generateNewPin() {
  await fetch('/api/pin/new', { method: 'POST' });
  fetchStatus();
}

async function revokeDevice(id) {
  if (confirm(`Revoke authorization for device ${id}? It will no longer connect without pairing again.`)) {
    await fetch('/api/devices/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    fetchStatus();
  }
}

fetchStatus();
setInterval(fetchStatus, 2500);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy HTTP request logging
        pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return

        if parsed.path == "/api/status":
            server = getattr(self.server, "app_server", None)
            if server:
                payload = server.get_status_payload()
            else:
                payload = {"error": "no_server"}
            self._send_json(payload)
            return

        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        server = getattr(self.server, "app_server", None)
        if not server:
            self.send_error(500, "Server not initialized")
            return

        # CSRF Protection: Reject cross-site requests to settings/action endpoints
        sec_fetch_site = self.headers.get("Sec-Fetch-Site", "")
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "none"):
            LOG.warning("Rejected cross-site POST request (Sec-Fetch-Site: %s)", sec_fetch_site)
            self.send_error(403, "Forbidden: Cross-site request rejected")
            return

        origin = self.headers.get("Origin", "")
        referer = self.headers.get("Referer", "")
        allowed = (
            f"http://127.0.0.1:{server.port}",
            f"http://localhost:{server.port}",
        )
        if origin and not any(origin.startswith(a) for a in allowed):
            LOG.warning("Rejected CSRF POST with invalid Origin: %s", origin)
            self.send_error(403, "Forbidden: Invalid origin")
            return
        if referer and not any(referer.startswith(a) for a in allowed):
            LOG.warning("Rejected CSRF POST with invalid Referer: %s", referer)
            self.send_error(403, "Forbidden: Invalid referer")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        if parsed.path == "/api/toggle":
            enabled = bool(data.get("enabled", True))
            server.set_enabled(enabled)
            self._send_json({"status": "ok", "enabled": enabled})
            return

        if parsed.path == "/api/pin/new":
            pin = server.generate_new_pin()
            self._send_json({"status": "ok", "pin": pin})
            return

        if parsed.path == "/api/devices/revoke":
            dev_id = str(data.get("id", ""))
            ok = server.revoke_device(dev_id)
            self._send_json({"status": "ok", "revoked": ok})
            return

        self.send_error(404, "Not Found")

    def _send_json(self, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class UKeyWebServer:
    """Embedded HTTP server for the laptop control dashboard."""

    def __init__(
        self,
        get_status_fn: Callable[[], dict[str, Any]],
        set_enabled_fn: Callable[[bool], None],
        generate_pin_fn: Callable[[], str],
        revoke_device_fn: Callable[[str], bool],
        host: str = "127.0.0.1",
        port: int = 8444,
    ) -> None:
        self.get_status_payload = get_status_fn
        self.set_enabled = set_enabled_fn
        self.generate_new_pin = generate_pin_fn
        self.revoke_device = revoke_device_fn
        self.host = host
        self.port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        try:
            self._server = ThreadingHTTPServer((self.host, self.port), DashboardHandler)
            setattr(self._server, "app_server", self)
            self._thread = threading.Thread(target=self._server.serve_forever, name="ukey-web", daemon=True)
            self._thread.start()
            LOG.info("Dashboard active on http://%s:%d", self.host, self.port)
        except Exception as exc:
            LOG.warning("Could not start dashboard on http://%s:%d: %s", self.host, self.port, exc)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
