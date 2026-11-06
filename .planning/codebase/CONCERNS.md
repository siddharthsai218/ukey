---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# Technical Concerns & Security Analysis

**Analysis Date:** 2026-11-06

## 1. Security Findings & Vulnerabilities

### Localhost Drive-By CSRF in Embedded Web Server
- **File:** `daemon/ukey_web.py` (lines 349–380)
- **Finding:** The local dashboard (`http://127.0.0.1:8444`) accepts POST requests to `/api/toggle` (which can disable uKey authentication) and `/api/devices/revoke` without verifying the `Origin` or `Host` headers and without an anti-CSRF token.
- **Risk:** Malicious JavaScript executing on an external webpage visited in the user's browser can issue background cross-origin requests to `http://127.0.0.1:8444/api/toggle` to silently disable or modify uKey settings.
- **Mitigation:** Enforce origin validation (`Origin: http://127.0.0.1:8444`) or require a session token header for all mutating API calls.

### Missing Rate-Limiting on 6-Digit Wi-Fi Pairing PIN
- **File:** `daemon/ukey_pairing.py` (lines 125–145)
- **Finding:** When `--wireless` is enabled on `0.0.0.0:8443`, pairing requests submit a 6-digit PIN. Invalid PIN attempts simply log a warning; there is no exponential backoff or lockout counter.
- **Risk:** An attacker on the local Wi-Fi network could attempt to brute-force the 900,000 PIN space via concurrent socket connections before the 15-minute PIN expiration kicks in.
- **Mitigation:** Implement an invalid-attempt counter that permanently burns the active PIN after 5 failed attempts.

### Permissive `0666` Mode on `/dev/uhid`
- **File:** `setup_udev.sh` (line 22)
- **Finding:** The udev rule sets `MODE="0666"` on `/dev/uhid` alongside `TAG+="uaccess"`.
- **Risk:** This makes `/dev/uhid` writable by any local user account, container, or sandboxed process on the system, allowing unprivileged processes to create arbitrary virtual input devices.
- **Mitigation:** Rely on systemd's dynamic user ACLs (`TAG+="uaccess"`) and restrict baseline mode to `0660` under group `input`.

## 2. Performance & Concurrency Concerns

### Potential 100% CPU Busy-Spin in `_watch_conn`
- **File:** `daemon/ukey_daemon.py` (lines 430–450)
- **Finding:** In `_watch_conn`, disconnect detection uses `select()` followed by `conn.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)`. Because `MSG_PEEK` does not consume data from the socket receive buffer, if the client sends data before `request()` reads it, `select()` will immediately return ready on every iteration, causing the thread to busy-spin until the buffer is cleared.
- **Mitigation:** Coordinate `_watch_conn` with the active I/O lock, or rely on socket keepalive probes (`SO_KEEPALIVE`) instead of continuous peek polling.

## 3. Protocol & Feature Limitations

- **Resident (Discoverable) Credentials Not Supported**:
  `daemon/ukey_daemon.py` line 783 explicitly rejects `options.get("rk") is True` with `CTAP2_ERR_UNSUPPORTED_OPTION`. Discoverable passkey flows without an explicit Relying Party ID or user allow-list are unsupported.
- **Transport Encryption over Wi-Fi**:
  While connections are authenticated using a 256-bit token hash, the TCP channel over Wi-Fi is plaintext JSON (no TLS or Noise protocol handshake). Physical USB mode (`adb reverse`) avoids this exposure.
- **Legacy U2F / CTAP1**:
  Legacy U2F raw commands (`CTAPHID_MSG`) return `6d 00`. uKey is strictly a CTAP2 authenticator.
