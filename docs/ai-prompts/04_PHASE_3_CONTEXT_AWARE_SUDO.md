# Phase 3 — Context-Aware Sudo (Lane B)

Read `00_MASTER_CONTEXT.md` and complete Phases 0–2 first.

## Goal

When a user runs `sudo` (or another supported PAM service), the phone shows the
**actual command and context** being authorized — not just “Approve login” — and the
user approves or denies with biometrics.

This is the feature that can make uKey genuinely different from `passkey`,
`vrtfido`, and hardware keys: “see what you sign” for local privilege escalation.

## Scope

Start with `sudo`. Do not attempt full polkit coverage in the first iteration; add
it only after `sudo` is solid.

Supported PAM services:

- `sudo` (primary),
- `su` / `login` (optional),
- `polkit-1` (optional, later).

Unsupported services must fall back safely.

### Browser WebAuthn context (do this first)

Browser logins use the same phone approval screen but a different context source.
Before building the PAM module, enrich the existing CTAP2 signer requests so the
phone can show:

- `webauthn.create` — RP ID, RP name, account name, host, action.
- `webauthn.get` — RP ID, stored account name, host, action.

The account name is not present in `authenticatorGetAssertion`; persist
`user.name` and `user.displayName` with the credential at registration time.

The phone must **not** claim to show the full URL or origin. CTAP2 sends only
`clientDataHash`, not the browser's `clientDataJSON`. Chrome already displays the
origin; uKey complements it with out-of-band RP/account confirmation.

Also bind the displayed context to the signature: send `rp_id`, `flags`,
`sign_count`, and `client_hash` so the phone can recompute the digest and refuse
to sign if the daemon's claimed context does not match.

The exact request schema, screen mockups, digest formulas, and code touchpoints
are in `docs/CONTEXT_DISPLAY.md`. Read it before editing the daemon or Android
app.

Practical limits:

- Google passkeys request resident credentials (`rk=true`). uKey currently
  rejects them. Test with `webauthn.io` or GitHub security keys first; do not
  claim Google passkey support until Phase 6.1 is complete.
- `pam_u2f` cannot provide the sudo command. It only has a challenge and an
  application parameter. The command requires the helper/PAM module below.
- `handleMakeCredential` in `UKeyService.kt` currently creates a credential
  without a user-facing approval. Add an approval card for registration too.

## Architecture

```
sudo
  └─ PAM module (C) or helper
       └─ ukey-context (host helper)
            ├─ gathers /proc + PAM context
            ├─ sends request to daemon over a local Unix socket
            └─ waits for signed approval
                 └─ daemon → phone over authenticated transport
                      └─ phone displays command, biometric approval
                           └─ phone signs request hash
                 └─ daemon verifies signature
            └─ PAM returns success/failure
```

Use the secure transport from Phase 1. Do not send context over plaintext TCP.

## Design document

Write `docs/CONTEXT_PROTOCOL.md` first. It must define:

- request and response fields,
- canonical JSON encoding,
- request ID and hash calculation,
- approval signature format,
- timeout and cancellation,
- privacy/redaction rules,
- local socket permissions and peer credential checks,
- error behavior and fallback,
- audit log format and hash chain.

## Host helper: `ukey-context`

Implement a helper (Python is acceptable for the first version) that gathers:

- `service` (`sudo`, `su`, `login`, `polkit-1`),
- `pam_user`,
- `pam_tty`,
- `pam_rhost`,
- `pid`, `ppid`,
- `cwd` from `/proc/<pid>/cwd`,
- `exe` from `/proc/<pid>/exe`,
- full command line from `/proc/<ppid>/cmdline` or `SUDO_COMMAND`,
- parent process chain (up to 5 ancestors),
- timestamp,
- request ID.

For `sudo`:

- Prefer `SUDO_COMMAND` when it is available and trustworthy.
- Otherwise read `/proc/<ppid>/cmdline` and reconstruct the command with proper
  quoting.
- Handle `sudo -i`, `sudo -u user`, `sudo -- command`, and shell wrappers.
- If the command cannot be determined, show a clear “unknown command” state rather
  than guessing.

Sanitization:

- Strip/replace control characters and terminal escape sequences.
- Limit each field and the total request size (e.g., 8 KiB).
- Preserve the command text as data, not HTML.
- Never execute or shell-evaluate the captured command.
- Provide a redaction config for patterns that look like secrets; do not log full
  commands by default.

## Local IPC

- Unix domain socket in `$XDG_RUNTIME_DIR/ukey/context.sock` with mode `0600`.
- Verify peer credentials with `SO_PEERCRED`; only the same UID may submit.
- The daemon must not accept context requests from arbitrary TCP clients.
- Bound the request queue and rate-limit.

## PAM module

Implement a small C PAM module (preferred) or a helper-based module:

- `pam_sm_authenticate`.
- Gather context via `ukey-context`.
- Send request to daemon.
- Wait for approval with a configurable timeout (default 60 seconds).
- On approve: return `PAM_SUCCESS`.
- On deny/timeout/transport error: return `PAM_AUTH_ERR` or `PAM_IGNORE` according
  to config.
- Default must preserve password fallback. A phone failure must not lock the user
  out.
- Support `mode=required` (no fallback) and `mode=optional` (fallback).
- Log decisions through syslog/journal without leaking command text by default.

Keep a root shell open during all PAM tests. Test in a VM or with a test user.

## Android UI

Add an approval screen/activity:

- Title: “Approve sudo?”
- Show:
  - the command in a monospace block,
  - user,
  - hostname,
  - TTY,
  - service,
  - timestamp,
  - a warning if the command is long/truncated.
- Buttons: Approve / Deny.
- Approve requires strong biometric authentication.
- Timeout shows “Request expired” and returns denial.
- Notification if the app is backgrounded; no auto-approve.
- Do not display raw control characters or HTML.
- Do not store command text in logs by default.

The phone signs a canonical hash of the request (including request ID, command,
user, host, TTY, timestamp) with the Keystore key. The daemon verifies the
signature before returning success.

## Audit log

Add a host-side audit log:

- Path: `~/.local/state/ukey/audit.jsonl` (or `~/.config/ukey/audit.jsonl`).
- Append-only JSON Lines.
- Fields:
  - timestamp,
  - request_id,
  - service,
  - user,
  - tty,
  - host,
  - command,
  - decision (`approved`/`denied`/`timeout`/`error`),
  - context_hash,
  - prev_hash,
  - entry_hash,
  - phone_signature (if approved).
- Hash chain:
  - `entry_hash = SHA256(prev_hash || canonical_json_without_entry_hash)`.
  - Phone signs `entry_hash` or a request-specific hash.
- `ukeyctl audit tail`, `ukeyctl audit verify`, `ukeyctl audit export`.
- Call it “tamper-evident,” not “tamper-proof.”
- Do not log secrets by default; provide redaction config.

## Tests

### Unit

- Context parser for:
  - simple `sudo ls`,
  - `sudo -u nobody id`,
  - `sudo -i`,
  - commands with spaces, quotes, `$()`, backticks, newlines, unicode,
  - very long commands,
  - missing `/proc` data.
- Canonical JSON and hash stability.
- Signature verification success/failure.
- Audit hash-chain verification and tamper detection.
- Redaction patterns.

### Integration

Use a test user/VM and a fake `loginctl` if needed.

1. `sudo -k; sudo ls` triggers a phone request showing `sudo ls`.
2. Approve → command runs.
3. Deny → command does not run; password fallback works if configured.
4. Timeout → command does not run; fallback works.
5. Phone disconnected → command does not hang; fallback works.
6. Command with shell metacharacters is displayed literally.
7. Audit entry matches the request and verifies.
8. Tampering with an audit line makes `ukeyctl audit verify` fail.
9. Normal password `sudo` still works.

## Acceptance criteria

1. The phone displays the exact command and context for `sudo`.
2. The phone shows the RP ID and stored account for a WebAuthn login, and does
   not claim to show the full origin.
3. Approve executes the command; deny/timeout does not.
4. Password fallback still works by default.
5. No lockout: a broken daemon or phone does not make `sudo` unusable.
6. Audit log is append-only, hash-chained, and verifiable.
7. No command text is logged by default without redaction.
8. The Phase 1 transport is used; no plaintext context over TCP.
9. Documentation matches behavior.

## Out of scope

- Full polkit coverage (optional follow-up).
- Full origin/URL display for WebAuthn. CTAP2 does not provide it; show RP ID and
  account only.
- Multi-device approval.
- Resident credentials.
- Packaging.

Do not start Phase 4 until Phase 3 acceptance checks pass.
