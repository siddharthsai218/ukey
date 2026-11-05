# uKey AI Build Prompts

This directory contains model-agnostic prompts for AI coding agents to build uKey
through phases. Each phase is a separate prompt file. Do not give an agent all
phases at once.

## How to use

1. Give the agent `00_MASTER_CONTEXT.md` first. It contains the repo state,
   architecture, safety rules, and verification commands.
2. Then give exactly one phase prompt, starting with
   `01_PHASE_0_STABILIZE.md`.
3. Require the agent to run the acceptance checks and report evidence before you
   move to the next phase.
4. Use one branch/worktree per phase. Do not let two agents edit the same
   checkout.
5. If an agent asks to change scope, stop and decide before it edits code.

## Phase order

| Phase | File | Lane | Depends on |
|---|---|---|---|
| 0 | `01_PHASE_0_STABILIZE.md` | Foundation | — |
| 1 | `02_PHASE_1_SECURE_TRANSPORT.md` | A: secure wireless | Phase 0 |
| 2 | `03_PHASE_2_PAM_AND_FIDO2.md` | Credibility | Phase 0 |
| 3 | `04_PHASE_3_CONTEXT_AWARE_SUDO.md` | B: context-aware sudo | Phase 2 |
| 4 | `05_PHASE_4_PACKAGING.md` | D: cross-distro | Phase 0; can run after Phase 1/2 |
| 5 | `06_PHASE_5_TEACHING_AND_DEMO.md` | C: teaching/reference | Continuous; final pass after Phase 2/3 |
| 6 | `07_PHASE_6_HARDENING.md` | Optional | Phases 0–3 |

For one agent driving the whole build, use
`08_FULL_PROJECT_ORCHESTRATOR.md`. It still enforces phase gates; do not ask an
agent to implement every phase in one change.

Lane mapping:

- **A — Secure wireless key:** Phase 1.
- **B — Context-aware sudo key:** Phase 3.
- **C — Teaching/reference implementation:** Phase 5, plus docs in every phase.
- **D — Cross-distro plug-and-play:** Phase 4.

## Non-negotiable rules

- Do not rewrite the project from scratch. Extend the existing code.
- Do not disturb the running `ukey.service` on port 8443 / `/dev/hidraw6`.
  Use `--port 8445 --device-name "uKey Test"` and `/dev/hidraw7` for tests.
- Add tests before or with behavior changes.
- Update documentation in the same phase as the code.
- Never claim a feature works without a command output or test proving it.
- Never add “first,” “unique,” “tamper-proof,” “tri-modal,” or “zero cloud”
  language unless the feature is implemented and tested.
- Never add telemetry, cloud relays, or hidden network calls.
- Keep the license compatible with GPL-3.0. Attribute prior art.
- For PAM changes: keep a root shell open, back up the PAM file, and test in a
  VM or with a test user. Never test PAM on your only login path.
- Do not commit `.venv/`, `android/app/build/`, APKs, credentials, keys, or logs.

## Definition of done for every phase

A phase is done only when all of these are true:

1. The code runs on the current checkout.
2. New and existing tests pass.
3. The acceptance checks in the phase prompt have been run and their output is
   included in the report.
4. Documentation matches behavior.
5. No unsupported claim was added.
6. The production service on port 8443 was not disturbed.
7. The agent reports files changed, tests run, manual checks, risks, and
   follow-ups.

## Suggested agent report format

```
## Summary
What changed and why.

## Files changed
- path: what changed

## Tests run
- command: result

## Manual verification
- command/scenario: observed result

## Risks / limitations
- ...

## Follow-ups
- ...
```

If the agent cannot meet an acceptance check, it must say so explicitly. It must
not mark the phase complete.
