# Full Project Orchestrator Prompt

Use this prompt when you want one agent to drive the whole build. It still forces
phase gates. Do not paste every phase prompt into one message and ask for
everything at once.

## Prompt

You are the lead engineer for uKey. Your job is to build lanes A, B, C, and D
through the phased plan in `docs/ai-prompts/`.

Repository: `/home/siddharth/Desktop/ukey`

First, read:

1. `docs/ai-prompts/00_MASTER_CONTEXT.md`
2. `docs/ai-prompts/README.md`
3. All phase files:
   - `01_PHASE_0_STABILIZE.md`
   - `02_PHASE_1_SECURE_TRANSPORT.md`
   - `03_PHASE_2_PAM_AND_FIDO2.md`
   - `04_PHASE_3_CONTEXT_AWARE_SUDO.md`
   - `05_PHASE_4_PACKAGING.md`
   - `06_PHASE_5_TEACHING_AND_DEMO.md`
   - `07_PHASE_6_HARDENING.md`

Then implement the phases **in order**, one at a time.

Rules:

- Do not implement all phases in one change.
- Start with Phase 0. Run every acceptance check in that phase.
- Report the Phase 0 result using the format in the master context.
- Wait for explicit approval before starting Phase 1.
- Repeat for each phase.
- If a phase fails an acceptance check, stop and report the failure. Do not move
  on.
- Use a separate branch/worktree per phase.
- Do not disturb the production service on port 8443 or `/dev/hidraw6`.
- Do not rewrite the project from scratch.
- Do not claim a feature works without command output or a test.
- Do not add “first,” “unique,” “tamper-proof,” “tri-modal,” or “zero cloud”
  language unless the exact claim is implemented and tested.
- Keep a root shell open for PAM phases.
- If a requirement is ambiguous or destructive, stop and ask.

Your first response must be a short plan:

1. Which phase you will start with.
2. Which files you expect to inspect.
3. Which acceptance checks you will run.
4. Any blockers you already see.

Do not edit files until you have read the master context and the phase you are
starting.

## Phase completion report

Use this exact format:

```
## Phase
Phase N — name

## Summary
What changed and why.

## Files changed
- path: what changed

## Tests run
- command: result

## Manual verification
- command/scenario: observed result

## Acceptance checklist
- [ ] criterion 1
- [ ] criterion 2
...

## Risks / limitations
- ...

## Follow-ups
- ...

## Ready for next phase?
Yes/No. If no, what is blocking.
```

If any acceptance box is unchecked, the answer to “Ready for next phase?” is No.
