# Security model

cogpin is itself a security control — a gate meant to resist a capable adversary (an
AI agent, or a human, trying to close a task by cutting a corner). So its threat model
*is* the product. This page states what it guarantees, what it doesn't, and how to
report a bypass.

## What it protects

The closing-discipline: that the unglamorous last mile of a change actually happens.
Concretely, it denies — in real time or at the change boundary — the corner-cuts
catalogued in [`docs/coverage-map.md`](docs/coverage-map.md): hook bypass, scope creep,
threshold-lowering, deleting the failing test, stripping the assertion, leaking a
secret, merging red, and the rest.

## The guarantee, precisely

**A `fact` block cannot be talked past.** It decides only over things the gated agent
can't author — the normalized diff, the file statuses, the command string it's about to
run, PR/commit metadata, reviewer approvals. The schema enforces this:
`severity="block"` requires `kind="fact"`, checked at parse time. A judgment (an
LLM-`judge`, a self-`attest`) is **advisory** — it warns or nudges, never blocks. So the
guarantee can't silently erode by editing the config to "block on vibes".

Two properties make it bypass-resistant against the diff it gates:

- **Base-pinning.** The change layer reads `cogpin.toml` and the gate-defining files
  from the pinned **base** ref, not the PR head. You cannot loosen the gate inside the
  same diff the gate is judging.
- **Protected paths.** Changing a gate-defining file (`cogpin.toml`, the engine, the
  hooks, the CI) requires an independent approval (`protected_path`), and an in-session
  edit to one is denied at `PreToolUse` (`self_protect`).

## What it does NOT claim

- **Not omniscience.** `forbid_pattern`/`forbid_removal` are presence-ungameable but
  value-gameable (`assert!(true)` satisfies "has an assert"); `secret_scan` is
  best-effort token matching (pair it with `gitleaks` via a `run` block for depth).
- **Not a substitute for review judgment.** The semantic-weakening classes
  (assertion-loosening, fake-impl, guard-removal) are *advisory* on purpose — no fact
  can prove them, so they surface to a human/LLM reviewer rather than block.
- **Not protection against a trusted admin.** Someone with repo-admin rights can change
  the base policy *through review*. cogpin draws the line at what an agent can do
  **mid-task without review**, not at what an authorized human can do deliberately.

## Agent-layer bypass is by design (and logged)

`[meta].bypass_env` lets a human escape the **agent** layer for a legitimate reason
(it's always logged). This is intentional: the agent layer is a *forcing function*, and
the authoritative **change** layer (pre-push + CI) ignores the bypass entirely. A bypass
at the agent layer never reaches production unchecked.

## Reporting a vulnerability

If you find a way to make a `fact` **block** pass while the underlying corner-cut is
present — i.e. a true bypass of the guarantee, not a value-gameable case already
documented above — please report it privately first:

- Open a **GitHub security advisory** on `IvanWng97/cogpin` (Security → Report a
  vulnerability), or email the address on the maintainer's GitHub profile.
- Include a minimal `cogpin.toml` + the diff/command that should have blocked but
  didn't.

Please don't open a public issue for a guarantee-bypass until it's fixed. Value-gameable
cases that are already in scope (the "what it does NOT claim" list) are normal issues —
open them publicly.

## Supported versions

Pre-1.0: only the latest release is supported. Once 1.0 ships, this section will pin a
support window.
