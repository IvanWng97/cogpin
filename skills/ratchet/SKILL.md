---
name: ratchet
description: Use when authoring or editing a ratchet.toml Definition-of-Done policy, or when a ratchet gate denies a command / blocks turn-end / reds CI — to fix the underlying cause properly instead of trying to bypass it.
---

# ratchet — authoring policies & responding to a block

ratchet is a Definition-of-Done gate. It enforces the closing-discipline an agent
tends to skip. It is the *anti-skill*: this prose helps you, but the binding part
is the engine's hooks, not these words.

## The one rule (the moat)

```
severity = "block"   REQUIRES   kind = "fact"
```

Only **facts** — things you cannot author — may hard-block: added/removed diff
lines, per-file A/M/D status, the command string, the current branch, PR/commit
metadata, reviewer approvals. Anything that needs **judgment** (`attest`,
`judge`) is advisory: it warns or nudges, never blocks. `validate` rejects a
`block` that isn't a fact, so the moat can't erode by accident.

## When a ratchet gate fires, FIX THE CAUSE — never bypass

A block means a real corner was about to be cut. The correct response is always to
satisfy the gate, not to route around it.

| ratchet says | the wrong move | the right move |
|---|---|---|
| denies `git commit --no-verify` | find another skip flag | run the hook; fix what it flags |
| denies commit/push on `main` | force it anyway | `git checkout -b <name>` first |
| `forbid_delete` on a test | delete it via a shell trick | keep the test; make it pass (or pair the rename) |
| `forbid_removal` of an `assert` | strip more guards | restore the assertion; fix the code under it |
| `Stop` block on an unticked box | tick it without doing the work | actually do it, then tick it |
| CI `check` is red | edit `ratchet.toml` to relax it | the config is base-pinned — relaxing it in the same PR does nothing; fix the change |

**Do not** add `--no-verify` / hook-skipping flags, and **do not** set
`[meta].bypass_env` to slip a change past the agent layer "just this once" — the
change layer (pre-push + CI) ignores the bypass and will still red. A bypass is
for a genuine, logged exception, not for avoiding the work.

## Authoring a ratchet.toml

1. `python3 .ratchet/ratchet.py init` (or `/ratchet-init`) to scaffold, then edit.
2. Pick primitives by the fact each reads:
   - command string → `forbid_command`, `forbid_commit_on_branch` (agent layer)
   - added lines → `secret_scan`, `forbid_pattern`
   - removed lines → `forbid_removal` (the "delete the safety net" guard)
   - file D-status → `forbid_delete` (the "delete the failing test" guard)
   - name-status pairing → `path_requires`, `cooccur`
   - PR/commit metadata → `marker_present`, `commit_footer`
   - reviewer approvals → `protected_path`
   - language-specific (lint/test exit code) → `run` (**`block` only at the change layer**)
   - forcing functions → `attest` (Stop checklist), `judge` (advisory LLM prompt)
3. Keep `base_pinned = true`. Add gate-defining files (`ratchet.toml`,
   `.ratchet/**`, CI workflows, hook configs) to a `protected_path` check.
4. `python3 .ratchet/ratchet.py validate` before committing.
5. New primitive blocking real code for the first time? Start it at `warn`, watch
   a few PRs for false positives, then promote to `block`.

See `README.md` for the full primitive table and the bypass-proof proof, and
`examples/{pixtuoid,node-ts,python}/ratchet.toml` for ready-to-lift policies.
