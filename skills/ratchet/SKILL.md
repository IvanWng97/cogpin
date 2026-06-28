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
2. Pick primitives by the fact each reads (full reference: `SCHEMA.md`):
   - command string → `forbid_command{deny}`, `forbid_commit_on_branch` (agent layer)
   - the live Write/Edit target → `self_protect` (agent layer; protect the gate files)
   - added lines → `secret_scan`, `forbid_pattern`, `file_must_contain` (positive floor)
   - removed lines → `forbid_removal` (the "delete the safety net" guard)
   - a value's direction across the diff → `numeric_floor` (lowered coverage/threshold)
   - the changed-path set → `scope_lock` (allowlist; scope creep), `change_budget` (blast radius)
   - file D-status / byte size → `forbid_delete`, `max_added_file_bytes`
   - name-status pairing → `path_requires`, `cooccur`
   - commit/PR message → `forbid_in_message`, `require_message_pattern`, `commit_footer`, `marker_present`
   - reviewer identity / checks (CI) → `protected_path`, `require_approval_from`,
     `pattern_requires_approval`, `approval_policy`, `require_checks_green`
   - language-specific (lint/test exit code) → `run` (**`block` only at the change layer**)
   - forcing functions → `attest` (Stop checklist), `judge` (advisory LLM prompt)
3. Keep `base_pinned = true`. Add gate-defining files (`ratchet.toml`,
   `.ratchet/**`, CI workflows, hook configs) to a `protected_path` check — and a
   `self_protect` check for the real-time agent-layer twin.
4. `python3 .ratchet/ratchet.py validate` before committing.
5. New primitive blocking real code for the first time? Start it at `warn`, watch
   a few PRs for false positives, then promote to `block`.

Or skip the hand-authoring: `python3 .ratchet/ratchet.py suggest` reads the repo's
`CLAUDE.md` house-rules + structure into a ranked draft, and `/ratchet-init` walks the
whole flow. Write it to `ratchet.toml.draft` (never the live config), mark each
non-safe-core block with `# TODO(ratchet:review)`, run `draft-lint` until clean, then
the **human renames** `…draft → …toml` — that rename is the sign-off ratchet's whole
premise depends on (an auto-applied gate a human rubber-stamps is the exact corner-cut
it stops).

## Wiring & verifying

- `/ratchet-init` (→ `ratchet install`) wires the change layer once per repo: vendor
  `.ratchet/ratchet.py`, scaffold config, add the pre-push managed block + CI. It
  **coexists, never clobbers** — appends a sentinel-fenced block to the effective
  pre-push, and for lefthook/pre-commit (which regenerate their own hook) it prints a
  snippet instead of writing. Commit `.ratchet/ratchet.py`, `ratchet.toml`, and
  `.github/workflows/ratchet.yml`.
- `/ratchet-doctor` (→ `ratchet doctor`) confirms both layers are live, with a one-line
  fix for anything missing; `/ratchet-gaps` shows which house-rules are still prose.
- A teammate's local pre-push (CI already gates them):
  `python3 .ratchet/ratchet.py install --no-vendor --no-config --no-ci`.
- "Fix the cause, don't bypass" still applies: if the gate blocks you, address the
  finding — don't loosen the policy (`self_protect` denies an in-session gate edit, and
  the CI action runs a rev-pinned engine over the base-pinned config regardless).

See `README.md` for the full primitive table, `SCHEMA.md` for every field + the CLI,
`docs/coverage-map.md` for why each primitive exists, and
`examples/{pixtuoid,node-ts,python,advisory}/ratchet.toml` for ready-to-lift policies.
