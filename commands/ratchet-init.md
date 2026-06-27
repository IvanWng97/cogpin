---
description: Wire ratchet into this repo end-to-end — install the change layer, draft a project-specific ratchet.toml from your house rules, then verify.
allowed-tools: Bash(python3 *), Read, Write, Edit
---

## 1 · Install the change layer (idempotent, non-clobbering)

!`python3 "${CLAUDE_PLUGIN_ROOT}/ratchet.py" install --cwd "${CLAUDE_PROJECT_DIR:-.}" 2>&1`

## 2 · Repo facts for the draft

!`python3 "${CLAUDE_PLUGIN_ROOT}/ratchet.py" suggest --cwd "${CLAUDE_PROJECT_DIR:-.}" --format json 2>&1`

---

The change layer is now wired (engine vendored at `.ratchet/ratchet.py`, a starter
`ratchet.toml`, a pre-push managed block in the effective hooks dir, and
`.github/workflows/ratchet.yml`). Now turn this repo's house rules into a
project-specific policy — **as a draft you review, never the live config**. The
irony ratchet exists to stop is a gate a human rubber-stamps, so the AI writes the
draft and the human's rename is the sign-off.

1. Read `CLAUDE.md` / `AGENTS.md` / `README` and reconcile them with the `suggest`
   JSON above (it already ranks the house-rules it detected, the dominant language's
   code/test/doc globs, and the repo's real test command). For each rule pick the
   right primitive. **Only the safe-core five** — `no-verify`, `branch-first`,
   `secret-scan`, `self-protect`, `protected-gate-files` — may be born at
   `severity="block"`; everything else starts `severity="warn"` until it has earned
   teeth on this repo.
2. **Write `ratchet.toml.draft`** (NOT `ratchet.toml`). Put a `# TODO(ratchet:review)`
   marker line on every non-safe-core block you add — the draft will not lint clean
   until a human has read and cleared each one.
3. Lint the draft by running:
   `python3 .ratchet/ratchet.py draft-lint --cwd .`
   It is a strict superset of `validate`: the moat (`block` requires `kind="fact"`),
   regex compiles, no match-everything pattern, base-pinning on, safe-core present,
   no born-at-block beyond the five, additive-only vs any existing config, and **zero
   outstanding review markers**. Fix whatever it flags and re-run until it is clean.
4. When it lints clean, tell me to **`mv ratchet.toml.draft ratchet.toml`** — that
   rename is the trust moment, the human signing off on the policy the gate enforces.
5. After I rename it, verify both layers by running:
   `python3 .ratchet/ratchet.py doctor --cwd .`
   Walk me through any `~` / `✗` with the one-line fix shown.
6. Remind me to `git add .ratchet/ratchet.py ratchet.toml .github/workflows/ratchet.yml`
   and commit — that, plus the `permissions:` block already in the scaffolded
   workflow, is what makes the gate hold for every clone and every PR, with no npm and
   no binary download.
