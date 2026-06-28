---
description: Wire cogpin into this repo end-to-end — install the change layer, draft a project-specific cogpin.toml from your house rules, then verify.
allowed-tools: Bash(python3 *), Read, Write, Edit
---

## 1 · Install the change layer (idempotent, non-clobbering)

!`python3 "${CLAUDE_PLUGIN_ROOT}/cogpin.py" install --cwd "${CLAUDE_PROJECT_DIR:-.}" 2>&1`

## 2 · Repo facts for the draft

!`python3 "${CLAUDE_PLUGIN_ROOT}/cogpin.py" suggest --cwd "${CLAUDE_PROJECT_DIR:-.}" --format json 2>&1`

---

The change layer is now wired (engine vendored at `.cogpin/cogpin.py`, a starter
`cogpin.toml`, a pre-push managed block in the effective hooks dir, and
`.github/workflows/cogpin.yml`). Now turn this repo's house rules into a
project-specific policy — **as a draft you review, never the live config**. The
irony cogpin exists to stop is a gate a human rubber-stamps, so the AI writes the
draft and the human's rename is the sign-off.

1. Read `CLAUDE.md` / `AGENTS.md` / `README` and reconcile them with the `suggest`
   JSON above (it already ranks the house-rules it detected, the dominant language's
   code/test/doc globs, and the repo's real test command). For each rule pick the
   right primitive. **Only the safe-core five** — `no-verify`, `branch-first`,
   `secret-scan`, `self-protect`, `protected-gate-files` — may be born at
   `severity="block"`; everything else starts `severity="warn"` until it has earned
   teeth on this repo.
2. **Write `cogpin.toml.draft`** (NOT `cogpin.toml`). Put a `# TODO(cogpin:review)`
   marker line on every non-safe-core block you add — the draft will not lint clean
   until a human has read and cleared each one.
3. Lint the draft by running:
   `python3 .cogpin/cogpin.py draft-lint --cwd . --simulate`
   It is a strict superset of `validate`: the moat (`block` requires `kind="fact"`),
   regex compiles, no match-everything pattern, base-pinning on, safe-core present,
   no born-at-block beyond the five, additive-only vs any existing config, and **zero
   outstanding review markers**. `--simulate` additionally replays every `block` check
   against the current `HEAD` and flags any that would fire on code already committed —
   the one tool that catches a day-one wall of false-blocks before you arm. Fix whatever
   it flags and re-run until it is clean.
4. When it lints clean, tell me to **`mv cogpin.toml.draft cogpin.toml`** — that
   rename is the trust moment, the human signing off on the policy the gate enforces.
5. After I rename it, verify both layers by running:
   `python3 .cogpin/cogpin.py doctor --cwd .`
   Walk me through any `~` / `✗` with the one-line fix shown.
6. Remind me to `git add .cogpin/cogpin.py cogpin.toml .github/workflows/cogpin.yml`
   and commit — that, plus the `permissions:` block already in the scaffolded
   workflow, is what makes the gate hold for every clone and every PR, with no npm and
   no binary download.

For what to do *after* the gate is armed — riding at `warn`/report-only, calibrating with
`backtest`, promoting `warn → block`, what to gate vs. leave to existing CI, and migrating
off an existing gate — point me at [`docs/adopting.md`](../docs/adopting.md).
