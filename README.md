# ratchet — a Definition-of-Done gate for AI coding agents

> Prose binds intention. Only mechanism binds behavior.

When an AI agent closes a task it tends to skip the unglamorous last mile —
forgets the test, bypasses the hook with `--no-verify`, leaves the docs stale,
drops a finding on the floor, or *says* it reviewed when it didn't. A `CLAUDE.md`
that says "always run the tests" is a suggestion the same model can rationalize
past. `ratchet` turns that closing-discipline into a gate the agent **can't** talk
its way around.

It does that with one rule:

```
severity = "block"   REQUIRES   kind = "fact"
```

A **fact** decides only over things the agent can't fake — the normalized diff,
the command it's about to run, PR/commit metadata. Those may hard-block. Anything
that needs *judgment* (an LLM-judge, a self-attestation) is **advisory** — it can
warn or nudge, never block. That single invariant is the whole moat: a forgetful
or over-confident agent can't pass a block it didn't actually satisfy, because it
never authored the evidence the block reads.

One language-agnostic engine, one per-repo `ratchet.toml`. The engine reads git
facts + your config; it never imports your project code. Anything
language-specific goes through the one `run` escape hatch. (The engine itself is
a single stdlib-only `ratchet.py` — auditable in plain text, zero dependencies.)

## Why not just CLAUDE.md? (even nested, per-directory)

`CLAUDE.md` / `AGENTS.md` is the right tool for conveying **intent** —
architecture, conventions, why a sharp edge exists. Keep it. But it is
structurally incapable of **enforcing** the closing-discipline, and writing more
of it doesn't fix that:

1. **The reader is the violator.** The same model that reads "always run the
   tests" decides whether to. An instruction it can rationalize past ("trivial
   change, I'll test later") is a suggestion to itself, not a gate.
2. **Salience decays exactly when it matters.** Long sessions summarize and evict
   early context; a nested `CLAUDE.md` only loads when you touch that tree; big
   files get skimmed. Closing-discipline is needed at the *end* of a long task —
   precisely when the instruction is faintest.
3. **Prose can't reject an action.** It cannot return a non-zero exit code. The
   agent can run `git commit --no-verify` and no `CLAUDE.md` will stop the tool
   call. `ratchet`'s `PreToolUse` hook *denies* it, in real time, before it runs.
4. **Self-report is gameable.** "I did a two-lens review" / "docs updated" is
   authored by the gated agent. A check that trusts the agent's own claim is no
   check. `ratchet` blocks only on facts the agent can't author — the diff, the
   command string, PR metadata.
5. **More prose ≠ more binding.** Splitting rules across many `CLAUDE.md` files
   improves locality of *intent*, not enforcement. Ten unenforced rules are
   bypassed as easily as one. You can't patch an enforcement gap with docs.
6. **The rulebook is editable in the same breath.** An agent can delete the
   "no `--no-verify`" line from `CLAUDE.md` in the very change that uses it.
   `ratchet` reads its policy from the pinned base ref — the gate you're under is the
   one that existed *before* your diff (proof below).

`ratchet` doesn't replace `CLAUDE.md`; it's the mechanism half of the idea your
`CLAUDE.md` already states: **prose binds intention; only mechanism binds
behavior.**

## Two layers

| Layer | Fires at | Authority |
|---|---|---|
| **agent** | Claude Code `PreToolUse` / `Stop` hook — real time | denies the forbidden command mid-session; bypassable via `[meta].bypass_env` (always logged) |
| **change** | git pre-push hook + CI | **authoritative** — base-pinned, ignores the bypass env |

## Install

The plugin runs two tiny Python lifecycle hooks, so `python3` (3.11+) needs to be
on your PATH — including the *non-interactive* shell's PATH for Nix/nvm-style
setups. If it isn't, nothing errors; the always-on gate just stays quiet.

### Claude Code

```
/plugin marketplace add IvanWng97/ratchet
```
```
/plugin install ratchet@ratchet
```
(Two separate prompts — send them one at a time.)

The desktop app has no `/plugin` command: install from the UI instead — Customize
→ the `+` by personal plugins → Create plugin and add marketplace → Add from
repository → enter the repo URL.

That gives you the **agent layer** immediately: the `PreToolUse` deny + `Stop`
nudge fire every session, and the `/ratchet-init` / `/ratchet-check` commands are
available. "Default-on" means enforcement is a property of your client + the repo,
not a step the agent has to remember.

### Wire the change layer (once per repo)

The agent layer is per-developer; the authoritative **change layer** (pre-push +
CI, base-pinned, un-bypassable) is per-repo. Run once, inside Claude Code:

```
/ratchet-init
```

It vendors the single-file engine to `.ratchet/ratchet.py`, scaffolds `ratchet.toml`, and adds
the CI step. Commit those and every clone — every agent, every PR — meets the same
gate. The CI step is just:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: python3 .ratchet/ratchet.py check
```

No npm, no package manager, no binary download — one stdlib-Python file, committed.

## The primitive library

Every check reads only facts — never your code.

| primitive | kind | decides over |
|---|---|---|
| `forbid_command{pattern}` | fact | the agent's command string (agent layer) |
| `secret_scan{forbid_paths,custom}` | fact | added lines vs token shapes + forbidden file globs |
| `forbid_pattern{pattern,scope,exempt,strip_comments}` | fact | added lines under a path scope |
| `path_requires{when,need}` | fact | name-status: if `when` changed, `need` must too |
| `cooccur{trigger,require}` | fact | if `trigger` appears (diff/PR), `require` must too |
| `marker_present{marker}` | fact | a marker block exists in the PR body |
| `commit_footer{}` | fact | every commit ends with `[meta].commit_footer` |
| `protected_path{paths,require_approval}` | fact | gate-defining files changed → need an independent approval |
| `run{cmd}` | fact* | shell-out; the exit code is the fact (**`block` only at the change layer**) |
| `attest{prompt,class}` | advisory | a `Stop`-hook checklist box |
| `judge{prompt}` | advisory | an advisory LLM-judge |

## Why it's actually bypass-proof

A `fact` block is only ungameable if the agent can't edit the gate **in the same
diff it's being gated on**. So:

1. **Base-pinning** — `ratchet.toml` (and your gate-defining files) are read from the
   pinned base ref, never the PR head. A same-PR edit that relaxes a check is
   evaluated against the *old* policy, so it can't disarm itself.
2. **`protected_path`** — changing those gate-defining files needs an independent
   approval, or the gate refuses.
3. **Isolated `run`** — invoke tools isolated (`ruff --isolated`, a pinned
   `pytest -c …`) so head-side config can't defang the teeth.

## Proof: watch it survive a bypass attempt

`ratchet` dogfoods itself. Here it refuses to be disarmed — one commit that adds a
secret **and** rewrites `ratchet.toml` to turn every block into a warn:

```console
$ python3 ratchet.py check                 # a clean commit
ratchet: ok (0 advisory warning(s))        # exit 0

$ printf 'AWS_KEY = "AKIA…EXAMPLE"\n' > leak.py          # leak a key, and…
$ sed -i 's/severity = "block"/severity = "warn"/' ratchet.toml   # …disarm the gate
$ grep -c 'severity = "block"' ratchet.toml
0                                      # HEAD's config now has ZERO blocks
$ git commit -am "feat: add module and 'tune' the gate"

$ python3 ratchet.py check
ratchet: definition-of-done NOT met (1 blocking)
  [BLOCK] secret-scan: possible secret in added line (leak.py)   # exit 1
```

The head-side `ratchet.toml` has no blocks left — yet the secret is still caught,
because the policy is read from the **base ref**. Without base-pinning this commit
passes; with it, the gate can't be edited by the diff it's gating. That is the
difference between a rule and a gate.

This isn't hypothetical — it's the documented failure class `ratchet` exists for.
Two reports against Claude Code, in the maintainers' own tracker, name it exactly:

- [#32198](https://github.com/anthropics/claude-code/issues/32198) — *"Claude
  Code skips mandatory rules in CLAUDE.md (**Definition of Done**)"*
- [#40117](https://github.com/anthropics/claude-code/issues/40117) — *"Agent
  bypasses git pre-commit hooks using `--no-verify` … **despite explicit deny
  rules**"*

Both describe a prose rule (in `CLAUDE.md`, in a deny list) that the agent read
and then ignored. That is precisely the gap `ratchet` closes: a prose rule *asks* the
agent not to; `ratchet` makes the unwanted outcome a non-event — the `--no-verify`
tool call is denied before it runs, and the skipped step reds the gate it can't
edit.

### What it does and doesn't claim

`ratchet` guarantees the **forcing function**, not omniscience. A `fact` block can't
be talked past — that's the strong claim, and it holds. But `secret_scan` is
best-effort pattern matching (pair it with `gitleaks` via a `run` block for
depth); `attest`/`judge` are advisory by construction (they exist to *surface*,
not to block); and a determined human with repo-admin rights can always change
the base policy through review. The line `ratchet` draws: **anything an agent can do
mid-task to cut a corner, it stops; anything that needs human judgment stays
advisory and visible.** That boundary is enforced by the schema itself
(`block` requires `fact`), so the guarantee can't silently erode.

## Config

Start from a scaffold:
```
python3 ratchet.py init      # or  /ratchet-init  inside Claude Code
python3 ratchet.py validate  # the block-requires-fact invariant + structural sanity
```

`ratchet` dogfoods itself — see [`ratchet.toml`](ratchet.toml): its own change layer re-runs
its own test suite from the base-pinned policy.

## Status

v0.1 — engine + Claude Code plugin (agent layer) + `/ratchet-init` repo wiring (change
layer). Stdlib Python (3.11+), no third-party deps, no package manager. MIT.

A real-world policy lives in [`examples/pixtuoid/ratchet.toml`](examples/pixtuoid/ratchet.toml)
— a faithful port of an 890-line bespoke DoD gate into 16 declarative checks.
