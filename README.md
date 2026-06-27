<p align="center"><img src="assets/logo.svg" alt="ratchet" width="96" height="96"></p>
<h1 align="center">ratchet</h1>

<p align="center"><b>A Definition-of-Done gate for AI coding agents.</b><br>
Prose binds intention. Only mechanism binds behavior.</p>

<p align="center"><img src="assets/concept.svg" alt="Prose asks; ratchet enforces" width="840"></p>

When an AI agent closes a task it tends to skip the unglamorous last mile —
forgets the test, bypasses the hook with `--no-verify`, deletes the failing test
to go green, leaves the docs stale, or *says* it reviewed when it didn't. A
`CLAUDE.md` that says "always run the tests" is a suggestion the same model can
rationalize past. **ratchet turns that closing-discipline into a gate the agent
can't talk its way around** — a Claude Code plugin you install once.

It rests on one rule:

```
severity = "block"   REQUIRES   kind = "fact"
```

A **fact** decides only over things the agent can't fake — the normalized diff,
the command it's about to run, PR/commit metadata, reviewer approvals. Those may
hard-block. Anything that needs *judgment* (an LLM-judge, a self-attestation) is
**advisory** — it warns or nudges, never blocks. That single invariant is the
whole moat: a forgetful or over-confident agent can't pass a block it didn't
actually satisfy, because **it never authored the evidence the block reads.**

One language-agnostic engine, one per-repo `ratchet.toml`. The engine reads git
facts + your config; it never imports your project code. Anything
language-specific goes through the one `run` escape hatch. The engine itself is a
single stdlib-only `ratchet.py` — auditable in plain text, zero dependencies, no
package manager.

## What it catches

Every shortcut an agent takes to *look* done maps to a fact it can't author. The
right-hand column is the ungameable signal each rule reads:

<p align="center"><img src="assets/catches.svg" alt="Each corner-cut and the fact that catches it" width="840"></p>

The three **NEW** rules close the canonical "make CI green by doing less"
corner-cuts that pure pattern-matching is blind to — they extend the engine's
fact surface to the parts of a diff most gates never look at:

- **`forbid_removal`** — the `-` twin of `forbid_pattern`. A *removed* line
  matching a guard pattern (an `assert`, an `await`, an error-propagating `?`, an
  auth check, a `# nosec` / SPDX header) blocks. *"Silently delete the safety
  net"* is the most common AI corner-cut, and the one a content scanner of
  *added* lines cannot see.
- **`forbid_delete`** — file D-status guard. *"Delete the failing test to reach
  green."* Whole-file deletions under a scope block (with `unless_paired_add` to
  let a genuine rename/reorg through).
- **`forbid_commit_on_branch`** — the live-branch fact. *"Commit straight to
  main."* The `PreToolUse` hook denies a commit/push on a protected branch in
  real time; the only way past is `git checkout -b`, which is the intended
  outcome. (A `run` block can't substitute — it's not a real-time op-denier.)

## Why not just CLAUDE.md? (even nested, per-directory)

`CLAUDE.md` / `AGENTS.md` is the right tool for **intent** — architecture,
conventions, why a sharp edge exists. Keep it. But it is structurally incapable
of **enforcing** the closing-discipline, and writing more of it doesn't fix that:

1. **The reader is the violator.** The same model that reads "always run the
   tests" decides whether to. An instruction it can rationalize past ("trivial
   change, I'll test later") is a suggestion to itself, not a gate.
2. **Salience decays exactly when it matters.** Long sessions summarize and evict
   early context; a nested `CLAUDE.md` only loads when you touch that tree; big
   files get skimmed. Closing-discipline is needed at the *end* of a long task —
   precisely when the instruction is faintest.
3. **Prose can't reject an action.** It cannot return a non-zero exit code. The
   agent can run `git commit --no-verify` and no `CLAUDE.md` will stop the tool
   call. ratchet's `PreToolUse` hook *denies* it, in real time, before it runs.
4. **Self-report is gameable.** "I did a two-lens review" / "docs updated" is
   authored by the gated agent. A check that trusts the agent's own claim is no
   check. ratchet blocks only on facts the agent can't author.
5. **More prose ≠ more binding.** Splitting rules across many `CLAUDE.md` files
   improves locality of *intent*, not enforcement. Ten unenforced rules are
   bypassed as easily as one. You can't patch an enforcement gap with docs.
6. **The rulebook is editable in the same breath.** An agent can delete the
   "no `--no-verify`" line from `CLAUDE.md` in the very change that uses it.
   ratchet reads its policy from the pinned base ref — the gate you're under is
   the one that existed *before* your diff ([proof below](#why-its-bypass-proof)).

ratchet doesn't replace `CLAUDE.md`; it's the mechanism half of the idea your
`CLAUDE.md` already states.

## Two layers, one config

<p align="center"><img src="assets/layers.svg" alt="The agent layer and the change layer enforce the same config twice" width="840"></p>

| Layer | Fires at | Authority |
|---|---|---|
| **agent** | Claude Code `PreToolUse` / `Stop` hook — real time | denies `--no-verify`, a commit/push on a protected branch, and a `git push` / `gh pr merge` whose DoD fails; `Stop` blocks turn-end on unticked attestation boxes. Bypassable via `[meta].bypass_env` (always logged) |
| **change** | git pre-push hook + CI | **authoritative** — base-pinned, ignores the bypass env |

The agent layer is *friction in real time* — it catches the cut at the moment the
agent reaches for it and mirrors what CI will enforce, so you fix it before you
push. The change layer is the *final word* — a red CI check no env var can turn
green.

## Install

The plugin runs two tiny Python lifecycle hooks, so `python3` (3.11+) needs to be
on your PATH — including the *non-interactive* shell's PATH for Nix/nvm-style
setups. If it isn't, nothing errors; the always-on gate just stays quiet.

### 1 · Add the plugin (Claude Code)

```
/plugin marketplace add IvanWng97/ratchet
```
```
/plugin install ratchet@ratchet
```
(Two separate prompts — send them one at a time.)

> The desktop app has no `/plugin` command: Customize → the `+` by personal
> plugins → Create plugin and add marketplace → Add from repository → the repo URL.

That gives you the **agent layer** immediately — the `PreToolUse` deny + `Stop`
nudge fire every session, and `/ratchet-init` / `/ratchet-check` become
available. "Default-on" means enforcement is a property of your client + the
repo, not a step the agent has to remember.

### 2 · Wire the change layer (once per repo)

The agent layer is per-developer; the authoritative **change layer** (pre-push +
CI, base-pinned, un-bypassable) is per-repo. Run once, inside Claude Code:

```
/ratchet-init
```

It vendors the single-file engine to `.ratchet/ratchet.py`, scaffolds
`ratchet.toml`, and adds the CI step. Commit those and every clone — every agent,
every PR — meets the same gate. The CI step is just:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }          # base-pinning needs history
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: python3 .ratchet/ratchet.py check
```

No npm, no package manager, no binary download — one stdlib-Python file,
committed.

## Why it's bypass-proof

A `fact` block is only ungameable if the agent can't edit the gate **in the same
diff it's being gated on**.

<p align="center"><img src="assets/bypass.svg" alt="Base-pinning: the gate is read from the base ref, not the PR head" width="840"></p>

1. **Base-pinning** — `ratchet.toml` (and your gate-defining files) are read from
   the pinned base ref, never the PR head. A same-PR edit that relaxes a check is
   evaluated against the *old* policy, so it can't disarm itself.
2. **`protected_path`** — changing those gate-defining files needs an independent
   approval, or the gate refuses.
3. **Isolated `run`** — invoke tools isolated (`ruff --isolated`, a pinned
   `pytest -c …`) so head-side config can't defang the teeth.

ratchet dogfoods itself. Here it refuses to be disarmed — one commit that adds a
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
because the policy is read from the **base ref**. That is the difference between a
rule and a gate.

This isn't hypothetical — it's a documented failure class. Two reports against
Claude Code, in the maintainers' own tracker, name it exactly:

- [#32198](https://github.com/anthropics/claude-code/issues/32198) — *"Claude
  Code skips mandatory rules in CLAUDE.md (**Definition of Done**)"*
- [#40117](https://github.com/anthropics/claude-code/issues/40117) — *"Agent
  bypasses git pre-commit hooks using `--no-verify` … **despite explicit deny
  rules**"*

Both describe a prose rule the agent read and then ignored. That is precisely the
gap ratchet closes: a prose rule *asks*; ratchet makes the unwanted outcome a
non-event — the `--no-verify` call is denied before it runs, and the skipped step
reds a gate it can't edit.

## The primitive library

Every check reads only facts — never your code.

| primitive | kind | decides over |
|---|---|---|
| `forbid_command{pattern,deny}` | fact | the agent's command string — `deny` matches the **normalized** verb, defeating `git -C/p push` / `cd d && …` / `env X=Y …` wrappers (agent layer) |
| `forbid_commit_on_branch{branch,ops}` | fact | the live current branch (agent layer) |
| `secret_scan{forbid_paths,custom}` | fact | added lines vs token shapes + forbidden file globs |
| `forbid_pattern{pattern,scope,exempt,strip_comments}` | fact | **added** lines under a path scope |
| `forbid_removal{pattern,scope,exempt,strip_comments}` | fact | **removed** lines under a path scope |
| `forbid_delete{scope,unless_paired_add,exempt}` | fact | per-file D-status (a deletion under scope) |
| `scope_lock{allow}` | fact | every A/M/D path must be inside the allowlist (scope creep) |
| `numeric_floor{key,direction,floor}` | fact | a numeric value's **direction** across the diff (lower coverage / raised retries / shortened timeout) |
| `path_requires{when,need}` | fact | name-status: if `when` changed, `need` must too |
| `cooccur{trigger,require}` | fact | if `trigger` appears (diff/PR), `require` must too |
| `marker_present{marker,when}` | fact | a marker block exists in the PR body |
| `forbid_in_message{tokens,msg_scope}` | fact | forbidden tokens in a commit/PR message (e.g. `[skip ci]`) |
| `commit_footer{}` | fact | every commit ends with `[meta].commit_footer` |
| `protected_path{paths,require_approval}` | fact | gate-defining files changed → need an independent approval |
| `run{cmd}` | fact\* | shell-out; the exit code is the fact (**`block` only at the change layer**) |
| `attest{box,class}` | advisory | a class-gated `Stop`-hook checklist box — blocks turn-end until ticked (forcing function; the change layer is the ungameable gate) |
| `judge{prompt}` | advisory | an advisory LLM-judge prompt (CI `continue-on-error` substance check) |

### What it does and doesn't claim

ratchet guarantees the **forcing function**, not omniscience. A `fact` block can't
be talked past — that's the strong claim, and it holds. But `secret_scan` is
best-effort pattern matching (pair it with `gitleaks` via a `run` block for
depth); `forbid_removal`/`forbid_pattern` are presence-ungameable but
value-gameable (`assert!(true)` satisfies a naive "has an assert"); `attest` /
`judge` are advisory by construction; and a determined human with repo-admin
rights can always change the base policy through review. The line ratchet draws:
**anything an agent can do mid-task to cut a corner, it stops; anything that needs
human judgment stays advisory and visible.** That boundary is enforced by the
schema itself (`block` requires `fact`), so the guarantee can't silently erode.

## Config & recipes

Start from a scaffold, then validate:

```
python3 ratchet.py init       # or  /ratchet-init  inside Claude Code
python3 ratchet.py validate   # checks the block-requires-fact invariant + structural sanity
```

Ready-to-lift policies:

- [`examples/pixtuoid/ratchet.toml`](examples/pixtuoid/ratchet.toml) — a faithful
  port of an 890-line bespoke DoD gate (Rust workspace) into 21 declarative checks.
- [`examples/node-ts/ratchet.toml`](examples/node-ts/ratchet.toml) — a Node/TS repo.
- [`examples/python/ratchet.toml`](examples/python/ratchet.toml) — a Python repo.

ratchet dogfoods itself — see [`ratchet.toml`](ratchet.toml): its own change layer
re-runs its own test suite from the base-pinned policy, and `branch-first` +
`keep-tests` + `no-test-delete` guard this very repo with the primitives it ships.

## Status

v0.1 — engine + Claude Code plugin (agent layer) + `/ratchet-init` repo wiring
(change layer). Stdlib Python (3.11+), no third-party deps, no package manager.
MIT.
