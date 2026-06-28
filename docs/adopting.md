# Adopting ratchet

The end-to-end path from "I have a repo" to "the gate is enforcing," plus the two
decisions every adopter gets wrong: **what to gate vs. leave to your existing CI**, and
**when it's safe to promote a check from `warn` to `block`**. If you're replacing an
existing gate, jump to [Migrating off an existing gate](#migrating-off-an-existing-gate).

The one rule underneath all of this: `severity = "block"` **requires** `kind = "fact"`
and an environment-authored fact (a diff, a file status, a branch, a CI conclusion, a
non-author approval). A judgment — an LLM verdict, a self-typed marker — is gameable by
the agent it gates, so it may only *warn*. That's the moat; adoption is mostly learning
to lean on it. See [`SCHEMA.md`](../SCHEMA.md) for the full surface.

## The path

```
install ─▶ draft (suggest) ─▶ draft-lint --simulate ─▶ ride at warn / report-only
        ─▶ backtest ─▶ promote warn→block ─▶ regression-test with fixtures
```

### 1 · Install

```
python3 ratchet.py install     # vendor .ratchet/ratchet.py + scaffold config/hook/CI/gitignore
```

(or `/ratchet-init` in Claude Code). `install` is idempotent — re-run it any time. It
vendors the engine to `.ratchet/ratchet.py` (committed, base-pinnable), wires the pre-push
hook, and scaffolds the CI workflow. Verify both layers with `ratchet doctor`.

### 2 · Draft a policy (don't hand-write from scratch)

```
python3 ratchet.py suggest --format toml   # a ranked, ready-to-arm TOML draft (CLAUDE.md rules → primitives)
python3 ratchet.py suggest                 # default: the JSON contract a host agent consumes (+ a `languages` breakdown)
python3 ratchet.py gaps                    # which CLAUDE.md house-rules NO check binds yet
```

`suggest` mines your `CLAUDE.md`/`AGENTS.md` house-rules and your tracked files into a
**ranked, all-`warn` draft** — every *inferred* check is born `warn`; only the safe-core ids
have teeth (four born `block`; `protected-gate-files` born `warn` — see
[below](#protected_path-promotion-solo-repo--team)). `suggest` itself **writes nothing**:
redirect `--format toml` into `ratchet.toml.draft` (or let the host agent author it from the
JSON), then **arm it** — review, resolve the `# TODO(ratchet:review)` markers, and `mv
ratchet.toml.draft ratchet.toml`. For a polyglot/monorepo, `suggest` detects the top
languages and the JSON `languages` array lets you author **per-subtree** checks (see
[`examples/monorepo/`](../examples/monorepo/)).

### 3 · Catch false-blocks *before* you arm (`--simulate`)

```
python3 ratchet.py draft-lint --simulate   # strict-validate the draft AND flag any block that
                                           # would fire on your EXISTING committed code
```

This is the step adopters miss. `draft-lint` is a superset of `validate` (it also gates on
unresolved `# TODO(ratchet:review)` markers); `--simulate` additionally replays every
`block` check against your current `HEAD` and reports any that would fire on code already in
the tree — i.e. a check that would block your *next* commit for a pre-existing reason. Fix
the scope or downgrade to `warn` before arming, so day one isn't a wall of false blocks.

### 4 · Ride non-failing first

Two independent ways to run the policy without failing anyone:

- **Per-check `severity = "warn"`** — *permanent, per-check*. The check fires and prints,
  never blocks. This is where most inferred checks should start.
- **`--report-only`** — *global, temporary* rollout switch. Runs the **authoritative**
  policy but always exits `0` (findings print + a CI annotation). Infra/config errors
  (unreachable base, unloadable config) still fail closed, so a shadow run can't go green
  while the gate never actually evaluated the diff.

  ```
  python3 ratchet.py check --report-only        # or `report-only: true` on the GitHub Action
  ```

Use per-check `warn` for checks you're unsure about long-term; use `--report-only` to ride
the *whole* policy over real PRs for a week before flipping it to enforce.

### 5 · Calibrate with `backtest`, then promote

```
python3 ratchet.py backtest --range main~50..main   # replay the policy over merged history
```

`backtest` replays your **current working policy** over a range of already-merged commits
and reports which would have blocked. A clean backtest over real history is the evidence
that promoting `warn → block` won't false-block legitimate work. (It covers diff-fact
checks only; `run` and PR-context checks — approvals, checks-green — are skipped and named
in the summary, so a clean report is never mistaken for "everything was exercised.")

**Promote when:** a check has run at `warn` (or under `--report-only`) over real PRs without
a false positive, **and** `backtest` is clean for it over recent history. Then change its
`severity` to `block`. Promote the cheap, unambiguous facts first (secret-scan,
test-deletion); leave the judgment-adjacent ones at `warn`.

### 6 · Regression-test the policy itself

Your `ratchet.toml` is load-bearing code — test it like code, so a later edit can't
silently neuter a check:

```
# runnable from examples/monorepo/ (the policy is that dir's ratchet.toml):
python3 ratchet.py check --cwd . --diff-file fixtures/rust-dbg.diff        --expect-block no-rust-dbg
python3 ratchet.py check --cwd . --diff-file fixtures/cross-isolation.diff --expect-clean no-js-console
```

A crafted diff + a per-check expectation; exit `0` = met, `1` = a violated expectation
(your regression net), `2` = couldn't run. The second line is the one `validate` can't give
you: it proves `no-js-console`'s `scope` really *confines* it — a `console.log` that lands in
the Rust subtree must **not** trip it. `validate` has no repo access, so it can't catch a glob
typo; only a fixture can. See [`examples/monorepo/fixtures/`](../examples/monorepo/fixtures/)
for the full per-subtree coverage set.

## What to gate vs. leave to your existing CI

This is the decision that determines whether ratchet *helps* or just *duplicates*. ratchet
exists to gate **process facts your CI and linters don't already check** — the
"closing-discipline" cuts an AI agent takes to make a task *look* done:

| Gate with ratchet (process facts) | Leave to your existing CI / linters |
| --- | --- |
| secrets / `.env` committed | the test **suite** itself |
| a deleted test, a stripped `assert` | type-checking, formatting |
| coverage / threshold *lowered* (`numeric_floor`) | building the artifact |
| `--no-verify`, commit on `main` (live, agent layer) | linting rules a linter already enforces |
| a required marker / footer / ledger trace | |
| a change needing a non-author approval | |

**Don't duplicate your CI.** If your repo already runs its test suite in CI, **do not add a
`run` block that re-runs it** — that's slower and redundant. The shipped
[`examples/pixtuoid/ratchet.toml`](../examples/pixtuoid/ratchet.toml) is the worked
reference: it ports an 890-line bespoke gate yet has **no `run` block — "the teeth are
pixtuoid's existing CI."** ratchet gates the closing-discipline; the compiled-code suite
stays in CI where it already runs.

If you additionally want ratchet to *enforce* that your existing CI was actually green
before a merge — not just decline to re-run it — require those jobs with
`require_checks_green` (an environment fact: the PR API's check conclusions):

```toml
[[check]]
id = "ci-green"
kind = "fact"
severity = "block"
primitive = "require_checks_green"
need = ["build", "test"]        # your existing job names; ratchet just requires they passed
```

Use a `run` block (as [`examples/python/ratchet.toml`](../examples/python/ratchet.toml)
does) only when the repo has **no** CI yet and ratchet's pre-push/CI is the *first* place
the suite runs.

## `protected_path` promotion (solo repo → team)

The `protected-gate-files` safe-core check is born `warn`, not `block` — deliberately. It
requires a **fresh, non-author** approval to change a gate-defining file, and a solo repo
has no second approver (GitHub forbids approving your own PR), so a `block` would be an
*unclearable wall*. Born `warn`, it's a loud nag you can still merge past. **Promote it to
`block` once a second reviewer or a CODEOWNERS exists** — at that point the approval is a
real environment fact and the moat lets it block. (Its live agent-layer twin, `self-protect`,
*is* born `block`: it denies an in-session Write/Edit to a gate file, which needs no
approver.)

## Migrating off an existing gate

Replacing a bespoke gate (a `check_dod.py`, a pile of CI shell, a custom bot)? Don't
flip-the-switch — **prove parity, then delete**:

1. **Port the rules.** Map each old rule to a primitive (or a `run`/`require_checks_green`
   that delegates to a tool already doing the work). `suggest` + `gaps` seed this; see
   [`docs/composition.md`](composition.md) for the honest-claims map of which primitive
   answers which requirement.
2. **Ride in parallel at `warn`/`--report-only`.** Keep the old gate authoritative while
   ratchet runs alongside, non-failing, on real PRs.
3. **Prove parity.** For every catch the old gate made, write a **fixture** (`check
   --diff-file --expect-block <id>`) that reproduces it, and `backtest` over the history the
   old gate guarded. When ratchet blocks everything the old gate did (and nothing it
   shouldn't), parity is proven — in tested, reviewable form, not by assertion.
4. **Flip + delete.** Promote the ported checks to `block`, remove the old gate in the same
   PR. [`examples/pixtuoid/ratchet.toml`](../examples/pixtuoid/ratchet.toml) is a faithful
   port of an 890-line bespoke gate into declarative checks — a worked reference.

## Troubleshooting

- **`doctor` prints `· skip` for the agent layer.** Expected outside Claude Code. The
  agent layer (the live PreToolUse/Stop hooks) only exists *inside* a Claude Code session,
  so `doctor` checks `CLAUDE_PLUGIN_ROOT` and skips that line from a plain shell or CI —
  it's **not** a breakage. Run `/ratchet-doctor` *inside* Claude Code to verify the plugin
  is active. The change layer (pre-push + CI) is what `doctor` verifies from a shell, and
  it's the authoritative one.
- **A check blocks on pre-existing code.** You skipped step 3 — run `draft-lint --simulate`,
  then tighten the `scope` or downgrade to `warn`.
- **The engine looks stale for the config** (`unknown primitive` / `unsupported schema`).
  The vendored `.ratchet/ratchet.py` predates a config that uses a newer primitive — run
  `ratchet update` to re-vendor the active engine.
- **CI's `require_checks_green` self-blocks.** If ratchet runs as a job in the *same*
  workflow it gates, its own check is still pending at query time — exclude it with
  `ignore = ["<ratchet job name>"]`, or `need` only the other checks.
