# Adopting cogpin

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
python3 cogpin.py install     # vendor .cogpin/cogpin.py + scaffold config/hook/CI/gitignore
```

(or `/cogpin-init` in Claude Code). `install` is idempotent — re-run it any time. It
vendors the engine to `.cogpin/cogpin.py` (committed, base-pinnable), wires the pre-push
hook, and scaffolds the CI workflow. Verify both layers with `cogpin doctor`.

### 2 · Draft a policy (don't hand-write from scratch)

```
python3 cogpin.py suggest --format toml   # a ranked, ready-to-arm TOML draft (CLAUDE.md rules → primitives)
python3 cogpin.py suggest                 # default: the JSON contract a host agent consumes (+ a `languages` breakdown)
python3 cogpin.py gaps                    # which CLAUDE.md house-rules NO check binds yet
```

`suggest` mines your `CLAUDE.md`/`AGENTS.md` house-rules and your tracked files into a
**ranked, all-`warn` draft** — every *inferred* check is born `warn`; only the safe-core ids
have teeth (four born `block`; `protected-gate-files` born `warn` — see
[below](#protected_path-promotion-solo-repo--team)). `suggest` itself **writes nothing**:
redirect `--format toml` into `cogpin.toml.draft` (or let the host agent author it from the
JSON), then **arm it** — review, resolve the `# TODO(cogpin:review)` markers, and `mv
cogpin.toml.draft cogpin.toml`. For a polyglot/monorepo, `suggest` detects the top
languages and the JSON `languages` array lets you author **per-subtree** checks (see
[`examples/monorepo/`](../examples/monorepo/)).

### 3 · Catch false-blocks *before* you arm (`--simulate`)

```
python3 cogpin.py draft-lint --simulate   # strict-validate the draft AND flag any block that
                                           # would fire on your EXISTING committed code
```

This is the step adopters miss. `draft-lint` is a superset of `validate` (it also gates on
unresolved `# TODO(cogpin:review)` markers); `--simulate` additionally replays every
`block` check against your current `HEAD` and reports any that would fire on code already in
the tree — i.e. a check that would block your *next* commit for a pre-existing reason. Fix
the scope or downgrade to `warn` before arming, so day one isn't a wall of false blocks.

`--simulate` is the *pre-arming* test: it reads the **draft** directly and proves no `block`
would false-fire on your existing code. Its complement — proving a block **does** fire on a
real violation, so your policy isn't silently inert — needs a live `cogpin.toml` and a check
that's actually at `block`, so it lands *after* you arm and promote: that's §6's
`check --diff-file … --expect-block <id>` (which reads the working `cogpin.toml`, not the
`.draft`). Knowing both tests exist up front lets you arm with evidence on both sides, instead
of eating a week of noisy real-PR warnings to discover the policy was wrong.

### 4 · Ride non-failing first

Two independent ways to run the policy without failing anyone:

- **Per-check `severity = "warn"`** — *permanent, per-check*. The check fires and prints,
  never blocks. This is where most inferred checks should start.
- **`--report-only`** — *global, temporary* rollout switch. Runs the **authoritative**
  policy but always exits `0` (findings print + a CI annotation). Infra/config errors
  (unreachable base, unloadable config) still fail closed, so a shadow run can't go green
  while the gate never actually evaluated the diff.

  ```
  python3 cogpin.py check --report-only        # or `report-only: true` on the GitHub Action
  ```

Use per-check `warn` for checks you're unsure about long-term; use `--report-only` to ride
the *whole* policy over real PRs for a week before flipping it to enforce.

### 5 · Calibrate with `backtest`, then promote

```
python3 cogpin.py backtest --range main~50..main   # replay the policy over merged history
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

Your `cogpin.toml` is load-bearing code — test it like code, so a later edit can't
silently neuter a check:

```
# runnable from examples/monorepo/ (the policy is that dir's cogpin.toml):
python3 cogpin.py check --cwd . --diff-file fixtures/rust-dbg.diff        --expect-block no-rust-dbg
python3 cogpin.py check --cwd . --diff-file fixtures/cross-isolation.diff --expect-clean no-js-console
```

A crafted diff + a per-check expectation; exit `0` = met, `1` = a violated expectation
(your regression net), `2` = couldn't run. The second line is the one `validate` can't give
you: it proves `no-js-console`'s `scope` really *confines* it — a `console.log` that lands in
the Rust subtree must **not** trip it. `validate` has no repo access, so it can't catch a glob
typo; only a fixture can. See [`examples/monorepo/fixtures/`](../examples/monorepo/fixtures/)
for the full per-subtree coverage set.

## What to gate vs. leave to your existing CI

This is the decision that determines whether cogpin *helps* or just *duplicates*. cogpin
exists to gate **process facts your CI and linters don't already check** — the
"closing-discipline" cuts an AI agent takes to make a task *look* done:

| Gate with cogpin (process facts) | Leave to your existing CI / linters |
| --- | --- |
| secrets / `.env` committed | the test **suite** itself |
| a deleted test, a stripped `assert` | type-checking, formatting |
| coverage / threshold *lowered* (`numeric_floor`) | building the artifact |
| `--no-verify`, commit on `main` (live, agent layer) | linting rules a linter already enforces |
| a required marker / footer / ledger trace | |
| a change needing a non-author approval | |

**Don't duplicate your CI.** If your repo already runs its test suite in CI, **do not add a
`run` block that re-runs it** — that's slower and redundant. The shipped
[`examples/pixtuoid/cogpin.toml`](../examples/pixtuoid/cogpin.toml) is the worked
reference: it ports an 890-line bespoke gate yet has **no `run` block — "the teeth are
pixtuoid's existing CI."** cogpin gates the closing-discipline; the compiled-code suite
stays in CI where it already runs.

**Runtime containment is *declared*, not enforced by cogpin.** To confine the agent — no
network, no `~/.ssh`, a command allowlist — use the `[capability]` stanza: cogpin *records*
the posture and compiles it to the harness (`cogpin capability emit` → `.claude/settings.json`),
but the **OS / harness is what enforces it** — cogpin is never in the syscall path (policy, not
enforcement; the in-band command deny is a forcing-function, not a sandbox). See
[`examples/capability-sandbox/`](../examples/capability-sandbox/cogpin.toml) for a worked stanza
with the honest per-field caveats (`no_network` can't *guarantee* no egress; `allow_commands` is
adds-only). That same recipe also demos `scope_lock` — a positive path-allowlist for the
scope-creep cut.

If you additionally want cogpin to *enforce* that your existing CI was actually green
before a merge — not just decline to re-run it — require those jobs with
`require_checks_green` (an environment fact: the PR API's check conclusions):

```toml
[[check]]
id = "ci-green"
kind = "fact"
severity = "block"
primitive = "require_checks_green"
need = ["build", "test"]        # your existing job names; cogpin just requires they passed
```

Use a `run` block (as [`examples/python/cogpin.toml`](../examples/python/cogpin.toml)
does) only when the repo has **no** CI yet and cogpin's pre-push/CI is the *first* place
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
   cogpin runs alongside, non-failing, on real PRs.
3. **Prove parity.** For every catch the old gate made, write a **fixture** (`check
   --diff-file --expect-block <id>`) that reproduces it, and `backtest` over the history the
   old gate guarded. When cogpin blocks everything the old gate did (and nothing it
   shouldn't), parity is proven — in tested, reviewable form, not by assertion.
4. **Flip + delete.** Promote the ported checks to `block`, remove the old gate in the same
   PR. [`examples/pixtuoid/cogpin.toml`](../examples/pixtuoid/cogpin.toml) is a faithful
   port of an 890-line bespoke gate into declarative checks — a worked reference.

## Troubleshooting

- **`doctor` prints `· skip` for the agent layer.** Expected outside Claude Code. The
  agent layer (the live PreToolUse/Stop hooks) only exists *inside* a Claude Code session,
  so `doctor` checks `CLAUDE_PLUGIN_ROOT` and skips that line from a plain shell or CI —
  it's **not** a breakage. Run `/cogpin-doctor` *inside* Claude Code to verify the plugin
  is active. The change layer (pre-push + CI) is what `doctor` verifies from a shell, and
  it's the authoritative one.
- **The cogpin pre-push block runs before my own hook code.** By design. The managed block is
  placed first (right after the shebang) and gates with `… || exit 1`, so it runs — and can block
  the push — before any user code, and can never be shadowed by a later process-replacing `exec`/`exit`.
  Your existing hook content is preserved verbatim, just below the block; re-running `cogpin install`
  lifts an old block that a prior version appended after an `exec` up to the top.
- **A check blocks on pre-existing code.** You skipped step 3 — run `draft-lint --simulate`,
  then tighten the `scope` or downgrade to `warn`.
- **The engine looks stale for the config** (`unknown primitive` / `unsupported schema`).
  The vendored `.cogpin/cogpin.py` predates a config that uses a newer primitive — run
  `cogpin update` to re-vendor the active engine.
- **CI's `require_checks_green` self-blocks.** If cogpin runs as a job in the *same*
  workflow it gates, its own check is still pending at query time — exclude it with
  `ignore = ["<cogpin job name>"]`, or `need` only the other checks.
- **`check` prints `N block approval/checks check(s) INERT … enforced NOTHING`.** The
  approval/checks family (`protected_path`, `require_approval_from`, `pattern_requires_approval`,
  `approval_policy`, `require_checks_green`) reads a PR fact supplied only by a PR-context run via
  `--reviews-file` / `--approvals` / `--checks-file` (the [Action](../action.yml) passes them on its
  `pull_request` path). Whenever those facts are absent — another platform, a foreign harness, the
  local pre-push, or a GitHub `push`-event run (no PR exists) — the check **silently no-ops**; cogpin
  now says so loudly rather than print a bare `ok` that reads as enforced. It stays exit 0. To make
  the check actually enforce, run it where the PR facts exist (CI on the `pull_request` path) or pass
  the equivalent files; otherwise the advisory is the honest statement that this lens is unenforced
  for that run. (The stderr line always prints; the Actions annotation is skipped on `push` events to
  avoid non-actionable noise on green main builds. `warn`-severity checks are never flagged — they
  had no teeth to lose.)
- **A check fails with `evaluation exceeded the … budget … possible ReDoS`.** One of your author
  regexes (`forbid_pattern` / `secret_scan` / `numeric_floor` / …) hit the per-check wall-clock cap
  evaluating an added line — almost always a *catastrophic-backtracking* pattern: a quantified group
  whose body is itself quantified (`(a+)+`, `(a*)*`, `(\d+){2,}`). On a public repo the added line is
  attacker-controlled, so the cap is a security property, not just a footgun — it fails the check
  loud instead of hanging the gate. Fix the **pattern**, not the input: rewrite it to be linear (e.g.
  `a+` instead of `(a+)+`, an explicit character class instead of nested quantifiers). The
  authoring-time warning (`draft-lint`, and every `check` run) flags these shapes before you arm — but
  it's a *partial* heuristic: it catches nested quantifiers, **not** alternation overlap (`(a|aa)+`),
  so on a Windows-only-CI repo (where the runtime cap degrades to a no-op) those stay unbounded and
  unwarned. The robust posture is to keep at least one POSIX job in the authoritative gate — the
  wall-clock budget covers both shapes there. See [`SCHEMA.md`](../SCHEMA.md).
- **`cogpin requires Python 3.11+`.** The engine uses the stdlib `tomllib` (Python 3.11). The
  GitHub Action pins a modern Python, but the local PreToolUse/pre-push hooks run your *system*
  `python3` — and Ubuntu/Debian's is still 3.10. If you hit this line, point the hook at a 3.11+
  interpreter (a `pyenv`/`asdf` shim, or `python3.11` on `PATH`).
