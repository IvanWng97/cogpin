# `ratchet.toml` — schema reference

The complete config surface. One TOML file per repo, read by the engine
([`ratchet.py`](ratchet.py)) — never your code. `python3 ratchet.py validate`
enforces everything below at parse time.

## The one rule

```
severity = "block"   REQUIRES   kind = "fact"  AND  provenance = "environment"
```

Only an ungameable, **environment-authored** fact may hard-block — two clauses, both
enforced by `validate`:

1. **`kind="fact"`** — a judgment (`judge`, `attest`) can warn or nudge but never blocks.
2. **`provenance="environment"`** — the fact must be produced by git / the harness / the PR
   API (a real diff, file status, branch, CI conclusion, a non-author approval), **not** a
   token the gated agent *types* that merely claims an out-of-band event. So `marker_present`
   (a self-typed PR-body marker) is `kind="fact"` but `provenance="agent"` → it may only
   **warn**. To actually *gate* a review, block on a real non-author approval
   (`require_approval_from` / `approval_policy`).

Provenance is a property of each primitive's `Spec`; the guarantee can't silently erode
through config. **Caveat (not enforceable structurally):** the message/number families
(`require_message_pattern`, `file_must_contain`, `commit_footer`, `forbid_in_message`,
`numeric_floor`) are `provenance="environment"` because the regulated artifact *is* the
committed text/number — but an author can still abuse them to encode an event-claim as a
required phrase (`"Tested: yes"`) or hand-edit a metric. For event-claims, use `attest`/`judge`;
pair `numeric_floor` with a `run`-generated metric file. The `marker_present`-vs-message line is
drawn on *typical use* (a marker has no non-attestation use), not on raw fabricability.

---

## Top level

```toml
schema = 1            # required; must equal the engine's SCHEMA_VERSION (1)
```

### `[repo]`

Named scopes a check can reference by name instead of repeating globs.

| key | type | default | meaning |
|---|---|---|---|
| `default_branch` | string | `"main"` | the branch `forbid_commit_on_branch` protects and the base-pin / diff range resolve against |
| `code` | string \| list | `[]` | the `code` named scope |
| `tests` | string \| list | `[]` | the `tests` named scope |
| `docs` | string \| list | `[]` | the `docs` named scope |
| `public_surface` | string \| list | `[]` | the `public_surface` attestation class scope |
| `claude_md` | string \| list | `["**/CLAUDE.md","**/AGENTS.md"]` | the `claude_md` attestation class scope |

A check's `scope` / `when` / `need` / `allow` may name `code` / `tests` / `docs`
to expand to these globs, or give a literal glob directly.

### `[meta]`

| key | type | default | meaning |
|---|---|---|---|
| `base_pinned` | bool | `true` | read `ratchet.toml` + gate-defining files from the pinned **base** ref, not the PR head (bypass-proof). Turning this off is itself a gate-defining change |
| `bypass_env` | string | — | the agent-layer escape-hatch env var (e.g. `RATCHET_BYPASS`). A non-empty value (or a `<ENV-with-dashes>: <reason>` line in the attestation) skips the **agent** layer — always logged. The **change** layer ignores it |
| `commit_footer` | string (regex) | — | the footer every commit must carry (read by the `commit_footer` primitive) |
| `attestation_file` | string | `.ratchet/attestation.md` | the Stop-hook checklist file the `attest` boxes look in |
| `feature_files` | int | `3` | a change is "feature-shaped" at ≥ this many changed files (or a new code module) — gates the `feature` attestation class |

---

## `[capability]` (optional)

A **declared** capability floor — *policy, not enforcement*. ratchet records and compares
this stanza and can **compile** it to a harness's native enforcement
(`ratchet capability emit`), but it **never** reads it during gate/check evaluation and
**never** confines a syscall itself. The OS / harness is the boundary; ratchet only declares
the posture (see [`docs/composition.md`](docs/composition.md) and the
[#24 re-brand](README.md)). Because it lives in `ratchet.toml`, it is `self_protect`'d and
read from the pinned base ref for free.

| key | type | default | meaning |
|---|---|---|---|
| `no_network` | bool | `false` | the agent should run with no outbound network |
| `fs_confine` | list(glob) | `[]` | filesystem roots the agent is confined to (e.g. `["."]`) |
| `deny_paths` | list(glob) | `[]` | paths the agent must never touch (`["~/.ssh/**","**/.env"]`) |
| `allow_commands` | list(verb) | `[]` | command-verb allowlist (the strong, OS-enforceable default-deny posture) |
| `deny_commands` | list(verb) | `[]` | command-verb denylist (a declaration to *compile out*, not a hook match) |
| `backend` | string | `claude-code` | the `emit` target (`claude-code` \| `bubblewrap` \| `docker` \| `seccomp`); only `claude-code` is rendered today |

`ratchet capability emit` (claude-code) translates the floor into `.claude/settings.json`
`permissions` (`deny_paths` → `Read/Edit/Write(<p>)`; `deny_commands` → `Bash(<verb>:*)`;
`no_network` → deny `WebFetch`/`WebSearch`/`curl`/`wget`/`nc` **+ a warning that settings.json
cannot *guarantee* no egress**). It is idempotent and **non-clobbering** — it manages only
the entries it itself emitted (recorded in `.ratchet/capability-emitted.json`), never your
own. A non-`claude-code` backend is *documented, not emitted* (ratchet declares; you wire the
sandbox). **`emit` generates; it never contains.** `--dry-run` prints the merged settings
without writing.

---

## `[[check]]`

| key | type | required | meaning |
|---|---|---|---|
| `id` | string | ✓ | unique identifier (duplicate ids are a config error) |
| `kind` | `fact` \| `advisory` | ✓ | `fact` = ungameable; `advisory` = judged |
| `severity` | `block` \| `warn` \| `attest` \| `judge` | ✓ | `block` requires `kind="fact"` **and** `provenance="environment"` (see The one rule) |
| `primitive` | string | ✓ | one of the primitives below |
| `layer` | `agent` \| `change` \| `both` | `change` | where it fires |

All remaining keys are primitive parameters — each primitive reads only the ones
listed for it.

A complete check reads top-to-bottom as *id · is-it-ungameable · how-hard · which-evaluator · its-params*:

```toml
[[check]]
id        = "keep-tests"        # unique
kind      = "fact"              # ungameable → allowed to block
severity  = "block"             # block REQUIRES kind = "fact"
primitive = "forbid_removal"    # the evaluator
scope     = "tests"             # a [repo] named scope, or a literal glob
pattern   = '^\s*def test_'     # the removed-line shape that blocks
```

That blocks any diff that *deletes* a `def test_…` line under `tests/`. Two of the
subtler primitives, inline:

```toml
# coverage can't ratchet down — blocks if `fail_under = N` drops across the diff
[[check]]
id = "coverage-floor"
kind = "fact"
severity = "block"
primitive = "numeric_floor"
key = 'fail_under\s*=\s*(\d+)'  # group 1 = the tracked value
direction = "no_decrease"

# touch the engine → you must touch a test (else just warn)
[[check]]
id = "engine-needs-tests"
kind = "fact"
severity = "warn"
primitive = "path_requires"
when = "code"                  # if a code-scoped path changed…
need = "tests"                 # …a tests-scoped path must change too
```

### Layers

- **agent** — fires at the Claude Code `PreToolUse` / `Stop` hook, in real time.
  Bypassable via `[meta].bypass_env` (logged). The *forcing function*.
- **change** — fires at the git pre-push hook + CI. **Authoritative**, base-pinned,
  ignores the bypass env. The real gate.
- **both** — evaluated in either context.

Some primitives are constrained: `forbid_commit_on_branch` and `self_protect` read
a *live* signal (current branch / the Write target) and must be `agent` or `both`;
a `run` block may only `block` at the `change` layer.

---

## Primitives

### Command / live-signal (agent layer)

#### `forbid_command`
The agent's command string.
- `pattern` (regex) — matched anywhere in the command (catches `--no-verify` in any position).
- `deny` (list) — **normalized**-verb match: strips `sudo` / `VAR=val` / `cd d &&` / `git -C p` / `git -c k=v` wrappers, then matches a contiguous token run, so the gated verb can't be smuggled past prefix matching.

#### `forbid_commit_on_branch`  *(agent / both)*
- `branch` (list of globs, default `[default_branch]`) — the protected branches.
- `ops` (list, default `["commit","push"]`) — the git ops to deny on them.

#### `self_protect`  *(agent / both)*
- `paths` (list of globs) — a `Write`/`Edit`/`MultiEdit`/`NotebookEdit` whose target matches is denied in real time. The live twin of `protected_path`.

### Diff-content facts

| primitive | params | blocks when |
|---|---|---|
| `secret_scan` | `forbid_paths`, `custom` (extra regexes) | a forbidden secret-path is added, or an added line matches a secret token shape |
| `forbid_pattern` | `pattern`, `scope`, `exempt`, `strip_comments` | an **added** line in scope matches `pattern` (and isn't `exempt`) |
| `forbid_removal` | `pattern`, `scope`, `exempt`, `strip_comments` | a **removed** line in scope matches `pattern` |
| `forbid_delete` | `scope`, `unless_paired_add`, `exempt` | a file under scope is **deleted** (D-status); `unless_paired_add` suppresses a paired rename/replace |
| `scope_lock` | `allow` | any A/M/D path falls **outside** the allowlist (an empty `allow` is inert) |
| `numeric_floor` | `key` (regex, group 1 = value), `direction` (`no_decrease`\|`no_increase`), `floor`, `scope` | the value weakens across the −/+ hunks on the same key, or crosses `floor` — read as a **minimum** under `no_decrease`, a **ceiling** under `no_increase` |
| `change_budget` | `max_added`, `max_removed`, `max_files`, `max_file_added`, `scope` | a count ceiling is exceeded |
| `file_must_contain` | `scope`, `pattern`, `status` (default `A`) | a changed file of `status` in scope adds **no** line matching `pattern` |
| `max_added_file_bytes` | `maxkb`, `allow_binary`, `scope` | an added/modified file exceeds `maxkb`, or is binary while `allow_binary=false` |

### Cross-file & message facts

| primitive | params | blocks when |
|---|---|---|
| `path_requires` | `when`, `need`, `when_marker` | a `when`-scoped path changed (or `when_marker` matched the PR body) but no `need` path did |
| `cooccur` | `trigger`, `require` | `trigger` appears (diff/PR/commit) but `require` does not |
| `marker_present` | `marker`, `when` | a `when`-scoped change lacks `marker` in the PR body (skips with no PR context). **`provenance="agent"` → `warn` only**: the marker is self-typed, so it can't hard-block (use a real approval to gate review) |
| `forbid_in_message` | `tokens`, `msg_scope` | a forbidden literal token is in the selected message scope(s) |
| `require_message_pattern` | `pattern`, `msg_scope` (default `commit_subject`) | a selected message does **not** match `pattern` |
| `commit_footer` | — (uses `[meta].commit_footer`) | a commit lacks the footer |

`msg_scope` ⊆ `{commit_subject, commit_body, pr_body}`.

### PR-metadata facts *(skip with no PR context; CI supplies them)*

| primitive | params | blocks when |
|---|---|---|
| `protected_path` | `paths`, `require_approval` | a gate-defining file changed without a **fresh, human, non-author** approval — when the `reviews` fact is present (CI), the approval must be on the current `head_sha`, not a bot, and not the author, so an approval of an earlier benign commit can't cover a later one (a flat `--approvals` list with no review metadata is only a degraded fallback). Born `warn` in the scaffold for solo repos (no independent approver); promote to `block` with a reviewer |
| `require_approval_from` | `paths`, `require_approval_from` (logins), `exclude_author`, `exclude_bot` | a change under `paths` has no APPROVED review from a listed owner |
| `pattern_requires_approval` | `pattern`, `scope`, `exclude_author`, `exclude_bot` | an added line in scope matches `pattern` but has no independent approval |
| `approval_policy` | `require_fresh`, `no_changes_requested`, `exclude_author`, `exclude_bot`, `min_approvals` | the count of **distinct** qualifying approvers is below `min_approvals`, or an outstanding `CHANGES_REQUESTED` remains |
| `require_checks_green` | `need` (allowlist of check names; empty = all), `ignore` (denylist) | a required status check did not conclude `success` — a `need`-listed check that never reported counts as **missing** and blocks (no vacuous pass) |

> **Same-workflow race:** when ratchet runs as a job in the *same* workflow it gates, its
> own check is still pending at query time and a bare `require_checks_green` (no `need`/`ignore`)
> would self-block. Exclude it with `ignore = ["<ratchet job name>"]`, or `need` only the other
> checks. `ratchet validate` prints a `note:` when neither is set. Both lists match the **rendered**
> check name exactly — a matrix job carries its suffix (e.g. `ratchet (ubuntu-latest)`), so use the
> name as it appears in `gh pr checks`.

These read CI-supplied facts via `ratchet check` flags: `--pr-body-file`,
`--approvals`, `--reviews-file` (a `gh pr view --json reviews` dump), `--head-sha`,
`--pr-author`, `--checks-file` (a `gh pr checks --json name,state` dump). Omitted →
the check skips rather than false-fires.

### Escape hatch & advisory

| primitive | kind | params | does |
|---|---|---|---|
| `run` | fact\* | `cmd` | shells out; the exit code is the fact. `block` only at the change layer |
| `attest` | advisory | `box`, `class`, `prompt` | a class-gated Stop-hook checklist box; blocks turn-end until ticked (forcing function only) |
| `judge` | advisory | `prompt` | emitted by `ratchet judge` for a CI `continue-on-error` LLM substance check |

`attest` classes: `always` (any code change) · `feature` (≥ `feature_files` or a new
module) · `public_surface` · `claude_md`. `box` defaults to the check `id`.

---

## CLI

```
# enforce
ratchet gate                    # agent layer: PreToolUse hook (reads the tool envelope on stdin)
ratchet stop --cwd .            # agent layer: Stop hook (blocks turn-end on unmet DoD)
ratchet check --cwd .           # change layer: gate the committed range (authoritative)
    [--no-run] [--allow-bypass] [--report-only]
    [--pr-body-file F] [--approvals a,b] [--reviews-file F]
    [--head-sha S] [--pr-author L] [--checks-file F]
    # --report-only: print findings + a summary but exit 0 (global, temporary rollout switch;
    #   distinct from per-check severity="warn"). Infra/config errors (unreachable base,
    #   unloadable config) STILL fail closed. The action exposes it as `report-only:`.
ratchet check --cwd . --diff-file F  # config-as-code: evaluate a crafted unified-diff FIXTURE
    [--expect-block a,b] [--expect-clean c,d]    # instead of the git range (tests ratchet.toml)
    [--commit-msg M] [--pr-body-file F] [--reviews-file F] [--checks-file F] [--approvals a,b] [--head-sha S] [--pr-author L]
    # Uses the WORKING config (you test the policy you're editing, not a base pin) and never runs
    #   `run` blocks. --expect-block/--expect-clean assert which checks fire: exit 0 = all met,
    #   1 = a violated expectation (the regression net), 2 = couldn't run. A unified diff carries
    #   no commit messages / blob sizes / PR context, so a check needing them is "blind" and an
    #   --expect over it errors (exit 2) rather than passing vacuously: supply --commit-msg
    #   (commit_footer / message checks), --reviews-file (approval primitives — flat --approvals
    #   un-blinds only protected_path), --checks-file (require_checks_green), --pr-body-file
    #   (marker_present / pr_body-scoped checks). `run`, max_added_file_bytes, and agent-layer /
    #   attest|judge checks are blind always (no diff can decide them). A supplied-but-unreadable
    #   context file is exit 2 (a test-authoring error), never coerced to empty. With no --expect
    #   flags it's a preview: print what would fire, exit 0.
ratchet backtest --cwd . --range main~50..main  # replay the policy over merged history (calibration)
    [--config F] [--fail-on-block]
    # which past commits WOULD this policy block? Pure report (exit 0) unless --fail-on-block;
    # exit 2 = couldn't run (bad range / shallow clone / unloadable config). Uses the WORKING
    # config; covers diff-fact checks only (`run` + PR-context checks are skipped + named).
ratchet judge --cwd .           # emit advisory judge prompts (CI pipes to a model)

# author
ratchet init --config ratchet.toml          # write a minimal starter config
ratchet validate --config ratchet.toml      # parse + the block-requires-fact invariant
ratchet suggest --cwd . [--format json|toml]  # repo facts → ranked draft (CLAUDE.md house-rules → primitives); writes NOTHING
    # POLYGLOT (#19): detects the top-K languages, not just the dominant one. The flat [repo].
    #   code/tests are the union over every detected language (a secondary enters at >=
    #   _SECONDARY_MIN_FILES=10 files — an ABSOLUTE floor, not a fraction, so a real 200-file
    #   subtree in a 5000-file repo is covered while 3 stray files are not). EVERY floor-clearing
    #   language is in the union (no cap → no language's files left uncovered).
    #   --format json adds a `languages` array [{name, file_count, code, tests}] (dominant-first) so
    #   a host agent can author PER-SUBTREE checks (a `console.log` forbid on JS-only, `println!` on
    #   Rust-only) that the merged blob can't express; --format toml adds a `# detected:` comment.
    #   See examples/monorepo/ for the literal-per-subtree recipe + its --diff-file coverage fixtures.
ratchet draft-lint --cwd . [--config ratchet.toml.draft] [--simulate]  # strict superset of validate; gates on # TODO(ratchet:review) markers
ratchet gaps --cwd . [--format text|json]   # advisory: which house-rules no check binds

# wire (the adoption surface)
ratchet install --cwd .         # vendor .ratchet/ratchet.py + scaffold config/hook/CI/gitignore (idempotent)
    [--no-vendor] [--no-config] [--no-hook] [--no-ci] [--no-gitignore]
ratchet uninstall --cwd .       # strip the local pre-push managed block (never removes committed source)
ratchet update --cwd .          # re-vendor the active engine → .ratchet/ratchet.py (fixes a stale-engine skew #16)
ratchet doctor --cwd . [--json] # diagnose both layers; one-line fix per finding
```

Exit codes: `gate` → `2` denies (stderr shown to the agent), `0` allows. `check` →
`1` on a blocking finding, `0` otherwise (warnings print, never fail). `stop` always
exits `0`; the block rides in the JSON decision the hook contract reads.
`draft-lint` → `1` while any structural problem or review marker remains, else `0`.
`doctor` → `1` only on a hard change-layer failure (engine missing / won't compile,
or `ratchet.toml` invalid); everything else is advisory. `suggest` / `gaps` always
exit `0`.

### Distribution & engine trust

`install` **vendors** the engine to `.ratchet/ratchet.py` (committed, base-pinnable,
offline) rather than referencing `${CLAUDE_PLUGIN_ROOT}` — that var exists only in a
live Claude session, while the change layer must run in CI / a teammate's pre-push /
a fresh clone. The composite GitHub Action (`uses: IvanWng97/ratchet@v0`) runs its
**own rev-pinned `ratchet.py`** over your **base-pinned config** by default
(`engine: pinned`), so neither the judge (engine) nor the policy (config) is read
from the PR head — a PR can't self-neuter the gate. `engine: vendored` runs the
consumer's HEAD `.ratchet/ratchet.py` instead, for teams that pin `.ratchet/**` via
`protected_path` + branch protection — the action **refuses `engine: vendored` under
`pull_request_target`** (it would execute untrusted PR-head code with a privileged
token). Pin the action to a release SHA (`uses: IvanWng97/ratchet@<sha>`) for a
fully reproducible engine; the `@v0` floating major tag is convenience, not a pin.
