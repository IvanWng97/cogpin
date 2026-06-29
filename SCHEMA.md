# `cogpin.toml` — schema reference

The complete config surface. One TOML file per repo, read by the engine
([`cogpin.py`](cogpin.py)) — never your code. `python3 cogpin.py validate`
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

> **A named scope can be broader than you expect.** When `init` / `suggest` auto-detect
> `[repo]`, `code` / `tests` are the **flat union across *every* detected language** above a
> small file-count floor — deliberate (under-coverage is the worse failure), but it means
> `scope = "code"` in a polyglot repo also matches your secondary languages. To pin a check to
> one subtree or language, give a literal glob (`scope = ["src/**/*.py"]`) instead of the name.

### `[meta]`

| key | type | default | meaning |
|---|---|---|---|
| `base_pinned` | bool | `true` | read `cogpin.toml` + gate-defining files from the pinned **base** ref, not the PR head (bypass-proof). Turning this off is itself a gate-defining change |
| `bypass_env` | string | — | the agent-layer escape-hatch env var (e.g. `COGPIN_BYPASS`). A non-empty value (or a `<ENV-with-dashes>: <reason>` line in the attestation) skips the **agent** layer — always logged. The **change** layer ignores it |
| `commit_footer` | string (regex) | — | the footer every commit must carry (read by the `commit_footer` primitive) |
| `attestation_file` | string | `.cogpin/attestation.md` | the Stop-hook checklist file the `attest` boxes look in |
| `feature_files` | int | `3` | a change is "feature-shaped" at ≥ this many changed files (or a new code module) — gates the `feature` attestation class |

---

## `[capability]` (optional)

A **declared** capability floor — *policy, not enforcement*. cogpin records and compares
this stanza and can **compile** it to a harness's native enforcement
(`cogpin capability emit`), but it **never** reads it during gate/check evaluation and
**never** confines a syscall itself. The OS / harness is the boundary; cogpin only declares
the posture (see [`docs/composition.md`](docs/composition.md) and the
[#24 re-brand](README.md)). Because it lives in `cogpin.toml`, it is `self_protect`'d and
read from the pinned base ref for free.

| key | type | default | meaning |
|---|---|---|---|
| `no_network` | bool | `false` | the agent should run with no outbound network |
| `fs_confine` | list(glob) | `[]` | filesystem roots the agent is confined to (e.g. `["."]`) |
| `deny_paths` | list(glob) | `[]` | paths the agent must never touch (`["~/.ssh/**","**/.env"]`) |
| `allow_commands` | list(verb) | `[]` | command-verb allowlist (the strong, OS-enforceable default-deny posture) |
| `deny_commands` | list(verb) | `[]` | command-verb denylist (a declaration to *compile out*, not a hook match) |
| `backend` | string | `claude-code` | the `emit` target (`claude-code` \| `bubblewrap` \| `docker` \| `seccomp`); only `claude-code` is rendered today |

`cogpin capability emit` (claude-code) translates the floor into `.claude/settings.json`
`permissions` (`deny_paths` → `Read/Edit/Write(<p>)`; `deny_commands` → deny `Bash(<verb>:*)`;
`allow_commands` → allow `Bash(<verb>:*)`; `no_network` → deny `WebFetch`/`WebSearch`/`curl`/`wget`/`nc`
**+ a warning that settings.json cannot *guarantee* no egress**). `allow_commands` only *adds*
allow entries — for a true allowlist set `permissions.defaultMode` to `ask`/`deny` yourself (emit
warns; cogpin won't flip your global mode). It is idempotent and **non-clobbering** — it manages only
the entries it itself emitted (recorded in `.cogpin/capability-emitted.json`), never your
own. A non-`claude-code` backend is *documented, not emitted* (cogpin declares; you wire the
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
# coverage can only hold or rise — blocks if `fail_under = N` drops across the diff
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

Some primitives are constrained: `forbid_command`, `forbid_commit_on_branch`, and
`self_protect` read a *live* signal (the command string / current branch / the Write
target) and must be `agent` or `both`; a `run` check must live at the `change` layer
(any agent placement is rejected, at any severity).

---

## Primitives

> **Required params (validate-enforced).** A primitive missing the field(s) it cannot function
> without loads clean but is a **silent no-op** — its evaluator early-returns, so the gate never
> fires. `cogpin validate` rejects these at parse time:
> `forbid_pattern` / `forbid_removal` / `require_message_pattern` / `file_must_contain` /
> `pattern_requires_approval` → `pattern`; `forbid_command` → `pattern` **or** `deny`;
> `forbid_in_message` → `tokens`; `marker_present` → `marker`; `numeric_floor` → `key`;
> `scope_lock` → `allow`; `self_protect` / `protected_path` → `paths`; `require_approval_from` →
> `paths` **and** `require_approval_from`; `cooccur` → `trigger` **and** `require`; `path_requires`
> → `need` **and** (`when` **or** `when_marker`); `change_budget` → at least one `max_*` cap;
> `run` → `cmd`; `commit_footer` → `[meta].commit_footer` (the footer regex, meta-scoped).
> Primitives with a documented empty/default mode (`secret_scan`, `forbid_delete`,
> `forbid_commit_on_branch`, `require_checks_green`, `approval_policy`, `max_added_file_bytes`,
> `attest`/`judge`) take no required param.

### Command / live-signal (agent layer)

#### `forbid_command`  *(agent / both)*
The agent's command string. Live-signal (reads the command at the PreToolUse intercept), so —
like `forbid_commit_on_branch` / `self_protect` — it is agent-layer-only; `validate` rejects a
`change`-layer (or default) placement, which could never fire at the authoritative layer.
- `pattern` (regex) — matched anywhere in the command (catches `--no-verify` in any position).
- `deny` (list) — **normalized**-verb match: shlex-tokenizes (quote glyphs stripped, quoted content kept whole, backslash-newline folded) and strips `sudo` / `VAR=val` / `cd d &&` / `git -C p` / `git -c k=v` wrappers, then matches a contiguous token run — so the gated verb can't be smuggled past prefix matching by wrapping it OR by quoting/splitting it (`git "push"`, `git p"ush"`). A verb merely *named* inside a quoted string (`echo "git push"`) stays one token and is not a false hit.

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

> **`path_requires` vs `cooccur`** — both co-require, on different axes. `path_requires` is a
> **file-status** co-requirement: *a path changed (or `when_marker` matched the PR body) ⇒ a
> `need` path must change* ("touched `code/` ⇒ touch `tests/`") — the *requirement* side always
> reasons over which paths are in the diff. `cooccur` is a
> **content-token** co-requirement: *a token appears ⇒ another token must appear* ("a
> migration string ⇒ a rollback string") — it reasons over regex matches in the **added
> lines** (and, at `warn`, the message / PR body). Pick by whether the rule is about *files
> touched* or *text present*.

### PR-metadata facts *(skip with no PR context; CI supplies them)*

| primitive | params | blocks when |
|---|---|---|
| `protected_path` | `paths`, `require_approval` | a gate-defining file changed without a **fresh, human, non-author** approval — when the `reviews` fact is present (CI), the approval must be on the current `head_sha`, not a bot, and not the author, so an approval of an earlier benign commit can't cover a later one (a flat `--approvals` list with no review metadata is only a degraded fallback). Born `warn` in the scaffold for solo repos (no independent approver); promote to `block` with a reviewer |
| `require_approval_from` | `paths`, `require_approval_from` (logins), `exclude_author`, `exclude_bot` | a change under `paths` has no APPROVED review from a listed owner |
| `pattern_requires_approval` | `pattern`, `scope`, `exclude_author`, `exclude_bot` | an added line in scope matches `pattern` but has no independent approval |
| `approval_policy` | `require_fresh`, `no_changes_requested`, `exclude_author`, `exclude_bot`, `min_approvals` | the count of **distinct** qualifying approvers is below `min_approvals`, or an outstanding `CHANGES_REQUESTED` remains |
| `require_checks_green` | `need` (allowlist of check names; empty = bare-iterate all reported), `ignore` (denylist) | a required status check did not conclude `success`. A `need`-listed check that never reported counts as **missing** and blocks — the **only** fail-closed form. Bare (or `ignore`-only) bare-iterates whatever the PR API returns, so an **empty/shrunken** set (a removed-or-renamed check, an `ignore` covering them all, a checks-fetch hiccup) passes **vacuously**; `validate` prints a `note:` for those shapes and the GitHub Action fails closed on a genuine fetch error. A check **name reported more than once** (a re-run / cross-workflow collision) is green only if *every* occurrence concluded `success` — a later `success` can't mask an earlier `failure` |

> **Same-workflow race:** when cogpin runs as a job in the *same* workflow it gates, its
> own check is still pending at query time and a bare `require_checks_green` (no `need`/`ignore`)
> would self-block. Exclude it with `ignore = ["<cogpin job name>"]`, or `need` only the other
> checks. `cogpin validate` prints a `note:` when neither is set. Both lists match the **rendered**
> check name exactly — a matrix job carries its suffix (e.g. `cogpin (ubuntu-latest)`), so use the
> name as it appears in `gh pr checks`.
>
> **Removal-detection:** only `need` blocks when a required check is *absent* — a bare or
> `ignore`-only list can't tell "all green" from "none reported" (an empty set iterates to a
> vacuous pass). Name the must-be-green checks in `need`, or lean on branch-protection required
> contexts for that axis.

**Choosing an approval primitive** — the four differ by *what triggers the requirement*:

| require approval… | use | trigger |
|---|---|---|
| when specific **gate / config files** change — anyone may approve, but it must be a fresh, human, non-author review | `protected_path` | by path (the change-layer twin of `self_protect`) |
| from a **named owner / team** when a path changes (CODEOWNERS-lite) | `require_approval_from` | by path + approver identity |
| when **risky content** appears in the diff (a new dependency, `unsafe {`, a new suppression), regardless of file | `pattern_requires_approval` | by content |
| as a **standing bar** on every PR (≥ N fresh approvals, no unresolved `CHANGES_REQUESTED`) | `approval_policy` | none — a repo-wide floor |

These read CI-supplied facts via `cogpin check` flags: `--pr-body-file`,
`--approvals`, `--reviews-file` (a `gh pr view --json reviews` dump), `--head-sha`,
`--pr-author`, `--checks-file` (a `gh pr checks --json name,state` dump). Omitted →
the check skips rather than false-fires.

### Escape hatch & advisory

| primitive | kind | params | does |
|---|---|---|---|
| `run` | fact\* | `cmd` | shells out; the exit code is the fact. Change layer only — any agent placement is rejected, at any severity |
| `attest` | advisory | `box`, `class`, `prompt` | a class-gated Stop-hook checklist box; blocks turn-end until ticked (forcing function only) |
| `judge` | advisory | `prompt` | emitted by `cogpin judge` for a CI `continue-on-error` LLM substance check |

`attest` classes: `always` (any code change) · `feature` (≥ `feature_files` or a new
module) · `public_surface` · `claude_md`. `box` defaults to the check `id`.

**The attestation file.** The boxes are ticked in `[meta].attestation_file` (default
`.cogpin/attestation.md`) — a markdown checklist, one line per box, the label matching each
check's `box` (or its `id`):

```markdown
- [ ] TDD            # unticked → a "block" gap that holds turn-end open
- [x] Self-review    # ticked  → satisfied
- [ ] Design         # only required when the change triggers this box's class (feature-shaped)
```

A box counts as ticked by the local `- [x] <label>` shape **anywhere** in the file (the
search is unanchored, so surrounding prose is fine; `- [X]` also counts, a space `- [ ]` does
not; trailing text — `- [x] TDD: a failing test came first` — is allowed). A missing file
reads as *all unticked*. Only the boxes whose **class** the change triggers are required, so a
docs-only change needn't tick a `feature` box. See `examples/pixtuoid/.dod/attestation.md` for
a worked template.

**Bypassing the agent layer, with a reason.** Set `[meta].bypass_env` (e.g. `COGPIN_BYPASS`)
and either export that env var or add a reason line to the attestation file — the env name
with underscores turned to dashes:

```
COGPIN-BYPASS: hotfix — CI is down, paging on-call (ticket OPS-123)
```

The reason must be non-empty. It skips the **agent** layer *and* the local pre-push hook (which
runs `check --allow-bypass`); the reason rides in the committed attestation marker and the hook
invocation the harness records. The **authoritative CI** run does **not** pass `--allow-bypass`,
so it ignores the bypass entirely — a bypass can wave through a *local* push, but never the CI
gate.

---

## CLI

```
# enforce
cogpin gate                    # agent layer: PreToolUse hook (reads the tool envelope on stdin)
cogpin stop --cwd .            # agent layer: Stop hook (blocks turn-end on unmet DoD)
cogpin check --cwd .           # change layer: gate the committed range (authoritative)
    [--no-run] [--allow-bypass] [--report-only] [--default-branch BR]
    [--pr-body-file F] [--approvals a,b] [--reviews-file F]
    [--head-sha S] [--pr-author L] [--checks-file F]
    # --default-branch BR: (CI only) the TRUSTED base branch name. Overrides cogpin.toml so the
    #   base pin can't be redirected from the PR head; the action passes the repo's real
    #   default_branch. An unfetchable trusted base fails CLOSED (exit 1, a config/infra error),
    #   never a narrowed diff.
    # --report-only: print findings + a summary but exit 0 (global, temporary rollout switch;
    #   distinct from per-check severity="warn"). Infra/config errors (unreachable base,
    #   unloadable config) STILL fail closed. The action exposes it as `report-only:`.
cogpin check --cwd . --diff-file F  # config-as-code: evaluate a crafted unified-diff FIXTURE
    [--expect-block a,b] [--expect-clean c,d]    # instead of the git range (tests cogpin.toml)
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
cogpin backtest --cwd . --range main~50..main  # replay the policy over merged history (calibration)
    [--config F] [--fail-on-block]
    # which past commits WOULD this policy block? Pure report (exit 0) unless --fail-on-block;
    # exit 2 = couldn't run (bad range / shallow clone / unloadable config). Uses the WORKING
    # config; covers diff-fact checks only (`run` + PR-context checks are skipped + named).
cogpin judge --cwd .           # emit advisory judge prompts (CI pipes to a model)

# author
cogpin init --config cogpin.toml          # write a minimal starter config
cogpin validate --config cogpin.toml      # parse + the block-requires-fact invariant
cogpin suggest --cwd . [--format json|toml]  # repo facts → ranked draft (CLAUDE.md house-rules → primitives); writes NOTHING
    # POLYGLOT (#19): detects the top-K languages, not just the dominant one. The flat [repo].
    #   code/tests are the union over every detected language (a secondary enters at >=
    #   _SECONDARY_MIN_FILES=10 files — an ABSOLUTE floor, not a fraction, so a real 200-file
    #   subtree in a 5000-file repo is covered while 3 stray files are not). EVERY floor-clearing
    #   language is in the union (no cap → no language's files left uncovered).
    #   --format json adds a `languages` array [{name, file_count, code, tests}] (dominant-first) so
    #   a host agent can author PER-SUBTREE checks (a `console.log` forbid on JS-only, `println!` on
    #   Rust-only) that the merged blob can't express; --format toml adds a `# detected:` comment.
    #   See examples/monorepo/ for the literal-per-subtree recipe + its --diff-file coverage fixtures.
cogpin draft-lint --cwd . [--config cogpin.toml.draft] [--simulate]  # strict superset of validate; gates on # TODO(cogpin:review) markers
cogpin gaps --cwd . [--format text|json]   # advisory: which house-rules no check binds

# wire (the adoption surface)
cogpin install --cwd .         # vendor .cogpin/cogpin.py + scaffold config/hook/CI/gitignore (idempotent)
    [--no-vendor] [--no-config] [--no-hook] [--no-ci] [--no-gitignore]
cogpin uninstall --cwd .       # strip the local pre-push managed block (never removes committed source)
cogpin update --cwd .          # re-vendor the active engine → .cogpin/cogpin.py (fixes a stale-engine skew #16)
cogpin doctor --cwd . [--json] # diagnose both layers; one-line fix per finding

# capability + misc
cogpin capability emit --cwd . [--dry-run]  # compile [capability] → .claude/settings.json (declare → emit; --dry-run previews)
cogpin selftest                # in-process smoke test (the full suite is tests/test_cogpin.py)
```

Exit codes: `gate` → `2` denies (stderr shown to the agent), `0` allows. `check` →
`1` on a blocking finding, `0` otherwise (warnings print, never fail). `stop` always
exits `0`; the block rides in the JSON decision the hook contract reads.
`draft-lint` → `1` while any structural problem or review marker remains, else `0`.
`doctor` → `1` only on a hard change-layer failure (engine missing / won't compile,
or `cogpin.toml` invalid); everything else is advisory. `suggest` / `gaps` always
exit `0`.

### Distribution & engine trust

`install` **vendors** the engine to `.cogpin/cogpin.py` (committed, base-pinnable,
offline) rather than referencing `${CLAUDE_PLUGIN_ROOT}` — that var exists only in a
live Claude session, while the change layer must run in CI / a teammate's pre-push /
a fresh clone. The composite GitHub Action (`uses: IvanWng97/cogpin@v0`) runs its
**own rev-pinned `cogpin.py`** over your **base-pinned config** by default
(`engine: pinned`), so neither the judge (engine) nor the policy (config) is read
from the PR head — a PR can't self-neuter the gate. `engine: vendored` runs the
consumer's HEAD `.cogpin/cogpin.py` instead, for teams that pin `.cogpin/**` via
`protected_path` + branch protection — the action **refuses `engine: vendored` under
`pull_request_target`** (it would execute untrusted PR-head code with a privileged
token). Pin the action to a release SHA (`uses: IvanWng97/cogpin@<sha>`) for a
fully reproducible engine; the `@v0` floating major tag is convenience, not a pin.
