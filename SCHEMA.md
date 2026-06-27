# `ratchet.toml` — schema reference

The complete config surface. One TOML file per repo, read by the engine
([`ratchet.py`](ratchet.py)) — never your code. `python3 ratchet.py validate`
enforces everything below at parse time.

## The one rule

```
severity = "block"   REQUIRES   kind = "fact"
```

Only an ungameable **fact** may hard-block. A judgment (`judge`, `attest`) can
warn or nudge but never blocks. `validate` rejects any `block` + non-`fact`
check — the guarantee can't silently erode through config.

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

## `[[check]]`

| key | type | required | meaning |
|---|---|---|---|
| `id` | string | ✓ | unique identifier (duplicate ids are a config error) |
| `kind` | `fact` \| `advisory` | ✓ | `fact` = ungameable; `advisory` = judged |
| `severity` | `block` \| `warn` \| `attest` \| `judge` | ✓ | `block` requires `kind="fact"` |
| `primitive` | string | ✓ | one of the primitives below |
| `layer` | `agent` \| `change` \| `both` | `change` | where it fires |

All remaining keys are primitive parameters — each primitive reads only the ones
listed for it.

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
| `numeric_floor` | `key` (regex, group 1 = value), `direction` (`no_decrease`\|`no_increase`), `floor`, `scope` | the value weakens across the −/+ hunks on the same key, or crosses `floor` |
| `change_budget` | `max_added`, `max_removed`, `max_files`, `max_file_added`, `scope` | a count ceiling is exceeded |
| `file_must_contain` | `scope`, `pattern`, `status` (default `A`) | a changed file of `status` in scope adds **no** line matching `pattern` |
| `max_added_file_bytes` | `maxkb`, `allow_binary`, `scope` | an added/modified file exceeds `maxkb`, or is binary while `allow_binary=false` |

### Cross-file & message facts

| primitive | params | blocks when |
|---|---|---|
| `path_requires` | `when`, `need`, `when_marker` | a `when`-scoped path changed (or `when_marker` matched the PR body) but no `need` path did |
| `cooccur` | `trigger`, `require` | `trigger` appears (diff/PR/commit) but `require` does not |
| `marker_present` | `marker`, `when` | a `when`-scoped change lacks `marker` in the PR body (skips with no PR context) |
| `forbid_in_message` | `tokens`, `msg_scope` | a forbidden literal token is in the selected message scope(s) |
| `require_message_pattern` | `pattern`, `msg_scope` (default `commit_subject`) | a selected message does **not** match `pattern` |
| `commit_footer` | — (uses `[meta].commit_footer`) | a commit lacks the footer |

`msg_scope` ⊆ `{commit_subject, commit_body, pr_body}`.

### PR-metadata facts *(skip with no PR context; CI supplies them)*

| primitive | params | blocks when |
|---|---|---|
| `protected_path` | `paths`, `require_approval` | a gate-defining file changed without an independent approval |
| `require_approval_from` | `paths`, `require_approval_from` (logins), `exclude_author` | a change under `paths` has no APPROVED review from a listed owner |
| `pattern_requires_approval` | `pattern`, `scope`, `exclude_author` | an added line in scope matches `pattern` but has no independent approval |
| `approval_state_depth` | `require_fresh`, `no_changes_requested`, `disallow_author`, `disallow_bot`, `min_approvals` | the qualifying-approval count is below `min_approvals`, or an outstanding `CHANGES_REQUESTED` remains |
| `require_checks_green` | `need` (check names; empty = all) | a required status check did not conclude `success` |

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
ratchet gate                    # agent layer: PreToolUse hook (reads the tool envelope on stdin)
ratchet stop --cwd .            # agent layer: Stop hook (blocks turn-end on unmet DoD)
ratchet check --cwd .           # change layer: gate the committed range (authoritative)
    [--no-run] [--allow-bypass]
    [--pr-body-file F] [--approvals a,b] [--reviews-file F]
    [--head-sha S] [--pr-author L] [--checks-file F]
ratchet judge --cwd .           # emit advisory judge prompts (CI pipes to a model)
ratchet validate --config ratchet.toml
ratchet init --config ratchet.toml
```

Exit codes: `gate` → `2` denies (stderr shown to the agent), `0` allows. `check` →
`1` on a blocking finding, `0` otherwise (warnings print, never fail). `stop` always
exits `0`; the block rides in the JSON decision the hook contract reads.
