# The primitive registry

This file is the **single source of truth** for cogpin's primitive library. The tables in
[`README.md`](../README.md) (verbose: param signatures + full prose) and the tutorial site's
*What it catches* page (condensed: bare name + short prose) are **generated** from the
` ```toml ` block below — they are not hand-maintained, so the two surfaces can never disagree
on the count, the membership, or a primitive's `kind`.

To change a primitive's documented surface, edit the entry here, then run:

```
python3 scripts/gen_primitives.py            # rewrite the generated regions in README + site
python3 scripts/gen_primitives.py --check    # verify they are current (the CI drift-guard)
```

Two invariants are enforced by [`tests/test_gen_primitives.py`](../tests/test_gen_primitives.py),
so a stale registry fails the suite:

1. the set of `id`s below **equals** `cogpin.PRIMITIVES` — the docs cannot claim a primitive the
   engine doesn't ship, nor omit one it does (this is what the old hand-kept "23 vs 26" drift was);
2. every generated region in `README.md` / the site is byte-current with this registry.

Field reference: `id` (the primitive name) · `params` (its config keys, rendered as `id{a,b}` in
the verbose view, omitted in the condensed view) · `kind` (`fact` / `fact · agent` / `fact\*` /
`advisory`) · `short` (condensed "decides over" prose, site view) · `long` (full "decides over"
prose, README view). The detailed *field* reference for each param lives in
[`SCHEMA.md`](../SCHEMA.md); this registry owns only the one-line "decides over" summaries.

```toml
[[primitive]]
id     = "forbid_command"
params = ["pattern", "deny"]
kind   = "fact"
short  = '''the agent's command string — `deny` matches the **normalized** verb (agent layer)'''
long   = '''the agent's command string — `deny` matches the **normalized** verb (shlex-tokenized), defeating `git -C/p push` / `cd d && …` / `env X=Y …` wrappers **and** quote/split evasion (`git "push"`) (agent layer)'''

[[primitive]]
id     = "forbid_commit_on_branch"
params = ["branch", "ops"]
kind   = "fact"
short  = '''the live current branch (agent layer)'''
long   = '''the live current branch (agent layer)'''

[[primitive]]
id     = "self_protect"
params = ["paths"]
kind   = "fact"
short  = '''a live Write/Edit to a gate-defining file (agent layer)'''
long   = '''a live Write/Edit to a gate-defining file — the real-time twin of `protected_path` (agent layer)'''

[[primitive]]
id     = "secret_scan"
params = ["forbid_paths", "custom"]
kind   = "fact"
short  = '''added lines vs token shapes + forbidden file globs'''
long   = '''added lines vs token shapes + forbidden file globs'''

[[primitive]]
id     = "forbid_pattern"
params = ["pattern", "scope", "exempt", "strip_comments"]
kind   = "fact"
short  = '''**added** lines under a path scope'''
long   = '''**added** lines under a path scope'''

[[primitive]]
id     = "forbid_removal"
params = ["pattern", "scope", "exempt", "strip_comments"]
kind   = "fact"
short  = '''**removed** lines under a path scope'''
long   = '''**removed** lines under a path scope'''

[[primitive]]
id     = "forbid_delete"
params = ["scope", "unless_paired_add", "exempt"]
kind   = "fact"
short  = '''per-file D-status (a deletion under scope)'''
long   = '''per-file D-status (a deletion under scope)'''

[[primitive]]
id     = "scope_lock"
params = ["allow"]
kind   = "fact"
short  = '''every A/M/D path must be inside the allowlist (scope creep)'''
long   = '''every A/M/D path must be inside the allowlist (scope creep)'''

[[primitive]]
id     = "numeric_floor"
params = ["key", "direction", "floor", "scope"]
kind   = "fact"
short  = '''a value's **direction** across the diff (lower coverage / raised retries)'''
long   = '''a numeric value's **direction** across the diff (lower coverage / raised retries / shortened timeout)'''

[[primitive]]
id     = "change_budget"
params = ["max_added", "max_removed", "max_files", "max_file_added", "scope"]
kind   = "fact"
short  = '''count ceilings over the diff (blast radius)'''
long   = '''count ceilings over the diff (blast radius)'''

[[primitive]]
id     = "file_must_contain"
params = ["scope", "pattern", "status"]
kind   = "fact"
short  = '''an added/changed file in scope must add a matching line'''
long   = '''every added/changed file in scope must add a matching line (e.g. an SPDX header)'''

[[primitive]]
id     = "max_added_file_bytes"
params = ["maxkb", "allow_binary", "scope"]
kind   = "fact"
short  = '''a per-file byte ceiling (vendored bundles, stray binaries)'''
long   = '''per-file byte ceiling on added/modified files (vendored bundles, stray binaries)'''

[[primitive]]
id     = "path_requires"
params = ["when", "need", "when_marker"]
kind   = "fact"
short  = '''name-status: if `when` changed, `need` must too'''
long   = '''name-status: if `when` changed, `need` must too'''

[[primitive]]
id     = "cooccur"
params = ["trigger", "require"]
kind   = "fact"
short  = '''if `trigger` appears, `require` must too'''
long   = '''if `trigger` appears (diff/PR), `require` must too'''

[[primitive]]
id     = "marker_present"
params = ["marker", "when"]
kind   = "fact · agent"
short  = '''a marker block exists in the PR body'''
long   = '''a self-typed marker in the PR body — **`warn` only** (agent-provenance: the gated agent can type the marker without the event it claims; to *gate* review, require a real non-author approval)'''

[[primitive]]
id     = "forbid_in_message"
params = ["tokens", "msg_scope"]
kind   = "fact"
short  = '''forbidden tokens in a commit/PR message (e.g. `[skip ci]`)'''
long   = '''forbidden tokens in a commit/PR message (e.g. `[skip ci]`)'''

[[primitive]]
id     = "require_message_pattern"
params = ["pattern", "msg_scope"]
kind   = "fact"
short  = '''every commit/PR message matches a shape (e.g. Conventional Commits)'''
long   = '''every commit/PR message must match a shape (e.g. Conventional Commits)'''

[[primitive]]
id     = "commit_footer"
params = []
kind   = "fact"
short  = '''every commit ends with the required footer'''
long   = '''every commit ends with `[meta].commit_footer`'''

[[primitive]]
id     = "protected_path"
params = ["paths", "require_approval"]
kind   = "fact"
short  = '''gate-defining files changed → need an independent approval'''
long   = '''gate-defining files changed → need a **fresh, human, non-author** approval (CI; `warn` by default on solo repos, promote to `block` with a reviewer)'''

[[primitive]]
id     = "require_approval_from"
params = ["paths", "require_approval_from", "exclude_author", "exclude_bot"]
kind   = "fact"
short  = '''a change under `paths` needs an owner's APPROVED review (CI)'''
long   = '''a change under `paths` needs an APPROVED review from a named owner (CODEOWNERS-lite; CI)'''

[[primitive]]
id     = "pattern_requires_approval"
params = ["pattern", "scope", "exclude_author", "exclude_bot"]
kind   = "fact"
short  = '''an added line matching `pattern` needs an approval (CI)'''
long   = '''an added line matching `pattern` (a new dep, an `unsafe`) needs an independent approval (CI)'''

[[primitive]]
id     = "approval_policy"
params = ["require_fresh", "no_changes_requested", "exclude_author", "exclude_bot", "min_approvals"]
kind   = "fact"
short  = '''the approval is fresh, human, non-author, no changes-requested (CI)'''
long   = '''the approval is fresh (on head), human, non-author, with no outstanding changes-requested; `min_approvals` counts **distinct** reviewers (CI)'''

[[primitive]]
id     = "require_checks_green"
params = ["need", "ignore"]
kind   = "fact"
short  = '''every required status check concluded `success` (CI)'''
long   = '''every (required) status check concluded `success` (CI); `ignore` excludes cogpin's own same-run job'''

[[primitive]]
id     = "run"
params = ["cmd"]
kind   = "fact\\*"
short  = '''shell-out; the exit code is the fact (**`block` only at the change layer**)'''
long   = '''shell-out; the exit code is the fact (**change layer only — any agent placement is rejected**)'''

[[primitive]]
id     = "attest"
params = ["box", "class"]
kind   = "advisory"
short  = '''a class-gated `Stop`-hook checklist box (forcing function)'''
long   = '''a class-gated `Stop`-hook checklist box — blocks turn-end until ticked (forcing function; the change layer is the ungameable gate)'''

[[primitive]]
id     = "judge"
params = ["prompt"]
kind   = "advisory"
short  = '''an advisory LLM-judge prompt for a CI substance check'''
long   = '''an advisory LLM-judge prompt (CI `continue-on-error` substance check)'''
```
