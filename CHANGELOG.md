# Changelog

All notable changes to ratchet. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
config `schema` version is separate and bumps only on a breaking config change.

## [Unreleased]

### Fixed (PR #1 two-lens-review follow-ups)
- **`require_checks_green` self-race (#5)** — when ratchet runs as a job in the same workflow
  it gates, its own check is still pending and a bare (no-`need`) config self-blocks. Added an
  `ignore` denylist (the complement of `need`) so you can exclude the ratchet job by name, and
  `ratchet validate` now prints a non-fatal `note:` when a `require_checks_green` check sets
  neither `need` nor `ignore`. Documented the race in [`SCHEMA.md`](SCHEMA.md).
- **`_install_prepush` perms drift (#6)** — appending the managed block to an existing
  husky / `.githooks` pre-push no longer widens it to `0o755`; it preserves the file's perms and
  only ensures `+x` (a brand-new ratchet-authored hook is still `0o755`). `uninstall`'s
  strip-and-keep path shares the same rule.
- **`_marked_ids` mis-association (#6)** — a `# TODO(ratchet:review)` marker above a
  *commented-out* check no longer binds to a *later* live `[[check]]` (only blank lines may
  intervene now). This also removes a `draft-lint` false-positive that mis-flagged the later check.
- Dropped the no-op `uninstall --no-hook` flag (uninstall's only action is stripping the hook).

## [1.0.0] — 2026-06-27

First stable release. The `@v1` floating major tag and the `/v1/` raw-engine URL
now resolve; `IvanWng97/ratchet@v1` and the curl install are live. SemVer applies
to the v1 surface from here — features and fixes ship as v1.x; a breaking change
goes to `v2`. The config `schema` version (currently `1`) is a separate lever.

### Security / hardening (two-lens review of the adoption arc)
- **`protected_path` now requires a FRESH, human, non-author approval** when the `reviews`
  fact is present (CI). Previously it accepted any non-empty approvals list, so an approval
  of an earlier benign commit (with GitHub's stale-approval dismissal off by default) — or a
  bot rubber-stamp — could cover a later malicious edit to a gate-defining file, defeating
  base-pinning's "a same-PR edit can't disarm the gate" guarantee. The composite action's
  `approvals` derivation is likewise filtered to `commit_id == head_sha`, non-bot, non-author.
- **`require_checks_green` no longer fails open in `action.yml`**: `gh pr checks` exits
  non-zero on failing/pending checks while still emitting JSON; the old `|| echo '[]'` replaced
  that with an empty array → a vacuous pass. Now it preserves the real JSON and falls back to
  `[]` only on genuinely empty output.
- The action **refuses `engine: vendored` under `pull_request_target`** (it would run
  untrusted PR-head code with a privileged token).
- `install` writes (engine / config / CI / gitignore) are **confined to the repo root** — a
  committed gate file shipped as a symlink escaping the tree can no longer make `install`
  clobber an arbitrary path on a victim's clone (the pre-push hook write still follows symlinks
  for stow). `doctor`'s gate-file self-protection check now also requires CI-workflow coverage.

### Changed — solo-repo policy
- The scaffold (and ratchet's own dogfood) now ships `protected-gate-files` at **`warn`**, not
  `block`: it needs an independent approver no solo repo has, so a hard block would be
  unclearable on every gate-touching PR. Promote to `block` once a second reviewer / CODEOWNERS
  exists; `draft-lint` accepts it at warn-or-block while the other four safe-core ids stay
  block. The agent-layer `self_protect` still hard-blocks in-session edits.
- `install` substitutes the repo's detected default branch into the scaffolded `ratchet.toml`
  and CI `push:` trigger (no longer hardcodes `main`).

### Added — seamless adoption (install / config-gen / CI action)
- `ratchet install` / `uninstall` / `doctor` — one-command, idempotent, non-clobbering
  wiring of the change layer. `install` vendors the engine to `.ratchet/ratchet.py`
  (committed, base-pinnable, offline), scaffolds `ratchet.toml`, scopes `.gitignore` to
  `.ratchet/.state`, and appends a sentinel-delimited managed block to the **effective**
  pre-push — coexisting with husky / lefthook / pre-commit / `core.hooksPath` (it emits a
  snippet for the managers that regenerate their own hook). `doctor` is a read-only
  9-point diagnosis (exit 1 only on a missing/uncompilable engine or invalid config).
- AI-assisted config generation — `ratchet suggest` (repo facts + ranked CLAUDE.md
  house-rules → a draft policy; the 23-row keyword→primitive map, dominant-language glob
  guessing, and text-parsed test-command detection), `ratchet draft-lint` (an 11-check
  strict superset of `validate` that gates `ratchet.toml.draft` on the moat + outstanding
  `# TODO(ratchet:review)` markers), and `ratchet gaps` (which house-rules no check binds).
  The AI writes the draft; the human's `mv …draft …toml` rename is the sign-off, and only
  the five safe-core ids may be born at `severity="block"`.
- `action.yml` — a composite GitHub Action (`uses: IvanWng97/ratchet@v1`) running its own
  **rev-pinned** engine over the consumer's **base-pinned** config (`engine: pinned`), so
  neither judge nor policy is read from the PR head. It bakes the gh fact-gathering (PR
  body, reviews via GraphQL → the flat shape the engine consumes, checks, approvals,
  head-sha, author), so the reviewer-identity / checks-green primitives work with zero
  consumer config. `engine: vendored` is offered for `protected_path`-pinned teams.
- `/ratchet-doctor` + `/ratchet-gaps` slash commands; `/ratchet-init` now runs
  `ratchet install` then drives the AI draft → `draft-lint` → rename → `doctor` flow.

### Added — fact-surface primitives (the empirical-mining batch)
- `self_protect` (agent layer) — deny a live `Write`/`Edit` to a gate-defining file; the
  real-time twin of `protected_path`.
- `require_message_pattern` — every commit/PR message must match a shape (e.g.
  Conventional Commits); the require-presence twin of `forbid_in_message`.
- `change_budget` — count ceilings over the diff (`max_added`/`max_removed`/`max_files`/
  `max_file_added`); a blast-radius cap.
- `file_must_contain` — a positive content floor: every added/changed file in scope must
  add a line matching a pattern (e.g. an SPDX header).
- `max_added_file_bytes` — a per-file byte ceiling on added/modified files (vendored
  bundles, stray binaries that produce zero diff lines); `allow_binary` toggle.
- `require_approval_from` — CODEOWNERS-lite: a change under `paths` needs an APPROVED
  review from a named owner.
- `pattern_requires_approval` — an added line matching a pattern (a new dependency, an
  `unsafe`) needs an independent approval.
- `approval_state_depth` — fresh-on-head / human / non-author / no-`CHANGES_REQUESTED`
  approval depth the bare "approved" badge can't express.
- `require_checks_green` — every required status check must have concluded `success`.
- New PR-fact CLI flags on `ratchet check`: `--reviews-file`, `--head-sha`,
  `--pr-author`, `--checks-file` (with `_load_reviews`/`_load_checks` normalizers for
  `gh pr view`/`gh pr checks` JSON). These skip cleanly with no PR context.
- `scripts/validate_plugin.py` — stdlib plugin-packaging validator (manifests, hooks
  reference, version parity, skill/command frontmatter).
- Docs: [`SCHEMA.md`](SCHEMA.md), [`docs/coverage-map.md`](docs/coverage-map.md),
  `CONTRIBUTING.md`, `SECURITY.md`, the repo's own `CLAUDE.md`/`AGENTS.md`.
- CI suite: `ci.yml` (tests × py3.11–3.13 × ubuntu/macos/windows + `py_compile` +
  validate-all-configs), `lint.yml` (ruff + mypy + actionlint), `plugin-validate.yml`,
  `self-gate.yml` (the DoD self-application, now wired with PR approval facts).

### Changed
- `self-gate.yml` now runs THROUGH the composite action (`uses: ./`), dogfooding the
  action's gh-facts wiring end-to-end; `validate_plugin.py` asserts `action.yml` is a
  composite that invokes the engine; `action.yml` is added to the dogfood's `self_protect`
  + `protected_path` paths.
- The `secret-scan` house-rule detector also matches the imperative "never commit
  secrets" / "do not commit credentials" phrasing.
- `forbid_in_message` and `require_message_pattern` share a `_msg_targets` helper.
- The `PreToolUse` hook matcher now also covers `Write`/`Edit`/`MultiEdit`/`NotebookEdit`
  (for `self_protect`); `cmd_gate` parses the tool envelope once via `_pretooluse_tool`.
- The dogfood `ratchet.toml`, `examples/node-ts` (a full team / PR-review layer), and
  `examples/python` now exercise the new primitives; added `examples/advisory/` — the
  eight semantic-weakening `judge` prompts mined from real AI-authored PR history.

## [0.1.0] — initial

- The engine: one stdlib-only `ratchet.py`, the `severity="block" ⇒ kind="fact"` moat,
  the two-layer (agent / change) model, base-pinning, and the first primitive set
  (`forbid_command`/`forbid_commit_on_branch`/`secret_scan`/`forbid_pattern`/
  `forbid_removal`/`forbid_delete`/`scope_lock`/`numeric_floor`/`forbid_in_message`/
  `path_requires`/`cooccur`/`marker_present`/`commit_footer`/`protected_path`/`run`/
  `attest`/`judge`).
- The Claude Code plugin: `PreToolUse` + `Stop` hooks, `/ratchet-init` + `/ratchet-check`
  commands, the authoring skill, the marketplace manifests.
- The tutorial site (Astro Starlight + a Pyodide playground running the real engine in
  the browser) and the logo.
