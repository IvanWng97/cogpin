# Changelog

All notable changes to ratchet. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
config `schema` version is separate and bumps only on a breaking config change.

## [Unreleased]

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
