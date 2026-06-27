# Changelog

All notable changes to ratchet. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The
config `schema` version is separate and bumps only on a breaking config change.

## [Unreleased]

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
