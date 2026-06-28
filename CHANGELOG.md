# Changelog

All notable changes to cogpin. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). cogpin is on a **0.x** line, so the
primitive / CLI surface may still change between minors — pin the action to the major tag (`@v0`)
or a commit SHA for reproducibility. The config `schema` version is separate and bumps only on a
breaking config change.

## [Unreleased]

### Fixed
- **`validate` now rejects a check that is missing a load-bearing param** ([#45](https://github.com/IvanWng97/cogpin/issues/45))
  — the third-party adopter audit's silent-no-op class. A `forbid_pattern` with no `pattern`, a
  `numeric_floor` with no `key`, a `require_approval_from` with no approver list, etc. used to load
  clean and then never fire — a toothless gate the adopter believes holds. `validate` now raises
  `ConfigError` (naming the field) for every primitive whose evaluator early-returns without its
  required param. Primitives with a documented empty/default mode are exempt. `SCHEMA.md` lists the
  per-primitive requirement. (`change_budget` cap of `0` counts as supplied — a real strict ceiling.)
- **Quoting or splitting a gated git verb no longer evades the agent-layer deny** — the M4
  finding. The git-op tokenizer stripped whole quoted *spans* before scanning, so `git "push"`,
  `git p"ush"`, `git 'commit'`, and a backslash-newline continuation lost their verb token and
  slipped past `forbid_commit_on_branch` / `forbid_command{deny}` — yet ran the real verb in a
  shell. It now tokenizes with `shlex` (quote glyphs removed, quoted *content* kept as one token,
  continuations folded), so the verb is caught while a verb merely *named* in a quoted string
  (`echo "git push"` / `echo "gh pr merge"`) stays one token and is not a false hit. The `gh pr
  merge` / `gh api …/merge` detection is token-aware for the same reason, and matches a
  path-qualified (`/usr/bin/gh`) or backtick-substituted invocation too. Malformed input
  (unbalanced quotes) degrades toward detection. `shlex` is stdlib — one file / zero deps preserved.
- **`require_checks_green` no longer passes vacuously on an absent/corrupt check set** — the M3
  fail-open from the audit. A bare (or `ignore`-only) list bare-iterates whatever checks the PR
  API returns, so an *empty* set was a silent all-green PASS. Three guards now close it:
  `cogpin check` **fails closed (exit 2)** on a `--checks-file` it can't parse (was: degrade to
  `[]`); the GitHub Action trusts only a valid JSON array from `gh pr checks` (which already
  emits `[]` for a genuinely-checkless PR) and writes a fail-closed sentinel on **any** non-array
  output — a real fetch failure (auth/network/rate-limit) — instead of the old blanket `[]`; and
  `validate` flags bare *and* `ignore`-only shapes, steering to a `need` allowlist — the only form
  that detects a removed/unreported required check.
- **`validate` now fails LOUD on config typos that used to silently disable a gate** — the
  fail-open class a whole-codebase audit flagged. An uncompilable regex in any field
  (`pattern` / `exempt` / `key` / `marker` / `when_marker` / `trigger` / `require` / `custom`),
  an unknown `msg_scope` member, or an out-of-range `status` now raise `ConfigError` at parse
  time instead of making the primitive return `None` (a vacuous PASS). Same discipline the
  `direction` enum already had; the regex compile already existed in `draft-lint` and is now in
  the authoritative `validate` path too.

### Changed
- **`forbid_command` is now agent-layer-only** (joins `forbid_commit_on_branch` / `self_protect`
  as a live-signal primitive). It reads the live command string, so a `change`-layer placement —
  including the default — could never fire at the authoritative layer; `validate` now rejects it.
  Declare `layer = "agent"` (every shipped recipe already does). This is what `SCHEMA.md` already
  documented.
- **A `run` check at `layer = "agent"` is rejected at any severity** (was: only `block`). No
  agent-layer runner dispatches a `run`, so an agent-layer `warn` run was a silent no-op.

## [0.1.0] — 2026-06-28

The first public release: one stdlib-only engine that turns an AI coding agent's "done" into an
enforced, ungameable Definition-of-Done.

### The engine
- **One file, zero runtime dependencies.** `cogpin.py` is stdlib-only (Python 3.11+, `tomllib`).
  The plugin *is* the auditable repo — no package, no build step, nothing to host.
- **The moat.** `severity = "block"` requires `kind = "fact"` **and** `provenance = "environment"`:
  only an ungameable, environment-authored fact (a diff line, a file status, the command string, a
  branch, a CI conclusion, a non-author approval) may hard-block. Any judgment — an LLM-judge, a
  self-attestation, a self-typed two-lens marker — is advisory by construction. `validate` enforces
  this at parse time, so a config that tries to make a judgment block won't load.
- **Two layers, one config.** An *agent* layer (PreToolUse deny + Stop nag — bypassable via
  `[meta].bypass_env`, always logged) and a *change* layer (pre-push + CI — base-pinned,
  authoritative, ignores the bypass).
- **Base-pinning.** The change layer reads policy *and* the gate-defining files from the pinned
  base ref, so a diff can't loosen the gate it is gated by.
- **Fact-surface model.** `DiffFacts` / `CommandFacts` are the only inputs a check reads; primitives
  are pure functions returning `reason | None`; fact-*acquisition* (git, the hook envelope, a CLI
  flag, the site's mini-diff parser) is decoupled from *evaluation* — which is why the in-browser
  playground runs the exact same engine.

### Primitives (26)
- **Diff / command / message facts:** `forbid_command`, `forbid_commit_on_branch`, `secret_scan`,
  `forbid_pattern`, `forbid_removal`, `forbid_delete`, `scope_lock`, `numeric_floor`,
  `forbid_in_message`, `require_message_pattern`, `path_requires`, `cooccur`, `marker_present`,
  `commit_footer`, `change_budget`, `file_must_contain`, `max_added_file_bytes`, `run`, `attest`,
  `judge`.
- **Gate-file & approval facts:** `self_protect`, `protected_path`, `require_approval_from`,
  `pattern_requires_approval`, `approval_policy`, `require_checks_green`.

### Distribution
- **Claude Code plugin** — the PreToolUse + Stop hooks, the `/cogpin-init` · `/cogpin-check` ·
  `/cogpin-doctor` · `/cogpin-gaps` commands, the authoring skill, and the marketplace manifests.
- **GitHub Action** (`uses: IvanWng97/cogpin@v0`) — a composite action running a rev-pinned engine
  over the consumer's base-pinned config, baking the `gh` fact-gathering (PR body, reviews, checks,
  approvals, head-sha, author) so the reviewer-identity / checks-green primitives work with zero
  consumer config.
- **Vendored engine** — `install` copies the engine to `.cogpin/cogpin.py` (committed,
  base-pinnable, offline) and wires the pre-push hook + CI; `doctor` verifies both layers.

### Adoption tooling
- `install` / `uninstall` / `doctor` — idempotent, non-clobbering wiring of the change layer that
  coexists with husky / lefthook / pre-commit / `core.hooksPath`.
- `suggest` / `draft-lint` / `gaps` — AI-assisted config generation: repo facts + ranked house
  rules → a draft policy; an 11-check strict superset of `validate` that gates the draft on the
  moat and outstanding review markers; and which house rules no check yet binds. The AI writes the
  draft; the human's `mv …draft …toml` rename is the sign-off, and only the safe-core ids may be
  born at `severity = "block"`.

### Docs, site & repo health
- [`README.md`](README.md), [`SCHEMA.md`](SCHEMA.md), [`CONTRIBUTING.md`](CONTRIBUTING.md),
  [`SECURITY.md`](SECURITY.md), [`docs/`](docs) (coverage-map · composition · adopting), and the
  repo's own `CLAUDE.md` / `AGENTS.md`.
- An Astro Starlight tutorial site with a Pyodide playground running the real engine in the browser.
- Community-health files (`CODE_OF_CONDUCT.md`, issue/PR templates, `CODEOWNERS`, `.editorconfig`,
  `.gitattributes`, Dependabot) and a CI security posture: CodeQL + zizmor workflow-security gating,
  a least-privilege Pages deploy, and tag-driven release automation.
- Cross-platform CI: tests × Python 3.11–3.14 × ubuntu/macos/windows, plus byte-compile,
  validate-all-configs, lint (ruff · mypy · actionlint · zizmor), plugin-validate, and the
  self-gate (cogpin gates cogpin).

[0.1.0]: https://github.com/IvanWng97/cogpin/releases/tag/v0.1.0
