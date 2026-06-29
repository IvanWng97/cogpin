# Changelog

All notable changes to cogpin. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). cogpin is on a **0.x** line, so the
primitive / CLI surface may still change between minors — pin the action to the major tag (`@v0`)
or a commit SHA for reproducibility. The config `schema` version is separate and bumps only on a
breaking config change.

## [Unreleased]

### Changed
- **The primitive-library tables are now generated from one registry, killing doc drift.**
  [`docs/primitives.md`](docs/primitives.md) is the single source of truth; `scripts/gen_primitives.py`
  renders README's verbose table (param signatures + full prose) and the tutorial site's condensed
  table (bare name + short prose) from it, and derives the primitive count everywhere it appears.
  `tests/test_gen_primitives.py` locks the registry's id set to the engine's `PRIMITIVES` and asserts
  the committed tables are byte-current — so the docs can no longer drift from the code. This closes
  the stale site count (it claimed *"23"* against the engine's 26), a `kind` that differed by surface
  (`marker_present` now reads `fact · agent` on the site too), and the lossy `forbid_command` /
  `numeric_floor` descriptions the two surfaces had diverged into.

## [0.1.1] — 2026-06-28

A hardening release. It closes the fail-open and silent-no-op classes a third-party adopter audit
surfaced ([#44](https://github.com/IvanWng97/cogpin/issues/44)–[#48](https://github.com/IvanWng97/cogpin/issues/48))
and the internal M/L deep-audit — each fix tightens a gate that could previously be evaded or that
quietly never fired. The moat (`block` ⇒ `kind="fact"` + `provenance="environment"`) and the config
surface are unchanged; the `@v0` action tag and the plugin manifests advance to 0.1.1, and the
release workflow now self-verifies that `v0` actually moves onto the shipped commit (the #44 class).

### Changed
- **CLI / error-message UX polish** ([#47](https://github.com/IvanWng97/cogpin/issues/47), adopter audit):
  the `marker_present` block-rejection now names the real-fact alternatives
  (`require_approval_from` / `approval_policy` / `require_checks_green`); an *unknown-primitive*
  config typo no longer misfires the "engine looks stale → `cogpin update`" hint (it points at
  `SCHEMA.md`; only a real schema skew suggests `update`); `doctor` prints a glyph legend
  (`✓ ~ ✗ ·`); `cogpin check --help` and the README state the exit codes (`0`/`1`/`2`); a bad
  `--config` path gives a human message ("config file not found" / "expected a file, not a
  directory") instead of a raw `OSError`; and `install` names *how* it wired the pre-push (`via
  husky → …` when husky is detected, else `directly → .git/hooks/pre-push (no hook manager detected)`).
- **`forbid_command` is now agent-layer-only** (joins `forbid_commit_on_branch` / `self_protect`
  as a live-signal primitive). It reads the live command string, so a `change`-layer placement —
  including the default — could never fire at the authoritative layer; `validate` now rejects it.
  Declare `layer = "agent"` (every shipped recipe already does). This is what `SCHEMA.md` already
  documented.
- **A `run` check at `layer = "agent"` is rejected at any severity** (was: only `block`). No
  agent-layer runner dispatches a `run`, so an agent-layer `warn` run was a silent no-op.

### Fixed
- **Three remaining fail-opens closed** (audit LOW batch):
  - `require_checks_green` no longer lets a duplicate check name hide a failure — the name-keyed
    set collapsed last-write-wins, so a `success` row after a `failure` of the same name (a
    re-run / cross-workflow collision) dropped the failure and passed a red tree. A name is now
    green only if **every** occurrence concluded `success`.
  - `cogpin check` now **fails closed** (exit 2) on a present-but-unreadable `--pr-body-file`
    instead of conflating "unreadable" with "absent" and silently skipping every `pr_body`-scoped
    check (it matched the fail-closed `--checks-file` / `--reviews-file` handlers everywhere else).
  - an **empty** `pr_body` (`""`) is now treated as real-but-empty by the message primitives, so a
    required `pr_body` pattern fails rather than passing vacuously — matching the `DiffFacts`
    contract `marker_present` already honored.
- **`gaps` no longer reports an attestation house rule as UNBOUND while `suggest` emits it** — the
  two CLIs contradicted each other. `is_bound`'s match-token haystack was built from
  `pattern/marker/key/deny/allow/tokens/need` only, so an `attest` check whose sole discriminator
  is `box` / `class` (e.g. the `attest-tdd` rule, match-token `TDD`) found an empty haystack and
  fell through to `(False, None)`. The haystack now includes `box` and `class`.
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

## [0.1.0] — 2026-06-28

The first public release: one stdlib-only engine that turns an AI coding agent's "done" into an
enforced, ungameable Definition-of-Done. (Formerly developed as **`ratchet`**; renamed to
**cogpin** at this inaugural release, which also reset the version line to 0.1.0.)

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

[0.1.1]: https://github.com/IvanWng97/cogpin/releases/tag/v0.1.1
[0.1.0]: https://github.com/IvanWng97/cogpin/releases/tag/v0.1.0
