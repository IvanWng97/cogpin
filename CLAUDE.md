# CLAUDE.md

Instructions for Claude Code (or any AI coding agent) working in this repo.
(`AGENTS.md` is a symlink to this file for the cross-tool standard.)

cogpin eats its own dog food: this repo is gated by [`cogpin.toml`](cogpin.toml),
so the rules below aren't just etiquette — `cogpin stop` / the pre-push hook / the
`self-gate` CI job will *enforce* them on your change. If a gate blocks you, fix the
cause; don't reach for a bypass (the `self_protect` check denies editing the gate
files in-session, and `--no-verify` is denied at `PreToolUse`).

## What this is

A Definition-of-Done gate for AI coding agents, shipped as a **Claude Code plugin**
(no npm/brew). One language-agnostic engine + one per-repo `cogpin.toml`. User-facing
overview: [`README.md`](README.md). Full config surface: [`SCHEMA.md`](SCHEMA.md).
Why each primitive exists: [`docs/coverage-map.md`](docs/coverage-map.md).

## Layout

```
cogpin.py              THE engine — one single-file, stdlib-only module (zero deps).
                        Sections: glob→regex · config (Config/Check/validate) · facts
                        (DiffFacts/CommandFacts) · primitive evaluators (pure fns) ·
                        engine (run_change/_eval_diff) · agent layer (gate/stop) · repo
                        introspection (suggest/gaps/draft-lint config-gen) · wiring
                        (install/uninstall/doctor) · CLI.
tests/test_cogpin.py   the whole suite — stdlib `unittest`, no pytest dep.
cogpin.toml            the dogfood policy that gates THIS repo.
action.yml              the composite GitHub Action — the change-layer DISTRIBUTION
                        surface (`uses: IvanWng97/cogpin@v0`); runs a rev-pinned engine
                        over the base-pinned config. self-gate.yml dogfoods it (`uses: ./`).
examples/*/cogpin.toml  lift-and-adjust recipes (python · node-ts · pixtuoid · monorepo · oracle · advisory · capability-sandbox).
scripts/validate_plugin.py   plugin-packaging validator (manifests + frontmatter + action.yml).
hooks/hooks.json        the PreToolUse + Stop hook wiring the plugin installs.
.claude-plugin/         plugin.json + marketplace.json (the `/plugin install` surface).
commands/ · skills/     /cogpin-init · /cogpin-check · /cogpin-doctor · /cogpin-gaps
                        + the authoring skill.
site/                   the Astro Starlight tutorial + Pyodide playground (own toolchain).
assets/                 the logo + the README diagrams (reproducible: gen_*.py).
```

The engine is the install surface too: `install` vendors it to `.cogpin/cogpin.py`
(committed, base-pinnable) and wires the pre-push + CI; `doctor` verifies both layers.
Adding/altering a subcommand updates the README CLI list + `SCHEMA.md` (docs-currency).

## Architecture invariants (load-bearing — don't break these)

1. **The moat: `severity="block"` REQUIRES `kind="fact"` AND `provenance="environment"`.**
   Only an ungameable, *environment-authored* fact may hard-block. Two clauses, both in
   `validate`: (a) `kind="fact"` — a judgment (LLM-judge, self-attestation) is gameable, so
   advisory by construction; (b) `provenance="environment"` — the fact must be produced by
   git / the harness / the PR API (a real diff, file status, branch, CI conclusion, non-author
   approval), NOT a self-authored token the gated agent types that merely *claims* an out-of-band
   event (`marker_present`, `attest`). The second clause closes the principal-agent hole *inside*
   the fact set (a self-typed two-lens marker is `kind="fact"` yet agent-fabricable → it may only
   warn). Provenance lives in each primitive's `Spec`; `_AGENT_PROVENANCE` derives the deny set.
   This rule is the product; protect it. (See `docs/composition.md` for the honest-claims map.)
2. **One file, zero runtime deps.** `cogpin.py` is stdlib-only (`tomllib` sets the
   3.11 floor). This is a *product value* — the plugin IS the auditable repo. Do not
   split it into a package, add a dependency, or introduce a build step. `pyproject.toml`
   configures the linters only; it is not a package manifest.
3. **Fact-surface model.** `DiffFacts` / `CommandFacts` are the only inputs a check
   reads. Primitives are **pure functions** returning `reason | None`. The engine
   (`_eval_diff`) is thin dispatch. Fact-*acquisition* is decoupled from *evaluation*
   (`from_range` = git, `from_pretooluse_json` = hook, the site's mini-diff parser all
   build the SAME `DiffFacts`) — that's why the browser playground runs the real engine.
4. **Two layers, one config.** `agent` (PreToolUse deny + Stop nag, bypassable via
   `[meta].bypass_env`, always logged) and `change` (pre-push + CI, base-pinned,
   authoritative, *ignores* the bypass). A live-signal primitive
   (`forbid_commit_on_branch`, `self_protect`) must be `agent`/`both`, never `change`.
5. **Base-pinning is bypass-proof.** The change layer reads `cogpin.toml` + the
   gate-defining files from the pinned **base** ref, so a diff can't loosen the gate it
   is gated by. Don't add a code path that reads the policy from the PR head.

## Conventions

- **TDD, always.** Failing test → minimal impl → green. Don't add a primitive without a
  test that exercises both its block and pass paths. The dogfood `engine-needs-tests`
  check warns if you touch `cogpin.py` without touching `tests/`.
- **No comments unless WHY.** The code is dense and self-describing; comment only a
  non-obvious constraint (a normalization the matcher needs, why a check skips).
- **No `print` in the engine except the CLI command handlers** (`cmd_*`) and the
  hook contract (`gate`/`stop` write to stderr / the JSON decision). Primitives never
  do I/O.
- **Errors degrade safe.** The `gate` hook must never block on a malformed payload
  (`_pretooluse_tool` returns `("", {})`); a missing/garbled PR-facts file makes the
  check *skip*, never false-fire.
- **Keep docs current.** A new primitive/field/flag updates: the `PRIMITIVES` set,
  `_eval_diff` (if diff-evaluated), `_from_raw` parsing, the `Check` fields, **plus** the
  [`docs/primitives.md`](docs/primitives.md) registry (the README + site primitive tables are
  *generated* from it — run `python3 scripts/gen_primitives.py`; `tests/test_gen_primitives.py`
  locks the registry's id set to `PRIMITIVES`), the `SCHEMA.md` field reference, and (if mined)
  `docs/coverage-map.md` — in the same change. The `docs-currency` check warns otherwise.

## Adding a primitive (the checklist)

0. **Delegation over a new primitive (ask first).** Can this requirement be answered by a
   `cogpin.toml` line that delegates to a tool already doing the work — a `run` shelling an
   existing linter/test, a `require_checks_green` over an existing CI job, an `approval_policy`
   over CODEOWNERS? If yes, it's answered by that line, NOT a new primitive. A primitive is
   justified only for a *fact no existing tool exposes* (and a `block` one must clear the moat:
   `provenance="environment"`). Scope is a liability budget. See [`docs/composition.md`](docs/composition.md).
1. Write the failing test(s) in `tests/test_cogpin.py` — block path + pass/skip path.
2. Add the pure fn `def my_primitive(check, facts, repo) -> str | None`.
3. Register the name in `PRIMITIVES`; parse any new `Check` fields in `_from_raw`
   (add the field with a default on `Check`); wire into `_eval_diff` (diff-evaluated)
   or the relevant gate runner (`run_command_gate` / `run_self_protect_gate` /
   `run_branch_gate`) for an agent-layer one.
4. If it needs a new fact, extend `DiffFacts` + its acquisition (`from_range` / a CLI
   `--…-file` flag + a `_load_*` helper) — keep acquisition out of the pure fn.
5. Add a `validate` guard if it has a layer/placement constraint.
6. Add an entry to the [`docs/primitives.md`](docs/primitives.md) registry and run
   `python3 scripts/gen_primitives.py` (regenerates the README + site tables; the suite then
   asserts the registry id set == `PRIMITIVES`); add the field reference to `SCHEMA.md`; cite
   provenance in `docs/coverage-map.md`.
7. Run the gates (below). All green, then commit.

## The gates (run before you call it done)

```
python3 -m py_compile cogpin.py
python3 -m unittest discover -s tests -p 'test_*.py'        # the suite
python3 cogpin.py validate                                 # the dogfood config
for f in examples/*/cogpin.toml; do python3 cogpin.py validate --config "$f"; done
python3 scripts/validate_plugin.py                          # plugin packaging
python3 scripts/gen_primitives.py --check                  # README/site primitive tables current
ruff check cogpin.py tests && mypy cogpin.py              # lint (config in pyproject.toml)
python3 cogpin.py check --cwd .                            # the self-gate (DoD on itself)
```

CI mirrors these exactly: `ci.yml` (tests × py3.11–3.13 × 3 OSes + compile +
validate-all), `lint.yml` (ruff + mypy + actionlint), `plugin-validate.yml`,
`self-gate.yml` (the DoD self-application). The cadence + authority of each is in
[`docs/governance.md`](docs/governance.md) if present; otherwise the workflow files
are the source of truth.

## Things NOT to do

- Don't add a dependency or split `cogpin.py` — zero-deps/one-file is the product.
- Don't add a `block` check whose `kind` isn't `fact` — `validate` will reject it, and
  it would be a lie about the guarantee.
- Don't read policy from the PR head (breaks base-pinning) or hardcode a separator in a
  path-string assertion (use `os.path.join` / compare structurally — Windows CI catches it).
- Don't `git push`, merge, or force-push without explicit confirmation, even after a
  commit. Don't add `--no-verify` / hook-skipping flags (the gate denies them anyway).
- Don't edit `cogpin.toml` / `cogpin.py` / the workflows to weaken a gate that's
  blocking you — `self_protect` denies it in-session, and `protected_path` needs an
  independent approval. Fix the underlying cause.
- Don't generate a README/CHANGELOG/docs unasked; do keep the ones above current.
