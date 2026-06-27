# Contributing to ratchet

Thanks for helping. ratchet has an unusually strong design spine — read this first so
your change lands in one round.

## The one rule you can't bend

```
severity = "block"   REQUIRES   kind = "fact"
```

Only an ungameable fact (a diff line, a file status, the command string, PR/commit
metadata, a reviewer's approval) may hard-block. Anything that needs judgment is
advisory. `python3 ratchet.py validate` enforces this at parse time. A PR that tries to
make a judgment block won't merge — it would be a lie about the guarantee.

## Non-negotiable invariants

- **One file, zero runtime deps.** The engine is a single stdlib-only `ratchet.py`.
  Don't add a dependency, split it into a package, or add a build step. (`pyproject.toml`
  configures linters only.)
- **Primitives are pure functions** (`check, facts, repo -> reason | None`). No I/O in a
  primitive. Fact *acquisition* (git, the hook envelope, a CLI flag) stays out of them.
- **Base-pinning stays intact.** The change layer reads policy from the base ref, never
  the PR head.

The full rationale is in [`CLAUDE.md`](CLAUDE.md) → "Architecture invariants".

## Workflow

1. **TDD.** Add the failing test in `tests/test_ratchet.py` first — both a block path
   and a pass/skip path. No new behavior without a test that exercises it.
2. Implement the minimal change.
3. Follow the **"Adding a primitive" checklist** in [`CLAUDE.md`](CLAUDE.md) if that's
   what you're doing (register in `PRIMITIVES`, parse fields, wire dispatch, validate
   guard, docs).
4. Update docs in the same change: the README primitive table, [`SCHEMA.md`](SCHEMA.md),
   and — if the primitive came from observed failures — [`docs/coverage-map.md`](docs/coverage-map.md).
5. Run every gate (below). All green.

## Gates

```
python3 -m py_compile ratchet.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 ratchet.py validate
for f in examples/*/ratchet.toml; do python3 ratchet.py validate --config "$f"; done
python3 scripts/validate_plugin.py
ruff check ratchet.py tests && mypy ratchet.py     # pip install ruff mypy
python3 ratchet.py check --cwd .                   # the self-gate (ratchet gates ratchet)
```

CI runs the same recipes (`ci.yml` / `lint.yml` / `plugin-validate.yml` /
`self-gate.yml`). Because the repo gates itself, your PR has to pass the gate it ships —
including `self-protect` (no in-session edit to the gate files) and the `protected_path`
approval on `ratchet.py` / `ratchet.toml` / the workflows.

## Style

- Match the surrounding code: dense, sectioned, comments only for a non-obvious WHY.
- Keep the engine's section dividers and the fact-surface separation.
- Don't reformat unrelated code. `ruff` (config in `pyproject.toml`) is the arbiter for
  Python; long regex/template literals are intentionally exempt from line-length.

## Reporting a security issue

See [`SECURITY.md`](SECURITY.md). Don't open a public issue for a bypass of the gate's
guarantee — report it privately first.
