<!-- cogpin gates this PR through its own cogpin.toml. The mechanical gates (definition-of-done /
     ci / lint / plugin-validate) are the teeth; this template is the human checklist + the
     two-lens-review cadence from CONTRIBUTING.md. Delete what doesn't apply. -->

## What & why


## The two-lens review (cogpin's cadence — see CONTRIBUTING.md)

- [ ] **Design lens** — the change belongs and keeps the invariants. The decisive one:
      **the moat holds** — every `severity = "block"` check is still `kind = "fact"` **and**
      `provenance = "environment"`. A new primitive is justified only by a fact no existing
      tool exposes (delegation via a `cogpin.toml` line couldn't answer it).
- [ ] **Adversarial lens** — hunted the diff for real bugs, fail-open/-closed inversions, a
      removed test/assert, and **cross-tree duplication** (grep'd the tree, not just the diff).

<!-- The `two-lens-review` check (warn) looks for the line below in this PR body. Keep it and
     note who/what ran each lens once both are done. -->
two-lens-review: design ✓ · adversarial ✓

## Gates (run locally — CI mirrors them)

- [ ] `python3 -m unittest discover -s tests -p 'test_*.py'`
- [ ] `python3 cogpin.py validate` + every `examples/*/cogpin.toml`
- [ ] `ruff check cogpin.py tests && mypy cogpin.py`
- [ ] `python3 cogpin.py check --cwd .` (the self-gate)
- [ ] Docs current (README primitive table / `SCHEMA.md` / `docs/coverage-map.md`) — if a
      primitive, `Check` field, or CLI flag changed.
