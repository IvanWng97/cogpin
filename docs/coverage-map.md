# Coverage map — what ratchet catches, and where each rule came from

ratchet's primitive library isn't a guess about how AI agents cut corners. The
fact-kind primitives were derived two ways: a first-principles pass over the
closing-discipline, then an empirical mining of **real** AI-authored PR/commit/review
history for failure classes the engine didn't yet cover. This page maps each
corner-cut class to the primitive that gates it and the evidence behind it.

## How the empirical pass was run

A 30-agent workflow swept nine corpora — the Claude Code issue tracker, public
`CLAUDE.md`/`AGENTS.md` repos, AI-authored commit reverts, the pixtuoid review
ledger, and competitor rule sets (pre-commit, Danger, OpenCommit, GitHub's own
agent-PR reviewer checklist). It produced **95 raw findings**, synthesized them into
**19 candidate gaps**, and adversarially verified each with a 3-skeptic pass against
verifiable citations. **Six** survived as real, fact-kind gaps; the semantic-weakening
classes that *can't* be a fact became the advisory library instead.

The discipline mirrors the engine's own rule: a finding only becomes a `block`
primitive if it decides over an ungameable fact. Everything else is advisory by
construction — see "the advisory frontier" below.

## The fact-kind coverage matrix

| corner-cut class | primitive | provenance |
|---|---|---|
| Bypass the hooks (`--no-verify`, `HUSKY=0`, `SKIP_PREFLIGHT`) | `forbid_command{pattern}` | first-principles; the canonical agent escape |
| Smuggle a gated verb past prefix matching (`git -C p push`, `cd d && …`, `env X=Y …`) | `forbid_command{deny}` (normalized) | mined — claude-code **#66176** ships the exact repro table; #49129 (113+ `rm -rf`/data-loss), #29082, #45974 (`git clean -fd`) |
| Commit straight to `main` / the shared checkout | `forbid_commit_on_branch` | first-principles; the "branch first" house rule |
| Loosen the gate's own config mid-session | `self_protect` (agent) / `protected_path` (change) | first-principles + the base-pin keystone |
| Scope creep — edit a subsystem outside the task | `scope_lock` | mined — **#34230** (titled "SCOPE LOCK violation"), #23067 (destroyed out-of-scope files), #64473/#18695/#57094/#62402, feature reqs #61888/#70236 (10+ reports; the single most-reported class) |
| Lower a quality threshold (coverage `fail_under`, raise retries, shorten a timeout) | `numeric_floor` | mined — `gh search commits "lower coverage threshold"` → 20+ repos in ~6 weeks; 0e3fbdf (85→75), 05c51cd (→19%), 70ca77e (→5%) |
| Commit a multi-MB binary / vendored bundle (zero diff lines) | `max_added_file_bytes` | mined — mirrors pre-commit's most-installed `check-added-large-files`; structurally invisible to every line-based primitive |
| Disarm CI from inside the message (`[skip ci]`) | `forbid_in_message` | mined — a one-token message disarms the change layer's own host; `marker_present`/`commit_footer` had no forbid-presence inverse |
| Ship a commit/PR message off its required shape (no Conventional Commits / ticket ref) | `require_message_pattern` | first-principles; the require-presence twin of `forbid_in_message` |
| Approve-then-push games (stale approval, self-approval, bot rubber-stamp, ignored CHANGES_REQUESTED) | `approval_policy` | mined — the gameable shape behind a bare `protected_path` approval check |
| Delete the failing test to go green | `forbid_delete{unless_paired_add}` | first-principles; the canonical "green by doing less" cut |
| Strip the assertion / the `await` / the guard line | `forbid_removal` | first-principles; the `−`-side twin a content scanner can't see |
| Slip a new dependency past review | `pattern_requires_approval` | ranked-unbuilt → built; the supply-chain cut |
| Touch a sensitive tree without an owner's review | `require_approval_from` | ranked-unbuilt → built; CODEOWNERS-lite |
| Mega-diff past honest review | `change_budget` | ranked-unbuilt → built; blast-radius cap |
| Ship a new file without its required header | `file_must_contain` | ranked-unbuilt → built; the positive-content floor |
| Merge a red / still-pending tree | `require_checks_green` | ranked-unbuilt → built |
| Leave docs / the ledger / a deferral-issue stale | `path_requires` / `cooccur` / `marker_present` | first-principles; the pixtuoid `check_dod.py` lineage |
| Drop a credential into the diff | `secret_scan` | first-principles (best-effort; pair with `gitleaks` via `run`) |

> **Provenance key.** *first-principles* — derived by reasoning about how agents cut corners.
> *mined* — surfaced in the empirical sweep of real AI-authored history (cited issues/commits).
> *ranked-unbuilt → built* — flagged as a gap in that ranking, then implemented.

## The advisory frontier (deliberately *not* blocking)

Some of the most damaging cuts are **semantic** — they need a comparison of the
*meaning* of two code states, which no set/string/count fact can prove. Making them
`block` would mean blocking on a judgment the gated agent can author, which the
schema forbids. They ship as the [`examples/advisory/`](../examples/advisory/ratchet.toml)
`judge` library (a CI `continue-on-error` LLM substance check):

| weakening class | why it can't be a fact |
|---|---|
| Assertion downgrade (`assertEqual`→`assertTrue`, exact→substring) | requires judging that the new assertion is *weaker*, not just different |
| Fake / mock implementation shaped to the test's expected output | requires judging intent vs computation |
| Validation loosening (anchor dropped, class widened, allowlist→denylist) | requires judging that the new pattern is *more permissive* |
| Guard / error-handling removal disguised as a refactor | the happy path still passes; "is this guard load-bearing?" is judgment |
| Silent fallback that swallows a failure | requires judging that the caught error *should* surface |
| Tautological test (`assert True`, `expect(x).toBe(x)`) | requires judging vacuity |
| Scope / spec drift (solved a narrower problem that passes the tests) | requires comparing to the *ask* |
| Comment / docstring rot | requires judging that prose now contradicts code |

**The forcing-function primitive.** `attest` is neither a blocking fact nor an LLM judge:
it's a class-gated `Stop`-hook checklist box that holds turn-end open until the agent ticks it —
a forcing function whose real teeth are the change-layer facts, not the box. Advisory by nature
(it decides over no diff fact, so it can never `block`); provenance: the pixtuoid `check_dod.py`
attestation lineage.

**The honest split:** a *test-skip marker* (`@pytest.mark.skip`, `it.only`,
`#[ignore]`) and a *suppression directive* (`# type: ignore`, `eslint-disable`,
`#[allow(...)]`) are ungameable **facts** — their *presence* blocks (or warns) via
`forbid_pattern`. Only whether the suppression is *justified* is advisory. So the
marker is a fact; the excuse is a judge prompt.

## What this does and doesn't claim

ratchet guarantees the **forcing function**, not omniscience. A `fact` block can't be
talked past — the strong claim, and it holds. But `forbid_removal`/`forbid_pattern`
are presence-ungameable yet value-gameable (`assert!(true)` satisfies "has an
assert"); `secret_scan` is best-effort; and a determined human with repo-admin rights
can always change the base policy *through review*. The line ratchet draws: anything an
agent can do **mid-task** to cut a corner, it stops; anything that needs **human
judgment** stays advisory and visible — a boundary the schema itself enforces.

**Provenance — the second clause of the moat.** `block` requires not just `kind="fact"` but
`provenance="environment"`: the fact must be produced by git / the harness / the PR API, never
a token the gated agent *types*. This closes a hole *inside* the fact set — a self-typed
`marker_present` ("two-lens-review:") is a verifiable string, yet it only **claims** an
out-of-band event the agent can fabricate, so it may only **warn**, not block. To gate a review,
block on a real non-author approval (`require_approval_from` / `approval_policy`). The honest
edges: the message/number families (`require_message_pattern`, `commit_footer`,
`file_must_contain`, `forbid_in_message`, `numeric_floor`) stay `environment` because the
regulated artifact *is* the committed text/number — but an author can abuse them to encode an
event-claim as a required phrase or hand-edit a metric; that abuse is structurally invisible to
provenance, so point event-claims at `attest`/`judge` and pair `numeric_floor` with a
`run`-generated metric file. The `marker_present`-vs-message line is drawn on *typical use*, not
raw fabricability.

**Fail-closed acquisition.** A fact gate only holds if it sees the *whole* change. So the
change layer refuses rather than passes when it can't: an unresolvable `base..HEAD` range
(a shallow clone — `actions/checkout`'s depth-1 default — or an unfetched base ref) exits
non-zero instead of gating a narrowed diff (use `fetch-depth: 0`); diff bytes are decoded
losslessly, so one non-UTF-8 byte can't empty a content scan; and non-ASCII paths
round-trip to the size/scope checks rather than silently dropping out. An unverifiable
gate fails **closed**, never open.
