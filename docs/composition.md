# Composition map — where cogpin fits (and where it doesn't)

cogpin is **one layer** in a defense-in-depth stack, not the stack. It is the
**policy plane**: it declares which un-fabricable facts must hold before a change
merges, and renders a verdict. Every other layer is owned by something cogpin
*calls into* — never re-implements. A green cogpin gate is **not** a statement
that the work is good; reading it that way is the safety-theater failure this page
exists to prevent.

The "cogpin role" column below is the taxonomy: **policy plane** (cogpin owns it),
**capability floor** (cogpin *declares* a posture, the OS *enforces*), **verification
oracle** (cogpin *runs* the fact checks authoritatively, in CI), **review** (cogpin
fact-gates that review *happened*, never that it was good), **admission** (cogpin
hands the green signal off — out of scope).

## The stack

| Layer | Owner | Covers | cogpin's role |
|---|---|---|---|
| **Policy plane** (Definition-of-Done) | **cogpin** (`cogpin.toml` + `cogpin.py`) | Declaring which un-fabricable facts must hold before a change merges; binding `CLAUDE.md` house-rules to machine-checked facts | **policy plane** — cogpin *is* this layer; the single source of "done" |
| **Capability floor / sandbox** | OS + container + the agent harness (seccomp, Landlock, FS perms, network egress, the harness permission prompts) | What a process/agent *can do at all* — true containment | **capability floor** — cogpin *declares* the required posture and *emits* it to the harness (`[capability]` + `cogpin capability emit`); it **never contains**. The in-band command-deny is a forcing-function, not a sandbox |
| **Verification oracle** | CI runner (GitHub Actions / `action.yml`) over the base-pinned config; the test/lint/build/coverage tools it shells | Running the fact checks authoritatively on a machine the diff can't tamper with; running the actual suite | **verification oracle** — cogpin's authoritative run, base-pinned, fails *closed*. `run` / `require_checks_green` *delegate* to the real tools |
| **Review / approval** | Humans — PR reviewers, CODEOWNERS, forge branch-protection required reviews | Judgment: is the change correct / wise / good? | **review** — cogpin can require that review *happened* (`require_approval_from`, `approval_policy`, `pattern_requires_approval`; `marker_present` is a forcing-function nag) — never that it was *good* |
| **Admission / deploy** | Supply chain + admission control — Sigstore/cosign, SLSA provenance, Kyverno/OPA Gatekeeper, forge branch protection | Only signed/provenanced artifacts from a green pipeline reach prod; runtime admission | **admission** — **not covered.** cogpin gates the *change before merge*, not the *artifact at deploy*; it hands the green signal off |

## What cogpin does NOT cover

cogpin's claims are narrow on purpose. Five things it explicitly does **not** do —
wire the owning layer above for each:

1. **Substance / quality of the change.** A fact-gate certifies a discipline
   *happened* (tests exist, a footer is present, an approval was recorded), never
   that it was done *well*. By construction an LLM-judge or a self-attestation can
   only be **advisory** — the moat (`block` requires `kind="fact"` **and**
   `provenance="environment"`) forbids hard-blocking on a judgment or a self-typed
   claim. → owned by the **review** layer.
2. **Code correctness / does-it-actually-work.** cogpin checks the facts you told
   it to; it does not know if the code is right. Whether the build passes and the
   tests are green is the **verification oracle**'s job — cogpin only *delegates*
   (`run`, `require_checks_green`) and reports the fact.
3. **Runtime containment.** cogpin cannot stop a process from doing anything. The
   agent-layer command/path/scope deny (`forbid_command`, `forbid_commit_on_branch`,
   `self_protect`, `scope_lock`) is an in-band **forcing-function**: it nudges the
   agent mid-session, is bypassable via `[meta].bypass_env`, and is *always logged*
   — it is **not** a sandbox. Defeated by indirection (a subprocess, a helper script,
   an obfuscated verb) and only fires if the harness invokes the hook. Real
   containment is the **capability floor** (OS/harness).
4. **Post-merge / deploy / runtime / production behavior.** Artifact signing, SLSA
   provenance, admission control, what the running system does in prod — all the
   **admission** layer. cogpin stops at merge.
5. **Anything off the fact-surface.** Only `DiffFacts` / `CommandFacts` are visible.
   If a requirement isn't expressible as a fact over the diff or the command, cogpin
   can't see it — and per the delegation rule below it should be pushed to a layer that can.

## The ceiling (stated plainly)

A fact-gate can certify that a discipline *happened*; it can never certify that the
discipline was done *well*. cogpin's entire value lives in the gap between a *fact*
and a *prohibition*: the only thing it will ever hard-block on is an un-fabricable,
independently-observable fact (`provenance="environment"` — a CI result, a recorded
approval, a branch name, a real diff), not something the author merely *asserts*. That
un-fabricable observability is the whole product. Above that line — was the code
correct, was the review thoughtful, is the running system safe — cogpin contributes
exactly nothing, and even the signal it *does* produce is worth zero unless a higher
layer (a human reviewer, a CI oracle, an admission controller) actually **consumes**
it. cogpin raises the floor of what is *observable* before a merge; it does not raise
the ceiling of what is *good*, and it is not a substitute for the layers that do.

## Project rule: delegation over a new primitive

Before adding a new engine primitive, ask: can this requirement be answered by a
`cogpin.toml` *line* that delegates to a tool which already enforces it? A `run`
check shelling an existing linter/test; a `require_checks_green` over an existing CI
job; a `path_requires`/`approval_policy` pointing at CODEOWNERS. **If a request is
satisfiable by a config line wiring an existing external tool, it is answered by that
line — not by a new primitive.** cogpin is the policy plane that *composes* other
layers' oracles, not a re-implementation of them. A new primitive is justified only
when it expresses a *fact no existing tool already exposes* — and even then it must
clear the moat (`block` ⇒ `provenance="environment"`). This is the operational
consequence of "one file, zero deps": every primitive that could have been a
delegation line is dead weight in the engine and a claim cogpin now has to *own*
instead of *borrow*. (It is step 0 of the "Adding a primitive" checklist in
[`CLAUDE.md`](../CLAUDE.md).)
