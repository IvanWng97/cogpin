# Definition-of-Done attestation

The `cogpin stop` hook holds turn-end open until every box this change's *class* requires is
ticked. Tick a box only once it is genuinely true — an unticked required box is the forcing
function, not paperwork. Format: a `- [x] <label>` line (a space `- [ ]` is unticked); the
`<label>` matches each `attest` check's `box`. This file is the template for the
`attestation_file = ".dod/attestation.md"` declared in this recipe's `cogpin.toml`.

<!-- class=always — required on ANY code change -->
- [ ] TDD            <!-- a failing test preceded the implementation, watched fail, then passed -->
- [ ] Self-review    <!-- re-read the whole diff end-to-end before ending the turn -->

<!-- class=feature — required when the change is feature-shaped (>= meta.feature_files, or a new module) -->
- [ ] Design         <!-- the approach is written down / linked, not improvised -->
- [ ] Impl-plan      <!-- broke the work into steps before coding -->

<!-- class=public_surface — required when a public-surface file changed -->
- [ ] Docs-currency  <!-- README / SCHEMA / docs updated to match the change -->

<!--
Agent-layer escape hatch (skips the STOP nag + the push/merge DoD gate; the CHANGE layer —
pre-push + CI — ignores it). [meta].bypass_env = "DOD_BYPASS", so the marker is the env name
with underscores turned to dashes. The reason must be non-empty:

DOD-BYPASS: <one-line reason — e.g. hotfix, CI down, paging on-call (ticket OPS-123)>
-->
