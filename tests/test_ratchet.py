"""Stdlib-only test suite for ratchet (no pytest dependency — `python3 -m unittest`)."""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ratchet import (  # noqa: E402
    HOUSE_RULE_MAP,
    PREPUSH_BLOCK,
    RATCHET_BEGIN,
    SAFE_CORE_IDS,
    Check,
    CommandFacts,
    Config,
    ConfigError,
    DiffFacts,
    HouseRuleHit,
    RepoCfg,
    RepoScan,
    _atomic_write,
    _detect_hook_manager,
    _effective_hook_target,
    _ensure_gitignore,
    _git_ops,
    _glob_to_re,
    _replace_or_append_block,
    _strip_block,
    _ticked,
    approval_state_depth,
    attestation_gaps,
    change_budget,
    change_classes,
    cmd_doctor,
    cmd_install,
    cmd_uninstall,
    commit_footer,
    cooccur,
    detect_test_command,
    draft_lint,
    file_must_contain,
    forbid_command,
    forbid_delete,
    forbid_in_message,
    forbid_pattern,
    forbid_removal,
    guess_globs,
    has_block,
    is_bound,
    marker_present,
    max_added_file_bytes,
    numeric_floor,
    path_requires,
    pattern_requires_approval,
    protected_path,
    push_or_merge,
    rank_house_rules,
    render_suggest_toml,
    require_approval_from,
    require_checks_green,
    require_message_pattern,
    run_branch_gate,
    run_change,
    run_command_gate,
    scan_house_rules,
    scope_lock,
    secret_scan,
    self_protect,
)

MIN = """
schema = 1
[repo]
default_branch = "main"
code = ["src/**/*.rs"]
"""


def repo():
    return RepoCfg(
        default_branch="main",
        code=["src/**/*.rs", "src/**/*.py"],
        tests=["tests/**/*.rs", "tests/**/*.py"],
        docs=["**/*.md", "docs/**"],
    )


def one_check(toml: str) -> Check:
    base = 'schema=1\n[repo]\ndefault_branch="main"\ncode=["src/**/*.rs"]\ntests=["tests/**/*.rs"]\ndocs=["**/*.md"]\n'
    return Config.parse(base + toml).checks[0]


class TestGlob(unittest.TestCase):
    def test_double_star_crosses_dirs_and_zero(self):
        self.assertTrue(_glob_to_re("src/**/*.rs").match("src/a.rs"))
        self.assertTrue(_glob_to_re("src/**/*.rs").match("src/x/y.rs"))
        self.assertTrue(_glob_to_re("**/*.md").match("README.md"))
        self.assertTrue(_glob_to_re("**/*.md").match("docs/a/b.md"))
        self.assertTrue(_glob_to_re("docs/**").match("docs/a/b.md"))
        self.assertFalse(_glob_to_re("src/*.rs").match("src/x/y.rs"))  # * stays in segment
        self.assertFalse(_glob_to_re("src/**/*.rs").match("lib/a.rs"))


class TestConfig(unittest.TestCase):
    def test_parses_minimal_and_base_pinned_defaults_on(self):
        c = Config.parse(MIN)
        self.assertEqual(c.repo.default_branch, "main")
        self.assertTrue(c.meta.base_pinned, "base_pinned must default ON (bypass-proof)")

    def test_block_requires_fact_is_enforced(self):
        bad = MIN + '\n[[check]]\nid="x"\nkind="advisory"\nseverity="block"\nprimitive="judge"\n'
        with self.assertRaises(ConfigError) as e:
            Config.parse(bad)
        self.assertIn("requires kind=fact", str(e.exception))

    def test_fact_block_is_allowed(self):
        ok = MIN + '\n[[check]]\nid="x"\nkind="fact"\nseverity="block"\nprimitive="forbid_command"\npattern="--no-verify"\n'
        self.assertEqual(len(Config.parse(ok).checks), 1)

    def test_run_block_must_be_change_layer(self):
        bad = MIN + '\n[[check]]\nid="r"\nkind="fact"\nseverity="block"\nlayer="agent"\nprimitive="run"\ncmd="true"\n'
        with self.assertRaises(ConfigError) as e:
            Config.parse(bad)
        self.assertIn("change layer", str(e.exception))

    def test_str_or_vec_normalizes(self):
        cfg = MIN + '\n[[check]]\nid="p"\nkind="fact"\nseverity="warn"\nprimitive="path_requires"\nwhen="code"\nneed=["a","b"]\n'
        chk = Config.parse(cfg).checks[0]
        self.assertEqual(chk.when, ["code"])
        self.assertEqual(chk.need, ["a", "b"])

    def test_duplicate_id_rejected(self):
        dup = MIN + (
            '\n[[check]]\nid="x"\nkind="fact"\nseverity="warn"\nprimitive="marker_present"\nmarker="m"\n'
            '\n[[check]]\nid="x"\nkind="fact"\nseverity="warn"\nprimitive="marker_present"\nmarker="n"\n'
        )
        with self.assertRaises(ConfigError) as e:
            Config.parse(dup)
        self.assertIn("duplicate", str(e.exception))

    def test_unknown_primitive_rejected(self):
        bad = MIN + '\n[[check]]\nid="x"\nkind="fact"\nseverity="warn"\nprimitive="frobnicate"\n'
        with self.assertRaises(ConfigError):
            Config.parse(bad)

    def test_wrong_schema_version_rejected(self):
        with self.assertRaises(ConfigError):
            Config.parse('schema = 2\n[repo]\ndefault_branch="main"\n')


class TestFacts(unittest.TestCase):
    def test_pretooluse_extracts_command(self):
        j = '{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}'
        self.assertEqual(CommandFacts.from_pretooluse_json(j).command, "git push origin main")

    def test_pretooluse_malformed_is_empty_not_raise(self):
        self.assertEqual(CommandFacts.from_pretooluse_json("not json").command, "")
        self.assertEqual(CommandFacts.from_pretooluse_json("{}").command, "")
        self.assertEqual(CommandFacts.from_pretooluse_json('{"tool_input":7}').command, "")


class TestPrimitives(unittest.TestCase):
    def test_forbid_command_denies_no_verify(self):
        c = one_check('[[check]]\nid="nv"\nkind="fact"\nseverity="block"\nprimitive="forbid_command"\npattern="--no-verify"')
        self.assertIsNotNone(forbid_command(c, CommandFacts("git push --no-verify")))
        self.assertIsNone(forbid_command(c, CommandFacts("git push")))

    def test_secret_scan_catches_token_and_envfile(self):
        c = one_check(
            '[[check]]\nid="s"\nkind="fact"\nseverity="block"\nprimitive="secret_scan"\n'
            'forbid_paths=[".env", "*.pem"]\ncustom=["re_[A-Za-z0-9]{16,}"]'
        )
        f = DiffFacts(added=[("src/a.rs", 'let k = "re_abcdefabcdefabcdef";')])
        self.assertIsNotNone(secret_scan(c, f))
        # forbidden path at root AND nested (basename match), but not on delete
        self.assertIsNotNone(secret_scan(c, DiffFacts(changed=[("A", ".env")])))
        self.assertIsNotNone(secret_scan(c, DiffFacts(changed=[("A", "config/.env")])))
        self.assertIsNotNone(secret_scan(c, DiffFacts(changed=[("M", "certs/server.pem")])))
        self.assertIsNone(secret_scan(c, DiffFacts(changed=[("D", ".env")])))
        self.assertIsNone(secret_scan(c, DiffFacts()))

    def test_secret_scan_builtin_aws_key(self):
        c = one_check('[[check]]\nid="s"\nkind="fact"\nseverity="block"\nprimitive="secret_scan"')
        f = DiffFacts(added=[("cfg.py", 'AWS = "AKIAIOSFODNN7EXAMPLE"')])
        self.assertIsNotNone(secret_scan(c, f))

    def test_forbid_pattern_scopes_and_exempts(self):
        c = one_check(
            '[[check]]\nid="p"\nkind="fact"\nseverity="block"\nprimitive="forbid_pattern"\n'
            'pattern="println!"\nscope="code"\nexempt="ratchet:allow"\nstrip_comments=false'
        )
        r = repo()
        hit = DiffFacts(added=[("src/x.rs", '    println!("debug");')])
        self.assertIsNotNone(forbid_pattern(c, hit, r))
        ex = DiffFacts(added=[("src/x.rs", '    println!("ok"); // ratchet:allow')])
        self.assertIsNone(forbid_pattern(c, ex, r))
        oos = DiffFacts(added=[("tests/x.rs", '    println!("in test");')])
        self.assertIsNone(forbid_pattern(c, oos, r))

    def test_forbid_pattern_comment_strip_kills_hidden_token(self):
        # with strip_comments, a token that only appears inside a comment is ignored
        c = one_check(
            '[[check]]\nid="p"\nkind="fact"\nseverity="warn"\nprimitive="forbid_pattern"\n'
            'pattern="TODO"\nscope="code"\nstrip_comments=true'
        )
        r = repo()
        in_comment = DiffFacts(added=[("src/x.py", "x = 1  # TODO later")])
        self.assertIsNone(forbid_pattern(c, in_comment, r))
        in_code = DiffFacts(added=[("src/x.py", 'raise Exception("TODO")')])
        self.assertIsNotNone(forbid_pattern(c, in_code, r))

    def test_path_requires_couples_code_to_docs(self):
        c = one_check('[[check]]\nid="d"\nkind="fact"\nseverity="warn"\nprimitive="path_requires"\nwhen="code"\nneed="docs"')
        r = repo()
        code_only = DiffFacts(changed=[("M", "src/a.rs")])
        self.assertIsNotNone(path_requires(c, code_only, r))
        both = DiffFacts(changed=[("M", "src/a.rs"), ("M", "README.md")])
        self.assertIsNone(path_requires(c, both, r))

    def test_cooccur(self):
        c = one_check(
            '[[check]]\nid="co"\nkind="fact"\nseverity="warn"\nprimitive="cooccur"\n'
            'trigger="BREAKING"\nrequire="CHANGELOG"'
        )
        miss = DiffFacts(pr_body="BREAKING change to the API")
        self.assertIsNotNone(cooccur(c, miss))
        ok = DiffFacts(pr_body="BREAKING change", commit_msgs=["docs: update CHANGELOG"])
        self.assertIsNone(cooccur(c, ok))
        none = DiffFacts(pr_body="ordinary change")
        self.assertIsNone(cooccur(c, none))

    def test_marker_present(self):
        c = one_check('[[check]]\nid="m"\nkind="fact"\nseverity="warn"\nprimitive="marker_present"\nmarker="Two-lens-review:"')
        r = repo()
        # PR context, marker absent → fail; present → pass
        self.assertIsNotNone(marker_present(c, DiffFacts(pr_body="no marker here"), r))
        self.assertIsNone(marker_present(c, DiffFacts(pr_body="Two-lens-review: A + B"), r))
        # no PR context (pr_body None) → skip, defer to CI
        self.assertIsNone(marker_present(c, DiffFacts(), r))

    def test_marker_present_when_gated_to_code(self):
        c = one_check(
            '[[check]]\nid="m"\nkind="fact"\nseverity="block"\nprimitive="marker_present"\n'
            'marker="Two-lens-review:"\nwhen="code"'
        )
        r = repo()
        # docs-only PR (no code path) → marker not required even with empty body
        docs_only = DiffFacts(pr_body="", changed=[("M", "README.md")])
        self.assertIsNone(marker_present(c, docs_only, r))
        # code PR with empty body → marker required → fail
        code_pr = DiffFacts(pr_body="", changed=[("M", "src/a.py")])
        self.assertIsNotNone(marker_present(c, code_pr, r))
        # code PR with the marker → pass
        code_ok = DiffFacts(pr_body="Two-lens-review:\n- a: APPROVE\n- b: APPROVE", changed=[("M", "src/a.py")])
        self.assertIsNone(marker_present(c, code_ok, r))

    def test_forbid_pattern_scope_accepts_glob_list(self):
        c = one_check(
            '[[check]]\nid="nv"\nkind="fact"\nseverity="block"\nprimitive="forbid_pattern"\n'
            'pattern="--no-verify"\nscope=["**/*.sh", "justfile", ".github/workflows/**"]'
        )
        r = repo()
        self.assertIsNotNone(forbid_pattern(c, DiffFacts(added=[("ci.sh", "git push --no-verify")]), r))
        self.assertIsNotNone(forbid_pattern(c, DiffFacts(added=[("justfile", "git commit --no-verify")]), r))
        # a .rs source file is out of the gitop scope → not flagged (token is data there)
        self.assertIsNone(forbid_pattern(c, DiffFacts(added=[("src/a.rs", 'let x = "--no-verify";')]), r))

    def test_commit_footer_requires_every_commit(self):
        pat = r"Co-Authored-By: Claude"
        ok = DiffFacts(commit_msgs=["feat: x\n\nCo-Authored-By: Claude Opus"])
        bad = DiffFacts(commit_msgs=["feat: y"])
        self.assertIsNone(commit_footer(pat, ok))
        self.assertIsNotNone(commit_footer(pat, bad))

    def test_protected_path_skips_without_pr_context(self):
        c = one_check(
            '[[check]]\nid="pp"\nkind="fact"\nseverity="block"\nprimitive="protected_path"\n'
            'paths=["ratchet.toml","justfile"]'
        )
        # no PR context (approvals None) → skip, defer to CI
        local = DiffFacts(changed=[("M", "ratchet.toml")])
        self.assertIsNone(protected_path(c, local))
        # PR context, gate file changed, zero approvals → block
        unapproved = DiffFacts(changed=[("M", "ratchet.toml")], approvals=[])
        self.assertIsNotNone(protected_path(c, unapproved))
        # PR context, gate file changed, an approval present → pass
        approved = DiffFacts(changed=[("M", "ratchet.toml")], approvals=["reviewer-bob"])
        self.assertIsNone(protected_path(c, approved))
        # PR context, no gate file touched → pass
        unrelated = DiffFacts(changed=[("M", "src/a.rs")], approvals=[])
        self.assertIsNone(protected_path(c, unrelated))

    def test_forbid_removal_guards_deleted_guard_lines(self):
        # the '-' twin of forbid_pattern: a REMOVED line matching the guard pattern
        # under scope blocks — the "silently delete the assert/await/?" class.
        c = one_check(
            '[[check]]\nid="keep-guards"\nkind="fact"\nseverity="block"\nprimitive="forbid_removal"\n'
            'pattern="assert|# nosec"\nscope="code"\nexempt="ratchet:allow"'
        )
        r = repo()
        hit = DiffFacts(removed=[("src/a.py", "    assert x == 1")])
        self.assertIsNotNone(forbid_removal(c, hit, r))
        # out of code scope (a removed test line) → not flagged
        oos = DiffFacts(removed=[("tests/a.py", "    assert y")])
        self.assertIsNone(forbid_removal(c, oos, r))
        # no pattern match → pass
        plain = DiffFacts(removed=[("src/a.py", "    x = 1")])
        self.assertIsNone(forbid_removal(c, plain, r))
        # an exempt pragma on the removed line → allowed
        ex = DiffFacts(removed=[("src/a.py", "    assert x  # ratchet:allow")])
        self.assertIsNone(forbid_removal(c, ex, r))
        # added lines are NOT the removed surface → pass even if they match
        added_only = DiffFacts(added=[("src/a.py", "    assert x == 1")])
        self.assertIsNone(forbid_removal(c, added_only, r))

    def test_forbid_removal_strip_comments(self):
        c = one_check(
            '[[check]]\nid="kr"\nkind="fact"\nseverity="warn"\nprimitive="forbid_removal"\n'
            'pattern="TODO"\nscope="code"\nstrip_comments=true'
        )
        r = repo()
        in_comment = DiffFacts(removed=[("src/x.py", "x = 1  # TODO later")])
        self.assertIsNone(forbid_removal(c, in_comment, r))
        in_code = DiffFacts(removed=[("src/x.py", 'raise Exception("TODO")')])
        self.assertIsNotNone(forbid_removal(c, in_code, r))

    def test_forbid_delete_guards_file_deletion(self):
        c = one_check(
            '[[check]]\nid="no-test-delete"\nkind="fact"\nseverity="block"\nprimitive="forbid_delete"\n'
            'scope="tests"\nunless_paired_add=true'
        )
        r = repo()
        # delete a test file → block ("delete the failing test to go green")
        self.assertIsNotNone(forbid_delete(c, DiffFacts(changed=[("D", "tests/a.py")]), r))
        # editing (M) is not a deletion → pass
        self.assertIsNone(forbid_delete(c, DiffFacts(changed=[("M", "tests/a.py")]), r))
        # a deletion out of scope (src) → pass
        self.assertIsNone(forbid_delete(c, DiffFacts(changed=[("D", "src/a.py")]), r))
        # unless_paired_add: a paired add under the same scope (rename/replace) → suppressed
        self.assertIsNone(
            forbid_delete(c, DiffFacts(changed=[("D", "tests/a.py"), ("A", "tests/b.py")]), r)
        )

    def test_forbid_delete_without_paired_suppression_still_blocks(self):
        c = one_check(
            '[[check]]\nid="nd"\nkind="fact"\nseverity="block"\nprimitive="forbid_delete"\nscope="tests"'
        )
        r = repo()
        # default unless_paired_add=false → a paired add does NOT suppress the delete
        self.assertIsNotNone(
            forbid_delete(c, DiffFacts(changed=[("D", "tests/a.py"), ("A", "tests/b.py")]), r)
        )


class TestEngine(unittest.TestCase):
    def cfg(self):
        return Config.parse(
            """
            schema = 1
            [repo]
            default_branch = "main"
            code = ["src/**/*.rs"]
            docs = ["**/*.md"]
            [meta]
            commit_footer = 'Co-Authored-By: Claude'
            [[check]]
            id = "secrets"
            kind = "fact"
            severity = "block"
            primitive = "secret_scan"
            custom = ['re_[A-Za-z0-9]{16,}']
            [[check]]
            id = "docs-currency"
            kind = "fact"
            severity = "warn"
            primitive = "path_requires"
            when = "code"
            need = "docs"
            [[check]]
            id = "nv"
            kind = "fact"
            severity = "block"
            layer = "agent"
            primitive = "forbid_command"
            pattern = "--no-verify"
            """
        )

    def test_change_layer_blocks_secret_warns_docs_skips_agent_check(self):
        f = DiffFacts(
            added=[("src/a.rs", 'let k="re_abcdefabcdefabcdef";')],
            changed=[("M", "src/a.rs")],
        )
        findings = run_change(self.cfg(), f)
        self.assertTrue(has_block(findings), "secret must block")
        self.assertTrue(any(x.id == "docs-currency" and x.severity == "warn" for x in findings))
        self.assertFalse(any(x.id == "nv" for x in findings), "agent check must not run in change layer")

    def test_no_run_skips_run_blocks(self):
        cfg = Config.parse(
            'schema=1\n[repo]\ndefault_branch="main"\n'
            '[[check]]\nid="teeth"\nkind="fact"\nseverity="block"\nlayer="change"\nprimitive="run"\ncmd="false"\n'
        )
        # allow_run=True executes `false` → blocking finding
        self.assertTrue(has_block(run_change(cfg, DiffFacts(), allow_run=True)))
        # allow_run=False (cheap Stop hook) skips it entirely
        self.assertEqual(run_change(cfg, DiffFacts(), allow_run=False), [])

    def test_command_gate_only_runs_forbid_command(self):
        findings = run_command_gate(self.cfg(), CommandFacts("git commit --no-verify"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "nv")
        self.assertTrue(has_block(findings))
        self.assertEqual(run_command_gate(self.cfg(), CommandFacts("git status")), [])


class TestAgentLayer(unittest.TestCase):
    """The check_dod.py-parity pieces: push/merge detection, change-class gating,
    and the attestation Stop-gaps."""

    ATTEST_CFG = """
        schema = 1
        [repo]
        default_branch = "main"
        code = ["crates/*/src/**/*.rs"]
        public_surface = ["crates/*/src/cli.rs"]
        [meta]
        feature_files = 3
        [[check]]
        id = "attest-tdd"
        kind = "advisory"
        severity = "attest"
        layer = "agent"
        primitive = "attest"
        class = "always"
        box = "TDD"
        [[check]]
        id = "attest-design"
        kind = "advisory"
        severity = "attest"
        layer = "agent"
        primitive = "attest"
        class = "feature"
        box = "Design"
        [[check]]
        id = "attest-docs"
        kind = "advisory"
        severity = "attest"
        layer = "agent"
        primitive = "attest"
        class = "public_surface"
        box = "Docs-currency"
    """

    def test_push_or_merge_detection(self):
        self.assertEqual(push_or_merge("git push origin main"), "push")
        self.assertEqual(push_or_merge("git add . && git push"), "push")
        self.assertEqual(push_or_merge("git -C dir -c k=v push"), "push")  # skips opt + value
        self.assertEqual(push_or_merge("gh pr merge 7 --squash"), "merge")
        self.assertEqual(push_or_merge("gh api repos/o/r/pulls/7/merge -X PUT"), "merge")
        self.assertIsNone(push_or_merge("git status"))
        self.assertIsNone(push_or_merge("git commit -m 'about to push'"))  # quoted → not a push

    def test_ticked_parsing(self):
        md = "- [x] TDD\n- [ ] Design\n-[X] Self-review"
        self.assertTrue(_ticked(md, "TDD"))
        self.assertTrue(_ticked(md, "Self-review"))
        self.assertFalse(_ticked(md, "Design"))
        self.assertFalse(_ticked(md, "Impl-plan"))

    def test_change_classes(self):
        cfg = Config.parse(self.ATTEST_CFG)
        # 1 code file, not public → always only
        c1 = change_classes(cfg, DiffFacts(changed=[("M", "crates/x/src/state.rs")]))
        self.assertEqual(c1, {"always": True, "feature": False, "public_surface": False, "claude_md": False})
        # 3 files → feature-shaped
        c2 = change_classes(cfg, DiffFacts(changed=[("M", f"crates/x/src/{n}.rs") for n in "abc"]))
        self.assertTrue(c2["feature"])
        # a new module (status A under code) → feature even with 1 file
        c3 = change_classes(cfg, DiffFacts(changed=[("A", "crates/x/src/new.rs")]))
        self.assertTrue(c3["feature"])
        # public-surface file touched
        c4 = change_classes(cfg, DiffFacts(changed=[("M", "crates/x/src/cli.rs")]))
        self.assertTrue(c4["public_surface"])
        # docs-only → nothing triggers
        c5 = change_classes(cfg, DiffFacts(changed=[("M", "README.md")]))
        self.assertFalse(any(c5.values()))

    def test_attestation_gaps_are_class_gated(self):
        cfg = Config.parse(self.ATTEST_CFG)
        # a single code file, nothing ticked → only the "always" box (TDD) is required
        facts1 = DiffFacts(changed=[("M", "crates/x/src/state.rs")])
        ids = {g.id for g in attestation_gaps(cfg, facts1, md="")}
        self.assertEqual(ids, {"attest-tdd"})
        # feature-shaped (3 files) → TDD + Design required
        facts2 = DiffFacts(changed=[("M", f"crates/x/src/{n}.rs") for n in "abc"])
        ids2 = {g.id for g in attestation_gaps(cfg, facts2, md="")}
        self.assertEqual(ids2, {"attest-tdd", "attest-design"})
        # ticking TDD clears it
        ids3 = {g.id for g in attestation_gaps(cfg, facts2, md="- [x] TDD")}
        self.assertEqual(ids3, {"attest-design"})
        # public surface → adds Docs-currency
        facts4 = DiffFacts(changed=[("M", "crates/x/src/cli.rs")])
        ids4 = {g.id for g in attestation_gaps(cfg, facts4, md="- [x] TDD")}
        self.assertEqual(ids4, {"attest-docs"})
        # docs-only → no required boxes at all
        self.assertEqual(attestation_gaps(cfg, DiffFacts(changed=[("M", "README.md")]), md=""), [])

    def test_attest_does_not_violate_block_requires_fact(self):
        # an attest check is advisory severity → the schema invariant doesn't reject it,
        # yet the Stop runtime still blocks turn-end on its unticked boxes.
        self.assertEqual(len(Config.parse(self.ATTEST_CFG).checks), 3)

    BRANCH_CFG = """
        schema = 1
        [repo]
        default_branch = "main"
        [[check]]
        id = "no-main-commit"
        kind = "fact"
        severity = "block"
        layer = "agent"
        primitive = "forbid_commit_on_branch"
        branch = ["main", "release/*"]
        ops = ["commit", "push"]
    """

    def test_git_ops_detects_subcommands(self):
        self.assertEqual(_git_ops("git commit -m x"), {"commit"})
        self.assertEqual(_git_ops("git add . && git push origin main"), {"add", "push"})
        self.assertEqual(_git_ops("git -C dir -c k=v push"), {"push"})  # skips opt + value
        self.assertEqual(_git_ops("ls -la"), set())
        self.assertEqual(_git_ops("git commit -m 'git push later'"), {"commit"})  # quote-stripped

    def test_forbid_commit_on_branch_denies_on_protected(self):
        cfg = Config.parse(self.BRANCH_CFG)
        # commit while on main → one blocking finding
        f = run_branch_gate(cfg, CommandFacts("git commit -m x"), "main")
        self.assertTrue(has_block(f))
        # push while on a release branch (glob match) → block
        self.assertTrue(has_block(run_branch_gate(cfg, CommandFacts("git push"), "release/1.2")))
        # on a feature branch → allowed
        self.assertEqual(run_branch_gate(cfg, CommandFacts("git commit -m x"), "feature/x"), [])
        # a non-commit/push op on main → allowed (not in ops)
        self.assertEqual(run_branch_gate(cfg, CommandFacts("git status"), "main"), [])
        # detached / unknown branch → never blocks (no false positive)
        self.assertEqual(run_branch_gate(cfg, CommandFacts("git commit -m x"), None), [])

    def test_forbid_commit_on_branch_defaults_to_repo_default_branch(self):
        cfg = Config.parse(
            'schema=1\n[repo]\ndefault_branch="trunk"\n'
            '[[check]]\nid="b"\nkind="fact"\nseverity="block"\nlayer="agent"\n'
            'primitive="forbid_commit_on_branch"\n'  # no branch/ops → defaults: branch=[default], ops=[commit,push]
        )
        self.assertTrue(has_block(run_branch_gate(cfg, CommandFacts("git commit -m x"), "trunk")))
        self.assertEqual(run_branch_gate(cfg, CommandFacts("git commit -m x"), "main"), [])

    def test_forbid_commit_on_branch_rejects_change_layer(self):
        # the current branch is a live agent-layer fact; a pure change-layer placement
        # would silently never fire, so the config must declare it agent/both.
        bad = (
            'schema=1\n[repo]\ndefault_branch="main"\n'
            '[[check]]\nid="b"\nkind="fact"\nseverity="block"\nlayer="change"\n'
            'primitive="forbid_commit_on_branch"\n'
        )
        with self.assertRaises(ConfigError):
            Config.parse(bad)


class TestDiffParsing(unittest.TestCase):
    """Exercise DiffFacts.from_range against a real git repo so the removed-line
    fact (and the added-line parser it mirrors) is covered end-to-end."""

    def _git(self, *args):
        subprocess.run(["git", "-C", self.d, *args], check=True, capture_output=True, text=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.dir if hasattr(self.tmp, "dir") else self.tmp.name
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._git("config", "commit.gpgsign", "false")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel, text):
        with open(os.path.join(self.d, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_from_range_captures_added_and_removed(self):
        self._write("a.py", "keep = 1\nassert x == 1\ndrop_me = 2\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        base = subprocess.run(
            ["git", "-C", self.d, "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        # remove the assert + drop_me lines, add a new one
        self._write("a.py", "keep = 1\nadded_line = 3\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "change")
        facts = DiffFacts.from_range(self.d, base, "HEAD")
        removed = [line for _, line in facts.removed]
        added = [line for _, line in facts.added]
        self.assertIn("assert x == 1", removed)
        self.assertIn("drop_me = 2", removed)
        self.assertIn("added_line = 3", added)
        # removed lines carry the (old) path
        self.assertTrue(all(p == "a.py" for p, _ in facts.removed))

    def test_from_range_whole_file_delete_records_removed_lines(self):
        self._write("gone.py", "assert critical\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        base = subprocess.run(
            ["git", "-C", self.d, "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        os.remove(os.path.join(self.d, "gone.py"))
        self._git("add", "-A")
        self._git("commit", "-qm", "delete file")
        facts = DiffFacts.from_range(self.d, base, "HEAD")
        self.assertIn(("D", "gone.py"), facts.changed)
        # the deleted file's lines surface as removed, tagged with the old path
        self.assertIn(("gone.py", "assert critical"), facts.removed)


class TestMinedPrimitives(unittest.TestCase):
    """The four mining-confirmed, zero-new-fact gaps: scope_lock, forbid_in_message,
    forbid_command `deny` (normalized verb match), numeric_floor."""

    def test_scope_lock_allowlist(self):
        c = one_check(
            '[[check]]\nid="sl"\nkind="fact"\nseverity="block"\nprimitive="scope_lock"\n'
            'allow=["docs/**", "src/**/*.py"]'
        )
        r = repo()
        # every changed path inside the allowlist → pass
        self.assertIsNone(scope_lock(c, DiffFacts(changed=[("M", "src/a.py"), ("A", "docs/x.md")]), r))
        # a modified path outside allow → block
        self.assertIsNotNone(scope_lock(c, DiffFacts(changed=[("M", "src/a.py"), ("M", "infra/deploy.tf")]), r))
        # A/M/D all count — a deletion outside scope blocks too
        self.assertIsNotNone(scope_lock(c, DiffFacts(changed=[("D", "prod/secrets.py")]), r))
        # empty allow → never blocks (unconfigured)
        empty = one_check('[[check]]\nid="e"\nkind="fact"\nseverity="block"\nprimitive="scope_lock"')
        self.assertIsNone(scope_lock(empty, DiffFacts(changed=[("M", "anything")]), r))

    def test_scope_lock_resolves_named_scopes(self):
        c = one_check('[[check]]\nid="sl"\nkind="fact"\nseverity="block"\nprimitive="scope_lock"\nallow=["docs"]')
        r = repo()  # docs = ["**/*.md", "docs/**"]
        self.assertIsNone(scope_lock(c, DiffFacts(changed=[("M", "README.md")]), r))
        self.assertIsNotNone(scope_lock(c, DiffFacts(changed=[("M", "src/a.py")]), r))

    def test_forbid_in_message(self):
        c = one_check(
            '[[check]]\nid="sci"\nkind="fact"\nseverity="block"\nprimitive="forbid_in_message"\n'
            'tokens=["[skip ci]", "[ci skip]"]'
        )
        self.assertIsNotNone(forbid_in_message(c, DiffFacts(commit_msgs=["feat: x [skip ci]"])))
        self.assertIsNotNone(forbid_in_message(c, DiffFacts(commit_msgs=["feat: x [SKIP CI]"])))  # case-insensitive
        self.assertIsNotNone(forbid_in_message(c, DiffFacts(pr_body="please [ci skip] this")))
        self.assertIsNone(forbid_in_message(c, DiffFacts(commit_msgs=["feat: normal"], pr_body="fine")))
        self.assertIsNone(forbid_in_message(c, DiffFacts(commit_msgs=["feat: ok"])))  # no pr context, clean

    def test_forbid_in_message_scope(self):
        # restrict to the commit SUBJECT (first line) — a token in the body is then ignored
        c = one_check(
            '[[check]]\nid="s"\nkind="fact"\nseverity="block"\nprimitive="forbid_in_message"\n'
            'tokens=["[skip ci]"]\nmsg_scope=["commit_subject"]'
        )
        self.assertIsNotNone(forbid_in_message(c, DiffFacts(commit_msgs=["wip [skip ci]\n\nbody"])))
        self.assertIsNone(forbid_in_message(c, DiffFacts(commit_msgs=["wip\n\nbody has [skip ci]"])))

    def test_forbid_command_deny_normalized(self):
        c = one_check(
            '[[check]]\nid="d"\nkind="fact"\nseverity="block"\nlayer="agent"\nprimitive="forbid_command"\n'
            'deny=["git push", "git reset --hard", "rm -rf"]'
        )
        self.assertIsNotNone(forbid_command(c, CommandFacts("git push origin main")))   # direct
        self.assertIsNotNone(forbid_command(c, CommandFacts("git -C /repo push")))       # -C wrapper
        self.assertIsNotNone(forbid_command(c, CommandFacts("cd /repo && git push")))    # cd && wrapper
        self.assertIsNotNone(forbid_command(c, CommandFacts("FOO=1 git push")))          # env prefix
        self.assertIsNotNone(forbid_command(c, CommandFacts("git -c k=v reset --hard HEAD~1")))  # -c k=v
        self.assertIsNotNone(forbid_command(c, CommandFacts("sudo rm -rf /tmp/x")))      # rm -rf
        self.assertIsNone(forbid_command(c, CommandFacts("git status")))                 # benign
        self.assertIsNone(forbid_command(c, CommandFacts("git format-patch")))           # different subcommand
        self.assertIsNone(forbid_command(c, CommandFacts('echo "git push later"')))      # quoted → not a real op

    def test_forbid_command_pattern_still_works_with_deny(self):
        # the legacy `pattern` (raw regex, matches anywhere) coexists with `deny`
        c = one_check(
            '[[check]]\nid="d"\nkind="fact"\nseverity="block"\nlayer="agent"\nprimitive="forbid_command"\n'
            'pattern="--no-verify"\ndeny=["git push"]'
        )
        self.assertIsNotNone(forbid_command(c, CommandFacts("git commit --no-verify")))
        self.assertIsNotNone(forbid_command(c, CommandFacts("git -C x push")))
        self.assertIsNone(forbid_command(c, CommandFacts("git commit -m ok")))

    def test_numeric_floor_no_decrease(self):
        c = one_check(
            "[[check]]\nid=\"cov\"\nkind=\"fact\"\nseverity=\"block\"\nprimitive=\"numeric_floor\"\n"
            "scope=[\"**/*.toml\"]\nkey='fail_under\\s*=\\s*([0-9.]+)'\ndirection=\"no_decrease\""
        )
        r = repo()
        lowered = DiffFacts(removed=[("setup.toml", "fail_under = 85")], added=[("setup.toml", "fail_under = 75")])
        self.assertIsNotNone(numeric_floor(c, lowered, r))   # 85 → 75 blocked
        raised = DiffFacts(removed=[("setup.toml", "fail_under = 75")], added=[("setup.toml", "fail_under = 85")])
        self.assertIsNone(numeric_floor(c, raised, r))       # tightening allowed
        oos = DiffFacts(removed=[("a.py", "fail_under = 85")], added=[("a.py", "fail_under = 75")])
        self.assertIsNone(numeric_floor(c, oos, r))          # out of scope

    def test_numeric_floor_no_increase(self):
        c = one_check(
            "[[check]]\nid=\"retry\"\nkind=\"fact\"\nseverity=\"block\"\nprimitive=\"numeric_floor\"\n"
            "scope=[\"*.cfg\"]\nkey='retries\\s*=\\s*([0-9]+)'\ndirection=\"no_increase\""
        )
        r = repo()
        raised = DiffFacts(removed=[("a.cfg", "retries = 1")], added=[("a.cfg", "retries = 5")])
        self.assertIsNotNone(numeric_floor(c, raised, r))    # raising retries blocked

    def test_numeric_floor_absolute_floor(self):
        c = one_check(
            "[[check]]\nid=\"cov\"\nkind=\"fact\"\nseverity=\"block\"\nprimitive=\"numeric_floor\"\n"
            "scope=[\"*.cfg\"]\nkey='cov\\s*=\\s*([0-9.]+)'\ndirection=\"no_decrease\"\nfloor=80"
        )
        r = repo()
        self.assertIsNotNone(numeric_floor(c, DiffFacts(added=[("a.cfg", "cov = 70")]), r))  # new value below floor
        self.assertIsNone(numeric_floor(c, DiffFacts(added=[("a.cfg", "cov = 85")]), r))     # at/above floor


class TestFullCoverage(unittest.TestCase):
    """The remaining ranked + mined gaps that complete the coverage map: count budgets,
    positive content, message-require, byte size, self-protect, and the PR-review-API
    family (reviews/head_sha/pr_author/checks facts)."""

    def test_change_budget(self):
        c = one_check('[[check]]\nid="cb"\nkind="fact"\nseverity="warn"\nprimitive="change_budget"\nmax_added=5\nmax_files=2')
        r = repo()
        self.assertIsNone(change_budget(c, DiffFacts(added=[("a", "x")], changed=[("M", "a")]), r))
        big = DiffFacts(added=[("a", f"l{i}") for i in range(6)], changed=[("M", "a")])
        self.assertIsNotNone(change_budget(c, big, r))  # too many added lines
        many = DiffFacts(changed=[("M", "a"), ("M", "b"), ("M", "c")])
        self.assertIsNotNone(change_budget(c, many, r))  # too many files

    def test_change_budget_per_file(self):
        c = one_check('[[check]]\nid="cb"\nkind="fact"\nseverity="warn"\nprimitive="change_budget"\nmax_file_added=3')
        over = DiffFacts(added=[("a.py", f"l{i}") for i in range(4)], changed=[("M", "a.py")])
        self.assertIsNotNone(change_budget(c, over, repo()))

    def test_file_must_contain(self):
        c = one_check(
            '[[check]]\nid="spdx"\nkind="fact"\nseverity="block"\nprimitive="file_must_contain"\n'
            'scope=["src/**/*.py"]\npattern="SPDX-License"\nstatus="A"'
        )
        r = repo()
        miss = DiffFacts(added=[("src/a.py", "import os")], changed=[("A", "src/a.py")])
        self.assertIsNotNone(file_must_contain(c, miss, r))  # added file lacks the line
        ok = DiffFacts(added=[("src/a.py", "# SPDX-License-Identifier: MIT"), ("src/a.py", "import os")], changed=[("A", "src/a.py")])
        self.assertIsNone(file_must_contain(c, ok, r))
        mod = DiffFacts(added=[("src/a.py", "import os")], changed=[("M", "src/a.py")])
        self.assertIsNone(file_must_contain(c, mod, r))  # status M is not gated when status=A

    def test_require_message_pattern(self):
        c = one_check(
            "[[check]]\nid=\"cc\"\nkind=\"fact\"\nseverity=\"block\"\nprimitive=\"require_message_pattern\"\n"
            "pattern='^(feat|fix|docs|chore)(\\(.+\\))?:'\nmsg_scope=[\"commit_subject\"]"
        )
        self.assertIsNone(require_message_pattern(c, DiffFacts(commit_msgs=["feat: add x"])))
        self.assertIsNotNone(require_message_pattern(c, DiffFacts(commit_msgs=["random subject"])))
        self.assertIsNone(require_message_pattern(c, DiffFacts()))  # no commits → skip

    def test_max_added_file_bytes(self):
        c = one_check(
            '[[check]]\nid="big"\nkind="fact"\nseverity="block"\nprimitive="max_added_file_bytes"\n'
            'maxkb=500\nallow_binary=false'
        )
        r = repo()
        self.assertIsNone(max_added_file_bytes(c, DiffFacts(changed=[("A", "x")]), r))  # no sizes fact → skip
        self.assertIsNone(max_added_file_bytes(c, DiffFacts(file_sizes={"a.txt": 1000}), r))
        self.assertIsNotNone(max_added_file_bytes(c, DiffFacts(file_sizes={"big.bin": 600 * 1024}), r))  # > 500kb
        self.assertIsNotNone(max_added_file_bytes(c, DiffFacts(file_sizes={"img.png": -1}), r))  # binary, disallowed

    def test_self_protect(self):
        c = one_check(
            '[[check]]\nid="sp"\nkind="fact"\nseverity="block"\nlayer="agent"\nprimitive="self_protect"\n'
            'paths=["ratchet.toml", ".ratchet/**", ".claude/settings.json"]'
        )
        self.assertIsNotNone(self_protect(c, "Edit", "ratchet.toml"))
        self.assertIsNotNone(self_protect(c, "Write", ".ratchet/ratchet.py"))
        self.assertIsNone(self_protect(c, "Edit", "src/app.py"))    # not a protected path
        self.assertIsNone(self_protect(c, "Bash", "ratchet.toml"))  # not a Write/Edit tool

    def test_require_approval_from(self):
        c = one_check(
            '[[check]]\nid="raf"\nkind="fact"\nseverity="block"\nprimitive="require_approval_from"\n'
            'paths=["core/**"]\nrequire_approval_from=["alice", "bob"]\nexclude_author=true'
        )
        self.assertIsNone(require_approval_from(c, DiffFacts(changed=[("M", "core/x.py")])))  # no PR ctx → skip
        ok = DiffFacts(changed=[("M", "core/x.py")], pr_author="zoe", reviews=[{"login": "alice", "state": "APPROVED"}])
        self.assertIsNone(require_approval_from(c, ok))
        bad = DiffFacts(changed=[("M", "core/x.py")], pr_author="zoe", reviews=[{"login": "carol", "state": "APPROVED"}])
        self.assertIsNotNone(require_approval_from(c, bad))   # approver not in the list
        sa = DiffFacts(changed=[("M", "core/x.py")], pr_author="alice", reviews=[{"login": "alice", "state": "APPROVED"}])
        self.assertIsNotNone(require_approval_from(c, sa))    # listed owner but is the author
        self.assertIsNone(require_approval_from(c, DiffFacts(changed=[("M", "docs/x.md")], pr_author="zoe", reviews=[])))

    def test_pattern_requires_approval(self):
        c = one_check(
            "[[check]]\nid=\"pra\"\nkind=\"fact\"\nseverity=\"block\"\nprimitive=\"pattern_requires_approval\"\n"
            "pattern='^\\+?\\s*[a-z0-9_-]+ = '\nscope=[\"**/Cargo.toml\"]\nexclude_author=true"
        )
        r = repo()
        dep = [("Cargo.toml", 'serde = "1"')]
        self.assertIsNone(pattern_requires_approval(c, DiffFacts(added=dep), r))  # no PR ctx → skip
        bad = DiffFacts(added=dep, pr_author="zoe", reviews=[])
        self.assertIsNotNone(pattern_requires_approval(c, bad, r))  # dep line, no approval
        ok = DiffFacts(added=dep, pr_author="zoe", reviews=[{"login": "bob", "state": "APPROVED"}])
        self.assertIsNone(pattern_requires_approval(c, ok, r))
        nomatch = DiffFacts(added=[("Cargo.toml", "# just a comment")], pr_author="zoe", reviews=[])
        self.assertIsNone(pattern_requires_approval(c, nomatch, r))

    def test_approval_state_depth(self):
        c = one_check(
            '[[check]]\nid="asd"\nkind="fact"\nseverity="block"\nprimitive="approval_state_depth"\n'
            'require_fresh=true\nno_changes_requested=true\ndisallow_author=true\ndisallow_bot=true\nmin_approvals=1'
        )
        self.assertIsNone(approval_state_depth(c, DiffFacts()))  # no PR ctx → skip
        ok = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "abc", "is_bot": False}])
        self.assertIsNone(approval_state_depth(c, ok))
        stale = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "OLD", "is_bot": False}])
        self.assertIsNotNone(approval_state_depth(c, stale))  # approval not on head
        sa = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "alice", "state": "APPROVED", "commit_id": "abc", "is_bot": False}])
        self.assertIsNotNone(approval_state_depth(c, sa))     # self-approval
        cr = DiffFacts(head_sha="abc", pr_author="alice", reviews=[
            {"login": "bob", "state": "APPROVED", "commit_id": "abc", "is_bot": False},
            {"login": "carol", "state": "CHANGES_REQUESTED", "commit_id": "abc", "is_bot": False}])
        self.assertIsNotNone(approval_state_depth(c, cr))     # outstanding changes-requested
        bot = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "dependabot", "state": "APPROVED", "commit_id": "abc", "is_bot": True}])
        self.assertIsNotNone(approval_state_depth(c, bot))    # bot-only approval

    def test_require_checks_green(self):
        c = one_check('[[check]]\nid="rcg"\nkind="fact"\nseverity="block"\nprimitive="require_checks_green"')
        self.assertIsNone(require_checks_green(c, DiffFacts()))  # no ctx → skip
        self.assertIsNone(require_checks_green(c, DiffFacts(checks=[{"name": "ci", "conclusion": "success"}])))
        self.assertIsNotNone(require_checks_green(c, DiffFacts(checks=[{"name": "ci", "conclusion": "failure"}])))
        self.assertIsNotNone(require_checks_green(c, DiffFacts(checks=[{"name": "ci", "conclusion": None}])))  # pending


class TestGlobGuessing(unittest.TestCase):
    """guess_globs — dominant-language detection + keep-only-matching globs."""

    def test_python_repo(self):
        code, tests, docs = guess_globs(["src/app.py", "tests/test_app.py", "docs/x.md"])
        self.assertTrue(any(_glob_to_re(g).match("src/app.py") for g in code))
        self.assertTrue(any(_glob_to_re(g).match("tests/test_app.py") for g in tests))
        self.assertIn("**/*.md", docs)
        self.assertIn("docs/**", docs)

    def test_rust_crates_layout(self):
        code, tests, _ = guess_globs(["crates/x/src/a.rs", "crates/x/tests/b.rs", "Cargo.toml"])
        self.assertIn("crates/*/src/**/*.rs", code)
        self.assertNotIn("src/**/*.rs", code)  # no flat leak

    def test_node_ts(self):
        code, tests, _ = guess_globs(["src/a.ts", "src/a.test.ts", "package.json"])
        self.assertTrue(any(_glob_to_re(g).match("src/a.ts") for g in code))
        self.assertIn("**/*.test.ts", tests)

    def test_only_emits_matching_globs(self):
        code, _, _ = guess_globs(["app.py", "util.py"])
        self.assertIn("*.py", code)
        self.assertNotIn("src/**/*.py", code)

    def test_dominant_language_wins(self):
        code, _, _ = guess_globs(["a.py", "b.py", "c.py", "one.js"])
        self.assertTrue(any(".py" in g for g in code))

    def test_empty_tree_safe(self):
        self.assertEqual(guess_globs([]), ([], [], ["**/*.md"]))


class TestTestCommand(unittest.TestCase):
    """detect_test_command — manifest parsed as TEXT, never executed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _w(self, name, text):
        with open(os.path.join(self.d, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_justfile(self):
        self._w("justfile", "build:\n  cargo build\ntest:\n  pytest\n")
        self.assertEqual(detect_test_command(self.d), ("just test", "justfile"))

    def test_package_json(self):
        self._w("package.json", '{"scripts": {"test": "vitest run"}}')
        self.assertEqual(detect_test_command(self.d), ("npm test", "package.json"))

    def test_package_json_ignores_npm_placeholder(self):
        self._w("package.json", '{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}')
        self.assertEqual(detect_test_command(self.d), (None, None))

    def test_pyproject_pytest(self):
        self._w("pyproject.toml", "[tool.pytest.ini_options]\naddopts = '-q'\n")
        self.assertEqual(detect_test_command(self.d), ("python3 -m pytest -q", "pyproject.toml"))

    def test_cargo(self):
        self._w("Cargo.toml", "[package]\nname = 'x'\n")
        self.assertEqual(detect_test_command(self.d), ("cargo test", "Cargo.toml"))

    def test_makefile(self):
        self._w("Makefile", "all:\n\tgo build\ntest:\n\tgo test ./...\n")
        self.assertEqual(detect_test_command(self.d), ("make test", "Makefile"))

    def test_priority_just_over_make(self):
        self._w("justfile", "test:\n  pytest\n")
        self._w("Makefile", "test:\n\tmake-test\n")
        self.assertEqual(detect_test_command(self.d), ("just test", "justfile"))

    def test_none(self):
        self.assertEqual(detect_test_command(self.d), (None, None))

    def test_malformed_toml_degrades(self):
        self._w("pyproject.toml", "this is not = valid = toml [[[")
        self.assertEqual(detect_test_command(self.d), (None, None))


class TestHouseRuleScan(unittest.TestCase):
    """scan_house_rules / rank_house_rules — CLAUDE.md prose → primitive hits."""

    def _scan(self, text, branch="main", cmd=None):
        return scan_house_rules(text, source="CLAUDE.md", default_branch=branch, test_cmd=cmd)

    def _ids(self, hits):
        return {h.suggested_id for h in hits}

    def test_no_verify(self):
        self.assertIn("no-verify", self._ids(self._scan("Never use --no-verify to skip hooks.")))

    def test_branch_first_uses_default_branch(self):
        hits = self._scan("If on main, branch first.", branch="trunk")
        bf = next(h for h in hits if h.suggested_id == "branch-first")
        self.assertEqual(bf.params["branch"], ["trunk"])

    def test_no_secrets(self):
        self.assertIn("secret-scan", self._ids(self._scan("Don't commit secrets or .env files.")))

    def test_never_commit_secrets_phrasing(self):
        # the common imperative phrasing ("Never commit secrets") must also map
        self.assertIn("secret-scan", self._ids(self._scan("Never commit secrets to the repo.")))

    def test_update_docs(self):
        self.assertIn("docs-currency", self._ids(self._scan("Keep docs current when you change the API.")))

    def test_two_lens_review(self):
        self.assertIn("two-lens-review", self._ids(self._scan("Every PR needs a two-lens review before merge.")))

    def test_run_tests_uses_detected_cmd(self):
        hits = self._scan("Always run the tests before pushing.", cmd="just test")
        tp = next(h for h in hits if h.suggested_id == "tests-pass")
        self.assertEqual(tp.params["cmd"], "just test")
        self.assertEqual(tp.render, "commented")
        self.assertEqual(tp.confidence, "high")

    def test_run_tests_without_cmd_low_conf(self):
        tp = next(h for h in self._scan("All tests must pass.") if h.suggested_id == "tests-pass")
        self.assertEqual(tp.confidence, "low")
        self.assertIn("TODO", tp.params["cmd"])

    def test_dedup_keeps_first(self):
        hits = self._scan("no --no-verify here\nand no --no-verify there\n")
        self.assertEqual(sum(1 for h in hits if h.suggested_id == "no-verify"), 1)

    def test_carries_evidence_line(self):
        hit = next(h for h in self._scan("  Rule: don't commit secrets.  ") if h.suggested_id == "secret-scan")
        self.assertEqual(hit.rule_text, "Rule: don't commit secrets.")

    def test_unrelated_prose_yields_nothing(self):
        self.assertEqual(self._scan("This project renders pixel art in a terminal."), [])

    def test_conventional_commits(self):
        self.assertIn("conventional-commits", self._ids(self._scan("Use conventional commits.")))

    def test_skip_ci(self):
        self.assertIn("no-skip-ci", self._ids(self._scan("Don't disable CI with [skip ci].")))

    def test_semantic_maps_to_judge(self):
        hit = next(h for h in self._scan("Don't loosen an assertion to pass.") if h.suggested_id == "semantic-judge")
        self.assertEqual(hit.render, "judge")
        self.assertIn("loosen", hit.params["prompt"])

    def test_ranks_high_before_low(self):
        # a high-confidence hit (secret-scan) outranks a low one (deferral-has-issue)
        ranked = rank_house_rules(self._scan("Don't commit secrets.\nTrack every deferred follow-up issue.\n"))
        ids = [h.suggested_id for h in ranked]
        self.assertLess(ids.index("secret-scan"), ids.index("deferral-has-issue"))


def _scan(rules_text="", branch="main", cmd="just test"):
    from ratchet import scan_house_rules
    return RepoScan(
        default_branch=branch, code=["src/**/*.py"], tests=["tests/**/*.py"], docs=["**/*.md"],
        test_cmd=cmd, test_cmd_source="justfile", claude_md_paths=["CLAUDE.md"],
        house_rules=scan_house_rules(rules_text, source="CLAUDE.md", default_branch=branch, test_cmd=cmd),
    )


class TestSuggestRender(unittest.TestCase):
    """render_suggest_toml — an all-warn (+commented/judge) starter that always parses."""

    def test_render_validates(self):
        Config.parse(render_suggest_toml(_scan("Run the tests. Two-lens review. Don't loosen an assertion.")))

    def test_render_is_all_warn_except_safe_core(self):
        cfg = Config.parse(render_suggest_toml(_scan("Use conventional commits. Keep docs current.")))
        blocks = {c.id for c in cfg.checks if c.severity == "block"}
        self.assertEqual(blocks, set(SAFE_CORE_IDS))

    def test_render_has_draft_banner_and_todos(self):
        toml = render_suggest_toml(_scan("Use conventional commits."))
        self.assertIn("ratchet.toml.draft", toml)
        self.assertIn("# TODO(ratchet:review)", toml)

    def test_render_commented_blocks_for_run_and_approval(self):
        toml = render_suggest_toml(_scan("Run the tests. Owner approval from CODEOWNERS. Stay in scope."))
        # run / require_approval_from / scope_lock render commented-out
        self.assertIn("# [[check]]", toml)
        self.assertNotIn('\nid = "tests-pass"', toml)  # only its commented form

    def test_render_includes_repo_and_base_pinned(self):
        toml = render_suggest_toml(_scan())
        self.assertIn("base_pinned = true", toml)
        self.assertIn('default_branch =', toml)


class TestDraftLint(unittest.TestCase):
    """draft_lint — the moat-safety net beyond validate."""

    def _base(self, rules=""):
        # a render with no markers cleared: strip markers to get a clean armed-or-advisory draft
        return render_suggest_toml(_scan(rules))

    def _clean(self):
        # safe-core only, no house-rules → zero markers → clean
        return render_suggest_toml(_scan(""))

    def _levels(self, text, existing=None, head=None):
        return [f.level for f in draft_lint(text, existing_cfg=existing, head_facts=head)]

    def test_clean_draft_with_no_markers_passes(self):
        self.assertNotIn("error", self._levels(self._clean()))
        self.assertNotIn("todo", self._levels(self._clean()))

    def test_re_error_pattern_rejected(self):
        bad = self._clean() + '\n[[check]]\nid = "x"\nkind = "fact"\nseverity = "warn"\nprimitive = "forbid_pattern"\npattern = "["\nscope = "src/**/*.py"\n'
        self.assertIn("error", self._levels(bad))

    def test_match_everything_pattern_rejected(self):
        bad = self._clean() + '\n[[check]]\nid = "x"\nkind = "fact"\nseverity = "warn"\nprimitive = "forbid_pattern"\npattern = ".*"\nscope = "src/**/*.py"\n'
        self.assertIn("error", self._levels(bad))

    def test_unknown_key_rejected(self):
        bad = self._clean() + '\n[[check]]\nid = "x"\nkind = "fact"\nseverity = "warn"\nprimitive = "secret_scan"\nforbid_path = "x"\n'
        self.assertIn("error", self._levels(bad))

    def test_base_pinned_false_rejected(self):
        bad = self._clean().replace("base_pinned = true", "base_pinned = false")
        self.assertIn("error", self._levels(bad))

    def test_missing_safe_core_rejected(self):
        minimal = 'schema = 1\n[repo]\ndefault_branch = "main"\n[meta]\nbase_pinned = true\n'
        self.assertIn("error", self._levels(minimal))

    def test_inferred_block_with_marker_rejected(self):
        bad = self._clean() + '\n# TODO(ratchet:review): from CLAUDE.md\n[[check]]\nid = "x"\nkind = "fact"\nseverity = "block"\nprimitive = "forbid_pattern"\npattern = "foo"\nscope = "src/**/*.py"\n'
        self.assertIn("error", self._levels(bad))

    def test_weaken_existing_rejected(self):
        existing = Config.parse('schema = 1\n[repo]\ndefault_branch = "main"\n[[check]]\nid = "keep-me"\nkind = "fact"\nseverity = "block"\nprimitive = "secret_scan"\n')
        self.assertIn("error", self._levels(self._clean(), existing=existing))  # keep-me dropped

    def test_secret_in_draft_text_rejected(self):
        bad = self._clean() + '\n# ghp_' + "a" * 36 + "\n"
        self.assertIn("error", self._levels(bad))

    def test_over_broad_forbid_command_warns(self):
        bad = self._clean() + '\n[[check]]\nid = "x"\nkind = "fact"\nseverity = "warn"\nlayer = "agent"\nprimitive = "forbid_command"\ndeny = ["git push"]\n'
        self.assertIn("warn", self._levels(bad))

    def test_todo_markers_force_findings(self):
        toml = self._base("Use conventional commits. Keep docs current.")
        self.assertIn("todo", self._levels(toml))


class TestGapsBinding(unittest.TestCase):
    """is_bound — primitive presence + the polymorphic match-token refinement."""

    def _hit(self, primitive, token=None):
        return HouseRuleHit(suggested_id="x", keyword="", primitive=primitive, params={},
                            confidence="high", match_token=token)

    def _check(self, toml):
        return Config.parse(MIN + toml).checks[-1]

    def test_is_bound_primitive_presence(self):
        c = self._check('[[check]]\nid = "s"\nkind = "fact"\nseverity = "block"\nprimitive = "secret_scan"\n')
        self.assertTrue(is_bound(self._hit("secret_scan"), [c])[0])

    def test_is_bound_polymorphic_requires_token(self):
        c = self._check('[[check]]\nid = "p"\nkind = "fact"\nseverity = "warn"\nprimitive = "forbid_pattern"\npattern = "println"\nscope = "src/**/*.rs"\n')
        self.assertFalse(is_bound(self._hit("forbid_pattern", ".only"), [c])[0])
        self.assertTrue(is_bound(self._hit("forbid_pattern", "println"), [c])[0])

    def test_is_bound_forbid_command_token(self):
        c = self._check('[[check]]\nid = "f"\nkind = "fact"\nseverity = "block"\nlayer = "agent"\nprimitive = "forbid_command"\ndeny = ["git push"]\n')
        self.assertFalse(is_bound(self._hit("forbid_command", "--no-verify"), [c])[0])
        c2 = self._check('[[check]]\nid = "f2"\nkind = "fact"\nseverity = "block"\nlayer = "agent"\nprimitive = "forbid_command"\npattern = "--no-verify"\n')
        self.assertTrue(is_bound(self._hit("forbid_command", "--no-verify"), [c2])[0])


class TestMoatPreservation(unittest.TestCase):
    """Pin the moat against future HOUSE_RULE_MAP edits."""

    _FACT_PRIMS = {
        "forbid_command", "forbid_commit_on_branch", "self_protect", "secret_scan",
        "forbid_pattern", "forbid_removal", "forbid_delete", "scope_lock", "numeric_floor",
        "change_budget", "file_must_contain", "max_added_file_bytes", "path_requires",
        "cooccur", "marker_present", "forbid_in_message", "require_message_pattern",
        "commit_footer", "protected_path", "require_approval_from", "pattern_requires_approval",
        "approval_state_depth", "require_checks_green", "run",
    }

    def test_suggest_introduces_no_nonfact_block(self):
        cfg = Config.parse(render_suggest_toml(_scan(
            "Run the tests. Two-lens review. Conventional commits. Don't loosen an assertion. "
            "Owner approval. Coverage must not drop. No [skip ci]. Keep docs current."
        )))
        for c in cfg.checks:
            if c.severity == "block":
                self.assertEqual(c.kind, "fact", f"{c.id} blocks but isn't a fact")

    def test_house_rule_map_block_rows_are_all_facts(self):
        for rule in HOUSE_RULE_MAP:
            if rule.render == "block":
                self.assertIn(rule.primitive, self._FACT_PRIMS, f"{rule.rid} renders block on a non-fact")


_RATCHET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ratchet.py")


class TestSuggestGapsCLI(unittest.TestCase):
    """End-to-end via subprocess in a temp git repo (mirrors TestDiffParsing's harness)."""

    def _git(self, *args):
        subprocess.run(["git", "-C", self.d, *args], check=True, capture_output=True, text=True)

    def _ratchet(self, *args):
        return subprocess.run([sys.executable, _RATCHET, *args, "--cwd", self.d],
                              capture_output=True, text=True, encoding="utf-8")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._git("config", "commit.gpgsign", "false")
        self._w("src/app.py", "import os\n")
        self._w("tests/test_app.py", "def test_x():\n    assert True\n")
        self._w("CLAUDE.md", "If on main, branch first.\nAlways run the tests.\nKeep docs current.\n"
                             "Don't commit secrets.\nUse conventional commits.\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def _w(self, rel, text):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_cli_suggest_on_python_repo(self):
        r = self._ratchet("suggest", "--format", "json")
        self.assertEqual(r.returncode, 0, r.stderr)
        import json as _json
        data = _json.loads(r.stdout)
        ids = {h["suggested_id"] for h in data["house_rules"]}
        self.assertIn("branch-first", ids)
        self.assertIn("tests-pass", ids)
        self.assertIn("docs-currency", ids)
        self.assertTrue(any(_glob_to_re(g).match("src/app.py") for g in data["code"]))

    def test_cli_suggest_toml_validates(self):
        r = self._ratchet("suggest", "--format", "toml")
        self.assertEqual(r.returncode, 0, r.stderr)
        draft = os.path.join(self.d, "ratchet.toml.draft")
        with open(draft, "w", encoding="utf-8") as fh:
            fh.write(r.stdout)
        v = subprocess.run([sys.executable, _RATCHET, "validate", "--config", draft],
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_cli_draft_lint_fails_on_markers(self):
        r = self._ratchet("suggest", "--format", "toml")
        with open(os.path.join(self.d, "ratchet.toml.draft"), "w", encoding="utf-8") as fh:
            fh.write(r.stdout)
        dl = self._ratchet("draft-lint")
        self.assertEqual(dl.returncode, 1)  # markers remain
        self.assertIn("TODO", dl.stdout)

    def test_cli_draft_lint_clean_after_markers_removed(self):
        r = self._ratchet("suggest", "--format", "toml")
        cleaned = "\n".join(ln for ln in r.stdout.splitlines()
                            if not ln.lstrip().startswith("# TODO(ratchet:review)"))
        with open(os.path.join(self.d, "ratchet.toml.draft"), "w", encoding="utf-8") as fh:
            fh.write(cleaned)
        dl = self._ratchet("draft-lint")
        self.assertEqual(dl.returncode, 0, dl.stdout + dl.stderr)

    def test_cli_gaps_roundtrip(self):
        r = self._ratchet("suggest", "--format", "toml")
        cleaned = "\n".join(ln for ln in r.stdout.splitlines()
                            if not ln.lstrip().startswith("# TODO(ratchet:review)"))
        with open(os.path.join(self.d, "ratchet.toml"), "w", encoding="utf-8") as fh:
            fh.write(cleaned)
        g = self._ratchet("gaps")
        self.assertEqual(g.returncode, 0, g.stderr)


def _quiet(fn, *a, **k):
    """Run a cmd_* entrypoint, swallow its stdout, return (rc, captured_stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = fn(*a, **k)
    return rc, buf.getvalue()


class TestBlockHelpers(unittest.TestCase):
    """Pure sentinel-block surgery — no git, no fs."""

    def test_append_when_absent(self):
        out = _replace_or_append_block("#!/bin/sh\necho hi\n", PREPUSH_BLOCK)
        self.assertTrue(out.startswith("#!/bin/sh\necho hi\n"))
        self.assertIn(RATCHET_BEGIN, out)

    def test_replace_in_place_no_double_append(self):
        once = _replace_or_append_block("#!/bin/sh\n", PREPUSH_BLOCK)
        twice = _replace_or_append_block(once, PREPUSH_BLOCK)
        self.assertEqual(once, twice)  # byte-idempotent
        self.assertEqual(once.count(RATCHET_BEGIN), 1)

    def test_append_adds_separator_when_no_trailing_newline(self):
        out = _replace_or_append_block("echo hi", PREPUSH_BLOCK)
        self.assertIn("echo hi\n" + RATCHET_BEGIN, out)

    def test_replace_preserves_surrounding(self):
        cur = _replace_or_append_block("#!/bin/sh\nA\n", PREPUSH_BLOCK) + "Z\n"
        out = _replace_or_append_block(cur, PREPUSH_BLOCK)
        self.assertIn("#!/bin/sh\nA\n", out)
        self.assertTrue(out.rstrip().endswith("Z"))
        self.assertEqual(out.count(RATCHET_BEGIN), 1)

    def test_strip_removes_exactly_the_span(self):
        cur = "#!/bin/sh\nA\n" + PREPUSH_BLOCK + "Z\n"
        out = _strip_block(cur)
        self.assertNotIn(RATCHET_BEGIN, out)
        self.assertIn("A\n", out)
        self.assertIn("Z\n", out)

    def test_strip_noop_when_absent(self):
        cur = "#!/bin/sh\necho hi\n"
        self.assertEqual(_strip_block(cur), cur)


class TestAtomicWrite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_through_symlink_to_realpath(self):
        real = os.path.join(self.d, "real.txt")
        with open(real, "w") as fh:
            fh.write("old\n")
        link = os.path.join(self.d, "link.txt")
        os.symlink(real, link)
        _atomic_write(link, "new\n")
        self.assertTrue(os.path.islink(link))  # symlink preserved
        with open(real) as fh:
            self.assertEqual(fh.read(), "new\n")  # real target updated

    @unittest.skipIf(os.name == "nt", "Windows has no POSIX exec bit (git-for-windows sh runs the hook regardless)")
    def test_executable_mode(self):
        p = os.path.join(self.d, "hook")
        _atomic_write(p, "#!/bin/sh\n", mode=0o755)
        self.assertTrue(os.stat(p).st_mode & 0o111)


class _GitRepo(unittest.TestCase):
    """Shared git-temp harness for the wiring tests."""

    def _git(self, *args):
        subprocess.run(["git", "-C", self.d, *args], check=True, capture_output=True, text=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._git("config", "commit.gpgsign", "false")

    def tearDown(self):
        self.tmp.cleanup()

    def _w(self, rel, text):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p) or self.d, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _read(self, rel):
        with open(os.path.join(self.d, rel), encoding="utf-8") as fh:
            return fh.read()

    def _prepush(self):
        return os.path.join(self.d, ".git", "hooks", "pre-push")


class TestEnsureGitignore(_GitRepo):
    def test_scoped_and_idempotent(self):
        _ensure_gitignore(self.d)
        _ensure_gitignore(self.d)
        gi = self._read(".gitignore")
        self.assertIn(".ratchet/.state", gi)
        self.assertNotIn(".ratchet/\n", gi)  # never the whole dir
        self.assertEqual(gi.count(".ratchet/.state"), 1)  # no dup

    def test_preserves_existing(self):
        self._w(".gitignore", "node_modules\n")
        _ensure_gitignore(self.d)
        gi = self._read(".gitignore")
        self.assertIn("node_modules", gi)
        self.assertIn(".ratchet/.state", gi)


class TestHookTarget(_GitRepo):
    def test_default_git_hooks(self):
        action, payload = _effective_hook_target(self.d, self.d)
        self.assertEqual(action, "write")
        self.assertEqual(os.path.realpath(payload), os.path.realpath(self._prepush()))

    def test_lefthook_emits_snippet(self):
        self._w("lefthook.yml", "pre-commit:\n")
        self.assertEqual(_detect_hook_manager(self.d), "lefthook")
        action, payload = _effective_hook_target(self.d, self.d)
        self.assertEqual(action, "snippet:lefthook")
        self.assertIn("lefthook", payload)

    def test_precommit_emits_repo_local_snippet(self):
        self._w(".pre-commit-config.yaml", "repos: []\n")
        action, payload = _effective_hook_target(self.d, self.d)
        self.assertEqual(action, "snippet:pre-commit")
        self.assertIn("repo: local", payload)

    def test_husky_targets_husky_prepush(self):
        os.makedirs(os.path.join(self.d, ".husky"))
        action, payload = _effective_hook_target(self.d, self.d)
        self.assertEqual(action, "write")
        self.assertEqual(payload, os.path.join(self.d, ".husky", "pre-push"))

    def test_core_hookspath_inside_repo(self):
        self._git("config", "core.hooksPath", ".githooks")
        action, payload = _effective_hook_target(self.d, self.d)
        self.assertEqual(action, "write")
        self.assertEqual(payload, os.path.join(self.d, ".githooks", "pre-push"))

    def test_core_hookspath_outside_repo_skips(self):
        outside = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(outside, ignore_errors=True))
        self._git("config", "core.hooksPath", outside)
        action, _payload = _effective_hook_target(self.d, self.d)
        self.assertEqual(action, "skip")


class TestInstall(_GitRepo):
    def test_install_all(self):
        rc, _ = _quiet(cmd_install, self.d)
        self.assertEqual(rc, 0)
        eng = os.path.join(self.d, ".ratchet", "ratchet.py")
        self.assertTrue(os.path.exists(eng))
        subprocess.run([sys.executable, "-m", "py_compile", eng], check=True)
        self.assertTrue(os.path.exists(os.path.join(self.d, "ratchet.toml")))
        pp = self._read(".git/hooks/pre-push")
        self.assertIn(RATCHET_BEGIN, pp)
        self.assertIn("[ -f .ratchet/ratchet.py ]", pp)  # inert guard
        if os.name != "nt":  # Windows has no POSIX exec bit
            self.assertTrue(os.stat(self._prepush()).st_mode & 0o111)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".github", "workflows", "ratchet.yml")))
        self.assertIn(".ratchet/.state", self._read(".gitignore"))

    def test_idempotent(self):
        _quiet(cmd_install, self.d)
        pp1 = self._read(".git/hooks/pre-push")
        gi1 = self._read(".gitignore")
        _quiet(cmd_install, self.d)
        self.assertEqual(self._read(".git/hooks/pre-push"), pp1)
        self.assertEqual(self._read(".gitignore"), gi1)

    def test_appends_to_existing_prepush(self):
        self._w(".git/hooks/pre-push", "#!/bin/sh\necho custom\n")
        _quiet(cmd_install, self.d)
        pp = self._read(".git/hooks/pre-push")
        self.assertIn("echo custom", pp)
        self.assertLess(pp.index("echo custom"), pp.index(RATCHET_BEGIN))  # runs first

    def test_replaces_stale_block_in_place(self):
        stale = "#!/bin/sh\necho keep\n" + RATCHET_BEGIN + "\nOLD GARBAGE\n# <<< ratchet <<<\n"
        self._w(".git/hooks/pre-push", stale)
        _quiet(cmd_install, self.d)
        pp = self._read(".git/hooks/pre-push")
        self.assertIn("echo keep", pp)
        self.assertNotIn("OLD GARBAGE", pp)
        self.assertEqual(pp.count(RATCHET_BEGIN), 1)

    def test_non_clobber_existing_config_and_ci(self):
        self._w("ratchet.toml", "schema = 1\n# mine\n")
        self._w(".github/workflows/ratchet.yml", "# mine\n")
        _quiet(cmd_install, self.d)
        self.assertIn("# mine", self._read("ratchet.toml"))
        self.assertIn("# mine", self._read(".github/workflows/ratchet.yml"))

    def test_flag_scope_no_hook_no_ci(self):
        rc, _ = _quiet(cmd_install, self.d, hook=False, ci=False)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".ratchet", "ratchet.py")))
        self.assertFalse(os.path.exists(self._prepush()))
        self.assertFalse(os.path.exists(os.path.join(self.d, ".github", "workflows", "ratchet.yml")))

    def test_lefthook_writes_no_prepush(self):
        self._w("lefthook.yml", "pre-commit:\n")
        _quiet(cmd_install, self.d)
        self.assertFalse(os.path.exists(self._prepush()))

    def test_self_vendor_short_circuits(self):
        """Running install FROM the already-vendored copy must not truncate it."""
        _quiet(cmd_install, self.d)
        vendored = os.path.join(self.d, ".ratchet", "ratchet.py")
        size_before = os.path.getsize(vendored)
        r = subprocess.run([sys.executable, vendored, "install", "--cwd", self.d, "--no-config", "--no-hook", "--no-ci"],
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.path.getsize(vendored), size_before)  # not truncated

    def test_not_a_git_repo_returns_1(self):
        nong = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(nong, ignore_errors=True))
        rc, _ = _quiet(cmd_install, nong)
        self.assertEqual(rc, 1)


class TestUninstall(_GitRepo):
    def test_strips_only_block_keeps_rest(self):
        self._w(".git/hooks/pre-push", "#!/bin/sh\necho custom\n")
        _quiet(cmd_install, self.d)
        rc, _ = _quiet(cmd_uninstall, self.d)
        self.assertEqual(rc, 0)
        pp = self._read(".git/hooks/pre-push")
        self.assertNotIn(RATCHET_BEGIN, pp)
        self.assertIn("echo custom", pp)

    def test_deletes_only_authored_file(self):
        _quiet(cmd_install, self.d)  # ratchet authored the whole pre-push
        _quiet(cmd_uninstall, self.d)
        self.assertFalse(os.path.exists(self._prepush()))

    def test_never_removes_committed_source(self):
        _quiet(cmd_install, self.d)
        _quiet(cmd_uninstall, self.d)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".ratchet", "ratchet.py")))
        self.assertTrue(os.path.exists(os.path.join(self.d, "ratchet.toml")))
        self.assertTrue(os.path.exists(os.path.join(self.d, ".github", "workflows", "ratchet.yml")))


class TestDoctor(_GitRepo):
    def test_clean_repo_exits_0(self):
        _quiet(cmd_install, self.d)
        rc, out = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 0, out)
        self.assertIn("change layer ready", out)

    def test_missing_engine_exits_1(self):
        self._w("ratchet.toml", "schema = 1\n[repo]\ndefault_branch=\"main\"\ncode=[\"src/**\"]\n")
        rc, _ = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 1)

    def test_invalid_config_exits_1(self):
        _quiet(cmd_install, self.d)
        # a block without kind=fact violates the moat → Config.parse raises
        self._w("ratchet.toml", 'schema = 1\n[repo]\ndefault_branch="main"\ncode=["src/**"]\n'
                                '[[check]]\nid="x"\nkind="judge"\nseverity="block"\nprimitive="secret_scan"\n')
        rc, _ = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 1)

    def test_missing_hook_is_advisory(self):
        _quiet(cmd_install, self.d, hook=False)
        rc, out = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 0, out)  # missing pre-push is ~ , not ✗

    def test_json_shape(self):
        _quiet(cmd_install, self.d)
        rc, out = _quiet(cmd_doctor, self.d, as_json=True)
        import json as _json
        data = _json.loads(out)
        self.assertTrue(all({"status", "label", "fix"} <= set(r) for r in data))


if __name__ == "__main__":
    unittest.main()
