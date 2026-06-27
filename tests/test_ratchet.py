"""Stdlib-only test suite for ratchet (no pytest dependency — `python3 -m unittest`)."""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ratchet  # noqa: E402
from ratchet import (  # noqa: E402
    Check,
    CommandFacts,
    Config,
    ConfigError,
    DiffFacts,
    RepoCfg,
    commit_footer,
    cooccur,
    forbid_command,
    forbid_delete,
    forbid_in_message,
    forbid_pattern,
    forbid_removal,
    has_block,
    marker_present,
    numeric_floor,
    path_requires,
    protected_path,
    run_branch_gate,
    run_change,
    run_command_gate,
    scope_lock,
    secret_scan,
    attestation_gaps,
    change_classes,
    push_or_merge,
    _git_ops,
    _glob_to_re,
    _ticked,
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


if __name__ == "__main__":
    unittest.main()
