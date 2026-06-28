"""Stdlib-only test suite for cogpin (no pytest dependency — `python3 -m unittest`)."""

import contextlib
import dataclasses
import inspect
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cogpin as R  # noqa: E402
from cogpin import (  # noqa: E402
    COGPIN_BEGIN,
    HOUSE_RULE_MAP,
    PREPUSH_BLOCK,
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
    _config_advisories,
    _detect_hook_manager,
    _effective_hook_target,
    _ensure_gitignore,
    _git_ops,
    _glob_to_re,
    _install_prepush,
    _marked_ids,
    _protects_gate_files,
    _replace_or_append_block,
    _strip_block,
    _ticked,
    approval_policy,
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
        # DiffFacts shapes used throughout: added/removed = (path, line); changed = (status, path) with status A/M/D
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
            'pattern="println!"\nscope="code"\nexempt="cogpin:allow"\nstrip_comments=false'
        )
        r = repo()
        hit = DiffFacts(added=[("src/x.rs", '    println!("debug");')])
        self.assertIsNotNone(forbid_pattern(c, hit, r))
        ex = DiffFacts(added=[("src/x.rs", '    println!("ok"); // cogpin:allow')])
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
        c = one_check(  # warn: marker_present is agent-provenance, cannot block (the #22 moat)
            '[[check]]\nid="m"\nkind="fact"\nseverity="warn"\nprimitive="marker_present"\n'
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
        # commit_footer is meta-driven (the footer is [meta].commit_footer, not a check
        # field), so it takes (check, footer_rx, facts) — check is only for the id-prefix.
        cf = one_check('[[check]]\nid="cf"\nkind="fact"\nseverity="warn"\nprimitive="commit_footer"')
        pat = r"Co-Authored-By: Claude"
        ok = DiffFacts(commit_msgs=["feat: x\n\nCo-Authored-By: Claude Opus"])
        bad = DiffFacts(commit_msgs=["feat: y"])
        self.assertIsNone(commit_footer(cf, pat, ok))
        self.assertIsNotNone(commit_footer(cf, pat, bad))

    def test_protected_path_skips_without_pr_context(self):
        c = one_check(
            '[[check]]\nid="pp"\nkind="fact"\nseverity="block"\nprimitive="protected_path"\n'
            'paths=["cogpin.toml","justfile"]'
        )
        # no PR context (approvals None) → skip, defer to CI
        local = DiffFacts(changed=[("M", "cogpin.toml")])
        self.assertIsNone(protected_path(c, local))
        # PR context, gate file changed, zero approvals → block
        unapproved = DiffFacts(changed=[("M", "cogpin.toml")], approvals=[])
        self.assertIsNotNone(protected_path(c, unapproved))
        # PR context, gate file changed, an approval present → pass
        approved = DiffFacts(changed=[("M", "cogpin.toml")], approvals=["reviewer-bob"])
        self.assertIsNone(protected_path(c, approved))
        # PR context, no gate file touched → pass
        unrelated = DiffFacts(changed=[("M", "src/a.rs")], approvals=[])
        self.assertIsNone(protected_path(c, unrelated))

    def test_protected_path_requires_fresh_human_nonauthor_approval(self):
        # The keystone: with the reviews fact present, a stale / bot / self approval must
        # NOT satisfy gate-file protection (the approve-benign-then-push-malicious bypass).
        c = one_check(
            '[[check]]\nid="pp"\nkind="fact"\nseverity="block"\nprimitive="protected_path"\n'
            'paths=["cogpin.toml"]'
        )
        touched = [("M", "cogpin.toml")]
        fresh = DiffFacts(changed=touched, head_sha="HEAD2", pr_author="alice",
                          reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "HEAD2"}])
        self.assertIsNone(protected_path(c, fresh))  # fresh human non-author → pass
        stale = DiffFacts(changed=touched, head_sha="HEAD2", pr_author="alice",
                          reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "HEAD1"}])
        self.assertIsNotNone(protected_path(c, stale))  # approval on an earlier commit → block
        bot = DiffFacts(changed=touched, head_sha="HEAD2", pr_author="alice",
                        reviews=[{"login": "rubber[bot]", "state": "APPROVED", "commit_id": "HEAD2", "is_bot": True}])
        self.assertIsNotNone(protected_path(c, bot))  # bot rubber-stamp → block
        selfapp = DiffFacts(changed=touched, head_sha="HEAD2", pr_author="alice",
                            reviews=[{"login": "alice", "state": "APPROVED", "commit_id": "HEAD2"}])
        self.assertIsNotNone(protected_path(c, selfapp))  # author self-approval → block
        none_yet = DiffFacts(changed=touched, head_sha="HEAD2", pr_author="alice", reviews=[])
        self.assertIsNotNone(protected_path(c, none_yet))  # reviews present but empty → block

    def test_forbid_removal_guards_deleted_guard_lines(self):
        # the '-' twin of forbid_pattern: a REMOVED line matching the guard pattern
        # under scope blocks — the "silently delete the assert/await/?" class.
        c = one_check(
            '[[check]]\nid="keep-guards"\nkind="fact"\nseverity="block"\nprimitive="forbid_removal"\n'
            'pattern="assert|# nosec"\nscope="code"\nexempt="cogpin:allow"'
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
        ex = DiffFacts(removed=[("src/a.py", "    assert x  # cogpin:allow")])
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
    """The remaining ranked + mined gaps that complete the coverage map. Primitives:
    change_budget, file_must_contain, max_added_file_bytes, require_message_pattern,
    self_protect, and the PR-review-API family — protected_path, require_approval_from,
    pattern_requires_approval, approval_policy, require_checks_green
    (reviews/head_sha/pr_author/checks facts)."""

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
            'paths=["cogpin.toml", ".cogpin/**", ".claude/settings.json"]'
        )
        self.assertIsNotNone(self_protect(c, "Edit", "cogpin.toml"))
        self.assertIsNotNone(self_protect(c, "Write", ".cogpin/cogpin.py"))
        self.assertIsNone(self_protect(c, "Edit", "src/app.py"))    # not a protected path
        self.assertIsNone(self_protect(c, "Bash", "cogpin.toml"))  # not a Write/Edit tool

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

    # name kept as test_approval_state_depth — editing this `def test_` line (e.g. renaming to
    # approval_policy) registers as a removal and trips this repo's own keep-tests gate.
    def test_approval_state_depth(self):
        c = one_check(
            '[[check]]\nid="asd"\nkind="fact"\nseverity="block"\nprimitive="approval_policy"\n'
            'require_fresh=true\nno_changes_requested=true\nexclude_author=true\nexclude_bot=true\nmin_approvals=1'
        )
        self.assertIsNone(approval_policy(c, DiffFacts()))  # no PR ctx → skip
        ok = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "abc", "is_bot": False}])
        self.assertIsNone(approval_policy(c, ok))
        stale = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "OLD", "is_bot": False}])
        self.assertIsNotNone(approval_policy(c, stale))  # approval not on head
        sa = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "alice", "state": "APPROVED", "commit_id": "abc", "is_bot": False}])
        self.assertIsNotNone(approval_policy(c, sa))     # self-approval
        cr = DiffFacts(head_sha="abc", pr_author="alice", reviews=[
            {"login": "bob", "state": "APPROVED", "commit_id": "abc", "is_bot": False},
            {"login": "carol", "state": "CHANGES_REQUESTED", "commit_id": "abc", "is_bot": False}])
        self.assertIsNotNone(approval_policy(c, cr))     # outstanding changes-requested
        bot = DiffFacts(head_sha="abc", pr_author="alice", reviews=[{"login": "dependabot", "state": "APPROVED", "commit_id": "abc", "is_bot": True}])
        self.assertIsNotNone(approval_policy(c, bot))    # bot-only approval

    def test_approval_policy_fresh_is_fail_closed_on_missing_commit(self):
        # a review with no recorded commit_id is NOT fresh (fail-closed) — consistent with
        # protected_path. In CI action.yml always supplies commit_id, so this pins the edge.
        c = one_check('[[check]]\nid="ap"\nkind="fact"\nseverity="block"\nprimitive="approval_policy"\n'
                      'require_fresh=true\nmin_approvals=1')
        f = DiffFacts(head_sha="abc", pr_author="alice",
                      reviews=[{"login": "bob", "state": "APPROVED", "commit_id": None, "is_bot": False}])
        self.assertIsNotNone(approval_policy(c, f))  # no commit_id ⇒ not fresh ⇒ blocks

    def test_require_checks_green(self):
        c = one_check('[[check]]\nid="rcg"\nkind="fact"\nseverity="block"\nprimitive="require_checks_green"')
        self.assertIsNone(require_checks_green(c, DiffFacts()))  # no ctx → skip
        self.assertIsNone(require_checks_green(c, DiffFacts(checks=[{"name": "ci", "conclusion": "success"}])))
        self.assertIsNotNone(require_checks_green(c, DiffFacts(checks=[{"name": "ci", "conclusion": "failure"}])))
        self.assertIsNotNone(require_checks_green(c, DiffFacts(checks=[{"name": "ci", "conclusion": None}])))  # pending

    def test_require_checks_green_ignore_excludes_self(self):
        """#5: cogpin's own job is pending while it gates the same run; `ignore` drops it
        from the all-green requirement so the gate doesn't self-block."""
        pending_self = [{"name": "ci", "conclusion": "success"},
                        {"name": "cogpin", "conclusion": None}]  # its own job, pending
        racy = one_check('[[check]]\nid="rcg"\nkind="fact"\nseverity="block"\nprimitive="require_checks_green"')
        self.assertIsNotNone(require_checks_green(racy, DiffFacts(checks=pending_self)))  # self-blocks
        guarded = one_check('[[check]]\nid="rcg"\nkind="fact"\nseverity="block"\n'
                            'primitive="require_checks_green"\nignore=["cogpin"]')
        self.assertIsNone(require_checks_green(guarded, DiffFacts(checks=pending_self)))  # excluded → green
        # ignore does NOT mask a genuinely failing OTHER check
        pending_self[0] = {"name": "ci", "conclusion": "failure"}
        self.assertIsNotNone(require_checks_green(guarded, DiffFacts(checks=pending_self)))

    def test_require_checks_green_advisory(self):
        """#5: validate surfaces the racy unconstrained shape (neither need nor ignore) but
        does not flag a guarded one."""
        racy = Config.parse('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="rcg"\n'
                            'kind="fact"\nseverity="block"\nprimitive="require_checks_green"')
        self.assertTrue(any("require_checks_green" in n for n in _config_advisories(racy)))
        guarded = Config.parse('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="rcg"\n'
                               'kind="fact"\nseverity="block"\nprimitive="require_checks_green"\nignore=["cogpin"]')
        self.assertEqual(_config_advisories(guarded), [])


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


class TestGuessScopes(unittest.TestCase):
    """#19 top-K polyglot detection: guess_scopes (per-language) + the guess_globs flat union."""

    def test_single_language_byte_identical(self):
        # the flat union over a one-language repo MUST equal the old single-dominant output
        py = ["src/app.py", "src/util.py", "tests/test_app.py", "docs/x.md"]
        self.assertEqual(guess_globs(py), (["src/**/*.py"], ["tests/**/*.py", "**/test_*.py"],
                                           ["**/*.md", "docs/**"]))
        langs = R.guess_scopes(py)
        self.assertEqual([ls.name for ls in langs], ["python"])

    def test_stray_secondary_excluded_absolute_floor(self):
        # 3 stray .py in a 50-file Rust repo: python is below the absolute floor → excluded
        paths = [f"crates/x/src/f{i}.rs" for i in range(50)] + ["a.py", "b.py", "c.py"]
        names = [ls.name for ls in R.guess_scopes(paths)]
        self.assertEqual(names, ["rust"])
        self.assertFalse(any(".py" in g for g in guess_globs(paths)[0]))

    def test_real_secondary_included_size_independent(self):
        # 200 .ts in a 5000-file Rust repo (~3.8%) MUST be included — a fraction gate would drop it
        paths = [f"crates/x/src/f{i}.rs" for i in range(5000)] + [f"site/src/c{i}.ts" for i in range(200)]
        names = [ls.name for ls in R.guess_scopes(paths)]
        self.assertEqual(names, ["rust", "node"])               # dominant-first
        code = guess_globs(paths)[0]
        self.assertTrue(any(".rs" in g for g in code) and any(".ts" in g for g in code))

    def test_secondary_floor_constant(self):
        # exactly _SECONDARY_MIN_FILES of a secondary clears the floor; one fewer does not
        base = [f"a{i}.py" for i in range(50)]
        at = base + [f"x{i}.rs" for i in range(R._SECONDARY_MIN_FILES)]
        below = base + [f"x{i}.rs" for i in range(R._SECONDARY_MIN_FILES - 1)]
        self.assertIn("rust", [ls.name for ls in R.guess_scopes(at)])
        self.assertNotIn("rust", [ls.name for ls in R.guess_scopes(below)])

    def test_flat_layout_secondary_contributes_fallback(self):
        # a secondary whose structured globs all miss must still emit its **/*{ext} fallback into
        # the merged code — else it is "included" yet covers nothing (silent under-coverage)
        paths = [f"a{i}.py" for i in range(40)] + [f"x{i}.rs" for i in range(15)]  # .rs at root, no crates/src
        rust = next(ls for ls in R.guess_scopes(paths) if ls.name == "rust")
        self.assertEqual(rust.code, ["**/*.rs"])
        self.assertIn("**/*.rs", guess_globs(paths)[0])

    def test_union_dedups_shared_glob(self):
        # python + node both contribute tests/** — it must appear once in the merged tests
        paths = [f"a{i}.py" for i in range(15)] + [f"b{i}.ts" for i in range(15)] + ["tests/t.py", "tests/t.ts"]
        tests = guess_globs(paths)[1]
        self.assertEqual(tests.count("tests/**"), 1)

    def test_no_language_cap_every_floor_clearer_covered(self):
        # NO max-lang cap: every floor-clearing language is in the breakdown AND the flat union
        # (a cap would leave the lowest-ranked langs' files matched by no glob — under-coverage)
        n = R._SECONDARY_MIN_FILES + 5
        paths = ([f"a{i}.py" for i in range(n)] + [f"b{i}.rs" for i in range(n)]
                 + [f"c{i}.go" for i in range(n)] + [f"d{i}.rb" for i in range(n)]
                 + [f"e{i}.java" for i in range(n)])
        self.assertEqual(len(R.guess_scopes(paths)), 5)
        code = guess_globs(paths)[0]
        for ext in (".py", ".rs", ".go", ".rb", ".java"):   # no language left uncovered
            self.assertTrue(any(ext in g for g in code), ext)

    def test_multi_ext_fallback_covers_present_exts(self):
        # node is multi-ext (.ts/.tsx/.js/.jsx); a flat .tsx-only / lib-.js subtree whose curated
        # globs all miss must fall back to a glob that MATCHES its files, not a dead **/*.ts
        tsx = [f"a{i}.py" for i in range(40)] + [f"comp{i}.tsx" for i in range(15)]   # root .tsx, no src/
        node = next(ls for ls in R.guess_scopes(tsx) if ls.name == "node")
        self.assertTrue(any(R._glob_to_re(g).match("comp0.tsx") for g in node.code))
        self.assertNotIn("**/*.ts", node.code)   # the old dead fallback must be gone
        libjs = [f"a{i}.py" for i in range(40)] + [f"lib/m{i}.js" for i in range(15)]
        node2 = next(ls for ls in R.guess_scopes(libjs) if ls.name == "node")
        self.assertTrue(any(R._glob_to_re(g).match("lib/m0.js") for g in node2.code))

    def test_secondary_floor_clamp_on_tiny_repo(self):
        # the min(_SECONDARY_MIN_FILES, dominant) clamp: a near-parity secondary enters on a tiny
        # repo (5 rs + 5 py → both), but one below parity does not (5 rs + 4 py → rust only)
        self.assertEqual(sorted(ls.name for ls in R.guess_scopes(
            [f"r{i}.rs" for i in range(5)] + [f"p{i}.py" for i in range(5)])), ["python", "rust"])
        self.assertEqual([ls.name for ls in R.guess_scopes(
            [f"r{i}.rs" for i in range(5)] + [f"p{i}.py" for i in range(4)])], ["rust"])

    def test_empty_and_no_code_safe(self):
        self.assertEqual(R.guess_scopes([]), [])
        self.assertEqual(R.guess_scopes(["README.md", "LICENSE"]), [])   # no code lang
        self.assertEqual(guess_globs(["README.md"]), ([], [], ["**/*.md"]))

    def test_scan_dict_exposes_languages(self):
        # the host-agent JSON contract gains `languages` without disturbing existing keys
        scan = R.RepoScan(default_branch="main", code=["**/*.py"], tests=[], docs=["**/*.md"],
                          test_cmd=None, test_cmd_source=None, claude_md_paths=[], house_rules=[],
                          languages=[R.LangScope("python", 3, ["**/*.py"], [])])
        d = R._scan_to_dict(scan)
        self.assertEqual(d["languages"], [{"name": "python", "file_count": 3,
                                           "code": ["**/*.py"], "tests": []}])
        self.assertIn("code", d)   # existing keys intact

    def test_render_toml_detected_comment_only_when_polyglot(self):
        multi = R.RepoScan(default_branch="main", code=["**/*.py", "**/*.rs"], tests=[], docs=["**/*.md"],
                           test_cmd=None, test_cmd_source=None, claude_md_paths=[], house_rules=[],
                           languages=[R.LangScope("python", 40, ["**/*.py"], []),
                                      R.LangScope("rust", 15, ["**/*.rs"], [])])
        out = R.render_suggest_toml(multi)
        self.assertIn("# detected: python(40), rust(15)", out)
        self.assertIn('schema = 1', out)   # still parses as a draft
        # single-language scan emits no detected comment (would be noise)
        solo = dataclasses.replace(multi, code=["**/*.py"],
                                   languages=[R.LangScope("python", 40, ["**/*.py"], [])])
        self.assertNotIn("# detected:", R.render_suggest_toml(solo))


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


def _reposcan(rules_text="", branch="main", cmd="just test"):
    from cogpin import scan_house_rules
    return RepoScan(
        default_branch=branch, code=["src/**/*.py"], tests=["tests/**/*.py"], docs=["**/*.md"],
        test_cmd=cmd, test_cmd_source="justfile", claude_md_paths=["CLAUDE.md"],
        house_rules=scan_house_rules(rules_text, source="CLAUDE.md", default_branch=branch, test_cmd=cmd),
    )


class TestSuggestRender(unittest.TestCase):
    """render_suggest_toml — an all-warn (+commented/judge) starter that always parses."""

    def test_render_validates(self):
        Config.parse(render_suggest_toml(_reposcan("Run the tests. Two-lens review. Don't loosen an assertion.")))

    def test_render_is_all_warn_except_safe_core(self):
        cfg = Config.parse(render_suggest_toml(_reposcan("Use conventional commits. Keep docs current.")))
        by_id = {c.id: c for c in cfg.checks}
        blocks = {c.id for c in cfg.checks if c.severity == "block"}
        # protected-gate-files is born warn (solo repos have no independent approver); the
        # other four safe-core ids are solo-satisfiable facts → born block.
        self.assertEqual(blocks, set(SAFE_CORE_IDS) - {"protected-gate-files"})
        self.assertEqual(by_id["protected-gate-files"].severity, "warn")
        self.assertEqual(by_id["protected-gate-files"].primitive, "protected_path")

    def test_render_has_draft_banner_and_todos(self):
        toml = render_suggest_toml(_reposcan("Use conventional commits."))
        self.assertIn("cogpin.toml.draft", toml)
        self.assertIn("# TODO(cogpin:review)", toml)

    def test_render_commented_blocks_for_run_and_approval(self):
        toml = render_suggest_toml(_reposcan("Run the tests. Owner approval from CODEOWNERS. Stay in scope."))
        # run / require_approval_from / scope_lock render commented-out
        self.assertIn("# [[check]]", toml)
        self.assertNotIn('\nid = "tests-pass"', toml)  # only its commented form

    def test_render_includes_repo_and_base_pinned(self):
        toml = render_suggest_toml(_reposcan())
        self.assertIn("base_pinned = true", toml)
        self.assertIn('default_branch =', toml)


class TestDraftLint(unittest.TestCase):
    """draft_lint — the moat-safety net beyond validate."""

    def _base(self, rules=""):
        # a render with no markers cleared: strip markers to get a clean armed-or-advisory draft
        return render_suggest_toml(_reposcan(rules))

    def _clean(self):
        # safe-core only, no house-rules → zero markers → clean
        return render_suggest_toml(_reposcan(""))

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

    def test_marker_skips_blanks_not_comments(self):
        """#6: only blank lines may sit between a marker and its [[check]]. A marker above a
        commented-out check must NOT bind to a LATER live check (which would mis-flag it)."""
        bound = '# TODO(cogpin:review)\n\n[[check]]\nid = "near"\nkind="fact"\nseverity="warn"\nprimitive="secret_scan"\n'
        self.assertEqual(_marked_ids(bound), {"near"})  # blank line still skipped
        spaced = (
            '# TODO(cogpin:review)\n'
            '# [[check]]\n'
            '# id = "commented"\n'
            '[[check]]\n'
            'id = "live"\n'
            'kind="fact"\nseverity="block"\nprimitive="secret_scan"\n'
        )
        self.assertEqual(_marked_ids(spaced), set())  # comment ends the association

    def test_base_pinned_false_rejected(self):
        bad = self._clean().replace("base_pinned = true", "base_pinned = false")
        self.assertIn("error", self._levels(bad))

    def test_missing_safe_core_rejected(self):
        minimal = 'schema = 1\n[repo]\ndefault_branch = "main"\n[meta]\nbase_pinned = true\n'
        self.assertIn("error", self._levels(minimal))

    def test_protected_gate_files_may_be_warn_or_block(self):
        # the chosen solo policy: protected-gate-files born warn lints clean; promoting it to
        # block also lints clean (a team with a reviewer); the other four must stay block.
        warn_draft = self._clean()
        self.assertNotIn("error", self._levels(warn_draft))
        block_draft = warn_draft.replace(
            'id = \'protected-gate-files\'\nkind = \'fact\'\nseverity = \'warn\'',
            'id = \'protected-gate-files\'\nkind = \'fact\'\nseverity = \'block\'')
        self.assertNotIn("error", self._levels(block_draft))
        # demoting a different safe-core id (secret-scan) to warn is still rejected
        weakened = warn_draft.replace(
            'id = \'secret-scan\'\nkind = \'fact\'\nseverity = \'block\'',
            'id = \'secret-scan\'\nkind = \'fact\'\nseverity = \'warn\'')
        self.assertIn("error", self._levels(weakened))

    def test_inferred_block_with_marker_rejected(self):
        bad = self._clean() + '\n# TODO(cogpin:review): from CLAUDE.md\n[[check]]\nid = "x"\nkind = "fact"\nseverity = "block"\nprimitive = "forbid_pattern"\npattern = "foo"\nscope = "src/**/*.py"\n'
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

    # the blockable (fact) primitives = all minus the advisory-by-nature ones. DERIVED so it
    # cannot drift from PRIMITIVES; the literal regression-pin lives in TestNoDrift.
    _FACT_PRIMS = R.PRIMITIVES - R._ADVISORY_ONLY

    def test_suggest_introduces_no_nonfact_block(self):
        cfg = Config.parse(render_suggest_toml(_reposcan(
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


_COGPIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cogpin.py")


class TestSuggestGapsCLI(unittest.TestCase):
    """End-to-end via subprocess in a temp git repo (mirrors TestDiffParsing's harness)."""

    def _git(self, *args):
        subprocess.run(["git", "-C", self.d, *args], check=True, capture_output=True, text=True)

    def _cogpin(self, *args):
        return subprocess.run([sys.executable, _COGPIN, *args, "--cwd", self.d],
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
        r = self._cogpin("suggest", "--format", "json")
        self.assertEqual(r.returncode, 0, r.stderr)
        import json as _json
        data = _json.loads(r.stdout)
        ids = {h["suggested_id"] for h in data["house_rules"]}
        self.assertIn("branch-first", ids)
        self.assertIn("tests-pass", ids)
        self.assertIn("docs-currency", ids)
        self.assertTrue(any(_glob_to_re(g).match("src/app.py") for g in data["code"]))

    def test_cli_suggest_toml_validates(self):
        r = self._cogpin("suggest", "--format", "toml")
        self.assertEqual(r.returncode, 0, r.stderr)
        draft = os.path.join(self.d, "cogpin.toml.draft")
        with open(draft, "w", encoding="utf-8") as fh:
            fh.write(r.stdout)
        v = subprocess.run([sys.executable, _COGPIN, "validate", "--config", draft],
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_cli_draft_lint_fails_on_markers(self):
        r = self._cogpin("suggest", "--format", "toml")
        with open(os.path.join(self.d, "cogpin.toml.draft"), "w", encoding="utf-8") as fh:
            fh.write(r.stdout)
        dl = self._cogpin("draft-lint")
        self.assertEqual(dl.returncode, 1)  # markers remain
        self.assertIn("TODO", dl.stdout)

    def test_cli_draft_lint_clean_after_markers_removed(self):
        r = self._cogpin("suggest", "--format", "toml")
        cleaned = "\n".join(ln for ln in r.stdout.splitlines()
                            if not ln.lstrip().startswith("# TODO(cogpin:review)"))
        with open(os.path.join(self.d, "cogpin.toml.draft"), "w", encoding="utf-8") as fh:
            fh.write(cleaned)
        dl = self._cogpin("draft-lint")
        self.assertEqual(dl.returncode, 0, dl.stdout + dl.stderr)

    def test_cli_gaps_roundtrip(self):
        r = self._cogpin("suggest", "--format", "toml")
        cleaned = "\n".join(ln for ln in r.stdout.splitlines()
                            if not ln.lstrip().startswith("# TODO(cogpin:review)"))
        with open(os.path.join(self.d, "cogpin.toml"), "w", encoding="utf-8") as fh:
            fh.write(cleaned)
        g = self._cogpin("gaps")
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
        self.assertIn(COGPIN_BEGIN, out)

    def test_replace_in_place_no_double_append(self):
        once = _replace_or_append_block("#!/bin/sh\n", PREPUSH_BLOCK)
        twice = _replace_or_append_block(once, PREPUSH_BLOCK)
        self.assertEqual(once, twice)  # byte-idempotent
        self.assertEqual(once.count(COGPIN_BEGIN), 1)

    def test_append_adds_separator_when_no_trailing_newline(self):
        out = _replace_or_append_block("echo hi", PREPUSH_BLOCK)
        self.assertIn("echo hi\n" + COGPIN_BEGIN, out)

    def test_replace_preserves_surrounding(self):
        cur = _replace_or_append_block("#!/bin/sh\nA\n", PREPUSH_BLOCK) + "Z\n"
        out = _replace_or_append_block(cur, PREPUSH_BLOCK)
        self.assertIn("#!/bin/sh\nA\n", out)
        self.assertTrue(out.rstrip().endswith("Z"))
        self.assertEqual(out.count(COGPIN_BEGIN), 1)

    def test_strip_removes_exactly_the_span(self):
        cur = "#!/bin/sh\nA\n" + PREPUSH_BLOCK + "Z\n"
        out = _strip_block(cur)
        self.assertNotIn(COGPIN_BEGIN, out)
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

    def test_confine_refuses_escaping_symlink(self):
        # a committed gate file shipped as a symlink escaping the repo must NOT be written
        # through (it would clobber an arbitrary path on a victim's `install`).
        outside = os.path.join(self.d, "outside.txt")
        with open(outside, "w") as fh:
            fh.write("victim\n")
        repo = os.path.join(self.d, "repo")
        os.makedirs(repo)
        link = os.path.join(repo, "engine.py")
        os.symlink(outside, link)  # escapes `repo`
        with self.assertRaises(OSError):
            _atomic_write(link, "payload\n", confine=repo)
        with open(outside) as fh:
            self.assertEqual(fh.read(), "victim\n")  # untouched
        # an in-repo target is fine
        _atomic_write(os.path.join(repo, "ok.py"), "x\n", confine=repo)


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
        self.assertIn(".cogpin/.state", gi)
        self.assertNotIn(".cogpin/\n", gi)  # never the whole dir
        self.assertEqual(gi.count(".cogpin/.state"), 1)  # no dup

    def test_preserves_existing(self):
        self._w(".gitignore", "node_modules\n")
        _ensure_gitignore(self.d)
        gi = self._read(".gitignore")
        self.assertIn("node_modules", gi)
        self.assertIn(".cogpin/.state", gi)


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
        eng = os.path.join(self.d, ".cogpin", "cogpin.py")
        self.assertTrue(os.path.exists(eng))
        subprocess.run([sys.executable, "-m", "py_compile", eng], check=True)
        self.assertTrue(os.path.exists(os.path.join(self.d, "cogpin.toml")))
        pp = self._read(".git/hooks/pre-push")
        self.assertIn(COGPIN_BEGIN, pp)
        self.assertIn("[ -f .cogpin/cogpin.py ]", pp)  # inert guard
        if os.name != "nt":  # Windows has no POSIX exec bit
            self.assertTrue(os.stat(self._prepush()).st_mode & 0o111)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".github", "workflows", "cogpin.yml")))
        self.assertIn(".cogpin/.state", self._read(".gitignore"))

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
        self.assertLess(pp.index("echo custom"), pp.index(COGPIN_BEGIN))  # runs first

    def test_replaces_stale_block_in_place(self):
        stale = "#!/bin/sh\necho keep\n" + COGPIN_BEGIN + "\nOLD GARBAGE\n# <<< cogpin <<<\n"
        self._w(".git/hooks/pre-push", stale)
        _quiet(cmd_install, self.d)
        pp = self._read(".git/hooks/pre-push")
        self.assertIn("echo keep", pp)
        self.assertNotIn("OLD GARBAGE", pp)
        self.assertEqual(pp.count(COGPIN_BEGIN), 1)

    def test_non_clobber_existing_config_and_ci(self):
        self._w("cogpin.toml", "schema = 1\n# mine\n")
        self._w(".github/workflows/cogpin.yml", "# mine\n")
        _quiet(cmd_install, self.d)
        self.assertIn("# mine", self._read("cogpin.toml"))
        self.assertIn("# mine", self._read(".github/workflows/cogpin.yml"))

    def test_flag_scope_no_hook_no_ci(self):
        rc, _ = _quiet(cmd_install, self.d, hook=False, ci=False)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".cogpin", "cogpin.py")))
        self.assertFalse(os.path.exists(self._prepush()))
        self.assertFalse(os.path.exists(os.path.join(self.d, ".github", "workflows", "cogpin.yml")))

    def test_lefthook_writes_no_prepush(self):
        self._w("lefthook.yml", "pre-commit:\n")
        _quiet(cmd_install, self.d)
        self.assertFalse(os.path.exists(self._prepush()))

    @unittest.skipIf(os.name == "nt", "Windows has no POSIX exec bit (git-for-windows sh runs the hook regardless)")
    def test_prepush_append_preserves_existing_perms(self):
        """#6: appending the managed block keeps the existing hook's perms (only ensures +x),
        never widening an existing husky/.githooks file to 0o755."""
        pp = self._prepush()
        os.makedirs(os.path.dirname(pp), exist_ok=True)
        with open(pp, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\necho custom\n")
        os.chmod(pp, 0o640)  # rw-r----- : non-exec, narrower than 0o755
        _install_prepush(pp)
        self.assertEqual(os.stat(pp).st_mode & 0o777, 0o751)  # preserved 0o640 + ensured +x
        self.assertIn(COGPIN_BEGIN, self._read(".git/hooks/pre-push"))

    @unittest.skipIf(os.name == "nt", "Windows has no POSIX exec bit (git-for-windows sh runs the hook regardless)")
    def test_prepush_new_hook_is_executable(self):
        """A hook cogpin authors from scratch is 0o755."""
        pp = self._prepush()
        os.makedirs(os.path.dirname(pp), exist_ok=True)
        _install_prepush(pp)
        self.assertEqual(os.stat(pp).st_mode & 0o777, 0o755)

    def test_self_vendor_short_circuits(self):
        """Running install FROM the already-vendored copy must not truncate it."""
        _quiet(cmd_install, self.d)
        vendored = os.path.join(self.d, ".cogpin", "cogpin.py")
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

    def test_install_substitutes_default_branch(self):
        self._git("checkout", "-q", "-b", "trunk")  # non-main default
        _quiet(cmd_install, self.d)
        self.assertIn('default_branch = "trunk"', self._read("cogpin.toml"))
        self.assertIn('branch = ["trunk"]', self._read("cogpin.toml"))
        self.assertIn("branches: [trunk]", self._read(".github/workflows/cogpin.yml"))


class TestUninstall(_GitRepo):
    def test_strips_only_block_keeps_rest(self):
        self._w(".git/hooks/pre-push", "#!/bin/sh\necho custom\n")
        _quiet(cmd_install, self.d)
        rc, _ = _quiet(cmd_uninstall, self.d)
        self.assertEqual(rc, 0)
        pp = self._read(".git/hooks/pre-push")
        self.assertNotIn(COGPIN_BEGIN, pp)
        self.assertIn("echo custom", pp)

    def test_deletes_only_authored_file(self):
        _quiet(cmd_install, self.d)  # cogpin authored the whole pre-push
        _quiet(cmd_uninstall, self.d)
        self.assertFalse(os.path.exists(self._prepush()))

    def test_never_removes_committed_source(self):
        _quiet(cmd_install, self.d)
        _quiet(cmd_uninstall, self.d)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".cogpin", "cogpin.py")))
        self.assertTrue(os.path.exists(os.path.join(self.d, "cogpin.toml")))
        self.assertTrue(os.path.exists(os.path.join(self.d, ".github", "workflows", "cogpin.yml")))


class TestDoctor(_GitRepo):
    def test_clean_repo_exits_0(self):
        _quiet(cmd_install, self.d)
        rc, out = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 0, out)
        self.assertIn("change layer ready", out)

    def test_missing_engine_exits_1(self):
        self._w("cogpin.toml", "schema = 1\n[repo]\ndefault_branch=\"main\"\ncode=[\"src/**\"]\n")
        rc, _ = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 1)

    def test_invalid_config_exits_1(self):
        _quiet(cmd_install, self.d)
        # a block without kind=fact violates the moat → Config.parse raises
        self._w("cogpin.toml", 'schema = 1\n[repo]\ndefault_branch="main"\ncode=["src/**"]\n'
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


class TestProtectsGateFiles(unittest.TestCase):
    def _cfg(self, paths):
        plist = ", ".join(f'"{p}"' for p in paths)
        return Config.parse('schema = 1\n[repo]\ndefault_branch="main"\n[[check]]\n'
                            f'id="pp"\nkind="fact"\nseverity="warn"\nprimitive="protected_path"\npaths=[{plist}]\n')

    def test_requires_engine_config_and_ci(self):
        # engine + config but NO workflow coverage → not fully protected (the engine-neuter hole)
        self.assertFalse(_protects_gate_files(self._cfg([".cogpin/**", "cogpin.toml"])))
        # all three covered → protected
        self.assertTrue(_protects_gate_files(self._cfg([".cogpin/**", "cogpin.toml", ".github/workflows/**"])))
        # cogpin's own repo shape (root engine, not vendored) also counts
        self.assertTrue(_protects_gate_files(self._cfg(["cogpin.py", "cogpin.toml", ".github/workflows/**"])))


if __name__ == "__main__":
    unittest.main()


# ─────────────────────────────────────────────────────────────────────────────
# 0.2.1 hardening — tests pinning the whole-codebase-review fixes (block + pass)
# ─────────────────────────────────────────────────────────────────────────────


class TestDiffParserHunkTracking(unittest.TestCase):
    """A removed/added CONTENT line beginning `-- `/`++ ` (an SQL/Lua comment) must NOT be
    misparsed as a `--- a/`/`+++ b/` file header — else it is dropped and poisons path
    attribution for the rest of the file (a scoped forbid_removal/secret_scan false-negative)."""

    def _git(self, *a):
        subprocess.run(["git", "-C", self.d, *a], check=True, capture_output=True, text=True)

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
        with open(os.path.join(self.d, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_dashdash_content_line_not_treated_as_header(self):
        self._w("q.sql", "-- header note\nDROP TABLE secret;\nkept = 1\n")
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        base = subprocess.run(["git", "-C", self.d, "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        self._w("q.sql", "kept = 1\n")  # remove the `-- ` comment line + the DROP line
        self._git("add", "-A")
        self._git("commit", "-qm", "change")
        facts = DiffFacts.from_range(self.d, base, "HEAD")
        removed = list(facts.removed)
        # the `-- header note` line is recorded (not silently dropped as a bogus header)…
        self.assertIn(("q.sql", "-- header note"), removed)
        # …and the genuinely-removed line keeps its REAL path (not a poisoned one)
        self.assertIn(("q.sql", "DROP TABLE secret;"), removed)
        self.assertTrue(all(p == "q.sql" for p, _ in facts.removed))


class TestSelfProtectAbsolutePaths(unittest.TestCase):
    """The live Write/Edit tool passes ABSOLUTE paths; self_protect must still fire for
    multi-segment protected globs (.github/workflows/**, .claude-plugin/**, hooks/hooks.json)."""

    def _check(self):
        return one_check(
            '[[check]]\nid="sp"\nkind="fact"\nseverity="block"\nlayer="agent"\nprimitive="self_protect"\n'
            'paths=["cogpin.toml", "cogpin.py", ".github/workflows/**", ".claude-plugin/**", "hooks/hooks.json"]'
        )

    def test_absolute_multisegment_paths_blocked(self):
        c = self._check()
        for abspath in (
            "/abs/repo/.github/workflows/self-gate.yml",
            "/abs/repo/.claude-plugin/marketplace.json",
            "/abs/repo/hooks/hooks.json",
            "/abs/repo/cogpin.toml",
        ):
            self.assertIsNotNone(self_protect(c, "Write", abspath), abspath)
        # a non-gate absolute path still passes, and backslash (Windows) paths are covered
        self.assertIsNone(self_protect(c, "Write", "/abs/repo/src/app.py"))
        self.assertIsNotNone(self_protect(c, "Edit", "C:\\repo\\.github\\workflows\\ci.yml"))


class TestSubshellEvasion(unittest.TestCase):
    """A glued subshell verb (`(git push)`, `$(git commit)`) must not hide the gated git
    verb from the tokenized op scan (forbid_commit_on_branch / push deny)."""

    BRANCH = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="bf"\nkind="fact"\n'
              'severity="block"\nlayer="agent"\nprimitive="forbid_commit_on_branch"\n'
              'branch=["main"]\nops=["commit","push"]\n')

    def test_glued_subshell_git_verb_is_seen(self):
        self.assertEqual(_git_ops("(git push)"), {"push"})
        self.assertEqual(_git_ops("(git commit -m x)"), {"commit"})
        self.assertIn("commit", _git_ops("$(git commit -m x)"))
        self.assertIn("push", _git_ops("{ git push; }"))
        self.assertEqual(push_or_merge("(git push origin main)"), "push")

    def test_glued_subshell_commit_denied_on_protected_branch(self):
        cfg = Config.parse(self.BRANCH)
        self.assertTrue(has_block(run_branch_gate(cfg, CommandFacts("(git commit -m x)"), "main")))
        self.assertTrue(has_block(run_branch_gate(cfg, CommandFacts("(git push)"), "main")))
        self.assertEqual(run_branch_gate(cfg, CommandFacts("(git status)"), "main"), [])


class TestApprovalHardening(unittest.TestCase):
    """Distinct-login counting, empty-login rejection, freshness edges, exclude_bot."""

    def test_min_approvals_counts_distinct_logins(self):
        c = one_check('[[check]]\nid="ap"\nkind="fact"\nseverity="block"\nprimitive="approval_policy"\n'
                      'min_approvals=2')
        one_person_twice = DiffFacts(reviews=[
            {"login": "bob", "state": "APPROVED"}, {"login": "bob", "state": "APPROVED"}])
        self.assertIsNotNone(approval_policy(c, one_person_twice))  # 1 distinct < 2 → block
        two_people = DiffFacts(reviews=[
            {"login": "bob", "state": "APPROVED"}, {"login": "amy", "state": "APPROVED"}])
        self.assertIsNone(approval_policy(c, two_people))  # 2 distinct → pass

    def test_empty_login_never_qualifies_protected_path(self):
        c = one_check('[[check]]\nid="pp"\nkind="fact"\nseverity="block"\nprimitive="protected_path"\n'
                      'paths=["cogpin.toml"]')
        ghost = DiffFacts(changed=[("M", "cogpin.toml")], head_sha="H", pr_author="alice",
                          reviews=[{"login": "", "state": "APPROVED", "commit_id": "H"}])
        self.assertIsNotNone(protected_path(c, ghost))  # deleted/ghost account (login "") → block

    def test_empty_login_never_qualifies_require_approval_from(self):
        c = one_check('[[check]]\nid="raf"\nkind="fact"\nseverity="block"\nprimitive="require_approval_from"\n'
                      'paths=["core/**"]\nrequire_approval_from=[""]')  # even if "" were configured
        f = DiffFacts(changed=[("M", "core/x.py")], pr_author="zoe",
                      reviews=[{"login": "", "state": "APPROVED"}])
        self.assertIsNotNone(require_approval_from(c, f))

    def test_freshness_is_noop_when_head_sha_unknown(self):
        # Documented degrade: freshness can't be checked without a head SHA, so a stale
        # approval qualifies. Pinned so a regression in head_sha acquisition is a visible change.
        c = one_check('[[check]]\nid="ap"\nkind="fact"\nseverity="block"\nprimitive="approval_policy"\n'
                      'require_fresh=true\nmin_approvals=1')
        no_head = DiffFacts(head_sha=None, pr_author="alice",
                            reviews=[{"login": "bob", "state": "APPROVED", "commit_id": "OLD"}])
        self.assertIsNone(approval_policy(c, no_head))  # head unknown → freshness disabled

    def test_protected_path_blocks_missing_or_empty_commit_id(self):
        c = one_check('[[check]]\nid="pp"\nkind="fact"\nseverity="block"\nprimitive="protected_path"\n'
                      'paths=["cogpin.toml"]')
        touched = [("M", "cogpin.toml")]
        absent = DiffFacts(changed=touched, head_sha="H2", pr_author="alice",
                           reviews=[{"login": "bob", "state": "APPROVED"}])  # no commit_id key
        self.assertIsNotNone(protected_path(c, absent))
        empty = DiffFacts(changed=touched, head_sha="H2", pr_author="alice",
                          reviews=[{"login": "bob", "state": "APPROVED", "commit_id": ""}])
        self.assertIsNotNone(protected_path(c, empty))  # loader's real output shape → block

    def test_exclude_bot_on_identity_gate(self):
        c = one_check('[[check]]\nid="raf"\nkind="fact"\nseverity="block"\nprimitive="require_approval_from"\n'
                      'paths=["core/**"]\nrequire_approval_from=["ci-bot"]\nexclude_bot=true')
        botonly = DiffFacts(changed=[("M", "core/x.py")], pr_author="zoe",
                            reviews=[{"login": "ci-bot", "state": "APPROVED", "is_bot": True}])
        self.assertIsNotNone(require_approval_from(c, botonly))  # exclude_bot drops the bot → block
        human = DiffFacts(changed=[("M", "core/x.py")], pr_author="zoe",
                          reviews=[{"login": "ci-bot", "state": "APPROVED", "is_bot": False}])
        self.assertIsNone(require_approval_from(c, human))


class TestNumericFloorDirectionValidate(unittest.TestCase):
    def test_bad_direction_rejected(self):
        bad = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="nf"\nkind="fact"\n'
               'severity="block"\nprimitive="numeric_floor"\nkey="cov=(\\\\d+)"\ndirection="decrease"\n')
        with self.assertRaises(ConfigError) as e:
            Config.parse(bad)
        self.assertIn("no_decrease", str(e.exception))

    def test_valid_directions_accepted(self):
        for d in ("no_decrease", "no_increase"):
            cfg = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="nf"\nkind="fact"\n'
                   f'severity="block"\nprimitive="numeric_floor"\nkey="cov=(\\\\d+)"\ndirection="{d}"\n')
            self.assertEqual(len(Config.parse(cfg).checks), 1)


class TestRequireChecksGreenNeed(unittest.TestCase):
    def test_need_allowlist_narrows_and_requires_presence(self):
        c = one_check('[[check]]\nid="rcg"\nkind="fact"\nseverity="block"\n'
                      'primitive="require_checks_green"\nneed=["ci"]')
        # a failing OTHER check NOT in `need` is ignored (narrowing works)
        self.assertIsNone(require_checks_green(c, DiffFacts(checks=[
            {"name": "ci", "conclusion": "success"}, {"name": "lint", "conclusion": "failure"}])))
        # the named-required check failing → block
        self.assertIsNotNone(require_checks_green(c, DiffFacts(checks=[
            {"name": "ci", "conclusion": "failure"}])))
        # the named-required check ABSENT (never reported) must NOT pass vacuously
        self.assertIsNotNone(require_checks_green(c, DiffFacts(checks=[
            {"name": "lint", "conclusion": "success"}])))


class TestReviewLoaders(unittest.TestCase):
    """The moat's fact-acquisition normalizers: nested GraphQL ↔ flat shape + degrade-safe."""

    def _tmp(self, name, text):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def test_load_reviews_nested_graphql_shape(self):
        from cogpin import _load_reviews
        p = self._tmp("r.json",
                      '[{"author":{"login":"bob","is_bot":false},"state":"APPROVED",'
                      '"commit":{"oid":"abc"},"authorAssociation":"MEMBER"}]')
        out = _load_reviews(p)
        self.assertEqual(out, [{"login": "bob", "state": "APPROVED", "commit_id": "abc",
                                "is_bot": False, "author_association": "MEMBER"}])

    def test_load_reviews_flat_shape(self):
        from cogpin import _load_reviews
        p = self._tmp("r.json", '[{"login":"amy","state":"APPROVED","commit_id":"def","is_bot":false}]')
        out = _load_reviews(p)
        self.assertEqual(out[0]["login"], "amy")
        self.assertEqual(out[0]["commit_id"], "def")

    def test_load_reviews_degrades_safe(self):
        from cogpin import _load_reviews
        self.assertIsNone(_load_reviews(self._tmp("r.json", "not json")))  # garbled → None (skip)
        self.assertIsNone(_load_reviews(self._tmp("r.json", '{"not":"a list"}')))
        self.assertIsNone(_load_reviews("/nonexistent/path.json"))

    def test_load_checks_conclusion_fallback_and_degrade(self):
        from cogpin import _load_checks
        p = self._tmp("c.json", '[{"name":"ci","state":"SUCCESS"},{"context":"build","status":"FAILURE"}]')
        out = _load_checks(p)
        self.assertEqual(out[0], {"name": "ci", "conclusion": "SUCCESS"})
        self.assertEqual(out[1], {"name": "build", "conclusion": "FAILURE"})  # context/status fallbacks
        self.assertIsNone(_load_checks(self._tmp("c.json", "garbled")))


class TestHookEntrypoints(unittest.TestCase):
    """The PreToolUse/Stop hook wrappers: the load-bearing 'never block on a malformed
    payload' contract + a real deny, exercised end-to-end via the CLI."""

    def _git(self, *a):
        subprocess.run(["git", "-C", self.d, *a], check=True, capture_output=True, text=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        with open(os.path.join(self.d, "cogpin.toml"), "w", encoding="utf-8") as fh:
            fh.write('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="nv"\nkind="fact"\n'
                     'severity="block"\nlayer="agent"\nprimitive="forbid_command"\npattern="--no-verify"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def _gate(self, stdin):
        return subprocess.run([sys.executable, _COGPIN, "gate"], input=stdin,
                              capture_output=True, text=True, cwd=self.d)

    def test_cmd_gate_malformed_payload_never_blocks(self):
        for payload in ("not json", "{}", '{"tool_input": "oops"}', ""):
            r = self._gate(payload)
            self.assertEqual(r.returncode, 0, f"malformed {payload!r} must not block (got {r.returncode})")

    def test_cmd_gate_denies_forbidden_command(self):
        r = self._gate('{"tool_name":"Bash","tool_input":{"command":"git push --no-verify"}}')
        self.assertEqual(r.returncode, 2)  # deny (exit 2, reason on stderr)
        self.assertIn("nv", r.stderr)


class TestBasePinning(unittest.TestCase):
    """Invariant #5: the base ref is read from the PINNED base, its NAME from a trusted flag
    (never the PR-head config), and an authoritative-but-unreachable base fails closed."""

    def _git(self, *a):
        subprocess.run(["git", "-C", self.d, *a], check=True, capture_output=True, text=True)

    def _sha(self, ref="HEAD"):
        return subprocess.run(["git", "-C", self.d, "rev-parse", ref],
                              capture_output=True, text=True).stdout.strip()

    def _w(self, rel, text):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(rel) else None
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._git("config", "commit.gpgsign", "false")

    def tearDown(self):
        self.tmp.cleanup()

    STRICT = ('schema=1\n[repo]\ndefault_branch="main"\n[meta]\nbase_pinned=true\n[[check]]\nid="sek"\n'
              'kind="fact"\nseverity="block"\nprimitive="secret_scan"\nforbid_paths=[".env","**/.env"]\n')
    LOOSE = 'schema=1\n[repo]\ndefault_branch="main"\n[meta]\nbase_pinned=true\n'

    def test_load_config_reads_base_not_working_tree(self):
        from cogpin import load_config
        self._w("cogpin.toml", self.STRICT)
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        base = self._sha()
        self._w("cogpin.toml", self.LOOSE)  # dirty working tree loosens the policy
        self.assertEqual(len(load_config(self.d, base).checks), 1, "must read the STRICT base config")

    def test_load_config_base_pinned_false_defers_to_working_tree(self):
        from cogpin import load_config
        off = self.STRICT.replace("base_pinned=true", "base_pinned=false")
        self._w("cogpin.toml", off)
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        base = self._sha()
        self._w("cogpin.toml", self.LOOSE)  # working tree: 0 checks
        self.assertEqual(len(load_config(self.d, base).checks), 0, "base_pinned=false → working-tree policy")

    def test_load_config_missing_base_toml_falls_back(self):
        from cogpin import load_config
        self._w("README.md", "x")
        self._git("add", "-A")
        self._git("commit", "-qm", "no toml yet")
        base = self._sha()
        self._w("cogpin.toml", self.STRICT)  # only in the working tree
        self.assertEqual(len(load_config(self.d, base).checks), 1, "base lacks cogpin.toml → fallback")

    def test_resolve_base_authoritative_fails_closed(self):
        from cogpin import BaseUnreachable, _resolve_base
        self._w("a.txt", "1")
        self._git("add", "-A")
        self._git("commit", "-qm", "c1")
        self._w("a.txt", "2")
        self._git("add", "-A")
        self._git("commit", "-qm", "c2")
        with self.assertRaises(BaseUnreachable):
            _resolve_base(self.d, "ghost", authoritative=True)  # unfetched base + HEAD has history
        self.assertEqual(_resolve_base(self.d, "ghost", authoritative=False), self._sha("HEAD~1"))

    def test_resolve_base_uses_remote_tracking_ref(self):
        from cogpin import _resolve_base
        self._w("a.txt", "1")
        self._git("add", "-A")
        self._git("commit", "-qm", "c1")
        c1 = self._sha()
        self._git("update-ref", "refs/remotes/origin/main", c1)  # simulate the fetched base
        self._w("a.txt", "2")
        self._git("add", "-A")
        self._git("commit", "-qm", "c2")
        self.assertEqual(_resolve_base(self.d, "main", authoritative=True), c1)  # merge-base, not HEAD~1

    def test_trusted_default_branch_pins_full_pr_range(self):
        # The fix: with the trusted --default-branch, the base is the merge-base over origin/main,
        # so a forbidden file added in an EARLIER PR commit is still in range (can't be hidden
        # behind a later clean commit by redirecting the base).
        from cogpin import cmd_check
        self._w("cogpin.toml", self.STRICT)
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        self._git("update-ref", "refs/remotes/origin/main", self._sha())
        self._w(".env", "SECRET=1")  # forbidden file, added in an earlier PR commit
        self._git("add", "-A")
        self._git("commit", "-qm", "add secret")
        self._w("clean.txt", "ok")   # a later, clean commit (HEAD)
        self._git("add", "-A")
        self._git("commit", "-qm", "clean")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cmd_check(self.d, allow_run=False, default_branch_arg="main")
        self.assertEqual(rc, 1, "the .env added across the full base..HEAD range must be caught")

    def test_authoritative_unreachable_base_fails_closed_e2e(self):
        from cogpin import cmd_check
        self._w("cogpin.toml", self.STRICT)
        self._git("add", "-A")
        self._git("commit", "-qm", "base")
        self._w("clean.txt", "ok")
        self._git("add", "-A")
        self._git("commit", "-qm", "head")
        with contextlib.redirect_stdout(io.StringIO()):
            # clean diff would be rc 0, but the trusted base is unfetched → refuse (rc 1)
            self.assertEqual(cmd_check(self.d, allow_run=False, default_branch_arg="ghost"), 1)


# ─────────────────────────────────────────────────────────────────────────────
# Phase A — merge-blocking drift guards: make the primitive parallel-lists go CI-red
# instead of silently shipping a fail-open gate. Test-layer introspection only
# (inspect/re over the engine source); the engine itself stays pure.
# ─────────────────────────────────────────────────────────────────────────────


class TestNoDrift(unittest.TestCase):
    """WHY the `(?:c|check)` binder in the dead-field scan: pure primitives bind
    `check.<field>` while the `_eval_diff` dispatch binds `c.<field>`. A future rename of
    either binder weakens these regexes into a FALSE-NEGATIVE (fail-safe: it never produces
    a false failure, only misses a dead field) — keep the convention or update the scan."""

    _ENGINE_SRC = inspect.getsource(R)
    _ROOT = os.path.dirname(_COGPIN)

    def _doc(self, rel):
        with open(os.path.join(self._ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_every_primitive_is_routed(self):
        # a name in PRIMITIVES with no dispatch arm silently returns None — a never-firing gate
        routers = [R._eval_diff, R.run_command_gate, R.run_self_protect_gate,
                   R.run_branch_gate, R.attestation_gaps, R.cmd_judge]
        routed = "\n".join(inspect.getsource(fn) for fn in routers)
        for p in R.PRIMITIVES:
            self.assertIn(f'"{p}"', routed, f"primitive {p!r} is in PRIMITIVES but no evaluator routes it")

    def test_no_dead_check_field(self):
        # a Check field parsed/declared but read by no primitive (the `Check.where` exhibit)
        core = {"id", "kind", "severity", "primitive", "layer"}
        for f in dataclasses.fields(R.Check):
            if f.name in core:
                continue
            self.assertRegex(self._ENGINE_SRC, rf"(?:c|check)\.{f.name}\b",
                             f"Check.{f.name} is declared/parsed but read by no primitive (dead field)")

    def test_known_keys_all_parsed(self):
        fr = inspect.getsource(R.Config._from_raw)
        for k in R._KNOWN_CHECK_KEYS:
            self.assertIn(f'"{k}"', fr, f"known key {k!r} is allowlisted but never read in _from_raw")

    def test_known_check_keys_derivation_is_stable(self):
        # the derived allowlist must equal the Check fields (+ the two aliases) — pins the swap
        aliases = {"approvers": "require_approval_from", "cls": "class"}
        self.assertEqual(R._KNOWN_CHECK_KEYS,
                         frozenset(aliases.get(f.name, f.name) for f in dataclasses.fields(R.Check)))

    def test_every_primitive_is_documented(self):
        readme, schema, cov = self._doc("README.md"), self._doc("SCHEMA.md"), self._doc("docs/coverage-map.md")
        for p in R.PRIMITIVES:
            self.assertIn(f"`{p}", readme, f"{p} missing from the README primitive table")
            self.assertIn(f"`{p}", schema, f"{p} missing from SCHEMA.md")
            self.assertIn(f"`{p}", cov, f"{p} missing from docs/coverage-map.md (provenance)")

    def test_primitive_count_matches_readme(self):
        counts = {int(m) for m in re.findall(r"(\d+) primitives", self._doc("README.md"))}
        self.assertEqual(counts, {len(R.PRIMITIVES)},
                         f"README 'N primitives' count drifted from {len(R.PRIMITIVES)}")

    def test_fact_prims_is_complement_of_advisory(self):
        # regression pin for the derived TestMoatPreservation._FACT_PRIMS
        self.assertEqual(R.PRIMITIVES - R._ADVISORY_ONLY, {
            "forbid_command", "forbid_commit_on_branch", "self_protect", "secret_scan",
            "forbid_pattern", "forbid_removal", "forbid_delete", "scope_lock", "numeric_floor",
            "change_budget", "file_must_contain", "max_added_file_bytes", "path_requires",
            "cooccur", "marker_present", "forbid_in_message", "require_message_pattern",
            "commit_footer", "protected_path", "require_approval_from", "pattern_requires_approval",
            "approval_policy", "require_checks_green", "run"})

    def test_advisory_primitive_cannot_be_declared_block(self):
        # the moat trusts the kind LABEL; an advisory-by-nature primitive mislabelled `fact`
        # would ship a `block` that silently never fires (not in the diff dispatch). Reject it.
        for prim, extra in (("judge", 'prompt="p"'), ("attest", 'box="x"\nclass="always"')):
            bad = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="x"\nkind="fact"\n'
                   f'severity="block"\nprimitive="{prim}"\n{extra}\n')
            with self.assertRaises(ConfigError):
                Config.parse(bad)
        # the same primitives are valid as advisory
        ok = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="j"\nkind="advisory"\n'
              'severity="warn"\nprimitive="judge"\nprompt="p"\n')
        self.assertEqual(len(Config.parse(ok).checks), 1)


# ─────────────────────────────────────────────────────────────────────────────
# Phase B — PRIMITIVE_SPECS is the single source for the name set, the fact/advisory
# split, and the layer-placement rule. Pins the table's columns against drift.
# ─────────────────────────────────────────────────────────────────────────────


class TestPrimitiveSpecs(unittest.TestCase):
    def test_primitives_is_spec_keyset_and_names_pinned(self):
        self.assertEqual(R.PRIMITIVES, frozenset(R.PRIMITIVE_SPECS))
        self.assertEqual(set(R.PRIMITIVE_SPECS), {
            "secret_scan", "forbid_command", "forbid_pattern", "forbid_removal", "forbid_delete",
            "forbid_commit_on_branch", "scope_lock", "self_protect", "forbid_in_message",
            "require_message_pattern", "numeric_floor", "change_budget", "file_must_contain",
            "max_added_file_bytes", "path_requires", "cooccur", "marker_present", "commit_footer",
            "protected_path", "require_approval_from", "pattern_requires_approval", "approval_policy",
            "require_checks_green", "run", "attest", "judge"})

    def test_spec_kinds_valid(self):
        for name, spec in R.PRIMITIVE_SPECS.items():
            self.assertIn(spec.kind, R.KINDS, f"{name}: invalid kind {spec.kind!r}")

    def test_advisory_only_derives_from_spec_kind(self):
        self.assertEqual(R._ADVISORY_ONLY,
                         frozenset(n for n, s in R.PRIMITIVE_SPECS.items() if s.kind == "advisory"))
        self.assertEqual(R._ADVISORY_ONLY, {"attest", "judge"})

    def test_agent_only_primitives_pinned(self):
        agent_only = {n for n, s in R.PRIMITIVE_SPECS.items() if s.layers != R._ANY_LAYER}
        self.assertEqual(agent_only, {"forbid_commit_on_branch", "self_protect"})
        for n in agent_only:
            self.assertEqual(R.PRIMITIVE_SPECS[n].layers, R._AGENT_ONLY)

    def test_layer_placement_guard_is_table_driven(self):
        # live-signal primitives are rejected at the change layer; a normal fact primitive is fine
        for prim, extra in (("self_protect", 'paths=["cogpin.toml"]'),
                            ("forbid_commit_on_branch", 'branch=["main"]')):
            bad = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="x"\nkind="fact"\n'
                   f'severity="warn"\nlayer="change"\nprimitive="{prim}"\n{extra}\n')
            with self.assertRaises(ConfigError):
                Config.parse(bad)
        ok = ('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="ok"\nkind="fact"\n'
              'severity="warn"\nlayer="change"\nprimitive="forbid_pattern"\npattern="x"\n')
        self.assertEqual(len(Config.parse(ok).checks), 1)


# ─────────────────────────────────────────────────────────────────────────────
# Review 5 — degrade-safe + encoding/path robustness on the git-acquisition layer.
# Each exercises bytes/paths/clones that previously made an AUTHORITATIVE gate
# silently PASS (E1/E3/E4, checks-file) or crashed an introspection CLI (C1/C2).
# ─────────────────────────────────────────────────────────────────────────────


class TestReview5Robustness(unittest.TestCase):
    def _git(self, *a):
        subprocess.run(["git", "-C", self.d, *a], check=True, capture_output=True, text=True)

    def _head(self):
        return subprocess.run(["git", "-C", self.d, "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._git("config", "commit.gpgsign", "false")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel, text):
        with open(os.path.join(self.d, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    def _commit(self, msg):
        self._git("add", "-A")
        self._git("commit", "-qm", msg)

    _RCG = ('schema=1\n[repo]\ndefault_branch="main"\n[meta]\nbase_pinned=true\n'
            '[[check]]\nid="green"\nkind="fact"\nseverity="block"\n'
            'primitive="require_checks_green"\nneed=["ci"]\n')

    # E1 — one non-UTF-8 byte anywhere in the diff must NOT empty the content scan
    def test_non_utf8_byte_does_not_null_content_diff(self):
        self._write("clean.py", "x = 1\n")
        self._commit("base")
        base = self._head()
        self._write("clean.py", 'x = 1\ntoken = "ghp_' + "A" * 36 + '"\n')
        with open(os.path.join(self.d, "blob.dat"), "wb") as fh:
            fh.write(b"latin1 \xff comment, no NUL so git treats it as text\n")
        self._commit("a secret + a non-utf8 sibling in the same diff")
        facts = DiffFacts.from_range(self.d, base, "HEAD")
        added = [line for _, line in facts.added]
        self.assertTrue(any("ghp_" in ln for ln in added),
                        "a stray non-UTF-8 byte must not null the whole content diff")

    # E3 — a unicode line separator inside a content line must not sever it (drop the tail)
    def test_unicode_line_separator_keeps_added_line_whole(self):
        self._write("a.py", "x = 1\n")
        self._commit("base")
        base = self._head()
        self._write("a.py", 'x = 1\ny = " ghp_' + "B" * 36 + '"\n')
        self._commit("U+2028 inside an added line")
        facts = DiffFacts.from_range(self.d, base, "HEAD")
        added = [line for _, line in facts.added]
        self.assertTrue(any("ghp_" in ln for ln in added),
                        "splitlines() drops the token after U+2028; split('\\n') keeps it")

    # E4 — a non-ASCII filename's blob size must be captured (quotepath round-trip), so the cap fires
    def test_non_ascii_filename_size_is_captured(self):
        self._write("seed.txt", "s\n")
        self._commit("base")
        base = self._head()
        name = "café.txt"  # quotepath=true would escape this to "caf\303\251.txt"
        with open(os.path.join(self.d, name), "w", encoding="utf-8") as fh:
            fh.write("X" * 5000)
        self._commit("add a big unicode-named file")
        facts = DiffFacts.from_range(self.d, base, "HEAD")
        self.assertIn(name, list(facts.changed_paths()))
        R._populate_file_sizes(self.d, base, "HEAD", facts)
        self.assertEqual(facts.file_sizes.get(name), 5000,
                         "a unicode-named blob must resolve under cat-file, not be dropped")
        c = one_check('[[check]]\nid="big"\nkind="fact"\nseverity="block"\n'
                      'primitive="max_added_file_bytes"\nmaxkb=1')
        self.assertIsNotNone(R.max_added_file_bytes(c, facts, repo()),
                             "the byte cap must fire on the unicode-named over-cap file")

    # E2 — a SHALLOW clone with an unreachable base must FAIL CLOSED in authoritative mode
    def test_shallow_clone_authoritative_fails_closed(self):
        self._write("f.txt", "1\n")
        self._commit("c1")
        self._write("f.txt", "2\n")
        self._commit("c2")
        dst = tempfile.TemporaryDirectory()
        self.addCleanup(dst.cleanup)
        # file:// (not a bare path) so --depth actually produces a shallow clone
        subprocess.run(["git", "clone", "--depth", "1", "file://" + self.d, dst.name],
                       check=True, capture_output=True, text=True)
        self.assertEqual(
            (R._git(dst.name, ["rev-parse", "--is-shallow-repository"]) or "").strip(), "true")
        with self.assertRaises(R.BaseUnreachable):
            R._resolve_base(dst.name, "no-such-branch", authoritative=True)

    # E2 contrast — a TRUE root commit (not shallow) degrades to None, never raises
    def test_true_root_commit_degrades_not_shallow(self):
        self._write("only.txt", "1\n")
        self._commit("root")
        self.assertEqual(
            (R._git(self.d, ["rev-parse", "--is-shallow-repository"]) or "").strip(), "false")
        self.assertIsNone(R._resolve_base(self.d, "no-such-branch", authoritative=True))

    # checks-file — a present-but-GARBLED checks file fails CLOSED for a need-scoped check
    def test_garbled_checks_file_fails_closed(self):
        self._write("cogpin.toml", self._RCG)
        self._commit("base")
        self._git("update-ref", "refs/remotes/origin/main", self._head())
        self._write("clean.txt", "ok")
        self._commit("head")
        garbled = os.path.join(self.d, "checks.json")
        with open(garbled, "w", encoding="utf-8") as fh:
            fh.write("not json at all")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = R.cmd_check(self.d, allow_run=False, default_branch_arg="main", checks_file=garbled)
        self.assertEqual(rc, 1, "a garbled checks file must fail closed, not silently skip the check")

    # checks-file — a genuinely ABSENT checks file still SKIPS (no false-block)
    def test_absent_checks_file_skips(self):
        self._write("cogpin.toml", self._RCG)
        self._commit("base")
        self._git("update-ref", "refs/remotes/origin/main", self._head())
        self._write("clean.txt", "ok")
        self._commit("head")
        missing = os.path.join(self.d, "does-not-exist.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = R.cmd_check(self.d, allow_run=False, default_branch_arg="main", checks_file=missing)
        self.assertEqual(rc, 0, "an absent checks file → skip (no PR context), never a false-block")

    # C2 — a non-UTF-8 CLAUDE.md must not crash the introspection sweep
    def test_scan_repo_tolerates_non_utf8_claude_md(self):
        with open(os.path.join(self.d, "CLAUDE.md"), "wb") as fh:
            fh.write(b"# house rules\n\xff always branch first\n")
        self._commit("add a latin-1 CLAUDE.md")
        self.assertIsInstance(R.scan_repo(self.d), R.RepoScan)  # must not raise


class TestReview5Introspection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    # C1 — a valid pyproject whose `tool` is a scalar must not crash detect_test_command
    def test_detect_test_command_non_dict_tool(self):
        with open(os.path.join(self.d, "pyproject.toml"), "w", encoding="utf-8") as fh:
            fh.write("tool = 5\n")
        self.assertEqual(R.detect_test_command(self.d), (None, None))  # must not raise TypeError

    # C2 — a non-UTF-8 manifest must degrade to the next source, never raise
    def test_detect_test_command_non_utf8_manifest(self):
        with open(os.path.join(self.d, "justfile"), "wb") as fh:
            fh.write(b"# \xff a latin-1 comment\nbuild:\n\techo hi\n")  # no `test:` target
        self.assertEqual(R.detect_test_command(self.d), (None, None))  # must not raise UnicodeDecodeError


# ─────────────────────────────────────────────────────────────────────────────
# #22 — the tightened moat: severity=block REQUIRES kind=fact AND provenance=environment.
# An agent-authored claim token (a self-typed marker, a ticked box) is gameable by the
# gated agent → it may only warn/attest, never hard-block. Closes the principal-agent
# hole INSIDE the fact set (a self-typed two-lens marker could hard-block before).
# ─────────────────────────────────────────────────────────────────────────────


class TestProvenanceMoat(unittest.TestCase):
    def _block(self, primitive, extra=""):
        return (f'[[check]]\nid="x"\nkind="fact"\nseverity="block"\nprimitive="{primitive}"\n{extra}')

    def test_spec_provenance_pinned(self):
        # exactly these three are agent-provenance; everything else is environment
        self.assertEqual(R._AGENT_PROVENANCE, {"marker_present", "attest", "judge"})
        for p in ("secret_scan", "require_checks_green", "run", "forbid_in_message",
                  "require_message_pattern", "commit_footer", "cooccur", "path_requires"):
            self.assertEqual(R.PRIMITIVE_SPECS[p].provenance, "environment", f"{p} must be environment")
        for p in ("marker_present", "attest", "judge"):
            self.assertEqual(R.PRIMITIVE_SPECS[p].provenance, "agent", f"{p} must be agent")

    def test_marker_present_block_rejected(self):
        # the #22 exhibit: a self-typed PR-body marker may no longer hard-block
        with self.assertRaises(ConfigError):
            Config.parse('schema=1\n[repo]\ndefault_branch="main"\n' +
                         self._block("marker_present", "marker='(?i)two-lens-review\\\\s*:'"))

    def test_marker_present_warn_still_valid(self):
        cfg = Config.parse('schema=1\n[repo]\ndefault_branch="main"\n[[check]]\nid="x"\nkind="fact"\n'
                            'severity="warn"\nprimitive="marker_present"\nmarker="X"\n')
        self.assertEqual(len(cfg.checks), 1)

    def test_every_agent_provenance_primitive_cannot_block(self):
        # the moat invariant, table-driven: no agent-provenance primitive may be authored block
        for p in R._AGENT_PROVENANCE:
            with self.assertRaises(ConfigError, msg=f"{p} block must be rejected"):
                Config.parse('schema=1\n[repo]\ndefault_branch="main"\n' +
                             self._block(p, "marker=\"X\"\npattern=\"X\"\nprompt=\"X\""))

    def test_cooccur_block_ignores_agent_authored_text(self):
        # a BLOCK cooccur must rest only on the diff (environment): the require token typed
        # into the PR body / a commit message must NOT satisfy it — else the gated agent
        # clears the gate by typing the token (the marker_present hole, re-opened via cooccur).
        blk = one_check('[[check]]\nid="co"\nkind="fact"\nseverity="block"\nprimitive="cooccur"\n'
                        'trigger="MIGRATION"\nrequire="rollback"')
        # trigger in the diff (environment) so the rule fires; require ONLY in agent text → blocks
        typed = DiffFacts(added=[("db.sql", "-- MIGRATION add table")],
                          pr_body="rollback: see below", commit_msgs=["chore: rollback ready"])
        self.assertIsNotNone(cooccur(blk, typed), "PR-body/commit token must NOT satisfy a block cooccur")
        # require actually in the diff → satisfied
        indiff = DiffFacts(added=[("db.sql", "-- MIGRATION add table"), ("down.sql", "rollback steps")])
        self.assertIsNone(cooccur(blk, indiff))

    def test_cooccur_warn_still_accepts_pr_body(self):
        # a WARN cooccur keeps the forcing-function convenience: PR-body/commit text satisfies it
        wrn = one_check('[[check]]\nid="co"\nkind="fact"\nseverity="warn"\nprimitive="cooccur"\n'
                        'trigger="BREAKING"\nrequire="CHANGELOG"')
        self.assertIsNone(cooccur(wrn, DiffFacts(pr_body="BREAKING", commit_msgs=["docs: CHANGELOG"])))
        self.assertIsNotNone(cooccur(wrn, DiffFacts(pr_body="BREAKING change only")))


# ─────────────────────────────────────────────────────────────────────────────
# #24 — [capability] is a DECLARED floor (policy), not enforcement: cogpin parses +
# validates it and compiles it to the harness via `capability emit`; it never contains.
# ─────────────────────────────────────────────────────────────────────────────


class TestCapability(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _cfg(self, cap_toml):
        with open(os.path.join(self.d, "cogpin.toml"), "w", encoding="utf-8") as fh:
            fh.write('schema=1\n[repo]\ndefault_branch="main"\n' + cap_toml)

    def _settings(self):
        return json.load(open(os.path.join(self.d, ".claude", "settings.json")))

    def _settings_exists(self):
        return os.path.exists(os.path.join(self.d, ".claude", "settings.json"))

    def test_capability_parses_and_defaults_empty(self):
        cfg = Config.parse('schema=1\n[repo]\ndefault_branch="main"\n[capability]\n'
                           'no_network=true\ndeny_paths=["~/.ssh/**"]\ndeny_commands=["curl"]\n'
                           'allow_commands=["git"]\nfs_confine=["."]\n')
        self.assertTrue(cfg.capability.no_network)
        self.assertEqual(cfg.capability.deny_paths, ["~/.ssh/**"])
        self.assertEqual(cfg.capability.backend, "claude-code")
        self.assertFalse(cfg.capability.is_empty())
        self.assertTrue(Config.parse('schema=1\n[repo]\ndefault_branch="main"\n').capability.is_empty())

    def test_capability_unknown_backend_rejected(self):
        with self.assertRaises(ConfigError):
            Config.parse('schema=1\n[repo]\ndefault_branch="main"\n[capability]\n'
                         'no_network=true\nbackend="nonsense"\n')

    def test_emit_pure_render(self):
        cap = R.Capability(no_network=True, deny_paths=["**/.env"],
                           deny_commands=["curl"], allow_commands=["git"], fs_confine=["."])
        deny, allow, warns = R._emit_claude_code(cap)
        for e in ("Read(**/.env)", "Edit(**/.env)", "Write(**/.env)", "Bash(curl:*)", "WebFetch"):
            self.assertIn(e, deny)
        self.assertIn("Bash(git:*)", allow)
        self.assertTrue(any("no_network" in w for w in warns))
        self.assertTrue(any("fs_confine" in w for w in warns))

    def test_emit_writes_idempotent_and_nonclobbering(self):
        os.makedirs(os.path.join(self.d, ".claude"))
        with open(os.path.join(self.d, ".claude", "settings.json"), "w") as fh:
            json.dump({"permissions": {"deny": ["Bash(sudo:*)"]}, "model": "opus"}, fh)
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        s = self._settings()
        self.assertIn("Bash(sudo:*)", s["permissions"]["deny"])   # user entry preserved
        self.assertIn("Bash(curl:*)", s["permissions"]["deny"])   # managed entry added
        self.assertEqual(s["model"], "opus")                      # unrelated key preserved
        first = open(os.path.join(self.d, ".claude", "settings.json")).read()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self.assertEqual(open(os.path.join(self.d, ".claude", "settings.json")).read(), first)  # idempotent

    def test_emit_drops_stale_managed_entry(self):
        self._cfg('[capability]\ndeny_commands=["curl","wget"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self._cfg('[capability]\ndeny_commands=["curl"]\n')   # wget removed from the stanza
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        deny = self._settings()["permissions"]["deny"]
        self.assertIn("Bash(curl:*)", deny)
        self.assertNotIn("Bash(wget:*)", deny)   # stale managed entry removed

    def test_emit_empty_floor_is_noop(self):
        self._cfg('')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        self.assertFalse(self._settings_exists())

    def test_emit_other_backend_documents_never_contains(self):
        self._cfg('[capability]\nno_network=true\nbackend="docker"\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        self.assertFalse(self._settings_exists())  # cogpin declares; it does not emit for docker

    def test_emit_dry_run_writes_nothing(self):
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d, dry_run=True), 0)
        self.assertIn("Bash(curl:*)", out.getvalue())
        self.assertFalse(self._settings_exists())

    def test_emit_writes_allow_e2e(self):
        # allow must actually PERSIST (the allow path is reconciled, not silently dropped)
        self._cfg('[capability]\nallow_commands=["git"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        self.assertIn("Bash(git:*)", self._settings()["permissions"]["allow"])

    def test_emit_drops_stale_allow(self):
        # symmetry with deny: a command removed from allow_commands is retracted from allow
        self._cfg('[capability]\nallow_commands=["git","npm"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self._cfg('[capability]\nallow_commands=["git"]\n')   # npm removed
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        allow = self._settings()["permissions"]["allow"]
        self.assertIn("Bash(git:*)", allow)
        self.assertNotIn("Bash(npm:*)", allow)   # stale managed allow removed

    def test_emit_full_empty_retracts(self):
        # emptying the WHOLE stanza retracts every managed entry, not just one dropped key
        os.makedirs(os.path.join(self.d, ".claude"))
        with open(os.path.join(self.d, ".claude", "settings.json"), "w") as fh:
            json.dump({"permissions": {"deny": ["Bash(sudo:*)"]}, "model": "opus"}, fh)
        self._cfg('[capability]\nno_network=true\ndeny_commands=["curl"]\nallow_commands=["git"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self._cfg('')   # stanza removed entirely
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        s = self._settings()
        self.assertEqual(s["model"], "opus")                       # unrelated key preserved
        self.assertEqual(s["permissions"]["deny"], ["Bash(sudo:*)"])  # user entry preserved
        self.assertNotIn("allow", s["permissions"])                # emptied managed key deleted
        for managed in ("Bash(curl:*)", "WebFetch", "Bash(git:*)"):
            self.assertNotIn(managed, s["permissions"].get("deny", []))
            self.assertNotIn(managed, s["permissions"].get("allow", []))

    def test_emit_full_empty_deletes_permissions_when_only_managed(self):
        # if cogpin's entries were the ONLY thing in permissions, retraction drops the whole key
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self._cfg('')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self.assertNotIn("permissions", self._settings())   # no vestigial empty container

    def test_emit_refuses_garbled_settings(self):
        # a present-but-unreadable settings.json must NOT be clobbered (fail closed → exit 1)
        os.makedirs(os.path.join(self.d, ".claude"))
        path = os.path.join(self.d, ".claude", "settings.json")
        with open(path, "w") as fh:
            fh.write("{ not valid json")
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 1)
        self.assertEqual(open(path).read(), "{ not valid json")   # left untouched

    def test_emit_refuses_non_object_settings(self):
        # valid JSON but a non-object (array) is also unusable → refuse, don't overwrite
        os.makedirs(os.path.join(self.d, ".claude"))
        path = os.path.join(self.d, ".claude", "settings.json")
        with open(path, "w") as fh:
            fh.write('["a list, not an object"]')
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 1)
        self.assertEqual(open(path).read(), '["a list, not an object"]')

    def test_emit_guards_non_list_permission_values(self):
        # a deny that's a bare string must not be shattered into characters when reconciling
        os.makedirs(os.path.join(self.d, ".claude"))
        with open(os.path.join(self.d, ".claude", "settings.json"), "w") as fh:
            json.dump({"permissions": {"deny": "Bash(sudo:*)"}}, fh)   # string, not list
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        deny = self._settings()["permissions"]["deny"]
        self.assertEqual(deny, ["Bash(curl:*)"])         # clean managed list, no char-shatter
        self.assertNotIn("B", deny)

    def test_emit_user_managed_collision_preserved_and_idempotent(self):
        # a user-authored entry that renders identically to a managed one must (a) be idempotent
        # across repeated emits and (b) survive a later retract — cogpin must never claim it as
        # managed (sidecar records owned-only, not the full render)
        os.makedirs(os.path.join(self.d, ".claude"))
        with open(os.path.join(self.d, ".claude", "settings.json"), "w") as fh:
            json.dump({"permissions": {"deny": ["Bash(curl:*)"]}, "model": "opus"}, fh)
        self._cfg('[capability]\nno_network=true\n')   # managed deny ALSO contains Bash(curl:*)
        spath = os.path.join(self.d, ".claude", "settings.json")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self.assertIn("Bash(curl:*)", self._settings()["permissions"]["deny"])
        first = open(spath).read()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        self.assertEqual(open(spath).read(), first)   # idempotent DESPITE the collision
        self._cfg('')   # retract the whole stanza
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            R.cmd_capability_emit(self.d)
        s = self._settings()
        self.assertEqual(s["model"], "opus")
        self.assertEqual(s["permissions"]["deny"], ["Bash(curl:*)"])   # user entry survives retract
        for managed in ("WebFetch", "Bash(wget:*)", "Bash(nc:*)"):
            self.assertNotIn(managed, s["permissions"]["deny"])         # managed-only entries gone

    def test_emit_non_utf8_settings_fails_closed(self):
        # invalid-UTF-8 settings.json must fail closed (refuse, exit 1), not crash with UnicodeDecodeError
        os.makedirs(os.path.join(self.d, ".claude"))
        path = os.path.join(self.d, ".claude", "settings.json")
        with open(path, "wb") as fh:
            fh.write(b'{"\xe9": 1}')   # lone 0xE9 → invalid UTF-8
        self._cfg('[capability]\ndeny_commands=["curl"]\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.cmd_capability_emit(self.d), 1)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b'{"\xe9": 1}')   # left untouched

    def test_emit_fs_confine_only_warns_not_silent(self):
        # a declared-but-non-enforceable floor (fs_confine only) must surface its warning and not
        # claim that nothing was declared
        self._cfg('[capability]\nfs_confine=["."]\n')
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(R.cmd_capability_emit(self.d), 0)
        msg = err.getvalue()
        self.assertIn("fs_confine", msg)               # the warning is surfaced, not swallowed
        self.assertIn("nothing is enforceable", msg)   # not "no [capability] floor declared"
        self.assertFalse(self._settings_exists())      # nothing written


def _cap3(fn, *a, **k):
    """Run a cmd_* entrypoint, return (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(*a, **k)
    return rc, out.getvalue(), err.getvalue()


# ── #16: the agent layer must never SILENTLY fail-open on an unloadable config ──
_STALE_CFG = ('schema=1\n[repo]\ndefault_branch="main"\ncode=["src/**"]\n'
              '[[check]]\nid="x"\nkind="fact"\nseverity="warn"\nprimitive="brand_new_primitive_v999"\n')


class TestStopFailSafe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_notices_on_unloadable_present_config(self):
        # a present-but-invalid config (unknown primitive — the stale-engine signature) must
        # tell the user the real-time gate is OFF, not vanish
        with open(os.path.join(self.d, "cogpin.toml"), "w", encoding="utf-8") as fh:
            fh.write(_STALE_CFG)
        rc, out, err = _cap3(R.cmd_stop, self.d)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "{}")          # decision contract intact
        self.assertIn("real-time gate OFF", err)     # notice on stderr
        self.assertIn("cogpin doctor", err)

    def test_silent_when_no_config(self):
        # no cogpin.toml → genuinely nothing to gate → no notice (would be noise)
        rc, out, err = _cap3(R.cmd_stop, self.d)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "{}")
        self.assertEqual(err, "")

    def test_notice_keyed_on_existence_not_exception_type(self):
        # a present-but-UNREADABLE config (a directory named cogpin.toml → IsADirectoryError,
        # an OSError not a ConfigError) must STILL notice — proves the branch keys on
        # os.path.exists, not on the exception class
        os.mkdir(os.path.join(self.d, "cogpin.toml"))
        rc, out, err = _cap3(R.cmd_stop, self.d)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "{}")
        self.assertIn("real-time gate OFF", err)

    def test_decision_json_uncorrupted(self):
        # the notice must never leak onto stdout (it carries the Stop-hook JSON decision)
        with open(os.path.join(self.d, "cogpin.toml"), "w", encoding="utf-8") as fh:
            fh.write(_STALE_CFG)
        _, out, err = _cap3(R.cmd_stop, self.d)
        self.assertEqual(out.strip(), "{}")          # byte-exact decision, no notice text
        self.assertNotIn("real-time gate", out)
        self.assertIn("real-time gate", err)


# ── #16: static engine-metadata extraction (no exec of a skewed/foreign engine) ──
class TestExtractEngineMeta(unittest.TestCase):
    def test_reads_real_engine_annassign(self):
        # PRIMITIVE_SPECS is an annotated assignment (ast.AnnAssign); the extractor must still
        # find it (walking only ast.Assign would yield an empty set → every primitive 'stale')
        src = R._slurp(R.__file__)
        prims, schema = R._extract_engine_meta(src)
        self.assertEqual(schema, R.SCHEMA_VERSION)
        self.assertEqual(prims, set(R.PRIMITIVES))   # all known primitives recovered
        self.assertIn("run", prims)
        self.assertIn("numeric_floor", prims)

    def test_old_primitives_set_literal_fallback(self):
        prims, schema = R._extract_engine_meta(
            'SCHEMA_VERSION = 1\nPRIMITIVES = frozenset({"run", "attest"})\n')
        self.assertEqual(prims, {"run", "attest"})
        self.assertEqual(schema, 1)

    def test_unparseable_degrades_safe(self):
        prims, schema = R._extract_engine_meta("def (this is not python")
        self.assertEqual(prims, set())
        self.assertIsNone(schema)


# ── #16: vendored-vs-config/running skew detection (pure) ──
class TestEngineSkew(unittest.TestCase):
    def setUp(self):
        self.real = R._slurp(R.__file__)

    def test_clean_when_in_sync(self):
        self.assertEqual(R._engine_skew(self.real, {"run", "secret_scan"}, 1, R.SCHEMA_VERSION), [])

    def test_flags_config_primitive_missing_from_vendored(self):
        rows = R._engine_skew(self.real, {"primitive_from_the_future"}, 1, R.SCHEMA_VERSION)
        self.assertTrue(any(s == "fail" and "STALE" in lbl and "primitive_from_the_future" in lbl
                            for s, lbl, _ in rows))

    def test_detects_skew_even_when_running_engine_cannot_validate(self):
        # the core scenario: detection uses RAW config primitives, so it works even for a
        # primitive Config.parse would reject — proven here by passing such a name directly
        rows = R._engine_skew(self.real, {"a_primitive_the_engine_lacks"}, 0, R.SCHEMA_VERSION)
        self.assertTrue(any(s == "fail" for s, _, _ in rows))

    def test_schema_mismatch_fails(self):
        old = 'SCHEMA_VERSION = 1\nPRIMITIVE_SPECS: dict = {"run": 1}\n'
        rows = R._engine_skew(old, {"run"}, 2, 2)   # vendored schema 1, config schema 2
        self.assertTrue(any(s == "fail" and "schema" in lbl for s, lbl, _ in rows))

    def test_degrades_on_unparseable_vendored(self):
        rows = R._engine_skew("def (broken", {"run"}, 1, R.SCHEMA_VERSION)
        self.assertTrue(any(s == "warn" and "can't determine" in lbl for s, lbl, _ in rows))
        # never raises

    def test_schema_vs_running_warns(self):
        # config omits schema (cfg_schema=0), vendored schema differs from the active engine →
        # the advisory drift warn branch (not the config-mismatch fail) fires
        old = 'SCHEMA_VERSION = 1\nPRIMITIVE_SPECS: dict = {"run": 1}\n'
        rows = R._engine_skew(old, {"run"}, 0, 2)   # vendored 1, running 2, config unset
        self.assertTrue(any(s == "warn" and "differs from the active engine" in lbl
                            for s, lbl, _ in rows))
        self.assertFalse(any(s == "fail" for s, _, _ in rows))   # not a config mismatch


class TestDoctorSkew(_GitRepo):
    _OLD_ENGINE = 'SCHEMA_VERSION = 1\nPRIMITIVE_SPECS = {"secret_scan": 1, "forbid_command": 1}\n'
    _CFG = ('schema = 1\n[repo]\ndefault_branch="main"\ncode=["src/**"]\n'
            '[[check]]\nid="cov"\nkind="fact"\nseverity="block"\nlayer="change"\n'
            'primitive="numeric_floor"\nkey=\'x=([0-9]+)\'\ndirection="no_decrease"\nscope=["a.txt"]\n')

    def test_reports_stale_vendored_engine(self):
        # vendored engine knows only secret_scan/forbid_command; config uses numeric_floor →
        # doctor must surface the stale-engine skew and fail (exit 1)
        self._w(".cogpin/cogpin.py", self._OLD_ENGINE)
        self._w("cogpin.toml", self._CFG)
        rc, out = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 1)
        self.assertIn("STALE", out)
        self.assertIn("numeric_floor", out)

    def test_clean_when_engine_matches_config(self):
        # vendored == running engine knows everything the config uses → no STALE row
        _quiet(cmd_install, self.d)
        self._w("cogpin.toml", self._CFG)
        rc, out = _quiet(cmd_doctor, self.d)
        self.assertNotIn("STALE", out)

    def test_unsupported_schema_hint(self):
        _quiet(cmd_install, self.d)
        self._w("cogpin.toml", 'schema = 999\n[repo]\ndefault_branch="main"\ncode=["src/**"]\n')
        rc, out = _quiet(cmd_doctor, self.d)
        self.assertEqual(rc, 1)
        self.assertIn("running engine may be stale", out)


class TestUpdate(_GitRepo):
    def _eng(self):
        return os.path.join(self.d, ".cogpin", "cogpin.py")

    def test_revendors_and_reports(self):
        rc, out, _ = _cap3(R.cmd_update, self.d)
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.exists(self._eng()))
        self.assertEqual(R._slurp(self._eng()), R._slurp(os.path.realpath(R.__file__)))
        self.assertIn("re-vendored", out)

    def test_idempotent_when_current(self):
        _cap3(R.cmd_update, self.d)               # first vendor
        before = R._slurp(self._eng())
        rc, out, _ = _cap3(R.cmd_update, self.d)  # second is a no-op
        self.assertEqual(rc, 0)
        self.assertIn("already current", out)
        self.assertEqual(R._slurp(self._eng()), before)

    def test_refuses_self_reference(self):
        # vendored copy IS the running engine (symlink) → can't update from itself
        os.makedirs(os.path.dirname(self._eng()), exist_ok=True)
        os.symlink(os.path.realpath(R.__file__), self._eng())
        rc, _, err = _cap3(R.cmd_update, self.d)
        self.assertEqual(rc, 1)
        self.assertIn("cannot update from the vendored copy", err)

    def test_not_a_git_repo(self):
        with tempfile.TemporaryDirectory() as nogit:
            rc, _, err = _cap3(R.cmd_update, nogit)
            self.assertEqual(rc, 1)
            self.assertIn("not a git repository", err)
            self.assertFalse(os.path.exists(os.path.join(nogit, ".cogpin", "cogpin.py")))


# ── #17: report-only rollout switch + backtest-over-history ──
_BLOCK_CFG = ('schema = 1\n[repo]\ndefault_branch = "main"\ncode = ["*.py"]\n[meta]\n'
              'base_pinned = true\n[[check]]\nid = "no-secret"\nkind = "fact"\nseverity = "block"\n'
              'layer = "change"\nprimitive = "forbid_pattern"\npattern = "SECRET"\nscope = "code"\n')


class TestReportOnly(_GitRepo):
    def _commit(self, msg, **files):
        for rel, txt in files.items():
            self._w(rel, txt)
        self._git("add", "-A")
        self._git("commit", "-q", "-m", msg)

    def _blocking(self):
        # C0 carries the (base-pinned) config; C1 adds a SECRET in a code file → change-layer block
        self._commit("base", **{"cogpin.toml": _BLOCK_CFG, "keep.txt": "x"})
        self._commit("leak", **{"leak.py": "API_SECRET = 1\n"})

    def test_report_only_returns_0_despite_block(self):
        self._blocking()
        rc, out = _quiet(R.cmd_check, self.d, report_only=True)
        self.assertEqual(rc, 0)
        self.assertIn("[BLOCK]", out)
        self.assertIn("report-only", out)
        rc2, _ = _quiet(R.cmd_check, self.d)        # same repo, enforcing → fails
        self.assertEqual(rc2, 1)

    def test_report_only_clean_repo_returns_0(self):
        self._commit("base", **{"cogpin.toml": _BLOCK_CFG, "keep.txt": "x"})
        self._commit("clean", **{"ok.py": "value = 1\n"})
        rc, out = _quiet(R.cmd_check, self.d, report_only=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("[BLOCK]", out)

    def test_report_only_still_fails_on_base_unreachable(self):
        # authoritative base (a --default-branch CI never fetched) MUST still fail closed,
        # even under report-only — it's an infra error, not a policy finding
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG, "a.txt": "1"})
        self._commit("c1", **{"b.txt": "2"})
        rc, _, err = _cap3(R.cmd_check, self.d, report_only=True, default_branch_arg="ghost-branch")
        self.assertEqual(rc, 1)
        self.assertIn("unreachable", err)

    def test_report_only_still_fails_on_bad_config(self):
        # an unloadable base-pinned config fails closed even under report-only
        bad = ('schema = 1\n[repo]\ndefault_branch = "main"\ncode=["*.py"]\n[meta]\nbase_pinned=true\n'
               '[[check]]\nid="x"\nkind="judge"\nseverity="block"\nprimitive="secret_scan"\n')  # block w/o fact
        self._commit("c0", **{"cogpin.toml": bad, "a.txt": "1"})
        self._commit("c1", **{"b.txt": "2"})   # HEAD~1 (the base) carries the bad config
        rc, _, err = _cap3(R.cmd_check, self.d, report_only=True)
        self.assertEqual(rc, 1)
        self.assertIn("cannot load", err)


class TestBacktest(_GitRepo):
    def _commit(self, msg, **files):
        for rel, txt in files.items():
            self._w(rel, txt)
        self._git("add", "-A")
        self._git("commit", "-q", "-m", msg)

    def test_flags_blocking_commit(self):
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        self._commit("c1", **{"a.py": "ok = 1\n"})
        self._commit("c2", **{"b.py": "X_SECRET = 2\n"})   # the offender
        self._commit("c3", **{"c.py": "fine = 3\n"})
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD~3..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("1/3 commit(s) would block", out)
        self.assertIn("no-secret", out)
        self.assertEqual(out.count("✗"), 1)

    def test_clean_history(self):
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        self._commit("c1", **{"a.py": "ok = 1\n"})
        self._commit("c2", **{"b.py": "fine = 2\n"})
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD~2..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("0/2 commit(s) would block", out)

    def test_invalid_range_exits_2(self):
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        rc, _, err = _cap3(R.cmd_backtest, self.d, "no-such-ref-xyz..HEAD")
        self.assertEqual(rc, 2)
        self.assertIn("invalid range", err)

    def test_empty_range_exits_0(self):
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("no commits in range", out)

    def test_skips_root_no_crash(self):
        # a range spanning the root commit (empty %P) must skip it, never traceback
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        self._commit("c1", **{"a.py": "ok = 1\n"})
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD")   # all history incl. root
        self.assertEqual(rc, 0)
        self.assertIn("would block", out)

    def test_fail_on_block_exits_1(self):
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        self._commit("c1", **{"b.py": "Y_SECRET = 1\n"})
        rc, _ = _quiet(R.cmd_backtest, self.d, "HEAD~1..HEAD", fail_on_block=True)
        self.assertEqual(rc, 1)

    def test_uses_working_config_over_history(self):
        # a commit predating the config is still judged by the CURRENT working config
        self._commit("c0", **{"seed.txt": "1"})
        self._commit("c1", **{"old.py": "Z_SECRET = 1\n"})   # added BEFORE the config existed
        self._commit("c2", **{"cogpin.toml": _BLOCK_CFG})   # config arrives last
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD~2..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("1/2 commit(s) would block", out)   # c1 flagged by today's policy

    def test_max_added_file_bytes_covered(self):
        # proves _populate_file_sizes runs per commit (else size gates silently skip)
        cfg = ('schema = 1\n[repo]\ndefault_branch = "main"\ncode = ["*.dat"]\n[meta]\nbase_pinned = true\n'
               '[[check]]\nid = "no-big"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
               'primitive = "max_added_file_bytes"\nmaxkb = 1\nscope = "code"\n')
        self._commit("c0", **{"cogpin.toml": cfg})
        self._commit("c1", **{"big.dat": "x" * 2048})   # 2KB > 1KB cap
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD~1..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("1/1 commit(s) would block", out)
        self.assertIn("no-big", out)

    def test_run_check_skipped_and_noted(self):
        # a `run` block is never executed by backtest (allow_run=False) and is named as blind
        cfg = (_BLOCK_CFG + '[[check]]\nid = "suite"\nkind = "fact"\nseverity = "block"\n'
               'layer = "change"\nprimitive = "run"\ncmd = "exit 1"\n')
        self._commit("c0", **{"cogpin.toml": cfg})
        self._commit("c1", **{"a.py": "ok = 1\n"})        # no SECRET; run would fail IF executed
        rc, out = _quiet(R.cmd_backtest, self.d, "HEAD~1..HEAD")
        self.assertEqual(rc, 0)
        self.assertIn("0/1 commit(s) would block", out)   # run NOT executed → not blocked
        self.assertIn("suite", out)                       # named in the blind note
        self.assertIn("NOT evaluated", out)

    def test_cli_invalid_range(self):
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        out = subprocess.run([sys.executable, os.path.join(os.path.dirname(R.__file__), "cogpin.py"),
                              "backtest", "--cwd", self.d, "--range", "bogus..HEAD"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)

    def test_blind_names_pr_body_and_run_block_checks(self):
        # a clean backtest must NOT overstate coverage: a `run` block and a pr_body-triggered
        # path_requires(when_marker) are both un-evaluable → named; a plain diff-fact check isn't
        toml = ('schema=1\n[repo]\ndefault_branch="main"\ncode=["*.py"]\ndocs=["docs/**"]\n[meta]\n'
                'base_pinned=true\n'
                '[[check]]\nid="secret"\nkind="fact"\nseverity="block"\nlayer="change"\n'
                'primitive="forbid_pattern"\npattern="X"\nscope="code"\n'
                '[[check]]\nid="suite"\nkind="fact"\nseverity="block"\nlayer="change"\n'
                'primitive="run"\ncmd="true"\n'
                '[[check]]\nid="migrate-docs"\nkind="fact"\nseverity="block"\n'
                'primitive="path_requires"\nwhen_marker="MIGRATION"\nneed=["docs"]\n')
        blind = R._backtest_blind(R.Config.parse(toml))
        self.assertIn("suite", blind)            # run — needs a checkout
        self.assertIn("migrate-docs", blind)     # pr_body trigger backtest can't supply
        self.assertNotIn("secret", blind)        # plain diff-fact check IS evaluated

    def test_missing_config_file_names_it(self):
        # a typo'd --config must say "no such file", not the misleading "schema version 0"
        self._commit("c0", **{"cogpin.toml": _BLOCK_CFG})
        rc, _, err = _cap3(R.cmd_backtest, self.d, "HEAD", config=os.path.join(self.d, "nope.toml"))
        self.assertEqual(rc, 2)
        self.assertIn("no such config file", err)
        self.assertNotIn("schema version", err)


# ── #18: config-as-code golden fixtures (DiffFacts.from_unified_diff + check --diff-file) ──
_FX_ADD = ("diff --git a/new.py b/new.py\nnew file mode 100644\nindex 0000000..1111111\n"
           "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+API_SECRET = 1\n")
_FX_DELETE = ("diff --git a/gone.py b/gone.py\ndeleted file mode 100644\nindex 1111111..0000000\n"
              "--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-assert critical\n")
_FX_MODIFY = ("diff --git a/keep.py b/keep.py\nindex 1111111..2222222 100644\n"
              "--- a/keep.py\n+++ b/keep.py\n@@ -2 +2 @@\n-old_line = 2\n+new_line = 3\n")
_FX_RENAME = ("diff --git a/old.py b/new_name.py\nsimilarity index 100%\n"
              "rename from old.py\nrename to new_name.py\n")
_FX_BINARY_ADD = ("diff --git a/logo.png b/logo.png\nnew file mode 100644\nindex 0000000..2222222\n"
                  "Binary files /dev/null and b/logo.png differ\n")
_FX_BINARY_DEL = ("diff --git a/old.png b/old.png\ndeleted file mode 100644\nindex 2222222..0000000\n"
                  "Binary files a/old.png and /dev/null differ\n")
# a CONTENT line that starts with `--- `/`+++ ` (an SQL/Lua `-- ` comment) must NOT be mistaken
# for a file header — the added SECRET below has to survive into facts.added.
_FX_COMMENT_TRAP = ("diff --git a/q.sql b/q.sql\nindex 1111111..2222222 100644\n--- a/q.sql\n"
                    "+++ b/q.sql\n@@ -1,2 +1,2 @@\n--- old comment\n+-- new comment SECRET\n")

_FX_CFG = ('schema = 1\n[repo]\ndefault_branch = "main"\ncode = ["*.py"]\ndocs = ["docs/**"]\n'
           '[[check]]\nid = "no-secret"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
           'primitive = "forbid_pattern"\npattern = "SECRET"\nscope = "code"\n'
           '[[check]]\nid = "no-todo"\nkind = "fact"\nseverity = "warn"\nlayer = "change"\n'
           'primitive = "forbid_pattern"\npattern = "TODO"\nscope = "code"\n')


class TestFromUnifiedDiff(unittest.TestCase):
    """DiffFacts.from_unified_diff — the fixture acquisition source mirrors from_range."""

    def test_added_and_removed_lines(self):
        f = DiffFacts.from_unified_diff(_FX_ADD + _FX_MODIFY)
        self.assertIn(("new.py", "API_SECRET = 1"), f.added)
        self.assertIn(("keep.py", "new_line = 3"), f.added)
        self.assertIn(("keep.py", "old_line = 2"), f.removed)

    def test_changed_status_add_modify_delete(self):
        f = DiffFacts.from_unified_diff(_FX_ADD + _FX_MODIFY + _FX_DELETE)
        self.assertIn(("A", "new.py"), f.changed)
        self.assertIn(("M", "keep.py"), f.changed)
        self.assertIn(("D", "gone.py"), f.changed)

    def test_rename_coalesces_to_modified_on_new_path(self):
        # matches git --name-status's R→M coalesce: the new path is what's "changed"
        f = DiffFacts.from_unified_diff(_FX_RENAME)
        self.assertEqual(f.changed, [("M", "new_name.py")])

    def test_binary_add_and_delete_paths(self):
        # a binary blob carries no +++/--- header — path must come from the `Binary files` line
        self.assertEqual(DiffFacts.from_unified_diff(_FX_BINARY_ADD).changed, [("A", "logo.png")])
        self.assertEqual(DiffFacts.from_unified_diff(_FX_BINARY_DEL).changed, [("D", "old.png")])

    def test_comment_line_not_mistaken_for_header(self):
        f = DiffFacts.from_unified_diff(_FX_COMMENT_TRAP)
        # the `+-- new comment SECRET` content survives attribution to q.sql (not dropped);
        # line[1:] strips only the leading `+` marker, leaving the `-- ` comment intact
        self.assertIn(("q.sql", "-- new comment SECRET"), f.added)
        self.assertEqual(f.changed, [("M", "q.sql")])

    def test_empty_diff_raises(self):
        with self.assertRaises(ValueError):
            DiffFacts.from_unified_diff("")

    def test_non_git_diff_raises(self):
        # a plain `diff -u` (no `diff --git`) has no rename/delete/binary status → reject it
        with self.assertRaises(ValueError):
            DiffFacts.from_unified_diff("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")

    def test_matches_real_git_output(self):
        # the contract is git's actual format — parse a diff git itself produced
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))

        def g(*a):
            subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)

        g("init", "-q")
        g("config", "user.email", "t@t")
        g("config", "user.name", "t")
        g("config", "commit.gpgsign", "false")
        with open(os.path.join(d, "keep.py"), "w") as fh:
            fh.write("a = 1\nold = 2\n")
        g("add", "-A")
        g("commit", "-qm", "base")
        with open(os.path.join(d, "new.py"), "w") as fh:
            fh.write("API_SECRET = 1\n")
        with open(os.path.join(d, "keep.py"), "w") as fh:
            fh.write("a = 1\nnew = 3\n")
        g("add", "-A")
        g("commit", "-qm", "change")
        raw = subprocess.run(["git", "-C", d, "diff", "HEAD~1", "HEAD"],
                             capture_output=True, text=True).stdout
        f = DiffFacts.from_unified_diff(raw)
        self.assertIn(("A", "new.py"), f.changed)
        self.assertIn(("M", "keep.py"), f.changed)
        self.assertIn(("new.py", "API_SECRET = 1"), f.added)

    def test_from_range_still_works_after_refactor(self):
        # the body loop was factored into _parse_unified_added_removed; from_range must be intact
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))

        def g(*a):
            subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)

        g("init", "-q")
        g("config", "user.email", "t@t")
        g("config", "user.name", "t")
        g("config", "commit.gpgsign", "false")
        with open(os.path.join(d, "a.py"), "w") as fh:
            fh.write("keep = 1\ndrop = 2\n")
        g("add", "-A")
        g("commit", "-qm", "base")
        with open(os.path.join(d, "a.py"), "w") as fh:
            fh.write("keep = 1\nadded = 3\n")
        g("add", "-A")
        g("commit", "-qm", "change")
        f = DiffFacts.from_range(d, "HEAD~1", "HEAD")
        self.assertIn(("a.py", "added = 3"), f.added)
        self.assertIn(("a.py", "drop = 2"), f.removed)
        self.assertIn(("M", "a.py"), f.changed)


class TestFixtureBlind(unittest.TestCase):
    """_fixture_blind: which expected checks a diff fixture can't decide given the context."""

    def _cfg(self):
        toml = (_FX_CFG
                + '[[check]]\nid = "suite"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
                  'primitive = "run"\ncmd = "true"\n'
                + '[[check]]\nid = "no-big"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
                  'primitive = "max_added_file_bytes"\nmaxkb = 1\nscope = "code"\n'
                + '[[check]]\nid = "needs-approval"\nkind = "fact"\nseverity = "block"\n'
                  'primitive = "protected_path"\nscope = "code"\n'
                + '[[check]]\nid = "ci-green"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
                  'primitive = "require_checks_green"\nneed = ["build"]\n')
        return R.Config.parse(toml)

    def test_run_and_size_always_blind(self):
        blind = R._fixture_blind(self._cfg(), DiffFacts())
        self.assertIn("suite", blind)          # run — needs a checkout
        self.assertIn("no-big", blind)         # max_added_file_bytes — needs blob bytes
        self.assertNotIn("no-secret", blind)   # plain diff-fact check IS evaluable

    def test_approval_blind_without_reviews(self):
        self.assertIn("needs-approval", R._fixture_blind(self._cfg(), DiffFacts()))

    def test_approval_evaluable_with_reviews(self):
        f = DiffFacts(reviews=[])
        self.assertNotIn("needs-approval", R._fixture_blind(self._cfg(), f))

    def test_checks_blind_without_checks_file(self):
        self.assertIn("ci-green", R._fixture_blind(self._cfg(), DiffFacts()))
        self.assertNotIn("ci-green", R._fixture_blind(self._cfg(), DiffFacts(checks=[])))


class TestFixtureCmd(_GitRepo):
    """cmd_fixture — the assert harness exit codes (0 met / 1 violated / 2 can't-run)."""

    def _fx(self, **files):
        for rel, txt in files.items():
            self._w(rel, txt)
        self._w("cogpin.toml", _FX_CFG)

    def test_expect_block_met(self):
        self._fx(**{"leak.diff": _FX_ADD})
        rc, out = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                         expect_block="no-secret")
        self.assertEqual(rc, 0)
        self.assertIn("expectation(s) met", out)

    def test_expect_clean_met(self):
        self._fx(**{"ok.diff": _FX_MODIFY})   # changes keep.py, no SECRET
        rc, out = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "ok.diff"),
                         expect_clean="no-secret")
        self.assertEqual(rc, 0)

    def test_expect_block_violated_returns_1(self):
        self._fx(**{"ok.diff": _FX_MODIFY})
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "ok.diff"),
                           expect_block="no-secret")
        self.assertEqual(rc, 1)
        self.assertIn("did not fire", err)

    def test_expect_clean_violated_returns_1(self):
        self._fx(**{"leak.diff": _FX_ADD})
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="no-secret")
        self.assertEqual(rc, 1)
        self.assertIn("it fired (block)", err)

    def test_unknown_expect_id_returns_2(self):
        self._fx(**{"leak.diff": _FX_ADD})
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="ghost")
        self.assertEqual(rc, 2)
        self.assertIn("not in cogpin.toml", err)

    def test_overlapping_expect_returns_2(self):
        self._fx(**{"leak.diff": _FX_ADD})
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="no-secret", expect_clean="no-secret")
        self.assertEqual(rc, 2)
        self.assertIn("BOTH", err)

    def test_blind_expect_returns_2(self):
        # expecting a `run` check (un-evaluable by a diff fixture) must error, not falsely pass
        self._w("cogpin.toml", _FX_CFG + '[[check]]\nid = "suite"\nkind = "fact"\n'
                'severity = "block"\nlayer = "change"\nprimitive = "run"\ncmd = "true"\n')
        self._w("leak.diff", _FX_ADD)
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="suite")
        self.assertEqual(rc, 2)
        self.assertIn("can't evaluate", err)

    def test_missing_diff_file_returns_2(self):
        self._fx()
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "nope.diff"),
                           expect_block="no-secret")
        self.assertEqual(rc, 2)
        self.assertIn("no such diff file", err)

    def test_no_diff_file_returns_2(self):
        self._fx()
        rc, _, err = _cap3(R.cmd_fixture, self.d, None, expect_block="no-secret")
        self.assertEqual(rc, 2)
        self.assertIn("require --diff-file", err)

    def test_non_git_diff_returns_2(self):
        self._fx(**{"plain.diff": "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"})
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "plain.diff"),
                           expect_block="no-secret")
        self.assertEqual(rc, 2)
        self.assertIn("not a git-format unified diff", err)

    def test_bad_config_returns_2(self):
        self._w("cogpin.toml", "this is not = valid toml [[[")
        self._w("leak.diff", _FX_ADD)
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="no-secret")
        self.assertEqual(rc, 2)
        self.assertIn("cannot load cogpin.toml", err)

    def test_preview_without_expectations_returns_0(self):
        self._fx(**{"leak.diff": _FX_ADD})
        rc, out = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"))
        self.assertEqual(rc, 0)
        self.assertIn("no --expect assertions", out)
        self.assertIn("[BLOCK]", out)   # still reports what fired

    def test_pr_body_fixture_makes_marker_check_evaluable(self):
        # a path_requires(when_marker) is blind WITHOUT a body file, evaluable WITH one
        cfg = (_FX_CFG + '[[check]]\nid = "migrate-docs"\nkind = "fact"\nseverity = "block"\n'
               'primitive = "path_requires"\nwhen_marker = "MIGRATION"\nneed = ["docs"]\n')
        self._w("cogpin.toml", cfg)
        self._w("leak.diff", _FX_ADD)   # touches new.py, NOT docs/
        self._w("body.md", "This PR does a MIGRATION\n")
        # without the body → blind → exit 2
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="migrate-docs")
        self.assertEqual(rc, 2)
        self.assertIn("can't evaluate", err)
        # with the body → marker triggers, docs/ absent → blocks → expectation met
        rc2, out2 = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="migrate-docs",
                           pr_body_file=os.path.join(self.d, "body.md"))
        self.assertEqual(rc2, 0)

    def test_cli_diff_file_routes_to_fixture(self):
        # the `check --diff-file` surface must route through main() to cmd_fixture
        self._fx(**{"leak.diff": _FX_ADD})
        engine = os.path.join(os.path.dirname(R.__file__), "cogpin.py")
        r = subprocess.run([sys.executable, engine, "check", "--cwd", self.d,
                            "--diff-file", os.path.join(self.d, "leak.diff"),
                            "--expect-block", "no-secret"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        r2 = subprocess.run([sys.executable, engine, "check", "--cwd", self.d,
                             "--diff-file", os.path.join(self.d, "leak.diff"),
                             "--expect-clean", "no-secret"], capture_output=True, text=True)
        self.assertEqual(r2.returncode, 1)


# ── PR6 code-review fixes: _fixture_blind must catch EVERY un-evaluable check (no false-clean) ──
# config with one check of every blind class + the diff-only baseline.
_FXB_CFG = (
    'schema = 1\n[repo]\ndefault_branch = "main"\ncode = ["*.py"]\ndocs = ["docs/**"]\n[meta]\n'
    'commit_footer = "Co-Authored-By"\n'
    '[[check]]\nid = "no-secret"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
    'primitive = "forbid_pattern"\npattern = "SECRET"\nscope = "code"\n'          # diff-only
    '[[check]]\nid = "footer"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
    'primitive = "commit_footer"\n'                                              # commit_msgs
    '[[check]]\nid = "conv"\nkind = "fact"\nseverity = "warn"\nlayer = "change"\n'
    'primitive = "require_message_pattern"\npattern = "^(feat|fix)"\n'           # commit_subject default
    '[[check]]\nid = "noverify"\nkind = "fact"\nseverity = "warn"\nlayer = "agent"\n'
    'primitive = "forbid_command"\npattern = "no-verify"\n'                      # agent layer
    '[[check]]\nid = "selfprot"\nkind = "fact"\nseverity = "warn"\nlayer = "both"\n'
    'primitive = "self_protect"\npaths = ["*.py"]\n'                             # both layer, not diff-eval
    '[[check]]\nid = "approve"\nkind = "fact"\nseverity = "warn"\n'
    'primitive = "approval_policy"\nscope = "code"\n'                            # reviews only
    '[[check]]\nid = "prot"\nkind = "fact"\nseverity = "warn"\n'
    'primitive = "protected_path"\nscope = "code"\n'                            # reviews OR approvals
)


class TestFixtureBlindReview(unittest.TestCase):
    """The review found _fixture_blind (copied from _backtest_blind) under-enumerated
    un-evaluable checks → silent false-clean. These pin every class it must now catch."""

    def _cfg(self):
        return R.Config.parse(_FXB_CFG)

    def test_commit_message_checks_blind_without_commit_msg(self):
        blind = R._fixture_blind(self._cfg(), DiffFacts())
        self.assertIn("footer", blind)    # commit_footer reads commit_msgs a diff lacks
        self.assertIn("conv", blind)      # require_message_pattern defaults to commit_subject

    def test_commit_message_checks_evaluable_with_commit_msg(self):
        blind = R._fixture_blind(self._cfg(), DiffFacts(commit_msgs=["feat: x\n\nCo-Authored-By: y"]))
        self.assertNotIn("footer", blind)
        self.assertNotIn("conv", blind)

    def test_agent_layer_check_always_blind(self):
        # forbid_command (agent layer) is never evaluated by run_change → blind even fully fed
        full = DiffFacts(commit_msgs=["x"], pr_body="b", reviews=[], checks=[], approvals=["a"])
        self.assertIn("noverify", R._fixture_blind(self._cfg(), full))

    def test_both_layer_non_diff_primitive_blind(self):
        # self_protect at layer="both" passes the agent-layer guard but _eval_diff returns None
        self.assertIn("selfprot", R._fixture_blind(self._cfg(), DiffFacts(reviews=[])))

    def test_flat_approvals_does_not_unblind_reviews_only_primitives(self):
        # approval_policy reads ONLY facts.reviews; --approvals alone must NOT un-blind it
        blind = R._fixture_blind(self._cfg(), DiffFacts(approvals=["alice"]))
        self.assertIn("approve", blind)            # still blind (no reviews)
        self.assertNotIn("prot", blind)            # protected_path DOES read approvals → evaluable

    def test_approval_policy_evaluable_with_reviews(self):
        self.assertNotIn("approve", R._fixture_blind(self._cfg(), DiffFacts(reviews=[])))

    def test_diff_only_check_never_blind(self):
        self.assertNotIn("no-secret", R._fixture_blind(self._cfg(), DiffFacts()))

    def test_unclassified_primitive_blind_by_default(self):
        # the default-blind property: a future/unlisted primitive must error on --expect, not
        # silently pass. _fixture_evaluable returns False for anything not explicitly evaluable.
        c = Check(id="x", primitive="judge", kind="advisory", severity="judge", layer="change")
        self.assertFalse(R._fixture_evaluable(c, DiffFacts()))


class TestFixtureReviewFixes(_GitRepo):
    """End-to-end cmd_fixture coverage for the review fixes."""

    def _w_cfg(self, extra=""):
        self._w("cogpin.toml", _FXB_CFG + extra)

    def test_expect_commit_footer_blind_without_msg(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_block="footer")
        self.assertEqual(rc, 2)
        self.assertIn("can't evaluate", err)

    def test_commit_msg_unblinds_footer_and_asserts(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        # a message with NO footer → commit_footer fires (block) → expect-block met
        rc, out = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                         expect_block="footer", commit_msg="just a subject, no footer")
        self.assertEqual(rc, 0)
        # a message WITH the footer → commit_footer clean → expect-clean met
        rc2, _ = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                        expect_clean="footer", commit_msg="subject\n\nCo-Authored-By: y")
        self.assertEqual(rc2, 0)

    def test_expect_agent_layer_check_errors(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="noverify")
        self.assertEqual(rc, 2)
        self.assertIn("can't evaluate", err)

    def test_flat_approvals_does_not_falsely_clean_approval_policy(self):
        # the headline false-clean: --approvals x must NOT make approval_policy "clean"
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)   # touches code → approval_policy would want approval
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="approve", approvals="alice")
        self.assertEqual(rc, 2)         # blind, not a bogus exit 0
        self.assertIn("can't evaluate", err)

    def test_reviews_file_unblinds_approval_policy(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        # an empty reviews array = a PR with zero approvals → approval_policy FIRES on a code change
        self._w("reviews.json", "[]")
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="approve", reviews_file=os.path.join(self.d, "reviews.json"))
        self.assertEqual(rc, 1)         # evaluated AND fired → expect-clean violated (not blind)

    def test_checks_file_unblinds_require_checks_green(self):
        self._w_cfg('[[check]]\nid = "ci"\nkind = "fact"\nseverity = "block"\nlayer = "change"\n'
                    'primitive = "require_checks_green"\nneed = ["build"]\n')
        self._w("leak.diff", _FX_ADD)
        self._w("checks.json", '[{"name": "build", "conclusion": "failure"}]')
        rc, _ = _quiet(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                       expect_block="ci", checks_file=os.path.join(self.d, "checks.json"))
        self.assertEqual(rc, 0)         # build failed → require_checks_green blocks → expect met

    def test_garbled_reviews_file_errors_not_coerced(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        self._w("bad.json", "{not json")
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="no-secret", reviews_file=os.path.join(self.d, "bad.json"))
        self.assertEqual(rc, 2)
        self.assertIn("cannot parse --reviews-file", err)

    def test_missing_reviews_file_errors(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="no-secret", reviews_file=os.path.join(self.d, "nope.json"))
        self.assertEqual(rc, 2)
        self.assertIn("no such --reviews-file", err)

    def test_missing_pr_body_file_errors(self):
        self._w_cfg()
        self._w("leak.diff", _FX_ADD)
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "leak.diff"),
                           expect_clean="no-secret", pr_body_file=os.path.join(self.d, "nope.md"))
        self.assertEqual(rc, 2)
        self.assertIn("no such --pr-body-file", err)

    def test_expect_block_against_warn_check_fails_with_reason(self):
        # a block→warn demotion is a real regression a fixture should catch (exit 1, not 2)
        self._w("cogpin.toml", _FX_CFG)   # no-todo is severity=warn
        self._w("todo.diff", "diff --git a/x.py b/x.py\nnew file mode 100644\n--- /dev/null\n"
                "+++ b/x.py\n@@ -0,0 +1 @@\n+x = 1  # TODO fix\n")
        rc, _, err = _cap3(R.cmd_fixture, self.d, os.path.join(self.d, "todo.diff"),
                           expect_block="no-todo")
        self.assertEqual(rc, 1)
        self.assertIn("fired as warn, not block", err)


class TestFromUnifiedDiffEdge(unittest.TestCase):
    """Parser edges the first pass under-covered (per review): CRLF, exact multi-file, chmod."""

    def test_crlf_fixture_parses(self):
        crlf = (_FX_ADD + _FX_MODIFY).replace("\n", "\r\n")
        f = DiffFacts.from_unified_diff(crlf)
        self.assertIn(("new.py", "API_SECRET = 1"), f.added)   # \r stripped, content intact
        self.assertIn(("keep.py", "old_line = 2"), f.removed)
        self.assertIn(("A", "new.py"), f.changed)

    def test_multifile_changed_exact(self):
        f = DiffFacts.from_unified_diff(_FX_ADD + _FX_MODIFY + _FX_DELETE)
        self.assertEqual(sorted(f.changed),
                         sorted([("A", "new.py"), ("M", "keep.py"), ("D", "gone.py")]))

    def test_mode_only_chmod_reported(self):
        # a pure chmod emits no +++/---/@@/Binary — path falls back to the `diff --git` line
        chmod = "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n"
        self.assertEqual(DiffFacts.from_unified_diff(chmod).changed, [("M", "run.sh")])


class TestMonorepoExample(unittest.TestCase):
    """#19 Ask-2: the polyglot monorepo example's per-subtree scopes are PROVEN by fixtures —
    `validate` can't catch a glob typo (no repo access), only a fixture can. This is the
    anti-under-coverage gate the example must ship with (not `validate --config` alone)."""

    def setUp(self):
        root = os.path.dirname(os.path.abspath(R.__file__))   # cogpin.py sits at the repo root
        self.mono = os.path.join(root, "examples", "monorepo")
        if not os.path.exists(os.path.join(self.mono, "cogpin.toml")):
            self.skipTest("examples/monorepo not present")

    def _fx(self, name):
        return os.path.join(self.mono, "fixtures", name)

    def test_config_validates(self):
        with open(os.path.join(self.mono, "cogpin.toml"), encoding="utf-8") as fh:
            cfg = Config.parse(fh.read())   # parses + passes the moat (raises ConfigError otherwise)
        ids = {c.id for c in cfg.checks}
        self.assertTrue({"no-rust-dbg", "no-js-console", "no-py-debugger"} <= ids)

    def test_rust_dbg_blocks_in_rust_subtree(self):
        rc, _ = _quiet(R.cmd_fixture, self.mono, self._fx("rust-dbg.diff"), expect_block="no-rust-dbg")
        self.assertEqual(rc, 0)

    def test_js_console_blocks_every_composed_subtree(self):
        # no-js-console's scope COMPOSES 4 literal globs (site+extension × .ts+.tsx). Each needs a
        # single-subtree fixture, else a typo in any one glob silently under-covers with no failure.
        for fx in ("js-console.diff", "js-console-site-ts.diff",
                   "js-console-site-tsx.diff", "js-console-ext-tsx.diff"):
            with self.subTest(fixture=fx):
                rc, _ = _quiet(R.cmd_fixture, self.mono, self._fx(fx), expect_block="no-js-console")
                self.assertEqual(rc, 0)

    def test_py_debugger_blocks_in_scripts_subtree(self):
        rc, _ = _quiet(R.cmd_fixture, self.mono, self._fx("py-debugger.diff"), expect_block="no-py-debugger")
        self.assertEqual(rc, 0)

    def test_cross_subtree_isolation(self):
        # a Rust debug token living in the TS tree (and a JS token in the Rust tree) must trip
        # NEITHER per-subtree rule — proof the literal-glob scoping actually confines each rule
        rc, _ = _quiet(R.cmd_fixture, self.mono, self._fx("cross-isolation.diff"),
                       expect_clean="no-rust-dbg,no-js-console")
        self.assertEqual(rc, 0)
