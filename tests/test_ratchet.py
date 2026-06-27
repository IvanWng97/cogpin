"""Stdlib-only test suite for ratchet (no pytest dependency — `python3 -m unittest`)."""

import os
import sys
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
    forbid_pattern,
    has_block,
    marker_present,
    path_requires,
    protected_path,
    run_change,
    run_command_gate,
    secret_scan,
    _glob_to_re,
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


if __name__ == "__main__":
    unittest.main()
