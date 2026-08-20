"""Targeted mutation testing for the decision logic.

The question a passing suite cannot answer: do these tests *constrain* the
code, or merely execute it? Mutation testing answers it by breaking the code
on purpose and checking the tests notice. A mutant that survives marks a line
whose behaviour nothing actually pins.

Scope is deliberate. A whole-repo `mutmut` run takes hours and spends most of
them on plumbing where a survivor means nothing. This targets the pure
decision functions -- version comparison, lead scoring, confidence
arithmetic, scope matching, maturity inference, the rate-limit bucket --
because those are where a silent wrong answer is most expensive: a mutant
that survives in `compare_versions` is a CVE that quietly stops matching.

Usage:
    python audit/mutation.py                # all targets
    python audit/mutation.py vulnref        # one module
    python audit/mutation.py --list         # show the plan
"""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "reconkg"

# module -> (functions to mutate, tests that should catch it)
TARGETS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "vulnref": (
        ("compare_versions", "version_satisfies", "score",
         "_corroboration_bonus", "build_leads"),
        ("tests/test_reconkg.py", "tests/test_integrity.py",
         "tests/test_final_round.py", "tests/test_exact_behaviour.py",
         # The signals and backport paths in build_leads live behind these
         # two files. Omitting them mutated code no listed test exercised,
         # which reads as a test gap and is really a harness gap.
         "tests/test_feeds.py", "tests/test_cpe_matching.py"),
    ),
    "exploitdb": (
        # The sanitising and the ranking. `safe_edb_id` is the one that
        # matters most: it is the gate between a downloaded CSV column and
        # an argument in a command an operator will paste.
        ("safe_edb_id", "clean_text", "platform_matches", "rank"),
        ("tests/test_exploitdb.py",),
    ),
    "commands": (
        # The safety controls. `coerce_category` and `_refuse_firing_verbs`
        # are the two the red cell broke (RC-31, RC-32), so a surviving
        # mutant in either is a real gap rather than a curiosity.
        ("coerce_category", "_worst_category", "_refuse_firing_verbs",
         "validate_module_path", "validate_script_name", "filter_commands",
         "assert_no_composed_exploits"),
        ("tests/test_round9_redcell.py", "tests/test_final_round.py",
         "tests/test_commands.py", "tests/test_ui.py",
         # `validate_script_name` is corpus three's gate between a script.db
         # row and `nmap --script <name>`; the tests that constrain it live
         # with the corpus that produces the rows.
         "tests/test_scriptdb.py"),
    ),
    "scriptdb": (
        # The parser and the mapping. `safe_script_name` is the one that
        # matters most -- it is the gate between third-party Lua source and
        # an argument in a command an operator will paste -- and
        # `clean_category` decides whether a tag reaches `_worst_category`
        # at all, which is where RC-35 lived.
        ("safe_script_name", "clean_category", "parse_entry",
         "service_prefixes", "cve_fragments", "script_matches"),
        ("tests/test_scriptdb.py",),
    ),
    "models": (
        ("observe", "decay", "contradictions", "_append_bounded"),
        ("tests/test_reconkg.py", "tests/test_audit_regressions.py",
         "tests/test_scope_ratelimit.py", "tests/test_exact_behaviour.py"),
    ),
    "auth": (
        ("_scope_matches", "may_touch", "satisfies", "validate_address"),
        ("tests/test_authz.py", "tests/test_scope_ratelimit.py",
         "tests/test_audit_regressions.py", "tests/test_exact_behaviour.py"),
    ),
    "catalog": (
        ("infer_maturity", "normalise_cve"),
        ("tests/test_catalog_import.py", "tests/test_integrity.py",
         "tests/test_exact_behaviour.py"),
    ),
    "sources": (
        ("effective_confidence", "reliability"),
        ("tests/test_audit_regressions.py", "tests/test_exact_behaviour.py"),
    ),
    "ratelimit": (
        ("take", "retry_after", "check"),
        ("tests/test_scope_ratelimit.py", "tests/test_exact_behaviour.py"),
    ),
    "cpe": (
        ("parse", "compare_attribute", "attribute_matches", "matches",
         "_within_window", "looks_backported", "infer_cpe", "weight"),
        ("tests/test_cpe_matching.py", "tests/test_feeds.py"),
    ),
    "feeds": (
        ("_best_cvss", "_cpe_match", "_cpe_ranges", "_nvd_entry", "factor",
         "explain", "probability", "_read_metadata"),
        ("tests/test_feeds.py",),
    ),
    "importers": (
        ("unsafe_doctype_reason", "_service_entry", "_normalise_state"),
        ("tests/test_golden_nmap.py", "tests/test_catalog_import.py",
         "tests/test_audit_round2.py", "tests/test_exact_behaviour.py"),
    ),
}

# Keyed on (module, FUNCTION, description) -- deliberately not on the line
# number, which is what this was keyed on until the exploitdb corpus grew a
# few lines above `rank` and four registered equivalents silently became
# survivors. The score fell from 100% to 86.2% with no behaviour changed.
#
# The direction that did NOT happen is the reason this had to be fixed rather
# than re-numbered: a line-keyed exemption drifts. Insert eight lines above a
# registered equivalent and the exemption lands on whatever mutant now
# occupies that line -- excusing a real survivor, silently, in the one tool
# whose entire job is to notice things tests do not.
#
# A function name is stable across edits that do not touch the function, and
# when it does change the exemption disappears rather than moving somewhere
# it does not belong. Failing open here is not an option; failing closed
# costs one re-justification.
EQUIVALENT: dict[tuple[str, str, str], str] = {
    ("exploitdb", "key", "1 -> 2"):
        "`0 if record.verified else 1` inside a sort key. The tuple is "
        "compared element-wise and only the relative order of the two "
        "branches matters, so any positive constant sorts identically to 1. "
        "No input can distinguish them, and a test asserting the literal "
        "would be asserting an implementation detail rather than an "
        "ordering. Covers all three `else 1` branches in the same sort key "
        "-- they were three line-keyed entries before this registry moved to "
        "function keys, and they collapse to one because the justification "
        "is identical for each.",
    ("models", "_append_bounded", "Gt -> GtE"):
        "At len == cap the branch computes head+tail == cap and elides zero, "
        "so `>` and `>=` produce identical state. Genuinely equivalent; no "
        "test can distinguish them.",
    ("catalog", "infer_maturity", "Gt -> GtE"):
        "inferred.weight > declared.weight -- no two ExploitMaturity members "
        "share a weight, so equal weight means the same member and both "
        "branches return the same object. Distinguishable only if the weight "
        "table ever gains a collision, which would be a bug in itself.",
    ("importers", "_service_entry", "3 -> 4"):
        "round(confidence, 3) -- conf is parsed as an integer and divided by "
        "10, so every reachable value has at most one decimal place. The "
        "rounding is defensive against a future change to that arithmetic and "
        "cannot be observed today.",
    ("models", "observe", "1.0 -> 2.0"):
        "min(round(new, 4), 1.0) -- noisy-OR of two values in [0,1] never "
        "exceeds 1.0 and the max() branch is bounded by its inputs, so the "
        "clamp is unreachable defensive code. Kept deliberately; raising the "
        "bound cannot change an outcome.",
}
"""Mutants that cannot be killed because they do not change behaviour.

Listing them with a justification is the honest alternative to either
chasing an unreachable 100% or quietly counting them as survivors. Each entry
is a claim that can be checked: if you can write a test that kills one, the
justification was wrong and the entry should go.
"""

_CMP_SWAP = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.In: ast.NotIn,
    ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}
_BIN_SWAP = {
    ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.Div,
    ast.Div: ast.Mult, ast.Mod: ast.Mult,
}
_BOOL_SWAP = {ast.And: ast.Or, ast.Or: ast.And}


@dataclass
class Mutant:
    module: str
    function: str
    line: int
    description: str
    source: str


@dataclass
class Report:
    killed: list[Mutant] = field(default_factory=list)
    survived: list[Mutant] = field(default_factory=list)
    errored: list[Mutant] = field(default_factory=list)
    equivalent: list[Mutant] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (len(self.killed) + len(self.survived) + len(self.errored)
                + len(self.equivalent))

    @property
    def score(self) -> float:
        """Equivalent mutants are excluded from the denominator, not counted
        as kills. Counting them as kills would inflate the number; counting
        them as survivors would imply a test gap that does not exist."""
        scored = len(self.killed) + len(self.survived)
        return round(100.0 * len(self.killed) / scored, 1) if scored else 0.0


class _Mutator(ast.NodeTransformer):
    """Applies exactly one mutation, identified by index."""

    def __init__(self, target_index: int, functions: tuple[str, ...]) -> None:
        self.target_index = target_index
        self.functions = functions
        self.counter = -1
        self.applied: tuple[int, str] | None = None
        self._depth: list[str] = []

    # -- scope tracking ----------------------------------------------------- #

    def visit_FunctionDef(self, node):  # noqa: N802
        self._depth.append(node.name)
        node = self.generic_visit(node)
        self._depth.pop()
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    @property
    def _in_scope(self) -> bool:
        return any(name in self.functions for name in self._depth)

    def _take(self, description: str, line: int) -> bool:
        if not self._in_scope:
            return False
        self.counter += 1
        if self.counter != self.target_index:
            return False
        self.applied = (line, description)
        return True

    # -- mutations ---------------------------------------------------------- #

    def visit_Compare(self, node):  # noqa: N802
        node = self.generic_visit(node)
        if len(node.ops) == 1 and type(node.ops[0]) in _CMP_SWAP:
            old = type(node.ops[0])
            if self._take(f"{old.__name__} -> {_CMP_SWAP[old].__name__}",
                          node.lineno):
                node.ops = [_CMP_SWAP[old]()]
        return node

    def visit_BinOp(self, node):  # noqa: N802
        node = self.generic_visit(node)
        old = type(node.op)
        if old in _BIN_SWAP:
            if self._take(f"{old.__name__} -> {_BIN_SWAP[old].__name__}",
                          node.lineno):
                node.op = _BIN_SWAP[old]()
        return node

    def visit_BoolOp(self, node):  # noqa: N802
        node = self.generic_visit(node)
        old = type(node.op)
        if self._take(f"{old.__name__} -> {_BOOL_SWAP[old].__name__}",
                      node.lineno):
            node.op = _BOOL_SWAP[old]()
        return node

    def visit_UnaryOp(self, node):  # noqa: N802
        node = self.generic_visit(node)
        if isinstance(node.op, ast.Not):
            if self._take("drop `not`", node.lineno):
                return node.operand
        return node

    def visit_Constant(self, node):  # noqa: N802
        if isinstance(node.value, bool):
            if self._take(f"{node.value} -> {not node.value}", node.lineno):
                return ast.copy_location(ast.Constant(value=not node.value),
                                         node)
        elif isinstance(node.value, (int, float)) and not isinstance(
                node.value, bool):
            if self._take(f"{node.value!r} -> {node.value + 1!r}",
                          node.lineno):
                return ast.copy_location(
                    ast.Constant(value=node.value + 1), node)
        return node


def stale_exemptions() -> list[str]:
    """Registered equivalents that no longer name a function under test.

    Two ways this list becomes non-empty, and both happened while rekeying
    this registry: a function is renamed, or an entry names a function that
    was never in TARGETS to begin with (`_confidence` for a mutant that lives
    in `_service_entry`). Either way the exemption is dead weight that reads
    like coverage, and the next person to see the score drop will re-justify
    a mutant that already had a justification.
    """
    problems = []
    for module, function, description in EQUIVALENT:
        listed = TARGETS.get(module)
        if listed is None:
            problems.append(
                f"{module}.{function}: module is not in TARGETS at all")
        elif function not in _mutatable_names(module, listed[0]):
            problems.append(
                f"{module}.{function} ({description}): not a mutated "
                f"function. TARGETS lists {', '.join(listed[0])}")
    return problems


def _mutatable_names(module: str, listed: tuple[str, ...]) -> set[str]:
    """Listed functions plus anything nested inside them.

    `rank` contains a `key` closure, and mutating `rank` mutates the closure
    too -- so `key` is a legitimate exemption target that never appears in
    TARGETS. Walking for nested definitions is the difference between a guard
    that catches renames and one that cries wolf at every comparator.
    """
    names = set(listed)
    try:
        tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return names

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name in listed:
            for inner in ast.walk(node):
                if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(inner.name)
    return names


def generate(module: str, functions: tuple[str, ...]) -> list[Mutant]:
    source = (PACKAGE / f"{module}.py").read_text()
    tree = ast.parse(source)

    # First pass: how many mutation sites exist.
    probe = _Mutator(-1, functions)
    probe.visit(ast.parse(source))
    count = probe.counter + 1

    mutants: list[Mutant] = []
    for index in range(count):
        mutator = _Mutator(index, functions)
        mutated = mutator.visit(ast.parse(source))
        if mutator.applied is None:
            continue
        line, description = mutator.applied
        ast.fix_missing_locations(mutated)
        try:
            text = ast.unparse(mutated)
        except Exception:
            continue
        mutants.append(Mutant(module, _enclosing(tree, line), line,
                              description, text))
    return mutants


def _enclosing(tree: ast.AST, line: int) -> str:
    best = "?"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end:
                best = node.name
    return best


class HarnessBroken(RuntimeError):
    """The unmutated baseline did not pass, so no result means anything."""


def run(module: str, only: str | None = None, limit: int | None = None
        ) -> Report:
    functions, tests = TARGETS[module]
    mutants = generate(module, functions)
    if limit:
        mutants = mutants[:limit]

    report = Report()
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp) / "work"
        shutil.copytree(ROOT, workspace,
                        ignore=shutil.ignore_patterns(
                            "__pycache__", "*.pyc", ".pytest_cache", "*.sqlite"))
        target_file = workspace / "reconkg" / f"{module}.py"
        pristine = target_file.read_text()

        # Baseline first. Without this the harness cannot distinguish "the
        # test suite caught the mutation" from "the test command never ran",
        # and every mutant scores as killed on a startup failure -- which is
        # exactly what happened, producing a meaningless 100%.
        baseline = _run_tests(workspace, tests)
        if baseline != "pass":
            raise HarnessBroken(
                f"baseline for {module} returned {baseline!r}, expected "
                f"'pass'. Every mutant would score as killed. Tests: "
                f"{', '.join(tests)}")

        for index, mutant in enumerate(mutants, 1):
            target_file.write_text(mutant.source)
            for cache in workspace.rglob("__pycache__"):
                shutil.rmtree(cache, ignore_errors=True)
            key = (module, mutant.function, mutant.description)
            if key in EQUIVALENT:
                report.equivalent.append(mutant)
                print(f"  [{index}/{len(mutants)}] {mutant.function}:"
                      f"{mutant.line} {mutant.description:34} -> equivalent",
                      flush=True)
                continue

            outcome = _run_tests(workspace, tests)
            if outcome == "fail":
                report.killed.append(mutant)
            elif outcome == "pass":
                report.survived.append(mutant)
            else:
                report.errored.append(mutant)
            print(f"  [{index}/{len(mutants)}] {mutant.function}:{mutant.line} "
                  f"{mutant.description:34} -> "
                  f"{'killed' if outcome == 'fail' else outcome}",
                  flush=True)
            target_file.write_text(pristine)
    return report


def _run_tests(workspace: Path, tests: tuple[str, ...]) -> str:
    """Run the selected tests in `workspace`. -> pass | fail | error | timeout.

    The environment is inherited, not constructed. Building a minimal env by
    hand dropped the user site-packages that pytest lives in, so the command
    exited non-zero without running a single test and the caller read that as
    a kill.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(workspace)
    env["RECONKG_TOKENS"] = "harness:operator:" + "x" * 24
    env.pop("PYTEST_ADDOPTS", None)
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-x", "-q", "--no-header",
             "-p", "no:cacheprovider", *tests],
            cwd=workspace, capture_output=True, timeout=180, env=env,
        )
    except subprocess.TimeoutExpired:
        return "timeout"          # an infinite loop counts as detected
    stdout = completed.stdout.decode(errors="replace")
    if completed.returncode == 0:
        return "pass"
    # A genuine kill reports failed tests. Anything else -- collection error,
    # missing interpreter, import failure -- is the harness misbehaving and
    # must not be counted as evidence about the test suite.
    if " failed" in stdout or "assert" in stdout:
        return "fail"
    return "error"


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for module, (functions, tests) in TARGETS.items():
            print(f"{module:12} {len(generate(module, functions)):4} mutants  "
                  f"functions={', '.join(functions)}")
        return 0

    limit = None
    for arg in argv:
        if arg.startswith("--limit="):
            limit = int(arg.split("=", 1)[1])
    modules = [a for a in argv if a in TARGETS] or list(TARGETS)

    overall = Report()
    started = time.time()
    for module in modules:
        print(f"\n=== {module} ===")
        report = run(module, limit=limit)
        overall.killed += report.killed
        overall.survived += report.survived
        overall.errored += report.errored
        overall.equivalent += report.equivalent
        print(f"  {module}: {len(report.killed)} killed, "
              f"{len(report.survived)} survived, "
              f"{len(report.equivalent)} equivalent, score {report.score}%")

    print(f"\n{'=' * 70}")
    print(f"mutants {overall.total} | killed {len(overall.killed)} | "
          f"survived {len(overall.survived)} | "
          f"equivalent {len(overall.equivalent)} | "
          f"errored {len(overall.errored)}")
    print(f"mutation score: {overall.score}%  "
          f"({time.time() - started:.0f}s)")
    if overall.survived:
        print("\nSURVIVORS -- behaviour no test pins:")
        for mutant in overall.survived:
            print(f"  {mutant.module}.{mutant.function}:{mutant.line}  "
                  f"{mutant.description}")
    return 1 if overall.survived else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
