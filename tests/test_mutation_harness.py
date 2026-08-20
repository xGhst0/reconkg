"""The harness that checks the tests needs checking too.

An equivalent-mutant registry is a list of claims that certain mutants cannot
be killed. Every entry is a hole in the mutation score, deliberately made and
deliberately justified. The failure mode is not a wrong justification -- those
are visible and arguable. It is an entry that stops matching the thing it
exempts, and there are two directions:

    fails closed   the exemption stops matching anything, the mutant reappears
                   as a survivor, the score drops, somebody re-justifies work
                   already done. Annoying.

    fails open     the exemption matches a DIFFERENT mutant and silently
                   excuses a real survivor, in the one tool whose entire job
                   is noticing what the tests do not. Not annoying.

The registry was keyed on line number until both happened: four exploitdb
entries un-matched when the file grew above them (100% -> 86.2%, no behaviour
changed), and a rekey named `_confidence` for a mutant that lives in
`_service_entry`. It is keyed on function name now, and these tests exist so
the next drift is a red test rather than a number nobody questions.
"""

from __future__ import annotations

import pytest

from audit.mutation import (EQUIVALENT, TARGETS, _mutatable_names,
                            stale_exemptions)


def test_no_exemption_names_a_function_that_is_not_mutated():
    """The regression. A renamed or mistyped function leaves an exemption
    that reads like coverage and provides none."""
    problems = stale_exemptions()
    assert problems == [], "stale equivalent-mutant exemptions:\n  " + \
        "\n  ".join(problems)


def test_every_exemption_carries_a_justification():
    """An unexplained exemption is indistinguishable from a suppressed
    failure. The text is the only thing that lets a reviewer disagree."""
    for key, reason in EQUIVALENT.items():
        assert len(reason) > 60, f"{key} is exempted without an argument"


def test_every_exemption_is_a_three_part_key():
    """Guards the rekey itself: a leftover `(module, line, description)`
    tuple would never match anything and would fail open on the next audit."""
    for key in EQUIVALENT:
        assert len(key) == 3, f"{key} is not (module, function, description)"
        module, function, description = key
        assert isinstance(function, str), (
            f"{key} still keys on a line number; exemptions drift when the "
            "file above them changes")


def test_every_target_module_exists_and_lists_real_tests():
    from pathlib import Path

    from audit.mutation import PACKAGE, ROOT

    for module, (functions, tests) in TARGETS.items():
        assert (PACKAGE / f"{module}.py").is_file(), f"no such module {module}"
        assert functions, f"{module} lists no functions to mutate"
        for test in tests:
            assert (ROOT / test).is_file(), (
                f"{module} points at {test}, which does not exist -- the "
                "harness would report a gap that is really a typo")


def test_nested_functions_count_as_mutatable():
    """`rank` contains a `key` closure and mutating the parent mutates it, so
    an exemption naming `key` is legitimate even though TARGETS cannot list
    it. Without this the guard cries wolf at every comparator."""
    names = _mutatable_names("exploitdb", TARGETS["exploitdb"][0])
    assert "key" in names
    assert "rank" in names


def test_an_unknown_module_is_reported_not_ignored():
    original = dict(EQUIVALENT)
    EQUIVALENT[("nosuchmodule", "f", "x -> y")] = "a" * 80
    try:
        assert any("nosuchmodule" in p for p in stale_exemptions())
    finally:
        EQUIVALENT.clear()
        EQUIVALENT.update(original)


def test_an_unknown_function_is_reported_not_ignored():
    original = dict(EQUIVALENT)
    EQUIVALENT[("exploitdb", "no_such_function", "x -> y")] = "a" * 80
    try:
        problems = stale_exemptions()
        assert any("no_such_function" in p for p in problems)
    finally:
        EQUIVALENT.clear()
        EQUIVALENT.update(original)
