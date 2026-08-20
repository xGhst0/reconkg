"""Command classification and the policy built on it.

The red cell's file (test_round9_redcell.py) attacks these controls. This one
pins their ordinary behaviour, which is the part a refactor is most likely to
quietly change: which category wins when a script declares several, what the
default tier actually contains, and whether a rationale survives to the
analyst who has to judge the suggestion.
"""

from __future__ import annotations

import shlex

import pytest

from reconkg.commands import (Category, Command, DEFAULT_CATEGORIES,
                              NEVER_COMPOSED, OPT_IN_CATEGORIES,
                              BoundaryViolation, _worst_category,
                              assert_no_composed_exploits, filter_commands,
                              http_probe_commands, metasploit_commands,
                              nmap_commands, nuclei_commands,
                              searchsploit_commands)


# --------------------------------------------------------------------------- #
# The tiers themselves
# --------------------------------------------------------------------------- #

def test_the_three_tiers_do_not_overlap():
    """Overlap would make the policy order-dependent, and the order is an
    implementation detail nobody should have to know."""
    assert not (DEFAULT_CATEGORIES & OPT_IN_CATEGORIES)
    assert not (DEFAULT_CATEGORIES & NEVER_COMPOSED)
    assert not (OPT_IN_CATEGORIES & NEVER_COMPOSED)


def test_every_category_is_in_exactly_one_tier():
    """A category in no tier is a silent gap: `filter_commands` would drop it
    with no policy ever having been stated about it."""
    covered = DEFAULT_CATEGORIES | OPT_IN_CATEGORIES | NEVER_COMPOSED
    missing = set(Category) - covered
    assert missing == set(), f"uncategorised: {sorted(c.value for c in missing)}"


def test_unclassified_sits_with_the_opt_in_tier_not_the_default_one():
    """The nuclei finding in COMMAND-MAPPING.md in one assertion. A source
    that does not classify itself must not be assumed benign."""
    assert Category.UNCLASSIFIED in OPT_IN_CATEGORIES
    assert Category.UNCLASSIFIED not in DEFAULT_CATEGORIES


# --------------------------------------------------------------------------- #
# _worst_category
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("declared,expected", [
    (["safe"], Category.SAFE),
    (["safe", "vuln"], Category.VULN),
    (["default", "safe", "discovery"], Category.SAFE),
    # Topic labels only: no safety claim was made, so none is assumed.
    (["default", "discovery"], Category.UNCLASSIFIED),
    (["auth"], Category.UNCLASSIFIED),
    (["discovery", "intrusive"], Category.INTRUSIVE),
    (["intrusive", "exploit"], Category.EXPLOIT),
    (["vuln", "intrusive"], Category.VULN),
    (["safe", "dos"], Category.DOS),
    (["discovery", "version"], Category.VERSION),
    (["malware", "safe"], Category.SAFE),
    (["external", "safe"], Category.EXTERNAL),
    ([], Category.UNCLASSIFIED),
])
def test_the_most_restrictive_declared_category_wins(declared, expected):
    assert _worst_category(declared) == expected


def test_a_benign_tag_cannot_launder_a_dangerous_one():
    """Taking the most permissive label would let `safe` whitewash whatever
    sits beside it. Real NSE scripts carry several categories at once."""
    assert _worst_category(["safe", "discovery", "exploit"]) == Category.EXPLOIT


def test_case_and_whitespace_do_not_change_the_verdict():
    assert _worst_category([" VULN ", "Safe"]) == Category.VULN


# --------------------------------------------------------------------------- #
# The Command type
# --------------------------------------------------------------------------- #

def test_a_composed_command_renders_shell_ready():
    command = Command(tool="nmap", category=Category.SAFE,
                      argv=("nmap", "-p", "80", "10.0.0.1"))
    assert shlex.split(command.rendered) == list(command.argv)


def test_a_command_with_neither_argv_nor_reference_is_refused():
    """It would render as an empty suggestion, which tells nobody anything."""
    with pytest.raises(ValueError):
        Command(tool="nmap", category=Category.SAFE)


@pytest.mark.parametrize("category", sorted(NEVER_COMPOSED,
                                            key=lambda c: c.value))
def test_no_never_composed_category_accepts_an_argv(category):
    with pytest.raises(BoundaryViolation):
        Command(tool="x", category=category, argv=("x",))


@pytest.mark.parametrize("category", sorted(NEVER_COMPOSED,
                                            key=lambda c: c.value))
def test_a_never_composed_category_is_still_reportable_by_name(category):
    """Suppressing it entirely would withhold the fact that a working exploit
    exists, which is most of what tells an analyst how urgent a lead is."""
    command = Command(tool="nmap", category=category,
                      reference="http-shellshock", source="script.db")
    assert not command.composed
    assert "http-shellshock" in command.rendered


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def test_searchsploit_is_safe_because_it_never_touches_the_target():
    for command in searchsploit_commands("CVE-2021-41773", "Apache", "2.4.49"):
        assert command.category is Category.SAFE
        assert command.composed


def test_searchsploit_adds_a_product_search_only_when_there_is_a_product():
    assert len(searchsploit_commands("CVE-2021-41773")) == 1
    assert len(searchsploit_commands("CVE-2021-41773", "Apache")) == 2


def test_nmap_version_recheck_is_emitted_by_default():
    commands = nmap_commands("10.0.0.1", 80)
    assert commands[0].category is Category.VERSION
    assert commands[0].category in DEFAULT_CATEGORIES


def test_an_nmap_script_takes_the_category_script_db_declares():
    commands = nmap_commands("10.0.0.1", 80, scripts=("http-vuln-cve2017-5638",),
                             categories={"http-vuln-cve2017-5638":
                                         ["exploit", "vuln"]})
    scripted = commands[-1]
    assert scripted.category is Category.EXPLOIT
    assert not scripted.composed, (
        "an exploit-category NSE script must be named, not aimed")


def test_an_unlisted_nmap_script_is_unclassified_not_assumed_safe():
    commands = nmap_commands("10.0.0.1", 80, scripts=("mystery-script",))
    assert commands[-1].category is Category.UNCLASSIFIED


def test_nuclei_is_unclassified_because_nuclei_does_not_classify():
    command = nuclei_commands("CVE-2026-0770", "10.0.0.1")[0]
    assert command.category is Category.UNCLASSIFIED
    assert "exploiting" in command.rationale.lower()


def test_tls_adds_a_certificate_probe_and_plain_http_does_not():
    assert len(http_probe_commands("10.0.0.1", 80)) == 1
    assert len(http_probe_commands("10.0.0.1", 443, tls=True)) == 2


def test_metasploit_stops_at_show_options():
    command = metasploit_commands("exploit/multi/http/x", "10.0.0.1", 80)[0]
    steps = [s.strip() for s in shlex.split(command.rendered)[-1].split(";")]
    assert steps[-1] == "show options"


def test_metasploit_omits_rport_when_there_is_no_port():
    command = metasploit_commands("exploit/multi/http/x", "10.0.0.1")[0]
    assert "RPORT" not in command.rendered


# --------------------------------------------------------------------------- #
# filter_commands
# --------------------------------------------------------------------------- #

def _sample() -> list[Command]:
    return [
        Command(tool="searchsploit", category=Category.SAFE,
                argv=("searchsploit", "--cve", "CVE-1")),
        Command(tool="nmap", category=Category.VULN,
                argv=("nmap", "--script", "vuln", "10.0.0.1")),
        Command(tool="nmap", category=Category.EXPLOIT,
                reference="http-shellshock"),
    ]


def test_the_default_filter_withholds_opt_in_commands():
    kept = filter_commands(_sample())
    assert [c.category for c in kept if c.composed] == [Category.SAFE]


def test_opting_in_admits_them():
    kept = filter_commands(_sample(), allowed=[Category.SAFE, Category.VULN])
    assert {c.category for c in kept if c.composed} == {Category.SAFE,
                                                        Category.VULN}


def test_named_commands_survive_every_filter():
    """Including the empty one. Hiding the existence of a working exploit
    from an analyst is withholding the thing that sets their priority."""
    for allowed in ([], [Category.SAFE], list(Category)):
        kept = filter_commands(_sample(), allowed=allowed)
        assert any(not c.composed for c in kept), f"allowed={allowed}"


def test_an_empty_allow_list_is_not_read_as_no_preference():
    """A registry that became falsy and got replaced by the global default is
    a bug this codebase has already had once."""
    kept = filter_commands(_sample(), allowed=[])
    assert [c for c in kept if c.composed] == []


def test_the_backstop_passes_a_clean_set():
    assert_no_composed_exploits(_sample())


# --------------------------------------------------------------------------- #
# Rationale
# --------------------------------------------------------------------------- #

def test_every_builder_explains_itself():
    """A suggestion with no reasoning is one an analyst can only take on
    faith, and taking generated suggestions on faith is the failure mode this
    whole ledger exists to avoid."""
    everything = (searchsploit_commands("CVE-1", "Apache", "2.4")
                  + nmap_commands("10.0.0.1", 80, scripts=("vuln",),
                                  categories={"vuln": ["vuln"]})
                  + http_probe_commands("10.0.0.1", 443, tls=True)
                  + nuclei_commands("CVE-1", "10.0.0.1")
                  + metasploit_commands("exploit/x", "10.0.0.1", 80))
    for command in everything:
        assert len(command.rationale) > 20, f"{command.tool} explains nothing"


def test_as_dict_carries_the_category_and_the_opt_in_flag():
    """The UI reads these to decide what to show and when to warn."""
    payload = Command(tool="nmap", category=Category.VULN,
                      argv=("nmap", "--script", "vuln")).as_dict()
    assert payload["category"] == "vuln"
    assert payload["requires_opt_in"] is True
    assert payload["composed"] is True


# --------------------------------------------------------------------------- #
# PROP-05  A control character in banner text blanked the whole hand-off
#
# Found by tests/test_properties.py::test_searchsploit_commands_hold_the
# _boundary, minimised to a version of `0\r0`. `searchsploit_commands`
# interpolated the product and version straight into `argv`, and those come
# from a fingerprint -- which is banner text, read from an nmap file or from a
# POSTed evidence body (`stages` reads `entry["version"]` unfiltered).
# `_clean_argv` refused the control character correctly, with a `ValueError`
# raised on the first line of `build_commands`, outside any handler: one
# poisoned banner cost the entire hand-off, every other command in it, and a
# 500 on the route.
#
# RC-39's finding at a different feed. The refusal in `_clean_argv` stays --
# it is the backstop and it is right -- but a *search term* has no business
# carrying control characters, so they are stripped where the value stops
# being prose and becomes an argument.
# --------------------------------------------------------------------------- #

def test_prop05_a_control_character_in_a_version_does_not_raise():
    commands = searchsploit_commands("CVE-2021-41773", "Apache", "2.4.49\r")
    assert len(commands) == 2
    assert commands[1].argv == ("searchsploit", "Apache 2.4.49")


def test_prop05_a_control_character_in_a_cve_id_does_not_raise():
    commands = searchsploit_commands("CVE-2021-41773\n; rm -rf /", "", "")
    assert commands[0].argv == ("searchsploit", "--cve",
                                "CVE-2021-41773 ; rm -rf /")
    # Still one shell word, still one argument, and it re-splits exactly.
    assert shlex.split(commands[0].rendered) == list(commands[0].argv)


def test_prop05_nuclei_is_guarded_on_the_same_path():
    command = nuclei_commands("CVE-2021-41773\r\n-u evil", "10.0.0.1")[0]
    assert "\r" not in command.argv[2] and "\n" not in command.argv[2]
    assert shlex.split(command.rendered) == list(command.argv)


def test_prop05_the_whole_hand_off_survives_one_poisoned_banner():
    """The property that actually failed: not "the term is clean" but "the
    other commands still get emitted"."""
    from reconkg.handoff import build_commands
    from reconkg.vulnref import LedgerRow

    row = LedgerRow(target="10.0.0.1", port=80, protocol="tcp", service="http",
                    product="Apache httpd", version="2.4.49\r", cvss=9.8,
                    cve_id="CVE-2021-41773", title="t", maturity="weaponised",
                    fingerprint_confidence=0.9)
    commands = build_commands(row)
    assert commands
    assert any(c.tool == "nmap" for c in commands)
    for command in commands:
        if command.composed:
            assert shlex.split(command.rendered) == list(command.argv)


def test_prop05_an_ordinary_banner_is_unchanged():
    """The clean-up must be invisible where there is nothing to clean, or it
    has silently changed which entries `searchsploit` returns."""
    commands = searchsploit_commands("CVE-2021-41773", "Apache httpd", "2.4.49")
    assert commands[1].argv == ("searchsploit", "Apache httpd 2.4.49")
