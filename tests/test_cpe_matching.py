"""CPE parsing, applicability matching, match provenance and backport risk.

Implements the design note in docs/CVE-IDENTIFICATION.md. Exact values
throughout, per the lesson from the mutation pass.
"""

from __future__ import annotations

import pytest

from reconkg.cpe import (ANY, NA, CPE, CPERange, MatchMethod, Relation,
                         attribute_matches, compare_attribute, infer_cpe,
                         looks_backported, parse)
from reconkg.models import ExploitMaturity, Fingerprint, Provenance
from reconkg.vulnref import CorrelationConfig, VulnEntry, build_leads


def _fp(product=None, version=None, cpe=None, banner=None, confidence=0.9):
    return Fingerprint(product=product, version=version, cpe=cpe,
                       raw_banner=banner,
                       provenance=Provenance(source_tool="nmap-sV",
                                             principal="scanner-a",
                                             confidence=confidence))


# --------------------------------------------------------------------------- #
# Parsing — both bindings, because both appear in the wild
# --------------------------------------------------------------------------- #

def test_parses_the_2_2_uri_nmap_emits():
    parsed = parse("cpe:/a:openbsd:openssh:7.4")
    assert (parsed.part, parsed.vendor, parsed.product, parsed.version) == \
        ("a", "openbsd", "openssh", "7.4")
    assert parsed.is_application is True
    assert parsed.has_version is True


def test_parses_the_2_3_formatted_string_nvd_emits():
    parsed = parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert parsed.identity() == ("a", "apache", "http_server")
    assert parsed.version == "2.4.49"
    assert parsed.update == ANY


def test_unspecified_trailing_attributes_default_to_any():
    parsed = parse("cpe:/a:apache:http_server")
    assert parsed.version == ANY
    assert parsed.has_version is False


def test_escaped_colon_does_not_shear_the_attributes():
    """A naive split on ':' shifts every later attribute by one position and
    does not raise -- it silently produces a CPE whose vendor is a fragment."""
    parsed = parse(r"cpe:2.3:a:vendor:product:1\:2:*:*:*:*:*:*:*")
    assert parsed.vendor == "vendor"
    assert parsed.product == "product"
    assert parsed.version == "1:2"


def test_escaped_dots_are_unescaped():
    assert parse(r"cpe:2.3:a:apache:http_server:2\.4\.49:*").version == "2.4.49"


@pytest.mark.parametrize("bad", [
    None, "", "   ", "not a cpe", "http://example.test",
    "cpe:/x:vendor:product",          # invalid part
    "cpe:2.3:z:a:b:c",                # invalid part
])
def test_unparseable_input_returns_none_rather_than_raising(bad):
    """A malformed CPE in a banner is a fact about the target, not a caller
    error, and must not stop the rest of the fingerprint being used."""
    assert parse(bad) is None


def test_case_is_normalised():
    assert parse("CPE:/A:Apache:HTTP_Server:2.4.49").vendor == "apache"


# --------------------------------------------------------------------------- #
# Attribute comparison — ANY and NA carry distinct meaning (NIST IR 7696)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("source,target,expected", [
    ("apache", "apache", Relation.EQUAL),
    (ANY, "apache", Relation.SUPERSET),
    ("apache", ANY, Relation.SUBSET),
    ("apache", "nginx", Relation.DISJOINT),
    (NA, "apache", Relation.DISJOINT),
    ("apache", NA, Relation.DISJOINT),
    (NA, NA, Relation.EQUAL),
    (ANY, ANY, Relation.EQUAL),
])
def test_attribute_relations(source, target, expected):
    assert compare_attribute(source, target) is expected


def test_na_is_not_a_wildcard():
    """Treating NA as "matches anything" is how a vulnerability scoped to a
    product with no edition matches every edition ever shipped."""
    assert attribute_matches(NA, "enterprise") is False
    assert attribute_matches("enterprise", NA) is False
    assert attribute_matches(NA, NA) is True


def test_an_unspecific_observation_does_not_satisfy_a_specific_criterion():
    """Refusing here is a deliberate direction: an unknown edition is not
    evidence of a matching edition."""
    assert attribute_matches("enterprise", ANY) is False
    assert attribute_matches(ANY, "enterprise") is True


# --------------------------------------------------------------------------- #
# Applicability statements — NVD's four boundary fields
# --------------------------------------------------------------------------- #

APACHE = CPE(part="a", vendor="apache", product="http_server")


def _range(**kw):
    return CPERange(cpe=APACHE, **kw)


def test_version_window_inclusive_start_exclusive_end():
    statement = _range(version_start_including="2.4.0",
                       version_end_excluding="2.4.50")
    for version, expected in (("2.4.0", True), ("2.4.49", True),
                              ("2.4.50", False), ("2.3.9", False)):
        observed = CPE(part="a", vendor="apache", product="http_server",
                       version=version)
        ok, method, why = statement.matches(observed)
        assert ok is expected, f"{version}: {why}"
        if ok:
            assert method is MatchMethod.CPE_RANGE


def test_exclusive_start_and_inclusive_end():
    statement = _range(version_start_excluding="2.4.0",
                       version_end_including="2.4.50")
    def check(version):
        return statement.matches(CPE(part="a", vendor="apache",
                                     product="http_server",
                                     version=version))[0]
    assert check("2.4.0") is False
    assert check("2.4.1") is True
    assert check("2.4.50") is True
    assert check("2.4.51") is False


def test_an_exact_version_statement_matches_only_that_version():
    statement = CPERange(cpe=CPE(part="a", vendor="apache",
                                 product="http_server", version="2.4.49"))
    ok, method, why = statement.matches(
        CPE(part="a", vendor="apache", product="http_server",
            version="2.4.49"))
    assert ok and method is MatchMethod.CPE_EXACT
    assert statement.matches(
        CPE(part="a", vendor="apache", product="http_server",
            version="2.4.50"))[0] is False


def test_a_statement_with_no_version_constraint_is_flagged_as_weak():
    """Real in NVD and dangerous: it applies to every version ever shipped."""
    ok, method, why = _range().matches(
        CPE(part="a", vendor="apache", product="http_server", version="2.4.49"))
    assert ok is True
    assert method is MatchMethod.PRODUCT_ONLY
    assert "constrains no version" in why


def test_a_non_vulnerable_statement_never_matches():
    statement = _range(version_end_excluding="9.9", vulnerable=False)
    ok, method, why = statement.matches(
        CPE(part="a", vendor="apache", product="http_server", version="2.4.49"))
    assert ok is False and method is None
    assert "not vulnerable" in why


def test_vendor_mismatch_is_refused_with_a_stated_reason():
    ok, method, why = _range(version_end_excluding="99").matches(
        CPE(part="a", vendor="nginx", product="http_server", version="1.0"))
    assert ok is False
    assert "vendor differs" in why


def test_tomcat_is_not_httpd():
    """The failure the substring matcher could not express."""
    ok, _, why = _range(version_end_excluding="99").matches(
        CPE(part="a", vendor="apache", product="tomcat", version="9.0.50"))
    assert ok is False
    assert "product differs" in why


def test_a_window_with_no_observed_version_does_not_match():
    ok, _, why = _range(version_end_excluding="2.4.50").matches(
        CPE(part="a", vendor="apache", product="http_server"))
    assert ok is False
    assert "no observed version" in why


# --------------------------------------------------------------------------- #
# Match method weighting
# --------------------------------------------------------------------------- #

def test_method_weights_are_ordered_identifier_above_heuristic():
    assert MatchMethod.CPE_EXACT.weight == 1.0
    assert MatchMethod.CPE_RANGE.weight == 0.95
    assert MatchMethod.PRODUCT_VERSION.weight == 0.75
    assert MatchMethod.PRODUCT_ONLY.weight == 0.3
    assert MatchMethod.CPE_EXACT.is_cpe and MatchMethod.CPE_RANGE.is_cpe
    assert not MatchMethod.PRODUCT_VERSION.is_cpe


def test_a_cpe_match_outranks_the_same_finding_by_substring():
    entry_cpe = VulnEntry(
        "CVE-X", "t", "apache", (), 9.0, ExploitMaturity.FUNCTIONAL,
        cpe_ranges=(CPERange(cpe=CPE(part="a", vendor="apache",
                                     product="http_server", version="2.4.49")),))
    entry_substring = VulnEntry("CVE-X", "t", "apache",
                                ((">=", "2.4.49"), ("<=", "2.4.49")), 9.0,
                                ExploitMaturity.FUNCTIONAL)
    fp = _fp(product="Apache httpd", version="2.4.49",
             cpe="cpe:/a:apache:http_server:2.4.49")
    cfg = CorrelationConfig()

    by_cpe = build_leads(fp, [entry_cpe], cfg)[0]
    by_substring = build_leads(fp, [entry_substring], cfg)[0]
    assert by_cpe.priority > by_substring.priority
    assert "cpe_exact" in by_cpe.rationale
    assert "product_version" in by_substring.rationale


def test_the_rationale_always_names_the_method():
    entry = VulnEntry("CVE-X", "t", "apache", ((">=", "2.0"),), 9.0)
    lead = build_leads(_fp(product="Apache httpd", version="2.4.49"),
                       [entry], CorrelationConfig())[0]
    assert lead.rationale.endswith("matched by product_version")


# --------------------------------------------------------------------------- #
# Inference — conservative on purpose
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("product,vendor,name", [
    ("Apache httpd", "apache", "http_server"),
    ("Apache Tomcat", "apache", "tomcat"),
    ("OpenSSH", "openbsd", "openssh"),
    ("nginx", "f5", "nginx"),
    ("Postfix smtpd", "postfix", "postfix"),
])
def test_known_products_infer_a_cpe(product, vendor, name):
    inferred = infer_cpe(product, "1.0")
    assert (inferred.vendor, inferred.product) == (vendor, name)


def test_tomcat_is_tested_before_any_shorter_apache_key():
    """Key ordering matters: a shorter "apache" key first would file Tomcat
    as httpd, which is the exact confusion CPE matching exists to end."""
    assert infer_cpe("Apache Tomcat", "9.0.50").product == "tomcat"
    assert infer_cpe("Apache httpd", "2.4.49").product == "http_server"


@pytest.mark.parametrize("product", [None, "", "Some Bespoke Appliance",
                                     "Unknown", "totally novel daemon"])
def test_unknown_products_infer_nothing(product):
    """A guessed CPE that is wrong is worse than no CPE: it promotes a weak
    substring match into something that looks like an identifier match."""
    assert infer_cpe(product, "1.0") is None


# --------------------------------------------------------------------------- #
# Backport risk — the failure mode the research called out
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("version,marker", [
    ("2.4.6-el7", "el7"),
    ("1.0.2k-fips.el7_9", "el7"),
    ("7.4p1-ubuntu0.3", "ubuntu"),
    ("2.4.41-4ubuntu3.14", "ubuntu"),
    ("1.1.1f-1+deb10u2", "deb10"),
    ("7.91+dfsg1", "dfsg"),
    ("3.6.3-suse", "suse"),
    ("2.4.6-amzn2", "amzn"),
])
def test_distribution_markers_are_detected(version, marker):
    assert looks_backported(version) == marker


@pytest.mark.parametrize("version", [
    "2.4.49", "7.4", "1.0.1g", "9.0.50", None, "",
    "2.4.49rc1",             # a pre-release is not a distribution build
    "1.2.3-beta",            # nor is a beta
])
def test_upstream_versions_are_not_flagged(version):
    """A false backport verdict suppresses a real finding, which costs more
    than the noise it saves. Detection stays narrow."""
    assert looks_backported(version) is None


def test_a_marker_in_the_banner_is_found_too():
    """The version alone is clean; the banner gives it away. The first
    marker in the text wins, and "CentOS" is a better thing to show an
    analyst than "el7" anyway."""
    assert looks_backported("2.4.6", "Apache/2.4.6 (CentOS) el7") == "CentOS"
    assert looks_backported("2.4.6", "Apache/2.4.6 (Ubuntu)") == "Ubuntu"


def test_the_version_is_checked_before_the_banner():
    assert looks_backported("2.4.6-el7", "Apache/2.4.6 (Ubuntu)") == "el7"


def test_a_backported_build_is_discounted_not_hidden():
    """Discounted rather than suppressed: the lead may still be real, and
    silently hiding it trades false positives for false negatives."""
    entry = VulnEntry("CVE-X", "t", "apache", ((">=", "2.0"),), 9.0,
                      ExploitMaturity.FUNCTIONAL)
    cfg = CorrelationConfig()
    upstream = build_leads(_fp(product="Apache httpd", version="2.4.6"),
                           [entry], cfg)[0]
    packaged = build_leads(_fp(product="Apache httpd", version="2.4.6-el7"),
                           [entry], cfg)[0]

    assert packaged.priority == pytest.approx(
        round(upstream.priority * cfg.backport_penalty, 4))
    assert "BACKPORT RISK" in packaged.rationale
    assert "el7" in packaged.rationale
    assert "BACKPORT RISK" not in upstream.rationale


def test_the_backport_penalty_is_exactly_a_quarter():
    assert CorrelationConfig().backport_penalty == 0.25


# --------------------------------------------------------------------------- #
# Mutation-driven: exactness the first pass missed
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [123, 4.5, True, [], {}, object()])
def test_non_string_input_is_refused_not_crashed_on(value):
    """A truthy non-string reached `.strip()` and raised AttributeError.
    Callers pass whatever a feed handed them; refusing is the contract."""
    assert parse(value) is None


def test_any_criterion_matches_even_a_not_applicable_candidate():
    """ANY is a superset of everything, NA included."""
    assert attribute_matches(ANY, NA) is True
    assert attribute_matches(ANY, "anything") is True


def test_an_exact_version_statement_needs_an_observed_version():
    statement = CPERange(cpe=CPE(part="a", vendor="apache",
                                 product="http_server", version="2.4.49"))
    ok, method, why = statement.matches(
        CPE(part="a", vendor="apache", product="http_server"))
    assert ok is False and method is None
    assert why == "no observed version to compare"


def test_inferred_cpe_keeps_the_observed_version():
    assert infer_cpe("OpenSSH", "7.4").version == "7.4"
    assert infer_cpe("OpenSSH", None).version == ANY
    assert infer_cpe("OpenSSH", "").version == ANY


def test_inferred_version_is_lower_cased():
    assert infer_cpe("Apache httpd", "2.4.49-RC1").version == "2.4.49-rc1"


def test_the_backport_discounted_priority_rounds_to_four_places():
    """0.5042 * 0.25 is 0.12605, which must land on 0.126."""
    entry = VulnEntry("CVE-X", "t", "apache", ((">=", "2.0"),), 9.0,
                      ExploitMaturity.FUNCTIONAL)
    cfg = CorrelationConfig()
    upstream = build_leads(_fp(product="Apache httpd", version="2.4.49",
                               confidence=0.83), [entry], cfg)[0]
    packaged = build_leads(_fp(product="Apache httpd", version="2.4.49-el7",
                               confidence=0.83), [entry], cfg)[0]
    assert upstream.priority == 0.5042
    assert packaged.priority == 0.126


# --------------------------------------------------------------------------- #
# PROP-01  `str(CPE)` lost the escaping that `parse` consumed
#
# Found by tests/test_properties.py::test_cpe_parse_round_trips_through_str,
# minimised to `cpe:2.3:a:\:a`. `_unescape` strips the backslashes on the way
# in and `__str__` did not put them back, so the round trip through a string
# was lossy -- and it is not a display path: `vulndb` stores `str(cpe)` in the
# `criteria` column and re-parses it on every candidate lookup, so an escaped
# colon anywhere in a CPE shifted every later attribute one position in the
# corpus and nothing raised.
# --------------------------------------------------------------------------- #

def test_prop01_an_escaped_colon_survives_a_str_round_trip():
    parsed = parse(r"cpe:2.3:a:apache:http_server:1\:2:*:*:*:*:*:*:*")
    assert parsed is not None
    assert parsed.version == "1:2"
    assert parse(str(parsed)) == parsed


def test_prop01_a_colon_in_an_attribute_does_not_shift_the_others():
    """The failure this actually caused: the colon re-split, so `vendor`
    became a fragment of the attribute before it and every field after moved
    along one. A corrupted identity is worse than a rejected one, because the
    lookup still succeeds -- against the wrong product."""
    source = CPE(part="a", vendor="v", product="p:x", version="1.0")
    reparsed = parse(str(source))
    assert reparsed == source
    assert reparsed.product == "p:x"
    assert reparsed.vendor == "v"
    assert reparsed.version == "1.0"


def test_prop01_a_literal_backslash_round_trips_too():
    source = CPE(part="a", vendor="v", product=r"p\x")
    assert parse(str(source)) == source


def test_prop01_an_ordinary_cpe_string_is_unchanged():
    """The escaping must be invisible where there is nothing to escape, or
    every stored `criteria` value in an existing corpus changes shape."""
    text = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert str(parse(text)) == text
