"""Reading a page title as an identity, and refusing to read one that isn't.

A host ran rConfig behind Apache on CentOS. reconkg returned 97 leads --
Apache, OpenSSL, PHP, jQuery, every Apache row annotated "distribution build
-- the fix may be applied without a version bump" -- and not one row about
rConfig, which was the way in. Three separate defects produced that, and
each of them is a shape rather than a string:

  * `Title[rConfig - Configuration Management]` was stored verbatim as a
    product name. No corpus files anything under that, so it matched nothing
    and the run reported no application at all.
  * `Title[400 Bad Request]` was stored as a product, and the Coverage panel
    then asked the operator to find a version for an HTTP status line.
  * A recognised product with no version generated nothing, because
    product-only matching is off by default -- a rule written for platform
    components that silences named applications along with them.

These tests are about the shapes. A test that asserted on the string
"rConfig" would pass while the next host's title failed exactly the same
way.
"""

from __future__ import annotations

import pytest

from reconkg.models import Fingerprint, Provenance
from reconkg.vulnref import CorrelationConfig, build_leads
from reconkg.webid import (WEB_PLATFORM_PRODUCTS, cpe_product, identities,
                           is_not_a_product, resolve_identity, split_version)


# --------------------------------------------------------------------------- #
# What is not a product
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("title", [
    "400 Bad Request",
    "403 Forbidden",
    "404 Not Found",
    "500 Internal Server Error",
    "502 Bad Gateway",
])
def test_an_http_status_line_is_never_an_application(title):
    """The observed failure, and every sibling of it.

    Port 443 was fetched over plain HTTP, Apache answered `400 Bad Request`,
    and the title became the application's name. The scheme bug is fixed;
    any host that answers a request with an error page would have done the
    same thing, so the status-line shape has to be refused on its own.
    """
    assert is_not_a_product(title)
    assert resolve_identity(title, None) is None


@pytest.mark.parametrize("title", [
    "Index of /", "Index of /uploads",
    "Apache HTTP Server Test Page powered by CentOS",
    "Welcome to nginx!",
    "It works!",
    "Test Page for the HTTP Server on Fedora",
])
def test_a_stock_page_names_the_server_not_the_application(title):
    """These are the dangerous ones: they contain a real product name.

    Left alone they arbitrate successfully to Apache or nginx and look like
    a genuine identification of the application -- which is worse than the
    status line, because nothing about the result appears wrong.
    """
    assert is_not_a_product(title)
    assert resolve_identity(title, None) is None


@pytest.mark.parametrize("title", ["Home", "Login", "Dashboard", "Untitled",
                                   "Access Denied", "  ", "-", "..."])
def test_a_generic_title_names_nothing(title):
    assert is_not_a_product(title)


def test_a_real_application_title_survives_all_of_it():
    assert not is_not_a_product("rConfig - Configuration Management")
    assert not is_not_a_product("phpMyAdmin")
    assert not is_not_a_product("Zabbix")


# --------------------------------------------------------------------------- #
# Splitting
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text,name,version", [
    ("phpMyAdmin 4.8.1", "phpMyAdmin", "4.8.1"),
    ("rConfig 3.9.6", "rConfig", "3.9.6"),
    ("GitLab v13.10.2", "GitLab", "13.10.2"),
    ("Grafana-8.3.0", "Grafana", "8.3.0"),
    ("OpenSSL 1.0.2k-fips", "OpenSSL", "1.0.2k-fips"),
])
def test_a_version_in_the_title_is_a_version(text, name, version):
    assert split_version(text) == (name, version)


@pytest.mark.parametrize("text", [
    "Zabbix", "rConfig", "Big Company 2024", "Section 3", "Error 500",
])
def test_a_lone_number_is_not_read_as_a_version(text):
    """A single number is far more often a year, a count or a section than a
    version, and an invented version is worse than a missing one -- the
    constraint check is applied to whatever it is handed."""
    _name, version = split_version(text)
    assert version is None


def test_a_string_that_is_only_a_version_names_nothing():
    name, version = split_version("3.9.6")
    assert version is None and name == "3.9.6"


# --------------------------------------------------------------------------- #
# Candidate ordering
# --------------------------------------------------------------------------- #

def test_the_product_can_be_the_first_segment():
    names = [n for n, _ in identities("rConfig - Configuration Management")]
    assert names[0] == "rConfig - Configuration Management"
    assert "rConfig" in names
    assert names.index("rConfig") < names.index("Configuration Management")


def test_the_product_can_be_the_last_segment():
    """"Dashboard | Zabbix". The generic half is skipped rather than ranked,
    so the arbiter is never offered the chance to recognise "Dashboard"."""
    names = [n for n, _ in identities("Dashboard | Zabbix")]
    assert "Zabbix" in names
    assert "Dashboard" not in names


def test_the_whole_title_is_offered_before_its_pieces():
    """"phpMyAdmin 4.8.1" is one product and one version. Splitting it first
    would offer a fragment and lose the version attached to the whole."""
    first, version = identities("phpMyAdmin 4.8.1")[0]
    assert (first, version) == ("phpMyAdmin", "4.8.1")


@pytest.mark.parametrize("title,expected", [
    ("Welcome to Jenkins!", "Jenkins!"),
    ("rConfig-Web", "rConfig-Web"),
])
def test_separators_that_are_not_separators(title, expected):
    """A hyphen inside a word, and a lead-in phrase. Splitting `rConfig-Web`
    would propose two fragments and neither is the product."""
    assert expected in [n for n, _ in identities(title)]


def test_junk_proposes_nothing_at_all():
    assert identities("400 Bad Request") == []
    assert identities("") == []


# --------------------------------------------------------------------------- #
# Arbitration
# --------------------------------------------------------------------------- #

def _corpus(*known: str):
    """A stand-in for `resolver.product_vendor`: name -> vendor, or None."""
    table = {name: f"{name}_vendor" for name in known}
    return lambda product: table.get(product)


def test_a_title_becomes_the_product_the_corpus_recognises():
    identity = resolve_identity("rConfig - Configuration Management", None,
                                _corpus("rconfig"))
    assert identity is not None
    assert identity.product == "rConfig"
    assert identity.vendor == "rconfig_vendor"
    assert identity.application is True
    assert "rConfig - Configuration Management" in identity.note


def test_a_version_in_the_title_travels_with_the_product():
    identity = resolve_identity("phpMyAdmin 4.8.1 | localhost", None,
                                _corpus("phpmyadmin"))
    assert identity is not None
    assert (identity.product, identity.version) == ("phpMyAdmin", "4.8.1")
    assert identity.application is True


def test_an_observed_version_is_never_overwritten_by_the_title():
    """The operator, or a versioned plugin, beats prose. A title reading
    "Foo 1.0" on a service nmap versioned at 2.3 is a stale page, not a
    correction."""
    identity = resolve_identity("Zabbix 1.0", "5.0.17", _corpus("zabbix"))
    assert identity is not None
    assert identity.version == "5.0.17"


def test_an_unrecognised_title_is_kept_verbatim_and_granted_nothing():
    """It still has to reach the Coverage panel, which names it to the
    operator. What it must not do is quietly become a product name."""
    identity = resolve_identity("Some Bespoke Portal", None, _corpus("nginx"))
    assert identity is not None
    assert identity.product == "Some Bespoke Portal"
    assert identity.application is False
    assert identity.vendor is None


@pytest.mark.parametrize("product", sorted(WEB_PLATFORM_PRODUCTS)[:8])
def test_a_platform_component_is_never_promoted(product):
    """Every corpus knows Apache. That is exactly why "Apache, version
    unknown" must not become a permission to list twenty years of Apache
    CVEs -- the failure this whole change exists to stop reproducing."""
    identity = resolve_identity(product, None, _corpus(cpe_product(product)))
    assert identity is not None
    assert identity.application is False


def test_without_a_corpus_nothing_is_ever_promoted():
    """A tool that cannot check must not claim to have checked. The junk
    filter still runs, because that needs no corpus."""
    identity = resolve_identity("rConfig - Configuration Management", None)
    assert identity is not None
    assert identity.application is False
    assert identity.product == "rConfig - Configuration Management"
    assert resolve_identity("400 Bad Request", None) is None


@pytest.mark.parametrize("name,expected", [
    ("rConfig", "rconfig"),
    ("Configuration Management", "configuration_management"),
    ("phpMyAdmin", "phpmyadmin"),
    ("Zoho ManageEngine!", "zoho_manageengine"),
])
def test_the_lookup_spelling_is_cpe_spelling(name, expected):
    """The name a candidate is proposed under and the name it is looked up
    under come from this one function. Two spellings of one normalisation is
    how a lookup silently starts answering "never heard of it" for software
    the corpus holds."""
    assert cpe_product(name) == expected


# --------------------------------------------------------------------------- #
# What the permission actually buys
# --------------------------------------------------------------------------- #

def _fp(**kw) -> Fingerprint:
    base = dict(product="rConfig", version=None,
                provenance=Provenance(source_tool="whatweb", confidence=0.6,
                                      principal="local"))
    base.update(kw)
    return Fingerprint(**base)


def _entry(cve_id="CVE-2019-16662", product="rconfig"):
    from reconkg.models import ExploitMaturity
    from reconkg.vulnref import VulnEntry

    return VulnEntry(cve_id=cve_id, title="rConfig command injection",
                     product_match=product, cvss=9.8,
                     maturity=ExploitMaturity.WEAPONISED)


def test_an_unversioned_fingerprint_still_produces_nothing_by_default():
    """Unchanged, and it has to stay unchanged: this is the rule that keeps
    an IIS 10.0 host from collecting 2008 ActiveX CVEs."""
    leads = build_leads(_fp(), [_entry()], CorrelationConfig())
    assert leads == []


def test_a_named_application_is_the_one_exception():
    leads = build_leads(_fp(application=True), [_entry()],
                        CorrelationConfig())
    assert [lead.cve_id for lead in leads] == ["CVE-2019-16662"]


def test_the_lead_says_out_loud_that_no_version_was_matched():
    """A product-only row that reads like a version match is worse than no
    row: an operator spends an afternoon on it and stops trusting the rest
    of the ledger."""
    lead = build_leads(_fp(application=True), [_entry()],
                       CorrelationConfig())[0]
    assert "VERSION UNKNOWN" in lead.rationale
    assert "matched by product_only" in lead.rationale


def test_version_unknown_leads_get_a_smaller_budget():
    """They are a reading list, not findings, and twelve of them would
    out-shout the version-matched rows they sit beside."""
    cfg = CorrelationConfig(max_unversioned_leads=3)
    entries = [_entry(cve_id=f"CVE-2019-1660{n}") for n in range(9)]
    assert len(build_leads(_fp(application=True), entries, cfg)) == 3
    versioned = _fp(version="3.9.6", application=True)
    assert len(build_leads(versioned, entries, cfg)) > 3


def test_the_permission_does_not_survive_the_confidence_floor():
    """`application` widens which matches count. It is not a way around the
    question of whether the fingerprint is credible at all."""
    weak = _fp(application=True,
               provenance=Provenance(source_tool="whatweb", confidence=0.2))
    assert build_leads(weak, [_entry()], CorrelationConfig()) == []
