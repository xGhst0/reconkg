"""The arbiter, wired to a real corpus, on the one path every source takes.

`webid` proposes readings of a product string and knows nothing. This is the
seam where the corpus decides, and where the decision has to hold for nmap,
whatweb, an imported foreign scan and an operator's POST alike -- all four
reach the graph through `DiscoveryEngine._apply_one`, and a filter installed
on the whatweb path alone would leave the other three writing HTTP status
lines into the knowledge graph. That is this project's standing bug, thirteen
findings of it, and putting the arbiter anywhere else would make fourteen.
"""

from __future__ import annotations

import pytest

from reconkg.cpe import CPERange, parse as parse_cpe
from reconkg.engine import DiscoveryEngine
from reconkg.models import ExploitMaturity
from reconkg.resolver import ENV_VAR, from_env
from reconkg.stages import FingerprintObs
from reconkg.store import TargetStore
from reconkg.vulndb import VulnDB
from reconkg.vulnref import VulnEntry


def _entry(cve_id, vendor, product, *, start=None, end="99.0"):
    return VulnEntry(
        cve_id=cve_id, title=f"flaw in {product}", cvss=9.8,
        product_match=product.replace("_", " "),
        maturity=ExploitMaturity.NOT_DEFINED,
        cpe_ranges=(CPERange(
            cpe=parse_cpe(f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"),
            version_start_including=start,
            version_end_excluding=end),),
    )


@pytest.fixture
def engine(tmp_path):
    """A corpus with one narrow application and one sprawling one.

    rconfig is the application an operator is hunting: a short file, and
    listing all of it is useful. mysql is the counter-example -- known to
    every corpus, versioned by nmap only sometimes, and a product whose
    whole file says nothing about any particular host.
    """
    path = tmp_path / "vuln.db"
    with VulnDB(path) as db:
        db.ingest([_entry("CVE-2019-16662", "rconfig", "rconfig"),
                   _entry("CVE-2019-16663", "rconfig", "rconfig")]
                  + [_entry(f"CVE-2020-100{n:02d}", "oracle", "mysql")
                     for n in range(12)])
        db.set_meta("built_at", "9999999999")
    return DiscoveryEngine(TargetStore(), evidence=None,
                           reference=from_env({ENV_VAR: str(path)}))


def _obs(product, version=None, **kw):
    base = dict(port=443, product=product, version=version, banner=product,
                ambiguous=version is None, confidence=0.4)
    base.update(kw)
    return FingerprintObs(**base)


# --------------------------------------------------------------------------- #
# Dropping what is not a product
# --------------------------------------------------------------------------- #

def test_a_status_line_never_reaches_the_graph(engine):
    """It reached it once. Port 443 was fetched over plain HTTP, Apache
    answered `400 Bad Request`, and the Coverage panel then listed an HTTP
    status line among the services needing a version."""
    assert engine._identify(_obs("400 Bad Request")) is None


def test_a_default_page_never_reaches_the_graph(engine):
    assert engine._identify(_obs("Apache HTTP Server Test Page")) is None


# --------------------------------------------------------------------------- #
# Recovering the application
# --------------------------------------------------------------------------- #

def test_a_title_is_read_into_the_product_the_corpus_files(engine):
    out = engine._identify(_obs("rConfig - Configuration Management"))
    assert out is not None
    assert out.product == "rConfig"
    assert out.application is True


def test_an_arbitrated_identity_clears_the_correlation_floor(engine):
    """whatweb declares a title at 0.4 and the source registry multiplies
    that by 0.85, landing at 0.34 -- under the 0.45 floor, where
    `build_leads` discards it before looking at anything else. Arbitrating
    an identity nothing may act on is wasted work.

    The raise is earned: a title is one tool reading one string, and a title
    the corpus recognises is that reading plus an independent body of
    evidence agreeing the software exists.
    """
    out = engine._identify(_obs("rConfig - Configuration Management"))
    assert out.confidence * 0.85 > 0.45


def test_nmaps_own_fingerprints_keep_the_confidence_nmap_earned(engine):
    """The raise applies only where the product name was actually rewritten.
    A source that already named its product did not need arbitrating."""
    out = engine._identify(_obs("rConfig", version="3.9.6", confidence=0.75))
    assert out.confidence == 0.75


def test_a_version_in_the_title_is_kept_and_settles_the_service(engine):
    out = engine._identify(_obs("rConfig 3.9.6 - Configuration Management"))
    assert (out.product, out.version) == ("rConfig", "3.9.6")
    assert out.ambiguous is False, "a recovered version is a commitment"


def test_no_version_leaves_the_service_unresolved(engine):
    """Committing to the product does not commit to the version, and the
    Coverage panel's question about this port is still open."""
    out = engine._identify(_obs("rConfig - Configuration Management"))
    assert out.version is None
    assert out.ambiguous is True


# --------------------------------------------------------------------------- #
# The CPE, which is what makes a submitted version mean anything
# --------------------------------------------------------------------------- #

def test_a_recognised_product_with_a_version_gets_a_cpe(engine):
    """Without one the lookup drops to the substring path, which carries no
    version bounds -- so an operator who read "3.9.6" off the login page and
    submitted it would get every rConfig CVE back, their version ignored,
    presented as a version match."""
    out = engine._identify(_obs("rConfig - Configuration Management",
                                version="3.9.6"))
    assert out.cpe == "cpe:2.3:a:rconfig:rconfig:3.9.6:*:*:*:*:*:*:*"


def test_no_version_means_no_cpe(engine):
    """A wildcard-version CPE would take the identifier path and ask range
    statements a question they cannot answer. The unversioned case has its
    own answer and it is `application`."""
    out = engine._identify(_obs("rConfig - Configuration Management"))
    assert out.cpe is None


def test_a_cpe_the_source_supplied_is_never_overwritten(engine):
    supplied = "cpe:2.3:a:vendor:rconfig:3.9.6:*:*:*:*:*:*:*"
    out = engine._identify(_obs("rConfig", version="3.9.6", cpe=supplied))
    assert out.cpe == supplied


# --------------------------------------------------------------------------- #
# The ceiling
# --------------------------------------------------------------------------- #

def test_a_sprawling_product_needs_a_version_before_it_may_speak(engine):
    """nmap reports `MySQL ?` on a port it could not version, and the corpus
    knows mysql perfectly well. Without a ceiling the permission that lets
    rConfig speak would empty two decades of MySQL advisories into the
    ledger, not one of them a statement about this host."""
    engine.APPLICATION_CVE_CEILING = 3
    out = engine._identify(_obs("MySQL", port=3306))
    assert out is None or out.application is False


def test_the_narrow_product_is_still_allowed(engine):
    engine.APPLICATION_CVE_CEILING = 3
    out = engine._identify(_obs("rConfig - Configuration Management"))
    assert out.application is True


def test_a_resolver_that_cannot_count_grants_nothing(engine):
    """A missing measurement must never read as a passed check."""
    engine.resolver.product_cve_count = None
    out = engine._identify(_obs("rConfig - Configuration Management"))
    assert out is None or out.application is False


# --------------------------------------------------------------------------- #
# End to end: the run that returned 97 leads and named no application
# --------------------------------------------------------------------------- #

def test_the_application_finally_produces_leads(engine):
    from reconkg.models import Fingerprint, Provenance

    out = engine._identify(_obs("rConfig - Configuration Management"))
    fp = Fingerprint(product=out.product, version=out.version, cpe=out.cpe,
                     ambiguous=out.ambiguous, application=out.application,
                     provenance=Provenance(source_tool="whatweb",
                                           confidence=out.confidence * 0.85,
                                           principal="local"))
    from reconkg.vulnref import build_leads

    leads = build_leads(fp, engine.resolver.candidates(fp),
                        engine.correlation)
    assert {lead.cve_id for lead in leads} == {"CVE-2019-16662",
                                              "CVE-2019-16663"}
    assert all("VERSION UNKNOWN" in lead.rationale for lead in leads)
