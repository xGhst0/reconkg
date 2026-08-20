"""Golden-file tests against XML produced by a real nmap.

Every fixture in `tests/fixtures/` came out of nmap 7.80 scanning live
listeners -- not hand-written to match what the parser already does. That
distinction is the entire point. The synthetic suite passed while the
importer rejected 100% of genuine nmap files on any host without defusedxml,
because I wrote fixtures without the `<!DOCTYPE nmaprun>` line that every
real file carries.

To regenerate or extend: `python tests/fixtures/regenerate.py` documents the
exact commands.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reconkg.importers import (UNINFORMATIVE_SERVICES, ingest, parse_nmap_xml,
                               unsafe_doctype_reason)
from reconkg.stages import EvidenceSource
from reconkg.store import TargetStore

FIXTURES = Path(__file__).parent / "fixtures"
ALL_SCANS = sorted(FIXTURES.glob("*.xml"))


def _load(name: str):
    return parse_nmap_xml(FIXTURES / name)


def test_fixtures_are_present():
    assert len(ALL_SCANS) >= 6, "golden fixtures missing; see regenerate.py"


def test_every_fixture_is_genuine_nmap_output():
    """Guard against someone quietly replacing these with hand-written XML."""
    for scan in ALL_SCANS:
        text = scan.read_text()
        assert text.startswith("<?xml"), scan.name
        assert "<!DOCTYPE nmaprun>" in text, scan.name
        assert 'scanner="nmap"' in text, scan.name
        assert 'xmloutputversion=' in text, scan.name


# --------------------------------------------------------------------------- #
# The bug real output found
# --------------------------------------------------------------------------- #

def test_real_nmap_doctype_is_not_rejected():
    """The regression that mattered: `<!DOCTYPE nmaprun>` opens every real
    nmap file, and the hardening used to refuse the lot."""
    for scan in ALL_SCANS:
        assert unsafe_doctype_reason(scan.read_text()) is None, scan.name


@pytest.mark.parametrize("document,fragment", [
    ('<!DOCTYPE n [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><n/>', "entity"),
    ('<!DOCTYPE n SYSTEM "http://evil.test/x.dtd"><n/>', "external"),
    ('<!DOCTYPE n PUBLIC "-//X//EN" "http://evil.test/x.dtd"><n/>', "external"),
    ('<!DOCTYPE n [ <!ELEMENT n EMPTY> ]><n/>', "internal subset"),
    ('<n>&xxe;</n><!ENTITY xxe "boom">', "entity"),
])
def test_dangerous_doctypes_are_still_refused(document, fragment):
    reason = unsafe_doctype_reason(document)
    assert reason is not None and fragment in reason


def test_every_fixture_parses(request):
    for scan in ALL_SCANS:
        result = parse_nmap_xml(scan)
        assert result.source == "Nmap XML"


# --------------------------------------------------------------------------- #
# Service identification, checked against what nmap actually said
# --------------------------------------------------------------------------- #

def test_version_detection_scan_extracts_products_and_versions():
    payload = _load("nmap_sV_localhost.xml").hosts["127.0.0.1"]
    services = {s["port"]: s for s in payload["services"]}

    ssh = services[2222]
    assert (ssh["service"], ssh["product"], ssh["version"]) == \
        ("ssh", "OpenSSH", "7.4")
    assert ssh["ambiguous"] is False
    assert ssh["confidence"] == 1.0          # nmap conf="10", method="probed"
    assert ssh["cpe"].startswith("cpe:/a:openbsd:openssh")

    http = services[8080]
    assert (http["product"], http["version"]) == ("Apache httpd", "2.4.49")
    assert http["ambiguous"] is False


def test_product_without_version_is_marked_ambiguous():
    """Postfix answered with a banner naming the product but no version."""
    services = {s["port"]: s
                for s in _load("nmap_sV_localhost.xml").hosts["127.0.0.1"]
                ["services"]}
    smtp = services[2525]
    assert smtp["product"] == "Postfix smtpd"
    assert smtp["version"] is None
    assert smtp["ambiguous"] is True


def test_tcpwrapped_is_not_treated_as_an_identification():
    """nmap says "something answered, I could not identify it". Recording
    that at probe confidence would let a non-answer look like a finding."""
    services = {s["port"]: s
                for s in _load("nmap_sV_localhost.xml").hosts["127.0.0.1"]
                ["services"]}
    wrapped = services[6379]
    assert wrapped["service"] in UNINFORMATIVE_SERVICES
    assert wrapped["ambiguous"] is True
    assert wrapped["confidence"] <= 0.2


def test_port_scan_without_sV_yields_only_table_guesses():
    """No -sV means nmap never spoke to anything; names come from
    nmap-services by port number and must not be trusted."""
    payload = _load("nmap_portscan_only.xml").hosts["127.0.0.1"]
    assert payload["ports"]
    for service in payload["services"]:
        assert service["ambiguous"] is True
        assert service["confidence"] <= 0.3
        assert service["product"] is None


def test_scan_type_selects_the_source_tool():
    """These were produced with -sT, so reachability is filed under the
    connect-sweep key, not the SYN one."""
    assert _load("nmap_sV_localhost.xml").port_tool == "nmap-sT"


# --------------------------------------------------------------------------- #
# Host handling
# --------------------------------------------------------------------------- #

def test_ipv6_addresses_survive_validation():
    result = _load("nmap_ipv6.xml")
    assert list(result.hosts) == ["::1"]
    assert result.hosts["::1"]["ports"]


def test_host_discovery_only_scan_still_records_the_host():
    """A -sn run has no <ports> element at all. "This address is live" is
    real evidence and used to be dropped, so a ping sweep imported nothing
    and gave no reason why."""
    result = _load("nmap_ping_only.xml")
    assert "127.0.0.1" in result.hosts
    assert result.discovered_only == ["127.0.0.1"]
    assert result.hosts["127.0.0.1"] == {}
    assert "host discovery" in result.summary()


def test_down_host_is_excluded():
    result = _load("nmap_host_down.xml")
    assert result.host_count == 0
    assert result.discovered_only == []


def test_script_output_does_not_confuse_the_parser():
    """--script adds <script> elements the parser has no business reading."""
    result = _load("nmap_with_scripts.xml")
    services = {s["port"]: s for s in result.hosts["127.0.0.1"]["services"]}
    assert services[2222]["product"] == "OpenSSH"
    assert services[8080]["version"] == "2.4.49"


# --------------------------------------------------------------------------- #
# Invariants that must hold for any real scan
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("scan", ALL_SCANS, ids=lambda p: p.name)
def test_parser_invariants_hold_for_every_real_scan(scan):
    from reconkg.auth import validate_address

    result = parse_nmap_xml(scan)
    for address, payload in result.hosts.items():
        assert validate_address(address) == address
        for port in payload.get("ports", []):
            assert 1 <= port["number"] <= 65535
            assert port["protocol"] in ("tcp", "udp")
            assert port["state"] in ("open", "closed", "filtered", "unknown")
            assert 0.0 <= port["confidence"] <= 1.0
        known = {p["number"] for p in payload.get("ports", [])}
        for service in payload.get("services", []):
            assert service["port"] in known, "service on an unreported port"
            assert 0.0 <= service["confidence"] <= 1.0
            if service["version"] is None:
                assert service["ambiguous"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("scan", ALL_SCANS, ids=lambda p: p.name)
async def test_every_real_scan_ingests_cleanly(scan):
    """End to end on genuine output: import, run the pipeline, no crash."""
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine

    store, evidence = TargetStore(), EvidenceSource()
    result = parse_nmap_xml(scan)
    added = await ingest(result, store, evidence, principal="scanner-a")
    assert added == list(result.hosts)

    engine = DiscoveryEngine(store, evidence, module_pipeline())
    for address in added:
        report = await engine.run(address)
        assert report.finished_at is not None
        assert all(0.0 <= r.priority <= 1.0 for r in report.ledger)


@pytest.mark.asyncio
async def test_real_openssh_banner_produces_the_expected_lead():
    """The full chain on real output: OpenSSH 7.4 from an actual banner
    grab reaches the ledger as CVE-2018-15473."""
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine

    store, evidence = TargetStore(), EvidenceSource()
    await ingest(_load("nmap_sV_localhost.xml"), store, evidence,
                 principal="scanner-a")
    report = await DiscoveryEngine(store, evidence, module_pipeline()).run(
        "127.0.0.1")

    cves = {r.cve_id for r in report.ledger}
    assert "CVE-2018-15473" in cves
    assert "CVE-2021-41773" in cves          # the Apache 2.4.49 listener
    for row in report.ledger:
        assert row.rationale
        assert row.fingerprint_confidence > 0
