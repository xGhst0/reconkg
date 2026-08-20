"""RC-11: index integrity, staleness, and catalogue-driven correlation."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from reconkg.catalog import (STALE_AFTER_DAYS, ExploitCatalog, IndexChanged,
                             digest_file)
from reconkg.models import ExploitMaturity, Fingerprint, Provenance
from reconkg.vulnref import CorrelationConfig, VulnEntry, build_leads, score

EDB = ("id,file,description,date_published,type,platform,verified,codes\n"
       "50383,exploits/a.sh,Apache 2.4.49 Path Traversal,2021-10-05,webapps,"
       "multiple,1,CVE-2021-41773\n")
MSF = json.dumps({"m": {"name": "Apache Normalize Path RCE",
                        "fullname": "exploit/multi/http/apache_normalize_path_rce",
                        "type": "exploit",
                        "references": [["CVE", "2021-41773"]]}})

APACHE = VulnEntry("CVE-2021-41773", "Apache RCE", "apache",
                   ((">=", "2.4.49"), ("<=", "2.4.49")), 9.8,
                   ExploitMaturity.THEORETICAL)


@pytest.fixture
def indexes(tmp_path):
    edb = tmp_path / "files_exploits.csv"
    msf = tmp_path / "msf.json"
    edb.write_text(EDB)
    msf.write_text(MSF)
    return edb, msf


@pytest.fixture
def catalog(indexes):
    edb, msf = indexes
    cat = ExploitCatalog()
    cat.load_exploitdb(edb)
    cat.load_metasploit(msf)
    return cat


def _fingerprint(confidence=0.9):
    return Fingerprint(product="Apache httpd", version="2.4.49",
                       provenance=Provenance(source_tool="nmap-sV",
                                             principal="scanner-a",
                                             confidence=confidence))


# --------------------------------------------------------------------------- #
# Provenance of the index files
# --------------------------------------------------------------------------- #

def test_loaded_indexes_record_their_digest_and_size(catalog, indexes):
    edb, _ = indexes
    prov = catalog.integrity["exploit-db"]
    assert prov.sha256 == digest_file(edb)
    assert prov.size == edb.stat().st_size
    assert prov.entries == 1
    assert prov.as_dict()["stale"] is False


def test_stale_index_is_flagged(tmp_path, indexes):
    edb, _ = indexes
    old = time.time() - (STALE_AFTER_DAYS + 30) * 86400
    os.utime(edb, (old, old))
    cat = ExploitCatalog()
    cat.load_exploitdb(edb)
    assert cat.integrity["exploit-db"].stale is True
    assert cat.stale_indexes() == ["exploit-db"]
    assert cat.integrity["exploit-db"].age_days > STALE_AFTER_DAYS


def test_stale_matters_because_absence_reads_as_safety(tmp_path, indexes):
    """A stale index reports 'nothing known' for anything newer, which is
    indistinguishable from 'genuinely no tooling exists'."""
    edb, _ = indexes
    cat = ExploitCatalog()
    cat.load_exploitdb(edb)
    assert cat.infer_maturity("CVE-2024-99999",
                              ExploitMaturity.NOT_DEFINED) is \
        ExploitMaturity.NOT_DEFINED     # silent, hence the staleness warning


# --------------------------------------------------------------------------- #
# Pinning
# --------------------------------------------------------------------------- #

def test_lockfile_round_trip_passes_verification(catalog, tmp_path):
    lock = tmp_path / "indexes.lock.json"
    catalog.write_lockfile(lock)
    assert catalog.verify_lockfile(lock) == []


def test_swapped_index_is_detected(indexes, tmp_path):
    """The attack: rewrite the msf index so every CVE looks weaponised, or
    strip it so the one that matters looks harmless."""
    edb, msf = indexes
    lock = tmp_path / "indexes.lock.json"
    first = ExploitCatalog()
    first.load_exploitdb(edb)
    first.load_metasploit(msf)
    first.write_lockfile(lock)

    msf.write_text(json.dumps({"m": {
        "name": "Backdoored entry", "fullname": "exploit/evil/thing",
        "type": "exploit", "references": [["CVE", "2018-15473"]]}}))

    second = ExploitCatalog()
    second.load_exploitdb(edb)
    second.load_metasploit(msf)
    with pytest.raises(IndexChanged, match="digest changed"):
        second.verify_lockfile(lock)


def test_non_strict_verification_reports_instead_of_raising(indexes, tmp_path):
    edb, msf = indexes
    lock = tmp_path / "indexes.lock.json"
    cat = ExploitCatalog()
    cat.load_exploitdb(edb)
    cat.write_lockfile(lock)
    msf.write_text(MSF)
    cat.load_metasploit(msf)
    complaints = cat.verify_lockfile(lock, strict=False)
    assert any("not pinned" in c for c in complaints)


def test_pinned_but_missing_index_is_a_complaint(catalog, tmp_path):
    lock = tmp_path / "indexes.lock.json"
    catalog.write_lockfile(lock)
    fresh = ExploitCatalog()
    with pytest.raises(IndexChanged, match="pinned but not loaded"):
        fresh.verify_lockfile(lock)


def test_missing_or_corrupt_lockfile(tmp_path, catalog):
    with pytest.raises(FileNotFoundError):
        catalog.verify_lockfile(tmp_path / "absent.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        catalog.verify_lockfile(bad)


# --------------------------------------------------------------------------- #
# Catalogue-driven correlation
# --------------------------------------------------------------------------- #

def test_availability_upgrades_declared_maturity_and_priority(catalog):
    fp = _fingerprint()
    without = build_leads(fp, [APACHE], CorrelationConfig())[0]
    with_cat = build_leads(fp, [APACHE], CorrelationConfig(), catalog)[0]

    assert without.exploit_maturity is ExploitMaturity.THEORETICAL
    assert with_cat.exploit_maturity is ExploitMaturity.WEAPONISED
    assert with_cat.priority > without.priority


def test_catalogue_never_downgrades_a_declared_maturity(catalog):
    weaponised = VulnEntry("CVE-2018-15473", "OpenSSH enum", "openssh",
                           (("<", "7.7"),), 5.3, ExploitMaturity.WEAPONISED)
    fp = Fingerprint(product="OpenSSH", version="7.4",
                     provenance=Provenance(source_tool="nmap-sV",
                                           principal="scanner-a",
                                           confidence=0.9))
    lead = build_leads(fp, [weaponised], CorrelationConfig(), catalog)[0]
    assert lead.exploit_maturity is ExploitMaturity.WEAPONISED


def test_score_accepts_an_overriding_maturity():
    fp = _fingerprint()
    low = score(APACHE, fp)
    high = score(APACHE, fp, ExploitMaturity.WEAPONISED)
    assert high > low


@pytest.mark.asyncio
async def test_engine_surfaces_availability_and_maturity_source(catalog,
                                                                tmp_path):
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine
    from reconkg.importers import ingest, parse_nmap_xml
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    xml = """<?xml version="1.0"?>
    <nmaprun><scaninfo type="syn"/>
     <host><status state="up"/>
      <address addr="10.10.10.42" addrtype="ipv4"/>
      <ports><port protocol="tcp" portid="80"><state state="open"/>
       <service name="http" product="Apache httpd" version="2.4.49" conf="10"
                method="probed"/></port></ports>
     </host></nmaprun>"""
    path = tmp_path / "scan.xml"
    path.write_text(xml)

    store, evidence = TargetStore(), EvidenceSource()
    await ingest(parse_nmap_xml(path), store, evidence, principal="scanner-a")
    engine = DiscoveryEngine(store, evidence, module_pipeline(),
                             reference=[APACHE], catalog=catalog)
    report = await engine.run("10.10.10.42")

    row = report.ledger[0]
    assert row.maturity == "weaponised"          # declared THEORETICAL
    assert row.maturity_source == "index"
    assert "EDB-50383" in row.availability
    assert "exploit/multi/http/apache_normalize_path_rce" in row.availability


@pytest.mark.asyncio
async def test_without_a_catalogue_nothing_changes(tmp_path):
    """The catalogue is optional; absent it, maturity stays as declared."""
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    store, evidence = TargetStore(), EvidenceSource()
    evidence.put("nmap-sS", "10.10.10.42",
                 {"ports": [{"number": 80, "state": "open"}]},
                 principal="scanner-a")
    evidence.put("nmap-sV", "10.10.10.42", {"services": [
        {"port": 80, "service": "http", "product": "Apache httpd",
         "version": "2.4.49", "confidence": 1.0}]}, principal="scanner-a")

    engine = DiscoveryEngine(store, evidence, module_pipeline(),
                             reference=[APACHE])
    row = (await engine.run("10.10.10.42")).ledger[0]
    assert row.maturity == "theoretical"
    assert row.maturity_source == "declared"
    assert row.availability == []


# --------------------------------------------------------------------------- #
# PROP-02  One CVE twice in a batch lost the whole batch
#
# Found by tests/test_properties.py::test_vulndb_ingest_accepts_any_generated
# _corpus, minimised to two entries with the same id. `VulnDB._write_batch`
# built one `cve_rows` tuple per entry with no intra-batch dedupe, so the
# `executemany` hit the primary key and raised `sqlite3.IntegrityError` --
# which aborts the transaction, so every good row in the batch (up to two
# thousand) went with the duplicate.
#
# Both sibling corpora already guard this and say why in a comment;
# `exploitdb._write_batch` and `scriptdb._write_batch` drop the earlier copy
# and keep the last, which matches the delete-then-insert semantics across
# batches. A control implemented in two of three corpora is a control with a
# hole in it, and a merged or re-published feed is not an exotic input.
# --------------------------------------------------------------------------- #

def test_prop02_a_duplicate_cve_in_one_batch_does_not_abort_the_ingest():
    from reconkg.vulndb import VulnDB

    entries = [VulnEntry("CVE-2021-41773", "first", "apache", cvss=9.8),
               VulnEntry("CVE-2021-42013", "other", "apache", cvss=9.8),
               VulnEntry("CVE-2021-41773", "second", "apache", cvss=7.5)]
    with VulnDB() as db:
        written = db.ingest(entries)
        assert written == 2
        assert db.stats().cves == 2
        # The good row survived, which is the part that matters.
        assert db.get("CVE-2021-42013") is not None
        # Last one wins, as it does across batches.
        assert db.get("CVE-2021-41773").title == "second"


def test_prop02_the_children_of_the_dropped_duplicate_go_with_it():
    """Deduping the parent and not its children would leave the alias table
    holding a row for a CVE revision that was never written."""
    from reconkg.vulndb import VulnDB

    with VulnDB() as db:
        db.ingest([VulnEntry("CVE-2021-41773", "first", "apache"),
                   VulnEntry("CVE-2021-41773", "second", "nginx")])
        stats = db.stats()
        assert stats.cves == 1
        assert stats.aliases == 1
        assert db.candidates_for_product("nginx 1.0")
        assert not db.candidates_for_product("apache 2.4.49")
