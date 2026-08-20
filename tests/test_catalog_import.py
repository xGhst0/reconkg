"""Exploit-availability catalogue and scan importers."""

from __future__ import annotations

import json
import textwrap
from datetime import date

import pytest

from reconkg.catalog import (ExploitCatalog, ExploitRecord, normalise_cve)
from reconkg.importers import ImportResult, ingest, parse_nmap_xml
from reconkg.models import ExploitMaturity

# --------------------------------------------------------------------------- #
# Fixtures -- synthetic files shaped like the real indexes
# --------------------------------------------------------------------------- #

EDB_CSV = """id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
50383,exploits/multiple/webapps/50383.sh,Apache HTTP Server 2.4.49 - Path Traversal & RCE,2021-10-05,Lucas,webapps,multiple,80,2021-10-05,2021-10-06,1,CVE-2021-41773;OSVDB-1234,,,,,
50406,exploits/multiple/webapps/50406.py,Apache 2.4.50 - Path Traversal,2021-10-08,Anon,webapps,multiple,80,2021-10-08,2021-10-08,0,CVE-2021-42013,,,,,
41738,exploits/windows/remote/41738.py,SMB - Remote Code Execution,2017-03-14,sleepya,remote,windows,445,2017-03-14,2017-03-14,1,CVE-2017-0144,,,,,
99999,exploits/linux/local/99999.c,Something with no CVE at all,2019-01-01,Nobody,local,linux,,2019-01-01,2019-01-01,0,,,,,,
notanid,broken/row.txt,Malformed row,,,,,,,,,,,,,
"""

MSF_PAIRS = {
    "exploit_multi_http_apache_normalize_path_rce": {
        "name": "Apache Normalize Path Traversal RCE",
        "fullname": "exploit/multi/http/apache_normalize_path_rce",
        "rank": 600,
        "disclosure_date": "2021-05-10",
        "type": "exploit",
        "platform": ["Unix", "Linux"],
        "references": [["CVE", "2021-41773"], ["URL", "https://example.test"]],
    },
    "exploit_windows_smb_ms17_010": {
        "name": "MS17-010 EternalBlue",
        "fullname": "exploit/windows/smb/ms17_010_eternalblue",
        "rank": 500,
        "disclosure_date": "2017-03-14",
        "type": "exploit",
        "platform": "Windows",
        "references": ["CVE-2017-0144"],          # flat-string shape
    },
    "auxiliary_scanner_no_refs": {
        "name": "Some scanner",
        "fullname": "auxiliary/scanner/http/thing",
        "type": "auxiliary",
        "references": [],
    },
    "malformed": {"name": "no fullname anywhere"},
}

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <scaninfo type="syn" protocol="tcp"/>
  <host>
    <status state="up"/>
    <address addr="10.10.10.42" addrtype="ipv4"/>
    <hostnames><hostname name="box.htb"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4" conf="10"
                 method="probed" extrainfo="protocol 2.0">
          <cpe>cpe:/a:openbsd:openssh:7.4</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" conf="8" method="probed"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" conf="3" method="table"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="filtered"/>
      </port>
      <port protocol="tcp" portid="notanumber">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.10.10.43" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

XXE_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/></host></nmaprun>
"""


@pytest.fixture
def catalog(tmp_path):
    (tmp_path / "files_exploits.csv").write_text(EDB_CSV)
    (tmp_path / "msf.json").write_text(json.dumps(MSF_PAIRS))
    cat = ExploitCatalog()
    cat.load_exploitdb(tmp_path / "files_exploits.csv")
    cat.load_metasploit(tmp_path / "msf.json")
    return cat


# --------------------------------------------------------------------------- #
# CVE normalisation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("CVE-2021-41773", "CVE-2021-41773"),
    ("cve_2021_41773", "CVE-2021-41773"),
    ("cve 2021 41773", "CVE-2021-41773"),
    ("2021-41773", "CVE-2021-41773"),
    ("CVE-2021-4177312", "CVE-2021-4177312"),
    ("OSVDB-1234", None),
    ("", None),
    ("nonsense", None),
])
def test_cve_normalisation(raw, expected):
    assert normalise_cve(raw) == expected


# --------------------------------------------------------------------------- #
# Exploit-DB index
# --------------------------------------------------------------------------- #

def test_edb_index_loads_and_skips_malformed_rows(catalog):
    stats = catalog.stats["exploit-db"]
    assert stats.rows == 5
    assert stats.loaded == 4          # the "notanid" row is dropped
    assert stats.skipped == 1
    assert stats.with_cve == 3


def test_edb_lookup_by_cve(catalog):
    hits = catalog.edb_for("CVE-2021-41773")
    assert [h.identifier for h in hits] == ["EDB-50383"]
    assert hits[0].verified is True
    assert hits[0].published == date(2021, 10, 5)
    assert "exploit-db.com/exploits/50383" in hits[0].url()


def test_edb_lookup_accepts_loose_cve_formatting(catalog):
    assert catalog.edb_for("cve 2021 41773")
    assert catalog.edb_for("2021-41773")


def test_edb_multiple_codes_are_split(catalog):
    record = catalog.edb_for("CVE-2021-41773")[0]
    assert record.cves == ("CVE-2021-41773",)   # OSVDB dropped, not mangled


def test_positional_csv_changes_do_not_break_parsing(tmp_path):
    """Columns reordered and a new one added -- header-name parsing survives."""
    reordered = ("codes,description,id,verified,brand_new_column,file\n"
                 "CVE-2021-41773,Apache RCE,50383,1,xyz,exploits/a.sh\n")
    path = tmp_path / "files_exploits.csv"
    path.write_text(reordered)
    cat = ExploitCatalog()
    cat.load_exploitdb(path)
    assert cat.edb_for("CVE-2021-41773")[0].identifier == "EDB-50383"


def test_wrong_csv_is_rejected_with_a_useful_message(tmp_path):
    path = tmp_path / "files_exploits.csv"
    path.write_text("alpha,beta\n1,2\n")
    with pytest.raises(ValueError, match="does not look like"):
        ExploitCatalog().load_exploitdb(path)


def test_missing_index_raises_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError):
        ExploitCatalog().load_exploitdb(tmp_path / "absent.csv")


# --------------------------------------------------------------------------- #
# Metasploit index
# --------------------------------------------------------------------------- #

def test_msf_index_handles_both_reference_shapes(catalog):
    assert catalog.msf_modules_for("CVE-2021-41773") == [
        "exploit/multi/http/apache_normalize_path_rce"]
    assert catalog.msf_modules_for("CVE-2017-0144") == [
        "exploit/windows/smb/ms17_010_eternalblue"]


def test_msf_entry_without_fullname_is_skipped(catalog):
    stats = catalog.stats["metasploit"]
    assert stats.rows == 4
    assert stats.loaded == 3
    assert stats.skipped == 1


def test_msf_modules_for_unknown_cve_is_empty_not_guessed(catalog):
    """The whole point: no module name is ever invented."""
    assert catalog.msf_modules_for("CVE-1999-0001") == []


def test_msf_json_that_is_a_list_also_parses(tmp_path):
    path = tmp_path / "msf.json"
    path.write_text(json.dumps(list(MSF_PAIRS.values())))
    cat = ExploitCatalog()
    stats = cat.load_metasploit(path)
    assert stats.loaded == 3


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "msf.json"
    path.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        ExploitCatalog().load_metasploit(path)


# --------------------------------------------------------------------------- #
# Maturity inference
# --------------------------------------------------------------------------- #

def test_msf_presence_infers_weaponised(catalog):
    assert catalog.infer_maturity("CVE-2021-41773") is ExploitMaturity.WEAPONISED


def test_verified_edb_only_infers_functional(catalog):
    """CVE-2021-42013 has an unverified EDB entry and no msf module."""
    assert catalog.infer_maturity("CVE-2021-42013") is \
        ExploitMaturity.PROOF_OF_CONCEPT


def test_unknown_cve_leaves_the_declared_value_untouched(catalog):
    assert catalog.infer_maturity("CVE-1999-0001",
                                  ExploitMaturity.THEORETICAL) is \
        ExploitMaturity.THEORETICAL


def test_inference_never_downgrades_an_operator_judgement(catalog):
    """An operator who said WEAPONISED knows something the index does not."""
    assert catalog.infer_maturity("CVE-2021-42013",
                                  ExploitMaturity.WEAPONISED) is \
        ExploitMaturity.WEAPONISED


def test_catalog_holds_identifiers_not_code(catalog):
    """Structural check: every record is metadata, no payload field exists."""
    for record in catalog.search("apache") + catalog.search("smb"):
        assert isinstance(record, ExploitRecord)
        assert not hasattr(record, "code")
        assert not hasattr(record, "payload")
        # `path` is an index-relative filename, not file contents
        assert len(record.path) < 200


def test_autoload_reports_missing_tooling_without_raising():
    report = ExploitCatalog().autoload(edb_paths=("/nonexistent/a.csv",),
                                       msf_paths=("/nonexistent/b.json",))
    assert report == {"exploit-db": "not installed",
                      "metasploit": "not installed"}


def test_lookup_commands_are_read_only():
    edb = ExploitRecord("exploit-db", "EDB-50383", "t")
    msf = ExploitRecord("metasploit", "exploit/multi/http/x", "t")
    assert edb.lookup_command() == "searchsploit -x 50383"
    assert "info exploit/multi/http/x" in msf.lookup_command()
    # Nothing that would fire a module.
    for command in (edb.lookup_command(), msf.lookup_command()):
        assert "run" not in command.split()
        assert "exploit" not in command.split()


# --------------------------------------------------------------------------- #
# nmap XML import
# --------------------------------------------------------------------------- #

@pytest.fixture
def scan_file(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)
    return path


def test_nmap_import_extracts_hosts_ports_and_services(scan_file):
    result = parse_nmap_xml(scan_file)
    assert result.host_count == 1                    # the down host is skipped
    payload = result.hosts["10.10.10.42"]
    assert {p["number"] for p in payload["ports"]} == {22, 80, 443, 445}
    assert {s["port"] for s in payload["services"]} == {22, 80, 443}


def test_nmap_confidence_comes_from_the_conf_attribute(scan_file):
    payload = parse_nmap_xml(scan_file).hosts["10.10.10.42"]
    by_port = {s["port"]: s for s in payload["services"]}
    assert by_port[22]["confidence"] == 1.0          # conf=10, probed
    assert by_port[80]["confidence"] == 0.8          # conf=8
    assert by_port[22]["cpe"] == "cpe:/a:openbsd:openssh:7.4"


def test_table_only_service_is_capped_and_marked_ambiguous(scan_file):
    """method="table" means nmap guessed from the port number. It never
    spoke to the service, so this must not become a confident fingerprint."""
    payload = parse_nmap_xml(scan_file).hosts["10.10.10.42"]
    https = next(s for s in payload["services"] if s["port"] == 443)
    assert https["ambiguous"] is True
    assert https["confidence"] <= 0.3


def test_product_without_version_is_ambiguous(scan_file):
    payload = parse_nmap_xml(scan_file).hosts["10.10.10.42"]
    http = next(s for s in payload["services"] if s["port"] == 80)
    assert http["product"] == "Apache httpd"
    assert http["version"] is None
    assert http["ambiguous"] is True


def test_filtered_port_state_and_confidence(scan_file):
    payload = parse_nmap_xml(scan_file).hosts["10.10.10.42"]
    smb = next(p for p in payload["ports"] if p["number"] == 445)
    assert smb["state"] == "filtered"
    assert smb["confidence"] < 0.95


def test_unparseable_portid_is_warned_not_fatal(scan_file):
    result = parse_nmap_xml(scan_file)
    assert any("portid" in w for w in result.warnings)
    assert result.host_count == 1


def test_xxe_document_is_refused(tmp_path):
    path = tmp_path / "evil.xml"
    path.write_text(XXE_XML)
    with pytest.raises(Exception):
        parse_nmap_xml(path)


def test_non_nmap_xml_is_rejected(tmp_path):
    path = tmp_path / "other.xml"
    path.write_text("<rss><channel/></rss>")
    with pytest.raises(ValueError, match="not nmap XML"):
        parse_nmap_xml(path)


def test_missing_scan_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml(tmp_path / "nope.xml")


def test_import_summary_is_readable(scan_file):
    text = parse_nmap_xml(scan_file).summary()
    assert "Importing 'Nmap XML'" in text
    assert "10.10.10.42" in text


# --------------------------------------------------------------------------- #
# End to end: import a scan, run the pipeline over it
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_imported_scan_flows_through_the_engine(scan_file):
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    store, evidence = TargetStore(), EvidenceSource()
    result = parse_nmap_xml(scan_file)
    added = await ingest(result, store, evidence, principal="scanner-a")
    assert result.port_tool == "nmap-sS"      # <scaninfo type="syn">
    assert added == ["10.10.10.42"]

    report = await DiscoveryEngine(store, evidence, module_pipeline()).run(
        "10.10.10.42")
    host = store.get("10.10.10.42")
    assert {p.number for p in host.ports} >= {22, 80}
    ssh = host.find_port(22).service
    assert ssh.best_fingerprint().version == "7.4"
    assert any(r.cve_id == "CVE-2018-15473" for r in report.ledger)


@pytest.mark.asyncio
async def test_reimporting_the_same_file_does_not_forge_corroboration(scan_file):
    """One operator importing twice is still one opinion."""
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine
    from reconkg.stages import EvidenceSource
    from reconkg.store import TargetStore

    store, evidence = TargetStore(), EvidenceSource()
    engine = DiscoveryEngine(store, evidence, module_pipeline())
    for _ in range(3):
        await ingest(parse_nmap_xml(scan_file), store, evidence,
                     principal="scanner-a")
        await engine.run("10.10.10.42")

    fp = store.get("10.10.10.42").find_port(22).service.best_fingerprint()
    assert fp.corroborating_principals == {"scanner-a"}
    assert fp.confidence == 0.75      # the nmap-sV ceiling, not 3x compounded
