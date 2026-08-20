"""Round-2 Red Cell findings: RC-07 .. RC-10.

Surface added since the first audit -- scan importers, the availability
catalogue, and third-party module loading. Each test fails against the code
as it stood before this pass.
"""

from __future__ import annotations

import csv

import pytest

from reconkg.catalog import MAX_FIELD_BYTES, MAX_TITLE, ExploitCatalog
from reconkg.importers import (MAX_HOSTS_PER_IMPORT, MAX_PORTS_PER_HOST,
                               ingest, parse_nmap_xml)
from reconkg.models import Provenance
from reconkg.modules import ModuleRegistry
from reconkg.stages import EvidenceSource
from reconkg.store import TargetStore

HOSTILE_XML = """<?xml version="1.0"?>
<nmaprun><scaninfo type="syn"/>
 <host><status state="up"/>
  <address addr="10.0.0.1&#10;X-Injected: yes" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
 </host>
 <host><status state="up"/>
  <hostnames><hostname name="&lt;script&gt;alert(1)&lt;/script&gt;"/></hostnames>
  <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
 </host>
 <host><status state="up"/>
  <address addr="../../../etc/passwd" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="21"><state state="open"/></port></ports>
 </host>
 <host><status state="up"/>
  <address addr="10.10.10.42" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
 </host>
</nmaprun>
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


# --------------------------------------------------------------------------- #
# RC-07  Importer bypassed address validation
# --------------------------------------------------------------------------- #

def test_rc07_hostile_addresses_are_rejected_at_parse_time(tmp_path):
    """The API validated addresses; the importer did not. Same class as
    RC-04, reintroduced through a second ingress."""
    result = parse_nmap_xml(_write(tmp_path, "hostile.xml", HOSTILE_XML))
    assert list(result.hosts) == ["10.10.10.42"]
    assert len(result.warnings) >= 3
    assert any("rejected address" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_rc07_store_refuses_a_hostile_address_from_any_caller():
    """The real fix: validation on the write, not on each ingress.

    A future importer that forgets to validate cannot poison the graph,
    because the store is the only writer and it checks.
    """
    store = TargetStore()
    prov = Provenance(source_tool="operator", principal="p", confidence=1.0)
    for bad in ["10.0.0.1\r\nX-Injected: yes", "<script>alert(1)</script>",
                "../../../etc/passwd", "a" * 300, ""]:
        with pytest.raises(ValueError):
            await store.ensure_host(bad, prov)
    assert store.list_hosts() == []


@pytest.mark.asyncio
async def test_rc07_nothing_hostile_reaches_the_event_stream(tmp_path):
    """Event paths are broadcast to every analyst window; that is where a
    CRLF or a <script> would have landed."""
    store, evidence = TargetStore(), EvidenceSource()
    result = parse_nmap_xml(_write(tmp_path, "hostile.xml", HOSTILE_XML))
    added = await ingest(result, store, evidence, principal="scanner-a")

    assert added == ["10.10.10.42"]
    for event in store.event_log:
        for text in (event.target, event.path):
            assert "\n" not in text and "\r" not in text
            assert "<" not in text and ".." not in text


def test_rc07_valid_hostnames_still_import(tmp_path):
    xml = """<?xml version="1.0"?>
    <nmaprun><scaninfo type="connect"/>
     <host><status state="up"/>
      <hostnames><hostname name="box.htb"/></hostnames>
      <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
     </host>
    </nmaprun>"""
    result = parse_nmap_xml(_write(tmp_path, "ok.xml", xml))
    assert list(result.hosts) == ["box.htb"]


# --------------------------------------------------------------------------- #
# RC-08  Unbounded import
# --------------------------------------------------------------------------- #

def _many_hosts(count: int) -> str:
    hosts = "".join(
        f'<host><status state="up"/>'
        f'<address addr="10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}" '
        f'addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
        f'<state state="open"/></port></ports></host>'
        for i in range(count))
    return f'<?xml version="1.0"?><nmaprun><scaninfo type="syn"/>{hosts}</nmaprun>'


def test_rc08_host_count_is_capped_and_reported(tmp_path):
    path = _write(tmp_path, "big.xml", _many_hosts(MAX_HOSTS_PER_IMPORT + 200))
    result = parse_nmap_xml(path)
    assert result.host_count == MAX_HOSTS_PER_IMPORT
    assert any("truncated" in w for w in result.warnings)


def test_rc08_port_count_per_host_is_capped(tmp_path):
    ports = "".join(
        f'<port protocol="tcp" portid="{i + 1}"><state state="open"/></port>'
        for i in range(MAX_PORTS_PER_HOST + 50))
    xml = (f'<?xml version="1.0"?><nmaprun><scaninfo type="syn"/>'
           f'<host><status state="up"/>'
           f'<address addr="10.0.0.1" addrtype="ipv4"/>'
           f'<ports>{ports}</ports></host></nmaprun>')
    result = parse_nmap_xml(_write(tmp_path, "ports.xml", xml))
    assert len(result.hosts["10.0.0.1"]["ports"]) == MAX_PORTS_PER_HOST
    assert any("stopped at" in w for w in result.warnings)


# --------------------------------------------------------------------------- #
# RC-09  CSV field bomb
# --------------------------------------------------------------------------- #

def test_rc09_oversized_csv_field_fails_cleanly(tmp_path):
    """Previously surfaced as a raw _csv.Error escaping the loader."""
    path = _write(tmp_path, "files_exploits.csv",
                  "id,file,description,codes,verified\n1,a,"
                  + "A" * (MAX_FIELD_BYTES + 1024) + ",CVE-2021-41773,1\n")
    with pytest.raises(ValueError, match="malformed CSV"):
        ExploitCatalog().load_exploitdb(path)


def test_rc09_titles_are_bounded(tmp_path):
    path = _write(tmp_path, "files_exploits.csv",
                  "id,file,description,codes,verified\n1,a,"
                  + "A" * 5000 + ",CVE-2021-41773,1\n")
    cat = ExploitCatalog()
    cat.load_exploitdb(path)
    assert len(cat.edb_for("CVE-2021-41773")[0].title) == MAX_TITLE


def test_rc09_csv_field_limit_is_restored_after_loading(tmp_path):
    """The loader raises the global csv limit; leaking that to the rest of
    the process would be a side effect nobody asked for."""
    before = csv.field_size_limit()
    path = _write(tmp_path, "files_exploits.csv",
                  "id,file,description,codes,verified\n1,a,ok,CVE-1-1111,1\n")
    ExploitCatalog().load_exploitdb(path)
    assert csv.field_size_limit() == before

    bad = _write(tmp_path, "bad.csv",
                 "id,description\n1," + "A" * (MAX_FIELD_BYTES + 10) + "\n")
    with pytest.raises(ValueError):
        ExploitCatalog().load_exploitdb(bad)
    assert csv.field_size_limit() == before      # restored on the error path


# --------------------------------------------------------------------------- #
# RC-10  Silent arbitrary code execution
# --------------------------------------------------------------------------- #

def test_rc10_load_path_requires_explicit_trust(tmp_path):
    with pytest.raises(PermissionError, match="trusted=True"):
        ModuleRegistry().load_path(tmp_path)


def test_rc10_error_names_the_directory_being_executed(tmp_path):
    try:
        ModuleRegistry().load_path(tmp_path)
    except PermissionError as exc:
        assert str(tmp_path) in str(exc)
    else:  # pragma: no cover
        pytest.fail("expected PermissionError")


# --------------------------------------------------------------------------- #
# Full round trip after the fixes
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_clean_scan_still_imports_and_correlates(tmp_path):
    """Regression guard: the hardening must not break the happy path."""
    from reconkg.builtin_modules import module_pipeline
    from reconkg.engine import DiscoveryEngine

    xml = """<?xml version="1.0"?>
    <nmaprun><scaninfo type="syn"/>
     <host><status state="up"/>
      <address addr="10.10.10.42" addrtype="ipv4"/>
      <ports>
       <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4" conf="10"
                 method="probed"/></port>
      </ports>
     </host>
    </nmaprun>"""
    store, evidence = TargetStore(), EvidenceSource()
    result = parse_nmap_xml(_write(tmp_path, "clean.xml", xml))
    await ingest(result, store, evidence, principal="scanner-a")
    report = await DiscoveryEngine(store, evidence, module_pipeline()).run(
        "10.10.10.42")
    assert any(r.cve_id == "CVE-2018-15473" for r in report.ledger)
