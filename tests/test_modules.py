"""Module system, gap planner, and hand-off."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from reconkg.builtin_modules import (BannerProbeModule, SynSweepModule,
                                     module_pipeline)
from reconkg.modules import (ModuleInfo, ModuleRegistry, Option, OptionDataStore,
                             OptType, Rank, ReconModule, RefType, Reference,
                             registry)
from reconkg.planner import Gap, GapPlanner, render_plan
from reconkg.stages import Outcome, StageResult
from reconkg.vulnref import DEFAULT_REFERENCE, LedgerRow


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #

def test_option_coercion_by_type():
    assert Option("A", OptType.INT).coerce("42") == 42
    assert Option("A", OptType.INT).coerce("0x10") == 16
    assert Option("A", OptType.FLOAT).coerce("0.5") == 0.5
    assert Option("A", OptType.BOOL).coerce("yes") is True
    assert Option("A", OptType.BOOL).coerce("OFF") is False
    assert Option("A", OptType.PORT).coerce("443") == 443
    assert Option("A", OptType.ADDRESS).coerce("Example.COM") == "example.com"


@pytest.mark.parametrize("opt,bad,message", [
    (Option("A", OptType.INT), "abc", "must be an integer"),
    (Option("A", OptType.BOOL), "maybe", "must be true or false"),
    (Option("A", OptType.PORT), "70000", "must be 1-65535"),
    (Option("A", OptType.PORT), "0", "must be 1-65535"),
    (Option("A", OptType.ADDRESS), "<script>", "not a valid IP"),
    (Option("A", OptType.FLOAT, minimum=0.0, maximum=1.0), "2.0", "must be <="),
    (Option("A", OptType.FLOAT, minimum=0.5), "0.1", "must be >="),
    (Option("A", OptType.ENUM, choices=("x", "y")), "z", "must be one of"),
])
def test_option_rejection_messages_are_actionable(opt, bad, message):
    with pytest.raises(ValueError, match=message):
        opt.coerce(bad)


def test_enum_option_requires_choices():
    with pytest.raises(ValueError):
        Option("A", OptType.ENUM)


def test_datastore_tracks_required_and_defaults():
    ds = OptionDataStore([
        Option("RHOST", OptType.ADDRESS, None, True),
        Option("DEPTH", OptType.INT, 3, False),
    ])
    assert ds.missing_required() == ["RHOST"]
    assert ds.get("DEPTH") == 3
    with pytest.raises(ValueError, match="required options not set"):
        ds.validate()
    ds.set("RHOST", "10.0.0.1")
    ds.validate()
    assert ds.get("RHOST") == "10.0.0.1"


def test_datastore_unset_restores_default():
    ds = OptionDataStore([Option("DEPTH", OptType.INT, 3)])
    ds.set("DEPTH", 9)
    ds.unset("DEPTH")
    assert ds.get("DEPTH") == 3


def test_unknown_option_is_rejected():
    ds = OptionDataStore([Option("DEPTH", OptType.INT, 3)])
    with pytest.raises(KeyError, match="unknown option"):
        ds.set("NOPE", 1)


def test_options_are_per_instance_not_shared():
    a, b = SynSweepModule(), SynSweepModule()
    a.options.set("TIMEOUT", 99)
    assert b.opt("TIMEOUT") == 8.0


# --------------------------------------------------------------------------- #
# Metadata and registry
# --------------------------------------------------------------------------- #

def test_fullname_format_is_enforced():
    with pytest.raises(ValueError, match="category/sub/name"):
        ModuleInfo(fullname="NotAPath", name="x")


def test_builtin_modules_are_registered():
    assert len(registry) >= 5
    assert registry.get("recon/fingerprint/banner_probe") is BannerProbeModule


def test_search_by_keyword_category_rank_and_cve():
    assert registry.search("banner")
    assert all(c.meta.category == "recon"
               for c in registry.search("category:recon"))
    assert all(c.meta.rank.order >= Rank.GREAT.order
               for c in registry.search("rank:great"))
    assert registry.search("nonexistentkeyword") == []


def test_search_results_are_ranked_best_first():
    results = registry.search("recon")
    orders = [c.meta.rank.order for c in results]
    assert orders == sorted(orders, reverse=True)


def test_unknown_module_error_suggests_a_near_match():
    with pytest.raises(KeyError, match="Did you mean"):
        registry.get("recon/wrong/banner_probe")


def test_reference_urls():
    assert Reference(RefType.CVE, "CVE-2021-41773").url().endswith("CVE-2021-41773")
    assert "exploit-db" in Reference(RefType.EDB, "50383").url()
    assert "attack.mitre.org" in Reference(RefType.ATTACK, "T1046").url()


def test_info_output_contains_the_operator_relevant_sections():
    text = BannerProbeModule().info()
    for section in ["Name:", "Module:", "Rank:", "Basic options:",
                    "Advanced options:", "Description:", "References:",
                    "Notes:"]:
        assert section in text
    assert "recon/fingerprint/banner_probe" in text
    assert "RHOST" in text


def test_rank_does_not_leak_into_the_confidence_model():
    """A module author must not be able to move a confidence score by
    declaring a high rank -- that was the RC-01 class of bug.

    Checks for *attribute access* on a module's rank, not for the word
    "rank" anywhere in the file. The original substring test failed the
    moment a docstring said "rank on severity alone", which is prose about
    ordering, not a read of `meta.rank`. A test that fires on vocabulary
    rather than behaviour trains people to reword comments to get green.
    """
    import ast
    import inspect
    from reconkg import engine, models, sources, vulnref

    for mod in (engine, models, sources, vulnref):
        tree = ast.parse(inspect.getsource(mod))
        reads = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Attribute) and node.attr == "rank"]
        assert not reads, (
            f"{mod.__name__} reads `.rank` at line "
            f"{reads[0].lineno}; module rank must not reach the "
            "confidence model")


# --------------------------------------------------------------------------- #
# Third-party loading
# --------------------------------------------------------------------------- #

GOOD_MODULE = '''
from reconkg.modules import ModuleInfo, Option, OptType, Rank, ReconModule
from reconkg.stages import Outcome, StageResult

class ThirdPartyModule(ReconModule):
    meta = ModuleInfo(fullname="thirdparty/test/probe", name="Test probe",
                      description="loaded from disk", rank=Rank.LOW)
    option_spec = (Option("RHOST", OptType.ADDRESS, None, True),)
    tool = "third-party"

    async def run(self, address, evidence, context):
        return StageResult(Outcome.NO_DATA, "stub")
'''

BROKEN_MODULE = "import a_module_that_does_not_exist\n"


def test_load_path_registers_third_party_modules(tmp_path):
    (tmp_path / "good.py").write_text(textwrap.dedent(GOOD_MODULE))
    reg = ModuleRegistry()
    assert reg.load_path(tmp_path, trusted=True) == 1
    module = reg.create("thirdparty/test/probe", RHOST="10.0.0.5")
    assert module.opt("RHOST") == "10.0.0.5"


def test_one_broken_file_does_not_stop_the_rest_loading(tmp_path):
    (tmp_path / "good.py").write_text(textwrap.dedent(GOOD_MODULE))
    (tmp_path / "broken.py").write_text(BROKEN_MODULE)
    reg = ModuleRegistry()
    assert reg.load_path(tmp_path, trusted=True) == 1
    assert len(reg.load_errors) == 1
    assert "broken.py" in reg.load_errors[0][0]


def test_load_path_rejects_a_non_directory(tmp_path):
    with pytest.raises(NotADirectoryError):
        ModuleRegistry().load_path(tmp_path / "nope", trusted=True)


def test_load_path_requires_explicit_trust(tmp_path):
    """RC-10: arbitrary code execution must be opted into at the call site."""
    with pytest.raises(PermissionError, match="executes every .py"):
        ModuleRegistry().load_path(tmp_path)


def test_duplicate_fullname_is_refused():
    reg = ModuleRegistry()

    class A(ReconModule):
        meta = ModuleInfo(fullname="x/y/z", name="A")

        async def run(self, address, evidence, context):
            return StageResult(Outcome.NO_DATA)

    class B(ReconModule):
        meta = ModuleInfo(fullname="x/y/z", name="B")

        async def run(self, address, evidence, context):
            return StageResult(Outcome.NO_DATA)

    reg.register(A)
    with pytest.raises(ValueError, match="duplicate"):
        reg.register(B)


# --------------------------------------------------------------------------- #
# Modules still work as pipeline stages
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_module_pipeline_behaves_like_the_stage_pipeline():
    from reconkg.demo import TARGET, build_evidence
    from reconkg.engine import DiscoveryEngine
    from reconkg.store import TargetStore

    store = TargetStore()
    report = await DiscoveryEngine(store, build_evidence(),
                                   module_pipeline()).run(TARGET)
    assert [a.outcome for a in report.attempts] == [
        "timeout", "success", "ambiguous", "success", "success"]
    assert report.ledger[0].cve_id == "CVE-2021-41773"


# --------------------------------------------------------------------------- #
# Planner
# --------------------------------------------------------------------------- #

@pytest.fixture
async def scanned_host():
    from reconkg.demo import TARGET, build_evidence
    from reconkg.engine import DiscoveryEngine
    from reconkg.store import TargetStore

    store = TargetStore()
    await DiscoveryEngine(store, build_evidence(), module_pipeline()).run(TARGET)
    return store.get(TARGET)


@pytest.mark.asyncio
async def test_planner_assigns_modules_to_knowledge_gaps(scanned_host):
    plan = GapPlanner().plan(scanned_host)
    by_gap = {r.gap: r for r in plan}

    assert by_gap[Gap.AMBIGUOUS_VERSION].module == "recon/fingerprint/deep_probe"
    assert by_gap[Gap.FILTERED_PORT].module == "recon/discovery/connect_sweep"
    assert by_gap[Gap.AMBIGUOUS_VERSION].options["RHOST"] == scanned_host.address


@pytest.mark.asyncio
async def test_planner_never_assigns_a_module_to_a_vulnerability_lead(
        scanned_host):
    """Structural invariant: leads route to the operator, not to a module.

    This is what stops the planner becoming an auto-exploit chain once a
    module directory is populated -- there is no slot to fill.
    """
    plan = GapPlanner().plan(scanned_host)
    leads = [r for r in plan if r.gap is Gap.LEAD_READY]
    assert leads, "expected at least one lead in the fixture"
    for rec in leads:
        assert rec.module is None
        assert rec.action == "handoff"
        assert "handoff" in rec.command()


@pytest.mark.asyncio
async def test_every_assigned_module_is_actually_instantiable(scanned_host):
    for rec in GapPlanner().plan(scanned_host):
        if rec.module:
            instance = registry.create(rec.module)
            for key, value in rec.options.items():
                instance.options.set(key, value)
            assert instance.options.missing_required() == []


@pytest.mark.asyncio
async def test_planner_flags_single_submitter_fingerprints(scanned_host):
    plan = GapPlanner().plan(scanned_host)
    uncorroborated = [r for r in plan if r.gap is Gap.UNCORROBORATED]
    assert uncorroborated
    assert uncorroborated[0].module is None
    assert "single submitter" in uncorroborated[0].reason


def test_planner_drops_gaps_whose_module_is_not_registered():
    from reconkg.models import Host, Port, PortState, Provenance
    empty = ModuleRegistry()
    host = Host(address="10.0.0.9",
                provenance=Provenance(source_tool="operator", confidence=1.0))
    host.ports.append(Port(number=80, state=PortState.OPEN,
                           provenance=Provenance(source_tool="nmap-sT",
                                                 confidence=0.9)))
    plan = GapPlanner(modules=empty).plan(host)
    assert plan and all(r.module is None for r in plan)


@pytest.mark.asyncio
async def test_render_plan_is_readable(scanned_host):
    text = render_plan(GapPlanner().plan(scanned_host))
    assert "gap(s) identified" in text
    assert "-> use recon/" in text
    assert "[operator action, no module]" in text


def test_render_plan_handles_a_complete_graph():
    assert "No gaps identified" in render_plan([])


# --------------------------------------------------------------------------- #
# Hand-off
# --------------------------------------------------------------------------- #

def _row(**kw):
    base = dict(target="10.10.10.42", port=80, protocol="tcp", service="http",
                product="Apache httpd", version="2.4.49",
                cve_id="CVE-2021-41773", title="Apache path traversal",
                cvss=9.8, maturity="weaponised", fingerprint_confidence=0.92,
                corroborated_by=["nmap-sV-intensity9", "whatweb"],
                independent_principals=["scanner-a", "scanner-b"],
                priority=1.0, rationale="2.4.49 in range")
    base.update(kw)
    return LedgerRow(**base)


def test_handoff_emits_lookups_not_invented_exploit_paths():
    from reconkg.handoff import build_handoff
    h = build_handoff(_row(), DEFAULT_REFERENCE)
    joined = " ".join(h.lookups)
    assert "searchsploit --cve CVE-2021-41773" in joined
    # Nothing that claims to be a ready-to-run exploit module.
    assert "exploit/" not in joined
    assert h.operator_supplied == []


def test_handoff_surfaces_the_reason_a_lead_may_be_wrong():
    from reconkg.handoff import build_handoff
    weak = build_handoff(_row(independent_principals=["scanner-a"],
                              fingerprint_confidence=0.5), DEFAULT_REFERENCE)
    text = " ".join(weak.caveats)
    assert "one independent submitter" in text.lower()
    assert "confidence is 0.50" in text
    assert "backport" in text.lower()


def test_handoff_includes_operator_supplied_commands():
    from reconkg.handoff import build_handoff
    from reconkg.vulnref import VulnEntry
    entry = VulnEntry("CVE-2021-41773", "t", "apache", (), 9.8,
                      handoff=("my-verified-command --target {}",))
    h = build_handoff(_row(), [entry])
    assert h.operator_supplied == ["my-verified-command --target {}"]


def test_handoff_render_carries_the_scope_warning():
    from reconkg.handoff import render_handoff, SCOPE_WARNING
    assert SCOPE_WARNING in render_handoff(_row(), DEFAULT_REFERENCE)


def test_handoff_quotes_shell_metacharacters():
    """A hostile product string must survive as one shell token.

    The operator is expected to paste these lines into a terminal, so an
    unquoted `;` in a fingerprint would be command injection with the
    operator as the delivery mechanism.
    """
    import shlex
    from reconkg.handoff import build_handoff
    h = build_handoff(_row(product="Apache; rm -rf /", version="2.4.49"),
                      DEFAULT_REFERENCE)
    searchsploit = [c for c in h.lookups if c.startswith("searchsploit ")][-1]
    tokens = shlex.split(searchsploit)
    assert tokens[0] == "searchsploit"
    assert tokens[1] == "Apache; rm -rf / 2.4.49"   # one token, not three
    assert len(tokens) == 2
