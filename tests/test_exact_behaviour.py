"""Exact-value tests for the decision logic, written to kill mutants.

Every test here exists because `audit/mutation.py` broke a specific line and
the suite did not notice. The pattern in the survivors was consistent: tests
asserted *directions* ("corroboration raises confidence", "a weak fingerprint
produces no leads") and never the arithmetic underneath. A direction test
passes whether the bonus is 1.125 or 2.125, so the constants that decide how
a ledger ranks were unpinned.

These assert the numbers. If a formula changes deliberately, these fail and
you update them on purpose -- which is the point.
"""

from __future__ import annotations

import ipaddress
import time

import pytest

from reconkg.auth import Role, _scope_matches, validate_address
from reconkg.catalog import ExploitCatalog, ExploitRecord
from reconkg.importers import _normalise_state, _service_entry
from reconkg.models import (MAX_PROVENANCE_HEAD, MAX_PROVENANCE_TAIL,
                            ExploitMaturity, Fingerprint, Provenance)
from reconkg.ratelimit import Bucket, RateLimiter
from reconkg.sources import SourceRegistry
from reconkg.vulnref import (CorrelationConfig, VulnEntry, _corroboration_bonus,
                             build_leads, score)


def _fp(principals=("scanner-a",), confidence=0.8, version="2.4.49"):
    fp = Fingerprint(product="Apache httpd", version=version,
                     provenance=Provenance(source_tool="nmap-sV",
                                           principal=principals[0],
                                           confidence=confidence))
    for extra in principals[1:]:
        fp.provenance_log.append(Provenance(source_tool="other",
                                            principal=extra,
                                            confidence=confidence))
    return fp


# --------------------------------------------------------------------------- #
# Corroboration bonus -- the formula was entirely unpinned
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("principals,expected", [
    ((), 1.0),
    (("a",), 1.0),
    (("a", "b"), 1.125),
    (("a", "b", "c"), 1.25),
    (("a", "b", "c", "d"), 1.25),      # capped
    (("a", "b", "c", "d", "e"), 1.25),
])
def test_corroboration_bonus_exact_values(principals, expected):
    fp = _fp(principals or ("system",))
    if not principals:
        fp.provenance_log[:] = [Provenance(source_tool="t", principal="system",
                                           confidence=0.5)]
    assert _corroboration_bonus(fp) == pytest.approx(expected)


def test_system_principal_never_counts_toward_corroboration():
    """`system` is reconkg's own decay bookkeeping, not an opinion."""
    fp = _fp(("scanner-a",))
    fp.provenance_log.append(Provenance(source_tool="nmap-sV",
                                        principal="system", confidence=0.5))
    assert _corroboration_bonus(fp) == 1.0


def test_bonus_is_capped_not_unbounded():
    fp = _fp(tuple(f"scanner-{i}" for i in range(50)))
    assert _corroboration_bonus(fp) == 1.25


# --------------------------------------------------------------------------- #
# score() arithmetic
# --------------------------------------------------------------------------- #

def test_score_exact_for_a_single_source():
    entry = VulnEntry("CVE-X", "t", "apache", (), 8.0,
                      ExploitMaturity.FUNCTIONAL)          # weight 0.9
    fp = _fp(("scanner-a",), confidence=0.5)
    # 8.0/10 * 0.9 * 0.5 * 1.0 (bonus) * 1.0 (has version) = 0.36
    assert score(entry, fp) == pytest.approx(0.36)


def test_score_applies_the_corroboration_bonus():
    entry = VulnEntry("CVE-X", "t", "apache", (), 8.0,
                      ExploitMaturity.FUNCTIONAL)
    fp = _fp(("a", "b"), confidence=0.5)
    assert score(entry, fp) == pytest.approx(0.405)        # 0.36 * 1.125


def test_score_penalises_a_missing_version_by_0_35():
    entry = VulnEntry("CVE-X", "t", "apache", (), 8.0,
                      ExploitMaturity.FUNCTIONAL, requires_version=False)
    versioned = score(entry, _fp(("a",), 0.5))
    unversioned = score(entry, _fp(("a",), 0.5, version=None))
    assert unversioned == pytest.approx(versioned * 0.35)


def test_score_is_clamped_to_one_not_merely_large():
    entry = VulnEntry("CVE-X", "t", "apache", (), 10.0,
                      ExploitMaturity.WEAPONISED)
    assert score(entry, _fp(("a", "b", "c"), confidence=1.0)) == 1.0


def test_score_rounds_to_four_places():
    entry = VulnEntry("CVE-X", "t", "apache", (), 7.7,
                      ExploitMaturity.PROOF_OF_CONCEPT)     # weight 0.7
    value = score(entry, _fp(("a",), confidence=0.3333))
    assert value == round(value, 4)
    assert value == pytest.approx(0.1796, abs=5e-5)


def test_maturity_override_changes_the_score():
    entry = VulnEntry("CVE-X", "t", "apache", (), 8.0,
                      ExploitMaturity.THEORETICAL)          # weight 0.4
    fp = _fp(("a",), confidence=1.0)
    assert score(entry, fp) == pytest.approx(0.32)
    assert score(entry, fp, ExploitMaturity.WEAPONISED) == pytest.approx(0.8)


# --------------------------------------------------------------------------- #
# build_leads boundaries
# --------------------------------------------------------------------------- #

ANY_APACHE = VulnEntry("CVE-X", "t", "apache", ((">=", "2.0"),), 9.0,
                       ExploitMaturity.FUNCTIONAL)


def test_confidence_exactly_at_the_floor_still_produces_a_lead():
    """`<` not `<=`: the floor is inclusive."""
    cfg = CorrelationConfig(min_confidence=0.45)
    assert build_leads(_fp(("a",), confidence=0.45), [ANY_APACHE], cfg)
    assert build_leads(_fp(("a",), confidence=0.4499), [ANY_APACHE], cfg) == []


def test_lead_cap_returns_exactly_the_limit():
    many = [VulnEntry(f"CVE-{i}", "t", "apache", ((">=", "2.0"),), 5.0)
            for i in range(20)]
    for limit in (1, 3, 7):
        cfg = CorrelationConfig(max_leads_per_service=limit)
        assert len(build_leads(_fp(("a",), 0.9), many, cfg)) == limit


def test_leads_are_returned_highest_priority_first():
    entries = [
        VulnEntry("CVE-LOW", "t", "apache", ((">=", "2.0"),), 2.0),
        VulnEntry("CVE-HIGH", "t", "apache", ((">=", "2.0"),), 9.8,
                  ExploitMaturity.WEAPONISED),
    ]
    leads = build_leads(_fp(("a",), 0.9), entries, CorrelationConfig())
    assert [lead.cve_id for lead in leads] == ["CVE-HIGH", "CVE-LOW"]


def test_contradiction_penalty_is_applied_and_rounded():
    """Chosen so the halved value needs a 5th decimal place: 0.4455 * 0.5 is
    0.22275, which must land on 0.2228. Comparing against
    `round(clean * 0.5, 4)` would move with the code and pin nothing."""
    cfg = CorrelationConfig(contradiction_penalty=0.5)
    fp = _fp(("a",), confidence=0.55)
    clean = build_leads(fp, [ANY_APACHE], cfg)[0].priority
    disputed = build_leads(fp, [ANY_APACHE], cfg, contradicted=True)[0].priority
    # 0.4455 before match-method weighting. A product-substring match now
    # carries 0.75, per the CVE-identification design note: an identifier
    # lookup and a string heuristic are different kinds of claim.
    assert clean == 0.3341
    assert disputed == 0.1671


def test_undisputed_lead_carries_no_dispute_marker():
    lead = build_leads(_fp(("a",), 0.9), [ANY_APACHE], CorrelationConfig())[0]
    assert "DISPUTED" not in lead.rationale


# --------------------------------------------------------------------------- #
# Confidence arithmetic and the provenance cap
# --------------------------------------------------------------------------- #

def test_noisy_or_is_exact_to_four_places():
    fp = _fp(("scanner-a",), confidence=0.6)
    result = fp.observe(Provenance(source_tool="whatweb", principal="scanner-b",
                                   confidence=0.7))
    # 1 - (1-0.6)(1-0.7) = 0.88
    assert result == 0.88
    assert fp.confidence == 0.88


def test_same_principal_takes_the_maximum_not_the_latest():
    fp = _fp(("scanner-a",), confidence=0.8)
    assert fp.observe(Provenance(source_tool="x", principal="scanner-a",
                                 confidence=0.3)) == 0.8


def test_confidence_never_exceeds_one():
    fp = _fp(("scanner-a",), confidence=0.99)
    for i in range(6):
        fp.observe(Provenance(source_tool="x", principal=f"p{i}",
                              confidence=0.99))
    assert fp.confidence == 1.0


def test_provenance_cap_keeps_exactly_head_plus_tail():
    fp = _fp(("scanner-a",), confidence=0.5)
    cap = MAX_PROVENANCE_HEAD + MAX_PROVENANCE_TAIL
    for i in range(cap + 37):
        fp.observe(Provenance(source_tool="x", principal="scanner-a",
                              confidence=0.5, note=f"n{i}"))
    assert len(fp.provenance_log) == cap
    assert fp.elided_observations == 37 + 1   # +1 for the original entry
    assert fp.provenance_log[0].note is None  # head preserved
    assert fp.provenance_log[-1].note == f"n{cap + 36}"


def test_no_elision_until_the_cap_is_exceeded():
    fp = _fp(("scanner-a",), confidence=0.5)
    cap = MAX_PROVENANCE_HEAD + MAX_PROVENANCE_TAIL
    for i in range(cap - 1):
        fp.observe(Provenance(source_tool="x", principal="scanner-a",
                              confidence=0.5))
    assert len(fp.provenance_log) == cap
    assert fp.elided_observations == 0


def test_decay_multiplies_exactly():
    fp = _fp(("scanner-a",), confidence=0.8)
    assert fp.decay(0.25, reason="x", source_tool="t") == 0.2
    assert fp.decay(1.0, reason="x", source_tool="t") == 0.2


# --------------------------------------------------------------------------- #
# validate_address boundaries
# --------------------------------------------------------------------------- #

def test_address_length_boundary_is_253():
    label = "a" * 63
    exact = ".".join([label, label, label, "a" * 61])      # 253 chars
    assert len(exact) == 253
    assert validate_address(exact) == exact
    with pytest.raises(ValueError, match="1-253"):
        validate_address(exact + "a")


@pytest.mark.parametrize("codepoint", [0x00, 0x01, 0x09, 0x0A, 0x0D, 0x1F,
                                       0x7F])
def test_control_characters_are_rejected_at_the_boundary(codepoint):
    with pytest.raises(ValueError):
        validate_address(f"10.0.0.1{chr(codepoint)}x")


def test_codepoint_0x20_is_whitespace_not_a_control_character():
    """0x20 is the boundary: stripped, not rejected."""
    assert validate_address("  10.0.0.1  ") == "10.0.0.1"


def test_del_is_rejected_but_0x7e_is_not_a_control_character():
    with pytest.raises(ValueError):
        validate_address("10.0.0.1" + chr(0x7F))
    with pytest.raises(ValueError, match="not a valid"):
        validate_address("host" + chr(0x7E))    # rejected as a bad hostname


def test_empty_after_strip_is_rejected():
    for blank in ("", "   ", "\t\t"):
        with pytest.raises(ValueError):
            validate_address(blank)


# --------------------------------------------------------------------------- #
# Scope matching edge cases
# --------------------------------------------------------------------------- #

def test_unparseable_cidr_denies_rather_than_allows():
    """A typo in a scope pattern must fail closed."""
    assert _scope_matches("10.0.0.0/99", "10.0.0.1") is False
    assert _scope_matches("notanetwork/24", "10.0.0.1") is False


def test_hostname_never_matches_a_cidr_pattern():
    assert _scope_matches("10.0.0.0/8", "box.htb") is False


def test_empty_pattern_denies():
    assert _scope_matches("", "10.0.0.1") is False
    assert _scope_matches("   ", "10.0.0.1") is False


def test_role_ordering_is_strict_at_each_boundary():
    assert Role.VIEWER.satisfies(Role.VIEWER) is True
    assert Role.SCANNER.satisfies(Role.VIEWER) is True
    assert Role.VIEWER.satisfies(Role.SCANNER) is False
    assert Role.OPERATOR.satisfies(Role.ADMIN) is False
    assert Role.ADMIN.satisfies(Role.ADMIN) is True


# --------------------------------------------------------------------------- #
# Source registry clamping
# --------------------------------------------------------------------------- #

def test_declared_confidence_above_one_is_clamped_before_scaling():
    registry = SourceRegistry()
    registry.register("tool", 0.5)
    assert registry.effective_confidence("tool", 5.0) == 0.5     # not 2.5
    assert registry.effective_confidence("tool", -3.0) == 0.0


def test_effective_confidence_rounds_to_four_places():
    registry = SourceRegistry()
    registry.register("tool", 0.3333)
    assert registry.effective_confidence("tool", 0.3333) == 0.1111


# --------------------------------------------------------------------------- #
# Maturity inference precedence
# --------------------------------------------------------------------------- #

def _catalog(*records):
    cat = ExploitCatalog()
    for record in records:
        cat.add(record)
    return cat


def test_verified_exploitdb_alone_infers_functional():
    cat = _catalog(ExploitRecord("exploit-db", "EDB-1", "t",
                                 ("CVE-2021-1",), verified=True))
    assert cat.infer_maturity("CVE-2021-1") is ExploitMaturity.FUNCTIONAL


def test_unverified_exploitdb_alone_infers_proof_of_concept():
    cat = _catalog(ExploitRecord("exploit-db", "EDB-1", "t",
                                 ("CVE-2021-1",), verified=False))
    assert cat.infer_maturity("CVE-2021-1") is ExploitMaturity.PROOF_OF_CONCEPT


def test_metasploit_outranks_a_verified_exploitdb_entry():
    cat = _catalog(
        ExploitRecord("exploit-db", "EDB-1", "t", ("CVE-2021-1",),
                      verified=True),
        ExploitRecord("metasploit", "exploit/a/b", "t", ("CVE-2021-1",)))
    assert cat.infer_maturity("CVE-2021-1") is ExploitMaturity.WEAPONISED


def test_equal_weight_keeps_the_declared_value():
    """`>` not `>=`: inference must not churn an equal-strength judgement."""
    cat = _catalog(ExploitRecord("exploit-db", "EDB-1", "t",
                                 ("CVE-2021-1",), verified=True))
    result = cat.infer_maturity("CVE-2021-1", ExploitMaturity.FUNCTIONAL)
    assert result is ExploitMaturity.FUNCTIONAL


# --------------------------------------------------------------------------- #
# Rate limiter arithmetic
# --------------------------------------------------------------------------- #

def test_retry_after_is_zero_when_tokens_remain():
    bucket = Bucket(capacity=5, refill_per_second=1)
    assert bucket.retry_after() == 0.0


def test_retry_after_is_the_exact_deficit_over_the_rate():
    bucket = Bucket(capacity=1, refill_per_second=4)
    bucket.tokens = 0.0
    bucket.updated = time.monotonic()
    assert bucket.retry_after(cost=2.0) == pytest.approx(0.5, abs=0.02)


def test_retry_after_is_infinite_when_the_bucket_never_refills():
    bucket = Bucket(capacity=1, refill_per_second=0.0)
    bucket.tokens = 0.0
    assert bucket.retry_after() == float("inf")


def test_take_at_exactly_the_available_cost_succeeds():
    bucket = Bucket(capacity=2, refill_per_second=0.0001)
    assert bucket.take(cost=2.0) is True
    assert bucket.take(cost=0.001) is False


def test_check_returns_zero_wait_when_allowed():
    limiter = RateLimiter(capacity=3, refill_per_second=1)
    allowed, wait = limiter.check("p")
    assert allowed is True and wait == 0.0


def test_eviction_triggers_at_the_limit_not_past_it():
    limiter = RateLimiter(capacity=5, max_principals=4)
    for i in range(4):
        limiter.check(f"p{i}")
    assert len(limiter._buckets) == 4
    limiter.check("p4")                       # the 5th forces an eviction
    assert len(limiter._buckets) <= 4


# --------------------------------------------------------------------------- #
# Importer state and confidence mapping
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("open", "open"),
    ("closed", "closed"),
    ("filtered", "filtered"),
    ("open|filtered", "filtered"),
    ("unfiltered", "unknown"),
    ("weird", "unknown"),
])
def test_state_normalisation_exact_mapping(raw, expected):
    assert _normalise_state(raw) == expected


class _Service:
    """Minimal stand-in for an ElementTree service element."""

    def __init__(self, **attrs):
        self._attrs = attrs

    def get(self, key, default=None):
        return self._attrs.get(key, default)

    def findall(self, _):
        return []


def test_missing_conf_attribute_defaults_to_three_tenths():
    entry = _service_entry(80, _Service(name="http", product="Apache httpd",
                                        version="2.4.49", method="probed"))
    assert entry["confidence"] == 0.3


def test_conf_ten_maps_to_one_point_zero():
    entry = _service_entry(80, _Service(name="http", product="Apache httpd",
                                        version="2.4.49", conf="10",
                                        method="probed"))
    assert entry["confidence"] == 1.0


def test_unparseable_conf_falls_back_to_the_default():
    entry = _service_entry(80, _Service(name="http", product="Apache httpd",
                                        version="2.4.49", conf="high",
                                        method="probed"))
    assert entry["confidence"] == 0.3


def test_table_method_is_capped_at_three_tenths_even_at_conf_ten():
    entry = _service_entry(443, _Service(name="https", conf="10",
                                         method="table"))
    assert entry["confidence"] == 0.3
    assert entry["ambiguous"] is True


def test_conf_zero_floors_at_0_05_rather_than_zero():
    entry = _service_entry(80, _Service(name="http", product="X",
                                        version="1", conf="0",
                                        method="probed"))
    assert entry["confidence"] == 0.05


def test_service_without_a_name_is_dropped():
    assert _service_entry(80, _Service(product="Apache httpd")) is None


# --------------------------------------------------------------------------- #
# Second mutation pass: survivors the first round of exact tests missed
# --------------------------------------------------------------------------- #

def test_cidr_scope_with_host_bits_set_still_matches_its_network():
    """Operators write `10.10.10.42/24` meaning "that subnet". `strict=False`
    accepts it; `strict=True` would raise and the pattern would silently
    match nothing at all."""
    assert _scope_matches("10.10.10.42/24", "10.10.10.99") is True
    assert _scope_matches("10.10.10.42/24", "10.10.11.99") is False


def test_noisy_or_rounds_rather_than_truncating():
    """0.333 combined with 0.333 is 0.555111 -- it must land on 0.5551."""
    fp = _fp(("scanner-a",), confidence=0.333)
    assert fp.observe(Provenance(source_tool="x", principal="scanner-b",
                                 confidence=0.333)) == 0.5551


def test_decay_rounds_to_four_places():
    fp = _fp(("scanner-a",), confidence=0.8)
    # 0.8 * 0.3333 = 0.26664
    assert fp.decay(0.3333, reason="x", source_tool="t") == 0.2666


def test_decay_factor_boundaries():
    fp = _fp(("scanner-a",), confidence=0.8)
    assert fp.decay(1.0, reason="identity", source_tool="t") == 0.8
    for bad in (1.0001, 1.5, 2.0, 0.0, -0.5):
        with pytest.raises(ValueError, match=r"\(0, 1\]"):
            fp.decay(bad, reason="x", source_tool="t")


def test_contradiction_floor_is_inclusive():
    """A fingerprint sitting exactly on the correlation floor is credible
    enough to generate leads, so it is credible enough to dispute one."""
    from reconkg.models import Service

    def at(confidence, version):
        return Fingerprint(product="Apache httpd", version=version,
                           provenance=Provenance(source_tool="nmap-sV",
                                                 principal=f"p{version}",
                                                 confidence=confidence))

    service = Service(name="http",
                      provenance=Provenance(source_tool="t", confidence=0.9))
    service.fingerprints.extend([at(0.45, "2.4.49"), at(0.45, "2.4.58")])
    assert len(service.contradictions(floor=0.45)) == 1

    service.fingerprints[:] = [at(0.4499, "2.4.49"), at(0.45, "2.4.58")]
    assert service.contradictions(floor=0.45) == []


@pytest.mark.parametrize("address,message", [
    ("10.0.0.1\x00x", "control characters"),
    ("10.0.0.1\x1fx", "control characters"),
    ("10.0.0.1\x7fx", "control characters"),
    ("10.0.0.1 x", "not a valid"),        # 0x20 is not a control character
    ("host\x7ename", "not a valid"),      # 0x7e is not a control character
])
def test_control_character_boundary_reports_the_right_reason(address, message):
    """Asserting only "it raises" left the 0x20 and 0x7F boundaries unpinned:
    widening the range by one still raised, just for the wrong reason."""
    with pytest.raises(ValueError, match=message):
        validate_address(address)


def test_retry_after_rounds_to_two_places():
    """1/3 of a second must present as 0.33, not 0.333 -- this is an
    operator-facing number in a Retry-After header."""
    bucket = Bucket(capacity=1, refill_per_second=3.0)
    bucket.tokens = 0.0
    bucket.updated = time.monotonic()
    assert bucket.retry_after(cost=1.0) == pytest.approx(0.33, abs=0.011)
    assert len(str(bucket.retry_after(cost=1.0)).split(".")[-1]) <= 2


def test_service_confidence_is_clamped_at_one_for_out_of_range_conf():
    """nmap documents conf as 1-10, but the file is untrusted input. A
    conf of 99 must not become a confidence of 9.9."""
    entry = _service_entry(80, _Service(name="http", product="X", version="1",
                                        conf="99", method="probed"))
    assert entry["confidence"] == 1.0


def test_service_confidence_is_rounded_to_three_places():
    """conf=7 is 0.7 exactly; the rounding shows on a value that is not."""
    entry = _service_entry(80, _Service(name="http", product="X", version="1",
                                        conf="7", method="probed"))
    assert entry["confidence"] == 0.7
    wrapped = _service_entry(80, _Service(name="tcpwrapped", conf="6",
                                          method="probed"))
    assert wrapped["confidence"] == 0.2      # capped, still 3dp-clean
