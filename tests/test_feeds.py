"""NVD / KEV / EPSS ingestion and exploitation-aware ordering.

Items 3 and 5 of docs/CVE-IDENTIFICATION.md.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from reconkg.feeds import (EPSS_MAX_FACTOR, KEV_FACTOR, EpssScores,
                           ExploitationSignals, KevCatalog, load_nvd)
from reconkg.models import ExploitMaturity, Fingerprint, Provenance
from reconkg.vulnref import CorrelationConfig, VulnEntry, build_leads

# --------------------------------------------------------------------------- #
# Fixtures shaped like the real published files
# --------------------------------------------------------------------------- #

NVD = {"vulnerabilities": [
    {"cve": {
        "id": "CVE-2021-41773",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "no"},
            {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"},
        ],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
            "cvssMetricV40": [{"cvssData": {"baseScore": 9.8}}],
        },
        "configurations": [{"nodes": [{
            "operator": "OR", "negate": False,
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            }],
        }]}],
    }},
    {"cve": {
        "id": "CVE-2018-15473",
        "descriptions": [{"lang": "en", "value": "OpenSSH username enumeration"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3}}]},
        "configurations": [{"nodes": [{
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "7.7",
            }],
        }]}],
    }},
    {"cve": {
        "id": "CVE-9999-0001",
        "vulnStatus": "Awaiting Analysis",
        "descriptions": [{"lang": "en", "value": "Not yet analysed"}],
        "metrics": {},
        "configurations": [],
    }},
    {"cve": {"descriptions": [{"lang": "en", "value": "no id at all"}]}},
]}

KEV = {
    "catalogVersion": "2026.08.17",
    "vulnerabilities": [
        {"cveID": "CVE-2021-41773", "vendorProject": "Apache",
         "product": "HTTP Server", "vulnerabilityName": "Path Traversal",
         "dateAdded": "2021-11-03", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2017-0144", "vendorProject": "Microsoft",
         "product": "SMBv1", "vulnerabilityName": "EternalBlue",
         "dateAdded": "2022-03-25", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "not-a-cve"},
    ],
}

EPSS_CSV = """#model_version:v2025.03.14,score_date:2026-08-17T00:00:00+0000
cve,epss,percentile
CVE-2021-41773,0.94100,0.99900
CVE-2018-15473,0.01234,0.75000
CVE-2023-38408,0.00042,0.10000
malformed-row,notanumber,0.5
"""


@pytest.fixture
def nvd_entries(tmp_path):
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(NVD))
    return load_nvd(path)


@pytest.fixture
def kev(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(KEV))
    catalog = KevCatalog()
    catalog.load(path)
    return catalog


@pytest.fixture
def epss(tmp_path):
    path = tmp_path / "epss.csv"
    path.write_text(EPSS_CSV)
    scores = EpssScores()
    scores.load(path)
    return scores


def _fp(product="Apache httpd", version="2.4.49",
        cpe="cpe:/a:apache:http_server:2.4.49", confidence=0.9):
    return Fingerprint(product=product, version=version, cpe=cpe,
                       provenance=Provenance(source_tool="nmap-sV",
                                             principal="scanner-a",
                                             confidence=confidence))


# --------------------------------------------------------------------------- #
# NVD
# --------------------------------------------------------------------------- #

def test_nvd_entries_carry_cpe_applicability_not_substrings(nvd_entries):
    apache = next(e for e in nvd_entries if e.cve_id == "CVE-2021-41773")
    assert apache.cpe_ranges
    assert apache.cpe_ranges[0].cpe.identity() == ("a", "apache", "http_server")
    assert apache.constraints == ()      # no substring version tuples


def test_cvss_v4_is_preferred_over_v31(nvd_entries):
    """Both are present in the fixture. The newer scale wins."""
    apache = next(e for e in nvd_entries if e.cve_id == "CVE-2021-41773")
    assert apache.cvss == 9.8


def test_missing_metrics_score_zero_rather_than_a_guess(nvd_entries):
    unanalysed = next(e for e in nvd_entries if e.cve_id == "CVE-9999-0001")
    assert unanalysed.cvss == 0.0


def test_an_unanalysed_record_says_so(nvd_entries):
    unanalysed = next(e for e in nvd_entries if e.cve_id == "CVE-9999-0001")
    assert "Awaiting Analysis" in unanalysed.notes
    assert "incomplete" in unanalysed.notes


def test_english_description_is_chosen(nvd_entries):
    apache = next(e for e in nvd_entries if e.cve_id == "CVE-2021-41773")
    assert apache.title.startswith("Path traversal in Apache")


def test_a_record_with_no_id_is_skipped_not_fatal(nvd_entries):
    assert len(nvd_entries) == 3
    assert all(e.cve_id.startswith("CVE-") for e in nvd_entries)


def test_version_boundaries_survive_ingestion(nvd_entries):
    ssh = next(e for e in nvd_entries if e.cve_id == "CVE-2018-15473")
    statement = ssh.cpe_ranges[0]
    assert statement.version_end_excluding == "7.7"
    assert statement.has_window is True


def test_an_ingested_entry_matches_by_cpe_end_to_end(nvd_entries):
    apache = next(e for e in nvd_entries if e.cve_id == "CVE-2021-41773")
    lead = build_leads(_fp(), [apache], CorrelationConfig())[0]
    assert "cpe_exact" in lead.rationale


def test_an_ingested_range_entry_matches_a_version_in_the_window(nvd_entries):
    ssh = next(e for e in nvd_entries if e.cve_id == "CVE-2018-15473")
    fp = _fp(product="OpenSSH", version="7.4", cpe="cpe:/a:openbsd:openssh:7.4")
    lead = build_leads(fp, [ssh], CorrelationConfig())[0]
    assert "cpe_range" in lead.rationale
    assert build_leads(_fp(product="OpenSSH", version="9.0",
                           cpe="cpe:/a:openbsd:openssh:9.0"),
                       [ssh], CorrelationConfig()) == []


def test_a_negated_node_is_not_treated_as_applicable(tmp_path):
    """A negated node states where the CVE does *not* apply."""
    blob = {"vulnerabilities": [{"cve": {
        "id": "CVE-2020-0001", "descriptions": [],
        "metrics": {}, "configurations": [{"nodes": [{
            "negate": True,
            "cpeMatch": [{"vulnerable": True,
                          "criteria": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}]}]}]}}]}
    path = tmp_path / "n.json"
    path.write_text(json.dumps(blob))
    assert load_nvd(path)[0].cpe_ranges == ()


def test_a_bare_list_of_cve_objects_also_parses(tmp_path):
    path = tmp_path / "bare.json"
    path.write_text(json.dumps([NVD["vulnerabilities"][0]["cve"]]))
    assert load_nvd(path)[0].cve_id == "CVE-2021-41773"


def test_invalid_json_is_rejected_by_name(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_nvd(path)


def test_a_missing_feed_raises_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_nvd(tmp_path / "absent.json")


# --------------------------------------------------------------------------- #
# KEV
# --------------------------------------------------------------------------- #

def test_kev_membership_is_binary(kev):
    assert "CVE-2021-41773" in kev
    assert "CVE-2023-38408" not in kev
    assert len(kev) == 2
    assert kev.catalog_version == "2026.08.17"


def test_kev_lookup_tolerates_loose_cve_formatting(kev):
    assert "cve 2021 41773" in kev
    assert "2021-41773" in kev


def test_kev_records_the_ransomware_flag(kev):
    entry = kev.get("CVE-2021-41773")
    assert entry.ransomware is True
    assert entry.date_added == date(2021, 11, 3)
    assert entry.vendor == "Apache"


def test_kev_skips_a_record_with_no_usable_id(kev):
    assert kev.stats.records == 3
    assert kev.stats.loaded == 2
    assert kev.stats.skipped == 1


# --------------------------------------------------------------------------- #
# EPSS
# --------------------------------------------------------------------------- #

def test_epss_skips_the_metadata_comment_line(epss):
    """csv.DictReader would otherwise take `#model_version:...` as the
    header and mis-key every row that follows."""
    assert epss.model_version == "v2025.03.14"
    assert epss.score_date.startswith("2026-08-17")
    assert len(epss) == 3


def test_epss_probabilities_are_exact(epss):
    assert epss.probability("CVE-2021-41773") == pytest.approx(0.941)
    assert epss.percentile("CVE-2021-41773") == pytest.approx(0.999)
    assert epss.probability("CVE-2023-38408") == pytest.approx(0.00042)


def test_an_unknown_cve_has_no_score_rather_than_zero(epss):
    """None and 0.0 mean different things: "not in the feed" versus
    "predicted never to be exploited"."""
    assert epss.probability("CVE-1999-0001") is None


def test_a_malformed_row_is_skipped(epss):
    assert epss.stats.skipped == 1
    assert epss.stats.loaded == 3


def test_a_file_without_a_cve_column_is_rejected(tmp_path):
    path = tmp_path / "wrong.csv"
    path.write_text("alpha,beta\n1,2\n")
    with pytest.raises(ValueError, match="does not look like an EPSS export"):
        EpssScores().load(path)


# --------------------------------------------------------------------------- #
# Exploitation-aware ordering — the point of items 3 and 5
# --------------------------------------------------------------------------- #

def test_kev_membership_dominates_epss(kev, epss):
    signals = ExploitationSignals(kev=kev, epss=epss)
    assert signals.factor("CVE-2021-41773") == KEV_FACTOR


def test_epss_scales_between_one_and_one_and_a_half(kev, epss):
    signals = ExploitationSignals(epss=epss)
    assert signals.factor("CVE-2018-15473") == pytest.approx(
        1.0 + EPSS_MAX_FACTOR * 0.01234)
    assert signals.factor("CVE-1999-0001") == 1.0


def test_no_feeds_means_no_adjustment():
    assert ExploitationSignals().factor("CVE-2021-41773") == 1.0
    assert ExploitationSignals().loaded is False


def test_an_exploited_mid_severity_cve_outranks_a_quiet_maximum_one(kev, epss):
    """The operational rule the research states plainly: a CVSS 7.5 under
    active exploitation is more urgent than a CVSS 9.8 nobody is touching."""
    exploited = VulnEntry("CVE-2021-41773", "exploited", "apache",
                          ((">=", "2.0"),), 7.5, ExploitMaturity.FUNCTIONAL)
    quiet = VulnEntry("CVE-1999-0001", "quiet", "apache",
                      ((">=", "2.0"),), 9.8, ExploitMaturity.FUNCTIONAL)
    signals = ExploitationSignals(kev=kev, epss=epss)
    cfg = CorrelationConfig()
    fp = _fp()

    without = build_leads(fp, [exploited, quiet], cfg)
    assert [l.cve_id for l in without] == ["CVE-1999-0001", "CVE-2021-41773"]

    with_signals = build_leads(fp, [exploited, quiet], cfg, signals=signals)
    assert [l.cve_id for l in with_signals] == ["CVE-2021-41773",
                                                "CVE-1999-0001"]


def test_the_reason_for_the_boost_is_stated_on_the_lead(kev, epss):
    entry = VulnEntry("CVE-2021-41773", "t", "apache", ((">=", "2.0"),), 7.5)
    lead = build_leads(_fp(), [entry], CorrelationConfig(),
                       signals=ExploitationSignals(kev=kev, epss=epss))[0]
    assert "KEV: actively exploited since 2021-11-03" in lead.rationale
    assert "used in ransomware" in lead.rationale


def test_an_epss_explanation_reads_as_a_probability(epss):
    entry = VulnEntry("CVE-2018-15473", "t", "openssh", ((">=", "1.0"),), 5.3)
    fp = _fp(product="OpenSSH", version="7.4", cpe=None)
    lead = build_leads(fp, [entry], CorrelationConfig(),
                       signals=ExploitationSignals(epss=epss))[0]
    assert ("EPSS 1.2% chance of exploitation in 30 days (75% percentile)"
            in lead.rationale)


def test_priority_stays_within_range_after_a_kev_boost(kev):
    entry = VulnEntry("CVE-2021-41773", "t", "apache", ((">=", "2.0"),), 10.0,
                      ExploitMaturity.WEAPONISED)
    lead = build_leads(_fp(confidence=1.0), [entry], CorrelationConfig(),
                       signals=ExploitationSignals(kev=kev))[0]
    assert 0.0 <= lead.priority <= 1.0


# --------------------------------------------------------------------------- #
# Mutation-driven: exact behaviour the first pass left unpinned
# --------------------------------------------------------------------------- #

def _one_cve(tmp_path, **overrides):
    record = {"id": "CVE-2020-1234",
              "descriptions": [{"lang": "en", "value": "example"}],
              "metrics": {}, "configurations": []}
    record.update(overrides)
    path = tmp_path / "one.json"
    path.write_text(json.dumps({"vulnerabilities": [{"cve": record}]}))
    return load_nvd(path)[0]


def test_product_match_skips_wildcard_products(tmp_path):
    """The substring fallback needs a real product name. Taking the first
    statement blindly would fill it with "*"."""
    entry = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"},
        {"vulnerable": True,
         "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
    ]}]}])
    assert entry.product_match == "http server"


def test_product_match_is_empty_when_every_product_is_a_wildcard(tmp_path):
    entry = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:-:*:*:*:*:*:*:*:*"},
    ]}]}])
    assert entry.product_match == ""


def test_underscores_become_spaces_for_the_substring_fallback(tmp_path):
    """nmap reports "Apache httpd", NVD says "http_server". The fallback has
    to meet the banner halfway or it never fires."""
    entry = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"vulnerable": True,
         "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}])
    assert "_" not in entry.product_match


def test_a_very_long_description_is_truncated_to_300(tmp_path):
    entry = _one_cve(tmp_path,
                     descriptions=[{"lang": "en", "value": "x" * 900}])
    assert len(entry.title) == 300


def test_an_ingested_entry_does_not_require_a_version(tmp_path):
    """NVD carries the version constraint inside the applicability
    statement, so the substring path must not additionally demand one --
    that would silently drop every CPE-less fingerprint."""
    entry = _one_cve(tmp_path)
    assert entry.requires_version is False
    # An entry with no applicability data has no product name either, and an
    # empty product_match must match nothing -- `"" in anything` is True, so
    # an unanalysed CVE would otherwise attach itself to every fingerprint
    # in the graph. This assertion is the bug that found.
    fp = Fingerprint(product="example", version=None,
                     provenance=Provenance(source_tool="t", principal="p",
                                           confidence=0.9))
    matched, why, _ = entry.matches(fp)
    assert matched is False
    assert why == "entry carries no product name to match on"
    versionless = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"vulnerable": True,
         "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}]}]}])
    banner_only = Fingerprint(product="Apache http server", version=None,
                              provenance=Provenance(source_tool="t",
                                                    principal="p",
                                                    confidence=0.9))
    matched, why, method = versionless.matches(banner_only)
    assert matched is True
    assert method.value == "product_only"


@pytest.mark.parametrize("score,expected", [
    (0.0, 0.0), (10.0, 10.0), (5.5, 5.5),
    (0.5, 0.5),         # below 1.0 but valid -- the lower bound is 0, not 1
    (-1.0, 0.0),        # out of range, refused
    (11.0, 0.0),        # out of range, refused
    ("high", 0.0),      # unparseable, refused
])
def test_cvss_scores_outside_zero_to_ten_are_refused(tmp_path, score, expected):
    """A fabricated or corrupt score flows straight into ranking."""
    entry = _one_cve(tmp_path,
                     metrics={"cvssMetricV31": [{"cvssData":
                                                 {"baseScore": score}}]})
    assert entry.cvss == expected


def test_the_legacy_cpe23uri_key_is_still_read(tmp_path):
    """Older exports spell the field `cpe23Uri`. Dropping them would look
    like a feed with no applicability data rather than a parser gap."""
    entry = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"vulnerable": True,
         "cpe23Uri": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}])
    assert entry.cpe_ranges
    assert entry.cpe_ranges[0].cpe.product == "http_server"


def test_a_match_with_no_vulnerable_key_defaults_to_vulnerable(tmp_path):
    """Absent means yes in NVD. Defaulting to False would silently discard
    the applicability data on any export that omits the flag."""
    entry = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}])
    assert entry.cpe_ranges[0].vulnerable is True


def test_an_unparseable_criteria_is_dropped_not_fatal(tmp_path):
    entry = _one_cve(tmp_path, configurations=[{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "not a cpe at all"},
        {"vulnerable": True,
         "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}])
    assert len(entry.cpe_ranges) == 1


def test_epss_lookup_tolerates_loose_cve_formatting(epss):
    assert epss.probability("cve 2021 41773") == pytest.approx(0.941)
    assert epss.probability("2021-41773") == pytest.approx(0.941)
    assert epss.percentile("cve_2021_41773") == pytest.approx(0.999)


def test_an_epss_explanation_survives_a_missing_percentile(tmp_path):
    """percentile is optional in some exports; the sentence must still read."""
    path = tmp_path / "epss.csv"
    path.write_text("cve,epss,percentile\nCVE-2020-1234,0.5,\n")
    scores = EpssScores()
    scores.load(path)
    assert scores.percentile("CVE-2020-1234") == 0.0
    text = ExploitationSignals(epss=scores).explain("CVE-2020-1234")
    assert "50.0% chance of exploitation in 30 days (0% percentile)" in text


def test_explain_is_empty_when_nothing_is_known(kev, epss):
    assert ExploitationSignals(kev=kev, epss=epss).explain("CVE-1999-9999") == ""
    assert ExploitationSignals().explain("CVE-2021-41773") == ""


def test_a_kev_entry_without_a_date_still_explains(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2020-1234", "knownRansomwareCampaignUse": "Unknown"}]}))
    catalog = KevCatalog()
    catalog.load(path)
    text = ExploitationSignals(kev=catalog).explain("CVE-2020-1234")
    assert text == "KEV: actively exploited"


def test_the_signal_adjusted_priority_rounds_to_four_places(epss):
    """Chosen so the boosted value needs a 5th place: 0.5468 * 1.00617 is
    0.55017, which must land on 0.5502. Asserting against a recomputed
    `round(x, 4)` would move with the code and pin nothing."""
    entry = VulnEntry("CVE-2018-15473", "t", "apache", ((">=", "2.0"),), 9.0,
                      ExploitMaturity.FUNCTIONAL)
    fp = _fp(product="Apache httpd", version="2.4.49", cpe=None,
             confidence=0.9)
    cfg = CorrelationConfig()

    plain = build_leads(fp, [entry], cfg)[0].priority
    boosted = build_leads(fp, [entry], cfg,
                          signals=ExploitationSignals(epss=epss))[0].priority
    assert plain == 0.5468
    assert boosted == 0.5502
