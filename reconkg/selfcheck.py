"""Verify reconkg against the real data, on a machine that has it.

    python -m reconkg.selfcheck

Two questions have been open through the whole build, and neither can be
answered where reconkg was developed. That sandbox reaches PyPI and nothing
else: NVD, CISA, EPSS, GitLab and the Ubuntu archive are all refused, and no
package bundles an nmap install. So every benchmark in `audit/` runs on
synthetic data and the `script.db` parser was written against documentation.

The questions are:

    1. Does the script.db parser handle a REAL script.db? The format is
       documented and the parser honours the documented shape plus one
       variant. Real files acquire comments, records with fields nobody
       mentioned, and whatever the local nmap version emits. A parser that
       silently drops 40% of a real file would report most scripts as
       `unclassified` while `describe()` cheerfully says a corpus is loaded.

    2. What is the real CVE coverage? Every coverage number quoted so far
       came from a synthetic corpus with a Pareto distribution I chose, and
       that distribution turned out to be far too top-heavy. The honest
       answer needs a real corpus and a set of fingerprints resembling real
       hosts.

This module answers both by measurement and prints what it finds, including
when the answer is unflattering. It changes nothing and writes nothing.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger("reconkg.selfcheck")

#: Where nmap puts its script index, in the order worth trying. The Homebrew
#: and Windows paths matter: an operator on macOS or Windows who gets "not
#: found" will reasonably conclude reconkg cannot use their install.
SCRIPT_DB_PATHS = (
    "/usr/share/nmap/scripts/script.db",
    "/usr/local/share/nmap/scripts/script.db",
    "/opt/homebrew/share/nmap/scripts/script.db",
    "/opt/local/share/nmap/scripts/script.db",
    "/snap/nmap/current/usr/share/nmap/scripts/script.db",
    r"C:\Program Files (x86)\Nmap\scripts\script.db",
    r"C:\Program Files\Nmap\scripts\script.db",
)

#: Service fingerprints resembling what an nmap scan of a real box returns.
#: Deliberately including the awkward ones -- a distribution-packaged build
#: whose version string is a lie, a service with no version at all, and a
#: product whose CPE nmap does not emit -- because a benchmark made only of
#: clean fingerprints measures the easy half and reports it as the whole.
BENCHMARK_FINGERPRINTS = (
    ("Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49"),
    ("Apache httpd", "2.4.41", "cpe:/a:apache:http_server:2.4.41"),
    ("OpenSSH", "7.4", "cpe:/a:openbsd:openssh:7.4"),
    ("OpenSSH", "8.2p1", "cpe:/a:openbsd:openssh:8.2p1"),
    ("nginx", "1.18.0", "cpe:/a:nginx:nginx:1.18.0"),
    ("Apache Tomcat", "9.0.30", "cpe:/a:apache:tomcat:9.0.30"),
    ("Microsoft IIS httpd", "10.0", "cpe:/a:microsoft:iis:10.0"),
    ("MySQL", "5.7.33", "cpe:/a:mysql:mysql:5.7.33"),
    ("PostgreSQL DB", "11.7", "cpe:/a:postgresql:postgresql:11.7"),
    ("ProFTPD", "1.3.5", "cpe:/a:proftpd:proftpd:1.3.5"),
    ("vsftpd", "2.3.4", "cpe:/a:vsftpd:vsftpd:2.3.4"),
    ("Samba smbd", "4.9.5", "cpe:/a:samba:samba:4.9.5"),
    ("ISC BIND", "9.11.4", "cpe:/a:isc:bind:9.11.4"),
    ("Exim smtpd", "4.92", "cpe:/a:exim:exim:4.92"),
    ("Werkzeug httpd", "0.16.0", None),
    ("Apache httpd", "2.4.6", "cpe:/a:apache:http_server:2.4.6"),
    ("Jenkins", "2.222", None),
    ("Unknown", None, None),
)


def _bar(fraction: float, width: int = 24) -> str:
    filled = max(0, min(width, round(fraction * width)))
    return "#" * filled + "." * (width - filled)


# --------------------------------------------------------------------------- #
# 1. The script.db parser, against a real file
# --------------------------------------------------------------------------- #

def find_script_db(explicit: Optional[str] = None) -> Optional[Path]:
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.is_file() else None
    for candidate in SCRIPT_DB_PATHS:
        path = Path(candidate)
        if path.is_file():
            return path
    return None


def check_script_db(explicit: Optional[str] = None) -> dict:
    """Parse the operator's real script.db and report what was dropped."""
    from .commands import Category
    from .scriptdb import NotAScriptDb, ParseStats, read_script_db

    path = find_script_db(explicit)
    print("\n" + "=" * 72)
    print("1. script.db parser against a real file")
    print("=" * 72)

    if path is None:
        print("  nmap's script.db was not found in any known location.")
        print("  Tried:")
        for candidate in SCRIPT_DB_PATHS:
            print(f"    {candidate}")
        print("\n  This is not a failure -- it means nmap is not installed "
              "here, so\n  corpus three has nothing to index and every NSE "
              "script will be\n  reported as `unclassified` (which is the "
              "conservative answer).")
        print("  Pass --script-db PATH if yours lives somewhere else.")
        return {"found": False}

    print(f"  found: {path}")
    stats = ParseStats()
    try:
        entries = list(read_script_db(path, stats))
    except NotAScriptDb as exc:
        print(f"\n  REFUSED: {exc}")
        print("  The parser judged this file not to be a script.db at all. "
              "If it\n  is one, that is a parser bug and the file's first "
              "few lines are\n  what to report.")
        return {"found": True, "refused": str(exc)}

    total = stats.lines or 1
    parsed_pct = stats.parsed / total
    print(f"  lines read      {stats.lines:>7,}")
    print(f"  entries parsed  {stats.parsed:>7,}  {_bar(parsed_pct)} "
          f"{parsed_pct:6.1%}")
    print(f"  lines skipped   {stats.skipped:>7,}")

    if stats.errors:
        print("\n  first unparsed lines -- these are the parser's blind "
              "spots:")
        for note in list(stats.errors)[:10]:
            print(f"    {note}")

    # Category distribution. A real script.db is the ground truth for how
    # often each category actually appears, and the tier policy was written
    # without ever having seen it.
    counts: dict[str, int] = {}
    for entry in entries:
        for category in entry.categories:
            key = str(getattr(category, "value", category))
            counts[key] = counts.get(key, 0) + 1

    if counts:
        print("\n  categories present, most common first:")
        known = {c.value for c in Category}
        for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            flag = "" if name in known else "   <- NOT IN reconkg's vocabulary"
            print(f"    {name:<14} {count:>5,}{flag}")

    unknown = sorted(set(counts) - {c.value for c in Category})
    if unknown:
        print(f"\n  {len(unknown)} category name(s) this build does not know. "
              "Each one\n  resolves to `unclassified`, which is safe but "
              "loses information.\n  Worth adding to Category: "
              + ", ".join(unknown))

    # The tier question, answered against real data rather than assumption.
    tiers = {"default": 0, "opt-in": 0, "never composed": 0}
    from .commands import (DEFAULT_CATEGORIES, NEVER_COMPOSED,
                           _worst_category)
    for entry in entries:
        resolved = _worst_category([str(getattr(c, "value", c))
                                    for c in entry.categories])
        if resolved in NEVER_COMPOSED:
            tiers["never composed"] += 1
        elif resolved in DEFAULT_CATEGORIES:
            tiers["default"] += 1
        else:
            tiers["opt-in"] += 1

    print("\n  how reconkg would tier the real catalogue:")
    for tier, count in tiers.items():
        share = count / max(len(entries), 1)
        print(f"    {tier:<16} {count:>5,}  {_bar(share)} {share:6.1%}")

    verdict = "PASS"
    if parsed_pct < 0.95:
        verdict = "FAIL"
        print(f"\n  VERDICT: FAIL. {1 - parsed_pct:.1%} of a real script.db "
              "did not parse.\n  The categories for those scripts are lost, "
              "and every one of them\n  will be reported as unclassified.")
    else:
        print(f"\n  VERDICT: PASS. {parsed_pct:.1%} of the file parsed.")

    return {"found": True, "path": str(path), "lines": stats.lines,
            "parsed": stats.parsed, "skipped": stats.skipped,
            "unknown_categories": unknown, "tiers": tiers,
            "verdict": verdict}


# --------------------------------------------------------------------------- #
# 2. Real CVE coverage
# --------------------------------------------------------------------------- #

def check_coverage(env: Optional[dict] = None) -> dict:
    """How many realistic fingerprints get a lead from the real corpus."""
    from .models import Fingerprint, Provenance
    from .resolver import ENV_VAR, StaticResolver, from_env
    from .vulnref import CorrelationConfig, build_leads

    env = env if env is not None else os.environ

    print("\n" + "=" * 72)
    print("2. CVE coverage against realistic fingerprints")
    print("=" * 72)

    try:
        resolver = from_env(env)
    except FileNotFoundError as exc:
        print(f"  {exc}")
        return {"error": str(exc)}

    print(f"  corpus: {resolver.describe()}")
    if isinstance(resolver, StaticResolver):
        print("\n  This is the built-in demonstration fixture. The numbers "
              "below\n  measure nine hand-written entries and say nothing "
              f"about real\n  coverage. Set {ENV_VAR} to a built corpus "
              "first.")

    config = CorrelationConfig()
    hits = 0
    rows = []
    for product, version, cpe in BENCHMARK_FINGERPRINTS:
        fp = Fingerprint(
            product=product, version=version, cpe=cpe,
            provenance=Provenance(source_tool="nmap", principal="selfcheck",
                                  confidence=0.9))
        try:
            leads = build_leads(fp, resolver.candidates(fp), config)
        except Exception as exc:                # pragma: no cover - defensive
            leads = []
            log.warning("lead building failed for %s: %s", fp.key, exc)
        hits += bool(leads)
        rows.append((product, version, len(leads),
                     leads[0].cve_id if leads else ""))

    print(f"\n  {'service':<24}{'version':<12}{'leads':>6}  top lead")
    print("  " + "-" * 66)
    for product, version, count, top in rows:
        mark = " " if count else "!"
        print(f" {mark}{product:<24}{version or '-':<12}{count:>6}  {top}")

    rate = hits / len(rows)
    print(f"\n  {hits}/{len(rows)} fingerprints produced at least one lead  "
          f"{_bar(rate)} {rate:.0%}")

    print("\n  What this number is and is not. It measures how often a "
          "version\n  string maps to a CVE. It does not measure how often "
          "that lead is\n  the way in: web logic flaws, credential reuse, "
          "SUID/sudo misconfig\n  and AD abuse have no version->CVE path at "
          "all, and no corpus size\n  changes that.")

    close = getattr(resolver, "close", None)
    if callable(close):
        close()
    return {"hits": hits, "total": len(rows), "rate": round(rate, 3),
            "rows": rows}


# --------------------------------------------------------------------------- #
# 3. Corpus health
# --------------------------------------------------------------------------- #

def check_corpora(env: Optional[dict] = None) -> dict:
    """What each of the three corpora says about itself."""
    from .resolver import exploits_from_env, from_env, scripts_from_env

    env = env if env is not None else os.environ
    print("\n" + "=" * 72)
    print("3. Corpus status")
    print("=" * 72)

    report = {}
    for name, factory in (("vulnerabilities", from_env),
                          ("exploits", exploits_from_env),
                          ("scripts", scripts_from_env)):
        try:
            resolver = factory(env)
        except FileNotFoundError as exc:
            print(f"\n  {name}:\n    CONFIGURED BUT UNUSABLE: {exc}")
            report[name] = {"error": str(exc)}
            continue
        text = resolver.describe()
        print(f"\n  {name}:\n    {text}")
        report[name] = {"describe": text}
        close = getattr(resolver, "close", None)
        if callable(close):
            close()
    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m reconkg.selfcheck",
        description="Verify reconkg against the real data on this machine.")
    parser.add_argument("--script-db", default=None,
                        help="path to nmap's script.db, if not in the usual "
                             "places")
    parser.add_argument("--skip-scripts", action="store_true")
    parser.add_argument("--skip-coverage", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)-7s %(message)s")

    print("reconkg self-check")
    print("Answers the two questions that cannot be answered where this was "
          "built.")

    results = {"corpora": check_corpora()}
    if not args.skip_scripts:
        results["script_db"] = check_script_db(args.script_db)
    if not args.skip_coverage:
        results["coverage"] = check_coverage()

    print("\n" + "=" * 72)
    failed = results.get("script_db", {}).get("verdict") == "FAIL"
    if failed:
        print("One check FAILED -- see above.")
        return 1
    print("Self-check complete. Nothing was written and nothing was sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
