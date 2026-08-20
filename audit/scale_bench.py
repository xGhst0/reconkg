"""Does the corpus design survive the real corpus size?

Nine hand-written CVEs told us nothing about this. NVD is north of 250,000,
and the two questions that decide whether the design is viable are:

    build   can a laptop ingest the whole feed in a tolerable time, without
            holding it all in memory
    lookup  is a per-fingerprint lookup indexed, or does it degrade linearly
            with corpus size

The second is the one that matters most, and it has a sharp test: run the
same lookup against a small corpus and a large one. If the index is doing its
job the times are indistinguishable. If the query is scanning, the ratio
tracks the size ratio.

    python -m audit.scale_bench --cves 250000
"""

from __future__ import annotations

import argparse
import random
import resource
import statistics
import tempfile
import time
from pathlib import Path

from reconkg.cpe import CPE, parse as parse_cpe
from reconkg.models import ExploitMaturity
from reconkg.vulndb import VulnDB
from reconkg.vulnref import VulnEntry
from reconkg.cpe import CPERange

# Real vendor/product pairs, so the identity distribution resembles NVD's:
# a long tail of products with a handful of CVEs, and a short head with
# thousands. A uniform distribution would flatter the index unfairly.
PRODUCTS = [
    ("apache", "http_server"), ("apache", "tomcat"), ("apache", "log4j"),
    ("openbsd", "openssh"), ("nginx", "nginx"), ("oracle", "mysql"),
    ("postgresql", "postgresql"), ("microsoft", "internet_information_services"),
    ("microsoft", "windows_10"), ("proftpd", "proftpd"), ("samba", "samba"),
    ("isc", "bind"), ("openssl", "openssl"), ("php", "php"),
    ("wordpress", "wordpress"), ("jenkins", "jenkins"), ("atlassian", "jira"),
    ("vmware", "vcenter_server"), ("fortinet", "fortios"), ("citrix", "netscaler"),
]


def synth(count: int, seed: int = 7) -> list[VulnEntry]:
    rng = random.Random(seed)
    entries = []
    for n in range(count):
        # Zipf-ish: index 0 gets far more CVEs than index 19.
        pick = min(int(rng.paretovariate(1.2)) - 1, len(PRODUCTS) - 1)
        vendor, product = PRODUCTS[pick]
        major = rng.randint(1, 9)
        cpe = parse_cpe(f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*")
        entries.append(VulnEntry(
            cve_id=f"CVE-2024-{n:07d}",
            title=f"Synthetic vulnerability {n} in {product}",
            product_match=product.replace("_", " "),
            cvss=round(rng.uniform(3.0, 10.0), 1),
            maturity=ExploitMaturity.NOT_DEFINED,
            cpe_ranges=(CPERange(cpe=cpe,
                                 version_start_including=f"{major}.0",
                                 version_end_excluding=f"{major + 1}.0"),),
        ))
    return entries


def _rss_mb() -> float:
    # ru_maxrss is KB on Linux, bytes on macOS. Assume Linux; the number is
    # indicative either way and the ratio is what matters.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def bench(count: int, lookups: int = 2000) -> dict:
    tmp = Path(tempfile.mkdtemp()) / f"bench-{count}.db"

    entries = synth(count)
    built_rss = _rss_mb()

    started = time.monotonic()
    with VulnDB(tmp) as db:
        written = db.ingest(entries)
        build_s = time.monotonic() - started

        del entries                     # measure lookup, not the generator
        probes = [parse_cpe(f"cpe:2.3:a:{v}:{p}:{n % 9 + 1}.5:*:*:*:*:*:*:*")
                  for n, (v, p) in enumerate(PRODUCTS * (lookups // 20 + 1))
                  ][:lookups]

        timings = []
        hits = 0
        for probe in probes:
            t0 = time.perf_counter()
            found = db.candidates_for_cpe(probe)
            timings.append((time.perf_counter() - t0) * 1000)
            hits += bool(found)

        # The verdict probe. The probes above conflate two effects: a bigger
        # corpus really does hold more Apache CVEs, so a slower lookup there
        # is correct behaviour, not a broken index. To test the index alone,
        # probe an identity that is absent from both corpora. The result set
        # is empty in each case, so the only variable left is how much data
        # SQLite had to traverse to establish that -- which is exactly what
        # an index is supposed to make constant.
        absent = parse_cpe("cpe:2.3:a:nonesuch:absent:1.0:*:*:*:*:*:*:*")
        constant = []
        for _ in range(1000):
            t0 = time.perf_counter()
            db.candidates_for_cpe(absent)
            constant.append((time.perf_counter() - t0) * 1000)

        stats = db.stats()

    size_mb = tmp.stat().st_size / 1e6
    return {
        "cves": written,
        "statements": stats.statements,
        "build_s": round(build_s, 2),
        "build_rate": int(written / build_s) if build_s else 0,
        "db_mb": round(size_mb, 1),
        "peak_rss_mb": round(built_rss, 1),
        "lookup_p50_ms": round(statistics.median(timings), 3),
        "lookup_p99_ms": round(sorted(timings)[int(len(timings) * 0.99)], 3),
        "hit_rate": round(hits / len(timings), 3),
        "indexed_probe_ms": round(statistics.median(constant), 4),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m audit.scale_bench")
    parser.add_argument("--cves", type=int, default=250_000)
    parser.add_argument("--compare", type=int, default=2_500,
                        help="small corpus to compare lookup latency against")
    args = parser.parse_args(argv)

    print(f"building a {args.compare:,}-CVE corpus for comparison...")
    small = bench(args.compare)
    print(f"building a {args.cves:,}-CVE corpus...")
    large = bench(args.cves)

    print("\n" + "=" * 66)
    print(f"{'':<18}{args.compare:>14,}{args.cves:>14,}{'ratio':>12}")
    print("-" * 66)
    for key in ("cves", "statements", "build_s", "build_rate", "db_mb",
                "lookup_p50_ms", "lookup_p99_ms", "indexed_probe_ms"):
        a, b = small[key], large[key]
        ratio = f"{b / a:.2f}x" if a else "--"
        print(f"{key:<18}{a:>14,}{b:>14,}{ratio:>12}")
    print("=" * 66)

    size_ratio = args.cves / args.compare
    indexed_ratio = (large["indexed_probe_ms"] / small["indexed_probe_ms"]
                     if small["indexed_probe_ms"] else 0)
    result_ratio = (large["lookup_p50_ms"] / small["lookup_p50_ms"]
                    if small["lookup_p50_ms"] else 0)

    print(f"\ncorpus grew {size_ratio:.0f}x")
    print(f"  constant-result probe grew {indexed_ratio:.2f}x  <- the index")
    print(f"  real-fingerprint lookup grew {result_ratio:.2f}x  <- mostly "
          "more candidates, which is correct")

    if indexed_ratio > 3.0:
        print("\nVERDICT: FAIL. A lookup returning nothing got materially "
              "slower as the corpus grew, so it is scanning rather than "
              "seeking. Check the query plan.")
        return 1
    print("\nVERDICT: PASS. Lookup cost is flat against corpus size; what "
          "growth remains is candidates the matcher genuinely has to weigh.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
