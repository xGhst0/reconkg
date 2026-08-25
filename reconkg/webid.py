"""What a web page calls itself, turned into something a corpus can match.

whatweb's `Title` plugin returns the contents of `<title>`, and it is the
only plugin that names the *application* rather than the stack underneath
it -- Apache, OpenSSL, PHP and jQuery all arrive carrying versions, and none
of them is what an operator is hunting. Keeping the title was right.
Storing it verbatim as a product name was not: a page title is prose.

Observed on one host, in a single run:

    Title[rConfig - Configuration Management]  ->  product "rconfig"
    Title[400 Bad Request]                     ->  not a product at all
    Title[phpMyAdmin 4.8.1 | localhost]        ->  product AND a free version

All three were recorded as products. The first matched nothing, because no
corpus files CVEs under "rconfig - configuration management". The second put
an HTTP status line into the knowledge graph, and the Coverage panel then
asked the operator to go and find a version for it. The third threw away a
version that was sitting in the string.

Nothing here contacts a target or opens a database. It *proposes* candidate
identities in preference order and an arbiter -- the corpus -- decides which
one is real. That split is deliberate. A splitter that also decided would be
guessing, and a guess that reaches the ledger looking like an identifier
match is the failure mode this project spends most of its code avoiding.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger(__name__)


#: Products that describe what a web application RUNS ON rather than what it
#: is. whatweb reports both in one list and they are not the same kind of
#: claim: Apache, OpenSSL, PHP and jQuery are the stack, and on a
#: distribution build their CVEs are backported anyway -- which reconkg
#: already says on every such lead. The application is what an operator is
#: actually hunting.
#:
#: Observed: a host returned 97 leads across Apache 2.4.6, OpenSSL 1.0.2k,
#: PHP 7.2.34 and jQuery 2.2.4, every Apache row carrying "CentOS --
#: distribution build". The way in was rConfig, an application none of those
#: names mention and nothing in the run ever identified. The ledger was not
#: wrong; it was answering a different question, at length.
#:
#: Lives here rather than in `planner.py` because two callers now need it and
#: the second one decides whether a fingerprint may generate leads. A set
#: that gates behaviour on one path and merely annotates on another is this
#: codebase's most-repeated bug; `planner` re-exports it so there is still
#: one definition.
WEB_PLATFORM_PRODUCTS = frozenset({
    "apache", "apache httpd", "httpd", "nginx", "iis", "lighttpd",
    "microsoft iis httpd", "microsoft-iis", "openssl", "php", "mod_ssl",
    "jquery", "jquery-ui", "bootstrap", "javascript", "html5", "modernizr",
    "httpserver", "x-powered-by", "cookies", "uncommonheaders", "title",
    "country", "ip", "script", "email", "meta-author", "openssh",
})


#: A response status line is what the *server* said, not what the software
#: is called. `400 Bad Request` reached the graph as an application because
#: port 443 was fetched over plain HTTP; that scheme bug is fixed, and a host
#: that answers any request with an error page would have done the same
#: thing. The shape is what disqualifies it, not the particular string.
_STATUS_LINE = re.compile(r"^[1-5]\d{2}\b")
_DIRECTORY_INDEX = re.compile(r"^index of\b")

#: A trailing version, with or without a `v` prefix. Two dotted components
#: minimum: a single number is far more often a year, a count or a section
#: number than a version, and inventing a version is worse than lacking one
#: -- `build_leads` tests constraints against whatever it is handed.
_VERSION_TAIL = re.compile(
    r"^(?P<name>.*?)[\s/_,-]*v?(?P<version>\d+(?:\.\d+)+[A-Za-z0-9._+-]*)$")

#: Title separators. `-` and `:` require surrounding space so `rConfig-Web`
#: and `12:30` survive intact; `|`, `::`, en/em dash and the guillemet do
#: not, because nothing spells a product name with them.
_SEPARATOR = re.compile(r"\s*(?:::|[|–—»·])\s*|\s+-\s+|\s*:\s+")

_LEAD_IN = re.compile(r"^(?:welcome\s+to|welcome)\s+", re.IGNORECASE)

#: What a page calls itself when it is not naming its software. Doing double
#: duty: rejected as whole titles, and skipped as segments -- so
#: "Dashboard | Zabbix" proposes Zabbix, which is the answer.
_GENERIC = frozenset({
    "untitled", "untitled document", "document", "home", "home page",
    "index", "login", "log in", "sign in", "signin", "logout", "dashboard",
    "welcome", "error", "forbidden", "not found", "page not found",
    "access denied", "unauthorized", "bad request", "internal server error",
    "service unavailable", "under construction", "coming soon",
    "site not found", "no title", "redirecting", "loading", "please wait",
    "admin", "administration", "control panel", "management", "portal",
    "main page", "start page", "test", "example domain",
})

#: Substrings marking a stock page shipped by the server package. These name
#: the web server, so without this they would arbitrate successfully to a
#: platform product and look like a real identification.
_PLACEHOLDER = (
    "test page", "default page", "it works", "welcome to nginx",
    "apache http server test", "iis windows server", "placeholder page",
    "web server's default", "site not configured", "future home of",
)


def cpe_product(name: str) -> str:
    """A human product name in the spelling a CPE corpus files it under.

    Lowercase, spaces to underscores, punctuation CPE does not carry
    dropped. Defined here, next to the splitter, so the name a candidate is
    *proposed* under and the name it is *looked up* under cannot drift --
    two spellings of one normalisation is how a lookup silently starts
    answering "never heard of it" for software the corpus holds.
    """
    text = (name or "").strip().lower()
    text = re.sub(r"[^a-z0-9._+-]+", "_", text)
    return text.strip("_")


def split_version(text: str) -> tuple[str, Optional[str]]:
    """`"phpMyAdmin 4.8.1"` -> `("phpMyAdmin", "4.8.1")`."""
    candidate = (text or "").strip()
    match = _VERSION_TAIL.match(candidate)
    if not match:
        return candidate, None
    name = match.group("name").strip()
    if not name:
        # The whole string was a version. That names nothing.
        return candidate, None
    return name, match.group("version")


def is_not_a_product(text: str) -> bool:
    """True when this string cannot be the name of any software.

    Judged on shape and on stock-page markers, never on a blocklist of
    strings observed on one host -- a list of one host's error pages fixes
    one host.
    """
    candidate = (text or "").strip()
    if len(candidate) < 2:
        return True
    lowered = candidate.lower()
    if _STATUS_LINE.match(lowered) or _DIRECTORY_INDEX.match(lowered):
        return True
    if lowered in _GENERIC:
        return True
    if any(marker in lowered for marker in _PLACEHOLDER):
        return True
    # Punctuation, digits and whitespace only.
    return not re.search(r"[a-z]", lowered)


def identities(title: str) -> list[tuple[str, Optional[str]]]:
    """Candidate `(product, version)` readings of a title, best first.

    Order is load-bearing, and it is document order rather than
    longest-first. For "rConfig - Configuration Management" the application
    is the first segment; for "Dashboard | Zabbix" it is the last, and the
    first is rejected as generic before it can be proposed. Whichever the
    arbiter recognises first wins, so a corpus that knows two of the
    segments returns the one the page led with.
    """
    text = (title or "").strip()
    if not text or is_not_a_product(text):
        return []

    proposals: list[tuple[str, Optional[str]]] = []
    seen: set[str] = set()

    def offer(candidate: str) -> None:
        name, version = split_version(_LEAD_IN.sub("", candidate).strip(" .,;"))
        if not name or is_not_a_product(name):
            return
        key = cpe_product(name)
        if not key or key in seen:
            return
        seen.add(key)
        proposals.append((name, version))

    # The whole title first: "phpMyAdmin 4.8.1" is one product and one
    # version, and splitting it would propose a nameless fragment.
    offer(text)
    for segment in _SEPARATOR.split(text):
        offer(segment or "")
    return proposals


@dataclass(frozen=True)
class Identity:
    """What a fingerprint should be recorded as, and why."""

    product: str
    version: Optional[str]
    vendor: Optional[str] = None
    """The vendor the corpus files this product under, when it knows one.

    Carried so the caller can build a CPE and reach the identifier path.
    Without it a recognised product still goes through the substring
    fallback, which has no version bounds at all -- an operator who read
    "3.9.6" off the page and submitted it would get every CVE ever filed
    against the product back, with the version they supplied ignored and the
    ledger presenting the result as a version match.
    """
    application: bool = False
    """The corpus recognises this product and it is not a platform component.

    The permission `build_leads` reads. An unversioned fingerprint normally
    generates nothing -- correctly, since product-only matching carries no
    version bounds and gave an IIS 10.0 host two 2008 ActiveX CVEs. That
    reasoning is about *platform* products, which hold thousands of CVEs
    across twenty years of unrelated versions. It does not hold for a named
    application the corpus knows: "rConfig, version unknown, here is every
    CVE filed against rConfig" is the most useful sentence available, and it
    is true.
    """
    note: str = ""


def resolve_identity(product: Optional[str], version: Optional[str],
                     lookup: Optional[Callable[[str], Optional[str]]] = None
                     ) -> Optional[Identity]:
    """Decide what a raw product claim really names. `None` = discard it.

    `lookup` takes a CPE-spelled product name and returns the vendor the
    corpus files it under, or `None` if it has never heard of it. One
    callable rather than a separate "do you know this?" predicate, because
    two questions answered from two queries can disagree -- and the
    disagreement would read as a product the corpus knows but cannot look
    up.

    It is optional so this stays usable, and testable, with no corpus at
    all. Without it the junk filter still runs and nothing is ever promoted,
    which is the honest behaviour for a tool that cannot check.
    """
    raw = (product or "").strip()
    if not raw:
        return Identity(product=raw, version=version)
    if is_not_a_product(raw):
        log.info("discarding %r: an HTTP status line, stock page or generic "
                 "title is not an application", raw)
        return None

    lowered = raw.lower()
    if lowered in WEB_PLATFORM_PRODUCTS:
        # Never promoted, whatever the corpus says. Apache is known to every
        # corpus; that is exactly why product-only Apache leads are noise.
        return Identity(product=raw, version=version)

    if lookup is None:
        return Identity(product=raw, version=version)

    vendor = lookup(cpe_product(raw))
    if vendor:
        return Identity(product=raw, version=version, vendor=vendor,
                        application=True,
                        note="product named in the corpus")

    for name, found in identities(raw):
        if name.lower() in WEB_PLATFORM_PRODUCTS:
            continue
        vendor = lookup(cpe_product(name))
        if not vendor:
            continue
        recovered = version or found
        log.info("read %r as product %r%s", raw, name,
                 f" version {recovered}" if recovered and not version else "")
        return Identity(
            product=name, version=recovered, vendor=vendor, application=True,
            note=(f"read out of the page title {raw!r}"
                  + (f"; version {found} came from the same string"
                     if found and not version else "")))

    # Unrecognised. Kept verbatim rather than mangled: the Coverage panel
    # still names it to the operator, and a title this tool cannot place is
    # exactly the case where a human reading the page beats more parsing.
    return Identity(product=raw, version=version)
