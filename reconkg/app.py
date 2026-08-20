"""FastAPI surface: REST for state, WebSocket for live updates.

Post-audit. Every route requires a bearer credential; the authenticated
principal -- not anything in the request body -- is what the confidence model
treats as an identity.
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import (Depends, FastAPI, HTTPException, Query, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

from . import auth
from .auth import (TICKET_TTL_SECONDS, AuthError, Principal, Role, configure,
                   current_authenticator, on_auth_failure, require_principal,
                   require_principal_ws, require_role, require_scope,
                   validate_address)
from .observability import (PROMETHEUS_CONTENT_TYPE, CorrelationMiddleware,
                            Metrics, StoreMetricsSubscriber, bind_correlation,
                            configure_json_logging, correlation_scope,
                            record_scan_report)
from .ratelimit import RateLimiter
from .snapshots import SnapshotManager
from . import builtin_modules  # noqa: F401  -- registers built-ins
from .builtin_modules import module_pipeline
from .catalog import ExploitCatalog
from .engine import DiscoveryEngine, ScanReport
from .events import ConnectionManager
from .handoff import render_handoff
from .modules import Rank, registry as module_registry
from .planner import GapPlanner, render_plan
from .resolver import exploits_from_env, scripts_from_env
from .sources import default_registry
from .stages import EvidenceSource
from .store import TargetStore
from .ui import PAGE as UI_PAGE, SECURITY_HEADERS as UI_SECURITY_HEADERS

log = logging.getLogger(__name__)

MAX_TARGETS = 10_000
MAX_REPORTS = 1_000
MAX_EVIDENCE_BYTES = 512 * 1024


class AppState:
    def __init__(self) -> None:
        self.store = TargetStore()
        self.evidence = EvidenceSource()
        self.manager = ConnectionManager(self.store)
        self.registry = default_registry()
        self.engine = DiscoveryEngine(self.store, self.evidence,
                                      module_pipeline(),
                                      registry=self.registry)
        self.exploits = exploits_from_env()
        self.scripts = scripts_from_env()
        """Corpora two and three, acquired the way corpus one is (RC-36).

        `exploits_from_env` and `scripts_from_env` existed, were tested, and
        were called by nothing that shipped: `/handoff` invoked
        `build_handoff` without `exploits=` or `scripts=`, so an operator who
        built an ExploitDB index and pointed `RECONKG_EXPLOIT_DB` at it got a
        hand-off with no exploit lines and no indication that the index had
        not been consulted. Same defect as RC-36 -- a corpus configured,
        loaded by nobody, absent silently.

        Acquired here rather than lazily inside the route so the failure
        contract holds: a variable that is set and unopenable raises now, at
        construction, instead of degrading to "nothing published for any
        CVE" on every lead of every scan. Unset is a different claim and
        gets the Null variant, whose `describe()` says "not checked" rather
        than "none found".
        """
        self.planner = GapPlanner()
        self.catalog = ExploitCatalog()
        self.catalog_report = self.catalog.autoload()
        self.engine.catalog = self.catalog
        self.reports: dict[str, ScanReport] = {}
        self.limiter = RateLimiter()
        self.metrics = Metrics()
        self.metrics_sub = StoreMetricsSubscriber(self.metrics)
        self._unsub_metrics = self.metrics_sub.attach(self.store)
        # Persistence is opt-in via RECONKG_SNAPSHOT_DIR. Defaulting to a
        # relative "./snapshots" meant every AppState in a process shared one
        # directory keyed on the current working directory: a second instance
        # restored the first one's graph, and the scope-filtering test started
        # seeing a host from an unrelated test. Silent shared mutable state
        # keyed on CWD is a worse default than no persistence at all.
        snapshot_dir = os.environ.get("RECONKG_SNAPSHOT_DIR")
        self.snapshots: Optional[SnapshotManager] = (
            SnapshotManager(self.store, snapshot_dir, retention=5,
                            quiet_period=2.0, max_staleness=30.0)
            if snapshot_dir else None)

    def close(self) -> None:
        """Release the SQLite handles the three corpora hold.

        Idempotent, and best effort per resolver: a failure closing one
        handle must not leave the other two open. The Null and Static
        variants have no `close` at all, which is why this asks rather than
        assumes -- a resolver is a protocol a third party implements.
        """
        for resolver in (getattr(self.engine, "resolver", None),
                         self.exploits, self.scripts):
            closer = getattr(resolver, "close", None)
            if closer is None:
                continue
            try:
                closer()
            except Exception as exc:        # pragma: no cover - defensive
                log.warning("error closing %s: %s",
                            type(resolver).__name__, exc)

    def remember(self, address: str, report: ScanReport) -> None:
        """RC-03: bounded report retention, oldest evicted first."""
        self.reports[address] = report
        while len(self.reports) > MAX_REPORTS:
            self.reports.pop(next(iter(self.reports)))


state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_json_logging(logging.INFO, static_fields={"service": "reconkg"})
    configure()  # raises AuthError if RECONKG_TOKENS is unset -- by design
    on_auth_failure(lambda reason: state.metrics.inc(
        "reconkg_auth_failures_total", reason=reason))
    # Restore before any ingress is served: the snapshot writes into the
    # store, and a request landing mid-restore would see a half-graph.
    restored = 0
    if state.snapshots is not None:
        restored = await state.snapshots.restore_into(state.store)
        state.snapshots.start()
    log.info("coordinator up", extra={"hosts_restored": restored,
                                      "persistence": state.snapshots is not None})
    try:
        yield
    finally:
        if state.snapshots is not None:
            await state.snapshots.aclose()
        on_auth_failure(None)
        state._unsub_metrics()
        await state.manager.shutdown()
        # The corpora hold open SQLite connections. A process that reloads
        # its AppState -- the test suite does it per test -- leaks one file
        # handle per corpus per instance without this.
        state.close()


app = FastAPI(title="Asset & Vulnerability Coordinator", version="0.3.0",
              lifespan=lifespan)
# Pure-ASGI middleware, added last so it wraps everything. Deliberately not
# BaseHTTPMiddleware: that runs the downstream app in a separate anyio task,
# and a ContextVar set inside it never reaches the route handler.
app.add_middleware(CorrelationMiddleware, metrics=state.metrics)


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #

class TargetIn(BaseModel):
    address: str
    hostnames: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        return validate_address(v)

    @field_validator("hostnames")
    @classmethod
    def _hostnames(cls, v: list[str]) -> list[str]:
        return [validate_address(h) for h in v]


class EvidenceIn(BaseModel):
    tool: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    address: str
    data: dict

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        return validate_address(v)


def _require_unscoped(principal: Principal, route: str) -> None:
    """RC-28: telemetry describes every host, so it needs every host's scope.

    There is no per-principal view of an aggregate that is honest and cheap
    at the same time. A principal that may not read a host may not read the
    counters that name it either.
    """
    if principal.scope:
        raise HTTPException(
            403, f"principal '{principal.name}' is scoped to "
                 f"{', '.join(principal.scope)}; {route} reports on the whole "
                 "engagement and is refused to scoped credentials")


def _get_target(address: str):
    """Validate a path parameter before it is used as a lookup key."""
    try:
        return validate_address(address)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


# --------------------------------------------------------------------------- #
# REST
# --------------------------------------------------------------------------- #

@app.get("/api/health")
async def health(principal: Principal = Depends(require_role(Role.VIEWER))
                 ) -> dict:
    """RC-30: the counters are the caller's view of the graph, not the graph.

    RC-16 filtered `/api/targets` to the caller's scope and this route was
    left reporting engagement-wide totals to any VIEWER: a principal confined
    to one subnet learned how many hosts the engagement holds, and by polling
    `events_emitted` could watch a scan of a host it is not allowed to see.
    Same control, older route.

    An unscoped principal sees the same numbers as before -- for them the
    whole graph *is* their view.
    """
    hosts = [h for h in state.store.list_hosts()
             if principal.may_touch(h.address)]
    if principal.scope:
        events = [e for e in state.store.event_log
                  if e.target is None or principal.may_touch(e.target)]
        retained = len(events)
        emitted = len(events)
    else:
        retained = len(state.store.event_log)
        emitted = state.store.events_emitted
    return {"status": "ok", "hosts": len(hosts),
            "clients": state.manager.client_count,
            "events_retained": retained,
            "events_emitted": emitted,
            "scoped": bool(principal.scope),
            "principal": principal.name,
            "role": principal.role.value}


@app.post("/api/targets", status_code=201)
async def create_target(
        body: TargetIn,
        principal: Principal = Depends(require_role(Role.OPERATOR))) -> dict:
    from .models import Provenance
    require_scope(principal, body.address)
    # RC-27: this was the one graph-write route with no limiter. It was cheap
    # and idempotent when RC-15/RC-17 added limits elsewhere, and cycle 8
    # changed that: re-observing a known host now emits `host.updated`, which
    # fans out to every connected client, the autosave and the metrics
    # subscriber. A byte-identical repeat POST is a write.
    allowed, retry = state.limiter.check(principal.name)
    if not allowed:
        state.metrics.inc("reconkg_ratelimit_rejections_total",
                          principal=principal.name, route="targets")
        raise HTTPException(429, "target creation rate limit exceeded",
                            headers={"Retry-After": str(int(retry) + 1)})
    if len(state.store.list_hosts()) >= MAX_TARGETS:
        raise HTTPException(429, "target limit reached")
    host = await state.store.add_hostnames(
        body.address, body.hostnames,
        Provenance(source_tool="operator", principal=principal.name,
                   confidence=1.0))
    return {"address": host.address, "id": host.id}


@app.get("/api/targets")
async def list_targets(
        principal: Principal = Depends(require_role(Role.VIEWER))) -> list[dict]:
    """RC-16: the listing is filtered to the caller's scope.

    Returning every host to a principal restricted to one subnet leaks the
    shape of the engagement -- which is exactly the reconnaissance the scope
    was meant to withhold.
    """
    return [{"address": h.address, "ports": len(h.ports),
             "leads": len(h.all_leads())} for h in state.store.list_hosts()
            if principal.may_touch(h.address)]


@app.get("/api/targets/{address}")
async def get_target(
        address: str,
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    target = _get_target(address)
    require_scope(principal, target)
    host = state.store.get(target)
    if host is None:
        raise HTTPException(404, f"no such target: {address}")
    return host.model_dump(mode="json")


@app.post("/api/evidence", status_code=201)
async def put_evidence(
        body: EvidenceIn,
        principal: Principal = Depends(require_role(Role.SCANNER))) -> dict:
    """Load parsed tool output for a target.

    The coordinator makes no outbound connections -- scanners run wherever you
    run them and post parsed results here. What the submitter may *not* do is
    declare its own credibility: `principal` is taken from the credential and
    the confidence in the body is clamped by the registry's ceiling for that
    tool (RC-01).
    """
    require_scope(principal, body.address)
    bind_correlation(principal=principal.name, target=body.address)
    allowed, retry = state.limiter.check(principal.name)
    if not allowed:
        state.metrics.inc("reconkg_ratelimit_rejections_total",
                          principal=principal.name, route="evidence")
        raise HTTPException(429, "evidence rate limit exceeded",
                            headers={"Retry-After": str(int(retry) + 1)})
    if state.store.get(body.address) is None:
        raise HTTPException(404, "unknown target; POST /api/targets first")
    if len(str(body.data)) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, "evidence payload too large")
    state.evidence.put(body.tool, body.address, body.data,
                       principal=principal.name)
    state.metrics.inc("reconkg_evidence_submissions_total",
                      principal=principal.name, tool=body.tool)
    # The importer and the API are two ingresses to the same graph; evidence
    # staged here does not itself mutate the store, so the autosave has
    # nothing to react to until a scan runs.
    if state.snapshots is not None:
        state.snapshots.mark_dirty()
    return {"tool": body.tool, "address": body.address,
            "principal": principal.name, "role": principal.role.value,
            "registered_tool": state.registry.is_registered(body.tool),
            "reliability_ceiling": state.registry.reliability(body.tool)}


@app.post("/api/targets/{address}/scan")
async def scan(
        address: str,
        principal: Principal = Depends(require_role(Role.SCANNER))) -> dict:
    target = _get_target(address)
    require_scope(principal, target)
    # RC-17: a scan runs the whole pipeline and re-correlates. It costs far
    # more than an evidence POST, so it draws more from the same bucket
    # rather than being exempt from it, as it was.
    allowed, retry = state.limiter.check(principal.name, cost=5.0)
    if not allowed:
        state.metrics.inc("reconkg_ratelimit_rejections_total",
                          principal=principal.name, route="scan")
        raise HTTPException(429, "scan rate limit exceeded",
                            headers={"Retry-After": str(int(retry) + 1)})
    if state.store.get(target) is None:
        raise HTTPException(404, f"no such target: {address}")
    with correlation_scope(target=target, principal=principal.name):
        report = await state.engine.run(target)
    record_scan_report(state.metrics, report)
    state.remember(target, report)
    return report.as_dict()


@app.get("/api/targets/{address}/ledger")
async def ledger(address: str,
                 min_priority: float = Query(0.0, ge=0.0, le=1.0),
                 principal: Principal = Depends(require_role(Role.VIEWER))
                 ) -> list[dict]:
    target = _get_target(address)
    require_scope(principal, target)
    report = state.reports.get(target)
    if report is None:
        raise HTTPException(404, f"no scan report for {address}")
    return [r.as_dict() for r in report.ledger if r.priority >= min_priority]


@app.get("/api/targets/{address}/attempts")
async def attempts(
        address: str,
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    target = _get_target(address)
    require_scope(principal, target)
    report = state.reports.get(target)
    if report is None:
        raise HTTPException(404, f"no scan report for {address}")
    return {"target": target, "exhausted": report.exhausted_slots,
            "attempts": [a.as_dict() for a in report.attempts]}


@app.get("/api/catalog")
async def catalog_status(
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    """Availability indexes: what loaded, its digest, and whether it is stale.

    Exposed because `infer_maturity` trusts these files. An operator reading
    a ledger should be able to see what the ranking was based on.
    """
    return {"loaded": state.catalog_report,
            "records": len(state.catalog),
            "cves": state.catalog.cve_count,
            "stale": state.catalog.stale_indexes(),
            "integrity": {k: v.as_dict()
                          for k, v in state.catalog.integrity.items()},
            "stats": {k: v.as_dict() for k, v in state.catalog.stats.items()}}


#: Corpus name -> what an absent one costs the reader. Held here rather
#: than in the page because it is a statement about the tool's coverage, and
#: a browser that paraphrased it would be the second author of a security
#: notice.
CORPUS_LABELS = {
    "vulnerabilities": "CVE corpus (RECONKG_VULN_DB)",
    "exploits": "exploit index (RECONKG_EXPLOIT_DB)",
    "scripts": "NSE script index (RECONKG_SCRIPT_DB)",
}


def _corpus_entry(name: str, resolver) -> dict:
    """One resolver's own words, plus the booleans the UI badges.

    `describe` is verbatim. The three strings that matter -- "demonstration
    fixture", "STALE", and the exploit index's "means 'not checked'" -- exist
    so an analyst can tell an empty answer from an unasked question, and a
    summary that replaced them with a status colour would delete exactly the
    distinction they were written for.
    """
    kind = type(resolver).__name__
    description = resolver.describe()
    return {"corpus": name,
            "label": CORPUS_LABELS.get(name, name),
            "describe": description,
            "resolver": kind,
            # "Configured" is not "non-empty": a Null resolver means the
            # operator never claimed to have this corpus, which is a
            # different fact from a corpus that holds nothing.
            "configured": not kind.startswith("Null"),
            "demonstration_fixture": "demonstration fixture" in description,
            "empty": "EMPTY corpus" in description,
            "not_checked": "not checked" in description
                           or "are unknown" in description,
            "stale": "STALE" in description}


@app.get("/api/corpus")
async def corpus_status(
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    """What the leads were resolved against, in the resolvers' own words.

    All three corpora, not just the CVE one. A hand-off is assembled from
    three independent indexes and an operator reading it needs to know which
    of them were consulted -- reporting only corpus one meant the panel could
    say "corpus at /var/lib/nvd.sqlite: 250,000 CVEs" while the exploit index
    was never configured and every lead silently read "no known exploit".

    VIEWER, matching `/api/catalog` -- its closest peer and the same kind of
    answer: what the ranking was based on, not what is on any host. The
    description names a corpus path and counts CVEs; it names no target, so
    unlike `/metrics` it does not need `_require_unscoped` (RC-28).

    `describe` is passed through verbatim rather than summarised. The strings
    that matter -- "demonstration fixture", "STALE", and the null exploit
    index's "'no known exploit' below means 'not checked'" -- exist so an
    analyst can tell "this host is clean" from "this corpus is nine
    hand-written entries", from "every CVE published in the last four months
    is missing", from "nobody asked". A UI that rewrote them into a status
    colour would delete exactly the distinction they were written for. The
    booleans beside them are for highlighting, and are derived from the same
    strings.
    """
    corpora = [_corpus_entry("vulnerabilities", state.engine.resolver),
               _corpus_entry("exploits", state.exploits),
               _corpus_entry("scripts", state.scripts)]
    # The top-level keys are corpus one's, kept because they are what the
    # route has always answered and what clients read. `corpora` is the whole
    # answer, and the panel reads that.
    first = corpora[0]
    return {"describe": first["describe"],
            "resolver": first["resolver"],
            "demonstration_fixture": first["demonstration_fixture"],
            "stale": first["stale"],
            "corpora": corpora}


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    """There was nothing here, so the first thing every new user saw was a
    404 from their own tool."""
    return RedirectResponse(url="/ui")


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
async def ui_page() -> HTMLResponse:
    """The single-page operator console. See reconkg/ui.py.

    Served WITHOUT authentication, which reverses the original decision, so
    the reasoning matters.

    It was behind `require_role(Role.VIEWER)` like every other read route.
    That is defensible until you try to use it: a browser cannot attach an
    `Authorization` header to a top-level navigation, so the page 401'd --
    and the page is the thing that asks you for your token. You could not
    authenticate because you could not load the form that authenticates you.
    A UI nobody can open is not a security control, it is a broken feature,
    and the practical result was operators reaching for a query-string token
    instead, which is exactly what RC-12 removed.

    What is actually being served anonymously: a static document with no
    engagement data in it. Every byte it displays arrives later from
    `/api/*`, all of which still require the bearer token, and the page
    holds that token in `sessionStorage` for its own tab only. Loading it
    without a credential shows empty panels.

    So the anonymous surface added here is one constant HTML response on
    loopback. The alternative was
    "it's only static" is how the first one always gets added.

    Consequence, stated rather than worked around: a browser cannot set an
    Authorization header on a top-level navigation, so this page is reached
    through a header-injecting client or a loopback proxy. Accepting the
    token as a query parameter instead would put a standing credential in
    access logs and browser history, which is the thing RC-12 replaced with
    single-use tickets.
    """
    return HTMLResponse(UI_PAGE, headers=dict(UI_SECURITY_HEADERS))


@app.get("/metrics")
async def prometheus_metrics(
        principal: Principal = Depends(require_role(Role.ADMIN))) -> Response:
    """Prometheus exposition.

    ADMIN, not VIEWER: label values include target addresses, so the metric
    set leaks the shape of the engagement. Exposing this to a scope-restricted
    viewer would reopen RC-16 through a new door -- scope enforced on the
    graph but not on the telemetry describing it.

    RC-28: and the role check alone did not finish that argument. `Principal.
    scope` is orthogonal to role -- `adm:admin:<token>:10.10.10.0/24` parses
    -- so a scoped admin was refused a direct read of an out-of-scope host
    with 403 and then handed every address in the engagement as a label
    value. Filtering the exposition per principal would mean re-deriving which
    label carries an address for every metric, on every scrape, and getting it
    wrong once is the whole leak; refusing a scoped principal outright is the
    check that cannot be partly right.
    """
    _require_unscoped(principal, "/metrics")
    return Response(state.metrics.render_prometheus(),
                    media_type=PROMETHEUS_CONTENT_TYPE)


@app.get("/api/metrics")
async def metrics_json(
        principal: Principal = Depends(require_role(Role.ADMIN))) -> dict:
    _require_unscoped(principal, "/api/metrics")     # RC-28
    return {"metrics": state.metrics.snapshot(),
            "snapshots": (state.snapshots.stats()
                          if state.snapshots is not None
                          else {"enabled": False})}


@app.post("/api/ws-ticket", status_code=201)
async def ws_ticket(
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    """Mint a short-lived, single-use ticket for the WebSocket handshake.

    Browsers cannot set an Authorization header on a WS upgrade, and a
    standing token in a query string ends up in access logs and history.
    """
    try:
        ticket = current_authenticator().issue_ticket(principal)
    except AuthError as exc:
        # RC-26: the table is full of *other* principals' tickets. Refusing
        # this caller is the honest answer; evicting one of theirs was the
        # bug.
        raise HTTPException(429, str(exc), headers={"Retry-After": "60"})
    return {"ticket": ticket, "expires_in": TICKET_TTL_SECONDS,
            "principal": principal.name}


# --------------------------------------------------------------------------- #
# Modules
# --------------------------------------------------------------------------- #

@app.get("/api/modules")
async def list_modules(
        q: str = Query("", max_length=200),
        principal: Principal = Depends(require_role(Role.VIEWER))) -> list[dict]:
    """Search modules. Supports `category:`, `rank:` and `cve:` filters."""
    try:
        found = module_registry.search(q)
    except ValueError as exc:
        raise HTTPException(400, f"bad search filter: {exc}") from None
    return [{"fullname": c.meta.fullname, "name": c.meta.name,
             "rank": c.meta.rank.value, "category": c.meta.category,
             "cves": c.meta.cves(),
             "disclosure_date": c.meta.disclosure_date.isoformat()
             if c.meta.disclosure_date else None}
            for c in found]


@app.get("/api/modules/{fullname:path}")
async def module_info(
        fullname: str,
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    try:
        instance = module_registry.create(fullname)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from None
    meta = instance.meta
    return {
        "fullname": meta.fullname, "name": meta.name,
        "description": meta.description, "rank": meta.rank.value,
        "authors": list(meta.authors), "platforms": list(meta.platforms),
        "notes": list(meta.notes),
        "references": [{"type": r.type.value, "value": r.value,
                        "url": r.url()} for r in meta.references],
        "disclosure_date": meta.disclosure_date.isoformat()
        if meta.disclosure_date else None,
        "options": [{"name": o.name, "type": o.type.value,
                     "default": o.default, "required": o.required,
                     "advanced": o.advanced, "description": o.description,
                     "choices": list(o.choices)} for o in instance.options],
        "info": instance.info(),
    }


# --------------------------------------------------------------------------- #
# Gap plan and hand-off
# --------------------------------------------------------------------------- #

@app.get("/api/targets/{address}/plan")
async def plan(
        address: str, render: bool = Query(False),
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    """What we still don't know, and which module would close each gap.

    Vulnerability leads appear here with `module: null` and
    `action: "handoff"` -- they route to the operator, not to a module.
    """
    target = _get_target(address)
    require_scope(principal, target)
    host = state.store.get(target)
    if host is None:
        raise HTTPException(404, f"no such target: {address}")
    recs = state.planner.plan(host)
    out = {"target": host.address,
           "recommendations": [r.as_dict() for r in recs],
           "commands": [r.command() for r in recs]}
    if render:
        out["rendered"] = render_plan(recs)
    return out


@app.get("/api/targets/{address}/handoff/{cve_id}")
async def handoff(
        address: str, cve_id: str, categories: str = "",
        principal: Principal = Depends(require_role(Role.VIEWER))) -> dict:
    """Verification lookups and caveats for one lead. Executes nothing."""
    target = _get_target(address)
    require_scope(principal, target)
    report = state.reports.get(target)
    if report is None:
        raise HTTPException(404, f"no scan report for {address}")
    row = next((r for r in report.ledger if r.cve_id.upper() == cve_id.upper()),
               None)
    if row is None:
        raise HTTPException(404, f"no lead {cve_id} on {target}")
    from .vulnref import DEFAULT_REFERENCE
    from .handoff import build_handoff
    from .commands import Category

    # The UI sends `categories=safe,version,intrusive` from its tickboxes.
    # Absent, the default tier only -- an API client that says nothing gets
    # the conservative answer rather than everything.
    selected = None
    if categories:
        selected = []
        for name in categories.split(","):
            try:
                selected.append(Category(name.strip().lower()))
            except ValueError:
                raise HTTPException(
                    400, f"unknown command category {name.strip()!r}")

    # All three corpora, or the Null resolvers that say they are absent.
    # Passing `exploits`/`scripts` is the whole of the wiring: `build_handoff`
    # has taken them since corpus two landed, and the API never supplied
    # them, so every hand-off answered from the built-in catalogue alone.
    built = build_handoff(row, state.engine.resolver, state.catalog, selected,
                          exploits=state.exploits, scripts=state.scripts)
    return {"lead": row.as_dict(), "lookups": built.lookups,
            "commands": [c.as_dict() for c in built.commands],
            "references": built.references, "caveats": built.caveats,
            "operator_supplied": built.operator_supplied,
            "rendered": built.render()}


# --------------------------------------------------------------------------- #
# WebSocket
# --------------------------------------------------------------------------- #

@app.websocket("/ws")
async def ws(websocket: WebSocket,
             client_id: Optional[str] = Query(None),
             target: Optional[str] = Query(None)) -> None:
    principal = await require_principal_ws(websocket)
    if principal is None:
        return  # already closed 1008
    if target is not None:
        try:
            target = validate_address(target)
        except ValueError:
            await websocket.close(code=1008)
            return
    if target is not None and not principal.may_touch(target):
        await websocket.close(code=1008)
        return
    client_id = f"{principal.name}:{(client_id or uuid.uuid4().hex[:8])[:32]}"
    await state.manager.connect(websocket, client_id, target,
                                scope=principal.may_touch)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await state.manager.disconnect(client_id)


# --------------------------------------------------------------------------- #
# Running it
#
# This was missing, and the README told people to run `python -m reconkg.app`
# -- which imported the module, did nothing, and exited silently. No server,
# no port, no error. The most annoying possible failure: it looks like it
# worked.
# --------------------------------------------------------------------------- #

def main(argv: Optional[list[str]] = None) -> int:
    """Serve the UI and API on loopback.

    Binds 127.0.0.1 and not 0.0.0.0, deliberately and without a flag to
    change it. This process holds an operator's scan results and issues
    commands aimed at hosts they are testing; the cost of it being reachable
    from the rest of the network is much higher than the inconvenience of
    an SSH tunnel for the rare case where remote access is genuinely wanted.
    """
    import argparse
    import secrets

    parser = argparse.ArgumentParser(prog="python -m reconkg.app")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("RECONKG_PORT", "8765")))
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed. pip install -e . --break-system-packages",
              file=sys.stderr)
        return 2

    # Without RECONKG_TOKENS the app refuses to start -- correct for a
    # deployment, useless for someone who just cloned it and wants to look at
    # the UI. Mint a random one for this process only: it is never written to
    # disk, it dies with the process, and it is printed to the operator's own
    # terminal. Same shape as Jupyter's startup token.
    minted = False
    if not os.environ.get(auth.TOKEN_ENV, "").strip():
        token = secrets.token_urlsafe(24)
        os.environ[auth.TOKEN_ENV] = f"local:{Role.ADMIN.value}:{token}"
        minted = True
    else:
        token = None

    url = f"http://127.0.0.1:{args.port}"
    print(flush=True)
    print(f"  reconkg  ->  {url}/ui")
    print(flush=True)
    if minted:
        print("  No RECONKG_TOKENS was set, so a token was generated for this", flush=True)
        print("  session only. It is not saved anywhere and changes on restart.", flush=True)
        print(flush=True)
        print(f"    Authorization: Bearer {token}", flush=True)
        print(flush=True)
        print("  The UI needs that header, which a browser cannot attach to a", flush=True)
        print("  plain navigation. Either use a header-injecting extension, or", flush=True)
        print("  drive the API directly:", flush=True)
        print(flush=True)
        print(f"    curl -H 'Authorization: Bearer {token}' {url}/api/corpus", flush=True)
        print(flush=True)
        print("  To set your own instead:", flush=True)
        print(f"    export {auth.TOKEN_ENV}='me:admin:<your-token>'", flush=True)
        print(flush=True)

    uvicorn.run("reconkg.app:app" if args.reload else app,
                host="127.0.0.1", port=args.port, reload=args.reload,
                log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
