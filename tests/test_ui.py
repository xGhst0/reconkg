"""Cycle 9 stream D: the local web UI, and the controls it must not undermine.

Three kinds of test live here.

*Routing and authorisation* -- `/ui` and `/api/corpus` are new ingresses, and
the standing finding across every round of this audit is a control enforced
on one path and skipped on the second. Both are checked against the same
matrix as their peers: anonymous, wrong role, right role, and (for the data
route) a scoped principal.

*The category gate through HTTP*, because that is how the UI reaches it. The
tickboxes become `?categories=`, and the opt-in tier must stay absent until
they are ticked while the never-composed tier stays uncomposed however they
are ticked.

*A static assertion on the served asset.* The page renders CVE titles,
product names, module paths and rationales, all of which come out of
downloaded feeds. `innerHTML` anywhere in it turns a poisoned feed record
into script execution in the analyst's browser, and a review will not catch
its reintroduction reliably. Grepping the bytes the route actually serves
will.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from reconkg.commands import (DEFAULT_CATEGORIES, NEVER_COMPOSED,
                              OPT_IN_CATEGORIES, Category, INTRUSIVE_WARNING)

ADMIN_T = "a" * 24
VIEWER_T = "v" * 24
SCANNER_T = "s" * 24
OPERATOR_T = "o" * 24

ADMIN = {"Authorization": f"Bearer {ADMIN_T}"}
VIEWER = {"Authorization": f"Bearer {VIEWER_T}"}
SCANNER = {"Authorization": f"Bearer {SCANNER_T}"}
OPERATOR = {"Authorization": f"Bearer {OPERATOR_T}"}

TOKENS = (f"adm:admin:{ADMIN_T},"
          f"view:viewer:{VIEWER_T},"
          f"scan:scanner:{SCANNER_T},"
          f"lead:operator:{OPERATOR_T}")
SCOPED_TOKENS = (f"view:viewer:{VIEWER_T}:10.10.10.0/24,"
                 f"scan:scanner:{SCANNER_T},"
                 f"lead:operator:{OPERATOR_T}")

TARGET = "10.10.10.42"
CVE = "CVE-2021-41773"

#: Read routes the UI calls. `/ui` is expected to behave exactly like these.
PEER_READ_ROUTES = ["/api/health", "/api/targets", "/api/catalog"]


def _client(monkeypatch, tokens: str = TOKENS):
    monkeypatch.setenv("RECONKG_TOKENS", tokens)
    monkeypatch.delenv("RECONKG_SNAPSHOT_DIR", raising=False)
    monkeypatch.delenv("RECONKG_VULN_DB", raising=False)
    from reconkg import app as app_module
    app_module.state = app_module.AppState()
    return app_module, TestClient(app_module.app)


def _seed(c, address: str = TARGET) -> None:
    """Enough evidence for the Apache 2.4.49 lead to reach the ledger."""
    c.post("/api/targets", json={"address": address}, headers=OPERATOR)
    c.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sT", "address": address,
        "data": {"ports": [{"number": 80, "state": "open",
                            "confidence": 0.9}]}})
    c.post("/api/evidence", headers=SCANNER, json={
        "tool": "nmap-sV-intensity9", "address": address,
        "data": {"services": [
            {"port": 80, "service": "http", "product": "Apache httpd",
             "version": "2.4.49", "confidence": 0.9,
             "banner": "Server: Apache/2.4.49 (Unix)"}]}})
    c.post(f"/api/targets/{address}/scan", headers=SCANNER)


@pytest.fixture
def client(monkeypatch):
    _module, c = _client(monkeypatch)
    with c:
        yield c


# --------------------------------------------------------------------------- #
# The page is served
# --------------------------------------------------------------------------- #

def test_the_ui_route_serves_the_page(client):
    response = client.get("/ui", headers=VIEWER)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert body.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in body


def test_the_page_is_self_contained(client):
    """No build step, no CDN, no npm. A tool that needs the internet to draw
    itself is a tool that does not work on the engagement network."""
    body = client.get("/ui", headers=VIEWER).text
    assert not re.search(r'src\s*=\s*["\']https?://', body)
    assert not re.search(r'href\s*=\s*["\']https?://[^"\']*\.css', body)
    assert "cdn" not in body.lower()


def test_the_page_carries_the_hardening_headers(client):
    headers = client.get("/ui", headers=VIEWER).headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"


def test_every_panel_the_spec_asked_for_is_present(client):
    body = client.get("/ui", headers=VIEWER).text
    for panel in ("panel-scan", "panel-graph", "panel-prov", "panel-ledger",
                  "panel-commands", "panel-corpus"):
        assert f'id="{panel}"' in body, panel


def test_progress_rides_the_existing_websocket_bus(client):
    """One event channel, not two. The page mints a ticket at the existing
    /api/ws-ticket and redeems it at the existing /ws."""
    body = client.get("/ui", headers=VIEWER).text
    assert "/api/ws-ticket" in body
    assert "new WebSocket(" in body
    assert body.count("new WebSocket(") == 1
    assert "setInterval" not in body      # no polling loop behind it either


# --------------------------------------------------------------------------- #
# Authorisation: the same treatment as the peer routes
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("path", ["/api/corpus"])
def test_new_routes_refuse_anonymous_callers(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", ["/api/corpus"])
def test_new_routes_refuse_a_bad_credential(client, path):
    assert client.get(path, headers={"Authorization": "Bearer " + "z" * 24}
                      ).status_code == 401


@pytest.mark.parametrize("path", ["/api/corpus"])
def test_new_routes_match_their_peers_exactly(client, path):
    """Not "is authenticated" but "authenticated the same way": the same
    status for the same credential as the routes beside it."""
    for peer in PEER_READ_ROUTES:
        assert (client.get(path).status_code
                == client.get(peer).status_code), peer
        for headers in (VIEWER, SCANNER, OPERATOR, ADMIN):
            assert (client.get(path, headers=headers).status_code
                    == client.get(peer, headers=headers).status_code), peer


def test_the_ui_does_not_accept_a_token_in_the_query_string(client):
    """RC-12: a standing credential in a query string lands in access logs
    and browser history. Tickets exist so it does not have to.

    `/ui` now serves anonymously (see below), so the assertion moved: the
    query string must not *authenticate* anything. The page loads either
    way and the data routes still refuse.
    """
    assert client.get(f"/api/corpus?token={VIEWER_T}").status_code == 401
    assert client.get(f"/api/health?token={VIEWER_T}").status_code == 401
    assert client.get(f"/api/targets?token={VIEWER_T}").status_code == 401


# --------------------------------------------------------------------------- #
# /ui is anonymous, and these say why
#
# It was behind require_role(VIEWER) with every other read route. That is
# defensible right up until someone tries to use it: a browser cannot attach
# an Authorization header to a top-level navigation, so the page 401'd -- and
# the page is what asks you for your token. You could not authenticate
# because you could not load the form that authenticates you. Reported from a
# real Kali install.
#
# A UI nobody can open is not a control, it is a broken feature, and the
# practical consequence was reaching for a query-string token, which is
# exactly what RC-12 removed. The tests below pin the narrower promise that
# replaced it: the shell is public on loopback, the data is not.
# --------------------------------------------------------------------------- #

def test_the_ui_shell_loads_without_a_credential(client):
    """The circular-dependency fix. A browser must be able to reach the page
    that asks for the token."""
    response = client.get("/ui")
    assert response.status_code == 200
    assert "<html" in response.text.lower()


def test_the_root_path_redirects_to_the_ui(client):
    """`/` used to 404, so the first thing a new user saw was their own tool
    reporting not-found."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (301, 302, 307, 308)
    assert response.headers["location"] == "/ui"


def test_the_anonymous_shell_carries_no_engagement_data(client):
    """The whole basis for serving it anonymously.

    Two things are deliberately NOT leaks and the first draft of this test
    flagged both, so they are named rather than left to be rediscovered:
    `placeholder="10.10.10.42"` is a hint on an empty input, and the string
    `"Bearer "` is the JavaScript literal that *builds* the header at
    runtime. Neither carries a fact about a host or a credential.

    What must never appear is a real token or data read out of the store.
    """
    body = client.get("/ui").text

    assert VIEWER_T not in body, "a real token is baked into the page"
    assert "reconkg-token" in body, (
        "the page should reference sessionStorage, not hold a token")

    import re
    # A CVE id in the shell would mean it was rendered server-side from the
    # corpus, which is the failure this test exists for. The word `CVE`
    # appearing in a column heading is fine.
    ids = re.findall(r"CVE-\d{4}-\d{4,7}", body)
    assert ids == [], f"the anonymous page names real CVEs: {ids[:5]}"

    # Any IPv4 outside the loopback/documentation ranges and the one
    # placeholder would have to have come from somewhere real.
    allowed = {"10.10.10.42", "127.0.0.1", "0.0.0.0"}
    addresses = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)) - allowed
    assert addresses == set(), f"unexpected addresses in the shell: {addresses}"


def test_the_shell_is_the_same_bytes_for_everyone(client):
    """It is a constant. An anonymous response that varies by caller would
    mean it is carrying state it should not have."""
    assert client.get("/ui").text == client.get("/ui", headers=VIEWER).text


@pytest.mark.parametrize("path", [
    "/api/corpus", "/api/health", "/api/targets", "/api/catalog"])
def test_every_data_route_still_refuses_anonymous_callers(client, path):
    """The half that did not change, asserted loudly because the half that
    did change is next door."""
    assert client.get(path).status_code == 401


def test_a_scoped_viewer_may_still_read_the_corpus_status(monkeypatch):
    """The description names a corpus, not a host, so unlike /metrics it is
    not engagement-shaped telemetry and does not need RC-28's refusal."""
    _module, c = _client(monkeypatch, SCOPED_TOKENS)
    with c:
        assert c.get("/api/corpus", headers=VIEWER).status_code == 200
        assert c.get("/api/catalog", headers=VIEWER).status_code == 200


# --------------------------------------------------------------------------- #
# Corpus status is describe(), verbatim
# --------------------------------------------------------------------------- #

def test_corpus_route_returns_the_resolvers_own_description(client, monkeypatch):
    from reconkg import app as app_module
    body = client.get("/api/corpus", headers=VIEWER).json()
    assert body["describe"] == app_module.state.engine.resolver.describe()
    assert body["resolver"] == "StaticResolver"


def test_the_demonstration_fixture_string_survives_verbatim(client):
    """"No leads" against the built-in nine is not the same answer as "no
    leads" against a real corpus, and the analyst is told which."""
    body = client.get("/api/corpus", headers=VIEWER).json()
    assert "demonstration fixture" in body["describe"]
    assert body["demonstration_fixture"] is True
    assert body["stale"] is False


def test_the_stale_token_survives_verbatim(client, monkeypatch):
    from reconkg import app as app_module

    class _StaleResolver:
        def candidates(self, fp):
            return []

        def describe(self):
            return ("corpus at /tmp/x.sqlite: 1 CVEs, 1 applicability "
                    "statements, built 400 days ago -- STALE. Every CVE "
                    "published since is missing.")

    monkeypatch.setattr(app_module.state.engine, "resolver", _StaleResolver())
    body = client.get("/api/corpus", headers=VIEWER).json()
    assert "STALE" in body["describe"]
    assert body["stale"] is True
    assert body["demonstration_fixture"] is False


def test_an_empty_corpus_is_badged_and_not_merely_described(client,
                                                            monkeypatch):
    """`/api/corpus` has computed `empty` since RC-43; the page dropped it.

    A corpus holding zero CVEs answers "no leads" to every question with
    total confidence. That is the one state this panel exists to make
    unmissable, and it was the one state carrying no badge at all -- the
    flag was computed server-side and never read.
    """
    from reconkg import app as app_module

    class _EmptyResolver:
        def candidates(self, fp):
            return []

        def describe(self):
            return ("EMPTY corpus at /tmp/x.sqlite: 0 CVEs. The build "
                    "produced nothing, so every lookup will report 'no "
                    "leads' regardless of the host.")

    monkeypatch.setattr(app_module.state.engine, "resolver", _EmptyResolver())
    body = client.get("/api/corpus", headers=VIEWER).json()
    assert body["empty"] is True
    assert body["demonstration_fixture"] is False

    page = client.get("/ui", headers=VIEWER).text
    assert "entry.empty" in page, (
        "the page never reads the flag, so the badge can never render")


# --------------------------------------------------------------------------- #
# The category gate, through the HTTP layer the tickboxes actually use
# --------------------------------------------------------------------------- #

def test_the_default_tickboxes_are_the_default_categories(client):
    """`safe`, `discovery`, `version` ticked; the opt-in tier not."""
    body = client.get("/ui", headers=VIEWER).text
    defaults = sorted(c.value for c in DEFAULT_CATEGORIES)
    optin = sorted(c.value for c in OPT_IN_CATEGORIES)
    assert f"const DEFAULT_CATEGORIES = {defaults!r}".replace("'", '"') in body
    assert f"const OPT_IN_CATEGORIES = {optin!r}".replace("'", '"') in body
    assert "intrusive" not in defaults and "vuln" not in defaults


def test_the_intrusive_warning_is_the_one_from_commands_py(client):
    """Verbatim, not paraphrased. The UI does not restate a security notice
    in its own words."""
    body = client.get("/ui", headers=VIEWER).text
    assert INTRUSIVE_WARNING in body


def test_default_categories_withhold_the_opt_in_tier(client):
    _seed(client)
    default = ",".join(sorted(c.value for c in DEFAULT_CATEGORIES))
    body = client.get(f"/api/targets/{TARGET}/handoff/{CVE}"
                      f"?categories={default}", headers=VIEWER).json()
    opt_in = {c.value for c in OPT_IN_CATEGORIES}
    for command in body["commands"]:
        if command["composed"]:
            assert command["category"] not in opt_in, command


def test_ticking_an_opt_in_category_changes_what_is_returned(client):
    _seed(client)

    def categories(query):
        return {c["category"] for c in client.get(
            f"/api/targets/{TARGET}/handoff/{CVE}?categories={query}",
            headers=VIEWER).json()["commands"] if c["composed"]}

    default = categories("safe,discovery,version")
    widened = categories("safe,discovery,version,vuln,intrusive,unclassified")
    assert "vuln" not in default
    assert widened > default
    assert widened & {c.value for c in OPT_IN_CATEGORIES}


def test_every_opt_in_command_is_flagged_as_one(client):
    """The tickbox is one half of the control; the per-command flag the UI
    badges is the other, and they have to agree."""
    _seed(client)
    every = ",".join(c.value for c in Category)
    body = client.get(f"/api/targets/{TARGET}/handoff/{CVE}"
                      f"?categories={every}", headers=VIEWER).json()
    opt_in = {c.value for c in OPT_IN_CATEGORIES}
    for command in body["commands"]:
        assert command["requires_opt_in"] == (command["category"] in opt_in)


def test_never_composed_commands_carry_no_runnable_line(client):
    """The panel shows these as named references. The API has to make that
    distinguishable without the UI inferring it: `composed` false and `argv`
    null, whatever the tickboxes say."""
    _seed(client)
    every = ",".join(c.value for c in Category)
    body = client.get(f"/api/targets/{TARGET}/handoff/{CVE}"
                      f"?categories={every}", headers=VIEWER).json()
    for command in body["commands"]:
        if command["category"] in {c.value for c in NEVER_COMPOSED}:
            assert command["composed"] is False
            assert command["argv"] is None
            assert command["reference"]


def test_unticking_everything_does_not_fall_back_to_the_default_tier(client):
    """The API reads an empty `categories=` as "not sent" and answers with
    the default tier. The page therefore never sends an empty one: with no
    box ticked it asks for the never-composed tier, which by definition
    carries no argv. Unticking `safe` has to actually remove safe commands,
    or the tickboxes are decoration."""
    _seed(client)
    never = ",".join(c.value for c in NEVER_COMPOSED)
    body = client.get(f"/api/targets/{TARGET}/handoff/{CVE}"
                      f"?categories={never}", headers=VIEWER).json()
    assert not [c for c in body["commands"] if c["composed"]]

    # ... while an actually-empty parameter would have.
    fallback = client.get(f"/api/targets/{TARGET}/handoff/{CVE}",
                          headers=VIEWER).json()
    assert [c for c in fallback["commands"] if c["composed"]]

    page = client.get("/ui", headers=VIEWER).text
    assert "ticked.length ? ticked : NEVER_COMPOSED" in page


def test_an_unknown_category_is_refused_rather_than_ignored(client):
    _seed(client)
    assert client.get(f"/api/targets/{TARGET}/handoff/{CVE}"
                      "?categories=safe,wizard", headers=VIEWER
                      ).status_code == 400


def test_categories_do_not_widen_scope(monkeypatch):
    """The parameter selects a view, not a permission."""
    _module, c = _client(monkeypatch, SCOPED_TOKENS)
    with c:
        _seed(c, "192.0.2.7")
        assert c.get("/api/targets/192.0.2.7/handoff/" + CVE +
                     "?categories=intrusive,vuln",
                     headers=VIEWER).status_code == 403


def test_the_rendered_field_is_shell_quoted_by_the_server(client):
    """What the copy button copies. If this were assembled in the browser
    from `argv`, quoting would have moved out of the one place it happens."""
    import shlex

    _seed(client)
    body = client.get(f"/api/targets/{TARGET}/handoff/{CVE}"
                      "?categories=safe,discovery,version", headers=VIEWER
                      ).json()
    for command in body["commands"]:
        if command["composed"]:
            assert shlex.split(command["rendered"]) == command["argv"]


def test_the_kev_and_epss_columns_still_match_what_the_feeds_write():
    """`LedgerRow` has no KEV or EPSS field: `ExploitationSignals.explain`
    writes both into `rationale`, and re-shaping the ledger belongs to
    whoever owns the feeds. The UI reads them back out, which makes the
    wording in feeds.py load-bearing -- reword it and two columns go blank
    with no error anywhere. This is the alarm for that.
    """
    from reconkg import feeds

    class _Kev:
        def __contains__(self, cve): return True

        def get(self, cve):
            return type("E", (), {"date_added": "2024-01-01",
                                  "ransomware": False})()

    class _Epss:
        def probability(self, cve): return 0.124

        def percentile(self, cve): return 0.9

    kev_line = feeds.ExploitationSignals(kev=_Kev()).explain("CVE-1")
    epss_line = feeds.ExploitationSignals(epss=_Epss()).explain("CVE-1")

    assert re.search(r"(^|\|\s)KEV:", "version match | " + kev_line)
    assert re.search(r"EPSS ([0-9.]+)%", epss_line)
    # The same two patterns, spelled the same way, in the page.
    page_source = (__import__("reconkg.ui", fromlist=["PAGE"]).PAGE)
    assert r"/(^|\|\s)KEV:/" in page_source
    assert r"/EPSS ([0-9.]+)%/" in page_source


# --------------------------------------------------------------------------- #
# The static assertion on the served asset
# --------------------------------------------------------------------------- #

#: Every sink that turns a string into markup or code. The page's data comes
#: from downloaded feeds, so any one of these is a stored XSS in an analyst's
#: browser, reachable by whoever can land a record in a feed.
MARKUP_SINKS = ["innerHTML", "outerHTML", "insertAdjacentHTML",
                "document.write", "eval(", "new Function", "srcdoc"]


@pytest.mark.parametrize("sink", MARKUP_SINKS)
def test_the_served_page_never_assigns_markup(client, sink):
    """Asserted against the bytes the route serves, not the source file.

    A static assertion, deliberately: it cannot prove the DOM is safe, but it
    catches the one regression that matters -- somebody reaching for
    `innerHTML` because it was shorter -- by name, on the next test run,
    instead of at the next audit.
    """
    assert sink not in client.get("/ui", headers=VIEWER).text


def test_the_page_never_joins_argv_into_a_command_line(client):
    """RC-32 in the browser. `argv` is exposed as a list because a list is
    safe; `argv.join(" ")` re-creates the injection, since an argument
    holding a space or a quote is one argument to execve and several words to
    a shell. The page uses `rendered`, which is shlex-quoted server-side."""
    body = client.get("/ui", headers=VIEWER).text
    assert not re.search(r"argv[\w.\[\]]*\s*\.join\s*\(", body)
    for line in body.splitlines():
        if "argv" in line:
            assert ".join" not in line, line
    # And nothing in the function that renders a command joins anything at
    # all: the whole point is that the server already did the quoting.
    render = body.split("function renderCommand(")[1].split(
        "\nfunction ")[0]
    assert ".join(" not in render
    assert "command.rendered" in body


def test_the_copy_button_copies_rendered_and_only_for_composed(client):
    """A copy button promises "this is a line you can paste". The
    never-composed tier must not get one."""
    body = client.get("/ui", headers=VIEWER).text
    assert "navigator.clipboard.writeText(rendered)" in body
    # The only call site is inside the `command.composed` branch.
    assert body.count("copyButton(") == 2          # definition + one call
    assert "controls.appendChild(copyButton(command.rendered));" in body


def test_the_page_builds_its_dom_with_createelement(client):
    body = client.get("/ui", headers=VIEWER).text
    assert "document.createElement" in body
    assert "node.textContent = String(text)" in body
