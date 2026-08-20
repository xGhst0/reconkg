"""The single-page operator console, served by the existing FastAPI app.

Cycle 9, stream D. Deliberate non-goals: no build step, no CDN, no npm, no
framework. One HTML document with inline CSS and vanilla JS, held here as a
module-level string rather than a file under `reconkg/static/` because
`[tool.setuptools.packages.find]` ships packages, not package data -- a
`.html` file would be present in the checkout and absent from the wheel, and
that failure is invisible until someone installs it.

Three rules the red cell asked for by name, and where each is enforced:

1. **A command line is never assembled in the browser.** `Command.as_dict()`
   exposes `argv` as a list on purpose -- structured, it is safe. Joining it
   with spaces re-creates the injection RC-32 closed, because a feed-supplied
   argument containing a space or a quote is one argument to `execve` and
   several words to a shell. The page renders `rendered`, which is the single
   place `shlex.quote` runs (see `commands.Command.rendered`), and the copy
   button copies that same string. `argv` is displayed, when it is displayed
   at all, as one list item per element -- which is what it is.

2. **No DOM is built from markup.** CVE titles, product names, module paths
   and rationales are downloaded feed data and are attacker-influenceable by
   anyone who can land a record in a feed. Every node in this page is made
   with `document.createElement` and filled with `textContent`. The string
   `innerHTML` does not appear in this file, and `tests/test_ui.py` asserts
   that against the served bytes so a regression is caught by name rather
   than by review.

3. **`composed: false` is never rendered as something runnable.** The
   never-composed tier is shown as a named reference with its source, and
   gets no copy button, because a copy button's whole promise is "this is a
   line you can paste".

The page is served under the same `require_role(Role.VIEWER)` dependency as
every other read route (see `app.ui_page`). It carries no engagement data
itself, but an anonymous route would still be a new anonymous ingress into a
process whose stated position since RC-06 is that it has none. A browser
cannot set an Authorization header on a top-level navigation, so the operator
reaches this page through a header-injecting client or a loopback proxy; a
token in the query string is deliberately not accepted, for the reason RC-12
gives about query strings reaching access logs and browser history.
"""

from __future__ import annotations

import json

from .commands import (DEFAULT_CATEGORIES, NEVER_COMPOSED, OPT_IN_CATEGORIES,
                       Category, INTRUSIVE_WARNING)

#: Sent with the document. `script-src 'unsafe-inline'` is required because
#: the script *is* the page; everything else is closed down so a hostile
#: string that did somehow reach the DOM has nowhere to send anything.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; "
        "script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _js(value) -> str:
    """A Python value as a JS literal, safe inside a `<script>` element.

    `json.dumps` escapes quotes and backslashes but not `</script>`, which
    ends the element wherever it appears. Escaping `<` closes that, and JSON
    is a subset of JS so the literal still parses.
    """
    return json.dumps(value).replace("<", "\\u003c")


_CONSTANTS = "\n".join([
    f"const INTRUSIVE_WARNING = {_js(INTRUSIVE_WARNING)};",
    f"const DEFAULT_CATEGORIES = {_js(sorted(c.value for c in DEFAULT_CATEGORIES))};",
    f"const OPT_IN_CATEGORIES = {_js(sorted(c.value for c in OPT_IN_CATEGORIES))};",
    f"const NEVER_COMPOSED = {_js(sorted(c.value for c in NEVER_COMPOSED))};",
    f"const ALL_CATEGORIES = {_js([c.value for c in Category])};",
])


_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>reconkg console</title>
<style>
  :root {
    --bg: #12141a; --panel: #191c24; --line: #2b303d; --ink: #dde2ec;
    --dim: #8b93a5; --accent: #6fb3ff; --warn: #ffb454; --bad: #ff6b6b;
    --ok: #7ddc8f;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--ink);
    font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  header {
    padding: 10px 16px; border-bottom: 1px solid var(--line);
    display: flex; gap: 12px; align-items: center; flex-wrap: wrap;
  }
  h1 { font-size: 15px; margin: 0 12px 0 0; letter-spacing: .06em; }
  h2 {
    font-size: 12px; margin: 0 0 8px; text-transform: uppercase;
    letter-spacing: .12em; color: var(--dim);
  }
  h3 { font-size: 13px; margin: 14px 0 6px; }
  main {
    display: grid;
    grid-template-columns: minmax(320px, 1fr) minmax(420px, 1.4fr);
    gap: 12px; padding: 12px; align-items: start;
  }
  .wide { grid-column: 1 / -1; }
  section {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 6px; padding: 12px;
  }
  input, button, select {
    font: inherit; background: #0e1015; color: var(--ink);
    border: 1px solid var(--line); border-radius: 4px; padding: 5px 8px;
  }
  button { cursor: pointer; }
  button:hover { border-color: var(--accent); }
  button:disabled { opacity: .45; cursor: default; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .dim { color: var(--dim); }
  .mono-pre { white-space: pre-wrap; word-break: break-word; margin: 0; font: inherit; }
  .badge {
    display: inline-block; padding: 0 6px; border-radius: 3px;
    border: 1px solid var(--line); font-size: 11px; margin-left: 6px;
    color: var(--dim);
  }
  .badge.kev { color: #12141a; background: var(--bad); border-color: var(--bad); }
  .badge.optin { color: #12141a; background: var(--warn); border-color: var(--warn); }
  .badge.named { color: #12141a; background: var(--accent); border-color: var(--accent); }
  .badge.backport { color: var(--warn); border-color: var(--warn); }
  .warning {
    border: 1px solid var(--warn); border-left: 5px solid var(--warn);
    background: rgba(255, 180, 84, .10); color: var(--warn);
    padding: 10px 12px; border-radius: 4px; margin: 10px 0;
  }
  .warning strong { display: block; margin-bottom: 4px; letter-spacing: .08em; }
  .badge.fixture { border-color: var(--warn); color: var(--warn); }
  .badge.stale { border-color: var(--bad); color: var(--bad); }
  /* Not an error and not fine: the corpus was never configured, so its
     silence is not evidence. Warn-coloured for the same reason `fixture`
     is. */
  .badge.absent { border-color: var(--warn); color: var(--warn); }
  .corpus-item { margin: 0 0 10px 0; }
  .corpus-item h3 { margin: 0 0 4px 0; font-size: 13px; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td {
    border-bottom: 1px solid var(--line); padding: 5px 6px;
    text-align: left; vertical-align: top;
  }
  th { cursor: pointer; color: var(--dim); font-weight: normal; white-space: nowrap; }
  th:hover { color: var(--accent); }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: #21252f; }
  tbody tr.selected { background: #232b3a; outline: 1px solid var(--accent); }
  ul.tree, ul.tree ul { list-style: none; margin: 0; padding-left: 16px; }
  ul.tree { padding-left: 0; }
  .node {
    cursor: pointer; padding: 1px 4px; border-radius: 3px;
    border: 1px solid transparent; display: inline-block;
  }
  .node:hover { border-color: var(--line); }
  .node.selected { border-color: var(--accent); background: #232b3a; }
  .kind { color: var(--dim); }
  .cmd {
    border: 1px solid var(--line); border-radius: 4px; padding: 8px;
    margin: 8px 0; background: #0e1015;
  }
  .cmd.named { border-left: 4px solid var(--accent); }
  .cmd.optin { border-left: 4px solid var(--warn); }
  code {
    font: inherit; white-space: pre-wrap; word-break: break-all;
    display: block; margin: 6px 0; color: var(--ok);
  }
  .log {
    height: 190px; overflow-y: auto; background: #0e1015; padding: 8px;
    border: 1px solid var(--line); border-radius: 4px; font-size: 12px;
  }
  .log div { border-bottom: 1px solid #181b22; padding: 1px 0; }
  .err { color: var(--bad); }
  .ok { color: var(--ok); }
  ul.plain { list-style: none; margin: 6px 0; padding: 0; }
  ul.plain li { padding: 2px 0; }
  ul.argv { margin: 4px 0 0 18px; padding: 0; color: var(--dim); font-size: 12px; }
  label.tick { margin-right: 12px; white-space: nowrap; }
</style>
</head>
<body>

<header>
  <h1>reconkg</h1>
  <label>token <input id="token" type="password" size="26"
         placeholder="bearer credential" autocomplete="off"></label>
  <button id="save-token">use</button>
  <span id="who" class="dim">not authenticated</span>
</header>

<main>

  <!-- 1. target input, scan trigger, live progress -->
  <section id="panel-scan">
    <h2>Target</h2>
    <div class="row">
      <input id="target" size="22" placeholder="10.10.10.42" autocomplete="off">
      <button id="add">add target</button>
      <button id="scan">scan</button>
      <button id="refresh">refresh</button>
    </div>
    <p class="dim" id="scan-status">idle</p>
    <h3>Live events <span class="dim" id="ws-state">(ws: closed)</span></h3>
    <div class="log" id="events"></div>
  </section>

  <!-- 6. corpus status, verbatim from each resolver's describe() -->
  <section id="panel-corpus">
    <h2>Corpora</h2>
    <div id="corpus-list"></div>
    <p class="dim" id="corpus-error"></p>
    <p class="dim">
      "no leads" is ambiguous, and so is "no known exploit". These lines are
      what tell you whether the host is clean, whether the corpus is nine
      hand-written entries, and whether the question was asked at all: an
      index that is <em>not configured</em> reports nothing found for every
      lead, which reads exactly like nothing existing.
    </p>
  </section>

  <!-- 2. knowledge graph -->
  <section id="panel-graph">
    <h2>Knowledge graph</h2>
    <ul class="tree" id="graph"></ul>
  </section>

  <section id="panel-prov">
    <h2>Provenance</h2>
    <p class="dim">Click any node. Every claim in the graph names the tool that
      made it, the authenticated principal that submitted it, the confidence it
      was recorded at, and when.</p>
    <div id="provenance"></div>
  </section>

  <!-- 3. ledger -->
  <section class="wide" id="panel-ledger">
    <h2>Ledger</h2>
    <p class="dim" id="ledger-note">no scan report yet</p>
    <table id="ledger">
      <thead><tr id="ledger-head"></tr></thead>
      <tbody id="ledger-body"></tbody>
    </table>
  </section>

  <!-- 4 + 5. commands and category tickboxes -->
  <section class="wide" id="panel-commands">
    <h2>Commands for the selected lead</h2>
    <div class="row" id="categories"></div>
    <div id="optin-warning"></div>
    <div id="commands"><p class="dim">Select a lead in the ledger.</p></div>
  </section>

</main>

<script>
"use strict";

__CONSTANTS__

// ---------------------------------------------------------------------- //
// DOM helpers. Everything below builds nodes; nothing parses markup.
// Feed-derived strings (CVE titles, product names, rationales, module
// paths) reach the page only through textContent.
// ---------------------------------------------------------------------- //

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) { node.className = cls; }
  if (text !== undefined && text !== null) { node.textContent = String(text); }
  return node;
}

function clear(node) {
  while (node.firstChild) { node.removeChild(node.firstChild); }
  return node;
}

function $(id) { return document.getElementById(id); }

const state = {
  token: sessionStorage.getItem("reconkg-token") || "",
  target: "",
  host: null,
  ledger: [],
  sortKey: "priority",
  sortDir: -1,
  selectedCve: null,
  ws: null
};

// ---------------------------------------------------------------------- //
// API. One place sets the Authorization header.
// ---------------------------------------------------------------------- //

async function api(path, options) {
  const opts = Object.assign({headers: {}}, options || {});
  opts.headers = Object.assign({}, opts.headers,
                               {"Authorization": "Bearer " + state.token});
  const response = await fetch(path, opts);
  const body = await response.json().catch(function () { return null; });
  if (!response.ok) {
    const detail = (body && body.detail) ? body.detail : response.statusText;
    throw new Error(response.status + " " + detail);
  }
  return body;
}

function note(message, cls) {
  const status = clear($("scan-status"));
  status.appendChild(el("span", cls || "dim", message));
}

function logEvent(text, cls) {
  const box = $("events");
  box.appendChild(el("div", cls || null, text));
  while (box.childElementCount > 400) { box.removeChild(box.firstChild); }
  box.scrollTop = box.scrollHeight;
}

// ---------------------------------------------------------------------- //
// 1. Target, scan, and live progress.
//
// The WebSocket is the one the app already publishes on: a single-use
// ticket from /api/ws-ticket, redeemed at /ws. There is no second channel
// and no polling loop behind it.
// ---------------------------------------------------------------------- //

async function openSocket() {
  if (state.ws) { state.ws.close(); state.ws = null; }
  if (!state.token) { return; }
  let ticket;
  try {
    ticket = (await api("/api/ws-ticket", {method: "POST"})).ticket;
  } catch (err) {
    $("ws-state").textContent = "(ws: " + err.message + ")";
    return;
  }
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  let url = scheme + "//" + window.location.host +
            "/ws?ticket=" + encodeURIComponent(ticket);
  if (state.target) { url += "&target=" + encodeURIComponent(state.target); }
  const socket = new WebSocket(url);
  state.ws = socket;
  $("ws-state").textContent = "(ws: connecting)";
  socket.onopen = function () { $("ws-state").textContent = "(ws: open)"; };
  socket.onclose = function () { $("ws-state").textContent = "(ws: closed)"; };
  socket.onerror = function () { $("ws-state").textContent = "(ws: error)"; };
  socket.onmessage = function (message) {
    let event;
    try { event = JSON.parse(message.data); } catch (err) { return; }
    if (event.type === "hello") {
      logEvent("connected as " + event.client_id, "ok");
      return;
    }
    const parts = [event.kind, event.target || "-", event.path || ""];
    if (event.replay) { parts.push("(replay)"); }
    if (event._dropped_before) {
      parts.push("[" + event._dropped_before + " events dropped]");
    }
    logEvent(parts.join("  "));
    if (event.target === state.target && !event.replay) { scheduleRefresh(); }
  };
}

let refreshTimer = null;
function scheduleRefresh() {
  if (refreshTimer) { return; }
  refreshTimer = window.setTimeout(function () {
    refreshTimer = null;
    loadGraph();
  }, 400);
}

async function addTarget() {
  try {
    await api("/api/targets", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({address: $("target").value.trim()})
    });
    note("target added", "ok");
    await selectTarget();
  } catch (err) { note(err.message, "err"); }
}

async function runScan() {
  if (!state.target) { note("set a target first", "err"); return; }
  $("scan").disabled = true;
  note("scanning " + state.target + " ...");
  try {
    const report = await api("/api/targets/" +
                             encodeURIComponent(state.target) + "/scan",
                             {method: "POST"});
    const leads = (report && report.ledger) ? report.ledger.length : 0;
    note("scan complete: " + leads + " lead(s)", "ok");
    await loadGraph();
    await loadLedger();
  } catch (err) {
    note(err.message, "err");
  } finally {
    $("scan").disabled = false;
  }
}

async function selectTarget() {
  state.target = $("target").value.trim();
  state.selectedCve = null;
  await openSocket();
  await loadGraph();
  await loadLedger();
  renderCommands(null);
}

// ---------------------------------------------------------------------- //
// 2. Knowledge graph: host -> port -> service -> fingerprint -> lead.
// ---------------------------------------------------------------------- //

async function loadGraph() {
  const tree = clear($("graph"));
  if (!state.target) {
    tree.appendChild(el("li", "dim", "no target selected"));
    return;
  }
  try {
    state.host = await api("/api/targets/" + encodeURIComponent(state.target));
  } catch (err) {
    tree.appendChild(el("li", "err", err.message));
    return;
  }
  renderGraph(state.host);
}

function nodeLine(kind, label, model, extra) {
  const line = el("span", "node");
  line.appendChild(el("span", "kind", kind + " "));
  line.appendChild(document.createTextNode(label));
  if (extra) { line.appendChild(el("span", "badge", extra)); }
  if (model && model.provenance) {
    line.appendChild(el("span", "badge",
      "conf " + Number(model.provenance.confidence).toFixed(2)));
    line.addEventListener("click", function (event) {
      event.stopPropagation();
      const previous = document.querySelector(".node.selected");
      if (previous) { previous.classList.remove("selected"); }
      line.classList.add("selected");
      renderProvenance(kind + " " + label, model);
    });
  }
  return line;
}

function renderGraph(host) {
  const tree = clear($("graph"));
  const hostItem = el("li");
  hostItem.appendChild(nodeLine("host", host.address, host,
                                host.os_guess || null));
  const ports = el("ul");
  (host.ports || []).forEach(function (port) {
    const portItem = el("li");
    portItem.appendChild(nodeLine("port", port.number + "/" + port.protocol,
                                  port, port.state));
    const service = port.service;
    if (service) {
      const serviceList = el("ul");
      const serviceItem = el("li");
      serviceItem.appendChild(nodeLine(
        "service",
        service.name + (service.tunnel ? " (" + service.tunnel + ")" : ""),
        service));
      const inner = el("ul");
      (service.fingerprints || []).forEach(function (fp) {
        const item = el("li");
        item.appendChild(nodeLine(
          "fingerprint", (fp.product || "?") + " " + (fp.version || "?"),
          fp, fp.ambiguous ? "ambiguous" : null));
        const leads = (service.leads || []).filter(function (lead) {
          return lead.matched_fingerprint_id === fp.id;
        });
        if (leads.length) {
          const leadList = el("ul");
          leads.forEach(function (lead) {
            const leadItem = el("li");
            leadItem.appendChild(nodeLine(
              "lead", lead.cve_id + " " + lead.title, lead,
              "cvss " + lead.cvss));
            const inspect = el("button", null, "commands");
            inspect.addEventListener("click", function () {
              selectLead(lead.cve_id);
            });
            leadItem.appendChild(document.createTextNode(" "));
            leadItem.appendChild(inspect);
            leadList.appendChild(leadItem);
          });
          item.appendChild(leadList);
        }
        inner.appendChild(item);
      });
      serviceItem.appendChild(inner);
      serviceList.appendChild(serviceItem);
      portItem.appendChild(serviceList);
    }
    ports.appendChild(portItem);
  });
  hostItem.appendChild(ports);
  tree.appendChild(hostItem);
}

function renderProvenance(label, model) {
  const box = clear($("provenance"));
  box.appendChild(el("h3", null, label));

  const current = model.provenance;
  const summary = el("ul", "plain");
  summary.appendChild(el("li", null, "source tool: " + current.source_tool));
  summary.appendChild(el("li", null, "principal: " + current.principal));
  summary.appendChild(el("li", null,
    "confidence: " + Number(current.confidence).toFixed(4)));
  if (current.declared_confidence !== null &&
      current.declared_confidence !== undefined) {
    summary.appendChild(el("li", "dim",
      "declared by submitter: " +
      Number(current.declared_confidence).toFixed(4) +
      " (clamped to the registry ceiling for that tool)"));
  }
  summary.appendChild(el("li", null, "observed at: " + current.observed_at));
  if (current.note) {
    summary.appendChild(el("li", null, "note: " + current.note));
  }
  box.appendChild(summary);

  if (model.rationale) {
    box.appendChild(el("h3", null, "Why this was asserted"));
    box.appendChild(el("pre", "mono-pre", model.rationale));
  }

  box.appendChild(el("h3", null, "Observation log"));
  const log = el("ul", "plain");
  (model.provenance_log || []).forEach(function (entry) {
    log.appendChild(el("li", null,
      entry.observed_at + "  " + entry.source_tool + "  by " +
      entry.principal + "  conf " + Number(entry.confidence).toFixed(4) +
      (entry.note ? "  -- " + entry.note : "")));
  });
  box.appendChild(log);
  if (model.elided_observations) {
    box.appendChild(el("p", "dim", model.elided_observations +
      " older observation(s) elided by the retention cap"));
  }
}

// ---------------------------------------------------------------------- //
// 3. Ledger.
//
// KEV membership and the EPSS probability are not fields on LedgerRow:
// feeds.ExploitationSignals.explain() writes them into `rationale`, and
// changing the ledger schema belongs to whoever owns the feeds, not to the
// UI. They are read back out here so the columns can be sorted on. The
// rationale itself is still shown verbatim on the lead.
// ---------------------------------------------------------------------- //

function kevOf(row) { return /(^|\|\s)KEV:/.test(row.rationale || ""); }

function epssOf(row) {
  const match = /EPSS ([0-9.]+)%/.exec(row.rationale || "");
  return match ? parseFloat(match[1]) : null;
}

const LEDGER_COLUMNS = [
  {key: "cve_id", label: "CVE",
   get: function (r) { return r.cve_id; }},
  {key: "title", label: "Title",
   get: function (r) { return r.title; }},
  {key: "cvss", label: "CVSS",
   get: function (r) { return r.cvss; }},
  {key: "kev", label: "KEV",
   get: function (r) { return kevOf(r) ? 1 : 0; }},
  {key: "epss", label: "EPSS",
   get: function (r) { const v = epssOf(r); return v === null ? -1 : v; }},
  {key: "priority", label: "Priority",
   get: function (r) { return r.priority; }},
  {key: "match_method", label: "Match method",
   get: function (r) { return r.match_method; }},
  {key: "backport", label: "Backport warning",
   get: function (r) { return r.backport_marker || ""; }},
  {key: "maturity", label: "Maturity",
   get: function (r) { return r.maturity; }},
  {key: "fingerprint_confidence", label: "FP conf",
   get: function (r) { return r.fingerprint_confidence; }}
];

async function loadLedger() {
  state.ledger = [];
  if (!state.target) { renderLedger(); return; }
  try {
    state.ledger = await api("/api/targets/" +
                             encodeURIComponent(state.target) + "/ledger");
    $("ledger-note").textContent = state.ledger.length + " lead(s)";
  } catch (err) {
    $("ledger-note").textContent = err.message;
  }
  renderLedger();
}

function renderLedger() {
  const head = clear($("ledger-head"));
  LEDGER_COLUMNS.forEach(function (column) {
    const marker = state.sortKey === column.key
                   ? (state.sortDir < 0 ? "  v" : "  ^") : "";
    const cell = el("th", null, column.label + marker);
    cell.addEventListener("click", function () {
      state.sortDir = (state.sortKey === column.key) ? -state.sortDir : -1;
      state.sortKey = column.key;
      renderLedger();
    });
    head.appendChild(cell);
  });

  const column = LEDGER_COLUMNS.filter(function (c) {
    return c.key === state.sortKey;
  })[0] || LEDGER_COLUMNS[0];

  const rows = state.ledger.slice().sort(function (a, b) {
    const left = column.get(a), right = column.get(b);
    if (left === right) { return 0; }
    return (left > right ? 1 : -1) * state.sortDir;
  });

  const body = clear($("ledger-body"));
  rows.forEach(function (row) {
    const tr = el("tr", row.cve_id === state.selectedCve ? "selected" : null);
    tr.addEventListener("click", function () { selectLead(row.cve_id); });

    tr.appendChild(el("td", null, row.cve_id));

    const title = el("td", null, row.title);
    if (row.disputed) { title.appendChild(el("span", "badge", "DISPUTED")); }
    tr.appendChild(title);

    tr.appendChild(el("td", null, row.cvss));

    const kev = el("td");
    kev.appendChild(kevOf(row) ? el("span", "badge kev", "KEV")
                               : el("span", "dim", "-"));
    tr.appendChild(kev);

    const epss = epssOf(row);
    tr.appendChild(el("td", epss === null ? "dim" : null,
                      epss === null ? "-" : epss + "%"));

    tr.appendChild(el("td", null, Number(row.priority).toFixed(4)));
    tr.appendChild(el("td", null, row.match_method));

    // A column, not a footnote. A version match on a distribution build is
    // not a patch-level match, and burying that in prose is how an analyst
    // spends an afternoon on an already-patched package.
    const backport = el("td");
    if (row.backport_marker) {
      backport.appendChild(el("span", "badge backport", row.backport_marker));
      backport.appendChild(el("div", "dim",
        "distribution build -- the fix may be applied without a version bump"));
    } else {
      backport.appendChild(el("span", "dim", "-"));
    }
    tr.appendChild(backport);

    tr.appendChild(el("td", null,
      row.maturity + " (" + row.maturity_source + ")"));
    tr.appendChild(el("td", null,
      Number(row.fingerprint_confidence).toFixed(2)));
    body.appendChild(tr);
  });
}

// ---------------------------------------------------------------------- //
// 5. Category tickboxes.
// ---------------------------------------------------------------------- //

function selectedCategories() {
  return ALL_CATEGORIES.filter(function (name) {
    const box = $("cat-" + name);
    return box && box.checked;
  });
}

function optedInCategories() {
  return selectedCategories().filter(function (name) {
    return OPT_IN_CATEGORIES.indexOf(name) !== -1;
  });
}

function renderCategories() {
  const box = clear($("categories"));
  box.appendChild(el("span", "dim", "categories:"));
  ALL_CATEGORIES.forEach(function (name) {
    // The never-composed tier is not a tickbox: those commands are always
    // shown, as named references, and no selection makes them runnable.
    if (NEVER_COMPOSED.indexOf(name) !== -1) { return; }
    const label = el("label", "tick");
    const tick = el("input");
    tick.type = "checkbox";
    tick.id = "cat-" + name;
    tick.checked = DEFAULT_CATEGORIES.indexOf(name) !== -1;
    tick.addEventListener("change", function () {
      renderOptInWarning();
      if (state.selectedCve) { selectLead(state.selectedCve); }
    });
    label.appendChild(tick);
    label.appendChild(document.createTextNode(" " + name));
    if (OPT_IN_CATEGORIES.indexOf(name) !== -1) {
      label.appendChild(el("span", "badge optin", "opt-in"));
    }
    box.appendChild(label);
  });
  renderOptInWarning();
}

// The authorisation warning, rendered above the command list. Called on the
// tick itself and again before commands are appended, so the warning is in
// the document before any opt-in command is -- not underneath it.
// The text is commands.INTRUSIVE_WARNING; the UI does not paraphrase a
// security notice.
function renderOptInWarning() {
  const box = clear($("optin-warning"));
  const opted = optedInCategories();
  if (!opted.length) { return false; }
  const warning = el("div", "warning");
  warning.appendChild(el("strong", null,
    "OPT-IN CATEGORIES ENABLED: " + opted.join(", ")));
  warning.appendChild(el("div", null, INTRUSIVE_WARNING));
  box.appendChild(warning);
  return true;
}

// ---------------------------------------------------------------------- //
// 4. Command panel for one lead.
// ---------------------------------------------------------------------- //

async function selectLead(cveId) {
  state.selectedCve = cveId;
  renderLedger();
  renderOptInWarning();
  // An empty `categories=` is read by the API as "the parameter was not
  // sent", which answers with the default tier -- so unticking every box
  // would still show safe commands, and the tickboxes would be lying. The
  // never-composed tier says the same thing without that ambiguity: those
  // categories carry no argv by definition, so nothing composed passes the
  // filter, and the named references still come back. An analyst who has
  // ticked nothing should still be told a working exploit exists.
  const ticked = selectedCategories();
  const categories = ticked.length ? ticked : NEVER_COMPOSED;
  clear($("commands")).appendChild(el("p", "dim", "loading " + cveId + " ..."));
  try {
    const handoff = await api(
      "/api/targets/" + encodeURIComponent(state.target) +
      "/handoff/" + encodeURIComponent(cveId) +
      "?categories=" + encodeURIComponent(categories.join(",")));
    renderCommands(handoff);
  } catch (err) {
    clear($("commands")).appendChild(el("p", "err", err.message));
  }
}

function copyButton(rendered) {
  const button = el("button", null, "copy");
  button.addEventListener("click", function () {
    // `rendered` is Command.rendered: shlex-quoted server-side, the single
    // place quoting happens. Never a join of argv.
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(rendered).then(
        function () { button.textContent = "copied"; },
        function () { button.textContent = "copy failed"; });
    } else {
      button.textContent = "no clipboard";
    }
  });
  return button;
}

function renderCommand(command) {
  const optIn = command.requires_opt_in;
  const flavour = command.composed ? (optIn ? "optin" : "") : "named";
  const block = el("div", ("cmd " + flavour).trim());

  const header = el("div", "row");
  header.appendChild(el("strong", null, command.tool));
  header.appendChild(el("span", "badge", command.category));
  if (optIn) { header.appendChild(el("span", "badge optin", "opt-in")); }
  if (!command.composed) {
    header.appendChild(el("span", "badge named", "named, not composed"));
  }
  if (command.source) {
    header.appendChild(el("span", "badge", command.source));
  }
  block.appendChild(header);

  if (command.composed) {
    // `rendered` only. Joining argv on spaces is the injection RC-32
    // closed: an argument holding a space or a quote is one argument to the
    // process and several words to a shell. argv is shown as a list, which
    // is what it is.
    block.appendChild(el("code", null, command.rendered));
    const controls = el("div", "row");
    controls.appendChild(copyButton(command.rendered));
    const argvList = el("ul", "argv");
    argvList.hidden = true;
    (command.argv || []).forEach(function (part) {
      argvList.appendChild(el("li", null, part));
    });
    const toggle = el("button", null, "argv");
    toggle.addEventListener("click", function () {
      argvList.hidden = !argvList.hidden;
    });
    controls.appendChild(toggle);
    block.appendChild(controls);
    block.appendChild(argvList);
  } else {
    // No copy button and no shell text: this tier is named, never aimed.
    const reference = el("div");
    reference.appendChild(el("span", "dim", "reference: "));
    reference.appendChild(document.createTextNode(command.reference));
    block.appendChild(reference);
    block.appendChild(el("p", "dim",
      "Category " + command.category + " is never composed into a runnable " +
      "invocation. reconkg names it so you can judge how urgent this lead " +
      "is; look it up in your own tooling."));
  }

  if (command.rationale) {
    block.appendChild(el("p", "dim", command.rationale));
  }
  return block;
}

function renderCommands(handoff) {
  const box = clear($("commands"));
  if (!handoff) {
    box.appendChild(el("p", "dim", "Select a lead in the ledger."));
    return;
  }
  const lead = handoff.lead;
  box.appendChild(el("h3", null,
    lead.cve_id + "  " + lead.title + "  on " + lead.target + ":" +
    lead.port + "/" + lead.protocol));

  if (handoff.caveats && handoff.caveats.length) {
    box.appendChild(el("h3", null, "Before you spend time on this"));
    const list = el("ul", "plain");
    handoff.caveats.forEach(function (caveat) {
      list.appendChild(el("li", "dim", "- " + caveat));
    });
    box.appendChild(list);
  }

  const commands = handoff.commands || [];
  const composed = commands.filter(function (c) { return c.composed; });
  const named = commands.filter(function (c) { return !c.composed; });

  // Warning first, command nodes second.
  if (composed.some(function (c) { return c.requires_opt_in; })) {
    renderOptInWarning();
  }

  if (composed.length) {
    box.appendChild(el("h3", null,
      "Commands, by what they do to the target"));
    composed.forEach(function (command) {
      box.appendChild(renderCommand(command));
    });
  }
  if (named.length) {
    box.appendChild(el("h3", null,
      "Known tooling for this CVE (named, not composed)"));
    named.forEach(function (command) {
      box.appendChild(renderCommand(command));
    });
  }
  if (!commands.length) {
    box.appendChild(el("p", "dim", "No commands for the ticked categories."));
  }

  if (handoff.lookups && handoff.lookups.length) {
    box.appendChild(el("h3", null, "Verification lookups"));
    const list = el("ul", "plain");
    handoff.lookups.forEach(function (line) {
      list.appendChild(el("li", null, line));
    });
    box.appendChild(list);
  }
  if (handoff.operator_supplied && handoff.operator_supplied.length) {
    box.appendChild(el("h3", null, "Operator-supplied follow-up"));
    const list = el("ul", "plain");
    handoff.operator_supplied.forEach(function (line) {
      list.appendChild(el("li", null, line));
    });
    box.appendChild(list);
  }
  if (handoff.references && handoff.references.length) {
    box.appendChild(el("h3", null, "References"));
    const list = el("ul", "plain");
    handoff.references.forEach(function (url) {
      list.appendChild(el("li", "dim", url));
    });
    box.appendChild(list);
  }
  box.appendChild(el("p", "dim",
    "reconkg does not run any of these. Confirm the target is in scope and " +
    "that you are authorised before you do."));
}

// ---------------------------------------------------------------------- //
// 6. Corpus status: all three resolvers, each verbatim from describe().
// ---------------------------------------------------------------------- //

function corpusItem(entry) {
  const box = el("div", "corpus-item");
  box.appendChild(el("h3", null, entry.label || entry.corpus));
  const flags = el("div", "row");
  flags.appendChild(el("span", "badge", entry.resolver));
  if (!entry.configured) {
    // The whole point of the panel. A corpus nobody configured answers
    // "nothing found" to every question, and that is not the same fact as
    // "nothing exists".
    flags.appendChild(el("span", "badge absent", "not configured"));
  }
  if (entry.not_checked) {
    flags.appendChild(el("span", "badge absent", "not checked"));
  }
  if (entry.demonstration_fixture) {
    flags.appendChild(el("span", "badge fixture",
      "demonstration fixture -- not a vulnerability database"));
  }
  if (entry.stale) { flags.appendChild(el("span", "badge stale", "STALE")); }
  box.appendChild(flags);
  // describe() verbatim. The server wrote these sentences; the page does not
  // summarise, colour-code away or re-word them.
  box.appendChild(el("pre", "mono-pre", entry.describe));
  return box;
}

async function loadCorpus() {
  const list = clear($("corpus-list"));
  $("corpus-error").textContent = "";
  try {
    const corpus = await api("/api/corpus");
    const entries = corpus.corpora || [];
    entries.forEach(function (entry) { list.appendChild(corpusItem(entry)); });
  } catch (err) {
    $("corpus-error").textContent = err.message;
  }
}

// ---------------------------------------------------------------------- //
// Wiring
// ---------------------------------------------------------------------- //

async function useToken() {
  state.token = $("token").value.trim();
  sessionStorage.setItem("reconkg-token", state.token);
  try {
    const health = await api("/api/health");
    $("who").textContent = health.principal + " (" + health.role +
                           (health.scoped ? ", scoped" : "") + ")";
    $("who").className = "ok";
  } catch (err) {
    $("who").textContent = err.message;
    $("who").className = "err";
    return;
  }
  await loadCorpus();
  await openSocket();
}

$("save-token").addEventListener("click", useToken);
$("add").addEventListener("click", addTarget);
$("scan").addEventListener("click", runScan);
$("refresh").addEventListener("click", selectTarget);
$("target").addEventListener("change", selectTarget);

renderCategories();
renderCommands(null);
$("token").value = state.token;
if (state.token) { useToken(); }
</script>
</body>
</html>
"""

#: The served document. Built once at import; the route returns it unchanged.
PAGE = _TEMPLATE.replace("__CONSTANTS__", _CONSTANTS)

# Belt and braces for rule 2 in the module docstring. `tests/test_ui.py`
# asserts the same thing against the bytes the route actually serves; doing it
# here as well means a stray `innerHTML` in an edit fails at import, before a
# test run, and names the reason.
for _forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                   "document.write", "eval(", "new Function"):
    if _forbidden in PAGE:                              # pragma: no cover
        raise AssertionError(
            f"reconkg/ui.py contains {_forbidden!r}. This page renders "
            "attacker-influenceable feed data -- CVE titles, product names, "
            "module paths, rationales. Every node is built with "
            "createElement and filled with textContent.")
del _forbidden
