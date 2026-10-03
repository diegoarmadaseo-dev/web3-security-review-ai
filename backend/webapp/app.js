/* Vericexa web app (docs/decisiones.md D-110).
 *
 * A thin client over the backend's JSON API (same origin, HttpOnly session
 * cookie). The backend is the authority for everything: admission, LOC,
 * quotas, plan limits, billing state. This file never counts LOC, never
 * decides whether a scan is allowed and never computes a quota - it shows
 * what the backend returns.
 *
 * XSS rule: every piece of data reaches the page through textContent or a
 * fixed attribute name via el(); no HTML-string sink and no dynamic code
 * evaluation is used anywhere (tests/test_backend_webapp.py checks).
 */
(function () {
  "use strict";
  var C = window.VXCore;
  var state = { user: null, workspaces: [], wsId: null, ws: null, catalog: null, timer: null, route: 0 };
  var view = document.getElementById("view");

  // ------------------------------------------------------------------ DOM
  function el(tag, attrs) {
    var node = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v === null || v === undefined || v === false) { return; }
      if (k === "text") { node.textContent = String(v); }
      else if (k === "onclick" || k === "onchange" || k === "onsubmit" || k === "oninput") { node.addEventListener(k.slice(2), v); }
      else if (k === "href") { node.setAttribute("href", safeHref(v)); }
      else if (k === "className") { node.className = v; }
      else { node.setAttribute(k, v === true ? "" : String(v)); }
    });
    for (var i = 2; i < arguments.length; i++) { append(node, arguments[i]); }
    return node;
  }
  function append(node, child) {
    if (child === null || child === undefined || child === false) { return; }
    if (Array.isArray(child)) { child.forEach(function (c) { append(node, c); }); return; }
    node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  // Only in-app hash routes and this backend's own paths are ever linked.
  function safeHref(v) {
    var s = String(v);
    return /^#\//.test(s) || /^\/(workspaces|app)\//.test(s) ? s : "#/dashboard";
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function render() { clear(view); for (var i = 0; i < arguments.length; i++) { append(view, arguments[i]); } view.focus(); }
  function kv(pairs) {
    var dl = el("dl", { className: "kv" });
    pairs.forEach(function (p) { if (p) { dl.appendChild(el("dt", { text: p[0] })); dl.appendChild(el("dd", null, p[1])); } });
    return dl;
  }
  function errorBox(err) {
    var d = C.describeError(err.status, err.body);
    return el("div", { className: "alert error", role: "alert" }, el("strong", { text: d.message }),
      d.details.length ? el("ul", null, d.details.map(function (x) { return el("li", { text: x }); })) : null);
  }
  function badge(status) { return el("span", { className: "badge " + status, text: C.jobStatusLabel(status) }); }

  // ------------------------------------------------------------------ API
  function api(method, path, body) {
    var opts = { method: method, credentials: "same-origin", headers: { "Accept": "application/json" } };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    return fetch(path, opts).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (res.status === 401) { window.location.assign("/auth/login"); }
        if (!res.ok) { var err = new Error("HTTP " + res.status); err.status = res.status; err.body = data; throw err; }
        return data;
      });
    });
  }
  function wsPath(suffix) { return "/workspaces/" + encodeURIComponent(state.wsId) + (suffix || ""); }
  function loadWs() { return api("GET", wsPath("")).then(function (d) { state.ws = d; return d; }); }
  function catalog() {
    if (state.catalog) { return Promise.resolve(state.catalog); }
    return api("GET", "/billing/plans").then(function (d) { state.catalog = d.plans || []; return state.catalog; });
  }
  function catalogEntry(plan) { return (state.catalog || []).filter(function (p) { return p.plan === plan; })[0] || null; }
  function canManage() { return state.ws && ["owner", "admin"].indexOf(state.ws.workspace.membership_role) >= 0; }

  // ------------------------------------------------------------------ boot
  function boot() {
    document.getElementById("disclaimer").textContent = C.DISCLAIMER;
    document.getElementById("sign-out").addEventListener("click", function () {
      api("POST", "/auth/logout", {}).catch(function () {}).then(function () { window.location.assign("/auth/login"); });
    });
    document.getElementById("ws-select").addEventListener("change", function (ev) {
      if (ev.target.value === "__new") { window.location.hash = "#/workspaces/new"; return; }
      selectWorkspace(ev.target.value);
      window.location.hash = "#/dashboard";
      route();
    });
    Promise.all([api("GET", "/auth/me"), api("GET", "/workspaces"), catalog().catch(function () { return []; })]).then(function (r) {
      state.user = r[0].user;
      document.getElementById("user-email").textContent = state.user.email || "";
      state.workspaces = r[1].workspaces || [];
      var saved = null;
      try { saved = window.localStorage.getItem("vx.workspace"); } catch (e) { saved = null; }
      var known = state.workspaces.filter(function (w) { return w.id === saved; })[0];
      selectWorkspace(known ? known.id : (state.workspaces[0] ? state.workspaces[0].id : null));
      window.addEventListener("hashchange", route);
      route();
    }).catch(function (err) { render(el("h1", { text: "Vericexa" }), errorBox(err)); });
  }
  function selectWorkspace(id) {
    state.wsId = id; state.ws = null;
    try { if (id) { window.localStorage.setItem("vx.workspace", id); } } catch (e) { /* per-browser convenience only */ }
    var sel = document.getElementById("ws-select");
    clear(sel);
    state.workspaces.forEach(function (w) { sel.appendChild(el("option", { value: w.id, text: w.name, selected: w.id === id })); });
    sel.appendChild(el("option", { value: "__new", text: "+ New workspace" }));
  }

  // ------------------------------------------------------------------ router
  function route() {
    if (state.timer) { clearTimeout(state.timer); state.timer = null; }
    state.route += 1;
    var r = C.parseHash(window.location.hash);
    var p = r.parts;
    Array.prototype.forEach.call(document.querySelectorAll("[data-nav]"), function (a) {
      a.className = a.getAttribute("data-nav") === (p[0] === "scan" ? "scan" : p[0] === "reports" ? "scans" : p[0] || "dashboard") ? "active" : "";
    });
    if (p[0] === "workspaces" && p[1] === "new") { return newWorkspaceView(); }
    if (!state.wsId) { return newWorkspaceView(); }
    var views = {
      dashboard: dashboardView, projects: function () { return p[1] ? projectView(p[1]) : projectsView(); },
      scan: function () { return newScanView(r.query); }, scans: function () { return p[1] ? jobView(p[1]) : scansView(r.query); },
      reports: function () { return reportView(p[1]); }, usage: usageView, billing: billingView
    };
    (views[p[0]] || dashboardView)();
  }
  function current(token) { return token === state.route; }

  // ------------------------------------------------------------------ views
  function newWorkspaceView() {
    var input = el("input", { type: "text", maxlength: "200", required: true, placeholder: "Workspace name" });
    var msg = el("div");
    render(el("h1", { text: state.workspaces.length ? "New workspace" : "Create your first workspace" }),
      el("form", { className: "inline", onsubmit: function (ev) {
        ev.preventDefault();
        api("POST", "/workspaces", { name: input.value }).then(function (d) {
          return api("GET", "/workspaces").then(function (l) {
            state.workspaces = l.workspaces || []; selectWorkspace(d.workspace_id); window.location.hash = "#/billing";
          });
        }).catch(function (err) { clear(msg); msg.appendChild(errorBox(err)); });
      } }, input, el("button", { type: "submit", text: "Create" })), msg);
  }

  function planCard(ws) {
    var ent = ws.entitlement, usage = ws.usage;
    if (!ent) {
      return el("div", { className: "card" }, el("h3", { text: "Plan" }), el("p", { text: "No plan yet." }), el("a", { className: "button", href: "#/billing", text: "Choose a plan" }));
    }
    var spec = catalogEntry(ent.plan) || {};
    return el("div", { className: "card" }, el("h3", { text: "Plan" }),
      el("div", { className: "big", text: spec.display_name || C.humanize(ent.plan) }),
      el("div", { className: "muted", text: (usage && usage.billing_type === "one_time" ? "One-time purchase" : C.humanize(ent.billing_interval || "") + " subscription") + " - " + C.humanize(ent.status) }),
      el("ul", { className: "small" }, C.planLimitLines(usage, spec).map(function (l) { return el("li", { text: l }); })));
  }
  function usageCard(usage) {
    if (!usage) { return el("div", { className: "card" }, el("h3", { text: "Usage" }), el("p", { className: "muted", text: "Available once a plan is active." })); }
    if (usage.usage_model === "scan_credit") {
      return el("div", { className: "card" }, el("h3", { text: "Quick scan" }),
        el("div", { className: "big", text: usage.scans_available > 0 ? "Available" : (usage.scans_reserved > 0 ? "In progress" : "Used") }),
        el("div", { className: "muted", text: "Available: " + usage.scans_available + " - in progress: " + usage.scans_reserved + " - used: " + usage.scans_consumed }));
    }
    return el("div", { className: "card" }, el("h3", { text: "Effective LOC this service month" }),
      el("div", { className: "big", text: C.formatNumber(usage.loc_used) + " / " + C.formatNumber(usage.loc_limit) }),
      el("div", { className: "bar " + usage.state }, el("span", { style: null, "data-pct": C.usagePercent(usage) })),
      el("div", { className: "muted", text: C.formatNumber(usage.loc_remaining) + " remaining - resets " + C.formatDate(usage.period_end) }));
  }
  function sizeBars(root) {
    // CSP forbids inline style attributes; widths are set through the CSSOM.
    Array.prototype.forEach.call(root.querySelectorAll("[data-pct]"), function (s) { s.style.width = s.getAttribute("data-pct") + "%"; });
  }

  function jobsTable(jobs, withProject) {
    if (!jobs.length) { return el("p", { className: "muted", text: "No scans yet." }); }
    return el("table", null, el("thead", null, el("tr", null, ["Created", withProject ? "Project" : null, "Source", "Effective LOC", "Status", "Indicator", ""].filter(function (x) { return x !== null; }).map(function (h) { return el("th", { text: h }); }))),
      el("tbody", null, jobs.map(function (j) {
        return el("tr", null, el("td", null, el("a", { href: "#/scans/" + j.id, text: C.formatDate(j.created_at) })),
          withProject ? el("td", { text: j.project_name || "-" }) : null,
          el("td", { text: C.sourceKindLabel(j.source_kind, j.git_repository) + (j.git_repository ? " - " + j.git_repository + "@" + C.shortSha(j.git_commit_sha) : "") }),
          el("td", { text: C.formatNumber(j.effective_loc) }), el("td", null, badge(j.status)),
          el("td", { text: j.report_id ? (j.score_status === "computed" ? j.score + " (" + j.risk_band + ")" : "Not computed") : "-" }),
          el("td", null, j.report_id ? el("a", { href: "#/reports/" + j.report_id, text: "Report" }) : null));
      })));
  }

  function dashboardView() {
    var token = state.route;
    Promise.all([loadWs(), api("GET", wsPath("/jobs?limit=5")), api("GET", wsPath("/projects?limit=5")), catalog().catch(function () { return []; })]).then(function (r) {
      if (!current(token)) { return; }
      var ws = r[0], adm = ws.admission || {};
      render(el("h1", { text: ws.workspace.name }),
        el("div", { className: "actions" }, el("a", { className: "button", href: "#/scan/new", text: "New scan" }), el("a", { className: "button secondary", href: "#/projects", text: "Projects" })),
        el("div", { className: "cards" }, planCard(ws), usageCard(ws.usage),
          el("div", { className: "card" }, el("h3", { text: "Active scans" }), el("div", { className: "big", text: adm.pending_jobs + " / " + adm.max_pending_jobs }), el("div", { className: "muted", text: "queued or running" }))),
        el("h2", { text: "Latest scans" }), jobsTable(r[1].jobs || [], true),
        el("h2", { text: "Projects" }), (r[2].projects || []).length ? el("ul", null, r[2].projects.map(function (p) { return el("li", null, el("a", { href: "#/projects/" + p.id, text: p.name })); })) : el("p", { className: "muted", text: "No projects yet." }));
      sizeBars(view);
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Dashboard" }), errorBox(err)); } });
  }

  function projectsView() {
    var token = state.route, msg = el("div");
    var input = el("input", { type: "text", maxlength: "200", required: true, placeholder: "Project name" });
    Promise.all([loadWs(), api("GET", wsPath("/projects?limit=100"))]).then(function (r) {
      if (!current(token)) { return; }
      var projects = r[1].projects || [];
      render(el("h1", { text: "Projects" }), el("p", { className: "muted", text: "Unlimited projects on every plan." }),
        el("form", { className: "inline", onsubmit: function (ev) {
          ev.preventDefault();
          api("POST", wsPath("/projects"), { name: input.value }).then(function () { route(); }).catch(function (err) { clear(msg); msg.appendChild(errorBox(err)); });
        } }, input, el("button", { type: "submit", text: "Create project" })), msg,
        projects.length ? el("table", null, el("thead", null, el("tr", null, ["Name", "Created", ""].map(function (h) { return el("th", { text: h }); }))),
          el("tbody", null, projects.map(function (p) {
            return el("tr", null, el("td", null, el("a", { href: "#/projects/" + p.id, text: p.name })), el("td", { text: C.formatDate(p.created_at) }),
              el("td", null, el("a", { href: "#/scan/new?project=" + p.id, text: "New scan" })));
          }))) : el("p", { className: "muted", text: "No projects yet." }));
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Projects" }), errorBox(err)); } });
  }

  function projectView(pid) {
    var token = state.route, msg = el("div");
    Promise.all([loadWs(), api("GET", wsPath("/projects/" + encodeURIComponent(pid))), api("GET", wsPath("/jobs?limit=50&project_id=" + encodeURIComponent(pid)))]).then(function (r) {
      if (!current(token)) { return; }
      var project = r[1].project, name = el("input", { type: "text", maxlength: "200", value: project.name });
      render(el("h1", { text: project.name }),
        el("div", { className: "actions" }, el("a", { className: "button", href: "#/scan/new?project=" + project.id, text: "New scan in this project" })),
        el("form", { className: "inline", onsubmit: function (ev) {
          ev.preventDefault();
          api("PATCH", wsPath("/projects/" + project.id), { name: name.value }).then(function () { route(); }).catch(function (err) { clear(msg); msg.appendChild(errorBox(err)); });
        } }, name, el("button", { type: "submit", className: "secondary", text: "Rename" }),
          canManage() ? el("button", { type: "button", className: "danger", text: "Delete project", onclick: function () {
            if (!window.confirm("Delete this project? Its scans and reports are kept.")) { return; }
            api("DELETE", wsPath("/projects/" + project.id)).then(function () { window.location.hash = "#/projects"; }).catch(function (err) { clear(msg); msg.appendChild(errorBox(err)); });
          } }) : null), msg,
        el("h2", { text: "Scans" }), jobsTable(r[2].jobs || [], false));
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Project" }), errorBox(err)); } });
  }

  function newScanView(query) {
    var token = state.route;
    if (query.workspace && query.workspace !== state.wsId && state.workspaces.some(function (w) { return w.id === query.workspace; })) { selectWorkspace(query.workspace); }
    Promise.all([loadWs(), api("GET", wsPath("/projects?limit=100")), catalog().catch(function () { return []; })]).then(function (r) {
      if (!current(token)) { return; }
      var ws = r[0], projects = r[1].projects || [], adm = ws.admission || {};
      var result = el("div"), key = C.newIdempotencyKey();
      var project = el("select", { "aria-label": "Project" }, el("option", { value: "", text: "No project" }),
        projects.map(function (p) { return el("option", { value: p.id, text: p.name, selected: p.id === query.project }); }));
      var order = ["quick", "standard", "pro"];
      var mode = el("select", { "aria-label": "Analysis mode" }, (adm.allowed_modes || []).slice().sort(function (a, b) { return order.indexOf(a) - order.indexOf(b); })
        .map(function (m) { return el("option", { value: m, text: C.humanize(m) }); }));
      // D-111: GitHub is offered only when the backend says the plan includes
      // it; the backend refuses it for any other plan regardless.
      var hasGitHub = (adm.features || []).indexOf("private_github") >= 0;
      var kind = hasGitHub && query.github ? "github" : "single";
      var gh = { repo: null, ref: "", sha: "" };
      var ghPane = el("div");
      var source = el("textarea", { spellcheck: "false", placeholder: "Paste Solidity source here" });
      var single = el("input", { type: "file", accept: ".sol,.vy" });
      var multi = el("input", { type: "file", multiple: true, accept: ".sol,.vy,.md,.txt" });
      var folder = el("input", { type: "file", multiple: true, webkitdirectory: true });
      var zip = el("input", { type: "file", accept: ".zip,application/zip" });
      var panes = {
        single: el("div", null, source, el("div", { className: "small muted" }, "or load a file: ", single)),
        files: el("div", null, el("div", null, "Files: ", multi), el("div", null, "or a folder: ", folder), el("p", { className: "small muted", text: "Paths are kept, so imports between files resolve. Files other than Solidity/Vyper sources and docs are ignored." })),
        zip: el("div", null, zip, el("p", { className: "small muted", text: "A ZIP of the project. It is checked on the server and never extracted to disk." })),
        github: ghPane
      };
      function ghSelectRepo(repoSelect, branchSelect, shaLine) {
        gh.repo = null; gh.ref = ""; gh.sha = ""; clear(branchSelect); shaLine.textContent = ""; onChange();
        if (!repoSelect.value) { return; }
        branchSelect.appendChild(el("option", { value: "", text: "Loading branches..." }));
        api("GET", wsPath("/github/repositories/" + encodeURIComponent(repoSelect.value) + "/branches")).then(function (d) {
          gh.repo = d.repository; clear(branchSelect);
          var branches = d.branches || [];
          branches.forEach(function (b) { branchSelect.appendChild(el("option", { value: b.name, text: b.name, selected: b.name === d.repository.default_branch })); });
          function pick() {
            var b = branches.filter(function (x) { return x.name === branchSelect.value; })[0];
            gh.ref = b ? b.name : ""; gh.sha = b ? b.commit_sha : "";
            shaLine.textContent = b ? "Commit to analyze: " + b.commit_sha : "No branch available.";
            onChange();
          }
          branchSelect.onchange = pick;
          pick();
        }).catch(function (err) { clear(branchSelect); clear(result); result.appendChild(errorBox(err)); });
      }
      function loadGitHub(notice) {
        clear(ghPane);
        if (notice) { ghPane.appendChild(el("div", { className: "alert " + (notice.kind === "ok" ? "ok" : "error"), role: "status", text: notice.text })); }
        if (!adm.github_configured) { ghPane.appendChild(el("p", { className: "muted", text: "GitHub is not configured on this server yet." })); return; }
        api("GET", wsPath("/github")).then(function (d) {
          var c = d.connection;
          function openExternal(url) { var safe = C.safeExternalUrl(url); if (safe) { window.location.assign(safe); } return !!safe; }
          if (!c) {
            ghPane.appendChild(el("p", { text: "Connect your GitHub account to scan a repository. Vericexa never asks for your GitHub password and only gets read access to the repositories you grant to its GitHub App." }));
            ghPane.appendChild(el("button", { type: "button", text: "Connect GitHub", onclick: function (ev) {
              ev.target.disabled = true;
              api("POST", wsPath("/github/connect"), {}).then(function (r) {
                if (!openExternal(r.authorize_url)) { ev.target.disabled = false; clear(result); result.appendChild(el("div", { className: "alert error", text: "GitHub could not be opened. Please try again." })); }
              })
                .catch(function (err) { ev.target.disabled = false; clear(result); result.appendChild(errorBox(err)); });
            } }));
            return;
          }
          var repoSelect = el("select", { "aria-label": "Repository" }, el("option", { value: "", text: "Loading repositories..." }));
          var branchSelect = el("select", { "aria-label": "Branch" });
          var shaLine = el("p", { className: "small" });
          ghPane.appendChild(el("div", { className: "actions" }, el("span", { text: "Connected to GitHub as " + c.github_login }),
            el("button", { type: "button", className: "secondary", text: "Disconnect", onclick: function () {
              if (!window.confirm("Disconnect GitHub from this workspace?")) { return; }
              api("DELETE", wsPath("/github")).then(function () { loadGitHub(null); }).catch(function (err) { clear(result); result.appendChild(errorBox(err)); });
            } })));
          ghPane.appendChild(el("div", { className: "field" }, el("label", { text: "Repository" }), repoSelect));
          ghPane.appendChild(el("div", { className: "field" }, el("label", { text: "Branch" }), branchSelect));
          ghPane.appendChild(shaLine);
          repoSelect.onchange = function () { ghSelectRepo(repoSelect, branchSelect, shaLine); };
          api("GET", wsPath("/github/repositories")).then(function (r) {
            clear(repoSelect);
            var repos = r.repositories || [];
            repoSelect.appendChild(el("option", { value: "", text: repos.length ? "Choose a repository" : "No repository granted yet" }));
            repos.forEach(function (x) { repoSelect.appendChild(el("option", { value: String(x.id), text: x.full_name + (x.private ? " (private)" : "") })); });
            if (r.truncated) { ghPane.appendChild(el("p", { className: "small muted", text: "Only the first " + repos.length + " repositories are listed." })); }
            if (r.install_url) {
              ghPane.appendChild(el("p", { className: "small muted" }, "Missing a repository? ", el("button", { type: "button", className: "secondary", text: "Choose repositories on GitHub", onclick: function () { openExternal(r.install_url); } })));
            }
          }).catch(function (err) { clear(repoSelect); clear(result); result.appendChild(errorBox(err)); });
        }).catch(function (err) { clear(result); result.appendChild(errorBox(err)); });
      }
      var paneHost = el("div");
      function showPane() { clear(paneHost); paneHost.appendChild(panes[kind]); }
      function onChange() { key = C.newIdempotencyKey(); clear(result); }
      [source, single, multi, folder, zip, project, mode].forEach(function (n) { n.addEventListener("change", onChange); });
      source.addEventListener("input", onChange);
      single.addEventListener("change", function () {
        if (single.files[0]) { single.files[0].text().then(function (t) { source.value = t; }); }
      });
      var kinds = [["single", "Single source"], ["files", "Multiple files"], ["zip", "ZIP"]].concat(hasGitHub ? [["github", "Import from GitHub"]] : []);
      var tabs = el("div", { className: "tabs", role: "radiogroup" }, kinds.map(function (t) {
        return el("label", null, el("input", { type: "radio", name: "kind", value: t[0], checked: t[0] === kind, onchange: function () { kind = t[0]; onChange(); showPane(); } }), " " + t[1]);
      }));
      showPane();
      if (hasGitHub) { loadGitHub(C.githubCallbackMessage(query.github)); }

      function payload(dryRun) {
        var base = { mode: mode.value, dry_run: dryRun };
        if (project.value) { base.project_id = project.value; }
        if (!dryRun) { base.idempotency_key = key; }
        if (kind === "single") { base.source = source.value; return Promise.resolve(base); }
        if (kind === "github") {
          if (!gh.repo || !gh.ref || !gh.sha) { return Promise.reject({ status: 400, body: { error: "", detail: "Choose a repository and a branch." } }); }
          base.github = { repository_id: gh.repo.id, ref: gh.ref, commit_sha: gh.sha };
          return Promise.resolve(base);
        }
        if (kind === "zip") {
          if (!zip.files[0]) { return Promise.reject({ status: 400, body: { error: "", detail: "Choose a ZIP file." } }); }
          return zip.files[0].arrayBuffer().then(function (buf) { base.archive = { format: "zip", content_base64: C.bytesToBase64(new Uint8Array(buf)) }; return base; });
        }
        var files = Array.prototype.slice.call(multi.files).concat(Array.prototype.slice.call(folder.files));
        if (!files.length) { return Promise.reject({ status: 400, body: { error: "", detail: "Choose one or more files." } }); }
        return Promise.all(files.map(function (f) { return f.text().then(function (t) { return { path: f.webkitRelativePath || f.name, content: t }; }); }))
          .then(function (list) { base.files = list; return base; });
      }
      function showPreview(d) {
        clear(result);
        result.appendChild(el("div", { className: "alert ok" }, el("strong", { text: "This scan can be submitted." }),
          el("ul", null, el("li", { text: "Effective LOC: " + C.formatNumber(d.effective_loc) }),
            d.max_loc_per_scan ? el("li", { text: "Plan limit per scan: " + C.formatNumber(d.max_loc_per_scan) + " effective LOC" }) : null,
            d.usage && typeof d.usage.loc_remaining === "number" ? el("li", { text: "Remaining this service month: " + C.formatNumber(d.usage.loc_remaining) + " effective LOC" }) : null,
            d.usage && d.usage.usage_model === "scan_credit" ? el("li", { text: "Uses your Quick scan (" + d.usage.scans_available + " available)" }) : null,
            d.github ? el("li", { text: "GitHub: " + d.github.full_name + " - branch " + d.github.ref + " - commit " + d.github.commit_sha }) : null),
          el("p", { className: "small", text: "Checked by the server. Starting the scan re-checks everything." })));
        if (d.files) {
          result.appendChild(el("table", null, el("thead", null, el("tr", null, ["File", "Language", "Effective LOC"].map(function (h) { return el("th", { text: h }); }))),
            el("tbody", null, d.files.map(function (f) { return el("tr", null, el("td", { text: f.path }), el("td", { text: f.language }), el("td", { text: C.formatNumber(f.effective_loc) })); }))));
          if (d.ignored_count) {
            result.appendChild(el("p", { className: "small muted", text: "Ignored (" + d.ignored_count + "): " + d.ignored.join(", ") + (d.ignored_count > d.ignored.length ? ", ..." : "") }));
          }
        }
      }
      function run(dryRun, button) {
        button.disabled = true;
        payload(dryRun).then(function (body) { return api("POST", wsPath("/jobs"), body); }).then(function (d) {
          if (d.github && kind === "github") { gh.sha = d.github.commit_sha; }   // Start analyzes exactly the commit Check pinned
          if (dryRun) { showPreview(d); } else { window.location.hash = "#/scans/" + d.job_id; }
        }).catch(function (err) { clear(result); result.appendChild(errorBox(err)); }).then(function () { button.disabled = false; });
      }
      var check = el("button", { type: "button", className: "secondary", text: "Check" });
      var submit = el("button", { type: "button", text: "Start scan" });
      check.addEventListener("click", function () { run(true, check); });
      submit.addEventListener("click", function () { run(false, submit); });

      render(el("h1", { text: "New scan" }),
        ws.entitlement ? el("div", { className: "alert info" }, el("strong", { text: "Your plan: " }), C.planLimitLines(ws.usage, catalogEntry(ws.entitlement.plan)).join(" - ")) :
          el("div", { className: "alert error" }, "This workspace has no active plan. ", el("a", { href: "#/billing", text: "Choose a plan" })),
        el("div", { className: "field" }, el("label", { text: "Project" }), project),
        el("div", { className: "field" }, el("label", { text: "Analysis mode" }), mode),
        el("div", { className: "field" }, el("label", { text: "Source" }), tabs, paneHost),
        el("div", { className: "actions" }, check, submit),
        el("p", { className: "small muted", text: "Each Check or Start counts as one scan request toward your per-minute request limit." }), result);
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "New scan" }), errorBox(err)); } });
  }

  function scansView(query) {
    var token = state.route, offset = parseInt(query.offset || "0", 10) || 0, limit = 20;
    var qs = "?limit=" + limit + "&offset=" + offset + (query.project ? "&project_id=" + encodeURIComponent(query.project) : "") + (query.status ? "&status=" + encodeURIComponent(query.status) : "");
    Promise.all([api("GET", wsPath("/jobs" + qs)), api("GET", wsPath("/projects?limit=100"))]).then(function (r) {
      if (!current(token)) { return; }
      var jobs = r[0].jobs || [];
      function go(extra) {
        var q = Object.assign({}, query, extra), parts = [];
        Object.keys(q).forEach(function (k) { if (q[k]) { parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(q[k])); } });
        window.location.hash = "#/scans" + (parts.length ? "?" + parts.join("&") : "");
      }
      var projectFilter = el("select", { "aria-label": "Filter by project", onchange: function (ev) { go({ project: ev.target.value, offset: "" }); } },
        el("option", { value: "", text: "All projects" }), (r[1].projects || []).map(function (p) { return el("option", { value: p.id, text: p.name, selected: p.id === query.project }); }));
      var statusFilter = el("select", { "aria-label": "Filter by status", onchange: function (ev) { go({ status: ev.target.value, offset: "" }); } },
        el("option", { value: "", text: "All statuses" }), ["queued", "claimed", "running", "succeeded", "failed", "canceled"].map(function (s) { return el("option", { value: s, text: C.jobStatusLabel(s), selected: s === query.status }); }));
      render(el("h1", { text: "Scans" }), el("div", { className: "actions" }, projectFilter, statusFilter, el("a", { className: "button", href: "#/scan/new", text: "New scan" })),
        jobsTable(jobs, true),
        el("div", { className: "actions" }, offset > 0 ? el("button", { type: "button", className: "secondary", text: "Previous", onclick: function () { go({ offset: String(Math.max(0, offset - limit)) }); } }) : null,
          jobs.length === limit ? el("button", { type: "button", className: "secondary", text: "Next", onclick: function () { go({ offset: String(offset + limit) }); } }) : null));
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Scans" }), errorBox(err)); } });
  }

  function jobView(jobId) {
    var token = state.route;
    api("GET", wsPath("/jobs/" + encodeURIComponent(jobId))).then(function (d) {
      if (!current(token)) { return; }
      var job = d.job, src = d.source || {}, usage = d.usage || {};
      render(el("h1", null, "Scan ", badge(job.status)),
        kv([["Created", C.formatDate(job.created_at)], ["Started", C.formatDate(job.started_at)], ["Finished", C.formatDate(job.completed_at)],
          ["Mode", C.humanize(job.mode)], ["Source", C.sourceKindLabel(src.kind, src.git && src.git.repository_full_name) + (src.name ? " - " + src.name : "")],
          src.git ? ["Repository", src.git.repository_full_name] : null, src.git ? ["Branch", src.git.ref] : null,
          src.git ? ["Commit", el("code", { text: src.git.commit_sha })] : null,
          ["Project", src.project_id ? el("a", { href: "#/projects/" + src.project_id, text: "Open project" }) : "-"],
          ["Effective LOC", C.formatNumber(usage.effective_loc)], job.attempt_count ? ["Attempts", String(job.attempt_count)] : null]),
        job.status === "failed" ? el("div", { className: "alert error" }, el("strong", { text: "The scan failed. " }), "No LOC or Quick scan was charged for it.", job.last_error ? el("pre", { text: job.last_error }) : null) : null,
        C.isPending(job.status) ? el("div", { className: "alert info", text: "This page refreshes automatically while the scan is " + C.jobStatusLabel(job.status).toLowerCase() + "." }) : null,
        d.report ? el("div", { className: "actions" }, el("a", { className: "button", href: "#/reports/" + d.report.id, text: "Open report" })) : null,
        (src.files || []).length ? [el("h2", { text: "Files" }), el("table", null, el("thead", null, el("tr", null, ["File", "Language", "Bytes", "Effective LOC"].map(function (h) { return el("th", { text: h }); }))),
          el("tbody", null, src.files.map(function (f) { return el("tr", null, el("td", { text: f.path }), el("td", { text: f.language }), el("td", { text: C.formatNumber(f.size_bytes) }), el("td", { text: C.formatNumber(f.effective_loc) })); })))] : null);
      if (C.isPending(job.status)) { state.timer = setTimeout(function () { if (current(token)) { jobView(jobId); } }, 4000); }
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Scan" }), errorBox(err)); } });
  }

  function findingView(f) {
    var sev = String(f.severity || "").toUpperCase();
    return el("div", { className: "finding" },
      el("h3", null, el("span", { className: "sev " + sev, text: sev || "-" }), " ", C.humanize(f.signature) || f.id || "Finding"),
      el("div", { className: "small muted", text: [f.category, f.confidence ? "confidence " + f.confidence : null, f.status].filter(Boolean).join(" - ") }),
      (f.locations || []).length ? el("ul", { className: "small" }, f.locations.map(function (l) { return el("li", { text: C.locationText(l) }); })) : null,
      f.description ? el("p", { text: f.description }) : null,
      (f.evidence || []).length ? [el("div", { className: "small muted", text: "Evidence" }), el("pre", { text: f.evidence.join("\n") })] : null,
      f.recommendation ? [el("div", { className: "small muted", text: "Recommendation" }), el("p", { text: f.recommendation })] : null,
      f.patch ? [el("div", { className: "small muted", text: "Suggested patch" }), el("pre", { text: typeof f.patch === "string" ? f.patch : JSON.stringify(f.patch, null, 2) }), el("p", { className: "small", text: C.PATCH_NOTE })] : null,
      f.stableKey ? el("div", { className: "small muted", text: "Stable key: " + f.stableKey }) : null);
  }
  function advisoryView(a) {
    var s = a.summary || {}, reviewed = (a.targets || []).filter(function (t) { return t.reviewStatus === "reviewed"; });
    return [el("h2", { text: "Advisory targeted code review" }),
      el("p", { className: "small muted", text: "Advisory only: it never changes the findings or the risk indicator above. Status: " + (a.status || "-") + "." }),
      el("p", { text: "Reviewed " + (s.targetsReviewed || 0) + " of " + (s.targetsCandidate || 0) + " candidate areas - supported " + (s.supported || 0) + ", contradicted " + (s.contradicted || 0) + ", insufficient context " + (s.insufficientContext || 0) + "." }),
      reviewed.map(function (t) {
        return el("div", { className: "finding" }, el("h3", { text: C.humanize(t.verdict || "") + " - " + C.locationText(t) }),
          t.explanation ? el("p", { text: t.explanation }) : null,
          (t.evidence || []).map(function (ev) { return el("pre", { text: C.locationText(ev) + "\n" + (ev.text || "") }); }));
      })];
  }
  function reportView(reportId) {
    var token = state.route;
    api("GET", wsPath("/reports/" + encodeURIComponent(reportId) + "/document")).then(function (d) {
      if (!current(token)) { return; }
      var rep = d.report, s = d.scored_report, ri = (s && s.riskIndicator) || {}, scope = (s && s.scope) || {};
      var computed = rep.score_status === "computed";
      var dl = "/workspaces/" + encodeURIComponent(state.wsId) + "/reports/" + encodeURIComponent(reportId) + "/download?format=";
      render(el("h1", { text: "Automated security review" }),
        el("div", { className: "alert info", text: C.DISCLAIMER }),
        kv([["Project", d.source.project_name || "-"], ["Date", C.formatDate(rep.created_at)], ["Mode", C.humanize(d.job.mode)],
          ["Source", C.sourceKindLabel(d.source.kind, d.source.git && d.source.git.repository_full_name) + (d.source.git ? " - " + d.source.git.repository_full_name + " @ " + d.source.git.commit_sha : "")], ["Analysis scope", scope.completeness ? C.humanize(scope.completeness) : "-"]]),
        (scope.reasons || []).length ? el("ul", { className: "small" }, scope.reasons.map(function (r) { return el("li", { text: typeof r === "string" ? r : (r.message || r.code || JSON.stringify(r)) }); })) : null,
        el("div", { className: "cards" }, el("div", { className: "card" }, el("h3", { text: "Automated Risk Indicator" }),
          el("div", { className: "big", text: computed ? rep.score + " - " + rep.risk_band : "Not computed" }),
          el("p", { className: "small", text: computed ? C.INDICATOR_NOTE : C.NOT_COMPUTED_NOTE }),
          computed && rep.risk_band === "LOW" ? el("p", { className: "small", text: C.LOW_NOTE }) : null)),
        d.purged ? el("div", { className: "alert error", text: "The content of this report has been removed under the retention policy; its summary is kept." }) : null,
        el("div", { className: "actions" }, s ? el("a", { className: "button secondary", href: dl + "json", download: "", text: "Download JSON" }) : null,
          d.markdown !== null ? el("a", { className: "button secondary", href: dl + "markdown", download: "", text: "Download Markdown" }) : null),
        s ? [el("h2", { text: "Findings (" + (s.findings || []).length + ")" }),
          (s.findings || []).length ? C.sortFindings(s.findings).map(findingView) : el("p", { text: C.NO_FINDINGS }),
          (s.categoryCoverage || []).length ? [el("h2", { text: "Category coverage" }), el("table", null, el("tbody", null, s.categoryCoverage.map(function (c) {
            return el("tr", null, el("td", { text: c.category }), el("td", { text: c.status }), el("td", { className: "small", text: c.note || "" }));
          })))] : null,
          (s.limitations || []).length ? [el("h2", { text: "Limitations" }), el("ul", null, s.limitations.map(function (l) { return el("li", { text: typeof l === "string" ? l : JSON.stringify(l) }); }))] : null]
          : (d.markdown !== null ? [el("h2", { text: "Report" }), el("pre", { text: d.markdown })] : null),
        d.advisory ? advisoryView(d.advisory) : null);
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Report" }), errorBox(err)); } });
  }

  function usageView() {
    var token = state.route;
    Promise.all([loadWs(), catalog().catch(function () { return []; })]).then(function () {
      if (!current(token)) { return; }
      var u = state.ws.usage;
      if (!u) { return render(el("h1", { text: "Usage" }), el("p", null, "No active plan. ", el("a", { href: "#/billing", text: "Choose a plan" }))); }
      var spec = catalogEntry(u.plan) || {};
      var body = u.usage_model === "scan_credit"
        ? kv([["Plan", spec.display_name || u.plan], ["Quick scans available", String(u.scans_available)], ["In progress", String(u.scans_reserved)], ["Used", String(u.scans_consumed)]])
        : [el("div", { className: "bar " + u.state }, el("span", { "data-pct": C.usagePercent(u) })),
          kv([["Plan", spec.display_name || u.plan], ["Service month", C.formatDate(u.period_start) + " - " + C.formatDate(u.period_end)],
            ["Effective LOC used", C.formatNumber(u.loc_used) + " of " + C.formatNumber(u.loc_limit)], ["Consumed by completed scans", C.formatNumber(u.loc_consumed)],
            ["Held by scans in progress", C.formatNumber(u.loc_reserved)], ["Remaining", C.formatNumber(u.loc_remaining)],
            ["Scans this service month", String(u.scans_in_period || 0)]])];
      render(el("h1", { text: "Usage" }), body, el("h2", { text: "Plan limits" }), el("ul", null, C.planLimitLines(u, spec).map(function (l) { return el("li", { text: l }); })),
        el("p", { className: "small muted", text: u.usage_model === "scan_credit" ? "Quick has no monthly allowance: each purchase includes exactly one scan." : "Unused LOC does not roll over to the next service month. Failed scans are not charged." }));
      sizeBars(view);
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Usage" }), errorBox(err)); } });
  }

  function billingView() {
    var token = state.route, msg = el("div");
    Promise.all([loadWs(), catalog()]).then(function (r) {
      if (!current(token)) { return; }
      var ws = r[0], ent = ws.entitlement, usage = ws.usage, adm = ws.admission || {};
      var subscription = ent && ent.plan !== "quick" && ["active", "trialing", "past_due"].indexOf(ent.status) >= 0;
      function go(promise) {
        promise.then(function (d) {
          var url = C.safeExternalUrl(d.checkout_url || d.portal_url);
          if (url) { window.location.assign(url); } else { clear(msg); msg.appendChild(errorBox({ status: 502, body: { error: "", detail: "Unexpected response from billing." } })); }
        }).catch(function (err) { clear(msg); msg.appendChild(errorBox(err)); });
      }
      var current_ = ent ? kv([["Plan", (catalogEntry(ent.plan) || {}).display_name || ent.plan], ["Status", C.humanize(ent.status)],
        ["Billing", ent.plan === "quick" ? "One-time purchase" : C.humanize(ent.billing_interval || "-") + " subscription"],
        ent.plan !== "quick" && ent.current_period_end ? ["Renews / period ends", C.formatDate(ent.current_period_end)] : null,
        ent.plan === "quick" && usage ? ["Quick scan", usage.scans_available > 0 ? "Available" : (usage.scans_reserved > 0 ? "In progress" : "Used")] : null])
        : el("p", { text: "No plan yet." });
      var cards = (r[1] || []).map(function (p) {
        return el("div", { className: "card" }, el("h3", { text: p.display_name }),
          el("ul", { className: "small" }, C.planLimitLines(null, p).map(function (l) { return el("li", { text: l }); })),
          p.prices.map(function (price) {
            var label = C.formatMoney(price.amount_cents, price.currency) + (price.interval === "one_time" ? " one-time" : price.interval === "monthly" ? " / month" : " / year");
            return el("div", { className: "actions" }, el("span", { text: label }), canManage() && adm.billing_configured && !subscription ? el("button", { type: "button", className: "secondary", text: "Choose", onclick: function () {
              go(api("POST", "/billing/checkout", { workspace_id: state.wsId, plan: p.plan, interval: price.interval, success_path: "/app#/billing", cancel_path: "/app#/billing" }));
            } }) : null);
          }));
      });
      render(el("h1", { text: "Billing" }), current_,
        subscription && canManage() ? el("div", { className: "actions" }, el("button", { type: "button", text: "Manage subscription", onclick: function () {
          go(api("POST", "/billing/portal", { workspace_id: state.wsId, return_path: "/app#/billing" }));
        } })) : null,
        !canManage() ? el("p", { className: "muted", text: "Only workspace owners and admins can change billing." }) : null,
        !adm.billing_configured ? el("p", { className: "muted", text: "Billing is not available in this environment." }) : null,
        msg, el("h2", { text: "Plans" }),
        subscription ? el("p", { className: "muted", text: "To change plan or billing interval, use Manage subscription." }) : null,
        el("div", { className: "cards" }, cards),
        el("p", { className: "small muted", text: "Payments and subscription status are handled by Stripe; this page shows the status Stripe reports." }));
    }).catch(function (err) { if (current(token)) { render(el("h1", { text: "Billing" }), errorBox(err)); } });
  }

  boot();
}());
