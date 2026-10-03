/* Vericexa web app - pure helpers (docs/decisiones.md D-110).
 *
 * No DOM, no network: formatting, error wording and plan-limit wording only.
 * Every number these helpers print comes from a backend response passed in
 * by app.js - nothing here knows a price, a quota or a LOC rule of its own,
 * so the backend stays the single authority. Loaded by the browser as a
 * plain script (window.VXCore) and by tests/test_backend_webapp.py through
 * Node (module.exports).
 */
(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.VXCore = api;
  }
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var DISCLAIMER = "Automated, AI-assisted security review of the submitted source code. " +
    "It is NOT a formal security audit, a certification, or a guarantee that the code is secure or that deployment is safe.";
  var NO_FINDINGS = "No findings matching the configured detection criteria were identified within the analyzed scope.";
  var INDICATOR_NOTE = "This indicator reflects findings detected within the analyzed scope. It is not a measure of overall protocol security.";
  var LOW_NOTE = "A LOW automated risk indicator does not mean that deployment is safe.";
  var PATCH_NOTE = "Suggested remediation only. Review, compile, test and validate independently before use.";
  var NOT_COMPUTED_NOTE = "Automated deterministic scoring was unavailable in this runtime.";

  // Backend error codes (backend/http_app.py, repository.py, submission_input.py)
  // -> wording. Unknown codes fall back to the backend's own message.
  var ERRORS = {
    too_many_pending_jobs: "This workspace already has the maximum number of scans queued or running. Wait for one to finish, then try again.",
    submit_rate_limited: "Too many scan requests in a short time. Please wait before trying again.",
    technical_budget_exhausted: "This workspace reached a technical safety limit for the current service month. Please contact support.",
    loc_quota_exceeded: "This scan needs more effective LOC than what is left of this service month's allowance.",
    loc_per_scan_limit_exceeded: "This scan is larger than your plan allows for a single scan.",
    no_scan_credit: "No unused Quick scan is available. Each Quick purchase includes exactly one scan.",
    no_source_code: "No Solidity/Vyper source code was found (0 effective LOC).",
    no_source_files: "No Solidity (.sol) or Vyper (.vy) file was found.",
    invalid_path: "A file path is not allowed.",
    duplicate_path: "Two files have the same path.",
    reserved_marker: "A file contains a line that is reserved by the submission format.",
    file_not_utf8: "A source file is not valid UTF-8 text.",
    too_many_files: "Too many files for one scan.",
    submission_too_large: "The files are larger than the maximum submission size.",
    archive_too_large: "The ZIP file is larger than allowed.",
    archive_uncompressed_too_large: "The ZIP file's contents are larger than allowed once decompressed.",
    archive_malformed: "The ZIP file could not be read.",
    archive_symlink: "The ZIP file contains a symbolic link, which is not allowed.",
    archive_encrypted: "The ZIP file contains an encrypted entry, which is not allowed.",
    invalid_archive: "The ZIP upload is not valid.",
    unsupported_archive_format: "Only ZIP archives are supported.",
    invalid_files: "The file list is not valid.",
    project_not_found: "The project was not found in this workspace.",
    project_name_taken: "A project with this name already exists in this workspace.",
    billing_not_configured: "This plan cannot be purchased yet.",
    report_content_unavailable: "The report content is no longer available.",
    // D-111 Private GitHub (backend/http_app.py, backend/github_integration.py)
    feature_not_available: "Private GitHub is available on the Standard and Pro plans.",
    github_not_configured: "GitHub is not configured on this server yet.",
    github_not_connected: "Connect your GitHub account first.",
    github_reconnect_required: "Your GitHub connection expired or was revoked. Connect GitHub again.",
    github_authorization_failed: "GitHub did not grant access.",
    github_rate_limited: "GitHub's API rate limit was reached. Please try again later.",
    github_unavailable: "GitHub could not be reached or returned an unexpected response. Please try again.",
    github_response_too_large: "GitHub returned more data than allowed.",
    repository_not_accessible: "This repository is not accessible with your GitHub connection.",
    repository_too_large: "This repository has too many files to scan from GitHub. Upload a ZIP of the contracts instead.",
    ref_not_found: "The branch does not exist in this repository.",
    commit_not_found: "The commit does not exist in this repository.",
    commit_not_on_ref: "The selected commit is not part of the branch. Run Check again.",
    invalid_repository_id: "Choose a repository.",
    invalid_ref: "Choose a branch.",
    invalid_commit_sha: "The commit SHA is not valid.",
    invalid_github_source: "The GitHub selection is not valid.",
    // D-112 free Trial and sign-up
    trial_already_used: "This email address has already used its free Trial. Choose Quick, Standard or Pro to keep scanning.",
    trial_not_eligible: "This email address is not eligible for the free Trial.",
    email_not_verified: "Verify your email address to start the free Trial.",
    project_limit_reached: "Your plan's project limit is reached.",
    trial_history_expired: "Trial results are kept for 7 days and this one is no longer available.",
    disposable_email_not_allowed: "This email address is not eligible for the free Trial. Please use a personal or work email address.",
    signup_rate_limited: "Too many requests. Please wait a few minutes and try again.",
    invalid_email: "Enter a valid email address.",
    // D-113 Private API keys
    invalid_key_name: "Enter a key name (at most 100 characters).",
    key_limit_reached: "This workspace has the maximum number of active API keys. Revoke an unused key first.",
    key_not_found: "The API key was not found."
  };
  // feature_not_available names the feature it refers to (backend/plans.py).
  var FEATURE_ERRORS = {
    private_api: "The Private API is available on the Quick, Standard and Pro plans.",
    report_download: "Report downloads are not included in the free Trial."
  };
  // Outcome word the backend appends after GitHub's authorization redirect.
  var GITHUB_CALLBACK = {
    connected: ["ok", "GitHub connected."],
    denied: ["error", "GitHub authorization was cancelled."],
    invalid_state: ["error", "The GitHub authorization link expired or was already used. Please connect again."],
    failed: ["error", "GitHub could not be connected. Please try again."],
    not_available: ["error", "Private GitHub is available on the Standard and Pro plans."],
    not_configured: ["error", "GitHub is not configured on this server yet."]
  };
  function githubCallbackMessage(word) { var m = GITHUB_CALLBACK[word]; return m ? { kind: m[0], text: m[1] } : null; }
  var STATUS_TEXT = {
    401: "Your session has ended. Please sign in again.",
    403: "You do not have access to this in the current workspace.",
    404: "Not found.",
    413: "The submission is too large.",
    429: "Too many requests. Please wait and try again.",
    500: "Something went wrong on our side. Please try again.",
    503: "This feature is not available right now."
  };

  function describeError(status, body) {
    var code = body && typeof body.error === "string" ? body.error : "";
    var message = (code === "feature_not_available" && body && FEATURE_ERRORS[body.feature]) || ERRORS[code] || code || STATUS_TEXT[status] || "Request failed (HTTP " + status + ").";
    var details = [];
    if (body && typeof body.detail === "string" && body.detail && body.detail !== message) { details.push(body.detail); }
    if (body && typeof body.effective_loc === "number") { details.push("Effective LOC: " + formatNumber(body.effective_loc)); }
    if (body && typeof body.max_loc_per_scan === "number") { details.push("Plan limit per scan: " + formatNumber(body.max_loc_per_scan) + " effective LOC"); }
    if (body && typeof body.loc_remaining === "number") { details.push("Remaining this service month: " + formatNumber(body.loc_remaining) + " effective LOC"); }
    if (body && typeof body.max_pending_jobs === "number") { details.push("Limit: " + body.max_pending_jobs + " scans queued or running"); }
    if (body && typeof body.max_projects === "number") { details.push("Projects included: " + body.max_projects); }
    if (body && typeof body.retry_after_seconds === "number") { details.push("Try again in " + body.retry_after_seconds + " s"); }
    return { code: code, message: message, details: details };
  }

  function formatNumber(n) {
    if (typeof n !== "number" || !isFinite(n)) { return "-"; }
    return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function formatMoney(cents, currency) {
    if (typeof cents !== "number") { return "-"; }
    if (cents === 0) { return "$0"; }
    var whole = Math.floor(cents / 100), rest = String(cents % 100);
    return (currency === "usd" ? "$" : "") + formatNumber(whole) + "." + (rest.length < 2 ? "0" + rest : rest) + (currency && currency !== "usd" ? " " + currency.toUpperCase() : "");
  }

  function formatDate(iso) {
    if (typeof iso !== "string" || !iso) { return "-"; }
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return iso; }
    return d.toISOString().replace("T", " ").slice(0, 16) + " UTC";
  }

  var JOB_STATUS = { queued: "Queued", claimed: "Starting", running: "Running", succeeded: "Completed", failed: "Failed", canceled: "Cancelled" };
  function jobStatusLabel(status) { return JOB_STATUS[status] || String(status || "-"); }
  function isPending(status) { return status === "queued" || status === "claimed" || status === "running"; }

  var SOURCE_KIND = { single: "Single source", files: "Multiple files", archive: "ZIP" };
  function sourceKindLabel(kind, gitRepository) { return gitRepository ? "GitHub" : (SOURCE_KIND[kind] || "Single source"); }
  function shortSha(sha) { return typeof sha === "string" && /^[0-9a-f]{40}$/.test(sha) ? sha.slice(0, 12) : "-"; }

  // Plan limits as stated by the backend's own usage summary and catalog entry.
  function planLimitLines(usage, catalogEntry) {
    var lines = [];
    var spec = catalogEntry || {};
    var perScan = usage && typeof usage.max_loc_per_scan === "number" ? usage.max_loc_per_scan : spec.max_loc_per_scan;
    if (spec.usage_model === "trial" || (usage && usage.usage_model === "trial")) {
      lines.push("1 free scan per email address (no card, no subscription)");
      if (typeof perScan === "number") { lines.push("Up to " + formatNumber(perScan) + " effective LOC"); }
      lines.push("1 project");
      lines.push("Report viewable for " + (spec.history_days || (usage && usage.history_days) || 7) + " days (no downloads)");
      return lines;
    }
    if (spec.usage_model === "scan_credit" || (usage && usage.usage_model === "scan_credit")) {
      lines.push((spec.scans_per_purchase || 1) + " scan per purchase (one-time payment, no subscription)");
    }
    if (typeof perScan === "number") { lines.push("Up to " + formatNumber(perScan) + " effective LOC per scan"); }
    var quota = usage && typeof usage.loc_limit === "number" ? usage.loc_limit : spec.monthly_loc_quota;
    if (typeof quota === "number") { lines.push(formatNumber(quota) + " effective LOC per service month"); }
    if (spec.max_projects === null || (usage && usage.max_projects === null)) { lines.push("Unlimited projects"); }
    var members = usage && typeof usage.max_members === "number" ? usage.max_members : spec.max_members;
    if (typeof members === "number") { lines.push("Up to " + members + " members"); }
    return lines;
  }

  function usagePercent(usage) {
    if (!usage || typeof usage.loc_limit !== "number" || usage.loc_limit <= 0) { return null; }
    return Math.max(0, Math.min(100, Math.round((usage.loc_used || 0) * 100 / usage.loc_limit)));
  }

  // Only an absolute HTTPS URL returned by the backend (Stripe Checkout or
  // portal) may be navigated to; anything else is refused.
  function safeExternalUrl(url) {
    return typeof url === "string" && /^https:\/\/[^\s"'<>]+$/.test(url) ? url : null;
  }

  var SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, INFORMATIONAL: 4 };
  function sortFindings(findings) {
    return (Array.isArray(findings) ? findings.slice() : []).sort(function (a, b) {
      var sa = SEVERITY_ORDER[String((a && a.severity) || "").toUpperCase()], sb = SEVERITY_ORDER[String((b && b.severity) || "").toUpperCase()];
      sa = sa === undefined ? 9 : sa; sb = sb === undefined ? 9 : sb;
      return sa - sb;
    });
  }

  function humanize(text) {
    if (typeof text !== "string" || !text) { return ""; }
    var s = text.replace(/[-_]+/g, " ").trim();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function locationText(loc) {
    if (!loc || typeof loc !== "object") { return ""; }
    var where = String(loc.file || "");
    if (loc.lineStart) { where += ":" + loc.lineStart + (loc.lineEnd && loc.lineEnd !== loc.lineStart ? "-" + loc.lineEnd : ""); }
    var scope = [loc.contract, loc["function"]].filter(function (x) { return typeof x === "string" && x; }).join(".");
    return scope ? where + " (" + scope + ")" : where;
  }

  function bytesToBase64(bytes) {
    var out = "", chunk = 0x8000;
    for (var i = 0; i < bytes.length; i += chunk) {
      out += String.fromCharCode.apply(null, Array.prototype.slice.call(bytes, i, i + chunk));
    }
    return btoa(out);
  }

  function newIdempotencyKey() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) { return "web-" + crypto.randomUUID(); }
    return "web-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  }

  // "#/scans/abc?project=x" -> { parts: ["scans","abc"], query: {project:"x"} }
  function parseHash(hash) {
    var raw = String(hash || "").replace(/^#\/?/, "");
    var q = raw.indexOf("?");
    var path = q >= 0 ? raw.slice(0, q) : raw, query = {};
    if (q >= 0) {
      raw.slice(q + 1).split("&").forEach(function (pair) {
        if (!pair) { return; }
        var i = pair.indexOf("=");
        var k = decodeURIComponent(i >= 0 ? pair.slice(0, i) : pair), v = i >= 0 ? decodeURIComponent(pair.slice(i + 1)) : "";
        query[k] = v;
      });
    }
    return { parts: path.split("/").filter(Boolean), query: query };
  }

  return {
    DISCLAIMER: DISCLAIMER, NO_FINDINGS: NO_FINDINGS, INDICATOR_NOTE: INDICATOR_NOTE, LOW_NOTE: LOW_NOTE,
    PATCH_NOTE: PATCH_NOTE, NOT_COMPUTED_NOTE: NOT_COMPUTED_NOTE, ERRORS: ERRORS,
    describeError: describeError, formatNumber: formatNumber, formatMoney: formatMoney, formatDate: formatDate,
    jobStatusLabel: jobStatusLabel, isPending: isPending, sourceKindLabel: sourceKindLabel, planLimitLines: planLimitLines,
    usagePercent: usagePercent, safeExternalUrl: safeExternalUrl, sortFindings: sortFindings, humanize: humanize,
    locationText: locationText, bytesToBase64: bytesToBase64, newIdempotencyKey: newIdempotencyKey, parseHash: parseHash,
    githubCallbackMessage: githubCallbackMessage, shortSha: shortSha
  };
}));
