/* Launch page behaviour. Deliberately small and dependency-free, like the console. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var out = $("out"), cards = $("cards");

  function say(msg, cls) {
    out.className = "out " + (cls || "");
    out.textContent = msg;
  }

  function renderChecks(pre) {
    cards.innerHTML = "";
    if (!pre || !pre.checks) return;
    var verdict = document.createElement("div");
    verdict.className = "verdict " + (pre.go ? "go" : "nogo");
    verdict.textContent = pre.go
      ? "GO — nothing blocks a confirmed finding on this machine."
      : "NO-GO — a hunt started now could not produce a confirmed finding, and it would "
        + "still report success. Fix the FAIL items, or tick the force box.";
    cards.appendChild(verdict);
    pre.checks.forEach(function (c) {
      var card = document.createElement("div");
      card.className = "card";
      var v = document.createElement("div");
      v.className = "v " + c.verdict;
      v.textContent = c.verdict;
      var body = document.createElement("div");
      var n = document.createElement("div");
      n.className = "cname"; n.textContent = c.name;
      var d = document.createElement("div");
      d.className = "cdetail"; d.textContent = c.detail || "";
      body.appendChild(n); body.appendChild(d);
      if (c.impact) {
        var im = document.createElement("div");
        im.className = "cdetail";
        im.textContent = "cost if ignored: " + c.impact;
        body.appendChild(im);
      }
      if (c.fix) {
        var fx = document.createElement("div");
        fx.className = "cfix"; fx.textContent = "fix: " + c.fix;
        body.appendChild(fx);
      }
      card.appendChild(v); card.appendChild(body);
      cards.appendChild(card);
    });
  }

  /* The hosts the operator has CONFIRMED, from the parsed scope. Empty until they press
     Parse scope — which is the point: there is no free-text target field to paste a
     program page into any more. */
  var parsed = null;

  function checkedHosts() {
    return Array.prototype.slice
      .call(document.querySelectorAll('#scopeOut input[data-host]:checked'))
      .map(function (el) { return el.getAttribute("data-host"); });
  }

  function anyFlaggedChecked() {
    return Array.prototype.slice
      .call(document.querySelectorAll('#scopeOut input[data-host][data-flagged="1"]:checked'))
      .length > 0;
  }

  function renderScope(res) {
    var box = $("scopeOut");
    box.innerHTML = "";
    var wrap = document.createElement("div");
    wrap.className = "hostlist";

    function section(title, items, cls, flagged) {
      if (!items.length) return;
      var h = document.createElement("h4");
      h.textContent = title;
      wrap.appendChild(h);
      items.forEach(function (it) {
        var host = it.host || it;
        var row = document.createElement("div");
        row.className = "host " + (cls || "");
        var cb = document.createElement("input");
        cb.type = "checkbox";
        cb.setAttribute("data-host", host);
        if (flagged) cb.setAttribute("data-flagged", "1");
        // Pre-ticked ONLY when the parser has strong evidence (a real asset table row)
        // and the derived set looks like one program's assets. A pasted policy page
        // yields a wide spread of bullet-only hosts -- that is how apple.com and
        // google.com reached a launch -- so those arrive unticked and must be read.
        var strongSet = (res.strong || []);
        cb.checked = !cls && !res.suspicious_spread && strongSet.indexOf(host) !== -1;
        cb.disabled = cls === "oos";
        var body = document.createElement("div");
        var n = document.createElement("div");
        n.className = "hn"; n.textContent = host;
        body.appendChild(n);
        // SHOW THE WORKING: the line this host was read from. Without it the operator
        // cannot tell an asset-table row from a footer link, which is the whole failure.
        var ev = (res.evidence || {})[host];
        if (ev && ev.line) {
          var src = document.createElement("div");
          src.className = "cdetail";
          src.textContent = (ev.strong ? "asset row: " : "read from: ") + ev.line;
          body.appendChild(src);
        }
        if (it.why) {
          var w = document.createElement("div");
          w.className = "hw"; w.textContent = it.why;
          body.appendChild(w);
        }
        row.appendChild(cb); row.appendChild(body);
        wrap.appendChild(row);
      });
    }

    section("In scope — these become the egress allowlist", res.in_scope, "", false);
    section("Flagged — confirm only if you mean it", res.flagged, "flag", true);
    /* Hosts the parser saw in PROSE rather than in an asset entry: a header example, a
       docs link, a contact address. Offered unchecked so a legitimate target the parser
       was too strict about is one tick away -- the parser must not be the only path. */
    section("Mentioned in the notes — tick only if these are really assets",
            (res.mentioned || []).map(function (h) {
              return { host: h, why: "seen in prose, not in an asset entry" };
            }), "flag", false);
    section("Out of scope — the guard will refuse these", res.out_of_scope, "oos", false);

    if (res.suspicious_spread) {
      var warn = document.createElement("div");
      warn.className = "verdict nogo";
      warn.textContent = "These span " + res.in_scope.length + " unrelated domains and "
        + "none came from an asset table row. That is what a whole policy PAGE looks "
        + "like when pasted — nav, footer, customer logos, other programs. Nothing is "
        + "pre-ticked: read each line below and tick only the program's real assets.";
      wrap.appendChild(warn);
    }
    if (!res.in_scope.length) {
      var p = document.createElement("div");
      p.className = "hw";
      p.textContent = "No in-scope hosts found in that text. Paste the program's asset "
        + "table — the hosts are read out of it.";
      wrap.appendChild(p);
    }
    box.appendChild(wrap);

    // Fill the program name and platform from what we learned, if still blank.
    if (!$("program").value.trim() && res.in_scope.length) {
      $("program").value = res.in_scope[0];
    }
    if (res.program_host) {
      var map = {"hackerone.com": "hackerone", "bugcrowd.com": "bugcrowd",
                 "intigriti.com": "intigriti", "yeswehack.com": "yeswehack",
                 "immunefi.com": "immunefi"};
      var plat = map[res.program_host.replace(/^www\./, "")];
      if (plat) $("platform").value = plat;
    }
  }

  $("parseBtn").addEventListener("click", function () {
    say("reading the scope…");
    fetch("/api/parse-scope", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: $("scope").value,
                             program_url: $("programUrl").value.trim() })
    })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (res.error) { say(res.error, "err"); return; }
        parsed = res;
        renderScope(res);
        say("Found " + res.in_scope.length + " in-scope host(s), "
          + res.out_of_scope.length + " excluded, " + res.flagged.length + " flagged, "
          + (res.mentioned || []).length + " mentioned in notes. "
          + "Confirm the list, then launch.", res.in_scope.length ? "ok" : "err");
      })
      .catch(function (e) { say("could not read the scope: " + e, "err"); });
  });

  function collect() {
    var ids = {};
    if ($("tokA").value) ids.a = $("tokA").value;
    if ($("tokB").value) ids.b = $("tokB").value;
    return {
      hosts: checkedHosts(),
      program_url: $("programUrl").value.trim(),
      program: $("program").value.trim(),
      platform: $("platform").value,
      scope_note: $("scope").value,
      engine: $("engine").value,
      rounds: parseInt($("rounds").value, 10) || 1,
      authorized: $("auth").checked,
      force: $("force").checked,
      confirm_flagged: anyFlaggedChecked(),
      identities: ids
    };
  }

  $("checkBtn").addEventListener("click", function () {
    var btn = this;
    btn.disabled = true;
    say("running preflight (this launches a real browser, ~10s)…");
    fetch("/api/preflight?engine=" + encodeURIComponent($("engine").value))
      .then(function (r) { return r.json(); })
      .then(function (pre) {
        say(pre.error ? ("preflight error: " + pre.error) : "", pre.error ? "err" : "");
        renderChecks(pre);
      })
      .catch(function (e) { say("preflight failed: " + e, "err"); })
      .finally(function () { btn.disabled = false; });
  });

  $("f").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = $("goBtn");
    btn.disabled = true;
    say("launching…");
    fetch("/api/launch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collect())
    })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (res.ok) {
          var link = "/?eng=" + encodeURIComponent(res.engagement);
          say("Hunt started.\n"
            + "  engagement : " + res.engagement + "\n"
            + "  pid        : " + res.pid + "\n"
            + "  log        : " + res.log + "\n\n"
            + "Opening the console…", "ok");
          renderChecks(res.preflight);
          setTimeout(function () { window.location.href = link; }, 2200);
          return;
        }
        say((res.error || "launch refused") , "err");
        if (res.preflight) renderChecks(res.preflight);
      })
      .catch(function (e) { say("launch failed: " + e, "err"); })
      .finally(function () { btn.disabled = false; });
  });

  // Refuse to submit before the scope has been parsed and confirmed. The server
  // validates this too; this is just a clearer message than a 400.
  $("f").addEventListener("submit", function (ev) {
    if (!checkedHosts().length) {
      ev.preventDefault();
      ev.stopImmediatePropagation();
      say("Press \u201cParse scope\u201d first, then confirm at least one in-scope host. "
        + "There is no free-text target field on purpose: that is what let a program "
        + "page become the target.", "err");
    }
  }, true);
})();
