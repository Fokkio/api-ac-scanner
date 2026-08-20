// api-ac-scanner front-end glue. Vanilla JS only — no framework.
(function () {
  "use strict";

  // Wire up "Preview fix" buttons (event delegation).
  document.addEventListener("click", async function (e) {
    const btn = e.target.closest('[data-act="preview"]');
    if (!btn) return;
    e.preventDefault();
    const scan = btn.getAttribute("data-scan");
    const rule = btn.getAttribute("data-rule");
    const file = btn.getAttribute("data-file");
    const panelId = "fix-" + btn.getAttribute("data-rule") + "-" + scan;
    let panel = btn.parentElement.parentElement.querySelector(".fix-panel");
    if (!panel) return;
    panel.hidden = false;
    panel.innerHTML = "<p class='muted'>Generating preview…</p>";

    try {
      const resp = await fetch("/api/fix/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: scan, ruleId: rule, file: file }),
      });
      const data = await resp.json();
      if (data.error) {
        panel.innerHTML = "<p class='muted'>" + escapeHtml(data.error) + "</p>";
        return;
      }
      panel.innerHTML = renderFixPanel(data, scan, rule, file);
      wireApply(panel, scan, rule, file);
    } catch (err) {
      panel.innerHTML = "<p class='muted'>Preview failed: " + escapeHtml(String(err)) + "</p>";
    }
  });

  function renderFixPanel(d, scan, rule, file) {
    const changes = (d.changes || [])
      .map((c) => "<li>" + escapeHtml(c) + "</li>")
      .join("");
    return (
      "<h4>Proposed fix for " + escapeHtml(rule) + "</h4>" +
      (changes ? "<ul class='muted'>" + changes + "</ul>" : "") +
      "<div class='diff'>" + diffHtml(d.original, d.fixed) + "</div>" +
      "<div style='margin-top:12px;display:flex;gap:8px'>" +
      "<button class='btn btn-primary btn-sm' data-act='apply'>Apply to my copy</button>" +
      "<span class='muted' style='align-self:center;font-size:12px'>(safe: your original is untouched until you click)</span>" +
      "</div>"
    );
  }

  function wireApply(panel, scan, rule, file) {
    const apply = panel.querySelector('[data-act="apply"]');
    if (!apply) return;
    apply.addEventListener("click", async function () {
      apply.disabled = true;
      apply.textContent = "Applying…";
      try {
        const resp = await fetch("/api/fix/apply", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scanId: scan, ruleId: rule, file: file }),
        });
        const data = await resp.json();
        if (data.ok) {
          panel.innerHTML = "<p class='muted'>✓ Fix applied to your uploaded copy.</p>";
        } else {
          panel.innerHTML = "<p class='muted'>Apply failed: " + escapeHtml(JSON.stringify(data)) + "</p>";
        }
      } catch (err) {
        panel.innerHTML = "<p class='muted'>Apply failed: " + escapeHtml(String(err)) + "</p>";
      }
    });
  }

  function diffHtml(orig, fixed) {
    const o = orig.split("\n");
    const f = fixed.split("\n");
    let html = "";
    let i = 0,
      j = 0;
    // simple line diff (LCS-free): show removed then added context
    const set = new Set(o);
    while (i < o.length && j < f.length) {
      if (o[i] === f[j]) {
        html += escapeHtml(o[i]) + "\n";
        i++;
        j++;
      } else if (set.has(f[j])) {
        html += "<span class='del'>- " + escapeHtml(o[i]) + "</span>\n";
        i++;
      } else {
        html += "<span class='add'>+ " + escapeHtml(f[j]) + "</span>\n";
        j++;
      }
    }
    while (i < o.length) {
      html += "<span class='del'>- " + escapeHtml(o[i]) + "</span>\n";
      i++;
    }
    while (j < f.length) {
      html += "<span class='add'>+ " + escapeHtml(f[j]) + "</span>\n";
      j++;
    }
    return html;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
})();
