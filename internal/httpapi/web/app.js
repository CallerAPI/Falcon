/* Falcon dashboard. Vanilla JS, no build step, one file. */
(function () {
  "use strict";

  // ---------- state ----------
  const qsToken = new URLSearchParams(location.search).get("token");
  if (qsToken) localStorage.setItem("falcon_token", qsToken);
  const token = localStorage.getItem("falcon_token") || "";

  const state = {
    view: "overview",
    range: localStorage.getItem("falcon_range") || "24h",
    live: false,
    q: "",
    traffic: { action: "", verstat: "", rows: [], next: 0, loading: false },
    drawer: { ev: null, tab: "summary" },
    status: null,
    sse: null,
    timers: [],
  };

  // ---------- helpers ----------
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const esc = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const fmtN = (n) => (n == null ? "0" : Number(n).toLocaleString());
  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
  const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));

  function headers(extra) {
    const h = Object.assign({ Accept: "application/json" }, extra || {});
    if (token) h["X-Falcon-Token"] = token;
    return h;
  }
  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: headers(opts && opts.body ? { "Content-Type": "application/json" } : {}) }, opts || {}));
    if (!res.ok) {
      let msg = res.status + " " + res.statusText;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    return res.json();
  }
  const get = (p) => api(p);
  const post = (p, body) => api(p, { method: "POST", body: JSON.stringify(body) });
  const put = (p, body) => api(p, { method: "PUT", body: JSON.stringify(body) });
  const del = (p) => api(p, { method: "DELETE" });

  function toast(msg, kind) {
    const el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.textContent = msg;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), 3800);
  }

  function timeAgo(iso) {
    if (!iso) return "";
    const d = (Date.now() - new Date(iso).getTime()) / 1000;
    if (d < 60) return Math.max(0, Math.round(d)) + "s ago";
    if (d < 3600) return Math.round(d / 60) + "m ago";
    if (d < 86400) return Math.round(d / 3600) + "h ago";
    return Math.round(d / 86400) + "d ago";
  }
  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    const pad = (n) => String(n).padStart(2, "0");
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function fmtDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + fmtTime(iso);
  }
  function rangeLabel(r) {
    return { "15m": "last 15 minutes", "1h": "last hour", "6h": "last 6 hours", "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days" }[r] || r;
  }

  const pill = (a) => '<span class="pill ' + esc(a) + '">' + esc(a) + "</span>";
  function scoreCell(score, action) {
    return '<span class="score ' + esc(action) + '"><span class="bar"><i style="width:' + clamp(score, 0, 100) + '%"></i></span><span class="mono num">' + esc(score) + "</span></span>";
  }
  function certDate(iso) {
    return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function errorsCard(sh) {
    return sh.errors && sh.errors.length ? '<div class="card" style="border-color:rgba(239,68,68,0.35)"><h2 style="margin-bottom:6px">Errors</h2>' + sh.errors.map((e) => '<div class="small mono">' + esc(e) + "</div>").join("") + "</div>" : "";
  }
  function signerCard(sh) {
    const s = sh.signer || {};
    return '<div class="card"><h2 style="margin-bottom:8px">Signer</h2><dl class="kv"><dt>SPC</dt><dd>' + esc(s.spc || "—") + "</dd><dt>organization</dt><dd>" + esc(s.org || "—") + "</dd><dt>common name</dt><dd>" + esc(s.cn || "—") + "</dd><dt>issuer</dt><dd>" + esc(s.issuer || "—") + "</dd><dt>serial</dt><dd>" + esc(s.serial || "—") + "</dd><dt>valid</dt><dd>" + esc(s.not_before ? certDate(s.not_before) + " → " + certDate(s.not_after) : "—") + "</dd><dt>x5u</dt><dd>" + esc(sh.x5u || "—") + "</dd></dl></div>";
  }
  function verstatChip(v, attest, source) {
    if (source === "switch") return '<span class="chip" title="The switch signs this call after Falcon screens it">switch signs' + (attest ? " · " + esc(attest) : "") + "</span>";
    if (!v && !attest) return '<span class="chip dim">no shaken</span>';
    let cls = "dim";
    let label = v || "unverified";
    if (v === "TN-Validation-Passed") { cls = "ok"; label = "verified"; }
    else if (v === "TN-Validation-Failed") { cls = "bad"; label = "failed"; }
    else if (v === "No-TN-Validation") { cls = "warn"; label = "no validation"; }
    return '<span class="chip ' + cls + '">' + esc(label) + (attest ? " · " + esc(attest) : "") + "</span>";
  }
  function reasonChips(reasons, max) {
    const rs = (reasons || []).filter((r) => r.weight > 0 || (reasons || []).length === 1);
    const shown = rs.slice(0, max || 3).map((r) => '<span class="chip">' + esc(r.code) + "</span>").join("");
    const more = rs.length > (max || 3) ? '<span class="chip dim">+' + (rs.length - (max || 3)) + "</span>" : "";
    return shown + more;
  }
  function empty(text, cmd) {
    return '<div class="empty">' + esc(text) + (cmd ? "<code>" + esc(cmd) + "</code>" : "") + "</div>";
  }

  // ---------- charts ----------
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  document.body.appendChild(tip);

  function setupCanvas(c) {
    const dpr = window.devicePixelRatio || 1;
    const rect = c.getBoundingClientRect();
    c.width = Math.max(1, Math.round(rect.width * dpr));
    c.height = Math.max(1, Math.round(rect.height * dpr));
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w: rect.width, h: rect.height };
  }
  const colors = { allow: "#34c26b", flag: "#e0a326", challenge: "#d97706", reject: "#ef4444", accent: "#6366f1", line: "#222836", muted: "#8a92a6" };

  function drawStacked(c, series, stepSeconds) {
    if (!c) return;
    const { ctx, w, h } = setupCanvas(c);
    ctx.clearRect(0, 0, w, h);
    const padL = 36, padR = 8, padT = 10, padB = 26;
    const n = series.length;
    if (!n) return;
    const max = Math.max(1, ...series.map((b) => b.count));
    const innerW = w - padL - padR, innerH = h - padT - padB;
    const bw = innerW / n;
    ctx.strokeStyle = colors.line;
    ctx.lineWidth = 1;
    ctx.fillStyle = colors.muted;
    ctx.font = "11px ui-monospace, Menlo, monospace";
    ctx.textAlign = "right";
    for (let g = 0; g <= 3; g++) {
      const y = padT + innerH - (innerH * g) / 3;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
      ctx.fillText(fmtN(Math.round((max * g) / 3)), padL - 6, y + 4);
    }
    const bars = [];
    series.forEach((b, i) => {
      const x = padL + i * bw;
      let y = padT + innerH;
      const parts = [["allow", b.allow], ["flag", b.flag], ["challenge", b.challenge], ["reject", b.reject]];
      parts.forEach(([k, v]) => {
        if (!v) return;
        const hh = (v / max) * innerH;
        ctx.fillStyle = colors[k];
        ctx.fillRect(x + Math.max(1, bw * 0.12), y - hh, Math.max(1, bw * 0.76), hh);
        y -= hh;
      });
      bars.push({ x, x2: x + bw, b });
    });
    ctx.fillStyle = colors.muted;
    ctx.textAlign = "center";
    const labels = Math.min(8, n);
    for (let i = 0; i < labels; i++) {
      const idx = Math.round((i * (n - 1)) / Math.max(1, labels - 1));
      const b = series[idx];
      if (!b) continue;
      const d = new Date(b.ts);
      const label = stepSeconds >= 86400 ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) : (stepSeconds >= 3600 ? d.toLocaleDateString(undefined, { weekday: "short" }) + " " + fmtTime(b.ts).slice(0, 5) : fmtTime(b.ts).slice(0, 5));
      ctx.fillText(label, padL + idx * bw + bw / 2, h - 8);
    }
    c.onmousemove = (e) => {
      const r = c.getBoundingClientRect();
      const x = e.clientX - r.left;
      const hit = bars.find((bb) => x >= bb.x && x < bb.x2);
      if (!hit) { tip.hidden = true; return; }
      const b = hit.b;
      tip.innerHTML = "<div class='muted'>" + esc(fmtDate(b.ts)) + "</div><div><b>" + fmtN(b.count) + "</b> requests · avg " + Math.round(b.avg_score || 0) + "</div>" +
        "<div style='color:" + colors.reject + "'>reject " + fmtN(b.reject) + "</div><div style='color:" + colors.flag + "'>flag " + fmtN(b.flag) + " · challenge " + fmtN(b.challenge) + "</div><div style='color:" + colors.allow + "'>allow " + fmtN(b.allow) + "</div>";
      tip.hidden = false;
      tip.style.left = Math.min(window.innerWidth - 220, e.clientX + 14) + "px";
      tip.style.top = e.clientY + 14 + "px";
    };
    c.onmouseleave = () => { tip.hidden = true; };
  }

  function drawHistogram(c, buckets, thresholds) {
    if (!c) return;
    const { ctx, w, h } = setupCanvas(c);
    ctx.clearRect(0, 0, w, h);
    const padL = 36, padR = 8, padT = 22, padB = 26;
    const max = Math.max(1, ...buckets);
    const innerW = w - padL - padR, innerH = h - padT - padB;
    const bw = innerW / 10;
    ctx.font = "11px ui-monospace, Menlo, monospace";
    buckets.forEach((v, i) => {
      const lo = i * 10;
      let color = colors.allow;
      if (lo >= thresholds.reject) color = colors.reject;
      else if (lo >= thresholds.challenge) color = colors.challenge;
      else if (lo >= thresholds.flag) color = colors.flag;
      const hh = (v / max) * innerH;
      ctx.fillStyle = color;
      ctx.fillRect(padL + i * bw + 4, padT + innerH - hh, bw - 8, hh);
      ctx.fillStyle = colors.muted;
      ctx.textAlign = "center";
      ctx.fillText(lo + "", padL + i * bw + bw / 2, h - 8);
      if (v) ctx.fillText(fmtN(v), padL + i * bw + bw / 2, padT + innerH - hh - 4);
    });
    [["flag", thresholds.flag], ["challenge", thresholds.challenge], ["reject", thresholds.reject]].forEach(([k, t]) => {
      const x = padL + (t / 100) * innerW;
      ctx.strokeStyle = colors[k];
      ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + innerH); ctx.stroke();
      ctx.setLineDash([]);
    });
  }

  // ---------- router ----------
  const titles = {
    overview: ["Overview", "What the switch saw"],
    traffic: ["Traffic", "Every screened request"],
    signers: ["Signers", "Who attested the calls (STIR/SHAKEN SPC)"],
    providers: ["Providers", "Where the SIP came from"],
    lists: ["Lists", "Your allow and deny rules"],
    tuning: ["Tuning", "Where the thresholds sit against real traffic"],
    system: ["System", "Trust, feeds, storage, and configuration"],
    plugins: ["Plugins", "Granted extensions"],
  };

  function navigate() {
    const hash = (location.hash || "#overview").slice(1);
    const [view, param] = hash.split("?");
    state.view = titles[view] ? view : "overview";
    $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === state.view));
    $("#viewTitle").textContent = titles[state.view][0];
    $("#viewHint").textContent = titles[state.view][1] + " · " + rangeLabel(state.range);
    if (param) {
      const p = new URLSearchParams(param);
      state.q = p.get("q") || "";
      $("#search").value = state.q;
      state.traffic.action = p.get("action") || "";
      state.traffic.verstat = p.get("verstat") || "";
    }
    render();
  }
  window.addEventListener("hashchange", navigate);

  function render() {
    state.timers.forEach(clearTimeout);
    state.timers = [];
    const v = $("#view");
    v.innerHTML = "";
    $("#search").placeholder = state.view === "plugins" ? "Search a number" : "Search number, IP, Call-ID, signer  ( / )";
    ({ overview: renderOverview, traffic: renderTraffic, signers: renderSigners, providers: renderProviders, lists: renderLists, tuning: renderTuning, system: renderSystem, plugins: renderPlugins })[state.view](v);
  }
  function schedule(fn, ms) { state.timers.push(setTimeout(fn, ms)); }

  // ---------- overview ----------
  async function renderOverview(v) {
    v.innerHTML = '<article class="card" id="valueCard" style="margin-bottom:14px"><div class="valuecard"><div class="lead muted">Loading what Falcon did…</div></div></article>' +
      '<section class="grid kpis" id="kpis"></section>' +
      '<section class="grid wide-narrow"><article class="card fill"><header><h2>Volume by decision</h2><span class="hint" id="chartHint"></span></header><canvas class="chart" id="chart"></canvas>' +
      '<div class="legend"><span><i style="background:' + colors.allow + '"></i>allow</span><span><i style="background:' + colors.flag + '"></i>flag</span><span><i style="background:' + colors.challenge + '"></i>challenge</span><span><i style="background:' + colors.reject + '"></i>reject</span></div></article>' +
      '<article class="card"><header><h2>Why calls were held</h2><span class="hint">top reasons</span></header><div class="rank" id="topReasons"></div></article></section>' +
      '<section class="grid three"><article class="card"><header><h2>Signers</h2><a class="hint" href="#signers">all →</a></header><div class="rank" id="topSigners"></div></article>' +
      '<article class="card"><header><h2>Providers</h2><a class="hint" href="#providers">all →</a></header><div class="rank" id="topProviders"></div></article>' +
      '<article class="card"><header><h2>Source IPs</h2><a class="hint" href="#providers">all →</a></header><div class="rank" id="topIps"></div></article></section>' +
      '<section class="grid three" id="addons"></section>';
    try {
      const [stats, status, value] = await Promise.all([get("/v1/stats?range=" + state.range), get("/v1/status"), get("/v1/value?range=" + state.range)]);
      renderValueCard($("#valueCard"), value);
      state.status = status;
      const total = stats.total || 0;
      const rej = (stats.by_action && stats.by_action.reject) || 0;
      const flag = ((stats.by_action && stats.by_action.flag) || 0) + ((stats.by_action && stats.by_action.challenge) || 0);
      const passed = (stats.by_verstat && stats.by_verstat["TN-Validation-Passed"]) || 0;
      const failed = (stats.by_verstat && stats.by_verstat["TN-Validation-Failed"]) || 0;
      const attC = (stats.by_attest && stats.by_attest.C) || 0;
      const signed = Object.keys(stats.by_attest || {}).filter((k) => k !== "none").reduce((a, k) => a + stats.by_attest[k], 0);
      $("#kpis").innerHTML = [
        ["Requests", fmtN(total), rangeLabel(state.range), ""],
        ["Rejected", fmtN(rej), pct(rej, total) + "% of requests", "hot"],
        ["Held", fmtN(flag), "flag + challenge", ""],
        ["Avg score", (stats.avg_score || 0).toFixed(1), "0 to 100", ""],
        ["Verified", fmtN(passed), failed ? fmtN(failed) + " failed" : "PASSporT passed", passed ? "ok" : ""],
        ["Attestation C", signed ? pct(attC, signed) + "%" : "—", signed ? fmtN(attC) + " of " + fmtN(signed) + " signed" : "no signed calls", attC ? "accent" : ""],
      ].map(([l, b, s, cls]) => '<article class="card kpi ' + cls + '"><label>' + l + "</label><b>" + b + '</b><div class="sub">' + esc(s) + "</div></article>").join("");
      $("#chartHint").textContent = fmtN(stats.timeseries.length) + " buckets · " + (stats.step_seconds >= 3600 ? stats.step_seconds / 3600 + "h" : stats.step_seconds / 60 + "m") + " each";
      drawStacked($("#chart"), stats.timeseries || [], stats.step_seconds);
      renderRank($("#topReasons"), stats.top_reasons, (r) => "#traffic?q=" + encodeURIComponent(r.name));
      renderRank($("#topSigners"), stats.top_signers, (r) => "#traffic?q=" + encodeURIComponent(r.name));
      renderRank($("#topProviders"), stats.top_providers, (r) => "#traffic?q=" + encodeURIComponent(r.name));
      renderRank($("#topIps"), stats.top_ips, (r) => "#traffic?q=" + encodeURIComponent(r.name));
      renderAddons($("#addons"), status);
      if (total === 0) {
        $("#chart").parentElement.insertAdjacentHTML("beforeend", empty("No SIP yet. Point a switch at the screen endpoint.", "curl -X POST " + location.origin + "/v1/screen -H 'X-Falcon-Token: …' -d @invite.json"));
      }
    } catch (e) {
      v.insertAdjacentHTML("afterbegin", '<div class="card">' + esc(e.message) + "</div>");
    }
    schedule(() => state.view === "overview" && renderOverview(v), 15000);
  }

  function renderRank(el, rows, href) {
    if (!el) return;
    if (!rows || !rows.length) { el.innerHTML = '<div class="muted small">none yet</div>'; return; }
    const max = Math.max(...rows.map((r) => r.count));
    el.innerHTML = rows.map((r) => '<a class="r clickable" href="' + esc(href(r)) + '"><span class="name" title="' + esc(r.name) + '">' + esc(r.name) + '</span><span class="mono num">' + fmtN(r.count) + '</span><span class="bar"><i style="width:' + Math.round((r.count / max) * 100) + '%"></i></span></a>').join("");
  }

  function renderAddons(el, status) {
    const feed = status.spam_feed || {}, fw = status.voice_firewall || {}, ip = status.ip_intel || {}, sh = status.shaken || {}, tr = (sh.trust || {});
    const cards = [
      { title: "STIR/SHAKEN trust", on: !!sh.enabled && tr.roots > 0, bad: !!sh.enabled && !(tr.roots > 0), body: sh.enabled ? (tr.roots ? tr.roots + " STI-CA roots · " + fmtN(tr.revoked) + " revoked · " + fmtN(sh.cached_chains) + " chains cached" : "roots not loaded" + (tr.roots_error ? ": " + tr.roots_error : "")) : "Verification is off (FALCON_SHAKEN=false).", href: "#system" },
      { title: "Telecom IP intel", on: !!ip.configured && ip.count > 0, bad: !!ip.configured && !!ip.error, body: ip.configured ? fmtN(ip.count) + " CIDR blocks" + (ip.error ? " · " + ip.error : "") : "Name the provider behind every source IP. Set FALCON_IP_INTEL_FILE or connect the hosted table.", href: ip.configured ? "#providers" : (feed.upsell_url || "#") },
      { title: "Spam database feed", on: !!feed.configured && feed.count > 0, bad: !!feed.configured && !!feed.error, body: feed.configured ? fmtN(feed.count) + " numbers loaded" + (feed.error ? " · " + feed.error : "") : "Drop listed spam DIDs at the switch with a CallerAPI key.", href: feed.upsell_url || "#" },
    ];
    el.innerHTML = cards.map((c) => '<a class="card status-card" href="' + esc(c.href) + '"' + (c.href.startsWith("http") ? ' target="_blank" rel="noreferrer"' : "") + '><div class="title"><h2>' + esc(c.title) + '</h2><span class="state ' + (c.bad ? "bad" : c.on ? "on" : "off") + '">' + (c.bad ? "attention" : c.on ? "active" : "off") + '</span></div><div class="muted small">' + esc(c.body) + "</div></a>").join("");
  }

  // ---------- traffic ----------
  function trafficRow(ev, isNew) {
    return '<tr class="row' + (isNew ? " new" : "") + '" data-id="' + ev.id + '">' +
      '<td class="mono muted" title="' + esc(ev.received_at) + '">' + esc(fmtTime(ev.received_at)) + "</td>" +
      "<td>" + pill(ev.action) + "</td>" +
      "<td>" + scoreCell(ev.risk_score, ev.action) + "</td>" +
      '<td class="mono">' + esc(ev.from) + "</td>" +
      '<td class="mono">' + esc(ev.to) + "</td>" +
      '<td class="mono nowrap">' + esc(ev.source_ip) + (ev.provider ? '<span class="sub" title="' + esc(ev.provider) + '">' + esc(ev.provider) + "</span>" : "") + "</td>" +
      '<td class="nowrap">' + (ev.signer_spc ? '<span class="chip">' + esc(ev.signer_spc) + "</span>" + (ev.signer_name ? '<span class="sub" title="' + esc(ev.signer_name) + '">' + esc(ev.signer_name) + "</span>" : "") : '<span class="muted">—</span>') + "</td>" +
      "<td>" + verstatChip(ev.verstat, ev.shaken_attest, ev.shaken && ev.shaken.source) + "</td>" +
      "<td>" + reasonChips(ev.reasons, 3) + "</td></tr>";
  }

  async function renderTraffic(v) {
    const t = state.traffic;
    v.innerHTML = '<div class="toolbar">' +
      '<select id="fAction"><option value="">all decisions</option><option>allow</option><option>flag</option><option>challenge</option><option>reject</option></select>' +
      '<select id="fVerstat"><option value="">any verification</option><option value="TN-Validation-Passed">verified</option><option value="TN-Validation-Failed">failed</option><option value="No-TN-Validation">no validation</option></select>' +
      '<span class="spacer"></span><span class="muted small" id="tCount"></span>' +
      '<a class="btn sm" id="csvBtn" href="#">Export CSV</a></div>' +
      '<article class="card" style="padding:0"><div class="table-wrap"><table><thead><tr><th>time</th><th>decision</th><th>score</th><th>from</th><th>to</th><th>source</th><th>signer</th><th>shaken</th><th>reasons</th></tr></thead><tbody id="rows"></tbody></table></div>' +
      '<div style="padding:12px;text-align:center"><button class="btn" id="moreBtn">Load more</button></div></article>';
    $("#fAction").value = t.action;
    $("#fVerstat").value = t.verstat;
    const csvHref = () => "/v1/events.csv?range=" + state.range + (t.action ? "&action=" + t.action : "") + (t.verstat ? "&verstat=" + t.verstat : "") + (state.q ? "&q=" + encodeURIComponent(state.q) : "") + (token ? "&token=" + encodeURIComponent(token) : "");
    $("#csvBtn").href = csvHref();
    $("#fAction").onchange = (e) => { t.action = e.target.value; loadTraffic(true); $("#csvBtn").href = csvHref(); };
    $("#fVerstat").onchange = (e) => { t.verstat = e.target.value; loadTraffic(true); $("#csvBtn").href = csvHref(); };
    $("#moreBtn").onclick = () => loadTraffic(false);
    $("#rows").onclick = (e) => { const tr = e.target.closest("tr.row"); if (tr) openEvent(tr.dataset.id); };
    await loadTraffic(true);
  }

  async function loadTraffic(reset) {
    const t = state.traffic;
    if (t.loading) return;
    t.loading = true;
    try {
      const params = new URLSearchParams({ range: state.range, limit: "100" });
      if (t.action) params.set("action", t.action);
      if (t.verstat) params.set("verstat", t.verstat);
      if (state.q) params.set("q", state.q);
      if (!reset && t.next) params.set("before", String(t.next));
      const res = await get("/v1/events?" + params.toString());
      const rows = res.data || [];
      t.rows = reset ? rows : t.rows.concat(rows);
      t.next = res.next_before || 0;
      const body = $("#rows");
      if (!body) return;
      if (!t.rows.length) {
        body.innerHTML = '<tr><td colspan="9">' + empty(state.q || t.action || t.verstat ? "Nothing matches these filters in " + rangeLabel(state.range) + "." : "No SIP yet in " + rangeLabel(state.range) + ". Point a switch at POST /v1/screen.") + "</td></tr>";
      } else if (reset) {
        body.innerHTML = t.rows.map((ev) => trafficRow(ev, false)).join("");
      } else {
        body.insertAdjacentHTML("beforeend", rows.map((ev) => trafficRow(ev, false)).join(""));
      }
      $("#tCount").textContent = fmtN(t.rows.length) + " shown";
      $("#moreBtn").disabled = rows.length < 100;
    } catch (e) {
      toast(e.message, "bad");
    } finally {
      t.loading = false;
    }
  }

  // ---------- signers and providers ----------
  function attestMini(p) {
    const tot = (p.attest_a + p.attest_b + p.attest_c) || 1;
    return '<span class="mini" title="A ' + p.attest_a + " · B " + p.attest_b + " · C " + p.attest_c + '"><i class="a" style="width:' + pct(p.attest_a, tot) + '%"></i><i class="b" style="width:' + pct(p.attest_b, tot) + '%"></i><i class="c" style="width:' + pct(p.attest_c, tot) + '%"></i></span>';
  }
  function networkCell(p) {
    if (!p.network_score) return '<span class="muted">—</span>';
    const c = p.network_score >= 80 ? colors.reject : p.network_score >= 50 ? colors.flag : "inherit";
    return '<span style="color:' + c + '" title="' + esc(p.network_installs) + ' installs">' + esc(p.network_score) + "</span>";
  }
  function partyActions(subject, value) {
    return '<button class="btn sm danger" data-act="deny" data-subject="' + esc(subject) + '" data-value="' + esc(value) + '">Deny</button> ' +
      '<button class="btn sm" data-act="allow" data-subject="' + esc(subject) + '" data-value="' + esc(value) + '">Allow</button>';
  }
  function bindPartyActions(root) {
    root.onclick = async (e) => {
      const b = e.target.closest("button[data-act]");
      if (b) {
        e.stopPropagation();
        await addRule(b.dataset.act, b.dataset.subject, b.dataset.value, "from dashboard");
        return;
      }
      const tr = e.target.closest("tr.row");
      if (tr && tr.dataset.q) location.hash = "#traffic?q=" + encodeURIComponent(tr.dataset.q);
    };
  }

  async function renderSigners(v) {
    v.innerHTML = '<article class="card" style="padding:0"><div class="table-wrap"><table><thead><tr><th>SPC</th><th>signer</th><th class="right">calls</th><th class="right">reject %</th><th class="right">avg</th><th>attestation</th><th class="right">verified</th><th class="right">failed</th><th class="right">callers</th><th class="right" title="score across every sharing install on the CallerAPI network">network</th><th>last seen</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></article>' +
      '<p class="muted small">The SPC is the Service Provider Code in the signing certificate. It names the provider that attested the call. A deny on an SPC rejects every call that provider signs, whatever number it shows. The network column is what every sharing install has seen of that signer in the last 7 days; a dash means no feed or no row.</p>';
    try {
      const res = await get("/v1/parties?by=signer&range=" + state.range + "&limit=200");
      const rows = res.data || [];
      $("#rows").innerHTML = rows.length ? rows.map((p) => '<tr class="row" data-q="' + esc(p.name) + '"><td class="mono">' + esc(p.name) + "</td><td>" + esc(p.label || "—") + '</td><td class="right mono num">' + fmtN(p.total) + '</td><td class="right mono num" style="color:' + (pct(p.reject, p.total) > 20 ? colors.reject : "inherit") + '">' + pct(p.reject, p.total) + '%</td><td class="right mono num">' + Math.round(p.avg_score) + "</td><td>" + attestMini(p) + '</td><td class="right mono num">' + fmtN(p.verstat_passed) + '</td><td class="right mono num">' + fmtN(p.verstat_failed) + '</td><td class="right mono num">' + fmtN(p.distinct_from) + '</td><td class="right mono num">' + networkCell(p) + '</td><td class="muted small">' + esc(timeAgo(p.last_seen)) + "</td><td>" + partyActions("spc", p.name) + ' <a class="btn sm" title="traceback pack: events, raw INVITEs, signer certificates" href="/v1/traceback.zip?spc=' + encodeURIComponent(p.name) + '&range=' + state.range + (token ? "&token=" + encodeURIComponent(token) : "") + '">Pack</a></td></tr>').join("") :
        '<tr><td colspan="12">' + empty("No signed calls in " + rangeLabel(state.range) + ". Signers appear once an INVITE carries an Identity header.") + "</td></tr>";
      bindPartyActions($("#rows"));
    } catch (e) { toast(e.message, "bad"); }
  }

  async function renderProviders(v) {
    v.innerHTML = '<section class="grid two">' +
      '<article class="card" style="padding:0"><header style="padding:14px 18px 0"><h2>Providers from IP intel</h2></header><div class="table-wrap"><table><thead><tr><th>provider</th><th class="right">calls</th><th class="right">reject %</th><th class="right">avg</th><th class="right">callers</th><th>last seen</th></tr></thead><tbody id="provRows"></tbody></table></div></article>' +
      '<article class="card" style="padding:0"><header style="padding:14px 18px 0"><h2>Source IPs</h2></header><div class="table-wrap"><table><thead><tr><th>ip</th><th>provider</th><th class="right">calls</th><th class="right">reject %</th><th class="right">callers</th><th>last seen</th><th></th></tr></thead><tbody id="ipRows"></tbody></table></div></article></section>';
    try {
      const [prov, ips] = await Promise.all([get("/v1/parties?by=provider&range=" + state.range + "&limit=200"), get("/v1/parties?by=ip&range=" + state.range + "&limit=200")]);
      const pr = prov.data || [], ir = ips.data || [];
      $("#provRows").innerHTML = pr.length ? pr.map((p) => '<tr class="row" data-q="' + esc(p.name) + '"><td>' + esc(p.name) + '</td><td class="right mono num">' + fmtN(p.total) + '</td><td class="right mono num">' + pct(p.reject, p.total) + '%</td><td class="right mono num">' + Math.round(p.avg_score) + '</td><td class="right mono num">' + fmtN(p.distinct_from) + '</td><td class="muted small">' + esc(timeAgo(p.last_seen)) + "</td></tr>").join("") :
        '<tr><td colspan="6">' + empty((state.status && state.status.ip_intel && state.status.ip_intel.configured) ? "No source IP matched the table in " + rangeLabel(state.range) + "." : "No IP intel table loaded. Set FALCON_IP_INTEL_FILE to a CSV of cidr,provider,risk.") + "</td></tr>";
      $("#ipRows").innerHTML = ir.length ? ir.map((p) => '<tr class="row" data-q="' + esc(p.name) + '"><td class="mono">' + esc(p.name) + "</td><td>" + esc(p.label || "—") + '</td><td class="right mono num">' + fmtN(p.total) + '</td><td class="right mono num" style="color:' + (pct(p.reject, p.total) > 20 ? colors.reject : "inherit") + '">' + pct(p.reject, p.total) + '%</td><td class="right mono num">' + fmtN(p.distinct_from) + '</td><td class="muted small">' + esc(timeAgo(p.last_seen)) + "</td><td>" + partyActions("ip", p.name) + "</td></tr>").join("") :
        '<tr><td colspan="7">' + empty("No traffic in " + rangeLabel(state.range) + ".") + "</td></tr>";
      bindPartyActions($("#provRows"));
      bindPartyActions($("#ipRows"));
    } catch (e) { toast(e.message, "bad"); }
  }

  // ---------- lists ----------
  async function addRule(kind, subject, value, note, ttl) {
    try {
      const r = await post("/v1/rules", { kind, subject, value, note: note || "", ttl: ttl || "" });
      toast(kind + " rule saved for " + subject + " " + r.value, "ok");
      if (state.view === "lists") renderLists($("#view"));
      return r;
    } catch (e) {
      toast(e.message, "bad");
    }
  }

  async function renderLists(v) {
    v.innerHTML = '<article class="card"><header><h2>Add a rule</h2><span class="hint">deny is a hard reject · allow ends scoring</span></header>' +
      '<form class="form" id="ruleForm"><label>kind<select name="kind"><option>deny</option><option>allow</option><option value="honeypot">honeypot (unassigned number)</option></select></label>' +
      '<label>subject<select name="subject"><option value="number">number</option><option value="ip">ip or cidr</option><option value="spc">signer SPC</option></select></label>' +
      '<label>value<input name="value" type="text" placeholder="+14155550100 · 203.0.113.0/24 · 1234" required></label>' +
      '<label>note<input name="note" type="text" placeholder="why"></label>' +
      '<label>expires<select name="ttl"><option value="">never</option><option value="1h">1 hour</option><option value="24h">24 hours</option><option value="168h">7 days</option><option value="720h">30 days</option></select></label>' +
      '<button class="btn primary" type="submit">Save</button></form></article>' +
      '<article class="card" style="padding:0"><div class="table-wrap"><table><thead><tr><th>kind</th><th>subject</th><th>value</th><th>note</th><th>created</th><th>expires</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></article>' +
      '<article class="card"><header><h2>Customers and the numbers they may present</h2><span class="hint">outbound calls from a customer with another caller id are rejected and paged</span></header>' +
      '<form class="form" id="custForm" style="grid-template-columns:1fr 1fr 2fr auto"><label>account id<input name="id" type="text" placeholder="acme" required></label><label>name<input name="name" type="text" placeholder="Acme Dialer"></label>' +
      '<label>numbers, comma separated, prefixes end with *<input name="dids" type="text" placeholder="+13125550100, +1312555*"></label><button class="btn primary" type="submit">Save</button></form>' +
      '<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>account</th><th>name</th><th>numbers</th><th class="right">calls 24h</th><th class="right">rejects</th><th class="right">ASR</th><th class="right">ACD</th><th></th></tr></thead><tbody id="custRows"></tbody></table></div>' +
      '<p class="muted small">Honeypot rules above list your unassigned numbers or prefixes. A call to one is unsolicited by definition and is one of the ways new spam numbers are found.</p></article>';
    $("#custForm").onsubmit = async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      const dids = String(f.get("dids") || "").split(",").map((x) => x.trim()).filter(Boolean);
      try {
        await api("/v1/customers", { method: "PUT", body: JSON.stringify({ id: f.get("id"), name: f.get("name"), dids }) });
        toast("customer saved", "ok"); renderLists(v);
      } catch (err) { toast(err.message, "bad"); }
    };
    try {
      const cres = await get("/v1/customers");
      const custs = cres.data || [];
      const rowsHtml = await Promise.all(custs.map(async (c) => {
        let act = {}, asr = 0, acd = 0;
        try { const d = await get("/v1/customers/" + encodeURIComponent(c.id)); act = d.last_24h || {}; asr = d.asr || 0; acd = d.acd || 0; } catch (_) {}
        return '<tr><td class="mono">' + esc(c.id) + "</td><td>" + esc(c.name || "—") + '</td><td class="mono small">' + esc((c.dids || []).join(", ") || "none: every caller id is accepted") + '</td><td class="right mono num">' + fmtN(act.calls || 0) + '</td><td class="right mono num" style="color:' + ((act.rejects || 0) > 0 ? colors.reject : "inherit") + '">' + fmtN(act.rejects || 0) + '</td><td class="right mono num">' + (act.completed ? asr + "%" : "—") + '</td><td class="right mono num">' + (act.answered ? acd + "s" : "—") + '</td><td><a class="btn sm" href="#traffic?q=' + encodeURIComponent(c.id) + '">Calls</a> <button class="btn sm ghost danger" data-cust="' + esc(c.id) + '">Remove</button></td></tr>';
      }));
      $("#custRows").innerHTML = rowsHtml.length ? rowsHtml.join("") : '<tr><td colspan="8">' + empty("No customers yet. Register each account and the numbers it may present; outbound calls then carry the account and a foreign caller id is rejected.") + "</td></tr>";
      $("#custRows").onclick = async (e) => {
        const b = e.target.closest("button[data-cust]");
        if (!b) return;
        try { await del("/v1/customers/" + encodeURIComponent(b.dataset.cust)); toast("customer removed", "ok"); renderLists(v); } catch (err) { toast(err.message, "bad"); }
      };
    } catch (e) { toast(e.message, "bad"); }
    $("#ruleForm").onsubmit = async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      await addRule(f.get("kind"), f.get("subject"), f.get("value"), f.get("note"), f.get("ttl"));
      e.target.reset();
    };
    try {
      const res = await get("/v1/rules");
      const rows = res.data || [];
      $("#rows").innerHTML = rows.length ? rows.map((r) => "<tr><td>" + (r.kind === "honeypot" ? '<span class="pill flag">honeypot</span>' : pill(r.kind === "deny" ? "reject" : "allow").replace(">reject<", ">deny<").replace(">allow<", ">allow<")) + '</td><td class="muted">' + esc(r.subject) + '</td><td class="mono">' + esc(r.value) + "</td><td>" + esc(r.note || "") + '</td><td class="muted small">' + esc(fmtDate(r.created_at)) + '</td><td class="muted small">' + (r.expires_at && !r.expires_at.startsWith("0001") ? esc(fmtDate(r.expires_at)) : "never") + '</td><td><button class="btn sm ghost danger" data-del="' + r.id + '">Remove</button></td></tr>').join("") :
        '<tr><td colspan="7">' + empty("No rules yet. Deny a number, a CIDR, or a signer SPC above, or from any row in Traffic.") + "</td></tr>";
      $("#rows").onclick = async (e) => {
        const b = e.target.closest("button[data-del]");
        if (!b) return;
        try { await del("/v1/rules/" + b.dataset.del); toast("rule removed", "ok"); renderLists(v); } catch (err) { toast(err.message, "bad"); }
      };
    } catch (e) { toast(e.message, "bad"); }
  }

  // ---------- value and Ask Falcon ----------
  function renderValueCard(el, v) {
    if (!el || !v) return;
    const pct = (v.blocked_pct || 0).toFixed(1);
    el.innerHTML = '<div class="valuecard"><div class="lead"><b>' + fmtN(v.blocked) + ' <span class="muted" style="font-size:14px;font-weight:500">of ' + fmtN(v.screened) + ' calls blocked · ' + pct + '%</span></b>' + esc(v.sentence) + '</div>' +
      '<div><div class="n" style="color:' + (v.spoofs_stopped ? colors.reject : "inherit") + '">' + fmtN(v.spoofs_stopped) + '</div><div class="l">spoofed caller ids stopped leaving your platform</div></div>' +
      '<div><div class="n">' + fmtN(v.verify_failed) + '</div><div class="l">failed STIR/SHAKEN verifications</div></div>' +
      '<div><div class="n">' + fmtN((v.honeypot_hits || 0) + (v.repeat_recordings || 0) + (v.voice_scams || 0)) + '</div><div class="l">honeypot hits, replayed recordings, voice scams</div></div>' +
      '<div><div class="n">' + (v.minutes_not_carried ? Math.round(v.minutes_not_carried) : "—") + '</div><div class="l">minutes of blocked traffic not carried' + (v.minutes_not_carried ? "" : " (needs call outcomes)") + '</div></div></div>';
  }
  const ask = { history: [], busy: false };
  function askOpen() {
    $("#ask").hidden = false; $("#scrim").hidden = false;
    $("#askInput").focus();
    askRefresh();
  }
  function askClose() { $("#ask").hidden = true; if ($("#drawer").hidden) $("#scrim").hidden = true; }
  async function askRefresh() {
    try {
      const [v, st] = await Promise.all([get("/v1/value?range=" + state.range), state.status ? Promise.resolve(state.status) : get("/v1/status")]);
      const a = (st && st.assistant) || {};
      $("#askProvider").textContent = a.provider ? "answers by " + a.provider + (a.model ? " · " + a.model : "") + " · context is this install's data for " + rangeLabel(state.range) : "no model connected · value card only · set FALCON_ASSISTANT_PROVIDER to ask questions";
      $("#askValue").innerHTML = '<div class="big"><b>' + fmtN(v.blocked) + '</b> of ' + fmtN(v.screened) + ' blocked · ' + (v.blocked_pct || 0).toFixed(1) + '%</div><div class="small" style="margin-top:6px">' + esc(v.sentence) + '</div>' +
        '<div class="row">' + [["spoofs stopped", v.spoofs_stopped], ["verify failed", v.verify_failed], ["honeypot hits", v.honeypot_hits], ["replayed recordings", v.repeat_recordings], ["voice scams", v.voice_scams], ["customers flagged", (v.customers_flagged || []).length], ["alerts", v.alerts_fired]].map(([k, n]) => '<span class="chip ' + (n ? "warn" : "dim") + '">' + esc(k) + " " + fmtN(n || 0) + "</span>").join("") + "</div>";
      const suggestions = ["What did you block today and from whom?", "Which of my customers should I look at first?", "Which signer is behind most rejects?", "How many spoofed caller ids left my platform?", "What would you tighten in the thresholds?"];
      $("#askSuggest").innerHTML = suggestions.map((q) => '<button class="btn sm ghost" data-q="' + esc(q) + '">' + esc(q) + "</button>").join("");
      $("#askSuggest").onclick = (e) => { const b = e.target.closest("button[data-q]"); if (b) { $("#askInput").value = b.dataset.q; $("#askForm").requestSubmit(); } };
    } catch (e) { toast(e.message, "bad"); }
  }
  function askAppend(role, text) {
    const d = document.createElement("div");
    d.className = "ask-msg " + (role === "user" ? "user" : "bot");
    d.textContent = text;
    $("#askLog").appendChild(d);
    $("#askLog").scrollTop = $("#askLog").scrollHeight;
  }
  $("#askBtn").onclick = askOpen;
  $("#askClose").onclick = askClose;
  $("#askForm").onsubmit = async (e) => {
    e.preventDefault();
    const q = $("#askInput").value.trim();
    if (!q || ask.busy) return;
    ask.busy = true;
    $("#askInput").value = "";
    askAppend("user", q);
    try {
      const r = await api("/v1/assistant", { method: "POST", body: JSON.stringify({ question: q, range: state.range, history: ask.history.slice(-8) }) });
      askAppend("assistant", r.answer + (r.provider === "none" && r.note ? "\n\n" + r.note : ""));
      ask.history.push({ role: "user", content: q }, { role: "assistant", content: r.answer });
    } catch (err) { askAppend("assistant", "Could not answer: " + err.message); }
    ask.busy = false;
  };

  // ---------- tuning ----------
  async function renderTuning(v) {
    v.innerHTML = '<section class="grid wide-narrow"><article class="card"><header><h2>Score distribution</h2><span class="hint" id="hHint"></span></header><canvas class="chart" id="hist"></canvas>' +
      '<div id="sliders"></div><div class="whatif" id="whatif"></div><p class="muted small" id="envHint"></p></article>' +
      '<article class="card"><header><h2>Reasons by weight</h2><span class="hint">held calls only</span></header><div class="rank" id="reasons"></div></article></section>';
    try {
      const [h, stats] = await Promise.all([get("/v1/histogram?range=" + state.range), get("/v1/stats?range=" + state.range)]);
      const buckets = h.buckets || [];
      const th = Object.assign({}, h.thresholds);
      const total = buckets.reduce((a, b) => a + b, 0);
      $("#hHint").textContent = fmtN(total) + " requests · dashed lines are the live thresholds";
      const draw = () => {
        drawHistogram($("#hist"), buckets, th);
        let allow = 0, flag = 0, challenge = 0, reject = 0;
        buckets.forEach((n, i) => {
          const lo = i * 10;
          if (lo >= th.reject) reject += n; else if (lo >= th.challenge) challenge += n; else if (lo >= th.flag) flag += n; else allow += n;
        });
        $("#whatif").innerHTML = [["allow", allow, colors.allow], ["flag", flag, colors.flag], ["challenge", challenge, colors.challenge], ["reject", reject, colors.reject]].map(([k, n, c]) => '<div class="w"><b style="color:' + c + '">' + fmtN(n) + "</b><span>" + k + " · " + pct(n, total) + "%</span></div>").join("");
        $("#envHint").innerHTML = "Thresholds are environment values. To apply these: <code class='mono'>FALCON_FLAG_SCORE=" + th.flag + " FALCON_CHALLENGE_SCORE=" + th.challenge + " FALCON_REJECT_SCORE=" + th.reject + "</code>. Buckets are ten points wide, so the what-if is a ten point approximation.";
      };
      $("#sliders").innerHTML = ["flag", "challenge", "reject"].map((k) => '<div class="slider"><span style="color:' + colors[k] + '">' + k + ' at</span><input type="range" min="0" max="100" step="10" value="' + th[k] + '" data-k="' + k + '"><span class="mono num" id="v_' + k + '">' + th[k] + "</span></div>").join("");
      $("#sliders").oninput = (e) => {
        const k = e.target.dataset.k;
        if (!k) return;
        th[k] = Number(e.target.value);
        if (k === "flag") { th.challenge = Math.max(th.challenge, th.flag); th.reject = Math.max(th.reject, th.challenge); }
        if (k === "challenge") { th.flag = Math.min(th.flag, th.challenge); th.reject = Math.max(th.reject, th.challenge); }
        if (k === "reject") { th.challenge = Math.min(th.challenge, th.reject); th.flag = Math.min(th.flag, th.challenge); }
        ["flag", "challenge", "reject"].forEach((kk) => { $('#sliders input[data-k="' + kk + '"]').value = th[kk]; $("#v_" + kk).textContent = th[kk]; });
        draw();
      };
      draw();
      renderRank($("#reasons"), stats.top_reasons, (r) => "#traffic?q=" + encodeURIComponent(r.name));
    } catch (e) { toast(e.message, "bad"); }
  }

  // ---------- system ----------
  async function renderSystem(v) {
    v.innerHTML = '<section class="grid three" id="sys"></section>' +
      '<section class="grid two"><article class="card"><header><h2>Effective configuration</h2><span class="hint">secrets shown as set or empty</span></header><dl class="kv" id="cfg"></dl></article>' +
      '<article class="card"><header><h2>Operations</h2></header><div class="toolbar" style="flex-wrap:wrap;gap:8px">' +
      '<button class="btn" id="reloadBtn">Reload tables</button>' +
      '<a class="btn" href="/metrics' + (token ? "?token=" + encodeURIComponent(token) : "") + '" target="_blank" rel="noreferrer">Prometheus /metrics</a>' +
      '<a class="btn" href="/v1/events.csv?range=' + state.range + (token ? "&token=" + encodeURIComponent(token) : "") + '">Export events CSV</a></div>' +
      '</article></section>' +
      '<section class="grid two"><article class="card"><header><h2>Telemetry</h2><span class="hint" id="shareState"></span></header>' +
      '<label style="display:flex;gap:10px;align-items:flex-start"><input type="checkbox" id="shareBox" style="margin-top:4px"><span>Share redacted screening events with CallerAPI<div class="muted small">On by default. Every install that shares improves detection for every other install. Untick to opt out; it applies within 30 seconds and survives restarts. <code>FALCON_SHARE=false</code> in the environment turns it off for good.</div></span></label>' +
      '<dl class="kv" style="margin-top:14px"><dt>sent</dt><dd>decision, score, reasons, calling number, source IP, user agent, signer SPC and name, verification result, SIP headers, Call-ID, switch label</dd>' +
      '<dt>never sent</dt><dd id="shareRedacted"></dd><dt>endpoint</dt><dd id="shareEndpoint" class="mono"></dd><dt>credit</dt><dd id="shareCredit"></dd><dt>network feed</dt><dd id="shareFeed"></dd></dl></article>' +
      '<article class="card"><header><h2>What the called number becomes</h2></header>' +
      '<pre class="mono small" style="white-space:pre-wrap;margin:0">INVITE sip:<b>REDACTED</b>@your-switch SIP/2.0\nFrom: &lt;sip:+13125550188@203.0.113.9&gt;;tag=a1\nTo: &lt;sip:<b>REDACTED</b>@your-switch&gt;;tag=b2\nP-Called-Party-ID: &lt;sip:<b>REDACTED</b>@your-switch&gt;\nIdentity: <b>REDACTED</b>\nContent-Length: 0\n\n<span class="muted">(SDP body dropped)</span></pre>' +
      '<p class="muted small">The same digits are also removed from any other header, the Call-ID, and reason text. A keyed hash with a per-install secret replaces the number so fan-out can be counted without it.</p></article></section>' +
      '<section class="grid two"><article class="card"><header><h2>Data retention</h2><span class="hint">applies within the hour, no restart</span></header>' +
      '<form id="retentionForm" class="form" style="grid-template-columns:1fr 1fr auto"><label>keep decisions for (days)<input name="retention_days" type="number" min="1" max="3650" required></label>' +
      '<label>keep raw SIP for (days)<input name="raw_sip_retention_days" type="number" min="0" max="3650" required></label><button class="btn primary" type="submit">Save</button></form>' +
      '<p class="muted small" id="retentionHint">Raw SIP carries subscriber numbers in the clear. It is scrubbed after its window; the decision, score, and reasons stay for the full retention. Set raw SIP to 0 to keep it for the life of the row.</p></article>' +
      '<article class="card"><header><h2>What leaves this host</h2></header><dl class="kv" id="egress"></dl></article></section>' +
      '<section class="grid two"><article class="card"><header><h2>Alerts</h2><span class="hint">evaluated every minute over the last 15 minutes, one page per key per hour</span></header>' +
      '<form id="alertForm" class="form" style="grid-template-columns:1fr 1fr 1fr">' +
      '<label style="grid-column:1/-1">webhook URL (Slack incoming webhook or any JSON receiver)<input name="alert_webhook_url" type="url" placeholder="https://hooks.slack.com/services/..."></label>' +
      '<label>min calls before a rate counts<input name="alert_min_calls" type="number" min="0"></label>' +
      '<label>signer reject % <input name="alert_signer_reject_pct" type="number" min="0" max="100"></label>' +
      '<label>overall reject %<input name="alert_reject_pct" type="number" min="0" max="100"></label>' +
      '<label>verification failure %<input name="alert_verify_fail_pct" type="number" min="0" max="100"></label>' +
      '<label>trust list stale after (hours)<input name="alert_trust_stale_hours" type="number" min="0"></label>' +
      '<div style="display:flex;gap:8px;align-items:end"><button class="btn primary" type="submit">Save</button><button class="btn" type="button" id="alertTest">Send test</button></div></form>' +
      '<div id="alertList" style="margin-top:12px"></div></article>' +
      '<article class="card"><header><h2>Audit log</h2><span class="hint">who changed what</span></header><div class="table-wrap"><table><thead><tr><th>when</th><th>actor</th><th>action</th><th>subject</th></tr></thead><tbody id="auditRows"></tbody></table></div></article></section>';
    try {
      const [status, cfg, settings, alertsRes, auditRes] = await Promise.all([get("/v1/status"), get("/v1/config"), get("/v1/settings"), get("/v1/alerts?limit=20"), get("/v1/audit?limit=30")]);
      const af = $("#alertForm");
      Object.entries(alertsRes.settings || {}).forEach(([k, v]) => { if (af[k]) af[k].value = v; });
      af.onsubmit = async (e) => {
        e.preventDefault();
        const body = {};
        [...af.elements].forEach((el) => { if (!el.name) return; body[el.name] = el.type === "number" ? Number(el.value) : el.value; });
        try { await api("/v1/alerts/settings", { method: "PUT", body: JSON.stringify(body) }); toast("alert settings saved", "ok"); } catch (err) { toast(err.message, "bad"); }
      };
      $("#alertTest").onclick = async () => { try { await api("/v1/alerts/test", { method: "POST", body: "{}" }); toast("test alert sent", "ok"); } catch (err) { toast(err.message, "bad"); } };
      const al = alertsRes.data || [];
      $("#alertList").innerHTML = al.length ? al.map((a) => '<div class="reason"><div><div class="code">' + esc(a.severity) + " · " + esc(a.title) + '</div><div class="detail">' + esc(a.detail) + '</div></div><div class="muted small">' + esc(timeAgo(a.at)) + (a.delivered ? "" : a.error ? " · not delivered: " + esc(a.error) : " · stored only") + "</div></div>").join("") : '<div class="muted small">No alerts fired yet. Thresholds above are the defaults; a webhook makes them page you.</div>';
      const au = auditRes.data || [];
      $("#auditRows").innerHTML = au.length ? au.map((e) => "<tr><td class=\"muted small\">" + esc(fmtDate(e.at)) + '</td><td class="mono small">' + esc(e.actor) + '</td><td class="mono small">' + esc(e.action) + '</td><td class="small" title="' + esc(e.detail || "") + '">' + esc(e.subject) + "</td></tr>").join("") : '<tr><td colspan="4" class="muted small">No changes recorded yet.</td></tr>';
      state.status = status;
      const tr = (status.shaken && status.shaken.trust) || {};
      const rf = $("#retentionForm");
      rf.retention_days.value = settings.effective.retention_days;
      rf.raw_sip_retention_days.value = settings.effective.raw_sip_retention_days;
      if (!settings.raw_sip_stored) $("#retentionHint").textContent = "Raw SIP storage is off (FALCON_STORE_RAW_SIP=false). Only decisions are kept.";
      rf.onsubmit = async (e) => {
        e.preventDefault();
        try {
          const r = await api("/v1/settings", { method: "PUT", body: JSON.stringify({ retention_days: Number(rf.retention_days.value), raw_sip_retention_days: Number(rf.raw_sip_retention_days.value) }) });
          toast("retention saved: " + r.effective.retention_days + " days, raw SIP " + r.effective.raw_sip_retention_days + " days", "ok");
        } catch (err) { toast(err.message, "bad"); }
      };
      const sh = cfg.shaken || {}, ipc = cfg.ip_intel || {}, ca = cfg.callerapi || {}, s3 = cfg.s3 || {}, sh2 = status.share || {};
      $("#egress").innerHTML = [
        ["STI-PA trust list", sh.enabled ? (sh.ca_url || "off, file only") : "off"],
        ["STI-PA CRL", sh.enabled ? (sh.crl_url || "off") : "off"],
        ["signer certificates", sh.enabled ? "https fetch of each x5u, public addresses only" + (sh.allow_http ? " (LAB MODE: http and private allowed)" : "") : "off"],
        ["IP intel table", ipc.url || "local file only"],
        ["CallerAPI feed", ca.spam_feed ? "download from " + ca.base : "off"],
        ["CallerAPI live lookup", ca.voice_firewall ? "calling number to " + ca.base : "off"],
        ["CallerAPI telemetry", sh2.effective ? "on, called party redacted, every 30s" : (sh2.configured ? "off, opted out in dashboard" : "off, FALCON_SHARE=false")],
        ["CallerAPI network feed", (status.reputation || {}).configured ? "hourly GET, signed with the install key" : "off"],
        ["alert webhook", (alertsRes.settings || {}).alert_webhook_url ? "on, fired alerts only" : "off"],
        ["voice provider", (status.voice || {}).provider && (status.voice || {}).provider !== "off" ? (status.voice || {}).provider + ": sampled clips and the calling number" : "off"],
        ["S3 export", s3.enabled ? s3.endpoint + " / " + s3.bucket : "off"],
      ].map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>").join("");
      const cards = [
        { t: "STIR/SHAKEN trust", on: status.shaken && status.shaken.enabled && tr.roots > 0, bad: status.shaken && status.shaken.enabled && !(tr.roots > 0), rows: [["roots", fmtN(tr.roots) + (tr.sequence ? " (list #" + tr.sequence + ")" : "")], ["roots loaded", tr.roots_loaded_at ? timeAgo(tr.roots_loaded_at) : "never"], ["revoked serials", fmtN(tr.revoked)], ["CRL loaded", tr.crl_loaded_at ? timeAgo(tr.crl_loaded_at) : "never"], ["cached chains", fmtN(status.shaken && status.shaken.cached_chains)], ["fetch budget", (status.shaken && status.shaken.budget_ms) + " ms"], ["list signature", (cfg.shaken || {}).verify_list ? "verified (ES256, same origin, expiry, sequence)" + ((cfg.shaken || {}).pa_pin === "set" ? ", pinned" : "") : "NOT CHECKED (lab)"], ["errors", [tr.roots_error, tr.crl_error].filter(Boolean).join("; ") || "none"]] },
        { t: "Telecom IP intel", on: status.ip_intel && status.ip_intel.configured && status.ip_intel.count > 0, bad: status.ip_intel && !!status.ip_intel.error, rows: [["blocks", fmtN(status.ip_intel && status.ip_intel.count)], ["loaded", status.ip_intel && status.ip_intel.loaded_at && !String(status.ip_intel.loaded_at).startsWith("0001") ? timeAgo(status.ip_intel.loaded_at) : "never"], ["file", (status.ip_intel && status.ip_intel.file) || "—"], ["url", (status.ip_intel && status.ip_intel.url) || "—"], ["error", (status.ip_intel && status.ip_intel.error) || "none"]] },
        { t: "Voice analysis", on: !!(status.voice && status.voice.budget && status.voice.budget.enabled), rows: [["provider", (status.voice || {}).provider || "off"], ["clips per hour", ((status.voice || {}).budget || {}).per_hour || 0], ["per customer per hour", ((status.voice || {}).budget || {}).per_customer_per_hour || 0], ["clip length", (((status.voice || {}).budget || {}).clip_seconds || 0) + " s"], ["triggers", "honeypot, sequential, fan-out, low ASR, short calls, network, outbound flagged"], ["transcripts", "kept on this host, never shared"]] },
        { t: "Storage and export", on: true, rows: [["decisions kept", ((status.retention || {}).retention_days || "—") + " days"], ["raw SIP kept", status.raw_sip_stored ? ((status.retention || {}).raw_sip_retention_days || 0) + " days" : "not stored"], ["rules", fmtN(status.rules)], ["S3 export", status.s3 ? "on" : "off"], ["telemetry", (status.share || {}).effective ? "on, redacted" : "off"], ["install", status.install_id], ["version", status.version], ["started", timeAgo(status.started_at)]] },
        { t: "Spam database feed", on: status.spam_feed && status.spam_feed.configured && status.spam_feed.count > 0, bad: status.spam_feed && !!status.spam_feed.error, rows: [["numbers", fmtN(status.spam_feed && status.spam_feed.count)], ["loaded", status.spam_feed && status.spam_feed.loaded_at && !String(status.spam_feed.loaded_at).startsWith("0001") ? timeAgo(status.spam_feed.loaded_at) : "never"], ["error", (status.spam_feed && status.spam_feed.error) || "none"]] },
        { t: "Voice firewall", on: status.voice_firewall && status.voice_firewall.configured, rows: [["live lookup", status.voice_firewall && status.voice_firewall.configured ? "on for every INVITE" : "off"]] },
        { t: "Thresholds", on: true, rows: [["flag", status.thresholds.flag], ["challenge", status.thresholds.challenge], ["reject", status.thresholds.reject], ["listen", status.listen]] },
      ];
      $("#sys").innerHTML = cards.map((c) => '<article class="card status-card"><div class="title"><h2>' + esc(c.t) + '</h2><span class="state ' + (c.bad ? "bad" : c.on ? "on" : "off") + '">' + (c.bad ? "attention" : c.on ? "active" : "off") + '</span></div><dl class="kv">' + c.rows.map(([k, val]) => "<dt>" + esc(k) + "</dt><dd>" + esc(val == null ? "—" : val) + "</dd>").join("") + "</dl></article>").join("");
      $("#cfg").innerHTML = Object.keys(cfg).sort().map((k) => "<dt>" + esc(k) + "</dt><dd>" + esc(typeof cfg[k] === "object" ? JSON.stringify(cfg[k]) : cfg[k]) + "</dd>").join("");
      const share = status.share || {};
      $("#shareBox").checked = !!share.effective;
      $("#shareBox").disabled = !share.configured;
      $("#shareState").textContent = share.effective ? "sharing" : (share.configured ? "opted out" : "disabled by FALCON_SHARE=false");
      $("#shareRedacted").textContent = (share.redacted || []).join(", ");
      $("#shareEndpoint").textContent = share.endpoint || "";
      $("#shareCredit").textContent = share.credited ? "CALLERAPI_API_KEY set, this account is credited" : "anonymous (set CALLERAPI_API_KEY to be credited)";
      const rep = status.reputation || {}, rs = rep.status || {};
      $("#shareFeed").textContent = !rep.configured ? "off" : rs.error ? "not loaded: " + rs.error : (rs.signers || 0) + " signers, " + (rs.fingerprints || 0) + " tools, loaded " + (rs.loaded_at ? timeAgo(rs.loaded_at) : "never") + (rep.enforce ? " · enforce on" : " · corroboration only");
      $("#shareBox").onchange = async (e) => {
        try {
          const r = await api("/v1/settings", { method: "PUT", body: JSON.stringify({ share_telemetry: e.target.checked }) });
          $("#shareState").textContent = r.effective.share_telemetry ? "sharing" : "opted out";
          toast(r.effective.share_telemetry ? "telemetry on, called party stays redacted" : "telemetry off, nothing leaves this host", "ok");
        } catch (err) { e.target.checked = !e.target.checked; toast(err.message, "bad"); }
      };
      $("#reloadBtn").onclick = async () => { $("#reloadBtn").disabled = true; try { const r = await post("/v1/reload", {}); toast("reloaded " + Object.keys(r.reloaded || {}).join(", "), "ok"); renderSystem(v); } catch (err) { toast(err.message, "bad"); $("#reloadBtn").disabled = false; } };
    } catch (e) { toast(e.message, "bad"); }
  }

  // ---------- drawer ----------
  async function openEvent(id) {
    try {
      const ev = await get("/v1/events/" + id);
      state.drawer.ev = ev;
      state.drawer.tab = "summary";
      $$("#drawerTabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === "summary"));
      $("#drawerKicker").textContent = "event #" + ev.id + " · " + fmtDate(ev.received_at) + (ev.switch ? " · " + ev.switch : "");
      $("#drawerTitle").innerHTML = esc(ev.from || "—") + ' <span class="muted">→</span> ' + esc(ev.to || "—");
      renderDrawer();
      $("#drawer").hidden = false;
      $("#scrim").hidden = false;
    } catch (e) { toast(e.message, "bad"); }
  }
  function closeDrawer() { $("#drawer").hidden = true; $("#scrim").hidden = true; }
  $("#drawerClose").onclick = closeDrawer;
  $("#scrim").onclick = () => { closeDrawer(); if (!$("#ask").hidden) askClose(); };
  $("#drawerTabs").onclick = (e) => {
    const b = e.target.closest("button[data-tab]");
    if (!b) return;
    state.drawer.tab = b.dataset.tab;
    $$("#drawerTabs button").forEach((x) => x.classList.toggle("on", x === b));
    renderDrawer();
  };

  function b64json(s) {
    try { return JSON.parse(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "="))); } catch (e) { return null; }
  }
  function highlightSIP(raw) {
    return esc(raw).split("\n").map((line) => {
      const m = line.match(/^([A-Za-z][A-Za-z0-9-]*):(.*)$/);
      if (m) {
        const hl = /^(Identity|From|P-Asserted-Identity|Via|User-Agent|Contact)$/i.test(m[1]) ? " hl" : "";
        return '<span class="h' + hl + '">' + m[1] + ":</span><span class='v'>" + m[2] + "</span>";
      }
      return line;
    }).join("\n");
  }
  function renderDrawer() {
    const ev = state.drawer.ev;
    if (!ev) return;
    const body = $("#drawerBody");
    const tab = state.drawer.tab;
    if (tab === "summary") {
      const sh = ev.shaken || {};
      const vs = ev.voice || null;
      body.innerHTML = '<div class="toolbar">' + pill(ev.action) + scoreCell(ev.risk_score, ev.action) + verstatChip(ev.verstat, ev.shaken_attest, sh.source) + (ev.direction === "outbound" ? '<span class="chip warn">outbound</span>' : "") + (ev.customer ? '<span class="chip">customer ' + esc(ev.customer) + "</span>" : "") + (ev.honeypot ? '<span class="chip bad">honeypot target</span>' : "") + (ev.provider ? '<span class="chip">' + esc(ev.provider) + "</span>" : "") + (ev.signer_spc ? '<span class="chip">SPC ' + esc(ev.signer_spc) + (ev.signer_name ? " · " + esc(ev.signer_name) : "") + "</span>" : "") + "</div>" +
        (ev.answered !== undefined || ev.sampled ? '<dl class="kv"><dt>outcome</dt><dd>' + (ev.answered === undefined ? "not reported yet" : (ev.answered ? "answered, " + esc(ev.duration_s || 0) + " s" : "not answered") + (ev.hangup_cause ? " · " + esc(ev.hangup_cause) : "")) + "</dd>" + (ev.sampled ? "<dt>audio</dt><dd>" + (vs ? esc(vs.seconds.toFixed(1)) + " s, " + esc(vs.channels) + (vs.channels > 1 ? " legs" : " channel") + (vs.repeat_count ? ' · <b style="color:' + colors.reject + '">same recording as ' + esc(vs.repeat_count) + " earlier calls</b>" : "") + (vs.caller_speech >= 0.55 && vs.callee_speech <= 0.08 && vs.channels > 1 ? " · one-way monologue" : "") : "requested, not received yet") + "</dd>" : "") + "</dl>" : "") +
        (vs && (vs.category || vs.error) ? '<div class="card" style="padding:6px 14px"><header style="margin:8px 0 2px"><h2>Voice analysis</h2><span class="hint">' + (vs.provider === "callerapi-live" ? "live · CallerAPI listened while the call was up" + (vs.seconds ? " · " + esc(Math.round(vs.seconds)) + " s" : "") : esc(vs.provider || "")) + "</span></header>" + (vs.error ? '<div class="small mono" style="color:' + colors.reject + '">' + esc(vs.error) + "</div>" : '<div class="toolbar"><span class="chip ' + (vs.score >= 0.7 ? "bad" : vs.score >= 0.4 ? "warn" : "dim") + '">' + esc(vs.category) + " · " + esc(Math.round(vs.score * 100)) + "%</span></div>" + (vs.summary ? '<p class="small">' + esc(vs.summary) + "</p>" : "") + (vs.transcript ? '<details class="small"><summary class="muted">transcript (stays on this host)</summary><pre style="white-space:pre-wrap;margin:6px 0 0">' + esc(vs.transcript) + "</pre></details>" : "")) + "</div>" : "") +
        '<dl class="kv"><dt>source</dt><dd>' + esc(ev.source_ip) + "</dd><dt>user agent</dt><dd>" + esc(ev.user_agent || "—") + "</dd><dt>call id</dt><dd>" + esc(ev.call_id || "—") + "</dd>" +
        (ev.fingerprint ? '<dt>tool fingerprint</dt><dd class="mono"><a href="#traffic?q=' + esc(ev.fingerprint) + '" title="show every call from software with these habits">' + esc(ev.fingerprint) + "</a>" + (ev.network_fingerprint ? ' <span class="chip ' + (ev.network_fingerprint.score >= 80 ? "bad" : ev.network_fingerprint.score >= 50 ? "warn" : "dim") + '">network ' + esc(ev.network_fingerprint.score) + " · " + esc(ev.network_fingerprint.installs) + " installs</span>" : "") + "</dd>" : "") +
        (ev.network_signer ? '<dt>signer on network</dt><dd>score ' + esc(ev.network_signer.score) + " across " + esc(ev.network_signer.installs) + " installs · " + esc(ev.network_signer.failed) + " failed · " + esc(ev.network_signer.spam_hits) + " spam hits</dd>" : "") +
        "<dt>SIP response</dt><dd>" + (ev.action === "reject" ? "603 Decline" : ev.action === "challenge" ? "407 Proxy Authentication Required" : "pass through") + "</dd></dl>" +
        (ev.fingerprint_parts ? '<details class="small" style="margin:0 0 10px"><summary class="muted">what the fingerprint is made of</summary><pre style="margin:6px 0 0">' + esc(ev.fingerprint_parts.join("\n")) + "</pre></details>" : "") +
        '<div class="card" style="padding:6px 14px"><header style="margin:8px 0 2px"><h2>Reasons</h2><span class="hint">weight adds to the score, capped at 100</span></header>' +
        ((ev.reasons || []).length ? ev.reasons.map((r) => '<div class="reason"><div><div class="code">' + esc(r.code) + '</div><div class="detail">' + esc(r.detail) + '</div></div><div class="w' + (r.weight ? "" : " zero") + '">' + (r.weight ? "+" + r.weight : "0") + "</div></div>").join("") : '<div class="muted small" style="padding:8px 0">Nothing looked wrong.</div>') + "</div>";
    } else if (tab === "shaken") {
      const sh = ev.shaken;
      const roots = !!(state.status && state.status.shaken && state.status.shaken.trust && state.status.shaken.trust.roots);
      if (sh && sh.source === "switch") {
        const na = sh.pending || !sh.x5u;
        const checks = [
          ["Certificate chains to a trusted STI-CA", sh.chain_trusted, na || (!sh.chain_trusted && !roots)],
          ["Certificate is within its validity period", sh.cert_valid, na],
          ["Certificate is not on the STI-PA CRL", !sh.revoked, na],
        ];
        body.innerHTML = '<div class="toolbar">' + verstatChip(sh.verstat, sh.attest, sh.source) + (sh.pending ? '<span class="chip warn">certificate fetch pending</span>' : "") + (sh.cached ? '<span class="chip dim">from cache</span>' : "") + "</div>" +
          '<p class="muted small">The switch signs this call on the way out, after Falcon screens the INVITE. Falcon read the certificate the switch signs with. There was no signature to check.</p>' +
          '<div class="check">' + checks.map(([label, ok, skip]) => '<div class="c ' + (skip ? "na" : ok ? "ok" : "bad") + '"><span class="m">' + (skip ? "–" : ok ? "✓" : "✕") + "</span><span>" + esc(label) + "</span></div>").join("") + "</div>" +
          errorsCard(sh) + signerCard(sh) +
          '<div class="card"><h2 style="margin-bottom:8px">Signing</h2><dl class="kv"><dt>attestation</dt><dd>' + esc(sh.attest || "—") + "</dd><dt>origid</dt><dd>" + esc(sh.origid || "—") + "</dd></dl></div>";
        return;
      }
      if (!sh || !sh.present) {
        body.innerHTML = empty(ev.shaken_attest ? "The Identity header was decoded but verification did not run on this install." : "This INVITE carried no Identity header. Unsigned traffic is legal but weak. Attestation and signer are unknown.");
        return;
      }
      const checks = [
        ["Identity header parsed as a PASSporT", sh.parsed_jwt],
        ["Algorithm is ES256", sh.alg === "ES256"],
        ["Signature verifies with the x5u certificate", sh.signature_ok, sh.pending],
        ["Certificate chains to a trusted STI-CA", sh.chain_trusted, sh.pending || (!sh.chain_trusted && !roots)],
        ["Certificate is within its validity period", sh.cert_valid, sh.pending],
        ["Certificate is not on the STI-PA CRL", sh.present && !sh.revoked && !sh.pending, sh.pending],
        ["iat is within 60 seconds", sh.fresh, !sh.iat],
        ["orig tn matches the calling number", sh.orig_matches_from, !sh.orig_tn || !ev.from],
        ["dest tn includes the called number", sh.dest_matches_to, !(sh.dest_tn && sh.dest_tn.length) || !ev.to],
      ];
      const raw = (ev.raw_sip || "").split("\n").find((l) => /^Identity:/i.test(l));
      const jwt = raw ? raw.replace(/^Identity:\s*/i, "").split(";")[0].trim() : "";
      const parts = jwt.split(".");
      const hdr = parts.length === 3 ? b64json(parts[0]) : null;
      const payload = parts.length === 3 ? b64json(parts[1]) : null;
      body.innerHTML = '<div class="toolbar">' + verstatChip(sh.verstat, sh.attest) + (sh.pending ? '<span class="chip warn">certificate fetch pending</span>' : "") + (sh.cached ? '<span class="chip dim">from cache</span>' : "") + '<span class="chip dim">' + esc(sh.latency_ms) + " ms</span></div>" +
        '<div class="check">' + checks.map(([label, ok, na]) => '<div class="c ' + (na ? "na" : ok ? "ok" : "bad") + '"><span class="m">' + (na ? "–" : ok ? "✓" : "✕") + "</span><span>" + esc(label) + "</span></div>").join("") + "</div>" +
        errorsCard(sh) + signerCard(sh) +
        '<div class="card"><h2 style="margin-bottom:8px">PASSporT</h2><dl class="kv"><dt>attestation</dt><dd>' + esc(sh.attest || "—") + "</dd><dt>orig tn</dt><dd>" + esc(sh.orig_tn || "—") + "</dd><dt>dest tn</dt><dd>" + esc((sh.dest_tn || []).join(", ") || "—") + "</dd><dt>origid</dt><dd>" + esc(sh.origid || "—") + "</dd><dt>iat</dt><dd>" + (sh.iat ? esc(new Date(sh.iat * 1000).toISOString()) : "—") + "</dd></dl>" +
        (hdr ? "<pre>" + esc(JSON.stringify(hdr, null, 2)) + "\n" + esc(JSON.stringify(payload, null, 2)) + "</pre>" : "") + "</div>";
    } else if (tab === "sip") {
      body.innerHTML = '<div class="toolbar"><button class="btn sm" id="copySip">Copy raw SIP</button></div><pre id="rawSip">' + highlightSIP(ev.raw_sip || "") + "</pre>";
      $("#copySip").onclick = () => { navigator.clipboard.writeText(ev.raw_sip || "").then(() => toast("copied", "ok")); };
    } else if (tab === "actions") {
      body.innerHTML = '<p class="muted small">Rules take effect on the next INVITE. Deny is a hard reject with SIP 603. Allow skips scoring for that subject.</p><div class="actions">' +
        (ev.from ? '<button class="btn danger" data-act="deny" data-subject="number" data-value="' + esc(ev.from) + '">Deny number ' + esc(ev.from) + '</button><button class="btn" data-act="allow" data-subject="number" data-value="' + esc(ev.from) + '">Allow number</button>' : "") +
        (ev.source_ip ? '<button class="btn danger" data-act="deny" data-subject="ip" data-value="' + esc(ev.source_ip) + '">Deny IP ' + esc(ev.source_ip) + '</button><button class="btn" data-act="allow" data-subject="ip" data-value="' + esc(ev.source_ip) + '">Allow IP</button>' : "") +
        (ev.signer_spc ? '<button class="btn danger" data-act="deny" data-subject="spc" data-value="' + esc(ev.signer_spc) + '">Deny signer ' + esc(ev.signer_spc) + '</button><button class="btn" data-act="allow" data-subject="spc" data-value="' + esc(ev.signer_spc) + '">Allow signer</button>' : "") +
        '</div><div class="toolbar" style="margin-top:14px"><a class="btn sm" href="#traffic?q=' + encodeURIComponent(ev.from || "") + '">All calls from this number</a><a class="btn sm" href="#traffic?q=' + encodeURIComponent(ev.source_ip || "") + '">All calls from this IP</a>' + (ev.signer_spc ? '<a class="btn sm" href="#traffic?q=' + encodeURIComponent(ev.signer_spc) + '">All calls by this signer</a>' : "") + "</div>";
      body.onclick = async (e) => {
        const b = e.target.closest("button[data-act]");
        if (!b) return;
        b.disabled = true;
        await addRule(b.dataset.act, b.dataset.subject, b.dataset.value, "from event #" + ev.id);
        b.disabled = false;
      };
    }
  }

  // ---------- live ----------
  function setLive(on) {
    state.live = on;
    $("#liveBtn").classList.toggle("on", on);
    if (state.sse) { state.sse.close(); state.sse = null; }
    if (!on) return;
    const es = new EventSource("/v1/stream" + (token ? "?token=" + encodeURIComponent(token) : ""));
    es.addEventListener("screen", (e) => {
      try {
        const ev = JSON.parse(e.data);
        if (state.view === "traffic") {
          const t = state.traffic;
          if (t.action && ev.action !== t.action) return;
          if (t.verstat && ev.verstat !== t.verstat) return;
          if (state.q && !JSON.stringify(ev).toLowerCase().includes(state.q.toLowerCase())) return;
          t.rows.unshift(ev);
          const body = $("#rows");
          if (body) {
            if (body.querySelector(".empty")) body.innerHTML = "";
            body.insertAdjacentHTML("afterbegin", trafficRow(ev, true));
            $("#tCount").textContent = fmtN(t.rows.length) + " shown";
          }
        }
      } catch (err) { /* ignore malformed frame */ }
    });
    es.onerror = () => { $("#liveBtn").classList.remove("on"); };
    es.onopen = () => { $("#liveBtn").classList.add("on"); };
    state.sse = es;
  }
  $("#liveBtn").onclick = () => setLive(!state.live);

  async function renderPlugins(v) {
    const params = new URLSearchParams((location.hash.split("?")[1] || ""));
    const slug = params.get("slug") || "";
    let catalog;
    try {
      catalog = await get("/v1/plugins");
    } catch (e) {
      v.innerHTML = '<div class="card">' + esc(e.message) + "</div>";
      return;
    }
    const items = (catalog && catalog.plugins) || [];
    const views = items.filter((p) => p.surface === "native" || p.surface === "iframe");
    if (!slug) {
      if (!views.length) {
        v.innerHTML = empty("No plugin pages are granted to this install.");
        return;
      }
      v.innerHTML = '<section class="plugin-list">' + views.map((p) =>
        '<a class="card plugin-card" href="#plugins?slug=' + encodeURIComponent(p.slug) + '"><span class="kicker">' + esc(p.kind || "view") + "</span><strong>" + esc(p.title || p.slug) + "</strong><span class=\"muted small\">" + esc(p.slug) + "</span></a>"
      ).join("") + "</section>";
      return;
    }
    const item = views.find((p) => p.slug === slug);
    $("#viewTitle").textContent = item ? (item.title || item.slug) : slug;
    if (item && item.surface === "iframe") {
      const frame = document.createElement("iframe");
      frame.className = "plugin-frame";
      frame.setAttribute("sandbox", "");
      frame.referrerPolicy = "no-referrer";
      frame.title = item.title || item.slug;
      v.appendChild(frame);
      try {
        const res = await fetch("/v1/plugins/" + encodeURIComponent(slug) + "/frame" + (state.q ? "?q=" + encodeURIComponent(state.q) : ""), { headers: headers() });
        if (!res.ok) throw new Error("plugin page unavailable");
        const html = await res.text();
        if (/<script/i.test(html)) throw new Error("plugin page refused");
        frame.srcdoc = html;
      } catch (e) {
        v.innerHTML = '<div class="card">' + esc(e.message) + "</div>";
      }
      return;
    }
    let panel;
    try {
      panel = await get("/v1/plugins/" + encodeURIComponent(slug) + "/view" + (state.q ? "?q=" + encodeURIComponent(state.q) : ""));
    } catch (e) {
      v.innerHTML = '<div class="card">' + esc(e.message) + "</div>";
      return;
    }
    paintPlugin(v, panel, slug);
  }

  function pendingCount(panel) {
    const row = (panel.stats || []).find((s) => s.label === "Pending");
    return row ? Number(row.value) || 0 : 0;
  }

  function paintPlugin(v, panel, slug) {
    const stats = (panel.stats || []).map((s) => '<article class="card kpi"><label>' + esc(s.label) + "</label><b>" + esc(s.value) + "</b></article>").join("");
    const cols = panel.columns || [];
    const head = cols.map((c) => "<th>" + esc(c.label || c.key) + "</th>").join("");
    const cell = (key, value) => {
      const text = value || "";
      if (key === "status") {
        const tone = text === "flagged" ? "flag" : text === "clear" ? "allow" : "challenge";
        return '<span class="pill ' + tone + '">' + esc(text || "unknown") + "</span>";
      }
      return esc(text);
    };
    const body = (panel.rows || []).map((row) => "<tr>" + cols.map((c) => "<td>" + cell(c.key, row[c.key]) + "</td>").join("") + "</tr>").join("");
    const emptyText = panel.import
      ? (state.q ? "No numbers match this search." : "No numbers yet. Drop a file to import them.")
      : (state.q ? "Nothing matches this number." : "Nothing to show.");
    const importer = panel.import
      ? '<form class="plugin-import" id="pluginImport"><label class="plugin-drop" id="pluginDrop"><input id="pluginFile" type="file"><span id="pluginDropText">Drop any file here, or choose one. Numbers are detected automatically. Each new number uses 1 credit.</span></label><div class="plugin-import-row"><button class="btn primary" type="submit">Import numbers</button></div></form>' + scheduleCard()
      : "";
    v.innerHTML = importer + (stats ? '<section class="grid kpis">' + stats + "</section>" : "") +
      '<article class="card" style="padding:0"><div class="table-wrap"><table><thead><tr>' + head + "</tr></thead><tbody>" +
      (body || '<tr><td colspan="' + Math.max(cols.length, 1) + '">' + empty(emptyText) + "</td></tr>") +
      "</tbody></table></div></article>";
    const form = $("#pluginImport");
    if (form) bindImport(form, v, slug);
    if (panel.import) bindSchedule(v, slug);
    if (panel.import && pendingCount(panel) > 0) {
      schedule(() => refreshPlugin(slug), 2000);
    }
  }

  function bindImport(form, v, slug) {
    let chosen = null;
    const drop = $("#pluginDrop");
    const input = $("#pluginFile");
    const label = $("#pluginDropText");
    const remember = () => { if (chosen) form.dataset.file = "1"; };
    input.onchange = () => {
      chosen = input.files && input.files[0];
      if (chosen) label.textContent = chosen.name;
      remember();
    };
    drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
    drop.ondragleave = () => drop.classList.remove("over");
    drop.ondrop = (e) => {
      e.preventDefault();
      drop.classList.remove("over");
      chosen = e.dataTransfer.files && e.dataTransfer.files[0];
      if (chosen) label.textContent = chosen.name;
      remember();
    };
    form.onsubmit = async (e) => {
      e.preventDefault();
      if (!chosen) { toast("Choose a file."); return; }
      const btn = form.querySelector("button");
      btn.disabled = true;
      try {
        const panel = await postFile("/v1/plugins/" + encodeURIComponent(slug) + "/import", chosen);
        v.innerHTML = "";
        paintPlugin(v, panel, slug);
        toast("Numbers imported.");
      } catch (err) {
        toast(err.message);
        btn.disabled = false;
      }
    };
  }

  async function postFile(path, file) {
    const body = new FormData();
    body.append("file", file, file.name || "numbers");
    const res = await fetch(path, { method: "POST", headers: headers(), body });
    if (!res.ok) {
      let msg = res.status + " " + res.statusText;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    return res.json();
  }

  const scheduleZones = [
    ["UTC", "UTC"],
    ["America/New_York", "Eastern time"],
    ["America/Chicago", "Central time"],
    ["America/Denver", "Mountain time"],
    ["America/Los_Angeles", "Pacific time"],
    ["America/Toronto", "Toronto"],
    ["Europe/London", "London"],
    ["Europe/Dublin", "Dublin"],
    ["Europe/Paris", "Paris"],
    ["Europe/Berlin", "Berlin"],
    ["Europe/Amsterdam", "Amsterdam"],
    ["Europe/Madrid", "Madrid"],
    ["Europe/Rome", "Rome"],
    ["Europe/Warsaw", "Warsaw"],
    ["Europe/Stockholm", "Stockholm"],
    ["Asia/Dubai", "Dubai"],
    ["Asia/Kolkata", "India"],
    ["Asia/Singapore", "Singapore"],
    ["Asia/Tokyo", "Tokyo"],
    ["Australia/Sydney", "Sydney"]
  ];

  function scheduleCard() {
    const days = ["M", "T", "W", "T", "F", "S", "S"].map((label, i) => {
      const on = i < 5;
      return '<button type="button" class="day' + (on ? " on" : "") + '" data-day="' + (i + 1) + '" aria-pressed="' + (on ? "true" : "false") + '">' + label + "</button>";
    }).join("");
    const every = [["15", "15m"], ["60", "1 hour"], ["360", "6 hours"], ["1440", "Day"]].map(([n, label]) =>
      '<button type="button" data-interval="' + n + '"' + (n === "60" ? ' class="on"' : "") + ">" + label + "</button>"
    ).join("");
    const zones = scheduleZones.map(([id, label]) => '<option value="' + id + '">' + esc(label) + "</option>").join("");
    return '<form class="card plugin-schedule" id="pluginSchedule">' +
      '<div class="plugin-schedule-head"><div><strong>Schedule</strong><span class="muted small" id="pluginScheduleWhen">Off</span></div>' +
      '<button type="button" class="switch" id="pluginScheduleOn" aria-pressed="false" aria-label="Check on a schedule"><i></i></button></div>' +
      '<div class="plugin-schedule-row"><span>Every</span><div class="seg" id="pluginEvery">' + every + "</div></div>" +
      '<div class="plugin-schedule-row"><span>Days</span><div class="days" id="pluginDays">' + days + "</div></div>" +
      '<div class="plugin-schedule-row"><span>Hours</span><input id="pluginStart" type="time" value="09:00" aria-label="Start"><span class="muted">to</span><input id="pluginEnd" type="time" value="17:00" aria-label="End"></div>' +
      '<div class="plugin-schedule-row"><span>Zone</span><select id="pluginZone" aria-label="Timezone">' + zones + "</select></div>" +
      '<p class="muted small">Each check uses 1 credit per number.</p>' +
      '<div class="plugin-import-row"><button class="btn primary" type="submit">Save schedule</button></div></form>';
  }

  function scheduleWhen(row) {
    if (!row || row.state === "off" || !row.enabled) return "Off";
    if (row.state === "checking") return "Checking the list.";
    if (row.state === "paused") return (row.note || "Not enough credits") + (row.next_run_local ? ". Next try " + row.next_run_local : "");
    return row.next_run_local ? "Next check " + row.next_run_local : "Scheduled";
  }

  function fillSchedule(row) {
    const form = $("#pluginSchedule");
    if (!form || !row) return;
    const on = $("#pluginScheduleOn");
    on.classList.toggle("on", !!row.enabled);
    on.setAttribute("aria-pressed", row.enabled ? "true" : "false");
    $$("#pluginEvery button").forEach((b) => b.classList.toggle("on", Number(b.dataset.interval) === Number(row.interval_minutes)));
    const days = row.weekdays || [];
    $$("#pluginDays button").forEach((b) => {
      const pressed = days.indexOf(Number(b.dataset.day)) >= 0;
      b.classList.toggle("on", pressed);
      b.setAttribute("aria-pressed", pressed ? "true" : "false");
    });
    $("#pluginStart").value = row.start || "09:00";
    $("#pluginEnd").value = row.end || "17:00";
    const zone = $("#pluginZone");
    if (row.timezone && !zone.querySelector('option[value="' + row.timezone + '"]')) {
      const extra = document.createElement("option");
      extra.value = row.timezone;
      extra.textContent = row.timezone;
      zone.appendChild(extra);
    }
    zone.value = row.timezone || "UTC";
    $("#pluginScheduleWhen").textContent = scheduleWhen(row);
    form.classList.toggle("off", !row.enabled);
    form.dataset.dirty = "";
  }

  function readSchedule() {
    return {
      enabled: $("#pluginScheduleOn").classList.contains("on"),
      interval_minutes: Number(($("#pluginEvery button.on") || { dataset: { interval: "60" } }).dataset.interval),
      weekdays: $$("#pluginDays button.on").map((b) => Number(b.dataset.day)),
      start: $("#pluginStart").value || "09:00",
      end: $("#pluginEnd").value || "17:00",
      timezone: $("#pluginZone").value || "UTC"
    };
  }

  function bindSchedule(v, slug) {
    const form = $("#pluginSchedule");
    const mark = () => { form.dataset.dirty = "1"; };
    $("#pluginScheduleOn").onclick = () => {
      const on = $("#pluginScheduleOn");
      const next = !on.classList.contains("on");
      on.classList.toggle("on", next);
      on.setAttribute("aria-pressed", next ? "true" : "false");
      form.classList.toggle("off", !next);
      mark();
    };
    $("#pluginEvery").onclick = (e) => {
      const b = e.target.closest("button[data-interval]");
      if (!b) return;
      $$("#pluginEvery button").forEach((x) => x.classList.toggle("on", x === b));
      mark();
    };
    $("#pluginDays").onclick = (e) => {
      const b = e.target.closest("button[data-day]");
      if (!b) return;
      const next = b.getAttribute("aria-pressed") !== "true";
      b.classList.toggle("on", next);
      b.setAttribute("aria-pressed", next ? "true" : "false");
      mark();
    };
    $("#pluginStart").onchange = mark;
    $("#pluginEnd").onchange = mark;
    $("#pluginZone").onchange = mark;
    form.onsubmit = async (e) => {
      e.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      try {
        fillSchedule(await put("/v1/plugins/" + encodeURIComponent(slug) + "/schedule", readSchedule()));
        toast("Schedule saved.");
      } catch (err) {
        toast(err.message);
      }
      btn.disabled = false;
    };
    get("/v1/plugins/" + encodeURIComponent(slug) + "/schedule").then(fillSchedule).catch(() => {});
  }

  async function refreshPlugin(slug) {
    if (state.view !== "plugins") return;
    const current = new URLSearchParams((location.hash.split("?")[1] || "")).get("slug") || "";
    if (current !== slug) return;
    const editing = $("#pluginSchedule");
    if (editing && editing.dataset.dirty === "1") return;
    const importing = $("#pluginImport");
    if (importing && importing.dataset.file === "1") return;
    try {
      const panel = await get("/v1/plugins/" + encodeURIComponent(slug) + "/view" + (state.q ? "?q=" + encodeURIComponent(state.q) : ""));
      const v = $("#view");
      v.innerHTML = "";
      paintPlugin(v, panel, slug);
    } catch (e) { /* keep the current table */ }
  }

  // ---------- topbar ----------
  $("#rangeSeg").onclick = (e) => {
    const b = e.target.closest("button[data-range]");
    if (!b) return;
    state.range = b.dataset.range;
    localStorage.setItem("falcon_range", state.range);
    $$("#rangeSeg button").forEach((x) => x.classList.toggle("on", x === b));
    $("#viewHint").textContent = titles[state.view][1] + " · " + rangeLabel(state.range);
    render();
  };
  $$("#rangeSeg button").forEach((x) => x.classList.toggle("on", x.dataset.range === state.range));
  let searchTimer;
  $("#search").oninput = (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = e.target.value.trim();
      if (state.view === "plugins") {
        const slug = new URLSearchParams((location.hash.split("?")[1] || "")).get("slug") || "";
        location.hash = "#plugins?slug=" + encodeURIComponent(slug) + (state.q ? "&q=" + encodeURIComponent(state.q) : "");
      } else if (state.view !== "traffic") location.hash = "#traffic?q=" + encodeURIComponent(state.q);
      else loadTraffic(true);
    }, 250);
  };
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== $("#search") && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); $("#search").focus(); $("#search").select(); }
    if (e.key === "Escape") { if (!$("#ask").hidden) askClose(); else if (!$("#drawer").hidden) closeDrawer(); else $("#search").blur(); }
    if ((e.key === "a" || e.key === "A") && !e.metaKey && !e.ctrlKey && document.activeElement.tagName !== "INPUT" && $("#ask").hidden) { e.preventDefault(); askOpen(); }
    if ((e.key === "l" || e.key === "L") && !/input|textarea|select/i.test(document.activeElement.tagName)) setLive(!state.live);
  });

  // ---------- health ----------
  async function health() {
    try {
      const h = await get("/v1/health");
      $("#healthDot").className = "dot ok";
      $("#healthText").textContent = "healthy";
      $("#installId").textContent = "install " + (h.install_id || "").slice(0, 8);
      $("#versionText").textContent = "falcon " + (h.version || "");
    } catch (e) {
      $("#healthDot").className = "dot bad";
      $("#healthText").textContent = token ? "unreachable" : "unauthorized · add ?token=";
    }
  }
  health();
  setInterval(health, 10000);
  window.addEventListener("resize", () => { if (state.view === "overview" || state.view === "tuning") render(); });

  navigate();
})();
