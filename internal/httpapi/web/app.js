/* Falcon dashboard. Vanilla JS, no build step, no network beyond this host.
   Each view builds its frame once and then patches only the regions whose
   content changed, so a refresh never blanks the page. The last answers
   are kept for the session, so a reload paints at once. */
(function () {
  "use strict";

  // ---------- auth and API ----------
  const boot = new URLSearchParams(location.search);
  if (boot.get("token")) {
    localStorage.setItem("falcon_token", boot.get("token"));
    boot.delete("token");
    const rest = boot.toString();
    history.replaceState(null, "", location.pathname + (rest ? "?" + rest : "") + location.hash);
  }
  const token = localStorage.getItem("falcon_token") || "";
  const withToken = (url) => (token ? url + (url.indexOf("?") >= 0 ? "&" : "?") + "token=" + encodeURIComponent(token) : url);

  function headers(extra) {
    const h = Object.assign({ Accept: "application/json", "X-Falcon-Request": "1" }, extra || {});
    if (token) h["X-Falcon-Token"] = token;
    return h;
  }
  async function api(path, opts) {
    opts = opts || {};
    const init = { method: opts.method || "GET", headers: headers(opts.body !== undefined ? { "Content-Type": "application/json" } : {}) };
    if (opts.body !== undefined) init.body = typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
    const res = await fetch(path, init);
    const raw = await res.text();
    let data = null;
    if (raw) { try { data = JSON.parse(raw); } catch (e) { data = raw; } }
    if (!res.ok) throw new Error((data && data.error) || res.status + " " + res.statusText);
    return data;
  }
  const get = (p) => api(p);
  const post = (p, b) => api(p, { method: "POST", body: b || {} });
  const put = (p, b) => api(p, { method: "PUT", body: b || {} });
  const del = (p) => api(p, { method: "DELETE" });

  // ---------- session cache ----------
  const CACHE = "falcon_cache_v2";
  const cache = (function () { try { return JSON.parse(sessionStorage.getItem(CACHE) || "{}"); } catch (e) { return {}; } })();
  let persistTimer = 0;
  function remember(key, data) {
    cache[key] = data;
    clearTimeout(persistTimer);
    persistTimer = setTimeout(function () {
      try { sessionStorage.setItem(CACHE, JSON.stringify(cache)); } catch (e) { /* storage full: keep memory only */ }
    }, 300);
  }

  // ---------- DOM helpers ----------
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  // A name such as "Example Inc." already ends the sentence.
  const sentence = (s) => String(s).replace(/\.+$/, "") + ".";
  function patch(el, html) { if (el && el.__html !== html) { el.innerHTML = html; el.__html = html; } }
  function setText(el, t) { if (el && el.textContent !== t) el.textContent = t; }

  const nf = new Intl.NumberFormat();
  const fmtN = (n) => nf.format(Math.round(n || 0));
  function fmtMs(ms) {
    if (!ms) return "0";
    if (ms < 10) return ms.toFixed(1);
    return String(Math.round(ms));
  }
  function ago(iso) {
    if (!iso) return "never";
    const d = (Date.now() - new Date(iso).getTime()) / 1000;
    if (d < 5) return "just now";
    if (d < 60) return Math.round(d) + "s ago";
    if (d < 3600) return Math.round(d / 60) + " min ago";
    if (d < 86400) return Math.round(d / 3600) + " h ago";
    return Math.round(d / 86400) + " days ago";
  }
  const pad = (n) => String(n).padStart(2, "0");
  function clock(iso) { const d = new Date(iso); return pad(d.getHours()) + ":" + pad(d.getMinutes()); }
  function dayClock(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + ", " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function when(iso) {
    const d = new Date(iso);
    const today = new Date();
    if (d.toDateString() === today.toDateString()) return clock(iso);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  function mmss(s) { s = Math.max(0, Math.floor(s || 0)); return Math.floor(s / 60) + ":" + pad(s % 60); }
  function seconds(s) {
    if (s >= 3600) return (s / 3600).toFixed(1) + " h";
    if (s >= 120) return Math.round(s / 60) + " min";
    return Math.round(s) + " s";
  }
  function rangeWords(r) { return { "1h": "the last hour", "24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days" }[r] || r; }

  const PLAIN = {
    spam_feed_hit: "On the CallerAPI spam list", voice_firewall_spam: "Live reputation says spam", bcid_spoofed: "Spoofed business number",
    caller_id_not_owned: "Caller ID the customer does not own", ip_intel_block: "Telecom fraud network", ip_intel_hostile: "Hostile network",
    ip_intel_suspicious: "Often abused network", caller_fanout: "Calls many different people", sequential_dialing: "Dials numbers in sequence",
    caller_low_asr: "Few calls answered", caller_short_calls: "Very short calls", caller_hits_honeypots: "Calls your unassigned numbers",
    honeypot_target: "Called an unassigned number", scanner_user_agent: "SIP scanner software", source_invite_flood: "Burst of calls from one source",
    from_invite_flood: "Burst of calls from one number", source_dest_scan: "Scans many destinations", missing_identity: "No STIR/SHAKEN signature",
    shaken_attest_c: "Attestation C", shaken_attest_b: "Attestation B", shaken_verify_failed: "Signature failed", shaken_invalid: "Malformed signature",
    shaken_cert_revoked: "Revoked certificate", shaken_orig_mismatch: "Signed caller ID differs", shaken_unverifiable: "Signature not checkable",
    network_signer: "Bad signer on the network", network_fingerprint: "Bad dialer on the network", premium_rate_dest: "Premium-rate destination",
    invalid_from_number: "Invalid caller ID", synthetic_from: "Made-up caller ID", from_equals_to: "Caller ID equals the called number",
    privacy_id_spoof: "Hidden caller ID", anonymous_from_no_pai: "Anonymous, no network identity", invite_no_sdp: "No audio offer",
    from_pai_mismatch: "Caller ID differs from network identity", from_rpid_mismatch: "Caller ID differs from party ID",
    contact_private_src_public: "Private address on a public call", sdp_zero_connection: "Audio offer has no address",
    max_forwards_low: "Passed through many hops", via_hop_flood: "Unusual number of hops", missing_user_agent: "No software named",
    missing_call_id: "No Call-ID", missing_from: "No caller", shaken_iat_stale: "Signature too old", shaken_iat_future: "Signature dated in the future",
    voice_scam: "Recording sounds like a scam", fas_ringback: "False answer: ringback", fas_busy: "False answer: busy",
    fas_sit: "False answer: intercept", fas_dead_air: "False answer: silence", fail_open: "Let through: unreadable",
  };
  function plain(code) {
    if (PLAIN[code]) return PLAIN[code];
    if (code.indexOf("denylist_") === 0) return "You blocked this " + code.slice(9).replace("spc", "signer").replace("ip", "address");
    if (code.indexOf("allowlist_") === 0) return "You allowed this " + code.slice(10).replace("spc", "signer").replace("ip", "address");
    if (code.indexOf("plugin_") === 0) return "A check you turned on";
    return code.replace(/_/g, " ");
  }
  function headlineCode(reasons) {
    const rs = (reasons || []).slice();
    const ev = rs.find((r) => r.code === "voice_scam" || r.code.indexOf("fas_") === 0);
    if (ev) return ev.code;
    rs.sort((a, b) => (b.weight || 0) - (a.weight || 0));
    return rs.length && (rs[0].weight > 0 || rs.length === 1) ? rs[0].code : "";
  }
  function headline(reasons) {
    const code = headlineCode(reasons);
    return code ? plain(code) : "";
  }
  function verdict(action, held) {
    if (held && action === "reject") return { cls: "would", text: "Would block" };
    if (action === "reject") return { cls: "blocked", text: "Blocked" };
    if (action === "flag" || action === "challenge") return { cls: "flagged", text: "Flagged" };
    return { cls: "allowed", text: "Allowed" };
  }
  const pill = (v) => '<span class="pill ' + v.cls + '">' + esc(v.text) + "</span>";
  const sk = (w, h) => '<span class="sk" style="width:' + w + ";height:" + (h || 14) + 'px"></span>';
  const skRows = (n) => Array.from({ length: n }, () => '<div class="row-item" style="cursor:default">' + sk("100%", 16) + "</div>").join("");

  function toast(msg, kind) {
    const el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.textContent = msg;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), 3600);
  }

  // ---------- shared state ----------
  const state = {
    range: ["1h", "24h", "7d", "30d"].indexOf(localStorage.getItem("falcon_range")) >= 0 ? localStorage.getItem("falcon_range") : "24h",
    q: "",
    status: cache.status || null,
    view: null,
    viewName: "",
  };

  async function loadStatus() {
    try {
      state.status = await get("/v1/status");
      remember("status", state.status);
      const a = state.status.assistant || {};
      $("#askBtn").hidden = !a.provider || a.provider === "off";
      setText($("#versionText"), "Falcon " + (state.status.version || ""));
    } catch (e) { /* the health check reports it */ }
    return state.status;
  }

  // ---------- live stream ----------
  const live = { subs: new Set(), es: null };
  function liveOn(fn) { live.subs.add(fn); }
  function liveOff(fn) { live.subs.delete(fn); }
  function startLive() {
    if (live.es) return;
    const es = new EventSource(withToken("/v1/stream"));
    es.addEventListener("screen", (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch (err) { return; }
      live.subs.forEach((fn) => { try { fn(msg); } catch (err) { /* one bad view must not stop the others */ } });
    });
    live.es = es;
  }

  // ---------- charts ----------
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  document.body.appendChild(tip);
  const COLORS = { blocked: "#ef4444", flagged: "#f59e0b", allowed: "#3b4256", grid: "#1f2330", text: "#5d6377" };

  function drawBars(canvas, series, step) {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width, h = rect.height, padB = 20, padT = 6;
    ctx.clearRect(0, 0, w, h);
    const n = series.length;
    if (!n) return;
    const max = Math.max(1, ...series.map((b) => b.count));
    const innerH = h - padB - padT, bw = w / n;
    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;
    for (let g = 1; g <= 2; g++) {
      const y = Math.round(padT + innerH - (innerH * g) / 2) + 0.5;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    const bars = [];
    series.forEach((b, i) => {
      const x = i * bw + Math.max(1, bw * 0.14), bwi = Math.max(1, bw * 0.72);
      let y = padT + innerH;
      [["allowed", b.allow], ["flagged", b.flag + b.challenge], ["blocked", b.reject]].forEach(([k, v]) => {
        if (!v) return;
        const hh = Math.max(1, (v / max) * innerH);
        ctx.fillStyle = COLORS[k];
        ctx.fillRect(x, y - hh, bwi, hh);
        y -= hh;
      });
      bars.push({ x0: i * bw, x1: (i + 1) * bw, b });
    });
    ctx.fillStyle = COLORS.text;
    ctx.font = "11px ui-sans-serif, system-ui";
    ctx.textAlign = "center";
    const labels = Math.min(6, n);
    for (let i = 0; i < labels; i++) {
      const idx = Math.round((i * (n - 1)) / Math.max(1, labels - 1));
      const d = new Date(series[idx].ts);
      const label = step >= 86400 ? d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) : step >= 3 * 3600 ? d.toLocaleDateString(undefined, { weekday: "short" }) + " " + pad(d.getHours()) + "h" : pad(d.getHours()) + ":" + pad(d.getMinutes());
      ctx.fillText(label, Math.min(w - 24, Math.max(24, idx * bw + bw / 2)), h - 5);
    }
    canvas.onmousemove = (e) => {
      const x = e.clientX - canvas.getBoundingClientRect().left;
      const hit = bars.find((bb) => x >= bb.x0 && x < bb.x1);
      if (!hit) { tip.hidden = true; return; }
      const b = hit.b;
      tip.innerHTML = '<div class="muted">' + esc(dayClock(b.ts)) + "</div><div><b>" + fmtN(b.count) + '</b> calls</div><div style="color:#fca5a5">' + fmtN(b.reject) + ' blocked</div><div style="color:#fcd34d">' + fmtN(b.flag + b.challenge) + " flagged</div>";
      tip.hidden = false;
      tip.style.left = Math.min(window.innerWidth - 180, e.clientX + 14) + "px";
      tip.style.top = e.clientY + 14 + "px";
    };
    canvas.onmouseleave = () => { tip.hidden = true; };
  }

  // ---------- actions shared by views ----------
  async function addRule(rule, label) {
    try {
      await post("/v1/rules", rule);
      toast((label || "Rule saved") + ". It applies to the next call.", "ok");
      return true;
    } catch (e) { toast(e.message, "bad"); return false; }
  }
  async function saveSettings(patchBody, okText) {
    try {
      const r = await put("/v1/settings", patchBody);
      toast(okText || "Saved", "ok");
      return r.effective;
    } catch (e) { toast(e.message, "bad"); return null; }
  }

  // ================= OVERVIEW =================
  function kpiCard(label, key, cls) {
    return '<article class="card kpi ' + (cls || "") + '" data-k="' + key + '"><div class="kpi-label">' + esc(label) + '</div><div class="kpi-value num" data-v>' + sk("60%", 33) + '</div><div class="kpi-sub" data-s></div></article>';
  }

  const Overview = {
    title: "Overview",
    mount(root) {
      root.innerHTML =
        '<section class="card status" id="ovStatus"><div class="status-main"><span class="ring idle"></span><div>' + sk("220px", 16) + "</div></div></section>" +
        '<section class="grid kpis" id="ovKpis">' + kpiCard("Calls screened", "screened") + kpiCard("Blocked", "blocked", "blocked") + kpiCard("Flagged", "flagged", "flagged") +
        kpiCard("Latency Falcon adds", "latency") + '<article class="card kpi fas" data-k="fas" hidden><div class="kpi-label">False answers</div><div class="kpi-value num" data-v>0</div><div class="kpi-sub" data-s></div></article></section>' +
        '<section class="grid main-split">' +
        '<div class="stack"><div class="card"><div class="card-head"><h2>Needs attention</h2><span class="hint" id="ovHint"></span></div><div class="insights" id="ovInsights">' + skRows(3) + "</div></div>" +
        '<div class="card"><div class="card-head"><h2>Calls over time</h2><div class="legend"><span><i style="background:#ef4444"></i>Blocked</span><span><i style="background:#f59e0b"></i>Flagged</span><span><i style="background:#3b4256"></i>Allowed</span></div></div><div class="chart-wrap"><canvas class="chart" id="ovChart"></canvas></div></div></div>' +
        '<div class="card flush recent"><div class="card-head"><h2>Latest stopped calls</h2><a class="link" href="#calls?verdict=stopped">See all</a></div><div class="rows" id="ovRecent">' + skRows(5) + "</div></div>" +
        "</section>";
      if (localStorage.getItem("falcon_kpi5") === "1") {
        $('#ovKpis [data-k="fas"]').hidden = false;
        $("#ovKpis").classList.add("five");
      }
      $("#ovInsights").onclick = (e) => this.onInsight(e);
      $("#ovRecent").onclick = (e) => { const r = e.target.closest("[data-id]"); if (r) Drawer.open(r.dataset.id); };
      this.ro = new ResizeObserver(() => this.drawChart());
      this.ro.observe($("#ovChart"));
      const cached = cache["overview:" + state.range];
      if (cached) this.render(cached);
      this.refresh();
      this.timer = setInterval(() => { if (!document.hidden) this.refresh(); }, 30000);
      this.onLive = (msg) => this.live(msg);
      liveOn(this.onLive);
    },
    unmount() { clearInterval(this.timer); liveOff(this.onLive); if (this.ro) this.ro.disconnect(); },
    rangeChanged() {
      const cached = cache["overview:" + state.range];
      if (cached) this.render(cached);
      this.refresh();
    },
    async refresh() {
      try {
        const d = await get("/v1/overview?range=" + state.range);
        remember("overview:" + state.range, d);
        if (state.view === this) this.render(d);
      } catch (e) {
        patch($("#ovStatus"), '<div class="status-main"><span class="ring warn"></span><div><strong>Falcon did not answer</strong><div class="muted">' + esc(e.message) + "</div></div></div>");
      }
    },
    render(d) {
      this.data = d;
      this.renderStatus(d);
      this.renderKpis(d);
      this.renderInsights(d);
      this.renderRecent(d);
      this.drawChart();
    },
    renderStatus(d) {
      const st = d.status || {};
      const sip = st.sip || {};
      let ring = "", head = "Protecting your switch", sub = "";
      if (!st.last_call_at) {
        ring = "idle"; head = "Waiting for the first call"; sub = "Connect a switch and Falcon starts at once.";
      } else if (st.mode === "monitor") {
        ring = "warn"; head = "Monitor mode: Falcon watches and blocks nothing"; sub = "Last call " + ago(st.last_call_at) + ".";
      } else {
        sub = "Last call " + ago(st.last_call_at) + ". Falcon blocks hard fraud and flags the rest.";
      }
      const tags = ['<span class="tag ' + (st.mode === "monitor" ? "warn" : "good") + '">' + (st.mode === "monitor" ? "Monitor" : "Enforce") + "</span>"];
      if (sip.mode === "bridge" && sip.enabled) {
        tags.push('<span class="tag">Bridge <b>' + fmtN(sip.active_calls || 0) + "</b> up</span>");
        const fm = { off: "FAS guard off", monitor: "FAS guard watching", enforce: "FAS guard holding" }[st.fas_mode] || "FAS guard";
        tags.push('<span class="tag ' + (st.fas_mode === "enforce" ? "good" : "") + '">' + fm + "</span>");
      }
      if (st.voice && st.voice !== "off") tags.push('<span class="tag">AI voice on</span>');
      if (st.update) tags.push('<a class="tag warn" href="https://github.com/CallerAPI/Falcon/releases" target="_blank" rel="noreferrer">Update ' + esc(st.update) + "</a>");
      patch($("#ovStatus"), '<div class="status-main"><span class="ring ' + ring + '"></span><div><strong>' + esc(head) + '</strong><div class="muted">' + esc(sub) + '</div></div></div><div class="status-tags">' + tags.join("") + "</div>");
    },
    renderKpis(d) {
      const t = d.totals || {}, lat = d.latency || {}, words = rangeWords(d.range || state.range);
      const set = (k, v, sub) => {
        const card = $('#ovKpis [data-k="' + k + '"]');
        if (!card) return;
        patch($("[data-v]", card), v);
        setText($("[data-s]", card), sub);
      };
      set("screened", fmtN(t.screened), "In " + words);
      set("blocked", fmtN(t.blocked), t.screened ? pctText(t.blocked, t.screened) + " of calls" + (t.held ? ", plus " + fmtN(t.held) + " held by monitor mode" : "") : "Nothing to stop yet");
      set("flagged", fmtN(t.flagged), t.recorded ? fmtN(t.recorded) + " recorded for review" : "Watched, not blocked");
      set("latency", lat.count ? fmtMs(lat.avg_ms) + "<small>ms</small>" : "0<small>ms</small>", lat.count ? "Average. 95% of calls under " + fmtMs(lat.p95_ms) + " ms" : "No calls measured yet");
      const fasCard = $('#ovKpis [data-k="fas"]');
      const showFas = (t.bridged || 0) > 0 || (t.fas || 0) > 0;
      fasCard.hidden = !showFas;
      $("#ovKpis").classList.toggle("five", showFas);
      localStorage.setItem("falcon_kpi5", showFas ? "1" : "0");
      if (showFas) set("fas", fmtN(t.fas), t.fas ? seconds(t.fas_seconds || 0) + " billed falsely, " + fmtN(t.bridged) + " calls bridged" : fmtN(t.bridged) + " calls bridged, all clean");
    },
    renderInsights(d) {
      const list = d.insights || [];
      this.insights = list;
      setText($("#ovHint"), list.length ? list.length + (list.length === 1 ? " item" : " items") : "");
      if (!list.length) {
        patch($("#ovInsights"), '<div class="clear"><span class="dot ok"></span><div><strong>All clear</strong><span class="muted">Falcon works in the background. Anything that needs you shows up here.</span></div></div>');
        return;
      }
      patch($("#ovInsights"), list.map((it, i) => {
        const external = it.link && it.link.indexOf("http") === 0;
        return '<div class="insight ' + esc(it.severity) + '"><div><h3>' + esc(it.title) + "</h3><p>" + esc(it.detail) + '</p></div><div class="acts">' +
          (it.action ? '<button type="button" class="btn primary sm" data-act="' + i + '">' + esc(it.action.label) + "</button>" : "") +
          (it.link ? '<a class="btn sm" href="' + esc(it.link) + '"' + (external ? ' target="_blank" rel="noreferrer"' : "") + ">" + esc(it.link_text || "Open") + "</a>" : "") +
          '<button type="button" class="icon-btn" data-dismiss="' + i + '" aria-label="Dismiss for a day" title="Dismiss for a day">×</button></div></div>';
      }).join(""));
    },
    async onInsight(e) {
      const act = e.target.closest("[data-act]"), dis = e.target.closest("[data-dismiss]");
      if (!act && !dis) return;
      const it = this.insights[Number((act || dis).dataset.act || (act || dis).dataset.dismiss)];
      if (!it) return;
      const card = (act || dis).closest(".insight");
      (act || dis).disabled = true;
      if (dis) {
        try { await post("/v1/insights/dismiss", { key: it.key, hours: 24 }); card.remove(); toast("Hidden for a day", "ok"); } catch (err) { toast(err.message, "bad"); dis.disabled = false; }
        return;
      }
      let done = false;
      if (it.action.rule) done = await addRule(it.action.rule, it.action.label);
      else if (it.action.setting) done = !!(await saveSettings(it.action.setting, "Done: " + it.action.label));
      if (done) { card.remove(); this.refresh(); loadStatus(); } else act.disabled = false;
    },
    renderRecent(d) {
      const rows = d.recent || [];
      if (!rows.length) {
        patch($("#ovRecent"), '<div class="empty"><strong>Nothing stopped</strong>No blocked or flagged calls in ' + esc(rangeWords(d.range || state.range)) + ".</div>");
        return;
      }
      patch($("#ovRecent"), rows.map((r) => this.recentRow(r)).join(""));
    },
    recentRow(r) {
      const why = r.code ? plain(r.code) : r.why;
      const count = r.calls > 1 ? '<span class="badge">' + fmtN(r.calls) + " calls</span>" : "";
      return '<div class="row-item" data-id="' + r.id + '"><span class="muted small num">' + esc(when(r.at)) + "</span><span>" + pill(verdict(r.action, r.held)) +
        '</span><div class="cell-main"><div class="line1">' + esc(r.from || "unknown") + count + '</div><div class="line2">' + esc(why || "No single reason") + "</div></div></div>";
    },
    drawChart() {
      if (!this.data) return;
      requestAnimationFrame(() => drawBars($("#ovChart"), this.data.series || [], this.data.step_seconds));
    },
    live(msg) {
      if (!this.data || msg.type || !msg.id) return;
      const t = this.data.totals;
      t.screened++;
      if (msg.action === "reject") t.blocked++;
      else if (msg.action === "flag" || msg.action === "challenge") t.flagged++;
      else t.allowed++;
      if (msg.held) t.held++;
      this.renderKpis(this.data);
      if (msg.action !== "allow") {
        const list = (this.data.recent || []).slice();
        const i = msg.from ? list.findIndex((x) => x.from === msg.from) : -1;
        const calls = i >= 0 ? (list[i].calls || 1) + 1 : 1;
        if (i >= 0) list.splice(i, 1);
        const top = headlineCode(msg.reasons);
        list.unshift({ id: msg.id, at: msg.received_at, action: msg.action, held: msg.held, from: msg.from, to: msg.to, code: top, why: "", calls: calls });
        this.data.recent = list.slice(0, 8);
        this.renderRecent(this.data);
        const first = $("#ovRecent .row-item");
        if (first) first.classList.add("new");
      }
    },
  };
  function pctText(a, b) { if (!b) return "0%"; const p = (a * 100) / b; return (p < 1 && p > 0 ? p.toFixed(1) : Math.round(p)) + "%"; }

  // ================= CALLS =================
  const FILTERS = [
    ["all", "All"], ["stopped", "Stopped"], ["blocked", "Blocked"], ["flagged", "Flagged"], ["recorded", "Recorded"], ["fas", "False answers"], ["outbound", "Outbound"],
  ];
  const VERDICTS = ["stopped", "blocked", "flagged"];
  const Calls = {
    title: "Calls",
    mount(root, params) {
      this.filter = VERDICTS.indexOf(params.verdict) >= 0 ? params.verdict : params.recorded ? "recorded" : params.fas ? "fas" : params.direction === "outbound" ? "outbound" : "all";
      if (params.q !== undefined) { state.q = params.q; $("#search").value = state.q; }
      root.innerHTML = '<div class="chips" id="callChips">' + FILTERS.map(([k, label]) => '<button type="button" class="chip-btn" data-f="' + k + '">' + label + "</button>").join("") + "</div>" +
        '<div class="card flush calls"><div class="row-head"><span>Time</span><span>Result</span><span>Call</span><span>Why</span><span class="right">Score</span><span class="right">Added</span></div>' +
        '<div class="rows" id="callRows">' + skRows(8) + '</div><div class="list-foot"><button type="button" class="btn" id="moreBtn" hidden>Load more</button></div></div>';
      this.paintChips();
      $("#callChips").onclick = (e) => {
        const b = e.target.closest("[data-f]");
        if (!b) return;
        this.filter = b.dataset.f;
        this.paintChips();
        history.replaceState(null, "", "#calls" + this.hashQuery());
        this.load(true);
      };
      $("#callRows").onclick = (e) => { const r = e.target.closest("[data-id]"); if (r) Drawer.open(r.dataset.id); };
      $("#moreBtn").onclick = () => this.load(false);
      this.onLive = (msg) => this.live(msg);
      liveOn(this.onLive);
      const key = "calls:" + this.cacheKey();
      if (cache[key]) this.paint(cache[key].data, true);
      this.load(true);
    },
    unmount() { liveOff(this.onLive); },
    rangeChanged() { this.load(true); },
    searchChanged() { history.replaceState(null, "", "#calls" + this.hashQuery()); this.load(true); },
    paintChips() { $$("#callChips [data-f]").forEach((b) => b.classList.toggle("on", b.dataset.f === this.filter)); },
    cacheKey() { return this.filter + "|" + state.range + "|" + state.q; },
    hashQuery() {
      const p = new URLSearchParams();
      if (VERDICTS.indexOf(this.filter) >= 0) p.set("verdict", this.filter);
      if (this.filter === "recorded") p.set("recorded", "1");
      if (this.filter === "fas") p.set("fas", "1");
      if (this.filter === "outbound") p.set("direction", "outbound");
      if (state.q) p.set("q", state.q);
      const s = p.toString();
      return s ? "?" + s : "";
    },
    query(before) {
      const p = new URLSearchParams(this.hashQuery().slice(1));
      p.set("range", state.range);
      p.set("limit", "60");
      if (before) p.set("before", String(before));
      return "/v1/events?" + p.toString();
    },
    async load(reset) {
      if (this.loading) return;
      this.loading = true;
      try {
        const res = await get(this.query(reset ? 0 : this.next));
        const rows = res.data || [];
        this.next = res.next_before || 0;
        if (reset) {
          this.rows = rows;
          remember("calls:" + this.cacheKey(), { data: rows });
          this.paint(rows, true);
        } else {
          this.rows = this.rows.concat(rows);
          $("#callRows").insertAdjacentHTML("beforeend", rows.map((r) => this.row(r)).join(""));
          $("#callRows").__html = null;
        }
        $("#moreBtn").hidden = rows.length < 60;
      } catch (e) {
        toast(e.message, "bad");
      } finally {
        this.loading = false;
      }
    },
    paint(rows) {
      if (!rows.length) {
        const words = rangeWords(state.range);
        patch($("#callRows"), '<div class="empty"><strong>No calls</strong>' + (state.q || this.filter !== "all" ? "Nothing matches in " + esc(words) + "." : "No calls in " + esc(words) + ".") + "</div>");
        return;
      }
      patch($("#callRows"), rows.map((r) => this.row(r)).join(""));
    },
    row(ev, fresh) {
      const v = verdict(ev.action, ev.held);
      const codes = (ev.reasons || []).map((r) => r.code);
      const badges = (codes.some((c) => c.indexOf("fas_") === 0) ? '<span class="badge fas">FAS</span>' : "") + (codes.indexOf("voice_scam") >= 0 ? '<span class="badge fas">Scam</span>' : "") + (ev.sampled ? '<span class="badge rec">Audio</span>' : "");
      const src = [ev.provider, ev.source_ip].filter(Boolean).join(", ");
      return '<div class="row-item' + (fresh ? " new" : "") + '" data-id="' + ev.id + '"><span class="muted small num" title="' + esc(ev.received_at) + '">' + esc(when(ev.received_at)) + "</span>" +
        "<span>" + pill(v) + "</span>" +
        '<div class="cell-main"><div class="line1">' + esc(ev.from || "unknown") + ' <span class="faint">to</span> ' + esc(ev.to || "") + '</div><div class="line2">' + esc(src || ev.direction || "") + "</div></div>" +
        '<div class="why">' + esc(headline(ev.reasons) || "Nothing wrong") + badges + "</div>" +
        '<span class="right mono">' + esc(ev.risk_score) + "</span>" +
        '<span class="right muted small num">' + (ev.latency_us ? fmtMs(ev.latency_us / 1000) + " ms" : "") + "</span></div>";
    },
    matches(ev) {
      switch (this.filter) {
        case "stopped": if (ev.action === "allow") return false; break;
        case "blocked": if (ev.action !== "reject") return false; break;
        case "flagged": if (ev.action !== "flag" && ev.action !== "challenge") return false; break;
        case "outbound": if (ev.direction !== "outbound") return false; break;
        case "recorded": case "fas": return false;
      }
      return !state.q || JSON.stringify(ev).toLowerCase().indexOf(state.q.toLowerCase()) >= 0;
    },
    live(msg) {
      if (msg.type || !msg.id || !this.matches(msg)) return;
      const box = $("#callRows");
      if ($(".empty", box)) box.innerHTML = "";
      box.insertAdjacentHTML("afterbegin", this.row(msg, true));
      box.__html = null;
      this.rows = [msg].concat(this.rows || []);
    },
  };

  // ================= CALL DRAWER =================
  const Drawer = {
    async open(id) {
      this.id = id;
      $("#drawer").hidden = false;
      $("#scrim").hidden = false;
      setText($("#drawerKicker"), "Call");
      setText($("#drawerTitle"), "");
      $("#drawerBody").innerHTML = '<div class="stack">' + sk("100%", 64) + sk("60%", 18) + sk("100%", 120) + "</div>";
      try {
        const ev = await get("/v1/events/" + id);
        if (this.id !== id) return;
        this.render(ev);
      } catch (e) {
        $("#drawerBody").innerHTML = '<div class="empty"><strong>Could not load the call</strong>' + esc(e.message) + "</div>";
      }
    },
    async refresh() {
      const id = this.id;
      if (!id || (this.audio && !this.audio.paused)) return;
      try {
        const ev = await get("/v1/events/" + id);
        if (this.id === id) this.render(ev);
      } catch (e) { /* keep what is on screen */ }
    },
    close() {
      $("#drawer").hidden = true;
      $("#scrim").hidden = true;
      if (this.audio) { this.audio.pause(); this.audio = null; }
      this.id = null;
    },
    render(ev) {
      if (this.audio) { this.audio.pause(); this.audio = null; }
      this.ev = ev;
      setText($("#drawerKicker"), dayClock(ev.received_at) + (ev.direction === "outbound" ? ", outbound" : "") + (ev.customer ? ", customer " + ev.customer : ""));
      setText($("#drawerTitle"), (ev.from || "unknown") + "  to  " + (ev.to || ""));
      const v = verdict(ev.action, ev.held);
      const lines = {
        blocked: "Falcon stopped this call. The switch got SIP 603.",
        would: "Monitor mode: Falcon would have stopped this call. It was let through.",
        flagged: "Falcon let this call through and marked it for review.",
        allowed: "Nothing about this call needed action.",
      };
      const media = ev.media || null, voice = ev.voice || null;
      let html = '<div class="verdict ' + v.cls + '"><div><strong>' + esc(v.text) + '</strong><span class="muted small">' + esc(lines[v.cls]) + '</span></div><div class="score"><b>' + esc(ev.risk_score) + '</b><span class="muted small">risk score</span></div></div>';
      if (ev.recording_url || (voice && (voice.transcript || voice.turns))) html += '<div class="section" id="dwAudio"></div>';
      if (media && media.answer_ms) html += '<div class="section" id="dwFas"></div>';
      const why = ev.why || [];
      html += '<div class="section"><h3>Why</h3>' + (why.length ? '<ul class="reasons">' + why.map((w) => '<li class="' + (w.evidence ? "ev" : "") + '"><div><div class="t">' + esc(w.text) + "</div>" + (w.detail ? '<div class="d">' + esc(w.detail) + "</div>" : "") + '</div><span class="w">' + (w.evidence ? "heard" : "+" + w.weight) + "</span></li>").join("") + "</ul>" : '<p class="muted">Nothing looked wrong.</p>') + "</div>";
      const fasOn = state.status && state.status.fas && state.status.fas.mode === "enforce";
      const fasActs = media && media.fas ? (fasOn ? "" : '<button type="button" class="btn primary sm" data-fas="enforce">Hold false answers</button>') + '<a class="btn sm" href="#threats?tab=vendors">Compare vendors</a>' : "";
      html += '<div class="section"><h3>Act on it</h3><div class="actions" id="dwActs">' + fasActs +
        (ev.from ? '<button type="button" class="btn danger sm" data-rule="deny|number|' + esc(ev.from) + '">Block ' + esc(ev.from) + '</button><button type="button" class="btn sm" data-rule="allow|number|' + esc(ev.from) + '">Allow this number</button>' : "") +
        (ev.source_ip ? '<button type="button" class="btn sm" data-rule="deny|ip|' + esc(ev.source_ip) + '">Block address ' + esc(ev.source_ip) + "</button>" : "") +
        (ev.signer_spc ? '<button type="button" class="btn sm" data-rule="deny|spc|' + esc(ev.signer_spc) + '">Block signer ' + esc(ev.signer_spc) + "</button>" : "") +
        '<a class="btn ghost sm" href="#calls?q=' + encodeURIComponent(ev.from || "") + '">All calls from this number</a>' +
        (ev.from ? '<a class="btn ghost sm" href="' + esc(withToken("/v1/traceback.zip?number=" + encodeURIComponent(ev.from) + "&range=7d")) + '">Traceback pack</a>' : "") + "</div></div>";
      html += this.technical(ev);
      $("#drawerBody").innerHTML = html;
      $("#dwActs").onclick = async (e) => {
        const f = e.target.closest("[data-fas]");
        if (f) {
          f.disabled = true;
          if (await saveSettings({ fas_mode: f.dataset.fas }, "FAS guard holds false answers now")) { f.remove(); loadStatus(); } else f.disabled = false;
          return;
        }
        const b = e.target.closest("[data-rule]");
        if (!b) return;
        const [kind, subject, value] = b.dataset.rule.split("|");
        b.disabled = true;
        await addRule({ kind, subject, value, note: "from call " + ev.id }, (kind === "deny" ? "Blocked " : "Allowed ") + value);
      };
      if ($("#dwAudio")) this.audioSection(ev);
      if ($("#dwFas")) this.fasSection(ev);
    },
    audioSection(ev) {
      const voice = ev.voice || {};
      let turns = voice.turns || [];
      const box = $("#dwAudio");
      let html = "<h3>Recording</h3>";
      if (ev.recording_url) {
        html += '<div class="player"><div class="player-top"><button type="button" class="play" id="plBtn" aria-label="Play">&#9654;</button><div class="track"><div class="bar" id="plBar"><i></i></div><div class="times"><span id="plNow">0:00</span><span id="plDur">' + mmss(voice.seconds || (ev.media && ev.media.seconds) || 0) + "</span></div></div>" +
          '<a class="btn ghost sm" href="' + esc(withToken(ev.recording_url)) + '" download>Download</a></div><div class="lanes" id="plLanes"></div></div>';
      } else {
        html += '<p class="muted small">The audio is not kept, only the text.</p>';
      }
      if (voice.category && voice.category !== "none") {
        const scam = voice.score >= 0.7;
        html += '<div class="ai" style="margin-top:12px"><span class="pill ' + (scam ? "blocked" : "neutral") + '">' + (scam ? "Sounds like a scam" : "Not a scam") + '</span><span class="tag">' + esc(voice.category) + '</span><span class="tag">' + Math.round((voice.score || 0) * 100) + "% sure</span></div>";
      } else if (voice.category === "none") {
        html += '<div class="ai" style="margin-top:12px"><span class="pill allowed">Ordinary call</span></div>';
      }
      if (voice.summary) html += '<p class="small" style="margin:10px 0 0">' + esc(voice.summary) + "</p>";
      if (turns.length) {
        html += '<div class="transcript" id="plText" style="margin-top:14px">' + turns.map((t, i) => '<div class="bubble ' + (t.speaker === "callee" ? "callee" : "caller") + '" data-i="' + i + '" data-t="' + (t.start || 0) + '"><div class="who"><span>' + (t.speaker === "callee" ? "Callee" : "Caller") + "</span><span>" + mmss(t.start) + "</span></div><p>" + esc(t.text) + "</p></div>").join("") + "</div>";
      } else if (voice.transcript) {
        html += "<pre>" + esc(voice.transcript) + "</pre>";
      } else if (voice.error) {
        html += '<p class="small" style="color:#fca5a5;margin-top:10px">The transcript failed: ' + esc(voice.error) + "</p>";
      } else if (ev.recording_url) {
        html += '<p class="muted small" style="margin-top:10px">No transcript yet. Turn on AI voice analysis in Settings to get one.</p>';
      }
      box.innerHTML = html;
      if (ev.recording_url) this.player(ev, turns);
      const text = $("#plText");
      if (text && this.audio) text.onclick = (e) => { const b = e.target.closest("[data-t]"); if (b) { this.audio.currentTime = Number(b.dataset.t); this.audio.play(); } };
    },
    player(ev, turns) {
      const audio = new Audio();
      audio.preload = "metadata";
      audio.src = withToken(ev.recording_url);
      this.audio = audio;
      const btn = $("#plBtn"), bar = $("#plBar"), fill = $("#plBar i");
      const total = () => (isFinite(audio.duration) && audio.duration > 0 ? audio.duration : (ev.voice && ev.voice.seconds) || (ev.media && ev.media.seconds) || 1);
      const lanes = () => {
        const tt = total();
        const span = (t) => '<span style="left:' + Math.min(100, (t.start / tt) * 100) + "%;width:" + Math.max(0.6, ((t.end - t.start) / tt) * 100) + '%"></span>';
        let fas = "";
        const m = ev.media;
        if (m && m.fas && m.fas_ms && m.answer_ms) {
          const start = m.answer_ms / 1000, end = start + m.fas_ms / 1000;
          fas = '<span>False answer</span><div class="lane fas">' + span({ start: start, end: Math.min(end, tt) }) + "</div>";
        }
        $("#plLanes").innerHTML = '<span>Caller</span><div class="lane caller">' + turns.filter((t) => t.speaker !== "callee").map(span).join("") + '</div><span>Callee</span><div class="lane callee">' + turns.filter((t) => t.speaker === "callee").map(span).join("") + "</div>" + fas;
      };
      lanes();
      audio.addEventListener("loadedmetadata", () => { setText($("#plDur"), mmss(total())); lanes(); });
      audio.addEventListener("timeupdate", () => {
        fill.style.width = Math.min(100, (audio.currentTime / total()) * 100) + "%";
        setText($("#plNow"), mmss(audio.currentTime));
        $$("#plText .bubble").forEach((b) => {
          const t = turns[Number(b.dataset.i)];
          b.classList.toggle("playing", !audio.paused && audio.currentTime >= t.start && audio.currentTime < t.end + 0.3);
        });
      });
      audio.addEventListener("play", () => { btn.innerHTML = "&#10074;&#10074;"; btn.setAttribute("aria-label", "Pause"); });
      audio.addEventListener("pause", () => { btn.innerHTML = "&#9654;"; btn.setAttribute("aria-label", "Play"); });
      audio.addEventListener("error", () => { $(".player").insertAdjacentHTML("beforeend", '<p class="small" style="color:#fca5a5;margin:0">The recording is gone. Recordings are kept for the days set in Settings.</p>'); btn.disabled = true; });
      btn.onclick = () => { if (audio.paused) audio.play(); else audio.pause(); };
      bar.onclick = (e) => { const r = bar.getBoundingClientRect(); audio.currentTime = ((e.clientX - r.left) / r.width) * total(); };
    },
    fasSection(ev) {
      const m = ev.media;
      const end = Math.max(m.end_ms || 0, m.answer_ms + 1);
      const ring = m.answer_ms, falseMS = Math.min(m.fas_ms || 0, end - m.answer_ms), talk = Math.max(0, end - m.answer_ms - falseMS);
      const pctW = (x) => ((x / end) * 100).toFixed(2) + "%";
      const kind = { ringback: "kept ringing", busy: "played a busy tone", sit: "played an intercept", dead_air: "sent no audio" }[m.fas] || "";
      const action = { held: "Falcon held the answer until a person spoke, so the caller was not billed for it.", failed: "Falcon failed the call back to the switch, so it could route the call again.", observed: "Falcon watched. Turn on FAS holding in Settings to stop it." }[m.fas_action] || "";
      const head = m.fas ? '<p style="margin:0 0 10px"><b style="color:#fca5a5">False answer.</b> ' + esc((m.route || "The vendor") + " answered and then " + kind + " for " + seconds((m.fas_ms || 0) / 1000) + ". " + action) + "</p>" : '<p class="muted small" style="margin:0 0 10px">Clean answer' + (m.route ? " from " + esc(m.route) : "") + ". A person or a voice spoke after the answer.</p>";
      $("#dwFas").innerHTML = "<h3>Answer supervision</h3>" + head + '<div class="timeline"><div class="tl-bar"><span class="tl-ring" style="width:' + pctW(ring) + '"></span>' + (falseMS ? '<span class="tl-false" style="width:' + pctW(falseMS) + '"></span>' : "") + '<span class="tl-talk" style="width:' + pctW(talk) + '"></span></div>' +
        '<div class="tl-legend"><span><i class="tl-ring"></i>Setup ' + seconds(ring / 1000) + "</span>" + (falseMS ? '<span><i class="tl-false"></i>False answer ' + seconds(falseMS / 1000) + "</span>" : "") + '<span><i class="tl-talk"></i>Conversation ' + seconds(talk / 1000) + "</span>" + (m.ended_by ? "<span>Ended by " + esc(m.ended_by) + "</span>" : "") + "</div></div>";
    },
    technical(ev) {
      const sh = ev.shaken || {};
      const rows = [
        ["Call-ID", ev.call_id], ["Source", [ev.source_ip, ev.provider].filter(Boolean).join(", ")], ["Software", ev.user_agent],
        ["Signer", ev.signer_spc ? ev.signer_spc + (ev.signer_name ? ", " + ev.signer_name : "") : ""], ["Attestation", ev.shaken_attest],
        ["Verification", ev.verstat], ["Switch", ev.switch], ["Latency added", ev.latency_us ? fmtMs(ev.latency_us / 1000) + " ms" : ""],
        ["Fingerprint", ev.fingerprint], ["Bridged by", ev.media ? (ev.media.route || "the default path") + ", " + (ev.media.carry || "") : ""],
      ].filter((r) => r[1]);
      let checks = "";
      if (sh.source === "switch") {
        checks = '<p class="muted small" style="margin:12px 0 0">The switch signs this call after Falcon screens it' + (sh.attest ? " with attestation " + esc(sh.attest) : "") + ". Falcon did not check a signature.</p>";
      } else if (sh.present) {
        const c = [["Signature verifies", sh.signature_ok, sh.pending], ["Certificate chains to a trusted CA", sh.chain_trusted, sh.pending], ["Certificate not revoked", !sh.revoked, sh.pending], ["Signed caller ID matches", sh.orig_matches_from, !sh.orig_tn], ["Signature is fresh", sh.fresh, !sh.iat]];
        checks = '<div class="check">' + c.map(([l, ok, na]) => '<div class="' + (na ? "na" : ok ? "ok" : "bad") + '"><span class="m">' + (na ? "-" : ok ? "✓" : "✕") + "</span><span>" + esc(l) + "</span></div>").join("") + "</div>";
      }
      return '<details class="tech"><summary>Technical details</summary><dl class="kv">' + rows.map((r) => "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>").join("") + "</dl>" + checks + (ev.raw_sip ? "<pre>" + esc(ev.raw_sip) + "</pre>" : "") + "</details>";
    },
  };

  // ================= THREATS =================
  const TABS = [["numbers", "Numbers"], ["signers", "Signers"], ["networks", "Networks"], ["upstreams", "Upstreams"], ["vendors", "Vendors"], ["tracebacks", "Tracebacks"], ["mine", "Your numbers"]];
  const Threats = {
    title: "Threats",
    mount(root, params) {
      this.tab = TABS.some((t) => t[0] === params.tab) ? params.tab : "numbers";
      root.innerHTML = '<div class="tabs" id="thTabs">' + TABS.map(([k, l]) => '<button type="button" data-t="' + k + '">' + l + "</button>").join("") + '</div><div id="thBody" class="stack"></div>';
      $("#thTabs").onclick = (e) => { const b = e.target.closest("[data-t]"); if (b) { this.tab = b.dataset.t; history.replaceState(null, "", "#threats?tab=" + this.tab); this.show(); } };
      $("#thBody").onclick = (e) => this.onClick(e);
      $("#thBody").onchange = (e) => { if (e.target.id === "upMonth" && e.target.value) { this.month = e.target.value; this.show(); } };
      this.show();
    },
    rangeChanged() { this.show(); },
    show() {
      $$("#thTabs [data-t]").forEach((b) => b.classList.toggle("on", b.dataset.t === this.tab));
      const body = $("#thBody");
      body.__html = null;
      const fn = { numbers: this.numbers, signers: this.signers, networks: this.networks, upstreams: this.upstreams, vendors: this.vendors, tracebacks: this.tracebacks, mine: this.mine }[this.tab];
      fn.call(this, body);
    },
    table(head, rows, empty) {
      return '<div class="card flush"><div class="table-wrap"><table><thead><tr>' + head.map((h) => "<th" + (h[1] ? ' class="right"' : "") + ">" + esc(h[0]) + "</th>").join("") + "</tr></thead><tbody>" +
        (rows.length ? rows.join("") : '<tr><td colspan="' + head.length + '"><div class="empty">' + empty + "</div></td></tr>") + "</tbody></table></div></div>";
    },
    async loadInto(body, key, url, render) {
      if (cache[key]) patch(body, render(cache[key]));
      else body.innerHTML = '<div class="card">' + sk("100%", 120) + "</div>";
      try {
        const d = await get(url);
        remember(key, d);
        if (state.view === this) patch(body, render(d));
      } catch (e) { patch(body, '<div class="card"><div class="empty"><strong>Could not load</strong>' + esc(e.message) + "</div></div>"); }
    },
    numbers(body) {
      this.loadInto(body, "suspects:" + state.range, "/v1/suspects?limit=60&range=" + state.range, (d) => {
        const rows = (d.data || []).map((r) => '<tr><td class="mono">' + esc(r.number) + "</td><td>" + esc((r.reasons || []).slice(0, 2).map((x) => plain(x.code)).join(", ") || "High score") +
          '</td><td class="right num">' + fmtN(r.calls) + '</td><td class="right num" style="color:' + (r.held ? "#fcd34d" : "inherit") + '">' + fmtN(r.held) + '</td><td class="right num">' + fmtN(r.destinations) + '</td><td class="muted small">' + esc(ago(r.last_seen)) +
          '</td><td class="acts"><a class="btn sm" href="#calls?q=' + encodeURIComponent(r.number) + '">Calls</a>' +
          (r.calls > r.reject ? '<button type="button" class="btn danger sm" data-rule="deny|number|' + esc(r.number) + '">Block</button>' : '<span class="muted small">Already blocked</span>') + "</td></tr>");
        return '<p class="muted small" style="margin:0">Calling numbers that stand out in ' + esc(rangeWords(state.range)) + ". Flagged calls got through, so numbers with the most flagged calls come first.</p>" +
          this.table([["Number"], ["Why"], ["Calls", 1], ["Flagged", 1], ["People reached", 1], ["Last seen"], [""]], rows, "<strong>No number stands out</strong>Calls look ordinary in this window.");
      });
    },
    signers(body) {
      this.loadInto(body, "signers:" + state.range, "/v1/parties?by=signer&limit=100&range=" + state.range, (d) => {
        const rows = (d.data || []).map((p) => '<tr><td class="mono">' + esc(p.name) + "</td><td>" + esc(p.label || "") + '</td><td class="right num">' + fmtN(p.total) +
          '</td><td class="right num" style="color:' + (p.verstat_failed / Math.max(1, p.total) > 0.2 ? "#fca5a5" : "inherit") + '">' + pctText(p.verstat_failed, p.total) +
          '</td><td class="right num">' + pctText(p.reject, p.total) + '</td><td class="right num">' + (p.network_score ? esc(p.network_score) : "") +
          '</td><td class="acts"><a class="btn sm" href="#calls?q=' + encodeURIComponent(p.name) + '">Calls</a><a class="btn ghost sm" href="' + esc(withToken("/v1/traceback.zip?spc=" + encodeURIComponent(p.name) + "&range=" + state.range)) + '" title="The archive a traceback request asks for">Traceback</a><button type="button" class="btn danger sm" data-rule="deny|spc|' + esc(p.name) + '">Block</button></td></tr>');
        return '<p class="muted small" style="margin:0">The providers that signed calls with STIR/SHAKEN. Blocking a signer stops every call it attests, whatever number it shows.</p>' +
          this.table([["SPC"], ["Signer"], ["Calls", 1], ["Failed", 1], ["Blocked", 1], ["Network score", 1], [""]], rows, "<strong>No signed calls</strong>Signers appear once INVITEs carry a STIR/SHAKEN signature.");
      });
    },
    networks(body) {
      this.loadInto(body, "ips:" + state.range, "/v1/parties?by=ip&limit=100&range=" + state.range, (d) => {
        const rows = (d.data || []).map((p) => '<tr><td class="mono">' + esc(p.name) + "</td><td>" + esc(p.label || "") + '</td><td class="right num">' + fmtN(p.total) +
          '</td><td class="right num" style="color:' + (p.reject / Math.max(1, p.total) > 0.5 ? "#fca5a5" : "inherit") + '">' + pctText(p.reject, p.total) + '</td><td class="right num">' + fmtN(p.distinct_from) +
          '</td><td class="muted small">' + esc(ago(p.last_seen)) + '</td><td class="acts"><a class="btn sm" href="#calls?q=' + encodeURIComponent(p.name) + '">Calls</a><button type="button" class="btn danger sm" data-rule="deny|ip|' + esc(p.name) + '">Block</button></td></tr>');
        return '<p class="muted small" style="margin:0">Where the SIP came from, with the network that owns each address.</p>' +
          this.table([["Address"], ["Network"], ["Calls", 1], ["Blocked", 1], ["Callers", 1], ["Last seen"], [""]], rows, "<strong>No traffic</strong>No calls in this window.");
      });
    },
    upstreams(body) {
      const month = this.month || new Date().toISOString().slice(0, 7);
      this.loadInto(body, "upreport:" + month, "/v1/upstreams/report?month=" + month, (d) => {
        const rows = (d.data || []).map((r) => "<tr><td>" + (r.id ? "<strong>" + esc(r.name) + "</strong>" : '<span class="muted">' + esc(r.name) + "</span>") +
          (r.rmd || r.frn ? '<div class="muted small mono">' + esc([r.rmd, r.frn].filter(Boolean).join(" / ")) + "</div>" : "") + "</td><td>" + (r.id ? standingPill({ check: r.standing ? { standing: r.standing, confirmed: r.confirmed } : null, words: r.standing_text }) : "") +
          '</td><td class="right num">' + fmtN(r.calls) + '</td><td class="right num" style="color:' + (r.blocked / Math.max(1, r.calls) > 0.2 ? "#fca5a5" : "inherit") + '">' + pctText(r.blocked, r.calls) +
          '</td><td class="right num">' + pctText(r.flagged, r.calls) + '</td><td class="right num">' + fmtN(r.spam_hits) + '</td><td class="right num">' + fmtN(r.honeypots) +
          '</td><td class="right num">' + fmtN(r.verify_failed) + '</td><td class="right num">' + fmtN(r.unsigned) + '</td><td class="right num">' + fmtN(r.tracebacks) + "</td></tr>");
        return '<div style="display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap"><p class="muted small" style="margin:0;max-width:640px">Each upstream for one month: what it sent, what Falcon stopped, and its FCC standing. Keep the CSV as evidence that you know your upstreams.</p>' +
          '<div style="display:flex;gap:8px;align-items:center"><input type="month" id="upMonth" value="' + esc(month) + '"><a class="btn sm" href="' + esc(withToken("/v1/upstreams/report.csv?month=" + month)) + '">Export CSV</a></div></div>' +
          this.table([["Upstream"], ["FCC standing"], ["Calls", 1], ["Blocked", 1], ["Flagged", 1], ["Spam list", 1], ["Honeypot", 1], ["Failed checks", 1], ["Unsigned or C", 1], ["Tracebacks", 1]], rows, "<strong>No upstreams</strong>Add your upstream carriers in Rules.");
      });
    },
    tracebacks(body) {
      body.innerHTML = '<div class="card"><div class="card-head"><h2>Log a traceback request</h2><span class="hint">You have 24 hours to answer</span></div>' +
        '<form id="tbForm" class="stack" style="gap:10px"><div class="form-row" style="grid-template-columns:repeat(3, minmax(0,1fr)) minmax(0,1.2fr)">' +
        '<label class="field">Calling number<input name="from" type="text" placeholder="+13125550100" required></label><label class="field">Called number<input name="to" type="text" placeholder="+14155550123"></label>' +
        '<label class="field">Call time (UTC)<input name="call_at" type="text" placeholder="2026-10-21 14:03:07" required></label><label class="field">Request reference<input name="reference" type="text" placeholder="Case number"></label></div>' +
        '<div class="form-row" style="grid-template-columns:150px minmax(0,1fr) auto"><label class="field">Search window<select name="window_minutes"><option value="5">5 minutes</option><option value="10" selected>10 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option></select></label>' +
        '<label class="field">Request received (UTC, empty is now)<input name="requested_at" type="text" placeholder="2026-10-21 15:00:00"></label><button class="btn primary" type="submit">Find the call</button></div></form>' +
        '<p class="muted small" style="margin:12px 0 0">Falcon searches its own call log, names the upstream that sent the call, and writes the answer. The called number never leaves this host.</p></div>' +
        '<div id="tbList" class="stack">' + '<div class="card">' + sk("100%", 100) + "</div></div>";
      $("#tbForm").onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target, f = new FormData(form);
        try {
          const c = await post("/v1/tracebacks", { from: f.get("from"), to: f.get("to"), call_at: f.get("call_at"), reference: f.get("reference"), window_minutes: Number(f.get("window_minutes")), requested_at: f.get("requested_at") });
          toast(c.upstream ? "Found the call. It came from " + sentence(c.upstream) : (c.event_ids || []).length ? "Found the call. Its address is not in the registry." : "No matching call. The answer says so.", "ok");
          form.reset();
          this.loadTracebacks();
        } catch (err) { toast(err.message, "bad"); }
      };
      this.loadTracebacks();
    },
    async loadTracebacks() {
      try {
        const res = await get("/v1/tracebacks");
        if (state.view !== this || this.tab !== "tracebacks") return;
        this.cases = res.data || [];
        if (!this.cases.length) { patch($("#tbList"), '<div class="card"><div class="empty"><strong>No traceback requests</strong>Log one above when a request arrives.</div></div>'); return; }
        const utc = (iso) => String(iso || "").replace("T", " ").slice(0, 19) + " UTC";
        const dueIn = (iso) => {
          const mins = Math.round((new Date(iso) - Date.now()) / 60000);
          return mins < 60 ? "Due in " + Math.max(mins, 1) + " min" : "Due in " + Math.round(mins / 60) + " h";
        };
        patch($("#tbList"), this.cases.map((c) => {
          const status = c.status === "answered" ? '<span class="pill allowed">Answered ' + esc(when(c.answered_at)) + "</span>" : c.overdue ? '<span class="pill blocked">Overdue</span>' : '<span class="pill flagged">' + esc(dueIn(c.due_at)) + "</span>";
          const found = c.upstream ? "Came from " + sentence(c.upstream) : (c.event_ids || []).length ? "The address is not in the upstream registry." : "No matching call.";
          return '<div class="card"><div class="card-head"><h2>' + esc(c.reference || "Call from " + c.from) + "</h2>" + status + "</div>" +
            '<p class="muted small" style="margin:0 0 10px">' + esc(c.from + (c.to ? " to " + c.to : "") + ", " + utc(c.call_at) + ". " + found) + "</p>" +
            '<textarea class="mono small" rows="7" style="width:100%" data-answer="' + c.id + '">' + esc(c.answer || "") + "</textarea>" +
            '<div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap"><button type="button" class="btn sm" data-tbcopy="' + c.id + '">Copy answer</button>' +
            (c.status === "answered" ? '<button type="button" class="btn ghost sm" data-tbstatus="' + c.id + '|open">Reopen</button>' : '<button type="button" class="btn primary sm" data-tbstatus="' + c.id + '|answered">Mark answered</button>') +
            ((c.event_ids || []).length ? '<a class="btn ghost sm" href="' + esc(withToken(c.pack_url)) + '">Download the pack</a>' : "") + "</div></div>";
        }).join(""));
      } catch (e) { toast(e.message, "bad"); }
    },
    vendors(body) {
      const render = (d) => {
        const vs = d.vendors || {}, routes = d.routes || {};
        const rows = (vs.data || []).map((r) => {
          const kinds = (r.by_kind || []).map((k) => k.count + " " + ({ ringback: "ringback", busy: "busy", sit: "intercept", dead_air: "silence" }[k.kind] || k.kind)).join(", ");
          return "<tr><td>" + esc(r.route || "Default path") + '</td><td class="right num">' + fmtN(r.calls) + '</td><td class="right num">' + pctText(r.answered, r.calls) +
            '</td><td class="right num" style="color:' + (r.fas ? "#fca5a5" : "inherit") + '">' + fmtN(r.fas) + "</td><td>" + esc(kinds) + '</td><td class="right num">' + (r.fas_seconds ? seconds(r.fas_seconds) : "") +
            '</td><td class="right num">' + (r.avg_ring_ms ? (r.avg_ring_ms / 1000).toFixed(1) + " s" : "") + "</td></tr>";
        });
        const rts = (routes.data || []).map((r) => '<tr><td class="mono">' + esc(r.prefix) + "</td><td>" + esc(r.label) + "</td><td>" + (r.target ? '<span class="mono">' + esc(r.target) + "</span>" : "Back to the switch") +
          "</td><td>" + (r.strip ? "Yes" : "No") + "</td><td>" + (r.carry === "all" ? "Every call" : "Suspicious calls") + '</td><td class="acts"><button type="button" class="btn ghost sm" data-delroute="' + r.id + '">Remove</button></td></tr>');
        const fasMode = vs.fas_mode || "monitor";
        return '<p class="muted small" style="margin:0">False answer supervision per vendor on bridged calls. ' + (fasMode === "enforce" ? "Falcon holds each answer until a person speaks." : fasMode === "off" ? "The FAS guard is off." : "Falcon watches. It does not hold answers yet.") + "</p>" +
          this.table([["Vendor"], ["Bridged", 1], ["Answered", 1], ["False answers", 1], ["Kinds"], ["Billed falsely", 1], ["Avg ring", 1]], rows, "<strong>No bridged calls</strong>Turn on the call bridge to hear vendor answers.") +
          '<div class="card"><div class="card-head"><h2>Vendor routes</h2><span class="hint">The switch adds a tech prefix, Falcon names the vendor</span></div>' +
          '<form id="routeForm" class="form-row" style="grid-template-columns:110px 1.2fr 1.2fr 140px 120px auto">' +
          '<label class="field">Prefix<input name="prefix" type="text" placeholder="9901" required></label><label class="field">Vendor name<input name="label" type="text" placeholder="Vendor X" required></label>' +
          '<label class="field">Send to (empty: back to the switch)<input name="target" type="text" placeholder="203.0.113.7:5060"></label>' +
          '<label class="field">Carry<select name="carry"><option value="all">Every call</option><option value="suspicious">Suspicious calls</option></select></label>' +
          '<label class="field">Strip prefix<select name="strip"><option value="true">Yes</option><option value="false">No</option></select></label><button class="btn primary" type="submit">Add route</button></form>' +
          '<div style="margin-top:14px">' + this.table([["Prefix"], ["Vendor"], ["Send to"], ["Strip"], ["Carry"], [""]], rts, "No routes. Calls without a prefix go back to the switch.") + "</div></div>";
      };
      const key = "vendors:" + state.range;
      if (cache[key]) patch(body, render(cache[key])); else body.innerHTML = '<div class="card">' + sk("100%", 120) + "</div>";
      Promise.all([get("/v1/vendors?range=" + state.range), get("/v1/routes")]).then(([vendors, routes]) => {
        const d = { vendors, routes };
        remember(key, d);
        if (state.view === this && this.tab === "vendors") { patch(body, render(d)); this.bindRoutes(); }
      }).catch((e) => toast(e.message, "bad"));
      this.bindRoutes();
    },
    bindRoutes() {
      const form = $("#routeForm");
      if (!form || form.__bound) return;
      form.__bound = true;
      form.onsubmit = async (e) => {
        e.preventDefault();
        const f = new FormData(form);
        try {
          await post("/v1/routes", { prefix: f.get("prefix"), label: f.get("label"), target: f.get("target"), carry: f.get("carry"), strip: f.get("strip") === "true" });
          toast("Route saved. The bridge uses it on the next call.", "ok");
          this.show();
        } catch (err) { toast(err.message, "bad"); }
      };
    },
    mine(body) {
      body.innerHTML = '<div class="card" id="ncImport"><div class="card-head"><h2>Your numbers</h2><span class="hint">1 credit per new number, 1 credit per number on each recheck</span></div>' +
        '<p class="muted small" style="margin:0 0 12px">Import a file with your numbers. Falcon finds them in any text, spreadsheet, or PDF, and shows which ones carriers and apps flag.</p>' +
        '<form id="ncForm" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center"><input id="ncFile" type="file" required><button class="btn primary" type="submit">Import numbers</button></form></div>' +
        '<div class="card" id="ncSched" hidden></div>' +
        '<div id="ncPanel">' + '<div class="card">' + sk("100%", 120) + "</div></div>";
      get("/v1/numbercheck/schedule").then((s) => this.paintSchedule(s)).catch(() => { /* number check is off; the panel says why */ });
      $("#ncForm").onsubmit = async (e) => {
        e.preventDefault();
        const file = $("#ncFile").files[0];
        if (!file) return;
        const fd = new FormData();
        fd.append("file", file, file.name);
        const btn = $("#ncForm button");
        btn.disabled = true;
        try {
          const res = await fetch("/v1/numbercheck/import", { method: "POST", headers: headers(), body: fd });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || res.statusText);
          toast("Numbers imported", "ok");
          this.paintNumbers(data);
        } catch (err) { toast(err.message, "bad"); }
        btn.disabled = false;
      };
      get("/v1/numbercheck/view?q=" + encodeURIComponent(state.q)).then((d) => this.paintNumbers(d)).catch((e) => {
        const off = /CALLERAPI_API_KEY/.test(e.message);
        if (off && $("#ncImport")) $("#ncImport").hidden = true;
        patch($("#ncPanel"), '<div class="card"><div class="empty"><strong>' + (off ? "Number check is off" : "Could not load your numbers") + "</strong>" +
          esc(off ? "Set CALLERAPI_API_KEY to keep a list of your own numbers and recheck them on a schedule." : e.message) + "</div></div>");
      });
    },
    paintSchedule(s) {
      const box = $("#ncSched");
      if (!box) return;
      const days = [[1, "Mon"], [2, "Tue"], [3, "Wed"], [4, "Thu"], [5, "Fri"], [6, "Sat"], [7, "Sun"]];
      const on = new Set(s.weekdays || []);
      const state = { off: "Off", scheduled: "Next check " + (s.next_run_local || "soon"), checking: "Checking now", paused: "Paused: the account is out of credits" }[s.state] || s.state || "";
      const zone = s.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
      box.hidden = false;
      box.innerHTML = '<div class="card-head"><h2>Recheck schedule</h2><span class="hint">' + esc(state) + "</span></div>" +
        '<form id="ncSchedForm" class="form-row" style="grid-template-columns:110px 140px repeat(2, 120px) minmax(0,1fr) auto">' +
        '<label class="field">Recheck<select name="enabled"><option value="true">On</option><option value="false">Off</option></select></label>' +
        '<label class="field">Every<select name="interval_minutes"><option value="15">15 minutes</option><option value="60">Hour</option><option value="360">6 hours</option><option value="1440">Day</option></select></label>' +
        '<label class="field">From<input name="start" type="time" value="' + esc(s.start || "09:00") + '"></label>' +
        '<label class="field">To<input name="end" type="time" value="' + esc(s.end || "17:00") + '"></label>' +
        '<label class="field">Time zone<input name="timezone" type="text" value="' + esc(zone) + '"></label>' +
        '<button class="btn primary" type="submit">Save</button></form>' +
        '<div class="chips" id="ncDays" style="margin-top:12px">' + days.map(([n, l]) => '<button type="button" class="chip-btn' + (on.has(n) ? " on" : "") + '" data-day="' + n + '">' + l + "</button>").join("") + "</div>" +
        (s.last_run_local ? '<p class="muted small" style="margin:10px 0 0">Last check ' + esc(s.last_run_local) + (s.note ? ". " + esc(s.note) : "") + "</p>" : "");
      const form = $("#ncSchedForm");
      form.enabled.value = s.enabled ? "true" : "false";
      form.interval_minutes.value = String(s.interval_minutes || 60);
      $("#ncDays").onclick = (e) => { const b = e.target.closest("[data-day]"); if (b) b.classList.toggle("on"); };
      form.onsubmit = async (e) => {
        e.preventDefault();
        const weekdays = $$("#ncDays .on").map((b) => Number(b.dataset.day));
        try {
          const saved = await put("/v1/numbercheck/schedule", { enabled: form.enabled.value === "true", interval_minutes: Number(form.interval_minutes.value), weekdays, start: form.start.value, end: form.end.value, timezone: form.timezone.value.trim() });
          toast("Schedule saved. Each recheck costs 1 credit per number.", "ok");
          this.paintSchedule(saved);
        } catch (err) { toast(err.message, "bad"); }
      };
    },
    paintNumbers(panel) {
      const cols = panel.columns || [];
      const stats = (panel.stats || []).map((s) => '<article class="card kpi" style="min-height:0"><div class="kpi-label">' + esc(s.label) + '</div><div class="kpi-value num" style="font-size:22px">' + esc(s.value) + "</div></article>").join("");
      const rows = (panel.rows || []).map((r) => "<tr>" + cols.map((c) => "<td" + (c.key === "number" ? ' class="mono"' : "") + ">" + (c.key === "status" ? '<span class="pill ' + (r[c.key] === "flagged" ? "blocked" : r[c.key] === "clear" ? "allowed" : "neutral") + '">' + esc(r[c.key] || "pending") + "</span>" : esc(r[c.key] || "")) + "</td>").join("") + "</tr>");
      patch($("#ncPanel"), (stats ? '<section class="grid kpis" style="margin-bottom:16px">' + stats + "</section>" : "") + this.table(cols.map((c) => [c.label || c.key]), rows, "<strong>No numbers yet</strong>Import a file to start."));
    },
    async onClick(e) {
      const rule = e.target.closest("[data-rule]");
      if (rule) {
        const [kind, subject, value] = rule.dataset.rule.split("|");
        rule.disabled = true;
        if (await addRule({ kind, subject, value, note: "from threats" }, "Blocked " + value)) rule.textContent = "Blocked";
        else rule.disabled = false;
        return;
      }
      const dr = e.target.closest("[data-delroute]");
      if (dr) {
        try { await del("/v1/routes/" + dr.dataset.delroute); toast("Route removed", "ok"); this.show(); } catch (err) { toast(err.message, "bad"); }
        return;
      }
      const cp = e.target.closest("[data-tbcopy]");
      if (cp) {
        const box = $('[data-answer="' + cp.dataset.tbcopy + '"]');
        try { await navigator.clipboard.writeText(box.value); toast("Answer copied", "ok"); } catch (err) { box.select(); toast("Select the text and copy it", "bad"); }
        return;
      }
      const st = e.target.closest("[data-tbstatus]");
      if (st) {
        const [id, status] = st.dataset.tbstatus.split("|");
        const box = $('[data-answer="' + id + '"]');
        st.disabled = true;
        try {
          await post("/v1/tracebacks/" + id, { status, answer: box ? box.value : undefined });
          toast(status === "answered" ? "Marked answered" : "Reopened", "ok");
          this.loadTracebacks();
        } catch (err) { toast(err.message, "bad"); st.disabled = false; }
      }
    },
  };

  // ================= RULES =================
  const Rules = {
    title: "Rules",
    mount(root) {
      root.innerHTML =
        '<div class="card"><div class="card-head"><h2>Add a rule</h2><span class="hint">Applies to the next call</span></div>' +
        '<form id="ruleForm" class="form-row" style="grid-template-columns:150px 160px minmax(0,1.4fr) minmax(0,1fr) 130px auto">' +
        '<label class="field">Do<select name="kind"><option value="deny">Block</option><option value="allow">Always allow</option><option value="honeypot">Honeypot</option></select></label>' +
        '<label class="field">Match<select name="subject"><option value="number">Number</option><option value="ip">Address or range</option><option value="spc">Signer (SPC)</option></select></label>' +
        '<label class="field">Value<input name="value" type="text" placeholder="+14155550100, 203.0.113.0/24, or 1234" required></label>' +
        '<label class="field">Note<input name="note" type="text" placeholder="Why"></label>' +
        '<label class="field">For<select name="ttl"><option value="">Always</option><option value="1h">1 hour</option><option value="24h">1 day</option><option value="168h">7 days</option><option value="720h">30 days</option></select></label>' +
        '<button class="btn primary" type="submit">Save</button></form>' +
        '<p class="muted small" style="margin:12px 0 0">Block rejects the call with SIP 603. Always allow skips every check. Honeypot marks your unassigned numbers: anyone who calls them is a robocaller.</p></div>' +
        '<div id="ruleList">' + '<div class="card">' + sk("100%", 80) + "</div></div>" +
        '<div class="card"><div class="card-head"><h2>Upstream carriers</h2><span class="hint" id="upHint">Falcon checks each one against FCC orders and the Robocall Mitigation Database</span></div>' +
        '<form id="upForm" class="stack" style="gap:10px"><input type="hidden" name="uid">' +
        '<div class="form-row" style="grid-template-columns:minmax(0,1.6fr) minmax(0,1fr) minmax(0,1fr) minmax(0,1.2fr)"><label class="field">Name<input name="name" type="text" placeholder="Northwind Voice" required></label>' +
        '<label class="field">RMD number<input name="rmd" type="text" placeholder="RMD0012345"></label><label class="field">FRN<input name="frn" type="text" placeholder="0012345678"></label>' +
        '<label class="field">Traceback contact<input name="contact" type="text" placeholder="noc@example.com"></label></div>' +
        '<div class="form-row" style="grid-template-columns:minmax(0,2.6fr) minmax(0,1.2fr) auto"><label class="field">Addresses<input name="ips" type="text" placeholder="192.0.2.10, 198.51.100.0/24"></label>' +
        '<label class="field">Signer codes<input name="spcs" type="text" placeholder="1234, 567J"></label><button class="btn primary" type="submit">Save</button></div></form>' +
        '<p class="muted small" style="margin:12px 0 0">Falcon blocks an upstream only on its RMD number or FRN, never on a name alone. The addresses and signer codes are what a block covers.</p>' +
        '<div id="upList" style="margin-top:14px"></div></div>' +
        '<div class="card"><div class="card-head"><h2>Your customers</h2><span class="hint">Outbound calls with a caller ID the customer does not own are rejected</span></div>' +
        '<form id="custForm" class="form-row" style="grid-template-columns:minmax(0,0.8fr) minmax(0,1fr) minmax(0,2fr) auto">' +
        '<label class="field">Account ID<input name="id" type="text" placeholder="acme" required></label><label class="field">Name<input name="name" type="text" placeholder="Acme Dialer"></label>' +
        '<label class="field">Numbers it may send, comma separated. End a prefix with *<input name="dids" type="text" placeholder="+13125550100, +1312555*"></label><button class="btn primary" type="submit">Save</button></form>' +
        '<div id="custList" style="margin-top:14px"></div></div>';
      $("#ruleForm").onsubmit = async (e) => {
        e.preventDefault();
        const f = new FormData(e.target);
        const kind = f.get("kind");
        if (await addRule({ kind, subject: f.get("subject"), value: f.get("value"), note: f.get("note"), ttl: f.get("ttl") }, kind === "deny" ? "Blocked" : kind === "allow" ? "Allowed" : "Honeypot saved")) { e.target.reset(); this.loadRules(); }
      };
      $("#custForm").onsubmit = async (e) => {
        e.preventDefault();
        const f = new FormData(e.target);
        try {
          await put("/v1/customers", { id: f.get("id"), name: f.get("name"), dids: String(f.get("dids") || "").split(",").map((x) => x.trim()).filter(Boolean) });
          toast("Customer saved", "ok");
          e.target.reset();
          this.loadCustomers();
        } catch (err) { toast(err.message, "bad"); }
      };
      $("#ruleList").onclick = async (e) => {
        const b = e.target.closest("[data-del]");
        if (!b) return;
        try { await del("/v1/rules/" + b.dataset.del); toast("Rule removed", "ok"); this.loadRules(); } catch (err) { toast(err.message, "bad"); }
      };
      $("#custList").onclick = async (e) => {
        const b = e.target.closest("[data-cust]");
        if (!b) return;
        try { await del("/v1/customers/" + encodeURIComponent(b.dataset.cust)); toast("Customer removed", "ok"); this.loadCustomers(); } catch (err) { toast(err.message, "bad"); }
      };
      const split = (v) => String(v || "").split(",").map((x) => x.trim()).filter(Boolean);
      $("#upForm").onsubmit = async (e) => {
        e.preventDefault();
        const form = e.target, f = new FormData(form);
        const body = { id: Number(f.get("uid")) || 0, name: f.get("name"), rmd: f.get("rmd"), frn: f.get("frn"), ips: split(f.get("ips")), spcs: split(f.get("spcs")), contact: f.get("contact") };
        try {
          const saved = await post("/v1/upstreams", body);
          toast(saved.words ? saved.name + ": " + saved.words : "Upstream saved", "ok");
          form.reset();
          form.elements.uid.value = "";
          this.loadUpstreams();
          this.loadRules();
        } catch (err) { toast(err.message, "bad"); }
      };
      $("#upList").onclick = async (e) => {
        const ed = e.target.closest("[data-upedit]"), rm = e.target.closest("[data-updel]");
        if (ed) {
          const u = (this.ups || [])[Number(ed.dataset.upedit)], el = $("#upForm").elements;
          if (!u) return;
          el.uid.value = u.id; el.name.value = u.name; el.rmd.value = u.rmd || ""; el.frn.value = u.frn || "";
          el.ips.value = (u.ips || []).join(", "); el.spcs.value = (u.spcs || []).join(", "); el.contact.value = u.contact || "";
          el.name.focus();
          return;
        }
        if (!rm) return;
        try { await del("/v1/upstreams/" + rm.dataset.updel); toast("Upstream removed", "ok"); this.loadUpstreams(); this.loadRules(); } catch (err) { toast(err.message, "bad"); }
      };
      this.loadRules();
      this.loadUpstreams();
      this.loadCustomers();
    },
    async loadUpstreams() {
      try {
        const res = await get("/v1/upstreams");
        const fcc = res.fcc || {}, list = fcc.list || {};
        let hint = "FCC autopilot is off. Set FALCON_FCC=true to check upstreams.";
        if (fcc.enabled) {
          hint = list.providers ? "Checked against " + fmtN(list.providers) + " providers. " + (fcc.mode === "enforce" ? "Falcon blocks upstreams under an FCC order." : "Monitor mode: Falcon alerts and blocks nothing.") : "Waiting for the FCC list" + (list.error ? ": " + list.error : ".");
        }
        setText($("#upHint"), hint);
        this.ups = res.data || [];
        if (!this.ups.length) { patch($("#upList"), '<p class="muted small" style="margin:0">No upstreams yet. Add the carriers that send you calls, with their RMD number, so Falcon can watch their FCC standing.</p>'); return; }
        const covers = (u) => {
          const all = (u.ips || []).concat((u.spcs || []).map((s) => "SPC " + s));
          return all.length > 4 ? all.slice(0, 4).join(", ") + ", and " + (all.length - 4) + " more" : all.join(", ") || "None";
        };
        patch($("#upList"), '<div class="table-wrap"><table><thead><tr><th>Upstream</th><th>RMD / FRN</th><th>Covers</th><th>FCC standing</th><th></th></tr></thead><tbody>' + this.ups.map((u, i) =>
          "<tr><td><strong>" + esc(u.name) + "</strong>" + (u.contact ? '<div class="muted small">' + esc(u.contact) + "</div>" : "") + '</td><td class="mono small">' + esc([u.rmd, u.frn].filter(Boolean).join(" / ") || "None") +
          '</td><td class="mono small">' + esc(covers(u)) + "</td><td>" + standingPill(u) + (u.check && u.check.since ? '<div class="muted small">Since ' + esc(u.check.since) + "</div>" : "") +
          '</td><td class="acts"><button type="button" class="btn ghost sm" data-upedit="' + i + '">Edit</button><button type="button" class="btn ghost sm" data-updel="' + u.id + '">Remove</button></td></tr>').join("") + "</tbody></table></div>");
      } catch (e) { toast(e.message, "bad"); }
    },
    async loadRules() {
      try {
        const res = await get("/v1/rules");
        const rows = (res.data || []).map((r) => {
          const kind = r.kind === "deny" ? '<span class="pill blocked">Block</span>' : r.kind === "allow" ? '<span class="pill allowed">Allow</span>' : '<span class="pill flagged">Honeypot</span>';
          const exp = r.expires_at && r.expires_at.indexOf("0001") !== 0 ? "Until " + dayClock(r.expires_at) : "Always";
          const from = { fleet: ", from the fleet hub", fcc: ", from the FCC autopilot" }[r.origin] || "";
          return "<tr><td>" + kind + "</td><td>" + esc({ number: "Number", ip: "Address", spc: "Signer" }[r.subject] || r.subject) + '</td><td class="mono">' + esc(r.value) + "</td><td>" + esc(r.note || "") +
            '</td><td class="muted small">' + esc(exp) + from + '</td><td class="acts">' + (from ? "" : '<button type="button" class="btn ghost sm" data-del="' + r.id + '">Remove</button>') + "</td></tr>";
        });
        patch($("#ruleList"), Threats.table([["Rule"], ["Match"], ["Value"], ["Note"], ["Active"], [""]], rows, "<strong>No rules yet</strong>Block a number from any call, or add one above."));
      } catch (e) { toast(e.message, "bad"); }
    },
    async loadCustomers() {
      try {
        const res = await get("/v1/customers");
        const custs = res.data || [];
        if (!custs.length) { patch($("#custList"), '<p class="muted small" style="margin:0">No customers. Add one to stop your own customers from sending caller IDs they do not own.</p>'); return; }
        patch($("#custList"), '<div class="table-wrap"><table><thead><tr><th>Account</th><th>Name</th><th>Numbers</th><th></th></tr></thead><tbody>' + custs.map((c) => '<tr><td class="mono">' + esc(c.id) + "</td><td>" + esc(c.name || "") + '</td><td class="mono small">' + esc((c.dids || []).join(", ") || "Any caller ID") +
          '</td><td class="acts"><a class="btn sm" href="#calls?q=' + encodeURIComponent(c.id) + '">Calls</a><button type="button" class="btn ghost sm" data-cust="' + esc(c.id) + '">Remove</button></td></tr>').join("") + "</tbody></table></div>");
      } catch (e) { toast(e.message, "bad"); }
    },
  };

  const STANDING = { listed: ["allowed", "In the RMD"], blocked: ["blocked", "FCC block order"], removed: ["blocked", "Removed from the RMD"], unlisted: ["blocked", "Not in the RMD"], not_found: ["flagged", "Number not found"], unknown: ["", "No RMD number"] };
  function standingPill(u) {
    const c = u.check;
    if (!c) return '<span class="pill">Not checked</span>';
    let [cls, text] = STANDING[c.standing] || ["", c.standing];
    if (!c.confirmed && cls === "blocked") { cls = "flagged"; text = "May be: " + text; }
    return '<span class="pill ' + cls + '" title="' + esc(u.words || "") + '">' + esc(text) + "</span>";
  }

  // ================= SETTINGS =================
  const PRESETS = [
    ["relaxed", "Relaxed", { flag_score: 50, challenge_score: 75, reject_score: 95 }, "Blocks only near-certain fraud."],
    ["balanced", "Balanced", { flag_score: 40, challenge_score: 60, reject_score: 80 }, "The default for a PBX trunk."],
    ["strict", "Strict", { flag_score: 30, challenge_score: 50, reject_score: 70 }, "Blocks more. Watch for false blocks."],
    ["carrier", "Carrier", { flag_score: 40, challenge_score: 101, reject_score: 101 }, "Scores only flag. Lists and hard checks still block."],
  ];
  const Settings = {
    title: "Settings",
    async mount(root) {
      root.innerHTML = '<div class="card flush" id="setMain"><div style="padding:20px">' + sk("100%", 160) + "</div></div>" + '<div class="card"><div class="card-head"><h2>Add-ons</h2><span class="hint">Built in. Each one says how to turn it on.</span></div><div class="modules" id="setModules">' + sk("100%", 90) + "</div></div>" +
        '<div class="grid two"><div class="card" id="setAlerts"></div><div class="card" id="setData"></div></div><div class="card" id="setSystem"></div>';
      try {
        const [settings, status, modules, alertsRes, audit, cfg] = await Promise.all([get("/v1/settings"), loadStatus(), get("/v1/modules"), get("/v1/alerts?limit=8"), get("/v1/audit?limit=12"), get("/v1/config")]);
        if (state.view !== this) return;
        this.eff = settings.effective;
        this.paintMain(status);
        this.paintModules(modules.data || []);
        this.paintAlerts(alertsRes);
        this.paintData(settings, status);
        this.paintSystem(status, audit.data || [], cfg);
      } catch (e) { toast(e.message, "bad"); }
    },
    paintMain(status) {
      const e = this.eff, sip = (status && status.sip) || {};
      const preset = PRESETS.find((p) => p[2].flag_score === e.flag_score && p[2].challenge_score === e.challenge_score && p[2].reject_score === e.reject_score);
      const bridge = sip.mode === "bridge" && sip.enabled;
      $("#setMain").innerHTML =
        '<div class="set"><div><h3>Protection</h3><p>Enforce blocks hard fraud and tells the switch to drop it. Monitor records every decision and blocks nothing. Start a new switch in monitor for a week.</p></div><div class="ctl">' +
        '<div class="seg" id="modeSeg"><button type="button" data-v="enforce">Enforce</button><button type="button" data-v="monitor">Monitor</button></div></div></div>' +
        '<div class="set"><div><h3>Sensitivity</h3><p>How high a score has to be before Falcon flags, holds, or blocks a call.</p></div><div class="ctl">' +
        '<div class="seg" id="presetSeg">' + PRESETS.map((p) => '<button type="button" data-p="' + p[0] + '">' + p[1] + "</button>").join("") + "</div>" +
        '<p class="muted small" id="presetHint">' + esc(preset ? preset[3] : "Custom levels") + "</p>" +
        '<form id="threshForm" class="form-row" style="grid-template-columns:repeat(3, 110px) auto"><label class="field">Flag at<input name="flag_score" type="number" min="0" max="101" value="' + e.flag_score + '"></label><label class="field">Hold at<input name="challenge_score" type="number" min="0" max="101" value="' + e.challenge_score + '"></label><label class="field">Block at<input name="reject_score" type="number" min="0" max="101" value="' + e.reject_score + '"></label><button class="btn" type="submit">Save levels</button></form></div></div>' +
        '<div class="set"><div><h3>Call bridge and recording</h3><p>' + (bridge ? (e.bridge_carry === "all" ? "Falcon carries every call that is not a hard block, like a PBX. It hears and records every call and every answer." : "Falcon carries suspicious calls back to your switch, records both sides, and hears false answers.") : "Off. Set FALCON_SIP_LISTEN and FALCON_SIP_MODE=bridge, then add Falcon to your switch as a carrier and as a customer.") + "</p></div><div class=\"ctl\">" +
        (bridge ? '<span class="tag good">On: ' + fmtN(sip.active_calls || 0) + " calls up, room for " + fmtN(sip.capacity || 0) + "</span>" : '<span class="tag">Off</span>') +
        '<form id="bridgeForm" class="form-row" style="grid-template-columns:repeat(4, 150px) auto"><label class="field">Carry<select name="bridge_carry"><option value="suspicious"' + (e.bridge_carry === "all" ? "" : " selected") + '>Suspicious calls</option><option value="all"' + (e.bridge_carry === "all" ? " selected" : "") + '>Every call</option></select></label><label class="field">Keep recordings (days)<input name="recording_retention_days" type="number" min="0" max="3650" value="' + e.recording_retention_days + '"></label>' +
        '<label class="field">Hear 1 in N fan-out calls<input name="bridge_fanout_every" type="number" min="0" value="' + e.bridge_fanout_every + '"></label><label class="field">Hear 1 in N clean calls<input name="bridge_clean_every" type="number" min="0" value="' + e.bridge_clean_every + '"></label><button class="btn" type="submit">Save</button></form>' +
        '<p class="muted small" style="margin:0">Every call puts Falcon in the audio of all calls, up to the bridge capacity. Past it, calls get 503 and your switch moves on. 0 turns sampling off.</p></div></div>' +
        '<div class="set"><div><h3>FAS guard</h3><p>Hears ringback, busy, intercepts, and silence after a vendor answers a bridged call. Watch records it and alerts. Hold keeps the answer back until a person speaks, so your customer is not billed for a false answer and the switch can route again.</p></div><div class="ctl">' +
        '<div class="seg" id="fasSeg"><button type="button" data-v="off">Off</button><button type="button" data-v="monitor">Watch</button><button type="button" data-v="enforce">Hold</button></div>' +
        (bridge ? "" : '<p class="muted small" style="margin:0">Needs the call bridge.</p>') + "</div></div>" +
        '<div class="set"><div><h3>FCC autopilot</h3><p>Checks your upstream carriers against FCC orders and the Robocall Mitigation Database every 6 hours. Watch alerts you. Block adds deny rules for an upstream the FCC removed or ordered blocked. Add upstreams in Rules.</p></div><div class="ctl">' +
        '<div class="seg" id="fccSeg"><button type="button" data-v="monitor">Watch</button><button type="button" data-v="enforce">Block</button></div><p class="muted small" id="fccHint" style="margin:0"></p></div></div>';
      const paintSegs = () => {
        $$("#modeSeg button").forEach((b) => b.classList.toggle("on", b.dataset.v === this.eff.mode));
        $$("#fasSeg button").forEach((b) => b.classList.toggle("on", b.dataset.v === this.eff.fas_mode));
        $$("#fccSeg button").forEach((b) => b.classList.toggle("on", b.dataset.v === this.eff.fcc_mode));
        const p = PRESETS.find((x) => x[2].flag_score === this.eff.flag_score && x[2].challenge_score === this.eff.challenge_score && x[2].reject_score === this.eff.reject_score);
        $$("#presetSeg button").forEach((b) => b.classList.toggle("on", !!p && b.dataset.p === p[0]));
        setText($("#presetHint"), p ? p[3] : "Custom levels");
      };
      paintSegs();
      const apply = async (body, text) => { const eff = await saveSettings(body, text); if (eff) { this.eff = eff; paintSegs(); const tf = $("#threshForm"); ["flag_score", "challenge_score", "reject_score"].forEach((k) => { tf[k].value = eff[k]; }); loadStatus(); } };
      $("#modeSeg").onclick = (ev) => { const b = ev.target.closest("[data-v]"); if (b && b.dataset.v !== this.eff.mode) apply({ mode: b.dataset.v }, b.dataset.v === "enforce" ? "Enforce: Falcon blocks hard fraud now" : "Monitor: Falcon records and blocks nothing"); };
      $("#fasSeg").onclick = (ev) => { const b = ev.target.closest("[data-v]"); if (b && b.dataset.v !== this.eff.fas_mode) apply({ fas_mode: b.dataset.v }, "FAS guard saved"); };
      $("#fccSeg").onclick = async (ev) => {
        const b = ev.target.closest("[data-v]");
        if (!b || b.dataset.v === this.eff.fcc_mode) return;
        await apply({ fcc_mode: b.dataset.v }, b.dataset.v === "enforce" ? "FCC autopilot blocks upstreams under an FCC order now" : "FCC autopilot alerts and blocks nothing");
        try { const mods = await get("/v1/modules"); if (state.view === this) this.paintModules(mods.data || []); } catch (e) { /* the next visit repaints */ }
      };
      $("#presetSeg").onclick = (ev) => { const b = ev.target.closest("[data-p]"); const p = b && PRESETS.find((x) => x[0] === b.dataset.p); if (p) apply(p[2], p[1] + " levels saved"); };
      $("#threshForm").onsubmit = (ev) => { ev.preventDefault(); const f = ev.target; apply({ flag_score: Number(f.flag_score.value), challenge_score: Number(f.challenge_score.value), reject_score: Number(f.reject_score.value) }, "Levels saved"); };
      $("#bridgeForm").onsubmit = (ev) => { ev.preventDefault(); const f = ev.target; apply({ bridge_carry: f.bridge_carry.value, recording_retention_days: Number(f.recording_retention_days.value), bridge_fanout_every: Number(f.bridge_fanout_every.value), bridge_clean_every: Number(f.bridge_clean_every.value) }, "Bridge settings saved"); };
    },
    paintModules(mods) {
      const fcc = mods.find((m) => m.id === "fcc");
      setText($("#fccHint"), fcc ? (fcc.state === "on" ? fcc.detail || "" : "Off. Set " + fcc.enable + ".") : "");
      const words = { on: "On", off: "Off", needs_key: "Needs a key", error: "Problem" };
      patch($("#setModules"), mods.map((m) => '<div class="module"><div class="module-top"><strong>' + esc(m.title) + '</strong><span class="state ' + esc(m.state) + '">' + esc(words[m.state] || m.state) + "</span></div><p>" + esc(m.summary) + "</p>" +
        (m.detail ? '<p style="color:var(--text-2)">' + esc(m.detail) + "</p>" : "") + (m.state !== "on" && m.enable ? '<span class="enable">' + esc(m.enable) + "</span>" : "") + "</div>").join(""));
    },
    paintAlerts(res) {
      const th = res.settings || {};
      const list = (res.data || []).map((a) => '<li><div><div class="t">' + esc(a.title) + '</div><div class="d">' + esc(ago(a.at)) + (a.delivered ? "" : a.error ? ", not delivered: " + esc(a.error) : ", kept here only") + "</div></div><span></span></li>").join("");
      $("#setAlerts").innerHTML = '<div class="card-head"><h2>Alerts</h2><span class="hint">Slack or any JSON webhook</span></div>' +
        '<form id="alertForm" class="stack" style="gap:12px"><label class="field">Webhook URL<input name="alert_webhook_url" type="url" placeholder="https://hooks.slack.com/services/..." value="' + esc(th.alert_webhook_url || "") + '"></label>' +
        '<div class="form-row" style="grid-template-columns:repeat(2, minmax(0,1fr))"><label class="field">Page when blocks pass (%)<input name="alert_reject_pct" type="number" min="0" max="100" value="' + esc(th.alert_reject_pct) + '"></label>' +
        '<label class="field">Page when a signer fails (%)<input name="alert_signer_reject_pct" type="number" min="0" max="100" value="' + esc(th.alert_signer_reject_pct) + '"></label></div>' +
        '<div style="display:flex;gap:8px"><button class="btn primary" type="submit">Save</button><button class="btn" type="button" id="alertTest">Send a test</button></div></form>' +
        (list ? '<ul class="reasons" style="margin-top:14px">' + list + "</ul>" : '<p class="muted small" style="margin:14px 0 0">No alerts yet.</p>');
      $("#alertForm").onsubmit = async (e) => {
        e.preventDefault();
        const f = e.target;
        try { await put("/v1/alerts/settings", Object.assign({}, th, { alert_webhook_url: f.alert_webhook_url.value, alert_reject_pct: Number(f.alert_reject_pct.value), alert_signer_reject_pct: Number(f.alert_signer_reject_pct.value) })); toast("Alerts saved", "ok"); } catch (err) { toast(err.message, "bad"); }
      };
      $("#alertTest").onclick = async () => { try { await post("/v1/alerts/test", {}); toast("Test alert sent", "ok"); } catch (err) { toast(err.message, "bad"); } };
    },
    paintData(settings, status) {
      const e = settings.effective, share = (status && status.share) || {};
      $("#setData").innerHTML = '<div class="card-head"><h2>Data and privacy</h2></div>' +
        '<form id="retForm" class="form-row" style="grid-template-columns:repeat(2, minmax(0,1fr)) auto"><label class="field">Keep calls (days)<input name="retention_days" type="number" min="1" max="3650" value="' + e.retention_days + '"></label>' +
        '<label class="field">Keep raw SIP (days)<input name="raw_sip_retention_days" type="number" min="0" max="3650" value="' + e.raw_sip_retention_days + '"></label><button class="btn" type="submit">Save</button></form>' +
        '<dl class="kv"><dt>Telemetry</dt><dd>' + (share.effective ? "On. Redacted call decisions go to CallerAPI and make every install sharper. Set FALCON_SHARE=false to turn it off." : status && status.demo && status.demo.enabled ? "Off in demo mode. Demo calls are synthetic." : "Off (FALCON_SHARE=false).") + "</dd>" +
        "<dt>Never leaves this host</dt><dd>" + esc((share.redacted || []).join(", ")) + "</dd></dl>";
      $("#retForm").onsubmit = async (ev) => {
        ev.preventDefault();
        const f = ev.target;
        await saveSettings({ retention_days: Number(f.retention_days.value), raw_sip_retention_days: Number(f.raw_sip_retention_days.value) }, "Retention saved");
      };
    },
    paintSystem(st, audit, cfg) {
      const tr = (st.shaken && st.shaken.trust) || {};
      const rows = [
        ["Version", st.version + (st.release && st.release.newer ? ", " + st.release.latest + " is out" : "")], ["Install", st.install_id], ["Started", ago(st.started_at)],
        ["Profile", st.profile], ["SIP", st.sip && st.sip.enabled ? st.sip.mode + " on " + st.sip.listen : "Off"],
        ["STIR/SHAKEN", st.shaken && st.shaken.enabled ? (tr.roots ? tr.roots + " trusted roots" : "Trust list not loaded") : "Off"],
        ["Spam list", st.spam_feed && st.spam_feed.configured ? fmtN(st.spam_feed.count) + " numbers" : "Off"],
        ["IP fraud list", st.ip_intel && st.ip_intel.configured ? fmtN(st.ip_intel.count) + " blocks" : "Off"],
        ["Recordings", (cfg.bridge && cfg.bridge.recordings) || ""],
      ];
      $("#setSystem").innerHTML = '<div class="card-head"><h2>System</h2><div style="display:flex;gap:8px"><button type="button" class="btn sm" id="reloadBtn">Reload lists</button><a class="btn sm" href="' + esc(withToken("/metrics")) + '" target="_blank" rel="noreferrer">Prometheus</a><a class="btn sm" href="' + esc(withToken("/v1/events.csv?range=" + state.range)) + '">Export CSV</a></div></div>' +
        '<div class="grid two"><dl class="kv" style="margin:0">' + rows.map((r) => "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>").join("") + "</dl>" +
        '<div><h3 class="muted small" style="margin:0 0 8px">Changes</h3>' + (audit.length ? '<ul class="reasons">' + audit.map((a) => '<li><div><div class="t">' + esc(a.action + " " + a.subject) + '</div><div class="d">' + esc(ago(a.at) + ", " + a.actor) + "</div></div><span></span></li>").join("") + "</ul>" : '<p class="muted small">No changes yet.</p>') + "</div></div>";
      $("#reloadBtn").onclick = async (e) => { e.target.disabled = true; try { await post("/v1/reload", {}); toast("Lists reloaded", "ok"); } catch (err) { toast(err.message, "bad"); } e.target.disabled = false; };
    },
  };

  // ---------- Ask Falcon ----------
  const ask = { history: [], busy: false };
  $("#askBtn").onclick = () => {
    $("#ask").hidden = false;
    $("#scrim").hidden = false;
    const a = (state.status && state.status.assistant) || {};
    setText($("#askProvider"), "Answers from this install's data for " + rangeWords(state.range) + (a.model ? ", " + a.model : ""));
    $("#askInput").focus();
  };
  $("#askClose").onclick = () => { $("#ask").hidden = true; if ($("#drawer").hidden) $("#scrim").hidden = true; };
  $("#askForm").onsubmit = async (e) => {
    e.preventDefault();
    const q = $("#askInput").value.trim();
    if (!q || ask.busy) return;
    ask.busy = true;
    $("#askInput").value = "";
    const add = (role, t) => { const d = document.createElement("div"); d.className = "ask-msg " + role; d.textContent = t; $("#askLog").appendChild(d); $("#askLog").scrollTop = 1e9; };
    add("user", q);
    try {
      const r = await post("/v1/assistant", { question: q, range: state.range, history: ask.history.slice(-8) });
      add("bot", r.answer);
      ask.history.push({ role: "user", content: q }, { role: "assistant", content: r.answer });
    } catch (err) { add("bot", "Could not answer: " + err.message); }
    ask.busy = false;
  };

  // ---------- router ----------
  const VIEWS = { overview: Overview, calls: Calls, threats: Threats, rules: Rules, settings: Settings };
  function parseHash() {
    const raw = (location.hash || "#overview").slice(1);
    const i = raw.indexOf("?");
    const name = (i >= 0 ? raw.slice(0, i) : raw) || "overview";
    const params = {};
    new URLSearchParams(i >= 0 ? raw.slice(i + 1) : "").forEach((v, k) => { params[k] = v; });
    return { name: VIEWS[name] ? name : "overview", params };
  }
  function navigate() {
    const { name, params } = parseHash();
    if (state.view && state.view.unmount) state.view.unmount();
    const view = VIEWS[name];
    state.view = view;
    state.viewName = name;
    $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === name));
    setText($("#viewTitle"), view.title);
    document.title = view.title + " - Falcon";
    const root = $("#view");
    root.__html = null;
    view.mount(root, params);
  }
  window.addEventListener("hashchange", navigate);

  // ---------- top bar ----------
  $$("#rangeSeg button").forEach((b) => b.classList.toggle("on", b.dataset.range === state.range));
  $("#rangeSeg").onclick = (e) => {
    const b = e.target.closest("[data-range]");
    if (!b || b.dataset.range === state.range) return;
    state.range = b.dataset.range;
    localStorage.setItem("falcon_range", state.range);
    $$("#rangeSeg button").forEach((x) => x.classList.toggle("on", x === b));
    if (state.view && state.view.rangeChanged) state.view.rangeChanged();
  };
  let searchTimer = 0;
  $("#search").oninput = (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = e.target.value.trim();
      if (state.viewName === "calls") Calls.searchChanged();
      else if (state.q) location.hash = "#calls?q=" + encodeURIComponent(state.q);
    }, 300);
  };
  function closeAll() {
    if (!$("#ask").hidden) { $("#ask").hidden = true; }
    if (!$("#drawer").hidden) Drawer.close();
    $("#scrim").hidden = true;
  }
  $("#drawerClose").onclick = () => Drawer.close();
  $("#scrim").onclick = closeAll;
  document.addEventListener("keydown", (e) => {
    const typing = /input|textarea|select/i.test(document.activeElement.tagName);
    if (e.key === "/" && !typing) { e.preventDefault(); $("#search").focus(); $("#search").select(); }
    if (e.key === "Escape") closeAll();
  });

  // ---------- health ----------
  async function health() {
    try {
      const h = await get("/v1/health");
      $("#healthDot").className = "dot ok";
      setText($("#healthText"), "Running");
      setText($("#versionText"), "Falcon " + (h.version || ""));
    } catch (e) {
      $("#healthDot").className = "dot bad";
      setText($("#healthText"), token ? "Not reachable" : "Add ?token= to the address");
    }
  }

  liveOn((msg) => {
    if (msg.type === "voice" && Drawer.id && String(msg.event_id) === String(Drawer.id)) Drawer.refresh();
  });

  health();
  setInterval(health, 15000);
  loadStatus();
  startLive();
  navigate();
})();
