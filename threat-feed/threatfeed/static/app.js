// Threat Feed client. All post content is untrusted social-media text, so
// every node is built with textContent via el() -- never innerHTML.
"use strict";

const $ = (s) => document.querySelector(s);
const state = { token: null, me: null, config: null, filters: { category: "", min_severity: 0, q: "", source: "" },
  nextBefore: null, stream: null, seen: new Set(), signup: false };

try { state.token = localStorage.getItem("tf_token"); } catch (_) { /* storage blocked */ }

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401 && state.token) { setToken(null); }
  const body = r.headers.get("content-type")?.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw Object.assign(new Error(body?.detail || r.statusText), { status: r.status });
  return body;
}

function setToken(t) {
  state.token = t;
  try { t ? localStorage.setItem("tf_token", t) : localStorage.removeItem("tf_token"); } catch (_) {}
}

const isPro = () => state.me?.tier === "pro";
const policy = () => state.me?.policy || state.config.tiers.free;

function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
const label = (c) => c.replace(/_/g, " ");

// ---- rendering --------------------------------------------------------
function renderPost(p, fresh = false) {
  const tags = el("div", { class: "tags" },
    p.categories.map((c) => el("span", { class: "tag" }, label(c))),
    p.cves.map((c) => el("span", { class: "tag" }, c)));
  const iocRow = el("div", { class: "tags" });
  if (p.iocs) {
    for (const [kind, vals] of Object.entries(p.iocs)) {
      if (kind === "cves") continue;
      for (const v of vals) iocRow.append(el("span", { class: "ioc", title: `${kind}: ${v}` }, v));
    }
  } else if (p.iocs_locked) {
    iocRow.append(el("button", { class: "locked", onclick: openPricing },
      `🔒 ${p.iocs_locked} IOC${p.iocs_locked > 1 ? "s" : ""} — Pro`));
  }
  return el("article", { class: `post${fresh ? " fresh" : ""}`, "data-id": p.id },
    el("div", { class: "post-head" },
      el("span", { class: `sev ${p.severity_label}`, title: `severity ${p.severity}/100` }, p.severity_label),
      el("span", { class: "author" }, p.author),
      el("span", {}, p.source === "reddit" ? p.author_handle : `@${p.author_handle}`),
      el("span", { class: "src" }, `· ${p.source}`),
      el("span", { class: "time", title: new Date(p.created_at * 1000).toLocaleString() }, ago(p.created_at))),
    el("div", { class: "text" }, p.text),
    tags, iocRow,
    el("a", { class: "open", href: safeUrl(p.url), target: "_blank", rel: "noopener noreferrer nofollow" },
      "Open original ↗"));
}

function safeUrl(u) {
  try { const x = new URL(u); return x.protocol === "https:" || x.protocol === "http:" ? x.href : "#"; }
  catch (_) { return "#"; }
}

function renderAd(a) {
  if (a.network) return renderNetworkAd(a.network);
  return el("aside", { class: "post ad", "aria-label": "Sponsored" },
    el("div", { class: "sponsored" }, `Sponsored · ${a.advertiser}`),
    el("h3", {}, a.headline), el("p", {}, a.body),
    el("a", { class: "btn ghost", href: a.click_url, target: "_blank", rel: "sponsored noopener" }, a.cta));
}

function renderNetworkAd(net) {
  // EthicalAds: a placeholder div plus their client script, loaded once.
  const box = el("aside", { class: "post ad", "aria-label": "Sponsored" }, el("div", { class: "sponsored" }, "Sponsored"));
  if (net.provider === "ethicalads") {
    box.append(el("div", { "data-ea-publisher": net.publisher, "data-ea-type": "text", class: "horizontal" }));
    if (!document.getElementById("ea-js")) {
      document.head.append(el("script", { id: "ea-js", async: true, src: "https://media.ethicalads.io/media/client/ethicalads.min.js" }));
    } else window.ethicalads?.reload?.();
  }
  return box;
}

function renderItem(it, fresh) { return it.type === "ad" ? renderAd(it) : renderPost(it, fresh); }

// ---- feed -------------------------------------------------------------
function feedParams(extra = {}) {
  const f = { ...state.filters, ...extra };
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v !== "" && v != null && v !== 0) qs.set(k, v);
  return qs.toString();
}

async function loadFeed(append = false) {
  const data = await api(`/api/feed?${feedParams(append && state.nextBefore ? { before: state.nextBefore } : {})}`);
  const feed = $("#feed");
  if (!append) { feed.replaceChildren(); state.seen.clear(); }
  for (const it of data.items) {
    if (it.type === "post") { if (state.seen.has(it.id)) continue; state.seen.add(it.id); }
    feed.append(renderItem(it));
  }
  state.nextBefore = data.next_before;
  $("#more").hidden = !data.next_before;
  $("#empty").hidden = feed.children.length > 0;
}

function matchesFilters(p) {
  const f = state.filters;
  if (f.category && !p.categories.includes(f.category)) return false;
  if (p.severity < f.min_severity) return false;
  if (f.source && p.source !== f.source) return false;
  if (f.q) { const q = f.q.toLowerCase(); if (!p.text.toLowerCase().includes(q) && !p.author_handle.toLowerCase().includes(q)) return false; }
  return true;
}

function startLive() {
  stopLive();
  if (isPro()) {
    // EventSource cannot send headers; the stream endpoint accepts ?token=.
    state.stream = new EventSource(`/api/stream?token=${encodeURIComponent(state.token)}`);
    state.stream.addEventListener("post", (e) => {
      const p = JSON.parse(e.data);
      if (state.seen.has(p.id) || !matchesFilters(p)) return;
      state.seen.add(p.id);
      $("#feed").prepend(renderPost(p, true));
      $("#empty").hidden = true;
    });
    state.stream.onopen = () => setLive(true);
    state.stream.onerror = () => setLive(false);
  } else {
    state.poll = setInterval(() => loadFeed().catch(() => {}), 60_000);
    setLive(false);
  }
}
function stopLive() { state.stream?.close(); state.stream = null; clearInterval(state.poll); }

function setLive(on) {
  const box = $("#liveState");
  box.replaceChildren();
  if (isPro()) box.append(el("span", { class: "dot", style: on ? "" : "background:#999;animation:none" }), on ? "Live" : "Reconnecting…");
  else box.append(`Delayed ${Math.round(policy().feed_delay_seconds / 60)} min · `,
    el("button", { class: "link", onclick: openPricing }, "go real-time"));
}

async function loadTrends() {
  const data = await api("/api/trends");
  const ol = $("#trends");
  ol.replaceChildren(...data.trends.map((t) => el("li", {},
    el("span", { class: "term", onclick: () => { $("#q").value = t.kind === "category" ? "" : t.term.replace(/^#/, "");
      if (t.kind === "category") setCategory(t.term); else { state.filters.q = $("#q").value; loadFeed(); } } },
      t.kind === "category" ? label(t.term) : t.term),
    el("div", { class: "meta" }, `${t.recent} posts · ${t.authors} researchers · ${t.score}× baseline`))));
  if (!data.trends.length) ol.append(el("li", { class: "muted small" }, "No spikes right now."));
  $("#trendsMore").hidden = !data.hidden;
  $("#trendsMore").replaceChildren(el("button", { class: "link", onclick: openPricing }, `+${data.hidden} more trends with Pro`));
}

// ---- chrome -----------------------------------------------------------
function renderChrome() {
  const pro = isPro();
  const badge = $("#tierBadge");
  badge.textContent = pro ? "Pro" : "Free";
  badge.className = `badge${pro ? " pro" : ""}`;
  $("#accountBtn").textContent = state.me?.email ? "Sign out" : "Sign in";
  $("#upgradeBtn").hidden = pro;
  $("#proTools").hidden = !pro;
  const side = $("#sideAd");
  side.hidden = pro;
  if (!pro) {
    side.replaceChildren(el("div", { class: "sponsored" }, "Sponsored"),
      el("h3", {}, "Go real-time, ad-free"),
      el("p", {}, `X researcher coverage, live stream, IOC exports and webhook alerts for ${state.config.pro_price}.`),
      el("button", { class: "primary", onclick: openPricing }, "See Pro"));
  }
  const srcSel = $("#source");
  srcSel.replaceChildren(el("option", { value: "" }, "All sources"),
    ...policy().sources.map((s) => el("option", { value: s }, s)));
  srcSel.value = state.filters.source;
  setLive(!!state.stream);
}

function setCategory(c) {
  state.filters.category = state.filters.category === c ? "" : c;
  document.querySelectorAll("#cats .chip").forEach((b) => b.classList.toggle("on", b.dataset.c === state.filters.category));
  loadFeed();
}

function feature(on, text) { return el("li", { class: on ? "" : "no" }, text); }

function openPricing() {
  const f = state.config.tiers.free, p = state.config.tiers.pro;
  const plan = (t, price, featured, cta) => el("div", { class: `plan${featured ? " featured" : ""}` },
    el("h3", {}, t.display_name), el("div", { class: "price" }, price),
    el("ul", {},
      feature(true, t.feed_delay_seconds ? `Feed delayed ${t.feed_delay_seconds / 60} min` : "Real-time live stream"),
      feature(true, `Sources: ${t.sources.join(", ")}`),
      feature(true, `${t.history_days} day${t.history_days > 1 ? "s" : ""} of history`),
      feature(t.show_iocs, "Full IOCs (hashes, IPs, domains, URLs)"),
      feature(t.exports, "Export IOCs as CSV / STIX 2.1"),
      feature(t.max_watchlists > 0, `Watchlists with webhook alerts${t.max_watchlists ? ` (${t.max_watchlists})` : ""}`),
      feature(t.api_keys, "REST + streaming API keys"),
      feature(true, `Top ${t.trends_limit} trends`),
      feature(true, t.ad_every_n_posts ? "Ad-supported" : "No ads")),
    cta);
  const proCta = isPro() ? el("button", { disabled: true }, "Current plan")
    : el("button", { class: "primary", onclick: upgrade }, "Upgrade to Pro");
  $("#plans").replaceChildren(plan(f, "$0", false, isPro() ? null : el("button", { disabled: true }, "Current plan")),
    plan(p, state.config.pro_price, true, proCta));
  $("#pricingDlg").showModal();
}

async function upgrade() {
  if (!state.me?.email) { $("#pricingDlg").close(); state.signup = true; openAuth(); return; }
  try {
    if (state.config.checkout_available) {
      const { url } = await api("/api/billing/checkout", { method: "POST" });
      location.href = url;
    } else if (state.config.dev_billing) {
      await api("/api/billing/dev-upgrade", { method: "POST" });
      $("#pricingDlg").close();
      await boot();
    } else {
      alert("Billing is not configured on this server yet.");
    }
  } catch (e) { alert(e.message); }
}

function openAuth() {
  $("#authTitle").textContent = state.signup ? "Create your account" : "Sign in";
  $("#authToggle").textContent = state.signup ? "I already have an account" : "Create an account instead";
  $("#authErr").hidden = true;
  $("#authDlg").showModal();
}

// ---- Pro dialogs ------------------------------------------------------
async function openWatchlists() {
  const { watchlists, max } = await api("/api/watchlists");
  $("#watchList").replaceChildren(...watchlists.map((w) => el("li", {},
    el("span", {}, el("strong", {}, w.name), ` — ${w.keywords.join(", ") || "any"} · sev ≥ ${w.min_severity}`,
      w.webhook_url ? " · webhook ✓" : ""),
    el("button", { class: "link", onclick: async () => { await api(`/api/watchlists/${w.id}`, { method: "DELETE" }); openWatchlists(); } }, "Delete"))));
  $("#watchForm").hidden = watchlists.length >= max;
  if (!$("#watchDlg").open) $("#watchDlg").showModal();
}

async function openKeys() {
  const { keys } = await api("/api/keys");
  $("#keyList").replaceChildren(...keys.map((k) => el("li", {},
    el("span", {}, el("code", {}, `${k.prefix}…`), ` ${k.label || ""} · created ${ago(k.created_at)}`),
    el("button", { class: "link", onclick: async () => { await api(`/api/keys/${encodeURIComponent(k.prefix)}`, { method: "DELETE" }); openKeys(); } }, "Revoke"))));
  if (!$("#keysDlg").open) { $("#newKey").hidden = true; $("#keysDlg").showModal(); }
}

async function download(path, filename) {
  const r = await fetch(path, { headers: { Authorization: `Bearer ${state.token}` } });
  if (!r.ok) { alert("Export failed"); return; }
  const a = el("a", { href: URL.createObjectURL(await r.blob()), download: filename });
  a.click(); URL.revokeObjectURL(a.href);
}

// ---- wiring -----------------------------------------------------------
function wire() {
  let t;
  $("#q").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { state.filters.q = e.target.value.trim(); loadFeed(); }, 300); });
  $("#minSev").addEventListener("change", (e) => { state.filters.min_severity = +e.target.value; loadFeed(); });
  $("#source").addEventListener("change", (e) => { state.filters.source = e.target.value; loadFeed(); });
  $("#more").addEventListener("click", () => loadFeed(true));
  $("#pricingBtn").addEventListener("click", openPricing);
  $("#upgradeBtn").addEventListener("click", openPricing);
  $("#accountBtn").addEventListener("click", async () => {
    if (state.me?.email) { try { await api("/api/auth/logout", { method: "POST" }); } catch (_) {} setToken(null); boot(); }
    else { state.signup = false; openAuth(); }
  });
  $("#authToggle").addEventListener("click", () => { state.signup = !state.signup; openAuth(); });
  $("#authForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const { token } = await api(`/api/auth/${state.signup ? "signup" : "login"}`,
        { method: "POST", json: { email: fd.get("email"), password: fd.get("password") } });
      setToken(token); $("#authDlg").close(); e.target.reset(); await boot();
    } catch (err) { $("#authErr").textContent = err.message; $("#authErr").hidden = false; }
  });
  $("#watchForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/watchlists", { method: "POST", json: { name: fd.get("name"),
        keywords: String(fd.get("keywords") || "").split(",").map((s) => s.trim()).filter(Boolean),
        min_severity: +fd.get("min_severity") || 0, webhook_url: fd.get("webhook_url") || null } });
      e.target.reset(); $("#watchErr").hidden = true; openWatchlists();
    } catch (err) { $("#watchErr").textContent = err.message; $("#watchErr").hidden = false; }
  });
  $("#watchBtn").addEventListener("click", openWatchlists);
  $("#keysBtn").addEventListener("click", openKeys);
  $("#mintKey").addEventListener("click", async () => {
    const { key } = await api("/api/keys", { method: "POST", json: { label: "" } });
    $("#newKey").textContent = `New key (shown once): ${key}`; $("#newKey").hidden = false; openKeys();
  });
  $("#csvBtn").addEventListener("click", () => download("/api/export/iocs.csv?hours=24", "threatfeed-iocs.csv"));
  $("#stixBtn").addEventListener("click", () => download("/api/export/stix?hours=24", "threatfeed-stix.json"));
  $("#manageBtn").addEventListener("click", async () => {
    try { const { url } = await api("/api/billing/portal", { method: "POST" }); location.href = url; }
    catch (e) { alert(e.status === 404 ? "No billing account on file." : e.message); }
  });
  document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));
}

function renderCategories() {
  $("#cats").replaceChildren(...state.config.categories.map((c) =>
    el("button", { class: "chip", "data-c": c, onclick: () => setCategory(c) }, label(c))));
}

function showBanner() {
  const p = new URLSearchParams(location.search);
  const b = $("#banner");
  if (p.has("upgraded")) { b.textContent = "Thanks for upgrading! Pro activates as soon as payment is confirmed (usually a few seconds)."; b.hidden = false; }
  else if (p.has("canceled")) { b.textContent = "Checkout canceled. You're still on the Free plan."; b.hidden = false; }
  if (p.has("upgraded") || p.has("canceled")) history.replaceState(null, "", "/");
}

async function boot() {
  state.config ||= await api("/api/config");
  state.me = await api("/api/me");
  renderChrome();
  await Promise.all([loadFeed(), loadTrends()]);
  startLive();
}

wire();
showBanner();
api("/api/config").then((c) => { state.config = c; renderCategories(); return boot(); })
  .catch((e) => { $("#feed").replaceChildren(el("p", { class: "error" }, `Failed to load: ${e.message}`)); });
setInterval(() => loadTrends().catch(() => {}), 120_000);
