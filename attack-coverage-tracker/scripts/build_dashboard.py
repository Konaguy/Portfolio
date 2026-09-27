"""
Generate dashboard/index.html with the coverage data embedded as a fallback.

The page fetches dashboard/coverage.json when served, and falls back to the
embedded snapshot so it renders standalone (opened from disk, or published as an
artifact). Re-run this after regenerating coverage.json:

    python -m attackcov.cli --repo
    python scripts/build_dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COVERAGE = ROOT / "dashboard" / "coverage.json"
OUT = ROOT / "dashboard" / "index.html"

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>ATT&CK Coverage Tracker</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
  :root {
    color-scheme: light;
    --page:#f5f7fa; --surface:#ffffff; --surface-2:#eef1f6; --surface-3:#e4e9f1;
    --ink:#101725; --ink-2:#57616f; --ink-3:#868f9d;
    --border:#e2e6ec; --border-2:#d3d9e2; --accent:#2a78d6; --accent-ink:#ffffff;
    --good:#1e874b; --warn:#b6820a;
    --shadow:0 1px 2px rgba(16,23,37,.06),0 6px 20px rgba(16,23,37,.05);
    --radius:12px;
    --f-display:"Archivo",system-ui,sans-serif; --f-body:"IBM Plex Sans",system-ui,sans-serif;
    --f-mono:"IBM Plex Mono",ui-monospace,Menlo,monospace;
  }
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
    color-scheme:dark;
    --page:#0f1218; --surface:#171b22; --surface-2:#1f242d; --surface-3:#262d38;
    --ink:#eef1f5; --ink-2:#a4adba; --ink-3:#79828f;
    --border:#262c36; --border-2:#333b47; --accent:#4a90e6; --accent-ink:#0f1218;
    --good:#43b877; --warn:#d8a52a;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);
  }}
  :root[data-theme="dark"]{
    color-scheme:dark;
    --page:#0f1218; --surface:#171b22; --surface-2:#1f242d; --surface-3:#262d38;
    --ink:#eef1f5; --ink-2:#a4adba; --ink-3:#79828f;
    --border:#262c36; --border-2:#333b47; --accent:#4a90e6; --accent-ink:#0f1218;
    --good:#43b877; --warn:#d8a52a;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box;}
  html,body{margin:0;}
  body{background:var(--page);color:var(--ink);font-family:var(--f-body);font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;}
  .wrap{max-width:1240px;margin:0 auto;padding-inline:20px;padding-block:28px 56px;}
  h1,h2,h3{font-family:var(--f-display);text-wrap:balance;margin:0;}
  .mono{font-family:var(--f-mono);}
  header.top{display:flex;flex-wrap:wrap;align-items:flex-start;gap:16px 24px;justify-content:space-between;margin-bottom:24px;}
  .brand h1{font-size:24px;letter-spacing:-.01em;}
  .brand .sub{color:var(--ink-2);font-size:13.5px;margin-top:4px;}
  .meta{display:flex;flex-wrap:wrap;align-items:center;gap:8px;}
  .pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:500;padding:5px 10px;border-radius:999px;border:1px solid var(--border-2);color:var(--ink-2);background:var(--surface);}
  .pill .dot{width:7px;height:7px;border-radius:50%;background:var(--accent);}
  .pill.demo{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,var(--border-2));}
  .pill.demo .dot{background:var(--warn);}
  button.toggle{font:inherit;font-size:12px;cursor:pointer;padding:5px 12px;border-radius:999px;border:1px solid var(--border-2);background:var(--surface);color:var(--ink-2);}
  button.toggle:hover{border-color:var(--accent);color:var(--ink);}

  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px;}
  .kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow);}
  .kpi .label{font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink-3);font-weight:600;}
  .kpi .value{font-family:var(--f-display);font-size:30px;line-height:1.1;margin-top:8px;font-variant-numeric:tabular-nums;}
  .kpi .foot{font-size:12px;color:var(--ink-2);margin-top:4px;}

  .panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);margin-bottom:22px;}
  .panel h2{font-size:15px;}
  .panel .cap{color:var(--ink-2);font-size:12.5px;margin:2px 0 16px;}
  .panelhead{display:flex;flex-wrap:wrap;gap:10px 16px;justify-content:space-between;align-items:baseline;margin-bottom:14px;}
  .legend{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--ink-2);flex-wrap:wrap;}
  .legend .cells{display:inline-flex;gap:3px;}
  .legend .lc{width:16px;height:12px;border-radius:3px;border:1px solid var(--border-2);}

  /* Matrix */
  .matrixscroll{overflow-x:auto;padding-bottom:6px;}
  .matrix{display:grid;grid-auto-flow:column;grid-auto-columns:minmax(150px,1fr);gap:10px;min-width:1050px;}
  .col{display:flex;flex-direction:column;gap:6px;}
  .colhead{position:sticky;top:0;}
  .colhead .tname{font-family:var(--f-display);font-size:12.5px;line-height:1.2;min-height:30px;}
  .colhead .tmeta{font-size:11px;color:var(--ink-3);font-variant-numeric:tabular-nums;margin-top:2px;}
  .colhead .tbar{height:4px;border-radius:2px;background:var(--surface-3);margin-top:6px;overflow:hidden;}
  .colhead .tbar>span{display:block;height:100%;background:var(--accent);}
  .cell{border:1px solid var(--border);border-radius:8px;padding:7px 8px;background:var(--surface-2);min-height:46px;display:flex;flex-direction:column;justify-content:center;gap:2px;}
  .cell.uncovered{border-style:dashed;border-color:var(--border-2);opacity:.62;}
  .cell .tid{font-family:var(--f-mono);font-size:10.5px;letter-spacing:.02em;}
  .cell .tt{font-size:11.5px;line-height:1.2;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}
  .cell .cnt{align-self:flex-start;font-size:10px;font-weight:600;padding:1px 6px;border-radius:999px;background:var(--accent);color:var(--accent-ink);font-variant-numeric:tabular-nums;}
  .cell.hide{display:none;}

  /* Coverage-by-tactic bars */
  .barrow{display:grid;grid-template-columns:150px 1fr 78px;align-items:center;gap:10px;margin-bottom:9px;}
  .barrow .bn{font-size:13px;}
  .barrow .bt{height:16px;background:var(--surface-3);border-radius:6px;overflow:hidden;}
  .barrow .bf{height:100%;background:var(--accent);border-radius:6px;min-width:2px;}
  .barrow .bx{text-align:right;font-size:12px;color:var(--ink-2);font-variant-numeric:tabular-nums;}

  table{border-collapse:collapse;width:100%;min-width:640px;}
  thead th{text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-3);font-weight:600;padding:11px 12px;border-bottom:1px solid var(--border);background:var(--surface-2);}
  tbody td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:13.5px;vertical-align:top;}
  tbody tr:last-child td{border-bottom:0;}
  .srcbadge{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;background:var(--surface-3);color:var(--ink-2);}
  .techchip{display:inline-block;font-family:var(--f-mono);font-size:11px;padding:1px 6px;border-radius:5px;background:color-mix(in srgb,var(--accent) 14%,var(--surface));color:var(--ink);margin:2px 3px 0 0;}
  .scroll{overflow-x:auto;}

  .controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px;}
  .controls label{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--ink-2);cursor:pointer;}
  footer.foot{margin-top:22px;color:var(--ink-3);font-size:12px;text-align:center;}
  footer.foot code{font-family:var(--f-mono);}
  @media (max-width:820px){.kpis{grid-template-columns:repeat(2,1fr);}.barrow{grid-template-columns:120px 1fr 70px;}}
  @media (prefers-reduced-motion:reduce){*{transition:none!important;}}
  :focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px;}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <h1>ATT&CK Coverage Tracker</h1>
      <div class="sub">Detection coverage mapped to MITRE ATT&CK, generated from the portfolio's Defender, Sentinel, and Sigma detections.</div>
    </div>
    <div class="meta">
      <span class="pill" id="genPill">—</span>
      <span class="pill demo" id="demoPill" hidden><span class="dot"></span> Embedded snapshot</span>
      <button class="toggle" id="themeBtn" type="button">◐ Theme</button>
    </div>
  </header>

  <section class="kpis" id="kpis"></section>

  <section class="panel">
    <div class="panelhead">
      <div><h2>Coverage matrix</h2><p class="cap" style="margin:2px 0 0">Techniques by tactic. Filled cells are covered; darker = more detections. Dashed = gap.</p></div>
      <div class="legend">
        <span>Detections</span>
        <span class="cells" id="legendCells"></span>
        <span class="lc" style="background:var(--surface-2);border-style:dashed" title="gap"></span> gap
      </div>
    </div>
    <div class="controls">
      <label><input type="checkbox" id="onlyCovered"> Show covered only</label>
      <label>Highlight: <input type="search" id="search" placeholder="technique id or name" style="font:inherit;font-size:13px;padding:5px 9px;border-radius:8px;border:1px solid var(--border-2);background:var(--surface);color:var(--ink)"></label>
    </div>
    <div class="matrixscroll"><div class="matrix" id="matrix"></div></div>
  </section>

  <section class="panel">
    <h2>Coverage by tactic</h2>
    <p class="cap">Covered techniques as a share of the catalog for each tactic.</p>
    <div id="tacticBars"></div>
  </section>

  <section class="panel">
    <h2>Detections</h2>
    <p class="cap">Every detection parsed, and the ATT&CK techniques it addresses.</p>
    <div class="scroll">
      <table>
        <thead><tr><th style="width:44%">Detection</th><th style="width:16%">Source</th><th>Techniques</th></tr></thead>
        <tbody id="detBody"></tbody>
      </table>
    </div>
  </section>

  <footer class="foot">
    Generated by <code>attack-coverage-tracker</code> · matrix uses a bundled ATT&CK catalog snapshot · import <code>navigator-layer.json</code> into the MITRE ATT&CK Navigator for the full matrix view.
  </footer>
</div>

<script>
const DEFAULT_COVERAGE = __DATA__;

let DATA = null;
const state = { onlyCovered:false, q:"" };

function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function tint(count){ // sequential: more detections => stronger accent tint
  if(!count) return "var(--surface-2)";
  const pct = Math.min(85, 22 + count*22);
  return `color-mix(in srgb, var(--accent) ${pct}%, var(--surface))`;
}

function renderKpis(){
  const s=DATA.summary;
  const tiles=[
    {label:"Detections parsed",value:s.detections_parsed,foot:Object.entries(s.sources).map(([k,v])=>`${v} ${k}`).join(" · ")},
    {label:"Techniques covered",value:s.techniques_covered,foot:`of ${s.techniques_total} in catalog`},
    {label:"Tactics with coverage",value:`${s.tactics_with_coverage}/${s.tactics_total}`,foot:"ATT&CK enterprise tactics"},
    {label:"Catalog coverage",value:s.coverage_pct+"%",foot:"covered ÷ catalog techniques"},
  ];
  document.getElementById("kpis").innerHTML=tiles.map(t=>`
    <div class="kpi"><div class="label">${t.label}</div><div class="value">${t.value}</div><div class="foot">${esc(t.foot)}</div></div>`).join("");
}

function renderLegend(){
  const cells=[1,2,3,4].map(n=>`<span class="lc" style="background:${tint(n)}" title="${n}${n===4?"+":""} detections"></span>`).join("");
  document.getElementById("legendCells").innerHTML=cells;
}

function matchQ(t){
  if(!state.q) return false;
  const q=state.q.toLowerCase();
  return t.id.toLowerCase().includes(q)||t.name.toLowerCase().includes(q);
}

function renderMatrix(){
  const m=document.getElementById("matrix");
  m.innerHTML=DATA.tactics.map(tac=>{
    const cells=tac.techniques.map(t=>{
      const hidden=state.onlyCovered&&!t.covered;
      const hl=matchQ(t);
      const subs=t.covered_subtechniques&&t.covered_subtechniques.length
        ? " ("+t.covered_subtechniques.map(s=>s.id).join(", ")+")" : "";
      const title=`${t.id} ${t.name}${t.covered?` — ${t.detection_count} detection(s)`:" — no detection"}${subs}`;
      const style=`background:${t.covered?tint(t.detection_count):""}` + (hl?";outline:2px solid var(--warn);outline-offset:1px":"");
      return `<div class="cell ${t.covered?"":"uncovered"} ${hidden?"hide":""}" style="${style}" title="${esc(title)}">
        <span class="tid">${t.id}</span>
        <span class="tt">${esc(t.name)}</span>
        ${t.covered?`<span class="cnt">${t.detection_count}</span>`:""}
      </div>`;
    }).join("");
    const pct=tac.total?Math.round(100*tac.covered/tac.total):0;
    return `<div class="col">
      <div class="colhead">
        <div class="tname">${esc(tac.name)}</div>
        <div class="tmeta">${tac.covered}/${tac.total} covered</div>
        <div class="tbar"><span style="width:${pct}%"></span></div>
      </div>
      ${cells}
    </div>`;
  }).join("");
}

function renderTacticBars(){
  const max=Math.max(1,...DATA.tactics.map(t=>t.total));
  document.getElementById("tacticBars").innerHTML=DATA.tactics.map(t=>{
    const w=(t.total/max)*100, cov=t.total?(t.covered/t.total)*w:0;
    return `<div class="barrow">
      <span class="bn">${esc(t.name)}</span>
      <span class="bt" title="${t.covered} of ${t.total} techniques"><span class="bf" style="width:${cov}%"></span></span>
      <span class="bx">${t.covered}/${t.total}</span>
    </div>`;
  }).join("");
}

function renderDetections(){
  const rows=DATA.detections.map(d=>{
    const chips=d.techniques.map(t=>`<span class="techchip" title="${esc(t.name)}">${esc(t.id)}</span>`).join("");
    return `<tr><td>${esc(d.name)}</td><td><span class="srcbadge">${esc(d.platform)}</span></td><td>${chips||"—"}</td></tr>`;
  }).join("");
  document.getElementById("detBody").innerHTML=rows;
}

function renderMeta(){
  let when=DATA.generated_at;
  try{when=new Date(DATA.generated_at).toLocaleString(undefined,{dateStyle:"medium",timeStyle:"short"});}catch(e){}
  document.getElementById("genPill").textContent="Generated "+when;
}

function boot(data,isSnapshot){
  DATA=data;
  document.getElementById("demoPill").hidden=!isSnapshot;
  renderMeta();renderKpis();renderLegend();renderMatrix();renderTacticBars();renderDetections();
}

(function(){
  const root=document.documentElement; let saved=null;
  try{saved=localStorage.getItem("attackcov-theme");}catch(e){}
  if(saved)root.setAttribute("data-theme",saved);
  document.getElementById("themeBtn").addEventListener("click",()=>{
    const cur=root.getAttribute("data-theme");
    const isDark=cur?cur==="dark":matchMedia("(prefers-color-scheme:dark)").matches;
    const next=isDark?"light":"dark"; root.setAttribute("data-theme",next);
    try{localStorage.setItem("attackcov-theme",next);}catch(e){}
  });
})();
document.getElementById("onlyCovered").addEventListener("change",e=>{state.onlyCovered=e.target.checked;renderMatrix();});
document.getElementById("search").addEventListener("input",e=>{state.q=e.target.value;renderMatrix();});

fetch("coverage.json",{cache:"no-store"})
  .then(r=>{if(!r.ok)throw new Error("no file");return r.json();})
  .then(d=>boot(d,false))
  .catch(()=>boot(DEFAULT_COVERAGE,true));
</script>
</body>
</html>
"""


def main() -> int:
    coverage = json.loads(COVERAGE.read_text(encoding="utf-8"))
    html = TEMPLATE.replace("__DATA__", json.dumps(coverage, separators=(",", ":")))
    OUT.write_text(html, encoding="utf-8")
    print(f"Wrote {OUT} ({len(html)} bytes) with embedded snapshot of {COVERAGE.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
