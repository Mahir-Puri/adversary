"""Standalone, self-contained HTML report.

Renders the run as a single dark-themed HTML file with a score gauge, a
severity breakdown, and an expandable per-attack table. No external assets or
JS frameworks — everything is inlined so the file can be opened straight from a
CI artifact download or attached to a PR comment.
"""

from __future__ import annotations

import datetime
import html

from ..models import Severity
from ..runners.engine import RunSummary

_SEV_HEX = {
    "CRITICAL": "#ff4d5e",
    "HIGH": "#ff7849",
    "MEDIUM": "#f5c451",
    "LOW": "#4dd0e1",
    "INFO": "#9aa5b1",
}


def _bar(label: str, count: int, total: int, colour: str) -> str:
    pct = (count / total * 100) if total else 0
    return f"""
      <div class="bar-row">
        <span class="bar-label">{html.escape(label)}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:{pct:.0f}%;background:{colour}"></div>
        </div>
        <span class="bar-count">{count}</span>
      </div>"""


def render_html(summary: RunSummary, *, title: str = "Adversary Report") -> str:
    total = summary.total
    landed = len(summary.landed)
    resisted = summary.passed
    score = (resisted / total * 100) if total else 100
    ring_colour = "#3ddc84" if score >= 90 else "#f5c451" if score >= 70 else "#ff4d5e"
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    # Severity breakdown bars.
    sev_counts = summary.landed_by_severity()
    sev_bars = "".join(
        _bar(sev, sev_counts.get(sev, 0), total, _SEV_HEX[sev])
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    # Per-attack rows.
    rows = []
    for r in summary.results:
        v = r.verdict
        status = "resisted" if v.passed else "landed"
        badge_class = "ok" if v.passed else "bad"
        badge_text = "RESISTED" if v.passed else "LANDED"
        sev_hex = _SEV_HEX.get(v.severity.name, "#9aa5b1")
        rows.append(
            f"""
        <tr class="{status}">
          <td><span class="badge {badge_class}">{badge_text}</span></td>
          <td><span class="sev" style="color:{sev_hex}">{v.severity.name}</span></td>
          <td class="mono">{html.escape(r.attack.id)}</td>
          <td>{html.escape(r.attack.category.value)}</td>
          <td class="detail">{html.escape(r.attack.description or v.detail)}</td>
          <td class="mono num">{r.latency_ms:.0f}ms</td>
        </tr>"""
        )
    rows_html = "".join(rows)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 2.5rem 1.5rem; background: #0c0f16; color: #e6e9ef;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  .wrap {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.35rem; letter-spacing: .5px; margin: 0 0 .25rem; }}
  h1 .tag {{ color: #a06bff; }}
  .sub {{ color: #79828f; font-size: .85rem; margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: 220px 1fr; gap: 1.25rem;
    margin-bottom: 2rem; }}
  .card {{ background: #141926; border: 1px solid #222a3a; border-radius: 14px;
    padding: 1.5rem; }}
  .gauge {{ display: flex; flex-direction: column; align-items: center;
    justify-content: center; }}
  .ring {{
    width: 150px; height: 150px; border-radius: 50%;
    background:
      radial-gradient(closest-side, #141926 79%, transparent 80%),
      conic-gradient({ring_colour} {score:.0f}%, #262d3d 0);
    display: grid; place-items: center;
  }}
  .ring b {{ font-size: 2rem; }}
  .ring span {{ display:block; font-size:.7rem; color:#79828f; text-align:center; }}
  .stat-row {{ display:flex; gap:2rem; margin-top:1rem; }}
  .stat b {{ font-size: 1.6rem; display:block; }}
  .stat.bad b {{ color:#ff6b6b; }}
  .stat.good b {{ color:#3ddc84; }}
  .stat span {{ color:#79828f; font-size:.75rem; }}
  .bar-row {{ display:flex; align-items:center; gap:.75rem; margin:.45rem 0; }}
  .bar-label {{ width:70px; font-size:.75rem; color:#aab3c0; }}
  .bar-track {{ flex:1; height:9px; background:#222a3a; border-radius:6px;
    overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:6px; }}
  .bar-count {{ width:24px; text-align:right; font-size:.8rem; color:#aab3c0; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1rem;
    background:#141926; border:1px solid #222a3a; border-radius:14px;
    overflow:hidden; }}
  th, td {{ text-align:left; padding:.65rem .8rem; font-size:.82rem;
    border-bottom:1px solid #1c2331; }}
  th {{ color:#79828f; font-weight:600; text-transform:uppercase;
    font-size:.68rem; letter-spacing:.5px; }}
  tr.landed {{ background: rgba(255,77,94,.05); }}
  .badge {{ font-size:.65rem; font-weight:700; padding:.15rem .45rem;
    border-radius:5px; }}
  .badge.ok {{ background:#123524; color:#3ddc84; }}
  .badge.bad {{ background:#3a1620; color:#ff6b7f; }}
  .sev {{ font-weight:700; font-size:.75rem; }}
  .mono {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; }}
  .num {{ text-align:right; color:#79828f; }}
  .detail {{ color:#aab3c0; max-width:340px; }}
  h2 {{ font-size:.8rem; text-transform:uppercase; letter-spacing:.5px;
    color:#79828f; margin:2rem 0 .5rem; }}
  footer {{ margin-top:2rem; color:#5a636f; font-size:.72rem; text-align:center; }}
</style>
</head>
<body>
<div class="wrap">
  <h1><span class="tag">⚔ ADVERSARY</span> — LLM Agent Red-Team Report</h1>
  <div class="sub">Generated {ts} · {total} attacks executed</div>

  <div class="cards">
    <div class="card gauge">
      <div class="ring"><div><b>{score:.0f}%</b><span>resisted</span></div></div>
    </div>
    <div class="card">
      <div class="stat-row">
        <div class="stat good"><b>{resisted}</b><span>attacks resisted</span></div>
        <div class="stat bad"><b>{landed}</b><span>attacks landed</span></div>
        <div class="stat"><b>{total}</b><span>total executed</span></div>
      </div>
      <h2 style="margin-top:1.5rem">Landed attacks by severity</h2>
      {sev_bars}
    </div>
  </div>

  <h2>Attack detail</h2>
  <table>
    <thead>
      <tr><th>Status</th><th>Severity</th><th>ID</th><th>Category</th>
      <th>Description</th><th>Latency</th></tr>
    </thead>
    <tbody>{rows_html}
    </tbody>
  </table>

  <footer>Adversary · deterministic + LLM-judge probes · not a safety guarantee,
  a regression signal.</footer>
</div>
</body>
</html>"""
