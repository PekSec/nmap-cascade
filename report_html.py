"""Offline Material 3 report presentation; no external assets or JavaScript."""
from html import escape
from pathlib import PurePath
import shlex
from urllib.parse import quote


# Material 3 baseline color roles, shape scale, and type scale. System fonts keep
# the exported report self-contained. https://material-web.dev/theming/
CSS = """
:root {
  color-scheme: light dark;
  --md-sys-color-primary: #6750a4; --md-sys-color-on-primary: #ffffff;
  --md-sys-color-primary-container: #eaddff; --md-sys-color-on-primary-container: #21005d;
  --md-sys-color-surface: #fef7ff; --md-sys-color-on-surface: #1d1b20;
  --md-sys-color-surface-container-low: #f7f2fa; --md-sys-color-surface-container: #f3edf7;
  --md-sys-color-surface-container-high: #ece6f0; --md-sys-color-on-surface-variant: #49454f;
  --md-sys-color-outline: #79747e; --md-sys-color-outline-variant: #cac4d0;
  --md-sys-color-error: #b3261e; --md-sys-color-error-container: #f9dedc;
  --md-sys-color-on-error-container: #410e0b;
  --md-ref-typeface-plain: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --md-sys-shape-corner-large: 16px; --md-sys-shape-corner-extra-large: 28px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --md-sys-color-primary: #d0bcff; --md-sys-color-on-primary: #381e72;
    --md-sys-color-primary-container: #4f378b; --md-sys-color-on-primary-container: #eaddff;
    --md-sys-color-surface: #141218; --md-sys-color-on-surface: #e6e0e9;
    --md-sys-color-surface-container-low: #1d1b20; --md-sys-color-surface-container: #211f26;
    --md-sys-color-surface-container-high: #2b2930; --md-sys-color-on-surface-variant: #cac4d0;
    --md-sys-color-outline: #938f99; --md-sys-color-outline-variant: #49454f;
    --md-sys-color-error: #f2b8b5; --md-sys-color-error-container: #8c1d18;
    --md-sys-color-on-error-container: #f9dedc;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--md-sys-color-surface); color: var(--md-sys-color-on-surface);
  font: 400 16px/1.5 var(--md-ref-typeface-plain); overflow-wrap: anywhere; }
a { color: var(--md-sys-color-primary); text-underline-offset: 3px; }
a:hover { text-decoration-thickness: 2px; }
:focus-visible { outline: 3px solid var(--md-sys-color-primary); outline-offset: 4px; }
.skip { position: absolute; left: 16px; top: -100px; padding: 12px 24px; z-index: 1;
  background: var(--md-sys-color-primary); color: var(--md-sys-color-on-primary); }
.skip:focus { top: 16px; }
.appbar { padding: 20px 32px; display: flex; align-items: center; justify-content: space-between;
  gap: 16px; flex-wrap: wrap; border-bottom: 1px solid var(--md-sys-color-outline-variant); }
.brand { display: flex; align-items: center; gap: 12px; font-size: 18px; font-weight: 600; }
.mark { display: grid; place-items: center; width: 44px; height: 44px; border-radius: 16px;
  background: var(--md-sys-color-primary); color: var(--md-sys-color-on-primary); font-size: 14px; }
.actions, nav { display: flex; gap: 8px; flex-wrap: wrap; }
.button, nav a { display: inline-flex; min-height: 48px; align-items: center; padding: 0 24px;
  border-radius: 999px; font-size: 14px; font-weight: 600; text-decoration: none; }
.button { background: var(--md-sys-color-primary-container); color: var(--md-sys-color-on-primary-container); }
.button.secondary { background: var(--md-sys-color-surface-container-high); color: var(--md-sys-color-on-surface); }
.button:hover, nav a:hover { box-shadow: inset 0 0 0 2px var(--md-sys-color-outline); }
main { max-width: 1200px; margin: auto; padding: 48px 32px; }
section { margin-bottom: 40px; scroll-margin-top: 24px; }
h1, h2, h3, h4, p { margin-top: 0; }
h1 { font-size: clamp(32px, 5vw, 45px); line-height: 1.16; font-weight: 400; letter-spacing: -.5px; margin-bottom: 16px; }
h2 { font-size: 28px; line-height: 36px; font-weight: 400; margin-bottom: 8px; }
h3 { font-size: 22px; line-height: 28px; font-weight: 500; margin-bottom: 8px; }
h4 { font-size: 16px; font-weight: 600; margin: 24px 0 12px; }
.eyebrow { font-size: 12px; line-height: 16px; letter-spacing: 1.5px; text-transform: uppercase;
  font-weight: 600; color: var(--md-sys-color-primary); margin-bottom: 12px; }
.muted, small { color: var(--md-sys-color-on-surface-variant); }
small { font-size: 12px; line-height: 18px; }
.hero { display: flex; gap: 24px; justify-content: space-between; align-items: start; }
.hero > div { min-width: 0; }
.badge { display: inline-flex; align-items: center; min-height: 32px; padding: 4px 12px;
  border-radius: 8px; background: var(--md-sys-color-surface-container-high);
  color: var(--md-sys-color-on-surface); font: 500 12px/20px var(--md-ref-typeface-plain); }
.badge.primary { background: var(--md-sys-color-primary-container); color: var(--md-sys-color-on-primary-container); }
.badge.error, .notice.error { background: var(--md-sys-color-error-container); color: var(--md-sys-color-on-error-container); }
.notice { padding: 20px 24px; border-radius: var(--md-sys-shape-corner-large);
  background: var(--md-sys-color-surface-container); margin: 24px 0; }
.notice p:last-child { margin-bottom: 0; }
nav { border-bottom: 1px solid var(--md-sys-color-outline-variant); padding-bottom: 12px; margin-bottom: 32px; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 28px 0; }
.metric { padding: 24px; border-radius: var(--md-sys-shape-corner-extra-large); background: var(--md-sys-color-surface-container); }
.metric:first-child { background: var(--md-sys-color-primary-container); color: var(--md-sys-color-on-primary-container); }
.metric strong { display: block; font-size: 45px; line-height: 52px; font-weight: 400; margin: 8px 0; }
.metric span { font-size: 14px; font-weight: 500; }
.card { padding: 24px; margin-top: 16px; border: 1px solid var(--md-sys-color-outline-variant);
  border-radius: var(--md-sys-shape-corner-extra-large); background: var(--md-sys-color-surface-container-low); }
.host-head { display: flex; gap: 16px; align-items: start; justify-content: space-between; }
.table-scroll { overflow-x: auto; border-radius: 12px; }
table { border-collapse: collapse; width: 100%; text-align: left; font-size: 14px; }
th { font-weight: 600; color: var(--md-sys-color-on-surface-variant); background: var(--md-sys-color-surface-container); }
th, td { padding: 14px 16px; border-bottom: 1px solid var(--md-sys-color-outline-variant); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
.ports { min-width: 620px; }
.ports th:first-child { width: 100px; }
.ports td:last-child { min-width: 220px; }
caption { text-align: left; padding: 8px 0 12px; font-weight: 500; }
details { margin-top: 12px; }
summary { cursor: pointer; padding: 12px; min-height: 48px; border-radius: 12px; }
summary:hover { background: var(--md-sys-color-surface-container-high); }
summary .badge { margin-left: 8px; }
.observation { border-top: 1px solid var(--md-sys-color-outline-variant); padding-top: 8px; }
.observation-body { padding: 12px; }
.evidence { background: var(--md-sys-color-surface-container); border-radius: 16px; }
.evidence-body { padding: 0 16px 16px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; padding: 16px; border-radius: 12px;
  background: var(--md-sys-color-surface); color: var(--md-sys-color-on-surface); font: 13px/1.6 ui-monospace, monospace; }
code { font: 13px/1.5 ui-monospace, monospace; }
dl { display: grid; grid-template-columns: minmax(100px, 150px) minmax(0, 1fr); gap: 8px 16px; font-size: 14px; }
dt { color: var(--md-sys-color-on-surface-variant); } dd { margin: 0; }
li { margin-bottom: 8px; }
.empty { padding: 24px; background: var(--md-sys-color-surface-container); border-radius: 16px; }
footer { border-top: 1px solid var(--md-sys-color-outline-variant); padding-top: 24px; font-size: 12px; }
@media (max-width: 700px) {
  .appbar { padding: 16px; } main { padding: 28px 16px; }
  .hero { flex-direction: column; } .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
  .metric { padding: 20px; } .metric strong { font-size: 36px; }
  .card { padding: 16px; } .observation-body { padding: 8px 0; }
  nav a { padding: 0 16px; } .execution th, .execution td { padding: 12px 8px; }
}
@media print {
  :root { color-scheme: light; --md-sys-color-surface: white; --md-sys-color-on-surface: black;
    --md-sys-color-on-surface-variant: #333; --md-sys-color-surface-container: #eee;
    --md-sys-color-surface-container-low: white; --md-sys-color-surface-container-high: #eee;
    --md-sys-color-primary: #6750a4; --md-sys-color-on-primary: white;
    --md-sys-color-primary-container: #eaddff; --md-sys-color-on-primary-container: #21005d;
    --md-sys-color-error-container: #f9dedc; --md-sys-color-on-error-container: #410e0b; }
  .actions, nav, .skip { display: none; } main { padding: 16px 0; }
  .card, .notice { break-inside: avoid; } .table-scroll { overflow: visible; } .ports { min-width: 0; }
  details::details-content { display: block; content-visibility: visible; }
}
"""


def e(value):
    return escape(str(value if value is not None else "Not recorded"), quote=True)


def badge(value):
    tone = "error" if value in ("failed", "interrupted", "partial", "error") else ""
    if value in ("completed", "open"):
        tone = "primary"
    return f'<span class="badge {tone}">{e(value).replace("_", " ")}</span>'


def artifact_link(filename, label):
    # Only sibling artifacts are navigable; never turn scanned content into a URL.
    if not filename or PurePath(filename).name != filename or filename in (".", "..") or "\\" in filename:
        return e(label)
    return f'<a href="./{quote(filename, safe="")}">{e(label)}</a>'


def script_evidence(script, endpoint):
    labels = {"script_report": "Script-reported evidence", "version_association": "Version match · unconfirmed",
              "error": "Script error"}
    states = ", ".join(str(s) for s in script["reported_states"])
    return f'''<details class="evidence"><summary><strong>{e(script['id'])}</strong>
      <span class="muted"> · {e(endpoint)} · {e(labels.get(script['interpretation'], 'Unclassified evidence'))}</span></summary>
      <div class="evidence-body">{f'<p>Script-reported state: <strong>{e(states)}</strong></p>' if states else ''}
      <pre>{e(script['output'] or 'No textual output recorded.')}</pre>
      <details><summary>Structured XML evidence</summary><pre>{e(script['xml'])}</pre></details></div></details>'''


def observation_html(obs, expanded):
    rows, evidence = [], [script_evidence(s, "Host") for s in obs["scripts"]]
    for port in obs["ports"]:
        service = port["service"]
        name = " ".join(service.get(k, "") for k in ("name", "product", "version", "extrainfo")).strip()
        cpes = ", ".join(cpe for cpe in port["cpes"] if cpe)
        endpoint = f"{port['port']}/{port['protocol']}"
        detail = f"Method: {service.get('method', 'unknown')} · Nmap confidence: {service.get('conf', 'unknown')}"
        rows.append(f'''<tr><td><code>{e(endpoint)}</code></td><td>{badge(port['state'].get('state', 'unknown'))}</td>
          <td>{e(port['state'].get('reason', 'Not recorded'))}</td><td>{e(name or 'Not identified')}
          <br><small>{e(detail)}</small>{f'<br><small>CPE: {e(cpes)}</small>' if cpes else ''}</td></tr>''')
        evidence.extend(script_evidence(s, endpoint) for s in port["scripts"])
    ports = f'''<div class="table-scroll" role="region" aria-label="Observed ports" tabindex="0"><table class="ports">
      <caption>Port observations</caption><thead><tr><th scope="col">Endpoint</th><th scope="col">State</th>
      <th scope="col">Reason</th><th scope="col">Service</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>''' if rows else '<p class="muted">No individual port observations recorded.</p>'
    os_matches = ''.join(f'<li>{e(m.get("name"))} <span class="muted">· Nmap match accuracy {e(m.get("accuracy"))}%</span></li>' for m in obs['os_matches'])
    trace = ''.join(f'<li>Hop {e(h.get("ttl"))}: {e(h.get("ipaddr"))} · {e(h.get("rtt"))} ms</li>' for h in obs['trace'])
    aggregates = ''.join(f'<li>{e(g.get("count"))} ports: {e(g.get("state"))}</li>' for g in obs['extraports'])
    incomplete = obs['process_status'] != 'completed' or obs['nmap_finished'].get('exit') != 'success'
    return f'''<details class="observation" {'open' if expanded else ''}><summary><strong>{e(obs['phase'])}</strong> {badge(obs['process_status'])}</summary>
      <div class="observation-body"><p class="muted">Host status: {e(obs['status'].get('state', 'unknown'))}
      · Reason: {e(obs['status'].get('reason', 'unknown'))} · {artifact_link(obs['artifact'], 'Source XML')}</p>
      {'<p class="notice error">Partial observation. This evidence is retained but excluded from completed-result counts.</p>' if incomplete else ''}
      {ports}{f'<details><summary>Aggregate port states</summary><ul>{aggregates}</ul></details>' if aggregates else ''}
      <h4>Script evidence</h4>{''.join(evidence) or '<p class="muted">No script output recorded. This is not a negative vulnerability result.</p>'}
      {f'<h4>OS fingerprint guesses</h4><ul>{os_matches}</ul>' if os_matches else ''}
      {f'<h4>Traceroute</h4><ol>{trace}</ol>' if trace else ''}</div></details>'''


def render_report(result):
    """Render the existing report model; never reclassify scan findings."""
    counts = result['counts']
    metrics = [(len(result['hosts']), 'Hosts with evidence'),
               (counts['discovered_open_endpoints'], 'Discovered open endpoints'),
               (counts['latest_observed_open_endpoints'], 'Latest observed open endpoints'),
               (len(result['selected_scripts']), 'Selected NSE scripts')]
    cards = ''.join(f'<div class="metric"><span>{e(label)}</span><strong>{e(value)}</strong></div>' for value, label in metrics)
    hosts = []
    for index, host in enumerate(result['hosts'], 1):
        observations = ''.join(observation_html(obs, i == len(host['observations']) - 1)
                               for i, obs in enumerate(host['observations']))
        changes = ''.join(f'<li><code>{e(c["port"])}/{e(c["protocol"])}</code> · {e(c["from"])} → {e(c["to"])}'
                          f' <span class="muted">({e(c["phase"])})</span></li>' for c in host['state_changes'])
        hosts.append(f'''<article class="card" id="host-{index}"><div class="host-head"><div><p class="eyebrow">Host {index:02d}</p>
          <h3>{e(host['address'])}</h3></div><span class="badge">{len(host['observations'])} observations</span></div>
          {f'<h4>State changes</h4><ul>{changes}</ul>' if changes else ''}{observations}</article>''')
    phases = []
    for phase in result['phases']:
        command = shlex.join(phase.get('command', []))
        phases.append(f'''<tr><td><strong>{e(phase['phase'])}</strong>
          {f'<details><summary>Command</summary><pre>{e(command)}</pre></details>' if command else ''}
          {f'<p>{e(phase["parse_error"])}</p>' if phase.get('parse_error') else ''}</td>
          <td>{badge(phase['status'])}<br><small>Exit: {e(phase.get('exit_code'))}</small></td>
          <td><small>{e(phase.get('started'))}<br>{e(phase.get('finished'))}</small></td></tr>''')
    partial = result['status'] != 'completed'
    notice = ('Incomplete scan. Some stages did not finish; the evidence collected so far is retained.' if partial
              else 'Execution finished. Completion describes the scan process, not the absence of vulnerabilities.')
    empty = ('No host evidence is available. Review execution errors below.' if partial
             else 'No host evidence was recorded.')
    errors = ''.join(f'<li>{e(error)}</li>' for error in result['errors'])
    limits = ''.join(f'<li>{e(limit)}</li>' for limit in result['limitations'])
    selection = '\n'.join(PurePath(name).name for name in result['selected_scripts'])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer">
<title>{e(result['scan'])} · Nmap Cascade report</title><style>{CSS}</style></head><body>
<a class="skip" href="#overview">Skip to report</a>
<header class="appbar"><div class="brand"><span class="mark" aria-hidden="true">NC</span>Nmap Cascade</div>
<div class="actions"><a class="button secondary" href="./SUMMARY.txt">Text report</a><a class="button" href="./RESULTS.json" download>Export JSON</a></div></header>
<main><section id="overview" aria-labelledby="report-title"><div class="hero"><div>
<p class="eyebrow">Network visibility / Scan report</p><h1 id="report-title">{e(result['scan'])}</h1>
<p class="muted">Target <strong>{e(result['target'])}</strong> · IPv4 / TCP · {e(result['timing'])}</p>
</div>{badge(result['status'])}</div><div class="metrics">{cards}</div>
<div class="notice {'error' if partial else ''}"><p><strong>{'Partial report' if partial else 'Execution completed'}</strong> · Exit {e(result['exit_code'])}</p><p>{e(notice)}</p></div>
<p class="muted">Started {e(result['started'])}<br>Finished {e(result['finished'])}</p></section>
<nav aria-label="Report sections"><a href="#hosts">Hosts &amp; evidence</a><a href="#execution">Execution</a><a href="#coverage">Coverage</a></nav>
<section id="hosts" aria-labelledby="hosts-title"><h2 id="hosts-title">Hosts &amp; evidence</h2>
<p class="muted">Observations stay attributed to their host and scan stage. Expand a script to inspect its evidence.</p>
{''.join(hosts) or f'<p class="empty">{e(empty)}</p>'}</section>
<section id="execution" aria-labelledby="execution-title"><h2 id="execution-title">Execution history</h2>
<p class="muted">A completed phase can still contain script errors or checks with no output.</p>
<div class="card"><div class="table-scroll" role="region" aria-label="Phase execution history" tabindex="0"><table class="execution">
<caption>Recorded stages</caption><thead><tr><th scope="col">Stage</th><th scope="col">Status</th><th scope="col">Started / finished</th></tr></thead>
<tbody>{''.join(phases)}</tbody></table></div></div>
{f'<div class="notice error"><h3>Execution errors</h3><ul>{errors}</ul></div>' if errors else ''}</section>
<section id="coverage" aria-labelledby="coverage-title"><h2 id="coverage-title">Coverage &amp; interpretation</h2>
<p class="muted">Missing evidence is unknown. Script results are not independently confirmed vulnerabilities.</p>
<div class="card"><ul>{limits}</ul><dl><dt>Unique TCP ports</dt><dd>{e(counts['discovered_unique_tcp_ports'])} discovered port numbers</dd>
<dt>Minimum rate</dt><dd>{e(result['min_rate']) if result['min_rate'] is not None else 'Nmap adaptive default'}</dd>
<dt>Maximum retries</dt><dd>{e(result['max_retries']) if result['max_retries'] is not None else 'Nmap timing default'}</dd>
<dt>NSE policy</dt><dd><code>{e(result['nse_selection'])}</code></dd></dl>
<details><summary>Selected scripts ({len(result['selected_scripts'])})</summary><p class="muted">Selection is not proof that every script executed.</p><pre>{e(selection or 'No script selection available.')}</pre></details>
<details><summary>Nmap version</summary><pre>{e(result['nmap_version'])}</pre></details></div></section>
<footer class="muted">Nmap Cascade · Offline report · Material 3 color, type and shape roles.
Expand evidence before printing. Source-file links work when this report stays in its output folder.</footer></main></body></html>'''
