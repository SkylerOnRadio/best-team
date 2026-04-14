import csv
import json
import os
import html
from datetime import datetime
# Add these new imports at the top of reporting.py
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich import box
from config import (
    C, PROJECT_NAME, PROJECT_VERSION, KILL_CHAIN_STAGES, 
    DISTRIBUTED_ATTACK_WINDOW, ENTROPY_BASELINE_LINES
)
from utils import get_system_metadata
from intelligence import risk_score as _risk_score


def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    """Helper for terminal progress bars."""
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET

def print_banner():
    C = "\033[38;2;90;184;240m"   # Bright pixel blue (Core blocks)
    D = "\033[38;2;41;128;196m"   # Mid blue (Side/Top borders)
    S = "\033[38;2;30;77;122m"    # Shadow blue (Bottom borders)
    R = "\033[0m"                 # Reset
    
    print(f"""
  {C}██{D}╗      {C}██████{D}╗   {C}██████{D}╗ 
  {C}██{D}║     {C}██{D}╔{S}═══{C}██{D}╗ {C}██{D}╔{S}════╝ 
  {C}██{D}║     {C}██{D}║   {C}██{D}║ {C}██{D}║  {C}███{D}╗
  {C}██{D}║     {C}██{D}║   {C}██{D}║ {C}██{D}║   {C}██{D}║
  {C}███████{D}╗{S}╚{C}██████{D}╔{S}╝ {S}╚{C}██████{D}╔{S}╝
  {S}╚══════╝ ╚═════╝   ╚═════╝ {R}
                           
{C}██████{D}╗  {C}███████{D}╗ {C}████████{D}╗ {C}███████{D}╗  {C}██████{D}╗ {C}████████{D}╗  {C}██████{D}╗  {C}██████{D}╗ 
{C}██{D}╔{S}══{C}██{D}╗ {C}██{D}╔{S}════╝ {S}╚══{C}██{D}╔{S}══╝ {C}██{D}╔{S}════╝ {C}██{D}╔{S}════╝ {S}╚══{C}██{D}╔{S}══╝ {C}██{D}╔{S}═══{C}██{D}╗ {C}██{D}╔{S}══{C}██{D}╗
{C}██{D}║  {C}██{D}║ {C}█████{D}╗      {C}██{D}║    {C}█████{D}╗   {C}██{D}║         {C}██{D}║    {C}██{D}║   {C}██{D}║ {C}██████{D}╔{S}╝
{C}██{D}║  {C}██{D}║ {C}██{D}╔{S}══╝      {C}██{D}║    {C}██{D}╔{S}══╝   {C}██{D}║         {C}██{D}║    {C}██{D}║   {C}██{D}║ {C}██{D}╔{S}══{C}██{D}╗
{C}██████{D}╔{S}╝ {C}███████{D}╗    {C}██{D}║    {C}███████{D}╗ {S}╚{C}██████{D}╗    {C}██{D}║    {S}╚{C}██████{D}╔{S}╝ {C}██{D}║  {C}██{D}║
{S}╚═════╝  ╚══════╝    ╚═╝    ╚══════╝  ╚═════╝    ╚═╝     ╚═════╝  ╚═╝  ╚═╝{R}
""")

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich import box
from rich.align import Align
from rich.text import Text

# ... [Keep your print_banner() and other imports here] ...

def report_terminal(result: dict, filepath: str):
    console = Console()
    
    # ─── EXTRACT DATA ─────────────────────────────────────────────────────────
    risk     = _risk_score(result["gaps"], result["threats"])
    risk_col = "red" if risk >= 75 else ("dark_orange" if risk >= 40 else "green")
    perf     = result["performance"]
    stats    = result["stats"]
    eb       = result["entropy_baseline"]
    sys_info = get_system_metadata()

    # ─── THE ORIGINAL BANNER ──────────────────────────────────────────────────
    print("\n")
    print_banner() # Call your original ASCII art function directly
    
    # Add a clean sub-header using rich
    console.print(f"  [bold cyan]Foreign Threat Analysis | v{PROJECT_VERSION}[/]")
    console.print(f"  [dim]Target: {filepath}[/]\n")

    # ─── ROW 1: METRICS (4 Columns) ───────────────────────────────────────────
    def make_metric(title, value, style="white"):
        return Panel(Align.center(Text(str(value), style=style, justify="center")), title=title, box=box.ROUNDED)

    metrics = Columns([
        make_metric("Parsed Lines", f"{stats['parsed']:,}", "bold blue"),
        make_metric("Throughput", f"{perf['mbps']} MB/s", "bold green"),
        make_metric("Processing Time", f"{perf['time']}s", "bold yellow"),
        make_metric("Active Workers", f"{perf['workers']}", "bold magenta"),
    ], expand=True)
    console.print(metrics)

    # ─── ROW 2: RISK & INTELLIGENCE ───────────────────────────────────────────
    # Left Side: System & Risk
    sys_table = Table.grid(padding=(0, 2))
    sys_table.add_column(style="dim", justify="right")
    sys_table.add_column(style="bold white")
    sys_table.add_row("Hostname:", sys_info['host'])
    sys_table.add_row("Log Type:", stats['log_type'])
    sys_table.add_row("CPU Cap:", f"{perf['cpu_limit']:.0f}%")
    
    bar_len = 40
    filled = int((risk / 100) * bar_len)
    risk_bar = "█" * filled + "░" * (bar_len - filled)
    
    sys_group = Group(
        sys_table,
        Text("\nSystem Compromise Probability:", style="bold"),
        Text(f"{risk:>3}% {risk_bar}", style=f"bold {risk_col}")
    )
    
    # Right Side: Findings Summary
    ioc_count = sum(1 for t in result["threats"] if t.get("is_ioc"))
    find_table = Table.grid(padding=(0, 2))
    find_table.add_column(style="bold white")
    find_table.add_column()
    
    find_table.add_row("Timeline Anomalies:", f"[red]{len(result['gaps'])}[/]" if result['gaps'] else "[green]0[/]")
    find_table.add_row("Active Entities:", f"[{'red' if len(result['threats']) > 3 else 'dark_orange'}]{len(result['threats'])}[/]")
    find_table.add_row("Obfuscated Payloads:", f"[yellow]{stats['obfuscated']}[/]")
    find_table.add_row("Rare Templates:", f"[magenta]{stats['rare_templates']}[/]")
    find_table.add_row("IOC Feed Matches:", f"[red]{ioc_count}[/]" if ioc_count else "[green]0[/]")
    find_table.add_row("Entropy Threshold:", f"[dim]Θ=[/][yellow]{eb['threshold']:.3f}[/]")

    console.print(Columns([
        Panel(sys_group, title="[bold]System Intelligence[/]", box=box.ROUNDED, border_style=risk_col),
        Panel(find_table, title="[bold]Forensic Overview[/]", box=box.ROUNDED, border_style="magenta")
    ], expand=True))

    # ─── ALERTS SECTION ───────────────────────────────────────────────────────
    alerts = []
    kc_actors = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    for kc in kc_actors[:3]:
        alerts.append(f"[bold red]⚠ KILL-CHAIN CONFIRMED:[/] {kc['ip']} (Progression Stages: {kc['kill_chain_score']})")
    
    dist_actors = [t for t in result["threats"] if "DISTRIBUTED_ATTACK" in t["risk_tags"]]
    if dist_actors:
        alerts.append(f"[bold dark_orange]🌐 DISTRIBUTED ATTACK:[/] {len(dist_actors)} IPs in coordinated swarm")
        
    if alerts:
        console.print(Panel("\n".join(alerts), box=box.HEAVY, border_style="red"))

    # ─── TOP THREAT ACTORS TABLE ──────────────────────────────────────────────
    if result["threats"]:
        threat_tb = Table(box=box.ROUNDED, expand=True, border_style="cyan", header_style="bold cyan")
        threat_tb.add_column("Threat Entity (IP)", justify="left")
        threat_tb.add_column("Hits", justify="right")
        threat_tb.add_column("KC", justify="center")
        threat_tb.add_column("Sessions", justify="center")
        threat_tb.add_column("Risk Indicators", style="dim")
        
        sorted_threats = sorted(result["threats"], key=lambda x: (x["kill_chain_score"], x["hits"]), reverse=True)[:8]
        for t in sorted_threats:
            tags_str = ", ".join(t["risk_tags"][:3])
            ioc_flag = " [red]\\[IOC][/]" if t.get("is_ioc") else ""
            
            # Highlight highly dangerous IPs
            ip_style = "bold red" if t["kill_chain_score"] >= 3 else "yellow"
            kc_style = "bold white on red" if t["kill_chain_score"] >= 3 else "dark_orange"
            
            threat_tb.add_row(
                f"[{ip_style}]{t['ip']}[/]", 
                str(t['hits']), 
                f"[{kc_style}] {t['kill_chain_score']} [/]", 
                str(t['session_count']), 
                f"{tags_str}{ioc_flag}"
            )
        console.print(threat_tb)

    # ─── TIMELINE ANOMALIES TABLE ─────────────────────────────────────────────
    if result["gaps"]:
        gap_tb = Table(box=box.ROUNDED, expand=True, border_style="red", header_style="bold red")
        gap_tb.add_column("Anomaly Type")
        gap_tb.add_column("Severity")
        gap_tb.add_column("Duration (H:M:S)")
        gap_tb.add_column("Line Coordinates")
        
        for g in result["gaps"][:6]:
            sev_col = "bold white on red" if g["severity"] == "CRITICAL" else "dark_orange"
            gap_tb.add_row(
                g['type'], 
                f"[{sev_col}] {g['severity']} [/]", 
                g.get('duration_human','N/A'), 
                f"L:{g['start_line']} → L:{g['end_line']}"
            )
        console.print(gap_tb)

    console.print()

def report_csv_integrity(result: dict, path: str):
    fields = ["type", "gap_start", "gap_end", "duration_human",
              "duration_seconds", "severity", "start_line", "end_line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for g in result["gaps"]:
            writer.writerow({k: g.get(k, "N/A") for k in fields})


def report_csv_behavioral(result: dict, path: str):
    fields = ["ip", "hits", "span", "kill_chain_score",
              "session_count", "is_ioc", "risk_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for t in result["threats"]:
            writer.writerow({
                "ip":               t["ip"],
                "hits":             t["hits"],
                "span":             t["span"],
                "kill_chain_score": t["kill_chain_score"],
                "session_count":    t["session_count"],
                "is_ioc":           t.get("is_ioc", False),
                "risk_tags":        ", ".join(t["risk_tags"]),
            })


def report_json(result: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

def _build_zone_breakdown_html(breakdown: dict) -> str:
    """Render the per-zone risk bars for the HTML report."""
    ZONE_META = {
        "integrity":    ("⏱️ Integrity",    "Timeline gaps & reversed timestamps"),
        "access":       ("🔐 Access",        "Login failures, brute force, privilege escalation"),
        "persistence":  ("🪝 Persistence",   "Log-tampering & anti-forensic commands"),
        "privacy":      ("🔒 Privacy",       "Sensitive file & credential access"),
        "continuity":   ("💥 Continuity",    "Service crashes, kernel panics, OOM events"),
        "exfiltration": ("📤 Exfiltration",  "Data-transfer & reverse-shell indicators"),
        "lateral":      ("🌐 Lateral Mvmt",  "SSH pivoting, PsExec, remote management tools"),
    }
    rows = []
    for zone, (label, note) in ZONE_META.items():
        p   = breakdown.get(zone, 0.0)
        pct = int(p * 100)
        col = "#ef4444" if pct >= 75 else ("#f59e0b" if pct >= 40 else "#10b981" if pct > 0 else "#d1d5db")
        rows.append(f"""
  <div class="zb-row">
    <span class="zb-lbl">{label}</span>
    <div class="zb-bar-wrap"><div class="zb-bar" style="width:{pct}%;background:{col}"></div></div>
    <span class="zb-pct" style="color:{col}">{pct}%</span>
  </div>
  <div class="zb-note">{note}</div>""")
    return "\n".join(rows)

def report_html(result: dict, filepath: str, path: str):
    risk       = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 75 else ("#f59e0b" if risk >= 40 else "#10b981")
    sys_info   = get_system_metadata()
    perf       = result["performance"]
    stats      = result["stats"]
    eb         = result["entropy_baseline"]
    esc        = html.escape

    def tag_html(label: str, color: str = "blue") -> str: 
        return f'<span class="tag tag-{color}">{esc(label)}</span>'
        
    def zone_count_cls(items) -> str: 
        return "ok" if not items else ""

    def gen_rows(subset: list) -> str:
        if not subset: return '<tr><td colspan="5" class="no-data">No threats detected in this zone.</td></tr>'
        out = []
        for t in subset:
            kc_b  = f'<span class="kc-badge">KC:{t["kill_chain_score"]}</span>' if t["kill_chain_score"] >= 2 else ""
            ioc_b = tag_html("IOC","red") if t.get("is_ioc") else ""
            tags  = " ".join(tag_html(tg, "red" if tg in ("KILL_CHAIN_DETECTED","KNOWN_MALICIOUS_IOC","LOG_TAMPERING","DATA_EXFIL") else "blue") for tg in t["risk_tags"])
            out.append(f"<tr><td><strong>{esc(t['ip'])}</strong>{ioc_b}</td><td>{t['hits']}</td><td>{t['session_count']}</td><td>{kc_b}</td><td>{tags}</td></tr>")
        return "".join(out)

    def gap_rows(gtype: str) -> str:
        subset = [g for g in result["gaps"] if g["type"] == gtype]
        if not subset: return '<tr><td colspan="4" class="no-data">None detected.</td></tr>'
        return "".join(f"<tr><td>{tag_html(g['severity'],'red')}</td><td>{esc(g.get('duration_human','N/A'))}</td><td>{g.get('start_line', 'N/A')}–{g.get('end_line', 'N/A')}</td><td>{esc(g['gap_start'][:19])}</td></tr>" for g in subset)

    priv_esc    = [t for t in result["threats"] if "PRIV_ESCALATION"     in t["risk_tags"]]
    brute_force = [t for t in result["threats"] if "BRUTE_FORCE_BURST"   in t["risk_tags"] or "FAILED_LOGIN" in t["risk_tags"]]
    distributed = [t for t in result["threats"] if "DISTRIBUTED_ATTACK"  in t["risk_tags"]]
    log_tamper  = [t for t in result["threats"] if "LOG_TAMPERING"       in t["risk_tags"]]
    exfil       = [t for t in result["threats"] if "DATA_EXFIL"          in t["risk_tags"]]
    lateral     = [t for t in result["threats"] if "LATERAL_MOVEMENT"    in t["risk_tags"]]
    kill_chain  = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    ent_hits    = [t for t in result["threats"] if "HIGH_ENTROPY_PAYLOAD" in t["risk_tags"]]
    ioc_hits    = [t for t in result["threats"] if t.get("is_ioc")]

    max_hits = max((t["hits"] for t in result["threats"]), default=1)
    actor_bars = "".join(f'<div class="actor-row"><span class="actor-ip">{esc(t["ip"])}</span><div class="actor-bar-wrap"><div class="actor-bar" style="width:{int(t["hits"]/max_hits*100)}%;background:{"#ef4444" if "KILL_CHAIN_DETECTED" in t["risk_tags"] else "#f59e0b" if t["kill_chain_score"] >= 2 else "#3b82f6"}"></div></div><span class="actor-hits">{t["hits"]}</span></div>' for t in sorted(result["threats"], key=lambda x: x["hits"], reverse=True)[:10])

    compare_html = ""
    if result.get("compare") and result["compare"]["count"]:
        compare_html = f"""<div class="card"><h3>🔄 New Actors vs Baseline</h3><p style="color:var(--secondary);font-size:13px;">{result['compare']['count']} previously unseen IPs.</p><p style="font-family:monospace;font-size:12px;word-break:break-all;">{esc(", ".join(result['compare']['new_actors'][:20]))}</p></div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{esc(PROJECT_NAME)} – {esc(os.path.basename(filepath))}</title>
<style>
:root{{--primary:#111827;--secondary:#6b7280;--danger:#ef4444;--warning:#f59e0b;--success:#10b981;--bg:#f3f4f6;--card:#ffffff;--border:#e5e7eb}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--primary);padding:24px;line-height:1.6;font-size:14px}}
.container{{max-width:1280px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;letter-spacing:-.5px}}
h2{{font-size:18px;font-weight:700;margin-bottom:16px}}
h3{{font-size:15px;font-weight:700;margin-bottom:12px}}
.card{{background:var(--card);border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);padding:24px;margin-bottom:20px;border:1px solid var(--border)}}
.g2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:20px}}
.g4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:20px}}
.pill{{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}}
.pill .val{{font-size:28px;font-weight:900;line-height:1}}
.pill .lbl{{font-size:11px;color:var(--secondary);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
.risk-meter{{height:48px;background:#e5e7eb;border-radius:24px;overflow:hidden;margin:12px 0;position:relative;border:1px solid var(--border)}}
.risk-fill{{height:100%;background:{risk_color};width:{risk}%}}
.risk-text{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900;font-size:17px;text-shadow:0 1px 4px rgba(0,0,0,.5)}}
details{{border:1px solid var(--border);border-radius:10px;margin-bottom:12px;background:#fafafa;overflow:hidden}}
summary{{padding:14px 18px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;border-left:4px solid var(--secondary)}}
summary::-webkit-details-marker{{display:none}}
summary::after{{content:'▼';margin-left:auto;font-size:11px;transition:transform .2s;color:var(--secondary)}}
details[open] summary::after{{transform:rotate(180deg)}}
details[open] summary{{border-left-color:var(--primary);background:#fff;border-bottom:1px solid var(--border)}}
.inner{{border:none;background:transparent;margin:8px 0;border-radius:0}}
.inner summary{{padding:10px 18px;font-size:13px;background:#f1f5f9;border-left:3px solid var(--secondary);font-weight:600}}
.tw{{padding:12px 16px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#f8fafc;color:var(--secondary);text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid #f1f5f9}}
tr:last-child td{{border:none}}tr:hover td{{background:#f9fafb}}
.tag{{padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;margin:2px;display:inline-block}}
.tag-red{{background:#fee2e2;color:#991b1b}}.tag-blue{{background:#dbeafe;color:#1e40af}}
.kc-badge{{background:#7c3aed;color:#fff;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;margin-left:6px}}
.no-data{{color:var(--secondary);font-style:italic;text-align:center;padding:16px}}
.story-card{{background:#0f172a;color:#e2e8f0;padding:24px;border-radius:12px;margin-bottom:20px;border-left:5px solid #38bdf8}}
.story-card p{{line-height:1.8;font-size:14px}}
.mr{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--border);font-size:13px}}
.mr:last-child{{border:none}}.ml{{color:var(--secondary)}}.mv{{font-weight:600}}
.actor-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}}
.actor-ip{{width:130px;font-family:monospace;font-size:12px;flex-shrink:0}}
.actor-bar-wrap{{flex:1;height:10px;background:#e5e7eb;border-radius:5px;overflow:hidden}}
.actor-bar{{height:100%;border-radius:5px}}.actor-hits{{width:50px;text-align:right;color:var(--secondary);font-size:12px}}
.ei{{font-size:12px;color:var(--secondary);padding:10px 16px;background:#f8fafc;border-bottom:1px solid var(--border)}}
.zh{{display:flex;align-items:center;gap:8px}}
.zc{{background:var(--danger);color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:700}}
.zc.ok{{background:var(--success)}}
.fp{{font-family:monospace;font-size:11px;background:#f1f5f9;padding:3px 8px;border-radius:4px;color:#374151}}
footer{{text-align:center;color:var(--secondary);font-size:11px;padding:20px 0}}
.zb-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px;font-size:13px}}
.zb-lbl{{width:110px;font-weight:600;flex-shrink:0;font-size:12px}}
.zb-bar-wrap{{flex:1;height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden}}
.zb-bar{{height:100%;border-radius:7px}}.zb-pct{{width:40px;text-align:right;font-weight:700;font-size:12px}}
.zb-note{{font-size:11px;color:var(--secondary);margin-top:2px;padding-left:122px;margin-bottom:10px}}
</style>
</head><body><div class="container">

<div class="card">
  <h1>🔍 {esc(PROJECT_NAME)}</h1>
  <p style="color:var(--secondary);margin:4px 0 4px;">Forensic Audit: <strong>{esc(os.path.basename(filepath))}</strong> &nbsp;·&nbsp; {sys_info['ts'][:19]}</p>
  <p style="margin-bottom:16px;font-size:12px;color:var(--secondary);">Saved to: <span class="fp">{esc(path)}</span></p>
  <div class="risk-meter"><div class="risk-fill"></div>
  <div class="risk-text">SYSTEM COMPROMISE PROBABILITY: {risk}%</div></div>
</div>

<div class="g4">
  <div class="pill"><div class="val" style="color:{'#ef4444' if result['gaps'] else '#10b981'}">{len(result['gaps'])}</div><div class="lbl">Timeline Anomalies</div></div>
  <div class="pill"><div class="val" style="color:#f59e0b">{len(result['threats'])}</div><div class="lbl">Threat Actors</div></div>
  <div class="pill"><div class="val" style="color:#7c3aed">{len(kill_chain)}</div><div class="lbl">Kill Chains</div></div>
  <div class="pill"><div class="val" style="color:#ef4444">{len(ioc_hits)}</div><div class="lbl">IOC Matches</div></div>
  <div class="pill"><div class="val" style="color:#3b82f6">{stats['obfuscated']}</div><div class="lbl">Entropy Alerts</div></div>
  <div class="pill"><div class="val" style="color:#0891b2">{len(distributed)}</div><div class="lbl">Dist. Attackers</div></div>
  <div class="pill"><div class="val">{stats['rare_templates']}</div><div class="lbl">Rare Templates</div></div>
  <div class="pill"><div class="val" style="color:#10b981">{perf['lps']:,}</div><div class="lbl">Lines/sec</div></div>
  <div class="pill"><div class="val" style="color:#10b981">{perf['mbps']}</div><div class="lbl">MB/sec</div></div>
  <div class="pill"><div class="val">{perf['workers']}</div><div class="lbl">Workers Used</div></div>
  <div class="pill"><div class="val" style="color:#7c3aed">{perf['cpu_limit']:.0f}%</div><div class="lbl">CPU Cap/Worker</div></div>
</div>

<div class="g2">
  <div class="card">
    <h3>💻 System Metadata</h3>
    <div class="mr"><span class="ml">Hostname</span><span class="mv">{sys_info['host']}</span></div>
    <div class="mr"><span class="ml">OS</span><span class="mv">{sys_info['os']} {sys_info['ver']}</span></div>
    <div class="mr"><span class="ml">Architecture</span><span class="mv">{sys_info['arch']}</span></div>
    <div class="mr"><span class="ml">Processor</span><span class="mv">{sys_info['cpu'] or 'N/A'}</span></div>
  </div>
  <div class="card">
    <h3>📈 Analysis Intelligence</h3>
    <div class="mr"><span class="ml">Log Type</span><span class="mv">{stats['log_type']}</span></div>
    <div class="mr"><span class="ml">Throughput</span><span class="mv">{perf['lps']:,} lines/sec @ {perf['mbps']} MB/s</span></div>
    <div class="mr"><span class="ml">Processing Time</span><span class="mv">{perf['time']}s ({perf['workers']} workers, CPU cap {perf['cpu_limit']:.0f}%)</span></div>
    <div class="mr"><span class="ml">Entropy Baseline</span><span class="mv">μ={eb['mean']:.3f}  σ={eb['std']:.3f}  Θ={eb['threshold']:.3f}</span></div>
    <div class="mr"><span class="ml">Parsed / Total</span><span class="mv">{stats['parsed']:,} / {stats['total']:,}</span></div>
  </div>
</div>

<div class="story-card">
  <h3 style="margin-bottom:10px;">📖 Forensic Reconstruction</h3>
  <p>Analysis of <strong>{stats['total']:,}</strong> lines using <strong>{perf['workers']} parallel workers</strong> at <strong>{perf['mbps']} MB/s</strong> identified <strong>{len(result['threats'])}</strong> active threat entities across <strong>{len(result['gaps'])}</strong> timeline violations.
  {'<strong style="color:#f87171">Kill-chain confirmed for ' + str(len(kill_chain)) + ' actor(s).</strong>' if kill_chain else 'No kill-chain confirmed.'}
  {'<strong style="color:#fb923c"> Distributed attack: ' + str(len(distributed)) + ' IPs.</strong>' if distributed else ''}
  Peak: <strong>{max((t['hits'] for t in result['threats']), default=0):,}</strong> events from one source.
  Entropy Θ={eb['threshold']:.2f} flagged <strong>{stats['obfuscated']}</strong> obfuscated payloads.</p>
</div>

{'<div class="card"><h3>📊 Top Actor Activity</h3>' + actor_bars + '</div>' if actor_bars else ''}

{compare_html}

<div class="card">
  <h3>🎯 Risk Zone Breakdown</h3>
  <p style="color:var(--secondary);font-size:12px;margin-bottom:16px;">Per-zone probabilities computed dynamically (using asymptotic exponential smoothing) based on distinct actors and attack volumes. They compound into the headline probability.</p>
{_build_zone_breakdown_html(result.get("risk_breakdown", {}))}
</div>

<div class="card">
  <h2>📂 Categorized Forensic Evidence</h2>

  <details><summary><div class="zh">⏱️ Zone 1: Timeline &amp; Integrity<span class="zc {zone_count_cls(result['gaps'])}">{len(result['gaps'])}</span></div></summary>
  <div class="tw">
    <details class="inner"><summary>Timeline Gaps</summary><table><thead><tr><th>Severity</th><th>Duration</th><th>Lines</th><th>Start</th></tr></thead><tbody>{gap_rows('GAP')}</tbody></table></details>
    <details class="inner"><summary>Reversed Timestamps</summary><table><thead><tr><th>Severity</th><th>Delta</th><th>Lines</th><th>Start</th></tr></thead><tbody>{gap_rows('REVERSED')}</tbody></table></details>
    <details class="inner"><summary>Anti-Forensic Commands</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(log_tamper)}</tbody></table></details>
  </div></details>

  <details><summary><div class="zh">🔐 Zone 2: Access &amp; Control<span class="zc {zone_count_cls(brute_force + priv_esc)}">{len(brute_force)+len(priv_esc)}</span></div></summary>
  <div class="tw">
    <details class="inner"><summary>Brute Force / Credential Attacks</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(brute_force)}</tbody></table></details>
    <details class="inner"><summary>Distributed Attack Participants</summary><div class="ei">Coordinated storm across {DISTRIBUTED_ATTACK_WINDOW}s windows.</div><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(distributed)}</tbody></table></details>
    <details class="inner"><summary>Privilege Escalation</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(priv_esc)}</tbody></table></details>
    <details class="inner"><summary>Lateral Movement</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(lateral)}</tbody></table></details>
  </div></details>

  <details><summary><div class="zh">💀 Zone 3: Kill-Chain &amp; Confirmed Attacks<span class="zc {zone_count_cls(kill_chain)}">{len(kill_chain)}</span></div></summary>
  <div class="tw">
    <details class="inner"><summary>Kill-Chain Actors</summary><div class="ei">Stages: {' → '.join(KILL_CHAIN_STAGES)}</div><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC Score</th><th>Tags</th></tr></thead><tbody>{gen_rows(kill_chain)}</tbody></table></details>
    <details class="inner"><summary>Data Exfiltration</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(exfil)}</tbody></table></details>
  </div></details>

  <details><summary><div class="zh">🔮 Zone 4: Obfuscation &amp; Entropy<span class="zc {zone_count_cls(ent_hits)}">{len(ent_hits)}</span></div></summary>
  <div class="tw">
    <div class="ei">Dynamic Θ={eb['threshold']:.3f} (μ={eb['mean']:.3f}, σ={eb['std']:.3f}). Lines above threshold: packed/encoded payloads.</div>
    <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
    <tbody>{gen_rows(ent_hits) if ent_hits else '<tr><td colspan="5" class="no-data">None detected.</td></tr>'}</tbody></table>
  </div></details>

  <details><summary><div class="zh">🌐 Zone 5: IOC Matches<span class="zc {zone_count_cls(ioc_hits)}">{len(ioc_hits)}</span></div></summary>
  <div class="tw">
    <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
    <tbody>{gen_rows(ioc_hits) if ioc_hits else '<tr><td colspan="5" class="no-data">No IOC matches. Use --ioc-feed to enable.</td></tr>'}</tbody></table>
  </div></details>
</div>

<footer>{esc(PROJECT_NAME)} v{PROJECT_VERSION} &nbsp;|&nbsp; {stats['parsed']:,} parsed &nbsp;|&nbsp; {stats['skipped']:,} skipped &nbsp;|&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)