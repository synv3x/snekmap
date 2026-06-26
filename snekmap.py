from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import box

from scanner import scan_network, flag_critical_ports
import cve_lookup
from cve_lookup import lookup_cve, get_rate_limit_stats, is_rate_limited, evaluate_confidence, CONFIDENCE_THRESHOLDS
from scanner_checks import test_credentials_for_port, CHECKED_PORTS
from protocol_checks import run_protocol_checks, CHECKED_PORTS as PROTO_PORTS
from correlation import correlate_all_findings
from report import generate_html_report, generate_pdf_report

try:
    import termios as _termios
    _HAS_TERMIOS = True
except ImportError:
    _HAS_TERMIOS = False

console = Console(legacy_windows=False, force_interactive=True)

__version__ = "0.1.0"

_SEV_STYLE = {
    "CRITICAL": ("bold red",    "\U0001f534"),
    "HIGH":     ("bold yellow", "\U0001f7e0"),
    "MEDIUM":   ("yellow",      "\U0001f7e1"),
    "LOW":      ("bold green",  "\U0001f7e2"),
    "N/A":      ("dim",         "⚪"),
}

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "N/A": 0}

# 60-char-wide block-letter "SNEKMAP" in Unicode box-drawing style.
# Each letter is composed of ██ (U+2588 FULL BLOCK) and the standard
# box-drawing corner/edge characters so they render correctly in any
# terminal that supports Unicode (Windows Terminal, iTerm2, etc.).
_ART = [
    "███████╗███╗  ██╗███████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗ ",
    "██╔════╝████╗ ██║██╔════╝██║ ██╔╝████╗ ████║██╔══██╗██╔══██╗",
    "███████╗██╔██╗██║█████╗  █████╔╝ ██╔████╔██║███████║██████╔╝",
    "╚════██║██║╚████║██╔══╝  ██╔═██╗ ██║╚██╔╝██║██╔══██║██╔═══╝ ",
    "███████║██║ ╚███║███████╗██║  ██╗██║ ╚═╝ ██║██║  ██║██║     ",
    "╚══════╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ",
]

_ART_GRADIENT = [
    "blue",
    "bright_blue",
    "bold bright_blue",
    "bold bright_blue",
    "bright_blue",
    "blue",
]


def _worst(cves: list) -> dict | None:
    if not cves:
        return None
    return max(cves, key=lambda c: _SEV_RANK.get(c.get("severity", "N/A"), 0))


def _os_style(os_name: str) -> str:
    """Return a Rich style string based on detected OS family."""
    lo = os_name.lower()
    if "windows" in lo:
        return "bright_blue"
    if "linux" in lo or "ubuntu" in lo or "debian" in lo or "fedora" in lo or "centos" in lo:
        return "bright_green"
    if "mac" in lo or "darwin" in lo or "ios" in lo or "macos" in lo:
        return "yellow"
    if "freebsd" in lo or "openbsd" in lo or "netbsd" in lo:
        return "magenta"
    if "android" in lo:
        return "green"
    return "white"


def print_banner() -> None:
    w = shutil.get_terminal_size(fallback=(100, 24)).columns
    console.print()

    art_width = len(_ART[0])  # 60 chars
    if w >= art_width + 2:
        pad = " " * ((w - art_width) // 2)
        for line, color in zip(_ART, _ART_GRADIENT):
            console.print(Text(pad + line, style=color))
    else:
        # Narrow terminal fallback: simple text banner
        console.print(Align.center(Text("S N E K M A P", style="bold bright_blue")))

    console.print()
    console.print(Align.center(Text(f"v{__version__}  ·  Network Reconnaissance & Vulnerability Assessment", style="dim")))
    console.print()
    console.print(Rule(style="dim blue"))
    console.print()


def display_host(host: dict) -> None:
    ip       = host["ip"]
    hostname = host.get("hostname", "")
    os_name  = host.get("os", "Unknown")
    os_acc   = host.get("os_accuracy", 0)
    ports    = host.get("ports", [])

    cve_total  = sum(len(p.get("cves", [])) for p in ports)
    host_label = f"{ip}  ({hostname})" if hostname else ip
    os_label   = f"{os_name}  [{os_acc}% confidence]" if os_acc else os_name

    info = Text()
    info.append(f"  {host_label}\n", style="bold bright_cyan")
    info.append("  OS:     ", style="dim white")
    info.append(f"{os_label}\n", style=_os_style(os_name))
    if host.get("cdn"):
        info.append("  CDN:    ", style="dim white")
        info.append(f"{host['cdn']} — origin version data may be unreliable\n", style="dim yellow")
    info.append(f"  Ports:  {len(ports)}   ", style="dim white")
    info.append("CVEs:  ", style="dim white")
    info.append(str(cve_total), style="bold red" if cve_total else "dim white")
    console.print(Panel(info, border_style="cyan", padding=(0, 1)))

    # Confidence warnings (low-confidence service/version detections)
    for port in ports:
        svc_conf = port.get("service_confidence", 100)
        ver_conf = port.get("version_confidence", 100)
        if svc_conf < CONFIDENCE_THRESHOLDS["service"]:
            console.print(
                f"[yellow]  [!] Port {port['port']}: Service identification uncertain "
                f"({svc_conf}% confidence) — CVE correlation skipped[/yellow]"
            )
        elif ver_conf < CONFIDENCE_THRESHOLDS["version"]:
            console.print(
                f"[yellow]  [!] Port {port['port']}: Version uncertain "
                f"({ver_conf}% confidence) — CVE correlation uses major version only[/yellow]"
            )

    # Display critical findings FIRST (before CVE table)
    critical_findings = [p for p in ports if p.get("critical_finding")]
    if critical_findings:
        console.print()
        console.print("[bold red]⚠️  CRITICAL FINDINGS (Immediate attention required):[/bold red]")
        for port in critical_findings:
            severity = port.get("critical_severity", "HIGH")
            finding  = port.get("critical_finding", "")
            severity_style = "bold red" if severity == "CRITICAL" else "bold yellow"
            console.print(f"  [{severity_style}]Port {port['port']}: {finding}[/{severity_style}]")
        console.print()

    # Display confirmed credential findings
    cred_ports = [p for p in ports if p.get("cred_findings")]
    if cred_ports:
        console.print("[bold red]🔐 CONFIRMED CREDENTIAL VULNERABILITIES:[/bold red]")
        for port in cred_ports:
            for finding in port["cred_findings"]:
                console.print(f"  [bold red]Port {port['port']}: {finding['finding']}[/bold red]")
                console.print(f"    [dim]{finding['evidence']}[/dim]")
        console.print()

    # Display protocol-specific findings
    proto_findings = host.get("protocol_findings", [])
    if proto_findings:
        console.print("[bold yellow]⚠  PROTOCOL VULNERABILITIES:[/bold yellow]")
        for finding in proto_findings:
            sev_style = "bold red" if finding["status"] == "CRITICAL" else "bold yellow"
            console.print(
                f"  [{sev_style}]Port {finding['port']} "
                f"({finding['protocol'].upper()}): {finding['finding']}[/{sev_style}]"
            )
            console.print(f"    [dim]Impact: {finding['impact']}[/dim]")
            console.print(f"    [dim]Fix:    {finding['remediation']}[/dim]")
        console.print()

    # Correlation analysis (OS-service patterns, escalation paths, high-value targets)
    if ports:
        corr_findings = correlate_all_findings(host)
        if corr_findings:
            _CORR_STYLE = {
                "CRITICAL": "bold red",
                "HIGH":     "bold yellow",
                "MEDIUM":   "yellow",
                "LOW":      "dim",
            }
            console.print("[bold blue]🔗 Correlation Analysis[/bold blue]")
            for finding in corr_findings:
                sty = _CORR_STYLE.get(finding["severity"], "white")
                console.print(f"  [{sty}][{finding['type']}] {finding['finding']}[/{sty}]")
                if "ports" in finding:
                    console.print(f"    [dim]Ports: {finding['ports']}[/dim]")
                if "investigation" in finding:
                    console.print(f"    [dim]→ {finding['investigation']}[/dim]")
                if "recommendation" in finding:
                    console.print(f"    [dim]→ {finding['recommendation']}[/dim]")
                if "risk" in finding:
                    console.print(f"    [dim]Risk: {finding['risk']}[/dim]")
            console.print()

    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        padding=(0, 1),
        show_edge=False,
        expand=True,
    )
    tbl.add_column("PORT",    style="bright_cyan", width=9,  no_wrap=True)
    tbl.add_column("PROTO",   style="dim",          width=6,  no_wrap=True)
    tbl.add_column("STATE",   style="bright_green", width=15, no_wrap=True)
    tbl.add_column("SERVICE", style="white",        width=14, no_wrap=True)
    tbl.add_column("VERSION / PRODUCT", style="dim white", ratio=1, no_wrap=False)
    tbl.add_column("CVEs",    justify="center",     width=8)

    for port in ports:
        ver = " ".join(filter(None, [
            port.get("product", ""),
            port.get("version", ""),
            port.get("extrainfo", ""),
        ])).strip() or "—"

        state     = port.get("state", "")
        state_sty = "yellow" if state == "open|filtered" else "bright_green"

        cves  = port.get("cves", [])
        worst = _worst(cves)
        if worst:
            sev         = worst.get("severity", "N/A")
            style, icon = _SEV_STYLE.get(sev, ("dim", "⚪"))
            cve_cell    = Text(f"{icon} {len(cves)}", style=style)
        else:
            cve_cell = Text("—", style="dim")

        tbl.add_row(
            str(port["port"]),
            port.get("protocol", "tcp").upper(),
            Text(state, style=state_sty),
            port.get("service", "—"),
            ver,
            cve_cell,
        )

    console.print(tbl)

    # CVE details section
    ports_with_cves = [p for p in ports if p.get("cves")]
    if ports_with_cves:
        console.print()
        console.print(Rule("  CVE Findings  ", style="dim yellow", align="left"))
        console.print()

        # Reserve space: ID(18) + SEV(14) + CVSS(11) + padding(~8) = 51; remainder for desc
        desc_max = max(40, console.width - 55)

        for port in ports_with_cves:
            cves      = port["cves"]
            ver_label = " ".join(filter(None, [port.get("product", ""), port.get("version", "")])).strip()
            port_label = f"Port {port['port']}/{port.get('service', '?')}"
            if ver_label:
                port_label += f"  ·  {ver_label}"

            console.print(f"  [dim white]{port_label}[/dim white]")

            cve_tbl = Table(
                box=None, show_header=False, padding=(0, 2),
                show_edge=False, expand=False,
            )
            cve_tbl.add_column(width=18, no_wrap=True)
            cve_tbl.add_column(width=14, no_wrap=True)
            cve_tbl.add_column(width=11, no_wrap=True)
            cve_tbl.add_column(max_width=desc_max)

            for cve in cves:
                sev         = cve.get("severity", "N/A")
                style, icon = _SEV_STYLE.get(sev, ("dim", "⚪"))
                score       = cve.get("cvss_score")
                score_str   = f"CVSS {score:.1f}" if score is not None else "CVSS  —"
                desc        = cve.get("description", "")
                if len(desc) > desc_max:
                    desc = desc[:desc_max - 3] + "..."

                cve_tbl.add_row(
                    Text(cve.get("id", "?"), style="bold white"),
                    Text(f"{icon} {sev}", style=style),
                    Text(score_str, style="dim"),
                    Text(desc, style="dim white"),
                )

            console.print(cve_tbl)
            console.print()

    console.print()


def display_summary(results: list) -> None:
    all_cves   = [c for h in results for p in h.get("ports", []) for c in p.get("cves", [])]
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
    for c in all_cves:
        sev = c.get("severity", "N/A")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    console.print(Rule("  Summary  ", style="bright_blue"))
    console.print()

    # Warn if NVD rate limiting affected this scan
    rl = get_rate_limit_stats()
    if rl["degraded_mode"] or rl["consecutive_hits"] > 0:
        if rl["degraded_mode"]:
            console.print("[bold yellow][!] CVE lookup degraded — NVD rate limit reached. Using static overrides only.[/bold yellow]")
        else:
            console.print(f"[yellow][!] NVD rate limit hit {rl['consecutive_hits']} time(s) during scan (backoff applied).[/yellow]")
        console.print()

    # Three columns: icon (fixed 2-cell width) | label | right-justified count.
    # Separating the wide emoji into its own column keeps the count column
    # properly aligned regardless of whether the terminal counts emoji as 1 or 2 cells.
    tbl = Table(box=None, show_header=False, padding=(0, 2), show_edge=False, expand=False)
    tbl.add_column(width=2)                                        # icon
    tbl.add_column(style="dim white", width=28)                    # label
    tbl.add_column(style="bold white", justify="right", width=8)   # count

    live_hosts  = len([h for h in results if h.get("ports")])
    total_ports = sum(len(h.get("ports", [])) for h in results)

    all_ports      = [p for h in results for p in h.get("ports", [])]
    critical_count = sum(1 for p in all_ports if p.get("critical_severity") == "CRITICAL")

    tbl.add_row("", "Hosts with open ports", str(live_hosts))
    tbl.add_row("", "Total open ports",      str(total_ports))
    tbl.add_row("", "Total CVEs found",      str(len(all_cves)))
    if critical_count:
        tbl.add_row(
            Text("⚠",                      style="bold red"),
            Text("Critical port findings", style="bold red"),
            Text(str(critical_count),      style="bold red"),
        )
    tbl.add_row("", "", "")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        style, icon = _SEV_STYLE[sev]
        count = sev_counts.get(sev, 0)
        tbl.add_row(
            Text(icon,              style=style),
            Text(sev.capitalize(), style=style),
            Text(str(count),       style=style if count else "dim"),
        )

    console.print(tbl)
    console.print()


def export_menu() -> str | None:
    console.print(Rule("  Export Report  ", style="bright_blue"))
    console.print()

    menu = Table(box=None, show_header=False, padding=(0, 2), show_edge=False, expand=False)
    menu.add_column(style="bold bright_cyan", width=5)
    menu.add_column()

    menu.add_row(Text("[1]"), Text("HTML Report",         style="white"))
    menu.add_row(Text("[2]"), Text("PDF Report",          style="white"))
    menu.add_row(Text("[3]"), Text("JSON Export", style="white"))
    menu.add_row(Text("[4]"), Text("CSV Export",  style="white"))
    menu.add_row(Text("[5]"), Text("All formats",          style="white"))
    menu.add_row(Text("[6]"), Text("Skip",                style="dim"))

    console.print(menu)
    console.print()

    while True:
        choice = console.input("[bright_cyan]>[/bright_cyan] Select (1-6): ").strip()

        if choice == "6":
            confirm = console.input("Skip report generation? (Y/n): ").strip().lower()
            if confirm == "y":
                return None
            continue

        if choice in {"1", "2", "3", "4", "5"}:
            return choice

        console.print("[red]  Invalid choice — enter 1 through 6.[/red]")


def resolve_output_dir(user_path: str | None) -> str:
    """Resolve the output directory with cross-platform fallbacks."""
    if user_path:
        p = Path(user_path)
        p.mkdir(parents=True, exist_ok=True)
        return str(p)

    # Honour XDG_DESKTOP_DIR if set and valid (Linux/freedesktop standard)
    xdg = os.environ.get("XDG_DESKTOP_DIR", "")
    if xdg:
        p = Path(xdg)
        if p.exists() and p.is_dir():
            return str(p)

    # Standard Desktop location (macOS, Windows)
    desktop = Path.home() / "Desktop"
    if desktop.exists() and desktop.is_dir():
        return str(desktop)

    fallback = Path.home() / ".snekmap" / "reports"
    fallback.mkdir(parents=True, exist_ok=True)
    return str(fallback)


_VALID_TARGET_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\-,/]*$')


def _validate_target(target: str) -> None:
    """Raise ValueError with a helpful message if the target looks malformed."""
    t = target.strip()
    if not t:
        raise ValueError("target cannot be empty")
    try:
        ipaddress.ip_address(t)
        return
    except ValueError:
        pass
    try:
        ipaddress.ip_network(t, strict=False)
        return
    except ValueError:
        pass
    # Accept hostnames and nmap range expressions (e.g. 192.168.1.1-5)
    if _VALID_TARGET_RE.match(t):
        return
    raise ValueError(
        f"invalid target '{t}' — expected an IP address, CIDR range, or hostname"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "SnekMap — Network reconnaissance and vulnerability assessment scanner. "
            "Combines nmap-style port scanning with automated CVE correlation "
            "from the NIST NVD database."
        ),
        epilog=(
            "examples:\n"
            "  snekmap 192.168.1.0/24                Standard scan of a /24\n"
            "  snekmap scanme.nmap.org -f            Fast scan against the nmap test host\n"
            "  snekmap 10.0.0.1 -d --no-cve          Deep scan, skip CVE lookups\n"
            "\n"
            "For NVD API access (10x faster CVE lookups), set the NVD_API_KEY environment\n"
            "variable. Request a key at https://nvd.nist.gov/developers/request-an-api-key"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target IP, hostname, or CIDR range")
    scan_mode_group = parser.add_mutually_exclusive_group()
    scan_mode_group.add_argument("-f", "--fast", action="store_true", help="Fast scan (top 100 ports)")
    scan_mode_group.add_argument("-d", "--deep", action="store_true", help="Deep scan (all 65535 ports)")
    parser.add_argument("--no-cve",        action="store_true", help="Skip CVE lookups (faster)")
    parser.add_argument(
        "--export",
        choices=["html", "pdf", "json", "csv", "all"],
        default=None,
        metavar="FORMAT",
        help="Export format without interactive menu: html, pdf, json, csv, all",
    )
    parser.add_argument("-o", "--output-dir", default=None, metavar="DIR",
                        help="Directory to save reports (default: Desktop, or ~/SnekMap-Reports if unavailable)")
    parser.add_argument("-v", "--version", action="version",    version=f"SnekMap {__version__}")
    parser.add_argument("-q", "--quiet",    action="store_true", help="Suppress banner and all progress spinners (useful for scripts/piping)")
    parser.add_argument("--easter-egg",    action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    if args.easter_egg:
        console.print('"if nmap and a snake had a baby, it would be me"')
        return

    try:
        _validate_target(args.target)
    except ValueError as e:
        console.print(f"[red]\\[-] {e}[/red]")
        return

    scan_mode  = "fast" if args.fast else "deep" if args.deep else "standard"
    file_ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = resolve_output_dir(args.output_dir)

    if not shutil.which("nmap"):
        console.print("[red]\\[-] Error: nmap not found. Install nmap to use SnekMap.[/red]")
        console.print("    Visit: https://nmap.org/download")
        return

    meta       = {"target": args.target, "mode": scan_mode, "version": __version__}

    console.print(f"  [dim]Target :[/dim]  [bright_cyan]{args.target}[/bright_cyan]")
    console.print(f"  [dim]Mode   :[/dim]  [white]{scan_mode}[/white]")
    if args.no_cve:
        console.print("  [dim]CVE lookup skipped (--no-cve)[/dim]")
    elif not os.environ.get("NVD_API_KEY"):
        console.print(
            "  [dim]\\[*] Tip: set [bold]NVD_API_KEY[/bold] env var for 10× faster CVE lookups "
            "— nvd.nist.gov/developers/request-an-api-key[/dim]"
        )
    console.print()

    # ── Phase 1: Host & port scan ──────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        console=console,
        transient=True,
        disable=args.quiet,
    ) as prog:
        task = prog.add_task("[bright_blue]\\[~] Scanning hosts and services...", total=None)
        try:
            results = scan_network(args.target, fast=args.fast, deep=args.deep)
        except Exception as exc:
            console.print(f"[red]  \\[-] Scan error: {exc}[/red]")
            return
        prog.update(task, completed=True)

    if not results:
        console.print("[red]  \\[-] No hosts found or scan failed.[/red]")
        return

    live        = [h for h in results if h.get("ports")]
    total_ports = sum(len(h.get("ports", [])) for h in results)
    console.print(
        f"  [bright_blue]\\[+][/bright_blue]  [bold]{len(live)}[/bold] host(s) "
        f"· [bold]{total_ports}[/bold] open port(s)\n"
    )

    # ── Phase 2: CVE lookup ────────────────────────────────────────────────────
    all_port_refs = [(h, p) for h in results for p in h.get("ports", [])]

    if args.no_cve:
        for _, port in all_port_refs:
            port["cves"] = []
        total_cves = 0
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            console=console,
            transient=True,
            disable=args.quiet,
        ) as prog:
            task = prog.add_task("[bright_blue]\\[~] Looking up CVEs...", total=len(all_port_refs))

            for _, port in all_port_refs:
                try:
                    port["cves"] = lookup_cve(
                        service=port.get("service", ""),
                        version=port.get("version", ""),
                        product=port.get("product", ""),
                        cpe=port.get("cpe", ""),
                        service_confidence=port.get("service_confidence", 100),
                        version_confidence=port.get("version_confidence", 100),
                    )
                except Exception:
                    port["cves"] = []
                prog.advance(task)

        total_cves = sum(len(p.get("cves", [])) for h in results for p in h.get("ports", []))
        console.print(
            f"  [bright_blue]\\[+][/bright_blue]  CVE lookup complete "
            f"· [bold]{total_cves}[/bold] CVE(s) found\n"
        )

    # ── Phase 2.5: Credential checks ──────────────────────────────────────────
    # Build list of (host_ip, port_dict) for every port worth testing
    checkable = [
        (host["ip"], port)
        for host in results
        for port in host.get("ports", [])
        if port["port"] in CHECKED_PORTS
    ]
    if checkable:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            console=console,
            transient=True,
            disable=args.quiet,
        ) as prog:
            task = prog.add_task(
                "[bright_blue]\\[~] Testing default credentials...",
                total=len(checkable),
            )
            for host_ip, port in checkable:
                try:
                    port["cred_findings"] = test_credentials_for_port(host_ip, port["port"])
                except Exception:
                    port["cred_findings"] = []
                prog.advance(task)

        cred_hits = sum(
            len(p.get("cred_findings", []))
            for h in results for p in h.get("ports", [])
        )
        if cred_hits:
            console.print(
                f"  [bold red]\\[!][/bold red]  [bold red]{cred_hits}[/bold red] "
                f"default credential finding(s) confirmed\n"
            )
        else:
            console.print(
                "  [bright_blue]\\[+][/bright_blue]  Credential checks complete"
                " — no default credentials accepted\n"
            )

    # ── Phase 2.75: Protocol-specific checks ──────────────────────────────────
    proto_checkable = [
        host
        for host in results
        if any(p["port"] in PROTO_PORTS for p in host.get("ports", []))
    ]
    if proto_checkable:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            console=console,
            transient=True,
            disable=args.quiet,
        ) as prog:
            task = prog.add_task(
                "[bright_blue]\\[~] Running protocol checks...",
                total=len(proto_checkable),
            )
            for host in proto_checkable:
                try:
                    host["protocol_findings"] = run_protocol_checks(
                        host["ip"], host.get("ports", [])
                    )
                except Exception:
                    host["protocol_findings"] = []
                prog.advance(task)

        proto_hits = sum(len(h.get("protocol_findings", [])) for h in results)
        if proto_hits:
            console.print(
                f"  [bold yellow]\\[!][/bold yellow]  [bold yellow]{proto_hits}[/bold yellow] "
                f"protocol vulnerability finding(s) detected\n"
            )
        else:
            console.print(
                "  [bright_blue]\\[+][/bright_blue]  Protocol checks complete"
                " — no misconfigurations detected\n"
            )

    # ── Display results ────────────────────────────────────────────────────────
    console.print(Rule("  Results  ", style="bright_cyan"))
    console.print()

    for host in results:
        if host.get("ports"):
            display_host(host)

    display_summary(results)

    # ── Export ─────────────────────────────────────────────────────────────────
    # Restore canonical terminal mode so backspace works in the export prompt.
    # Progress/Live may leave ECHOE unset, causing backspace to echo as ^H.
    if _HAS_TERMIOS:
        try:
            fd = sys.stdin.fileno()
            attrs = _termios.tcgetattr(fd)
            attrs[3] |= _termios.ECHO | _termios.ICANON | _termios.ECHOE
            _termios.tcsetattr(fd, _termios.TCSADRAIN, attrs)
        except Exception:
            try:
                import subprocess as _sp
                _sp.run(["stty", "sane"], stdin=sys.stdin, check=False, capture_output=True)
            except Exception:
                pass
    _export_map = {"html": "1", "pdf": "2", "json": "3", "csv": "4", "all": "5"}
    if args.export:
        choice = _export_map[args.export]
    else:
        choice = export_menu()

    if not choice:
        console.print("  [dim]Report generation skipped.[/dim]\n")
        return

    console.print()
    if choice in {"1", "5"}:
        out = os.path.join(output_dir, f"snekmap_report_{file_ts}.html")
        try:
            generate_html_report(results, out, metadata=meta)
            console.print(f"  [bright_blue]\\[+][/bright_blue]  HTML → [bold]{out}[/bold]")
        except Exception as e:
            console.print(f"  [red]\\[-][/red]  HTML failed: {e}")

    if choice in {"2", "5"}:
        out = os.path.join(output_dir, f"snekmap_report_{file_ts}.pdf")
        try:
            generate_pdf_report(results, out, metadata=meta)
            console.print(f"  [bright_blue]\\[+][/bright_blue]  PDF  → [bold]{out}[/bold]")
        except Exception as e:
            console.print(f"  [red]\\[-][/red]  PDF failed: {e}")

    if choice in {"3", "5"}:
        out = os.path.join(output_dir, f"snekmap_report_{file_ts}.json")
        try:
            _api_degraded = cve_lookup._nvd_warn_shown
            for h in results:
                for p in h.get("ports", []):
                    p["cve_lookup_status"] = "degraded" if _api_degraded else "complete"

            all_cves_j = [c for h in results for p in h.get("ports", []) for c in p.get("cves", [])]
            sev_counts_j: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for _cve in all_cves_j:
                _sev = _cve.get("severity", "N/A").lower()
                if _sev in sev_counts_j:
                    sev_counts_j[_sev] += 1

            payload = {
                "metadata": {
                    "target":    args.target,
                    "mode":      scan_mode,
                    "version":   __version__,
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                },
                "scanner": {
                    "name":         "SnekMap",
                    "version":      __version__,
                    "cve_database": "NIST NVD v2.0",
                    "api_degraded": _api_degraded,
                },
                "summary": {
                    "hosts_scanned":       len(results),
                    "hosts_with_findings": len([h for h in results
                                                if any(p.get("cves") for p in h.get("ports", []))]),
                    "total_ports":         sum(len(h.get("ports", [])) for h in results),
                    "total_cves":          len(all_cves_j),
                    "severity_breakdown":  sev_counts_j,
                },
                "context": {
                    "note": (
                        "No CVEs found. This may indicate: (1) target runs patched/hardened software, "
                        "(2) services hide version info (CDN, WAF, internal network), "
                        "(3) CVE lookup was degraded due to API issues (see scanner.api_degraded)."
                    ),
                },
                "results": results,
            }
            with open(out, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            console.print(f"  [bright_blue]\\[+][/bright_blue]  JSON → [bold]{out}[/bold]")
        except Exception as e:
            console.print(f"  [red]\\[-][/red]  JSON failed: {e}")

    if choice in {"4", "5"}:
        out = os.path.join(output_dir, f"snekmap_report_{file_ts}.csv")
        try:
            _api_degraded = cve_lookup._nvd_warn_shown
            with open(out, "w", newline="", encoding="utf-8") as f:
                f.write("# SnekMap Security Assessment Report\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Target: {args.target}\n")
                f.write(f"# Scan Mode: {scan_mode}\n")
                f.write(f"# API Degraded: {'true' if _api_degraded else 'false'}\n")
                f.write("#\n")
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                writer.writerow([
                    "host_ip", "hostname", "os",
                    "port", "protocol", "service", "product", "version",
                    "cve_id", "severity", "cvss_score", "description",
                ])
                for host in results:
                    for port in host.get("ports", []):
                        cves = port.get("cves", [])
                        if cves:
                            for cve in cves:
                                writer.writerow([
                                    host["ip"], host.get("hostname", ""), host.get("os", ""),
                                    port["port"], port.get("protocol", "tcp"),
                                    port.get("service", ""), port.get("product", ""), port.get("version", ""),
                                    cve.get("id", ""), cve.get("severity", ""),
                                    cve.get("cvss_score", ""), cve.get("description", ""),
                                ])
                        else:
                            writer.writerow([
                                host["ip"], host.get("hostname", ""), host.get("os", ""),
                                port["port"], port.get("protocol", "tcp"),
                                port.get("service", ""), port.get("product", ""), port.get("version", ""),
                                "", "", "", "",
                            ])
            console.print(f"  [bright_blue]\\[+][/bright_blue]  CSV  → [bold]{out}[/bold]")
        except Exception as e:
            console.print(f"  [red]\\[-][/red]  CSV failed: {e}")

    console.print()


if __name__ == "__main__":
    main()
