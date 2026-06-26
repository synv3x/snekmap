from datetime import datetime

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "N/A": 0}

_SEV_CLASS = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "N/A":      "na",
}


def _worst_sev(cves: list) -> str:
    if not cves:
        return "N/A"
    return max(cves, key=lambda c: _SEV_RANK.get(c.get("severity", "N/A"), 0)).get("severity", "N/A")


def _cve_badge(count: int, worst: str) -> str:
    if not count:
        return '<span class="no-cve">—</span>'
    cls   = _SEV_CLASS.get(worst, "na")
    label = f"{count} CVE{'s' if count != 1 else ''}"
    return f'<span class="cve-badge {cls}">{label}</span>'


def _cve_card(cve: dict) -> str:
    sev   = cve.get("severity", "N/A")
    cls   = _SEV_CLASS.get(sev, "na")
    score = cve.get("cvss_score")
    score_str = f"CVSS&nbsp;{score:.1f}" if score is not None else "CVSS&nbsp;—"
    desc  = (cve.get("description") or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    cve_id = cve.get("id", "?")
    return f"""
                <div class="cve-entry {cls}">
                    <div class="cve-entry-header">
                        <span class="cve-id">{cve_id}</span>
                        <span class="sev-label {cls}">{sev}</span>
                        <span class="cvss-score">{score_str}</span>
                    </div>
                    <div class="cve-desc">{desc}</div>
                </div>"""


def generate_html_report(results: list, output_file: str = "report.html", metadata: dict = None) -> None:
    if metadata is None:
        metadata = {}

    now        = datetime.now()
    timestamp  = now.strftime("%Y-%m-%d %H:%M:%S")
    target     = metadata.get("target", "—")
    scan_mode  = metadata.get("mode", "standard").capitalize()
    version    = metadata.get("version", "0.1.0")

    # Aggregate
    live_hosts  = [h for h in results if h.get("ports")]
    total_ports = sum(len(h.get("ports", [])) for h in results)
    all_cves    = [c for h in results for p in h.get("ports", []) for c in p.get("cves", [])]
    total_cves  = len(all_cves)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
    for c in all_cves:
        sev_counts[c.get("severity", "N/A")] = sev_counts.get(c.get("severity", "N/A"), 0) + 1

    def pct(sev: str) -> float:
        return round(sev_counts.get(sev, 0) / total_cves * 100, 1) if total_cves else 0

    # Severity summary cards
    sev_card_html = ""
    for sev, label in [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]:
        cls = sev.lower()
        sev_card_html += f"""
        <div class="sev-card {cls}">
            <div class="sev-label-text">{label}</div>
            <div class="sev-count">{sev_counts.get(sev, 0)}</div>
        </div>"""

    # Risk distribution bar
    risk_bar = f"""
    <div class="risk-bar">
        <div class="seg seg-critical" style="width:{pct('CRITICAL')}%" title="Critical {pct('CRITICAL')}%"></div>
        <div class="seg seg-high"     style="width:{pct('HIGH')}%"     title="High {pct('HIGH')}%"></div>
        <div class="seg seg-medium"   style="width:{pct('MEDIUM')}%"   title="Medium {pct('MEDIUM')}%"></div>
        <div class="seg seg-low"      style="width:{pct('LOW')}%"      title="Low {pct('LOW')}%"></div>
    </div>
    <div class="risk-bar-legend">
        <span class="rbl-item critical">&#9632; Critical {sev_counts.get('CRITICAL',0)}</span>
        <span class="rbl-item high">&#9632; High {sev_counts.get('HIGH',0)}</span>
        <span class="rbl-item medium">&#9632; Medium {sev_counts.get('MEDIUM',0)}</span>
        <span class="rbl-item low">&#9632; Low {sev_counts.get('LOW',0)}</span>
    </div>"""

    # Per-host sections
    host_sections = ""
    for host in results:
        ports = host.get("ports", [])
        if not ports:
            continue

        ip       = host["ip"]
        hostname = host.get("hostname", "")
        os_name  = host.get("os", "Unknown")
        os_acc   = host.get("os_accuracy", 0)

        host_cves      = [c for p in ports for c in p.get("cves", [])]
        host_cve_count = len(host_cves)
        os_label       = f"{os_name} ({os_acc}% confidence)" if os_acc else os_name
        hostname_html  = f'<div class="host-hostname">{hostname}</div>' if hostname else ""
        cve_badge_html = (
            f'<span class="host-badge badge-cves">{host_cve_count} CVE{"s" if host_cve_count != 1 else ""}</span>'
            if host_cve_count else ""
        )
        cdn            = host.get("cdn", "")
        cdn_badge_html = f'<span class="host-badge badge-cdn">CDN: {cdn}</span>' if cdn else ""

        # Port table rows
        port_rows = ""
        for port in ports:
            ver = " ".join(filter(None, [
                port.get("product", ""),
                port.get("version", ""),
                port.get("extrainfo", ""),
            ])).strip() or "—"

            cves      = port.get("cves", [])
            worst     = _worst_sev(cves)
            port_rows += f"""
                <tr>
                    <td class="col-port">{port["port"]}/{port.get("protocol", "tcp")}</td>
                    <td class="col-state">{port.get("state", "")}</td>
                    <td class="col-service">{port.get("service", "—")}</td>
                    <td class="col-version">{ver}</td>
                    <td>{_cve_badge(len(cves), worst)}</td>
                </tr>"""

        # Critical findings section (shown before CVE details)
        critical_section = ""
        critical_ports = [p for p in ports if p.get("critical_finding")]
        if critical_ports:
            items = "".join(
                f'<li><strong>Port {p["port"]}:</strong> {p["critical_finding"]}</li>'
                for p in critical_ports
            )
            critical_section = f"""
            <div class="critical-section">
                <div class="critical-section-title">&#9888; Critical Findings</div>
                <ul class="critical-list">{items}</ul>
            </div>"""

        # CVE detail groups per port
        cve_groups = ""
        for port in ports:
            cves = port.get("cves", [])
            if not cves:
                continue
            ver_label  = " ".join(filter(None, [port.get("product", ""), port.get("version", "")])).strip()
            port_label = f"Port {port['port']}/{port.get('service', '?')}"
            if ver_label:
                port_label += f" &mdash; {ver_label}"
            cards = "".join(_cve_card(c) for c in cves)
            cve_groups += f"""
            <div class="cve-port-group">
                <div class="cve-port-label">{port_label}</div>
                {cards}
            </div>"""

        cve_section = ""
        if cve_groups:
            cve_section = f"""
            <div class="cve-section">
                <div class="cve-section-title">&#9888; CVE Findings</div>
                {cve_groups}
            </div>"""

        host_sections += f"""
        <div class="host-card">
            <div class="host-card-header">
                <div>
                    <div class="host-ip">{ip}</div>
                    {hostname_html}
                </div>
                <div class="host-badges">
                    <span class="host-badge badge-os">OS: {os_label}</span>
                    {cdn_badge_html}
                    <span class="host-badge badge-ports">{len(ports)} port{"s" if len(ports) != 1 else ""} open</span>
                    {cve_badge_html}
                </div>
            </div>
            <table class="port-table">
                <thead>
                    <tr>
                        <th>Port</th><th>State</th><th>Service</th>
                        <th>Version / Product</th><th>CVEs</th>
                    </tr>
                </thead>
                <tbody>{port_rows}</tbody>
            </table>
            {critical_section}
            {cve_section}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SnekMap Security Report &mdash; {timestamp}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',Courier,monospace;background:#090912;color:#cdd6f4;line-height:1.6;font-size:14px}}
a{{color:inherit;text-decoration:none}}
.container{{max-width:1140px;margin:0 auto;padding:40px 24px}}

/* Header */
.report-header{{border-bottom:2px solid #2563EB;padding-bottom:24px;margin-bottom:40px}}
.report-title{{font-size:1.55em;color:#2563EB;margin-bottom:4px;letter-spacing:.02em}}
.report-subtitle{{color:#6c7086;font-size:.85em;margin-bottom:14px}}
.report-meta{{display:flex;gap:28px;flex-wrap:wrap;color:#6c7086;font-size:.8em;margin-top:12px;border-top:1px solid #1e1e2e;padding-top:14px}}
.report-meta span{{display:flex;gap:6px;align-items:center}}
.report-meta strong{{color:#a6adc8}}

/* Section */
.section{{margin-bottom:48px}}
.section-title{{color:#585b70;font-size:.73em;text-transform:uppercase;letter-spacing:.14em;border-bottom:1px solid #1e1e2e;padding-bottom:8px;margin-bottom:22px}}

/* Summary stat cards */
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:26px}}
.summary-card{{background:#11111b;border:1px solid #1e1e2e;border-radius:7px;padding:18px 20px}}
.summary-card .lbl{{font-size:.71em;text-transform:uppercase;letter-spacing:.1em;color:#6c7086}}
.summary-card .val{{font-size:2.1em;font-weight:bold;margin-top:5px}}
.s-hosts .val{{color:#89b4fa}}
.s-ports .val{{color:#89dceb}}
.s-cves  .val{{color:#f38ba8}}

/* Severity cards */
.severity-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:22px}}
.sev-card{{border-radius:6px;padding:14px 18px;border-left:3px solid}}
.sev-card .sev-label-text{{font-size:.71em;text-transform:uppercase;letter-spacing:.1em}}
.sev-card .sev-count{{font-size:1.9em;font-weight:bold;margin-top:3px}}
.sev-card.critical{{background:#1a0a0a;border-color:#ff1744}}
.sev-card.critical .sev-label-text{{color:#ff5572}}
.sev-card.critical .sev-count{{color:#ff1744}}
.sev-card.high{{background:#1a0f00;border-color:#ff6d00}}
.sev-card.high .sev-label-text{{color:#ff9a40}}
.sev-card.high .sev-count{{color:#ff6d00}}
.sev-card.medium{{background:#1a1600;border-color:#ffd600}}
.sev-card.medium .sev-label-text{{color:#ffe166}}
.sev-card.medium .sev-count{{color:#ffd600}}
.sev-card.low{{background:#001a09;border-color:#00e676}}
.sev-card.low .sev-label-text{{color:#69ff99}}
.sev-card.low .sev-count{{color:#00e676}}

/* Risk bar */
.risk-bar{{height:11px;border-radius:6px;overflow:hidden;display:flex;background:#1e1e2e;margin-bottom:10px}}
.seg{{height:100%;min-width:2px;transition:width .3s}}
.seg-critical{{background:#ff1744}}
.seg-high{{background:#ff6d00}}
.seg-medium{{background:#ffd600}}
.seg-low{{background:#00e676}}
.risk-bar-legend{{display:flex;gap:18px;flex-wrap:wrap;font-size:.76em}}
.rbl-item{{opacity:.7}}
.rbl-item.critical{{color:#ff1744}}
.rbl-item.high{{color:#ff6d00}}
.rbl-item.medium{{color:#ffd600}}
.rbl-item.low{{color:#00e676}}

/* Host cards */
.host-card{{background:#11111b;border:1px solid #1e1e2e;border-radius:8px;margin-bottom:26px;overflow:hidden}}
.host-card-header{{background:#161622;border-bottom:1px solid #1e1e2e;padding:14px 20px;display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px}}
.host-ip{{font-size:1.08em;font-weight:bold;color:#89b4fa}}
.host-hostname{{color:#6c7086;font-size:.84em;margin-top:3px}}
.host-badges{{display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
.host-badge{{font-size:.74em;padding:3px 10px;border-radius:4px;border:1px solid;white-space:nowrap}}
.badge-os{{color:#89dceb;border-color:#89dceb33;background:#89dceb0d}}
.badge-ports{{color:#a6adc8;border-color:#313244;background:#1e1e2e}}
.badge-cves{{color:#f38ba8;border-color:#f38ba833;background:#f38ba80d}}
.badge-cdn{{color:#f9e2af;border-color:#f9e2af33;background:#f9e2af0d}}

/* Port table */
.port-table{{width:100%;border-collapse:collapse;font-size:.86em}}
.port-table th{{background:#161622;color:#585b70;font-size:.71em;text-transform:uppercase;letter-spacing:.1em;padding:9px 18px;text-align:left;font-weight:normal;border-bottom:1px solid #1e1e2e}}
.port-table td{{padding:9px 18px;border-bottom:1px solid #161622}}
.port-table tr:last-child td{{border-bottom:none}}
.port-table tbody tr:hover td{{background:#161622}}
.col-port{{color:#89dceb;font-weight:bold;white-space:nowrap}}
.col-state{{color:#a6e3a1}}
.col-service{{color:#cdd6f4}}
.col-version{{color:#6c7086}}
.cve-badge{{display:inline-block;font-size:.76em;padding:2px 9px;border-radius:4px;font-weight:bold}}
.cve-badge.critical{{background:#1a0a0a;color:#ff1744;border:1px solid #ff174430}}
.cve-badge.high{{background:#1a0f00;color:#ff6d00;border:1px solid #ff6d0030}}
.cve-badge.medium{{background:#1a1600;color:#ffd600;border:1px solid #ffd60030}}
.cve-badge.low{{background:#001a09;color:#00e676;border:1px solid #00e67630}}
.cve-badge.na{{background:#111;color:#666;border:1px solid #33333330}}
.no-cve{{color:#313244}}

/* CVE section */
.critical-section{{padding:18px 20px;border-top:1px solid #2d0a0a;background:#1a0505}}
.critical-section-title{{color:#fc8181;font-size:.74em;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px;font-weight:bold}}
.critical-list{{list-style:none;padding:0;margin:0}}
.critical-list li{{padding:6px 0;color:#fed7d7;font-size:.85em;border-bottom:1px solid #2d0a0a}}
.critical-list li:last-child{{border-bottom:none}}
.critical-list li strong{{color:#fc8181}}
.cve-section{{padding:18px 20px;border-top:1px solid #1e1e2e}}
.cve-section-title{{color:#fab387;font-size:.74em;text-transform:uppercase;letter-spacing:.1em;margin-bottom:16px;font-weight:bold}}
.cve-port-group{{margin-bottom:22px}}
.cve-port-group:last-child{{margin-bottom:0}}
.cve-port-label{{color:#585b70;font-size:.81em;padding-bottom:8px;margin-bottom:10px;border-bottom:1px solid #1e1e2e}}
.cve-entry{{border-radius:5px;padding:13px 16px;margin-bottom:8px;border-left:3px solid}}
.cve-entry:last-child{{margin-bottom:0}}
.cve-entry.critical{{background:#1a0a0a;border-color:#ff1744}}
.cve-entry.high{{background:#1a0f00;border-color:#ff6d00}}
.cve-entry.medium{{background:#1a1600;border-color:#ffd600}}
.cve-entry.low{{background:#001a09;border-color:#00e676}}
.cve-entry.na{{background:#111;border-color:#555}}
.cve-entry-header{{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:7px}}
.cve-id{{font-weight:bold;color:#cdd6f4;font-size:.91em}}
.sev-label{{font-size:.73em;font-weight:bold;text-transform:uppercase;letter-spacing:.08em}}
.sev-label.critical{{color:#ff1744}}
.sev-label.high{{color:#ff6d00}}
.sev-label.medium{{color:#ffd600}}
.sev-label.low{{color:#00e676}}
.sev-label.na{{color:#666}}
.cvss-score{{font-size:.76em;color:#6c7086;font-weight:bold}}
.cve-desc{{color:#7f849c;font-size:.84em;line-height:1.65}}

/* Footer */
.report-footer{{border-top:1px solid #1e1e2e;margin-top:52px;padding-top:22px;color:#313244;font-size:.76em;text-align:center;line-height:2}}

@media print{{
    body{{background:#fff;color:#111}}
    .report-header{{border-color:#333}}
    .report-title{{color:#1D4ED8}}
    .host-card{{border:1px solid #ddd;break-inside:avoid;margin-bottom:16px}}
    .host-card-header,.port-table th{{background:#f5f5f5}}
    .cve-entry{{border-left-width:3px}}
}}
</style>
</head>
<body>
<div class="container">

<div class="report-header">
    <div class="report-title">SECURITY ASSESSMENT REPORT</div>
    <div class="report-subtitle">Network Vulnerability Scan &mdash; Generated {timestamp}</div>
    <div class="report-meta">
        <span><strong>Generated:</strong>&nbsp;{timestamp}</span>
        <span><strong>Target:</strong>&nbsp;{target}</span>
        <span><strong>Scan Mode:</strong>&nbsp;{scan_mode}</span>
        <span><strong>SnekMap</strong>&nbsp;v{version}</span>
    </div>
</div>

<div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
        <div class="summary-card s-hosts">
            <div class="lbl">Hosts Scanned</div>
            <div class="val">{len(live_hosts)}</div>
        </div>
        <div class="summary-card s-ports">
            <div class="lbl">Open Ports</div>
            <div class="val">{total_ports}</div>
        </div>
        <div class="summary-card s-cves">
            <div class="lbl">CVEs Found</div>
            <div class="val">{total_cves}</div>
        </div>
    </div>
    <div class="severity-grid">{sev_card_html}</div>
    {risk_bar}
</div>

<div class="section">
    <div class="section-title">Findings by Host</div>
    {host_sections or '<p style="color:#585b70;padding:16px 0">No hosts with open ports found.</p>'}
</div>

<div class="report-footer">
    SnekMap v{version} &nbsp;&middot;&nbsp; Report generated {timestamp}
</div>

</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)


def generate_pdf_report(results: list, output_file: str = "report.pdf", metadata: dict = None) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.colors import HexColor, white
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Table, TableStyle,
            Spacer, HRFlowable, KeepTogether,
        )
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        raise ImportError("reportlab is required: pip install reportlab")

    if metadata is None:
        metadata = {}

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target    = metadata.get("target", "—")
    scan_mode = metadata.get("mode", "standard").capitalize()
    version   = metadata.get("version", "0.1.0")

    W, H   = A4
    MARGIN = 18 * mm

    def C(h: str) -> HexColor:
        return HexColor(h)

    # Palette
    BG_DARK  = C("#0F172A")
    BLUE     = C("#2563EB")
    TXT_DARK = C("#1E293B")
    TXT_MID  = C("#475569")
    TXT_DIM  = C("#94A3B8")
    LINE     = C("#E2E8F0")
    ROW_ALT  = C("#F8FAFC")

    SEV_BG = {
        "CRITICAL": C("#FFF5F5"), "HIGH": C("#FFFAF0"),
        "MEDIUM":   C("#FFFFF0"), "LOW":  C("#F0FFF4"), "N/A": C("#F7FAFC"),
    }
    SEV_FG = {
        "CRITICAL": C("#C53030"), "HIGH": C("#C05621"),
        "MEDIUM":   C("#B7791F"), "LOW":  C("#276749"), "N/A": C("#718096"),
    }

    # Running header drawn on pages 2+; clean footer on every page.
    def _page(canvas, doc):
        canvas.saveState()
        if doc.page > 1:
            # Dark header strip with tool name + page number (page 1 uses the story title).
            canvas.setFillColor(BG_DARK)
            canvas.rect(MARGIN, H - 36, W - 2 * MARGIN, 36, fill=1, stroke=0)
            canvas.setFillColor(BLUE)
            canvas.setFont("Helvetica-Bold", 10)
            canvas.drawString(MARGIN, H - 23, "SnekMap  —  Security Assessment Report")
            canvas.setFillColor(TXT_DIM)
            canvas.setFont("Helvetica", 8)
            canvas.drawRightString(W - MARGIN, H - 23, f"Page {doc.page}")
        # Thin footer rule + credit line on every page.
        canvas.setFillColor(LINE)
        canvas.rect(MARGIN, 20, W - 2 * MARGIN, 0.5, fill=1, stroke=0)
        canvas.setFillColor(TXT_DIM)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawCentredString(W / 2, 10,
            "SnekMap by synv3x  ·  github.com/synv3x/snekmap")
        canvas.restoreState()

    # Paragraph style helper
    def ps(name: str, **kw) -> ParagraphStyle:
        base = {"fontName": "Helvetica", "fontSize": 9, "textColor": TXT_DARK, "leading": 13}
        base.update(kw)
        return ParagraphStyle(name, **base)

    S = {
        "h1":    ps("h1",  fontName="Helvetica-Bold", fontSize=16, spaceBefore=6, spaceAfter=4),
        "h2":    ps("h2",  fontName="Helvetica-Bold", fontSize=11, spaceBefore=10, spaceAfter=5),
        "label": ps("lbl", fontName="Helvetica-Bold", fontSize=7,  textColor=TXT_DIM,
                    spaceBefore=6, spaceAfter=4, leading=10),
        "meta":  ps("met", fontSize=8.5, textColor=TXT_DIM, leading=12),
        "body":  ps("bod", fontSize=9,   textColor=TXT_MID, leading=13),
    }

    # Aggregate stats
    live_hosts  = [h for h in results if h.get("ports")]
    total_ports = sum(len(h.get("ports", [])) for h in results)
    all_cves    = [c for h in results for p in h.get("ports", []) for c in p.get("cves", [])]
    total_cves  = len(all_cves)
    sev_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
    for c in all_cves:
        sev_counts[c.get("severity", "N/A")] = sev_counts.get(c.get("severity", "N/A"), 0) + 1

    story = []

    # ── Title block ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("SECURITY ASSESSMENT REPORT", S["h1"]))
    story.append(Paragraph(f"Network Vulnerability Scan  ·  SnekMap v{version}", S["meta"]))
    story.append(Spacer(1, 3 * mm))

    # Two-column metadata block aligned to the same grid as the stat boxes below.
    # Label col is fixed; value col fills remaining space.
    _lbl_w  = 28 * mm
    _val_w  = (W - 2 * MARGIN - 2 * _lbl_w) / 2
    meta_rows = [
        ["Generated", timestamp,  "Target",  target],
        ["Scan Mode", scan_mode,  "Version", f"SnekMap v{version}"],
    ]
    meta_tbl = Table(meta_rows, colWidths=[_lbl_w, _val_w, _lbl_w, _val_w])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",     (0, 0), (0, -1),  TXT_DIM),
        ("TEXTCOLOR",     (2, 0), (2, -1),  TXT_DIM),
        ("TEXTCOLOR",     (1, 0), (1, -1),  TXT_DARK),
        ("TEXTCOLOR",     (3, 0), (3, -1),  TXT_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_tbl)
    story.append(HRFlowable(width="100%", thickness=1, color=LINE, spaceBefore=5*mm, spaceAfter=5*mm))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", S["label"]))

    col3 = (W - 2 * MARGIN) / 3

    # Stat cards
    _lbl_c = lambda name: ps(name, fontName="Helvetica-Bold", fontSize=7, textColor=TXT_DIM,
                              spaceBefore=6, spaceAfter=4, leading=10, alignment=TA_CENTER)
    stat_data = [
        [Paragraph("HOSTS",      _lbl_c("lbl_hosts")),
         Paragraph("OPEN PORTS", _lbl_c("lbl_ports")),
         Paragraph("CVEs FOUND", _lbl_c("lbl_cves"))],
        [Paragraph(str(len(live_hosts)), ps("sv1", fontName="Helvetica-Bold", fontSize=22, textColor=C("#2563EB"), leading=26, alignment=TA_CENTER)),
         Paragraph(str(total_ports),     ps("sv2", fontName="Helvetica-Bold", fontSize=22, textColor=C("#0891B2"), leading=26, alignment=TA_CENTER)),
         Paragraph(str(total_cves),      ps("sv3", fontName="Helvetica-Bold", fontSize=22, textColor=C("#DC2626"), leading=26, alignment=TA_CENTER))],
    ]
    stat_tbl = Table(stat_data, colWidths=[col3, col3, col3])
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), C("#EFF6FF")),
        ("BACKGROUND",    (1, 0), (1, -1), C("#ECFEFF")),
        ("BACKGROUND",    (2, 0), (2, -1), C("#FEF2F2")),
        ("BOX",           (0, 0), (-1, -1), 0.5, LINE),
        ("LINEAFTER",     (0, 0), (1, -1),  0.5, LINE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 3 * mm))

    # Severity cards
    col4 = (W - 2 * MARGIN) / 4
    _sev_lbl_c = lambda name: ps(name, fontName="Helvetica-Bold", fontSize=7, textColor=TXT_DIM,
                                  spaceBefore=6, spaceAfter=4, leading=10, alignment=TA_CENTER)
    sev_data = [
        [Paragraph(s, _sev_lbl_c(f"lbl_{s.lower()}")) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")],
        [Paragraph(str(sev_counts[s]),
                   ps(f"scv_{s.lower()}", fontName="Helvetica-Bold", fontSize=20,
                      textColor=SEV_FG[s], leading=24, alignment=TA_CENTER))
         for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")],
    ]
    sev_tbl = Table(sev_data, colWidths=[col4, col4, col4, col4])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), SEV_BG["CRITICAL"]),
        ("BACKGROUND",    (1, 0), (1, -1), SEV_BG["HIGH"]),
        ("BACKGROUND",    (2, 0), (2, -1), SEV_BG["MEDIUM"]),
        ("BACKGROUND",    (3, 0), (3, -1), SEV_BG["LOW"]),
        ("BOX",           (0, 0), (-1, -1), 0.5, LINE),
        ("LINEAFTER",     (0, 0), (2, -1),  0.5, LINE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    story.append(sev_tbl)
    story.append(HRFlowable(width="100%", thickness=1, color=LINE, spaceBefore=6*mm, spaceAfter=3*mm))

    # ── Findings by Host ──────────────────────────────────────────────────────
    story.append(Paragraph("FINDINGS BY HOST", S["label"]))

    PORT_WIDTHS = [(W - 2 * MARGIN) * x for x in (0.11, 0.08, 0.10, 0.14, 0.42, 0.15)]
    CVE_WIDTHS  = [(W - 2 * MARGIN) * x for x in (0.19, 0.11, 0.08, 0.62)]

    PORT_HDR_STYLE = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C("#1E293B")),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  TXT_DIM),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  7),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, ROW_ALT]),
        ("GRID",          (0, 0), (-1, -1), 0.3, LINE),
        ("TEXTCOLOR",     (0, 1), (0, -1),  C("#0369A1")),
        ("FONTNAME",      (0, 1), (0, -1),  "Courier-Bold"),
    ])

    CVE_HDR_STYLE = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C("#F1F5F9")),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  TXT_DIM),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  7),
        ("FONTSIZE",      (0, 1), (-1, -1), 7.5),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("GRID",          (0, 0), (-1, -1), 0.3, LINE),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])

    for host in results:
        ports = host.get("ports", [])
        if not ports:
            continue

        ip         = host["ip"]
        hostname   = host.get("hostname", "")
        os_name    = host.get("os", "Unknown")
        os_acc     = host.get("os_accuracy", 0)
        host_label = f"{ip}  ({hostname})" if hostname else ip
        os_label   = f"{os_name}  [{os_acc}% confidence]" if os_acc else os_name
        host_cves  = [c for p in ports for c in p.get("cves", [])]

        # Host header + port table kept together if possible
        cdn      = host.get("cdn", "")
        cdn_note = f"  &nbsp;&nbsp;·&nbsp;&nbsp;  CDN: {cdn}" if cdn else ""
        header_block = [
            Paragraph(host_label,
                      ps("hip", fontName="Helvetica-Bold", fontSize=12,
                         textColor=C("#1D4ED8"), spaceBefore=6, spaceAfter=2)),
            Paragraph(
                f"OS: {os_label}  &nbsp;&nbsp;·&nbsp;&nbsp;  "
                f"{len(ports)} port(s) open  &nbsp;&nbsp;·&nbsp;&nbsp;  {len(host_cves)} CVE(s){cdn_note}",
                S["meta"],
            ),
            Spacer(1, 2 * mm),
        ]

        # Port table
        port_rows = [["PORT", "PROTO", "STATE", "SERVICE", "VERSION / PRODUCT", "CVEs"]]
        for port in ports:
            ver = " ".join(filter(None, [
                port.get("product", ""), port.get("version", ""), port.get("extrainfo", ""),
            ])).strip() or "—"
            cves      = port.get("cves", [])
            worst_sev = (max(cves, key=lambda c: _SEV_RANK.get(c.get("severity", "N/A"), 0))
                         .get("severity", "N/A")) if cves else "N/A"
            port_rows.append([
                f"{port['port']}/{port.get('protocol','tcp')}",
                port.get("protocol", "tcp").upper(),
                port.get("state", ""),
                port.get("service", "—"),
                ver,
                f"{len(cves)} ({worst_sev})" if cves else "—",
            ])

        port_tbl = Table(port_rows, colWidths=PORT_WIDTHS, repeatRows=1)
        pstyle   = TableStyle(PORT_HDR_STYLE.getCommands())
        for i, port in enumerate(ports, start=1):
            cves = port.get("cves", [])
            if cves:
                ws = (max(cves, key=lambda c: _SEV_RANK.get(c.get("severity", "N/A"), 0))
                      .get("severity", "N/A"))
                pstyle.add("TEXTCOLOR", (5, i), (5, i), SEV_FG.get(ws, TXT_MID))
                pstyle.add("FONTNAME",  (5, i), (5, i), "Helvetica-Bold")
        port_tbl.setStyle(pstyle)
        header_block.append(port_tbl)

        story.append(KeepTogether(header_block))

        # CVE detail tables (flow freely across pages)
        ports_with_cves = [p for p in ports if p.get("cves")]
        if ports_with_cves:
            story.append(Paragraph("CVE FINDINGS", S["label"]))

            for port in ports_with_cves:
                cves      = port["cves"]
                ver_label = " ".join(filter(None, [port.get("product", ""), port.get("version", "")])).strip()
                plabel    = f"Port {port['port']}/{port.get('service', '?')}"
                if ver_label:
                    plabel += f"  ·  {ver_label}"

                story.append(Paragraph(
                    plabel,
                    ps("pl", fontName="Helvetica-Bold", fontSize=8.5,
                       textColor=TXT_MID, spaceBefore=4, spaceAfter=3),
                ))

                cve_rows = [["CVE ID", "SEVERITY", "CVSS", "DESCRIPTION"]]
                for cve in cves:
                    sev       = cve.get("severity", "N/A")
                    score     = cve.get("cvss_score")
                    score_str = f"{score:.1f}" if score is not None else "—"
                    desc      = (cve.get("description") or "")
                    if len(desc) > 320:
                        desc = desc[:317] + "..."
                    cve_rows.append([
                        Paragraph(cve.get("id", "?"),
                                  ps("ci", fontName="Courier-Bold", fontSize=7.5, textColor=TXT_DARK)),
                        Paragraph(sev,
                                  ps("sv2", fontName="Helvetica-Bold", fontSize=7.5,
                                     textColor=SEV_FG.get(sev, TXT_MID))),
                        Paragraph(score_str,
                                  ps("sc2", fontName="Helvetica-Bold", fontSize=7.5, textColor=TXT_MID)),
                        Paragraph(desc,
                                  ps("de2", fontSize=7.5, textColor=TXT_MID, leading=10)),
                    ])

                cve_tbl   = Table(cve_rows, colWidths=CVE_WIDTHS, repeatRows=1)
                cve_style = TableStyle(CVE_HDR_STYLE.getCommands())
                for i, cve in enumerate(cves, start=1):
                    sev = cve.get("severity", "N/A")
                    cve_style.add("BACKGROUND", (0, i), (-1, i), SEV_BG.get(sev, white))
                cve_tbl.setStyle(cve_style)
                story.append(cve_tbl)
                story.append(Spacer(1, 3 * mm))

        story.append(HRFlowable(width="100%", thickness=0.5, color=LINE,
                                spaceBefore=4*mm, spaceAfter=4*mm))

    doc = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN + 18,
        bottomMargin=MARGIN,
        title="SnekMap Security Report",
        author="SnekMap",
    )
    doc.build(story, onFirstPage=_page, onLaterPages=_page)
