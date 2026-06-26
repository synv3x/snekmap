"""Correlate findings across OS, services, and ports."""


def correlate_os_services(host: dict) -> list:
    """Find unusual OS-service combinations."""
    findings = []
    os_name  = host.get("os", "Unknown").lower()
    services = {p.get("service", "").lower() for p in host.get("ports", [])}
    ports    = {p["port"] for p in host.get("ports", [])}

    if ("linux" in os_name or "unix" in os_name) and ("smb" in services or "cifs" in services or 445 in ports):
        findings.append({
            "type":          "UNUSUAL",
            "severity":      "MEDIUM",
            "finding":       "Linux system running SMB (normally Windows-only)",
            "investigation": "Verify if intentional (Samba) or misconfigured",
            "risk":          "May indicate container escape or unusual configuration",
        })

    if ("linux" in os_name or "unix" in os_name) and ("rdp" in services or 3389 in ports):
        findings.append({
            "type":          "UNUSUAL",
            "severity":      "MEDIUM",
            "finding":       "Linux running RDP (Windows remote desktop protocol)",
            "investigation": "Check if xrdp or similar is installed",
            "risk":          "Unusual configuration — verify legitimacy",
        })

    return findings


def correlate_service_patterns(host: dict) -> list:
    """Find dangerous service combinations."""
    findings = []
    services = {p.get("service", "").lower() for p in host.get("ports", [])}

    if "ftp" in services and "ssh" in services:
        findings.append({
            "type":           "PATTERN",
            "severity":       "MEDIUM",
            "finding":        "Both FTP and SSH available (redundant protocols)",
            "recommendation": "Disable FTP — use SFTP/SCP over SSH instead",
            "risk":           "FTP is unencrypted; SSH is the secure equivalent",
        })

    if "http" in services and "https" in services:
        findings.append({
            "type":           "PATTERN",
            "severity":       "LOW",
            "finding":        "Both HTTP and HTTPS available",
            "recommendation": "Redirect HTTP → HTTPS and disable plain HTTP",
            "risk":           "Plain HTTP allows MITM attacks",
        })

    databases = {"mysql", "postgresql", "mongodb", "redis"} & services
    if len(databases) > 1:
        findings.append({
            "type":          "PATTERN",
            "severity":      "LOW",
            "finding":       f"Multiple database engines detected: {', '.join(sorted(databases))}",
            "investigation": "Verify if intentional (microservices) or misconfigured",
            "risk":          "Increased attack surface",
        })

    return findings


def correlate_critical_ports(host: dict) -> list:
    """Find high-value targets and dangerous configurations."""
    findings = []
    ports = {p["port"] for p in host.get("ports", [])}

    # Active Directory Domain Controller: Kerberos (88) + LDAP (389) + SMB (445)
    dc_indicators = {88, 389, 445}
    dc_found = dc_indicators & ports
    if len(dc_found) >= 2:
        findings.append({
            "type":          "HIGH_VALUE",
            "severity":      "CRITICAL",
            "finding":       "Likely Active Directory Domain Controller detected",
            "ports":         sorted(dc_found),
            "investigation": "High-value target — full AD security audit required",
            "risk":          "Compromise = entire domain compromise",
        })

    # Database + Web on same host amplifies SQL injection impact
    db_ports  = {3306, 5432, 6379, 27017, 1433}
    web_ports = {80, 443, 8080, 8443}
    if (ports & db_ports) and (ports & web_ports):
        findings.append({
            "type":          "ESCALATION_PATH",
            "severity":      "HIGH",
            "finding":       "Database and web server co-located on same host",
            "investigation": "Verify network segmentation — DB should not be web-accessible",
            "risk":          "SQL injection → direct database access (no network hop)",
        })

    # Multiple web service ports = larger web attack surface
    web_services = {80, 443, 8000, 8080, 8443, 8888, 9000}
    multi_web = ports & web_services
    if len(multi_web) > 1:
        findings.append({
            "type":          "SERVICE_TYPE",
            "severity":      "LOW",
            "finding":       "Multiple web services detected (likely application server)",
            "ports":         sorted(multi_web),
            "investigation": "Verify intended configuration",
            "risk":          "Larger web attack surface",
        })

    return findings


def correlate_all_findings(host: dict) -> list:
    """Run all correlation checks and return combined findings."""
    findings = []
    findings.extend(correlate_os_services(host))
    findings.extend(correlate_service_patterns(host))
    findings.extend(correlate_critical_ports(host))
    return findings
