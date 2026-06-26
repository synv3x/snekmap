from __future__ import annotations

import nmap
import concurrent.futures
from functools import partial


_CDN_PORTS      = {80, 443, 8080, 8443}
_CDN_SIGNATURES = ("cloudflare", "akamai", "fastly", "cloudfront", "imperva", "sucuri")

# Ports that indicate immediate security risk (no CVE lookup needed)
CRITICAL_PORTS = {
    21:    "CRITICAL - FTP: Anonymous login typically allowed (no credentials required by default)",
    23:    "CRITICAL - Telnet: Unencrypted terminal (replaced by SSH everywhere)",
    3306:  "CRITICAL - MySQL: Exposed database (no authentication required on network access)",
    5432:  "CRITICAL - PostgreSQL: Exposed database (authentication required but exposed)",
    6379:  "CRITICAL - Redis: No authentication by default (complete data exposure)",
    27017: "CRITICAL - MongoDB: No authentication by default (complete data exposure)",
    3389:  "CRITICAL - RDP: Exposed remote desktop (brute force vulnerability)",
    445:   "HIGH - SMB/CIFS: Potential null sessions, guest access, or exploitation",
    389:   "HIGH - LDAP: Check for anonymous binding (directory information exposure)",
    139:   "HIGH - NetBIOS: Information disclosure and potential exploitation",
}

HIGH_RISK_SERVICES = {
    "telnet": "CRITICAL - Unencrypted terminal (use SSH instead)",
    "ftp":    "CRITICAL - Unencrypted file transfer (use SFTP instead)",
}


def flag_critical_ports(ports: list) -> list:
    """Mark ports with known critical issues. No CVE lookup needed."""
    for port in ports:
        if port["port"] in CRITICAL_PORTS:
            port["critical_finding"]  = CRITICAL_PORTS[port["port"]]
            port["critical_severity"] = "CRITICAL" if "CRITICAL" in CRITICAL_PORTS[port["port"]] else "HIGH"

        service_lower = port.get("service", "").lower()
        if service_lower in HIGH_RISK_SERVICES and "critical_finding" not in port:
            port["critical_finding"]  = HIGH_RISK_SERVICES[service_lower]
            port["critical_severity"] = "CRITICAL"

    return ports


def detect_cdn(ports: list) -> str | None:
    for port in ports:
        if port.get("port") not in _CDN_PORTS:
            continue
        banner = " ".join(filter(None, [
            port.get("product", ""),
            port.get("version", ""),
            port.get("extrainfo", ""),
        ])).lower()
        for sig in _CDN_SIGNATURES:
            if sig in banner:
                return sig
    return None


def _parse_os(host_data: dict) -> tuple[str, int]:
    """Return (os_name, accuracy) from nmap host data, preferring osmatch, falling back to osclass."""
    if host_data.get("osmatch"):
        best = host_data["osmatch"][0]
        name = best.get("name", "").strip()
        acc  = int(best.get("accuracy", 0))
        if name:
            return name, acc
        # osmatch entry exists but name is empty; try its osclass
        for oc in best.get("osclass", []):
            parts = [p for p in (oc.get("vendor", ""), oc.get("osfamily", ""), oc.get("osgen", "")) if p]
            if parts:
                return " ".join(parts), int(oc.get("accuracy", acc))

    # No osmatch; try top-level osclass (some nmap/python-nmap versions expose it here)
    if host_data.get("osclass"):
        oc    = host_data["osclass"][0]
        parts = [p for p in (oc.get("vendor", ""), oc.get("osfamily", ""), oc.get("osgen", "")) if p]
        acc   = int(oc.get("accuracy", 0))
        if parts:
            return " ".join(parts), acc

    return "Unknown", 0


def scan_host(host: str, fast: bool = False, deep: bool = False) -> dict:
    scanner = nmap.PortScanner()

    if fast:
        port_spec = "--top-ports 100"
    elif deep:
        port_spec = "-p-"
    else:
        port_spec = "--top-ports 1000"

    # smb-os-discovery / rdp-ntlm-info only activate when ports 445 / 3389 are open,
    # so they add no overhead on hosts without those services.
    timeout   = "--host-timeout 1800s" if deep else "--host-timeout 600s"
    # Using nmap default -T3 (balanced timing):
    # - T3 = moderate speed (~5 min for /24), won't trigger WAF
    # - Fast enough for CTFs, stealthy enough for live work
    # - Users can override via --nmap-args if needed
    base_args = (
        f"-sV --version-intensity 5 "
        f"--script smb-os-discovery,rdp-ntlm-info "
        f"--min-rate 3000 --open {port_spec} {timeout}"
    )
    # --osscan-limit speeds up OS detection by skipping hosts with <2 open TCP ports
    os_flags  = "-O --osscan-guess --osscan-limit"

    # Attempt 1: with OS detection (requires root/admin on most systems)
    scanned = False
    try:
        scanner.scan(host, arguments=f"{base_args} {os_flags}".strip())
        scanned = True
    except nmap.PortScannerError:
        pass  # insufficient privileges for OS detection; retry without -O

    if not scanned:
        # Attempt 2: base scan without OS detection — errors propagate to caller
        scanner.scan(host, arguments=base_args.strip())
        scanned = True

    if not scanned or host not in scanner.all_hosts():
        return {"ip": host, "hostname": "", "os": "Unknown", "os_accuracy": 0, "ports": []}

    host_data = scanner[host]

    hostname = ""
    for entry in host_data.get("hostnames", []):
        if entry.get("name"):
            hostname = entry["name"]
            break

    os_name, os_accuracy = _parse_os(host_data)

    ports = []
    for proto in ("tcp", "udp"):
        if proto not in host_data:
            continue
        for port_num, svc in host_data[proto].items():
            if svc.get("state") not in ("open", "open|filtered"):
                continue
            # nmap reports service-detection confidence on a 0-10 scale via "conf".
            _conf = int(svc.get("conf", "10")) * 10
            ports.append({
                "port":               port_num,
                "protocol":           proto,
                "state":              svc.get("state", ""),
                "service":            svc.get("name", ""),
                "product":            svc.get("product", ""),
                "version":            svc.get("version", ""),
                "extrainfo":          svc.get("extrainfo", ""),
                "cpe":                svc.get("cpe", ""),
                "service_confidence": _conf,
                "version_confidence": _conf,
            })

    ports.sort(key=lambda p: p["port"])

    # Flag critical ports immediately (no CVE lookup needed)
    ports = flag_critical_ports(ports)

    result = {
        "ip":          host,
        "hostname":    hostname,
        "os":          os_name,
        "os_accuracy": os_accuracy,
        "ports":       ports,
    }
    cdn = detect_cdn(ports)
    if cdn:
        result["cdn"] = cdn
    return result


def scan_network(target: str, fast: bool = False, deep: bool = False) -> list:
    scanner = nmap.PortScanner()
    try:
        # Using nmap default -T3 instead of -T4 (less aggressive)
        scanner.scan(hosts=target, arguments="-sn --min-rate 5000")
    except nmap.PortScannerError:
        # Ping scan may be blocked (e.g. firewall); treat single target as live
        if "/" not in target and " " not in target:
            return [scan_host(target, fast=fast, deep=deep)]
        return []

    live_hosts = scanner.all_hosts()
    if not live_hosts:
        # ICMP may be filtered; if single host, attempt a direct scan anyway
        if "/" not in target and " " not in target:
            return [scan_host(target, fast=fast, deep=deep)]
        return []

    fn = partial(scan_host, fast=fast, deep=deep)
    max_workers = min(10, len(live_hosts))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(fn, live_hosts))

    return results
