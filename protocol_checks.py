"""Protocol-specific security checks (LDAP, SMB, DNS, NFS, SNMP)."""
from __future__ import annotations

import subprocess
import time

def check_ldap_anonymous_bind(host: str, port: int = 389) -> dict | None:
    """Check if LDAP allows anonymous binding (information disclosure)."""
    try:
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{host}:{port}", "-b", "", "-s", "base", "objectclass=*"]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if result.returncode == 0 and (b"dn:" in result.stdout or b"objectClass" in result.stdout):
            return {
                "status": "HIGH",
                "finding": "LDAP: Anonymous binding allowed",
                "impact": "Directory information disclosure possible (user enumeration)",
                "remediation": "Disable anonymous binding in LDAP config",
            }
    except Exception:
        pass
    return None


def check_smb_null_sessions(host: str, port: int = 445) -> dict | None:
    """Check if SMB allows null sessions (share enumeration)."""
    try:
        cmd = ["smbclient", "-L", f"//{host}", "-U", ""]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if (b"Sharename" in result.stdout or b"IPC$" in result.stdout) and result.returncode == 0:
            return {
                "status": "HIGH",
                "finding": "SMB: Null sessions allowed",
                "impact": "Share enumeration possible, information disclosure",
                "remediation": "Set 'restrict anonymous = 1' or '2' in smb.conf",
            }
    except Exception:
        pass
    return None


def check_dns_zone_transfer(host: str, port: int = 53) -> dict | None:
    """Check if DNS allows zone transfers (AXFR)."""
    try:
        cmd = ["dig", f"@{host}", "example.com", "axfr", "+short"]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        # More than 100 bytes of output without comment lines suggests a real zone dump
        if len(result.stdout) > 100 and b";" not in result.stdout[:50]:
            return {
                "status": "HIGH",
                "finding": "DNS: Zone transfer allowed (AXFR)",
                "impact": "Complete zone enumeration possible (all DNS records exposed)",
                "remediation": "Restrict zone transfers to authorized nameservers only",
            }
    except Exception:
        pass
    return None


def check_nfs_world_writable(host: str, port: int = 111) -> dict | None:
    """Check NFS for world-readable or world-writable shares."""
    try:
        cmd = ["showmount", "-e", host]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        output = result.stdout
        if b"(everyone)" in output or (b"*" in output and b"(rw" in output):
            return {
                "status": "CRITICAL",
                "finding": "NFS: World-accessible shares detected",
                "impact": "Anyone can read/write data on NFS shares",
                "remediation": "Restrict NFS exports to specific IPs; enforce ro vs rw per export",
            }
    except Exception:
        pass
    return None


def check_snmp_weak_community(host: str, port: int = 161) -> dict | None:
    """Check SNMP for default/weak community strings."""
    try:
        for community in ("public", "private", "community"):
            cmd = ["snmpwalk", "-c", community, "-v", "2c", host, "1.3.6.1.2.1.1.1.0"]
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            if result.returncode == 0 and len(result.stdout) > 20:
                return {
                    "status": "HIGH",
                    "finding": f"SNMP: Weak community string '{community}' accepted",
                    "impact": "SNMP info disclosure (system info, network config, routing tables)",
                    "remediation": f"Change community string from '{community}'; upgrade to SNMPv3 with auth",
                }
    except Exception:
        pass
    return None


_PORT_CHECKS = {
    389:  ("ldap",  check_ldap_anonymous_bind),
    445:  ("smb",   check_smb_null_sessions),
    139:  ("smb",   check_smb_null_sessions),
    53:   ("dns",   check_dns_zone_transfer),
    111:  ("nfs",   check_nfs_world_writable),
    2049: ("nfs",   check_nfs_world_writable),
    161:  ("snmp",  check_snmp_weak_community),
}

CHECKED_PORTS = set(_PORT_CHECKS.keys())


def run_protocol_checks(host: str, ports: list) -> list:
    """Run protocol-specific checks for detected services; return list of findings."""
    findings = []
    for port_info in ports:
        port_num = port_info["port"]
        if port_num not in _PORT_CHECKS:
            continue
        protocol_name, check_func = _PORT_CHECKS[port_num]
        try:
            result = check_func(host, port_num)
            if result:
                findings.append({"port": port_num, "protocol": protocol_name, **result})
        except Exception:
            pass
        time.sleep(0.3)
    return findings
