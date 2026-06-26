"""Credential testing and protocol-specific vulnerability checks."""
from __future__ import annotations

import ftplib
import socket
import time


# Default credentials to test per port
DEFAULT_CREDENTIALS = {
    21: {
        "name": "FTP",
        "protocol": "ftp",
        "creds": [
            ("anonymous", "anonymous"),
            ("anonymous", ""),
            ("admin", "admin"),
            ("ftp", "ftp"),
        ],
    },
    22: {
        "name": "SSH",
        "protocol": "ssh",
        "creds": [
            ("root", ""),
            ("root", "root"),
            ("admin", "admin"),
            ("admin", "password"),
        ],
    },
    3306: {
        "name": "MySQL",
        "protocol": "mysql",
        "creds": [
            ("root", ""),
            ("root", "root"),
            ("admin", "admin"),
        ],
    },
    5432: {
        "name": "PostgreSQL",
        "protocol": "postgres",
        "creds": [
            ("postgres", ""),
            ("postgres", "postgres"),
        ],
    },
    6379: {
        "name": "Redis",
        "protocol": "redis",
        "creds": [("", "")],
    },
}

# Which ports this module actively tests (others are defined but not exercised)
CHECKED_PORTS = {21, 22, 3306, 5432, 6379}


def test_ftp_anonymous(host: str, port: int) -> dict | None:
    """Test FTP for anonymous login."""
    try:
        ftp = ftplib.FTP(timeout=3)
        ftp.connect(host, port)
        ftp.login("anonymous", "anonymous")
        ftp.quit()
        return {
            "status":   "CRITICAL",
            "finding":  "FTP anonymous login ALLOWED",
            "evidence": "Successfully logged in as anonymous:anonymous",
        }
    except Exception:
        return None


def test_ssh_creds(host: str, port: int, username: str, password: str) -> dict | None:
    """Test SSH with given credentials (requires paramiko)."""
    try:
        import paramiko  # optional dependency
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            host, port=port,
            username=username, password=password,
            timeout=3, allow_agent=False, look_for_keys=False,
        )
        ssh.close()
        pwd_display = password if password else "(empty)"
        return {
            "status":   "CRITICAL",
            "finding":  f"SSH default credentials work: {username}:{pwd_display}",
            "evidence": "Successfully authenticated via SSH",
        }
    except ImportError:
        return None
    except Exception:
        return None


def test_mysql_creds(host: str, port: int, username: str, password: str) -> dict | None:
    """Test MySQL with given credentials (requires pymysql)."""
    try:
        import pymysql  # optional dependency
        conn = pymysql.connect(
            host=host, port=port,
            user=username, password=password,
            connect_timeout=3,
        )
        conn.close()
        pwd_display = password if password else "(empty)"
        return {
            "status":   "CRITICAL",
            "finding":  f"MySQL default credentials work: {username}:{pwd_display}",
            "evidence": "Successfully authenticated to MySQL",
        }
    except ImportError:
        return None
    except Exception:
        return None


def test_postgres_creds(host: str, port: int, username: str, password: str) -> dict | None:
    """Test PostgreSQL with given credentials (requires psycopg2 or similar)."""
    try:
        import psycopg2  # optional dependency
        conn = psycopg2.connect(
            host=host, port=port,
            user=username, password=password,
            connect_timeout=3,
        )
        conn.close()
        pwd_display = password if password else "(empty)"
        return {
            "status":   "CRITICAL",
            "finding":  f"PostgreSQL default credentials work: {username}:{pwd_display}",
            "evidence": "Successfully authenticated to PostgreSQL",
        }
    except ImportError:
        return None
    except Exception:
        return None


def test_redis_auth(host: str, port: int) -> dict | None:
    """Test Redis for unauthenticated access via raw socket PING."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.sendall(b"PING\r\n")
        response = sock.recv(1024)
        sock.close()
        if b"PONG" in response:
            return {
                "status":   "CRITICAL",
                "finding":  "Redis: No authentication required",
                "evidence": "PING command succeeded without credentials",
            }
    except Exception:
        pass
    return None


def test_credentials_for_port(host: str, port: int) -> list:
    """
    Test default credentials for a given port number.
    Returns a list of finding dicts (may be empty).
    """
    findings = []

    if port == 21:
        result = test_ftp_anonymous(host, port)
        if result:
            findings.append(result)

    elif port == 22:
        for username, password in DEFAULT_CREDENTIALS[22]["creds"]:
            result = test_ssh_creds(host, port, username, password)
            if result:
                findings.append(result)
                break  # stop after first success

    elif port == 3306:
        for username, password in DEFAULT_CREDENTIALS[3306]["creds"]:
            result = test_mysql_creds(host, port, username, password)
            if result:
                findings.append(result)
                break

    elif port == 5432:
        for username, password in DEFAULT_CREDENTIALS[5432]["creds"]:
            result = test_postgres_creds(host, port, username, password)
            if result:
                findings.append(result)
                break

    elif port == 6379:
        result = test_redis_auth(host, port)
        if result:
            findings.append(result)

    time.sleep(0.5)  # brief pause between port tests
    return findings
