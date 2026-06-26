# SnekMap

SnekMap is a network reconnaissance and vulnerability assessment scanner for penetration testers and security auditors. It combines nmap port scanning with automated CVE correlation from the NIST NVD API, default credential testing, protocol-specific misconfiguration checks, cross-finding correlation, and multi-format report generation — all in a single command-line tool designed for Kali Linux and POSIX environments.

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Host & port discovery** | Ping sweep + concurrent service version detection via nmap. Fast (top 100), standard (top 1000), and deep (all 65535) scan modes |
| 2 | **CVE correlation** | Per-port CVE lookup via NIST NVD API v2.0. Confidence-gated: skips correlation when nmap service detection is uncertain (< 60%), uses major-version-only matching when version confidence is low (< 70%). 24-hour local cache |
| 3 | **Default credential testing** | Automatically tests discovered services (FTP, SSH, MySQL, PostgreSQL, Redis) against common default credentials after scanning |
| 4 | **Protocol-specific checks** | Actively tests detected protocols for known misconfigurations: LDAP anonymous binding, SMB null sessions, DNS zone transfer (AXFR), NFS world-accessible shares, SNMP weak community strings |
| 5 | **Cross-finding correlation** | Analyses the full set of findings to surface patterns: Active Directory Domain Controller identification, database + web server co-location (SQL injection escalation path), Linux/Windows OS–service mismatches, redundant protocol pairs |
| 6 | **Multi-format reports** | HTML (styled, print-ready), PDF (ReportLab), JSON (structured payload with metadata), and CSV (one row per CVE). Non-interactive `--export` flag for CI/scripting use |
| 7 | **CDN / WAF detection** | Identifies Cloudflare, Akamai, Fastly, CloudFront, Imperva, and Sucuri from service banners; warns when version data may be unreliable behind a CDN |

---

## Requirements

- **Python 3.9+**
- **nmap** installed and on `PATH` (OS detection requires root/sudo)
- pip packages in `requirements.txt`

> OS detection (`-O`) falls back gracefully if elevated privileges are unavailable.

---

## Installation

### Kali Linux / Debian / Ubuntu (recommended)

```bash
git clone https://github.com/synv3x/snekmap.git
cd snekmap
chmod +x install.sh
./install.sh
```

The script checks Python 3.9+, nmap, and git; creates `~/.snekmap/`; installs pip dependencies; prompts for an optional NVD API key; and runs a connectivity test.

```bash
./install.sh --help     # show requirements, what gets installed, uninstall steps
```
### Manual

```bash
git clone https://github.com/synv3x/snekmap.git
cd snekmap
pip install -r requirements.txt
python snekmap.py --help
```

---

## Usage

```
snekmap TARGET [OPTIONS]
```

> If running without the installer: `python snekmap.py TARGET [OPTIONS]`

### Examples

```bash
# Standard scan of a single host — top 1000 ports, CVE lookup, all checks
snekmap 192.168.1.10

# Fast scan of a /24 network — top 100 ports per host
snekmap 192.168.1.0/24 -f

# Deep scan — all 65535 ports (slow; use on focused targets)
sudo snekmap 10.0.0.5 -d

# Offline scan — skip CVE lookup (no internet required)
snekmap 192.168.1.10 --no-cve

# Export all report formats non-interactively (for scripts / CI)
snekmap 10.0.0.0/24 -f --export all -o /tmp/scan-$(date +%Y%m%d)

# Quiet JSON export — suppress banner, save to a specific directory
snekmap 192.168.1.10 -q --export json -o /tmp/scans
```

### Options

| Flag | Description |
|------|-------------|
| `-f`, `--fast` | Fast scan (top 100 ports) |
| `-d`, `--deep` | Deep scan (all 65535 ports) |
| `--no-cve` | Skip CVE lookups (faster, no internet required) |
| `--export FORMAT` | Export without interactive menu: `html` `pdf` `json` `csv` `all` |
| `-o DIR`, `--output-dir DIR` | Directory to save reports (default: Desktop → `~/.snekmap/reports`) |
| `-q`, `--quiet` | Suppress banner and progress spinners |
| `-v`, `--version` | Show version and exit |

---

## NVD API Key

Without an API key, CVE lookups are rate-limited to 5 requests per 30 seconds. A free key raises this to 50 requests per 30 seconds — roughly 10x faster on targets with many open ports. The installer will prompt you to enter one; you can also set it manually:

```bash
# Request a free key at https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your-key-here
```

Add the `export` line to `~/.bashrc` or `~/.zshrc` to make it permanent.

---

## Output Formats

| Format | Contents |
|--------|----------|
| **HTML** | Styled, self-contained report with host table, CVE findings, severity summary, and critical findings highlighted |
| **PDF** | ReportLab document suitable for client delivery; includes stat cards and per-host CVE tables |
| **JSON** | Structured payload: `metadata`, `scanner`, `summary`, `context`, and per-host `results` with full CVE data |
| **CSV** | Flat spreadsheet with one row per CVE finding; `#`-prefixed metadata header block for traceability |

Reports are saved to (in order of preference):

1. Path given via `-o DIR`
2. `$XDG_DESKTOP_DIR` (Linux/freedesktop), if set and valid
3. `~/Desktop`, if it exists
4. `~/.snekmap/reports` (auto-created)

---

## Optional Dependencies

### Credential Testing Dependencies

For advanced credential testing, install:

```bash
pip install paramiko pymysql psycopg2-binary
```

- **paramiko** — SSH credential testing
- **pymysql** — MySQL credential testing
- **psycopg2-binary** — PostgreSQL credential testing

If not installed, those tests are skipped gracefully.

FTP and Redis credential testing use Python's stdlib (`ftplib`, `socket`) and need no extra packages.

---

## Man Page

The installer (`./install.sh`) handles man page installation automatically.
To install or read it manually:

```bash
# Install system-wide
sudo cp snekmap.1 /usr/share/man/man1/
sudo mandb
man snekmap

# Or read directly without installing
man ./snekmap.1
```

---

## Credits

- **[nmap](https://nmap.org)** — the underlying scanner engine
- **[NIST NVD](https://nvd.nist.gov)** — CVE database and API
- **[python-nmap](https://pypi.org/project/python-nmap/)** — Python interface to nmap
- **[Rich](https://github.com/Textualize/rich)** — terminal formatting
- **[ReportLab](https://www.reportlab.com)** — PDF generation
- **[Claude Code](https://claude.ai/code)** — assisted with feature implementation, terminal UI, and refactoring (see SOURCES.md for full breakdown)

---

## License

MIT — see [LICENSE](./LICENSE) for full text.
