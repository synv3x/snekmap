# AI Assistance Disclosure

## Summary

SnekMap is a tool designed and architected by synv3x (~70-80% original work)
with implementation assistance from Claude Code (~20-30% boilerplate/polish).

---

## What synv3x Built (Architecture & Design)

### Core Strategy

- 4-phase scan pipeline: discovery → CVE correlation → credentials → protocol checks → correlation
- CPE-based CVE matching (deliberately chose CPE over keyword search for precision)
- Confidence-gated correlation: 60% service threshold, 70% version threshold
- Adaptive rate limiting with exponential backoff and degraded mode
- 24-hour disk + in-memory caching strategy
- Cross-finding correlation patterns (AD DC detection, escalation paths, OS mismatches)

### Code Written by synv3x

- **snekmap.py** — CLI argument parsing, 4-phase orchestration, display functions
- **scanner.py** — nmap integration, OS detection parsing, CDN detection, critical port flagging
- **cve_lookup.py** — 3-tier lookup logic (CPE → keyword → override), confidence evaluation, rate limit state machine, dual cache layer
- **correlation.py** — all pattern detection algorithms (AD fingerprint, DB+web escalation path, OS/service mismatch, redundant protocol pairs)
- All integration, testing, and debugging across 7 features

### Design Decisions by synv3x

| Decision | Rationale |
|----------|-----------|
| CPE matching over keyword search | Precision — keyword search returns thousands of irrelevant hits for generic service names |
| Confidence thresholding | Avoids correlating low-confidence nmap detections that may be wrong service IDs |
| Degraded mode under rate limits | Tool remains useful even when NVD API is unavailable, falling back to static overrides |
| Protocol-specific checks | Generic port-open findings aren't actionable; targeted probes confirm real misconfigurations |
| Cross-finding correlation | Individual CVEs matter less than escalation paths — a DB+web co-location is more dangerous than either alone |

---

## What Claude Code Implemented (Boilerplate & Polish)

### Functions Generated from Specifications

- **scanner_checks.py** — `test_ftp_anonymous()`, `test_ssh_creds()`, `test_mysql_creds()`, `test_postgres_creds()`, `test_redis_auth()` — all credential testers, ImportError handling for optional deps
- **protocol_checks.py** — `check_ldap_anonymous_bind()`, `check_smb_null_sessions()`, `check_dns_zone_transfer()`, `check_nfs_world_writable()`, `check_snmp_weak_community()` — subprocess-based protocol probes
- **report.py** — `generate_html_report()` (self-contained dark-theme HTML with severity cards, risk bar, per-host CVE tables); `generate_pdf_report()` (ReportLab A4 document: stat cards, severity breakdown, per-host port and CVE tables with row coloring, running headers, page footers); JSON export payload with metadata/scanner/summary structure; CSV export with `#`-prefixed metadata header block
- **install.sh** — entire installer script: platform detection (apt/dnf/pacman/brew), venv setup, PEP 668 handling, NVD API key prompt with 30-second timeout, connectivity test, man page installation with fallback paths
- **snekmap.1** — man page (groff formatting, OPTIONS, ENVIRONMENT, FILES, EXAMPLES sections)
- **README.md** — initial structure, feature table, installation instructions, usage examples, output format reference
- **Rich UI** — ASCII art banner, blue gradient rendering, progress spinners, port/CVE tables, severity icons and color coding

### Implementation Pattern

Claude Code wrote function bodies and styling. synv3x specified:
- What each function should test and what output it must return
- Severity classification (CRITICAL vs HIGH vs LOW) for each finding type
- When to skip gracefully (ImportError on optional deps, subprocess not found)
- Where each component slots into the pipeline and how errors propagate

---

## Collaboration Model

```
synv3x:   Architecture · Strategy · Testing · Integration · Design decisions
Claude:   Boilerplate · Styling · Documentation · Scaffolding · Function bodies
Result:   Production-grade tool with honest division of labor
```

---

## External Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| [python-nmap](https://pypi.org/project/python-nmap/) | 0.7.1 | Python interface to nmap |
| [requests](https://pypi.org/project/requests/) | 2.34.2 | HTTPS calls to NVD API |
| [rich](https://github.com/Textualize/rich) | 15.0.0 | Terminal formatting and progress UI |
| [reportlab](https://www.reportlab.com) | 4.5.1 | PDF report generation |
| paramiko *(optional)* | 3.4.0 | SSH default-credential checks |
| pymysql *(optional)* | 1.1.0 | MySQL default-credential checks |
| psycopg2-binary *(optional)* | ≥2.9.0 | PostgreSQL default-credential checks |

### External Tools & APIs

- **[nmap](https://nmap.org)** — port scanner; must be installed separately
- **[NIST NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities)** — CVE data source; free API key available for higher rate limits
- **ldapsearch, smbclient, dig, showmount, snmpwalk** — protocol check tools; silently skipped if absent
