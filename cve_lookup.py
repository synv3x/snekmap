"""
CVE lookup via NVD API 2.0.

Strategy (most-specific to least):
  1. Static overrides  — manually curated, matched on product+version string.
  2. CPE-name lookup   — uses nmap's CPE string (converted to 2.3 format) with
                         NVD's cpeName parameter for exact dictionary matching.
  3. Product+version keyword — only when both are non-empty and non-generic.
  4. Everything else   — return []. No noisy keyword-only fallback.

Local cache: ~/.snekmap/cve_cache.json  (TTL 24 h)
API key:     NVD_API_KEY env var         (50 req/30 s vs 5 req/30 s without)
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ── Rate limit tracking ───────────────────────────────────────────────────────

_rate_limit_state = {
    "consecutive_hits": 0,
    "last_hit_time":    None,
    "backoff_seconds":  8,
    "degraded_mode":    False,
    "lock":             threading.Lock(),
}


def _handle_rate_limit() -> None:
    """Called on 429. Applies exponential backoff; enters degraded mode after 3 hits."""
    with _rate_limit_state["lock"]:
        _rate_limit_state["consecutive_hits"] += 1
        _rate_limit_state["last_hit_time"]     = time.time()
        hits = _rate_limit_state["consecutive_hits"]

        # Exponential backoff: 8 → 16 → 32 → 60 s max
        backoff = min(8 * (2 ** hits), 60)
        _rate_limit_state["backoff_seconds"] = backoff

        if hits >= 3:
            _rate_limit_state["degraded_mode"] = True
            print(
                f"\n[!] Rate limited {hits} times. Degraded mode: Using static overrides only.",
                file=sys.stderr, flush=True,
            )
        else:
            print(
                f"\n[!] Rate limited. Waiting {backoff}s before retry...",
                file=sys.stderr, flush=True,
            )

    time.sleep(backoff)


def _reset_rate_limit() -> None:
    """Called on a successful API response. Clears hit counter and degraded flag."""
    with _rate_limit_state["lock"]:
        if _rate_limit_state["consecutive_hits"] > 0:
            _rate_limit_state["consecutive_hits"] = 0
            _rate_limit_state["degraded_mode"]    = False


def is_rate_limited() -> bool:
    """Return True when in degraded mode (NVD lookups should be skipped)."""
    return _rate_limit_state["degraded_mode"]


def get_rate_limit_stats() -> dict:
    """Return a snapshot of the current rate-limit state for display."""
    return {
        "consecutive_hits": _rate_limit_state["consecutive_hits"],
        "degraded_mode":    _rate_limit_state["degraded_mode"],
        "backoff_seconds":  _rate_limit_state["backoff_seconds"],
    }

# ── Confidence thresholds ─────────────────────────────────────────────────────

CONFIDENCE_THRESHOLDS = {
    "service": 60,  # < 60 % → skip CVE correlation entirely
    "version": 70,  # < 70 % → strip to major version only
}


def evaluate_confidence(service_confidence: int = 100, version_confidence: int = 100) -> dict:
    """Return trust flags for service/version data quality."""
    return {
        "service_trusted": service_confidence >= CONFIDENCE_THRESHOLDS["service"],
        "version_trusted": version_confidence >= CONFIDENCE_THRESHOLDS["version"],
        "service_confidence": service_confidence,
        "version_confidence": version_confidence,
    }


# ── Constants ─────────────────────────────────────────────────────────────────

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SKIP_SERVICES = frozenset({
    "tcpwrapped", "unknown", "filtered", "generic", "",
})

# Generic protocols — without a version they produce thousands of irrelevant hits.
_REQUIRE_VERSION = frozenset({
    "http", "https", "ftp", "ftps", "smtp", "smtps",
    "dns", "mdns", "ssl", "tls", "upnp", "tcp", "udp",
})

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "N/A": 0}

_API_KEY = os.environ.get("NVD_API_KEY", "")
# NVD rate limits: 50 req/30 s with key, 5 req/30 s without.
_SLEEP          = 0.7 if _API_KEY else 6.5
_nvd_warn_shown = False

_CACHE_TTL = timedelta(hours=24)

# ── Cache ─────────────────────────────────────────────────────────────────────

_CACHE_PATH = Path.home() / ".snekmap" / "cve_cache.json"
_cache: dict = {}
_cache_loaded = False
_mem_cache: dict[tuple, list] = {}


def _load_cache() -> None:
    global _cache, _cache_loaded
    if _cache_loaded:
        return
    _cache_loaded = True
    if _CACHE_PATH.exists():
        try:
            with open(_CACHE_PATH, encoding="utf-8") as f:
                _cache = json.load(f)
        except (json.JSONDecodeError, OSError):
            _cache = {}


def _save_cache() -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache, f, separators=(",", ":"))
    except OSError:
        pass


def _cache_get(key: str) -> list | None:
    _load_cache()
    entry = _cache.get(key)
    if not entry:
        return None
    try:
        ts = datetime.fromisoformat(entry["ts"])
        if datetime.now(tz=timezone.utc) - ts > _CACHE_TTL:
            del _cache[key]
            return None
        return entry["cves"]
    except (KeyError, ValueError):
        return None


def _cache_set(key: str, cves: list) -> None:
    _load_cache()
    _cache[key] = {
        "cves": cves,
        "ts":   datetime.now(tz=timezone.utc).isoformat(),
    }
    _save_cache()


# ── Static overrides ──────────────────────────────────────────────────────────

def _load_overrides() -> dict:
    """Load cve_overrides.json from the project directory (next to this file)."""
    path = Path(__file__).parent / "cve_overrides.json"
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        # Normalise keys to lower-case for case-insensitive matching.
        return {k.lower(): v for k, v in raw.items()}
    except (json.JSONDecodeError, OSError):
        return {}


_OVERRIDES: dict = _load_overrides()


def _get_overrides(product: str, version: str) -> list:
    """Return manually curated CVEs for a product+version fingerprint, if any."""
    key = f"{product} {version}".strip().lower()
    return list(_OVERRIDES.get(key, []))


# ── CPE helpers ───────────────────────────────────────────────────────────────

def _cpe22_to_23(cpe: str) -> str:
    """
    Convert a CPE 2.2 URI (cpe:/part:vendor:product:version:…) to the
    CPE 2.3 formatted string (cpe:2.3:part:vendor:product:version:…:*)
    required by the NVD API cpeName parameter.
    Returns the input unchanged if it is already CPE 2.3 or unrecognised.
    """
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return cpe
    rest  = cpe[5:]          # strip "cpe:/"
    parts = rest.split(":")
    # CPE 2.3 formatted string has exactly 11 components after "cpe:2.3:"
    while len(parts) < 11:
        parts.append("*")
    return "cpe:2.3:" + ":".join(parts[:11])


# ── NVD API ───────────────────────────────────────────────────────────────────

def _nvd_warn(reason: str) -> None:
    global _nvd_warn_shown
    if not _nvd_warn_shown:
        _nvd_warn_shown = True
        print(
            f"\n[!] CVE lookup degraded — NVD API returned {reason}. "
            "Continuing scan without CVE data.",
            file=sys.stderr,
            flush=True,
        )


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_cve(item: dict) -> dict | None:
    cve    = item.get("cve", {})
    status = cve.get("vulnStatus", "")
    if status in ("Rejected", "Disputed"):
        return None

    metrics    = cve.get("metrics", {})
    severity   = "N/A"
    cvss_score = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            cd         = metrics[key][0]["cvssData"]
            severity   = cd.get("baseSeverity", "N/A")
            cvss_score = cd.get("baseScore")
            break
    else:
        if metrics.get("cvssMetricV2"):
            cd         = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cd.get("baseScore", 0.0)
            severity   = _score_to_severity(cvss_score)

    description = "No description available."
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc["value"]
            break

    return {
        "id":          cve.get("id", "Unknown"),
        "description": description,
        "severity":    severity,
        "cvss_score":  cvss_score,
    }


def _fetch_nvd(*, cpe: str = "", keyword: str = "") -> list:
    """
    Single NVD API call.  Pass either cpe= (uses cpeName parameter, most precise)
    or keyword= (uses keywordSearch, last resort).  Returns parsed CVE dicts.
    """
    headers = {"apiKey": _API_KEY} if _API_KEY else {}
    if cpe:
        params = {"cpeName": cpe, "resultsPerPage": 20}
    else:
        params = {"keywordSearch": keyword, "resultsPerPage": 10}

    wait = 8.0
    for attempt in range(3):
        try:
            resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
            if resp.status_code == 200:
                _reset_rate_limit()
                raw = resp.json().get("vulnerabilities", [])
                return [c for c in (_parse_cve(v) for v in raw) if c is not None]
            reason = "429 (rate limited)" if resp.status_code == 429 else str(resp.status_code)
            _nvd_warn(reason)
            if resp.status_code in (403, 429, 503):
                if resp.status_code == 429:
                    _handle_rate_limit()
                else:
                    time.sleep(wait)
                    wait = min(wait * 2, 60)
                continue
            return []
        except requests.Timeout:
            _nvd_warn("timeout")
            if attempt < 2:
                time.sleep(wait)
                wait = min(wait * 2, 60)
            else:
                return []
        except requests.RequestException:
            if attempt < 2:
                time.sleep(wait)
                wait = min(wait * 2, 60)
            else:
                return []
    return []


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_cve(
    service: str,
    version: str = "",
    product: str = "",
    cpe: str = "",
    service_confidence: int = 100,
    version_confidence: int = 100,
) -> list:
    """
    Return up to 10 CVEs for the given service fingerprint, sorted by severity.

    Priority:
      1. Static overrides (exact product+version match, always included).
      2. CPE-name lookup via NVD (uses nmap-provided CPE string if available).
      3. Product+version keyword (fallback when CPE is absent but both fields exist
         and neither is in the generic skip/require-version sets).
      4. Return [] — no further guessing.

    Confidence gating:
      - service_confidence < 60 → return [] (don't correlate uncertain identifications)
      - version_confidence  < 70 → strip to major version, discard CPE (too specific)
    """
    confidence = evaluate_confidence(service_confidence, version_confidence)
    if not confidence["service_trusted"]:
        return []

    service = (service or "").strip().lower()
    version = (version or "").strip()
    product = (product or "").strip()
    cpe     = (cpe     or "").strip()

    # Low version confidence: use only major version to avoid false positives;
    # also discard CPE because it embeds the full version string.
    if not confidence["version_trusted"] and version:
        version = version.split(".")[0]
        cpe = ""

    _key = (service, version, product, cpe)
    if _key in _mem_cache:
        return _mem_cache[_key]

    # If rate limited, skip NVD entirely and fall back to static overrides only
    if is_rate_limited():
        overrides = _get_overrides(product, version)
        result = overrides[:10]
        _mem_cache[_key] = result
        return result

    # ── 1. Static overrides ──
    overrides = _get_overrides(product, version)

    # ── 2 & 3. API lookup ──
    api_cves: list[dict] = []

    if cpe:
        cpe23     = _cpe22_to_23(cpe)
        cached    = _cache_get(cpe23)
        if cached is not None:
            api_cves = cached
        else:
            time.sleep(_SLEEP)
            api_cves = _fetch_nvd(cpe=cpe23)
            _cache_set(cpe23, api_cves)

    elif (product and version
          and product.lower() not in _SKIP_SERVICES
          and product.lower() not in _REQUIRE_VERSION):
        kw     = f"{product} {version}"
        cached = _cache_get(kw)
        if cached is not None:
            api_cves = cached
        else:
            time.sleep(_SLEEP)
            api_cves = _fetch_nvd(keyword=kw)
            _cache_set(kw, api_cves)

    seen: set[str] = set()
    merged: list[dict] = []
    for cve in overrides + api_cves:
        if cve["id"] not in seen:
            seen.add(cve["id"])
            merged.append(cve)

    merged.sort(
        key=lambda c: (_SEV_RANK.get(c["severity"], 0), c.get("cvss_score") or 0),
        reverse=True,
    )
    _mem_cache[_key] = merged[:10]
    return _mem_cache[_key]
