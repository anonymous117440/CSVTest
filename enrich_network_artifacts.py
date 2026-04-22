#!/usr/bin/env python3
"""
Network Artifact Enrichment Script

Enriches IP addresses with:
  - Geolocation + ASN  (ipinfo.io, falls back to ip-api.com)
  - Reverse DNS
  - RDAP/WHOIS         (requires: pip install ipwhois)
  - Abuse intelligence (requires AbuseIPDB API key)
  - Threat intel       (requires VirusTotal API key)

Usage:
    python enrich_network_artifacts.py input.csv [options]

Requirements:
    pip install requests ipwhois
"""

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

import requests

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_routable_ip(value: str) -> bool:
    """Returns True for globally routable IPs (excludes private, loopback, link-local, etc.)."""
    try:
        addr = ipaddress.ip_address(value.strip())
        return addr.is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Geolocation — ipinfo.io (primary) with ip-api.com fallback
# ---------------------------------------------------------------------------

def _geo_ipinfo(ip: str, api_key: Optional[str], timeout: int) -> Optional[dict]:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": api_key} if api_key else {}
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if "bogon" in data:
            return {"notes": "bogon"}
        loc = data.get("loc", ",").split(",")
        lat = loc[0] if len(loc) == 2 else ""
        lon = loc[1] if len(loc) == 2 else ""
        org_field = data.get("org", "")  # "AS15169 Google LLC"
        asn = org_field.split(" ")[0] if org_field else ""
        asn_name = " ".join(org_field.split(" ")[1:]) if org_field else ""
        return {
            "country": data.get("country", ""),
            "country_code": data.get("country", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "latitude": lat,
            "longitude": lon,
            "isp": asn_name,
            "org": asn_name,
            "asn": asn,
            "asn_name": asn_name,
            "rdns_geo": data.get("hostname", ""),
        }
    except requests.RequestException:
        return None


def _geo_ipapi(ip: str, timeout: int) -> Optional[dict]:
    fields = "status,country,countryCode,regionName,city,lat,lon,isp,org,as,asname"
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "latitude": data.get("lat", ""),
            "longitude": data.get("lon", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
            "asn_name": data.get("asname", ""),
        }
    except requests.RequestException:
        return None


def enrich_geo(ip: str, ipinfo_key: Optional[str] = None, timeout: int = 10) -> dict:
    geo = _geo_ipinfo(ip, ipinfo_key, timeout)
    if geo is None:
        geo = _geo_ipapi(ip, timeout)
    return geo or {}


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# RDAP / WHOIS
# ---------------------------------------------------------------------------

def enrich_whois(ip: str) -> dict:
    if not HAS_IPWHOIS:
        return {}
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        network = result.get("network", {})
        return {
            "rdap_network_name": network.get("name", ""),
            "rdap_network_cidr": network.get("cidr", ""),
            "rdap_asn": result.get("asn", ""),
            "rdap_asn_description": result.get("asn_description", ""),
            "rdap_asn_country": result.get("asn_country_code", ""),
        }
    except Exception as exc:
        return {"rdap_error": str(exc)}


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def enrich_abuseipdb(ip: str, api_key: str, max_age_days: int = 90, timeout: int = 10) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", ""),
            "abuse_is_whitelisted": data.get("isWhitelisted", ""),
            "abuse_is_tor": data.get("isTor", ""),
            "abuse_total_reports": data.get("totalReports", ""),
            "abuse_last_reported_at": data.get("lastReportedAt", ""),
            "abuse_usage_type": data.get("usageType", ""),
            "abuse_domain": data.get("domain", ""),
        }
    except requests.RequestException as exc:
        return {"abuse_error": str(exc)}


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def enrich_virustotal(ip: str, api_key: str, timeout: int = 15) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "vt_malicious": stats.get("malicious", 0),
            "vt_suspicious": stats.get("suspicious", 0),
            "vt_harmless": stats.get("harmless", 0),
            "vt_undetected": stats.get("undetected", 0),
            "vt_reputation": attrs.get("reputation", ""),
            "vt_country": attrs.get("country", ""),
            "vt_as_owner": attrs.get("as_owner", ""),
            "vt_asn": attrs.get("asn", ""),
            "vt_network": attrs.get("network", ""),
        }
    except requests.RequestException as exc:
        return {"vt_error": str(exc)}


# ---------------------------------------------------------------------------
# Threat scoring heuristic
# ---------------------------------------------------------------------------

def compute_threat_score(row: dict) -> str:
    """Heuristic score: LOW / MEDIUM / HIGH / CRITICAL."""
    score = 0

    abuse = row.get("abuse_confidence_score", 0)
    if isinstance(abuse, (int, float)):
        if abuse >= 90:
            score += 4
        elif abuse >= 50:
            score += 2
        elif abuse > 0:
            score += 1

    vt_mal = row.get("vt_malicious", 0)
    if isinstance(vt_mal, (int, float)):
        if vt_mal >= 10:
            score += 4
        elif vt_mal >= 5:
            score += 3
        elif vt_mal >= 1:
            score += 1

    vt_sus = row.get("vt_suspicious", 0)
    if isinstance(vt_sus, (int, float)) and vt_sus >= 1:
        score += 1

    reports = row.get("abuse_total_reports", 0)
    if isinstance(reports, (int, float)) and reports > 0:
        score += 1

    if score == 0:
        return "LOW"
    if score <= 2:
        return "MEDIUM"
    if score <= 4:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Per-IP enrichment
# ---------------------------------------------------------------------------

def enrich_ip(
    ip: str,
    ipinfo_key: Optional[str],
    abuseipdb_key: Optional[str],
    virustotal_key: Optional[str],
    skip_rdap: bool,
    skip_rdns: bool,
) -> dict:
    row: dict = {"ip": ip}

    if not is_routable_ip(ip):
        row["notes"] = "non-routable/private"
        row["threat_score"] = "LOW"
        return row

    geo = enrich_geo(ip, ipinfo_key)
    row.update(geo)

    if not skip_rdns:
        rdns = row.pop("rdns_geo", "") or reverse_dns(ip)
        row["rdns"] = rdns
    else:
        row.pop("rdns_geo", None)

    if not skip_rdap:
        row.update(enrich_whois(ip))

    if abuseipdb_key:
        row.update(enrich_abuseipdb(ip, abuseipdb_key))

    if virustotal_key:
        row.update(enrich_virustotal(ip, virustotal_key))

    row["threat_score"] = compute_threat_score(row)
    return row


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

def read_ips_from_csv(path: str, ip_column: Optional[int] = None) -> list[tuple[str, str]]:
    """Returns (original_line, ip) pairs. Handles plain lists, CSV, and TSV."""
    entries: list[tuple[str, str]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        sample = fh.read(4096)
        fh.seek(0)

        # Plain one-IP-per-line file
        non_empty = [ln.strip() for ln in sample.splitlines() if ln.strip()]
        if non_empty and all(is_valid_ip(ln) for ln in non_empty):
            for line in fh:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    entries.append((ip, ip))
            return entries

        # Structured CSV/TSV
        sniffer = csv.Sniffer()
        try:
            dialect = sniffer.sniff(sample)
        except csv.Error:
            dialect = csv.excel  # type: ignore[assignment]

        reader = csv.reader(fh, dialect)
        for row in reader:
            if not row:
                continue
            if ip_column is not None:
                if ip_column < len(row):
                    cell = row[ip_column].strip()
                    if is_valid_ip(cell):
                        entries.append((",".join(row), cell))
            else:
                for cell in row:
                    cell = cell.strip()
                    if is_valid_ip(cell):
                        entries.append((",".join(row), cell))
                        break
    return entries


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def enrich_all(
    entries: list[tuple[str, str]],
    ipinfo_key: Optional[str],
    abuseipdb_key: Optional[str],
    virustotal_key: Optional[str],
    skip_rdap: bool,
    skip_rdns: bool,
    max_workers: int,
) -> list[dict]:
    total = len(entries)
    print(f"[*] Enriching {total} IPs with up to {max_workers} parallel workers...", file=sys.stderr)

    results: dict[str, dict] = {}

    def worker(item: tuple[str, str]) -> dict:
        _, ip = item
        return enrich_ip(ip, ipinfo_key, abuseipdb_key, virustotal_key, skip_rdap, skip_rdns)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(worker, item): item for item in entries}
        for i, future in enumerate(as_completed(futures), 1):
            row = future.result()
            results[row["ip"]] = row
            threat = row.get("threat_score", "")
            marker = "!!" if threat in ("HIGH", "CRITICAL") else "  "
            print(f"  {marker} [{i:>3}/{total}] {row['ip']:20s} {threat}", file=sys.stderr)

    return [results[ip] for _, ip in entries if ip in results]


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "ip", "threat_score",
    "country", "country_code", "region", "city", "latitude", "longitude",
    "asn", "asn_name", "isp", "org",
    "rdns",
    "rdap_network_name", "rdap_network_cidr", "rdap_asn",
    "rdap_asn_description", "rdap_asn_country", "rdap_error",
    "abuse_confidence_score", "abuse_is_whitelisted", "abuse_is_tor",
    "abuse_total_reports", "abuse_last_reported_at",
    "abuse_usage_type", "abuse_domain", "abuse_error",
    "vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
    "vt_reputation", "vt_country", "vt_as_owner", "vt_asn", "vt_network",
    "vt_error",
    "notes",
]


def write_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2, default=str)


def print_summary(rows: list[dict]) -> None:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in rows:
        counts[r.get("threat_score", "LOW")] = counts.get(r.get("threat_score", "LOW"), 0) + 1

    print("\n=== Enrichment Summary ===")
    print(f"  Total IPs : {len(rows)}")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        print(f"  {level:8s}  : {counts.get(level, 0)}")

    high_risk = [r for r in rows if r.get("threat_score") in ("HIGH", "CRITICAL")]
    if high_risk:
        print("\n  High/Critical IPs:")
        for r in sorted(high_risk, key=lambda x: x.get("abuse_confidence_score") or 0, reverse=True):
            print(
                f"    {r['ip']:20s}  abuse={r.get('abuse_confidence_score','N/A'):>4}"
                f"  vt_malicious={r.get('vt_malicious','N/A')}"
                f"  [{r.get('country_code','??')}] {r.get('org','')}"
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Enrich network artifacts (IPs) from a CSV or plain-text file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Geolocation + rDNS + RDAP (no API keys needed):
  python enrich_network_artifacts.py test.csv

  # Full enrichment with threat intel:
  python enrich_network_artifacts.py test.csv \\
      --abuseipdb-key YOUR_KEY \\
      --virustotal-key YOUR_KEY

  # ipinfo.io API key for higher rate limits:
  python enrich_network_artifacts.py test.csv --ipinfo-key YOUR_KEY

  # Skip slow RDAP lookups, output both CSV and JSON:
  python enrich_network_artifacts.py test.csv --skip-rdap --output-format both

  # Use environment variables for API keys:
  export IPINFO_API_KEY=xxx
  export ABUSEIPDB_API_KEY=yyy
  export VIRUSTOTAL_API_KEY=zzz
  python enrich_network_artifacts.py test.csv
""",
    )
    p.add_argument("input", help="Input file: plain IP list, CSV, or TSV")
    p.add_argument("-o", "--output", help="Output base path (default: <input>_enriched)")
    p.add_argument(
        "--output-format", choices=["csv", "json", "both"], default="csv",
        help="Output format (default: csv)",
    )
    p.add_argument(
        "--ip-column", type=int, default=None,
        help="Zero-based column index for IPs in structured CSV (auto-detected by default)",
    )
    p.add_argument(
        "--ipinfo-key", default=os.environ.get("IPINFO_API_KEY"),
        help="ipinfo.io API key — optional, raises the 50k/month free limit",
    )
    p.add_argument(
        "--abuseipdb-key", default=os.environ.get("ABUSEIPDB_API_KEY"),
        help="AbuseIPDB API key (or ABUSEIPDB_API_KEY env var)",
    )
    p.add_argument(
        "--virustotal-key", default=os.environ.get("VIRUSTOTAL_API_KEY"),
        help="VirusTotal API key (or VIRUSTOTAL_API_KEY env var)",
    )
    p.add_argument("--skip-rdap", action="store_true", help="Skip RDAP/WHOIS lookups")
    p.add_argument("--skip-rdns", action="store_true", help="Skip reverse DNS lookups")
    p.add_argument(
        "--workers", type=int, default=10,
        help="Parallel worker threads (default: 10)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading from {args.input}", file=sys.stderr)
    entries = read_ips_from_csv(args.input, args.ip_column)
    if not entries:
        print("[ERROR] No valid IP addresses found.", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Found {len(entries)} IP entries", file=sys.stderr)

    if not args.abuseipdb_key:
        print("[*] No AbuseIPDB key — abuse intel disabled  (set ABUSEIPDB_API_KEY)", file=sys.stderr)
    if not args.virustotal_key:
        print("[*] No VirusTotal key — VT intel disabled    (set VIRUSTOTAL_API_KEY)", file=sys.stderr)
    if not HAS_IPWHOIS and not args.skip_rdap:
        print("[*] ipwhois not installed — RDAP skipped     (pip install ipwhois)", file=sys.stderr)

    start = datetime.now()
    rows = enrich_all(
        entries,
        ipinfo_key=args.ipinfo_key,
        abuseipdb_key=args.abuseipdb_key,
        virustotal_key=args.virustotal_key,
        skip_rdap=args.skip_rdap,
        skip_rdns=args.skip_rdns,
        max_workers=args.workers,
    )

    base = args.output or os.path.splitext(args.input)[0] + "_enriched"
    base = base.removesuffix(".csv").removesuffix(".json")

    if args.output_format in ("csv", "both"):
        csv_path = base + ".csv"
        write_csv(rows, csv_path)
        print(f"\n[+] CSV  → {csv_path}", file=sys.stderr)

    if args.output_format in ("json", "both"):
        json_path = base + ".json"
        write_json(rows, json_path)
        print(f"[+] JSON → {json_path}", file=sys.stderr)

    elapsed = (datetime.now() - start).total_seconds()
    print(f"[*] Done in {elapsed:.1f}s", file=sys.stderr)
    print_summary(rows)


if __name__ == "__main__":
    main()
