#!/usr/bin/env python3
"""
Enterprise SOC Threat Intelligence & IoC Triage Automation Script
Author: Security Operations / Detection Engineering Team
Purpose: Automates indicator of compromise (IoC) enrichment by querying
         VirusTotal API v3 and AbuseIPDB API v2, generating a structured
         risk scoring report for SOC Tier 1 analysts.
"""

import argparse
import json
import os
import re
import sys
import time
from typing import Dict, Any, List
import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# Regex patterns for input validation
IP_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> str:
    """Classifies an IoC string as IP, HASH, or UNKNOWN."""
    ioc_clean = ioc.strip()
    if IP_PATTERN.match(ioc_clean):
        return "IP"
    elif MD5_PATTERN.match(ioc_clean) or SHA1_PATTERN.match(ioc_clean) or SHA256_PATTERN.match(ioc_clean):
        return "HASH"
    return "UNKNOWN"


def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> Dict[str, Any]:
    """Queries VirusTotal API v3 for IP addresses or file hashes."""
    if not api_key:
        return {"error": "VirusTotal API key missing. Set VT_API_KEY env var or pass --vt-key."}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    endpoint = f"{VT_BASE_URL}/ip_addresses/{ioc}" if ioc_type == "IP" else f"{VT_BASE_URL}/files/{ioc}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "meaningful_name": data.get("meaningful_name") or data.get("as_owner", "N/A")
            }
        elif response.status_code == 404:
            return {"status": "Not Found / Zero Detections in VirusTotal database"}
        else:
            return {"error": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}


def query_abuseipdb(ip_address: str, api_key: str) -> Dict[str, Any]:
    """Queries AbuseIPDB API v2 for IP reputation and abuse confidence score."""
    if not api_key:
        return {"error": "AbuseIPDB API key missing. Set ABUSEIPDB_API_KEY env var or pass --abuse-key."}

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(ABUSEIPDB_BASE_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "total_reports": data.get("totalReports", 0),
                "usage_type": data.get("usageType", "N/A")
            }
        else:
            return {"error": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}


def assess_verdict(vt_data: Dict[str, Any], abuse_data: Dict[str, Any]) -> str:
    """Calculates overall analyst verdict based on aggregated telemetry."""
    vt_malicious = vt_data.get("malicious", 0) if isinstance(vt_data, dict) else 0
    abuse_score = abuse_data.get("abuse_confidence_score", 0) if isinstance(abuse_data, dict) else 0

    if vt_malicious >= 5 or abuse_score >= 50:
        return "MALICIOUS (High Confidence)"
    elif vt_malicious > 0 or abuse_score > 20:
        return "SUSPICIOUS (Further Investigation Required)"
    return "BENIGN / LOW RISK"


def format_markdown_report(results: List[Dict[str, Any]], output_path: str):
    """Outputs a clean Markdown report suitable for ticket attachments or GitHub portfolios."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Automated SOC Threat Intelligence Triage Report\n\n")
        f.write(f"**Generated At:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
        f.write("| Indicator | Type | Verdict | VirusTotal Malicious | Abuse Confidence Score | Context / Owner |\n")
        f.write("|---|---|---|---|---|---|\n")

        for item in results:
            ioc = item["ioc"]
            ioc_type = item["type"]
            verdict = item["verdict"]
            vt = item.get("virustotal", {})
            abuse = item.get("abuseipdb", {})

            vt_mal = vt.get("malicious", "N/A") if isinstance(vt, dict) and "malicious" in vt else "N/A"
            abuse_score = f"{abuse.get('abuse_confidence_score')}%" if isinstance(abuse, dict) and "abuse_confidence_score" in abuse else "N/A"
            owner = vt.get("meaningful_name") or abuse.get("isp") or "N/A"

            f.write(f"| `{ioc}` | {ioc_type} | **{verdict}** | {vt_mal} engines | {abuse_score} | {owner} |\n")

    print(f"\n[+] Markdown report successfully written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Automated SOC Threat Intelligence Enrichment & IoC Triage Tool"
    )
    parser.add_argument("--ioc", help="Single IP address or File Hash (MD5, SHA1, SHA256)")
    parser.add_argument("--file", help="Path to text file containing list of IoCs (one per line)")
    parser.add_argument("--vt-key", default=os.getenv("VT_API_KEY"), help="VirusTotal API Key")
    parser.add_argument("--abuse-key", default=os.getenv("ABUSEIPDB_API_KEY"), help="AbuseIPDB API Key")
    parser.add_argument("--output", default="triage_report.md", help="Path to export Markdown report")

    args = parser.parse_args()

    iocs = []
    if args.ioc:
        iocs.append(args.ioc.strip())
    elif args.file:
        if not os.path.exists(args.file):
            print(f"[-] Error: Input file '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "r") as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        # Fallback to interactive mode or sample demo IoCs
        print("[*] No IoC input specified. Running in demonstration mode with test indicators...")
        iocs = [
            "8.8.8.8",
            "185.220.101.5",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]

    print(f"[*] Processing {len(iocs)} Indicator(s) of Compromise...\n")
    results = []

    for ioc in iocs:
        ioc_type = detect_ioc_type(ioc)
        print(f"--> Analyzing [{ioc_type}]: {ioc}")

        vt_res = query_virustotal(ioc, ioc_type, args.vt_key) if args.vt_key else {"error": "No VT Key Provided"}
        abuse_res = query_abuseipdb(ioc, args.abuse_key) if (args.abuse_key and ioc_type == "IP") else {"error": "N/A for Hashes or No Key"}

        verdict = assess_verdict(vt_res, abuse_res)

        results.append({
            "ioc": ioc,
            "type": ioc_type,
            "virustotal": vt_res,
            "abuseipdb": abuse_res,
            "verdict": verdict
        })

        print(f"    Verdict: {verdict}\n")
        time.sleep(1)  # Respect public API rate limits (e.g. 4 req/min on free VT)

    format_markdown_report(results, args.output)


if __name__ == "__main__":
    main()
