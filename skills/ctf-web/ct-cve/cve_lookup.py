#!/usr/bin/env python3
"""
CVE CTF Lookup Tool — NVD API v2.0 + GitHub PoC search + searchsploit

Usage:
    python3 cve_lookup.py CVE-2024-12345
    python3 cve_lookup.py CVE-2024-12345 --poc
    python3 cve_lookup.py CVE-2024-12345 --full
"""

import argparse
import json
import subprocess
import sys
import urllib.request
import urllib.parse

TIMEOUT = 15
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def nvd_lookup(cve_id: str) -> dict:
    url = f"{NVD_API}?cveId={cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cve-ctf-lookup/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"[!] NVD lookup failed: {e}")
        return {}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"[-] CVE not found in NVD: {cve_id}")
        return {}

    cve = vulns[0]["cve"]

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "No description"
    )

    metrics = cve.get("metrics", {})
    cvss_data = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key, [])
        if m:
            cvss_data = m[0].get("cvssData", {})
            break

    cwes = [
        w["description"][0]["value"]
        for w in cve.get("weaknesses", [])
        if w.get("description")
    ]

    refs = [r["url"] for r in cve.get("references", [])]

    cpes = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.append({
                        "product": match.get("criteria", ""),
                        "version_start": match.get("versionStartIncluding", match.get("versionStartExcluding", "")),
                        "version_end": match.get("versionEndIncluding", match.get("versionEndExcluding", "")),
                    })

    return {
        "id": cve.get("id"),
        "published": cve.get("published", "")[:10],
        "modified": cve.get("lastModified", "")[:10],
        "description": desc,
        "cvss_score": cvss_data.get("baseScore"),
        "cvss_severity": cvss_data.get("baseSeverity"),
        "cvss_vector": cvss_data.get("vectorString"),
        "cwes": cwes,
        "cpes": cpes[:5],
        "references": refs,
    }


def print_nvd_summary(info: dict):
    print(f"\n{'='*60}")
    print(f"  {info['id']}")
    print(f"{'='*60}")
    print(f"  Published  : {info['published']}")
    print(f"  Modified   : {info['modified']}")
    print(f"  CVSS Score : {info.get('cvss_score', 'N/A')} ({info.get('cvss_severity', 'N/A')})")
    print(f"  Vector     : {info.get('cvss_vector', 'N/A')}")
    print(f"  CWE(s)     : {', '.join(info['cwes']) or 'None'}")
    print()
    print(f"  DESCRIPTION:")
    desc = info["description"]
    for i in range(0, len(desc), 90):
        print(f"    {desc[i:i+90]}")
    print()
    if info["cpes"]:
        print(f"  AFFECTED PRODUCTS:")
        for c in info["cpes"]:
            crit = c["product"].split(":")
            product = ":".join(crit[3:5]) if len(crit) >= 5 else c["product"]
            ver = f"{c['version_start']} - {c['version_end']}".strip(" -")
            print(f"    {product}  [{ver}]" if ver else f"    {product}")
    print()
    if info["references"]:
        print(f"  REFERENCES (top 5):")
        for r in info["references"][:5]:
            print(f"    {r}")
    print()


def print_poc_links(cve_id: str):
    year, num = cve_id.split("-")[1], cve_id.split("-")[2]
    q = urllib.parse.quote(cve_id)
    print(f"\n[*] PoC Hunt Links — {cve_id}")
    print(f"    GitHub        : https://github.com/search?q={q}&type=repositories&sort=updated")
    print(f"    Exploit-DB    : https://www.exploit-db.com/search?cve={year}-{num}")
    print(f"    sploitus      : https://sploitus.com/?query={q}")
    print(f"    PacketStorm   : https://packetstormsecurity.com/search/?q={q}")
    print(f"    NVD           : https://nvd.nist.gov/vuln/detail/{cve_id}")
    print(f"    Nuclei tmpl   : https://github.com/projectdiscovery/nuclei-templates/search?q={q}")
    print()

    print("[*] Running searchsploit...")
    try:
        result = subprocess.run(
            ["searchsploit", cve_id],
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout.strip()
        if out and "No results" not in out:
            print(out)
        else:
            print("    [-] No searchsploit results")
    except FileNotFoundError:
        print("    [!] searchsploit not installed")
    except subprocess.TimeoutExpired:
        print("    [!] searchsploit timeout")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="CVE CTF Lookup — NVD + PoC search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cve_lookup.py CVE-2024-12345
  python3 cve_lookup.py CVE-2024-12345 --poc
  python3 cve_lookup.py CVE-2024-12345 --full
        """
    )
    parser.add_argument("cve_id", help="CVE ID (e.g. CVE-2024-12345)")
    parser.add_argument("--poc", action="store_true", help="Show PoC search links + searchsploit")
    parser.add_argument("--full", action="store_true", help="NVD summary + PoC links + all references")
    args = parser.parse_args()

    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        print(f"[!] Invalid format. Expected CVE-YYYY-NNNNN, got: {cve_id}")
        sys.exit(2)

    info = nvd_lookup(cve_id)
    if not info:
        sys.exit(2)

    print_nvd_summary(info)

    if args.poc or args.full:
        print_poc_links(cve_id)

    if args.full and len(info["references"]) > 5:
        print(f"  ALL REFERENCES ({len(info['references'])}):")
        for r in info["references"]:
            print(f"    {r}")


if __name__ == "__main__":
    main()
