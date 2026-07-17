#!/usr/bin/env python3
"""
reconwrap - passive subdomain enumeration (crt.sh + certspotter) + gated
active port scanning.

Design principle: passive recon never automatically feeds into active
scanning (nmap). Scanning a target always requires an explicit,
separately-confirmed target and a "yes", so the tool can never silently
escalate from "just looking up public records" into "scanning
infrastructure you don't have permission to touch."

Two independent certificate-transparency sources are queried for
subdomains so a single service's outage (crt.sh in particular is prone
to this) doesn't take down the whole lookup.

Usage:
    python reconwrap.py subdomains nmap.org
    python reconwrap.py scan scanme.nmap.org --top-ports 100
    python reconwrap.py scan scanme.nmap.org --top-ports 100 --yes
    python reconwrap.py subdomains nmap.org --json
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests


def _query_crtsh(domain: str, timeout: int = 15, retries: int = 3) -> list[str] | None:
    """
    crt.sh certificate transparency lookup. Returns None on total failure,
    distinct from an empty list (which means "queried fine, found nothing").
    crt.sh is a single, frequently-overloaded service, hence the retries.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            break
        except requests.RequestException as e:
            if attempt == retries:
                print(f"[!] crt.sh failed after {retries} attempts: {e}", file=sys.stderr)
                return None
            wait = 2**attempt
            print(f"[!] crt.sh error (attempt {attempt}/{retries}), retrying in {wait}s: {e}", file=sys.stderr)
            time.sleep(wait)

    try:
        records = resp.json()
    except ValueError:
        print("[!] crt.sh returned unparseable data", file=sys.stderr)
        return None

    names = set()
    for r in records:
        for name in r.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*."):
                names.add(name)
    return sorted(names)


def _query_certspotter(domain: str, timeout: int = 15) -> list[str] | None:
    """
    Cert Spotter (SSLMate), a second, independently-run CT log aggregator.
    Free tier allows a limited number of unauthenticated queries per hour,
    no API key needed. Separate infrastructure from crt.sh, so an outage
    on one doesn't take down the other.
    """
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 429:
            print("[!] certspotter: unauthenticated rate limit hit for this hour", file=sys.stderr)
            return None
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] certspotter failed: {e}", file=sys.stderr)
        return None

    try:
        records = resp.json()
    except ValueError:
        print("[!] certspotter returned unparseable data", file=sys.stderr)
        return None

    names = set()
    for r in records:
        for name in r.get("dns_names", []):
            name = name.strip().lower()
            if name and not name.startswith("*."):
                names.add(name)
    return sorted(names)


def get_subdomains(domain: str) -> tuple[list[str], dict[str, bool]]:
    """
    Queries crt.sh and certspotter, merges and dedupes results.
    Returns (sorted_subdomains, status), where status maps each source
    name to whether it actually answered, so a genuine "nothing found"
    is never confused with "every source failed."
    """
    combined = set()
    status = {}

    crtsh_result = _query_crtsh(domain)
    status["crt.sh"] = crtsh_result is not None
    if crtsh_result:
        combined.update(crtsh_result)

    certspotter_result = _query_certspotter(domain)
    status["certspotter"] = certspotter_result is not None
    if certspotter_result:
        combined.update(certspotter_result)

    return sorted(combined), status


def check_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def scan_target(target: str, top_ports: int = 100, timeout: int = 300) -> dict:
    """
    Active port scan via nmap, output parsed from XML.
    Caller is responsible for confirming authorization before calling this.
    """
    if not check_nmap_available():
        print(
            "[!] nmap not found on PATH. Install it from https://nmap.org/download.html, "
            "then open a NEW terminal window so PATH updates.",
            file=sys.stderr,
        )
        sys.exit(1)

    cmd = ["nmap", "-Pn", "-sV", f"--top-ports={top_ports}", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] nmap failed: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"[!] nmap timed out after {timeout}s", file=sys.stderr)
        sys.exit(1)

    return parse_nmap_xml(result.stdout, target)


def parse_nmap_xml(xml_output: str, target: str) -> dict:
    root = ET.fromstring(xml_output)
    ports_found = []

    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports_found.append(
                {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else "unknown",
                    "version": (service.get("product", "") + " " + service.get("version", "")).strip()
                    if service is not None
                    else "",
                }
            )

    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_ports": ports_found,
    }


def confirm_scan(target: str, auto_yes: bool) -> bool:
    print(f"\n[!] About to actively scan: {target}")
    print("[!] Only run this against hosts you own or are explicitly authorized to test.")
    print("[!] scanme.nmap.org is the one public host the Nmap project permits for this.\n")
    if auto_yes:
        return True
    answer = input(f"Type 'yes' to confirm you're authorized to scan {target}: ").strip().lower()
    return answer == "yes"


def print_subdomain_results(domain: str, subs: list[str], status: dict[str, bool]):
    sources_line = ", ".join(f"{name}: {'ok' if ok else 'failed'}" for name, ok in status.items())
    print(f"\n== Subdomains for {domain} ==")
    print(f"Sources -> {sources_line}")
    if not subs:
        reason = "none found" if any(status.values()) else "all sources failed, try again shortly"
        print(f"  ({reason})")
    for s in subs:
        print(f"  {s}")
    print(f"\nTotal: {len(subs)}\n")


def print_scan_results(result: dict):
    print(f"\n== Port scan: {result['target']} ==")
    print(f"Scanned at: {result['scanned_at']}")
    if not result["open_ports"]:
        print("  No open ports found in the scanned range.")
    for p in result["open_ports"]:
        version = f" ({p['version']})" if p["version"] else ""
        print(f"  {p['port']}/{p['protocol']}  {p['service']}{version}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Passive recon + gated active port scanning.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sub = sub.add_parser("subdomains", help="Passive subdomain enumeration via crt.sh + certspotter")
    p_sub.add_argument("domain")
    p_sub.add_argument("--json", action="store_true")

    p_scan = sub.add_parser("scan", help="Active port scan (requires explicit confirmation)")
    p_scan.add_argument("target")
    p_scan.add_argument("--top-ports", type=int, default=100)
    p_scan.add_argument("--yes", action="store_true", help="Skip the interactive confirmation prompt")
    p_scan.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.command == "subdomains":
        subs, status = get_subdomains(args.domain)
        if args.json:
            print(json.dumps({"domain": args.domain, "subdomains": subs, "sources": status}, indent=2))
        else:
            print_subdomain_results(args.domain, subs, status)

    elif args.command == "scan":
        if not confirm_scan(args.target, args.yes):
            print("[!] Not confirmed, aborting.")
            sys.exit(1)
        result = scan_target(args.target, top_ports=args.top_ports)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_scan_results(result)


if __name__ == "__main__":
    main()