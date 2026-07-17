# Recon wrapper

A passive subdomain enumeration + gated active port scanning tool. The point isn't the individual techniques, it's keeping "look things up" and "actively scan something" as two separate steps that can't silently blur into each other.

## Problem

Most quick recon scripts chain subdomain discovery straight into port scanning for convenience. That's fine until the discovered list includes infrastructure you were never authorized to touch, at which point automation just turned passive research into an unauthorized scan.

## Approach

- **Subdomain enumeration is entirely passive.** It only reads public Certificate Transparency logs (crt.sh and certspotter), it never sends a single packet to the target itself.
- **Port scanning is active** (nmap under the hood) and is gated behind an explicit target plus a typed `yes` confirmation. The two never auto-chain, there's no code path where a subdomain result feeds straight into a scan.
- **Two independent CT log sources**, not one, so a single service's outage doesn't take the whole lookup down with it. This wasn't a hypothetical resilience feature, see the example below.

## Stack

Python 3, `requests`, nmap (via `subprocess`), XML parsing (`xml.etree.ElementTree`), `argparse`.

## Usage

```
pip install requests

# Passive subdomain enumeration, works against any domain, no permission needed
python reconwrap.py subdomains nmap.org

# Active port scan, requires nmap installed and explicit confirmation
python reconwrap.py scan scanme.nmap.org --top-ports 100

# JSON output for either command
python reconwrap.py subdomains nmap.org --json
```

## Example: subdomain enumeration surviving a live outage

Captured output from actual testing, crt.sh went down mid-run and certspotter carried the result:

```
[!] crt.sh error (attempt 1/3), retrying in 2s: 502 Server Error: Bad Gateway...
[!] crt.sh error (attempt 2/3), retrying in 4s: 502 Server Error: Bad Gateway...
[!] crt.sh failed after 3 attempts: HTTPSConnectionPool(host='crt.sh', port=443): Read timed out.

== Subdomains for nmap.org ==
Sources -> crt.sh: failed, certspotter: ok
  insecure.com
  insecure.org
  issues.nmap.com
  issues.nmap.org
  issues.npcap.com
  issues.npcap.org
  nmap.com
  nmap.net
  nmap.org
  npcap.com
  npcap.org
  seclists.com
  seclists.net
  seclists.org
  sectools.com
  sectools.net
  sectools.org
  secwiki.com
  secwiki.net
  secwiki.org
  svn.nmap.org
  www.nmap.org

Total: 22
```

## Example: gated port scan

```
python reconwrap.py scan scanme.nmap.org --top-ports 100

[!] About to actively scan: scanme.nmap.org
[!] Only run this against hosts you own or are explicitly authorized to test.
[!] scanme.nmap.org is the one public host the Nmap project permits for this.

Type 'yes' to confirm you're authorized to scan scanme.nmap.org: yes

== Port scan: scanme.nmap.org ==
Scanned at: 2026-07-17T14:05:26+00:00
  22/tcp  ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)
  80/tcp  http (Apache httpd 2.4.7)
  443/tcp  tcpwrapped
  8080/tcp  tcpwrapped
  8443/tcp  tcpwrapped
```

## Design decisions worth knowing about

- **The passive/active separation is enforced in the code, not just the docs.** There's no path from `get_subdomains()` results into `scan_target()`.
- **scanme.nmap.org is the only pre-approved active-scan target.** Scanning anything else requires you to already hold explicit authorization, the tool reminds you of that on every run rather than trusting `--yes` silently.
- **Two CT sources instead of one**, added after crt.sh's own instability turned up during development, not as a defensive afterthought.

## What I'd improve

- A third CT source for further resilience, crt.sh and certspotter both index public logs but neither is exhaustive
- Concurrent DNS resolution to check which discovered subdomains are actually live, rather than just listing certificate history
- Backoff/retry for certspotter's unauthenticated rate limit, it currently just reports the 429 and stops

## Legal note

Only run the `scan` command against hosts you own or have explicit written authorization to test. Scanning systems without authorization is a criminal offence in most jurisdictions, including the UK's Computer Misuse Act 1990.