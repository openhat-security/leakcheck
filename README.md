# leakcheck

Domain reconnaissance + live-website secret scanning, in one script.

Frontend build tools quietly bake secrets into public JavaScript bundles, and a domain's wider surface (forgotten subdomains, open ports, sloppy headers, archived URLs) leaks just as much. `leakcheck.sh` first maps the surface, then mirrors what a browser or an attacker can download and scans all of it with **TruffleHog** (800+ detectors, live verification) and **Gitleaks** (150+ rules).

## Install

```bash
brew install trufflehog gitleaks wget jq
# curl, dig, whois are usually already present
curl -fsSLO https://raw.githubusercontent.com/openhat-security/leakcheck/main/leakcheck.sh
chmod +x leakcheck.sh
```

On Linux, install `trufflehog` and `gitleaks` from their GitHub releases, and `wget`, `jq`, `curl`, `dig` (`dnsutils`/`bind-tools`) and `whois` from your package manager.

### Optional tools (more recon when present)

`nmap`, `ffuf` or `gobuster`, `nuclei`, `testssl.sh`, `subfinder`/`amass`/`assetfinder`/`findomain`, `kingfisher` or `detect-secrets`. The script auto-detects each and skips what's missing. Set `SHODAN_API_KEY` to enable Shodan lookups.

## Usage

```bash
./leakcheck.sh https://example.com
./leakcheck.sh --active https://example.com          # add port scan, dir brute, nuclei, subdomain brute, AXFR
./leakcheck.sh https://app.example.com https://admin.example.com
./leakcheck.sh https://example.com && echo clean || echo "LEAKS FOUND"
./leakcheck.sh --help
```

Passive recon runs by default. `--active` adds scans that touch the target directly (port scanning, directory brute force, nuclei, subdomain brute, zone-transfer attempts) — only run it against assets you're authorized to test.

## What it does

**Recon (passive, default)**

1. **DNS** — every record type, DNSSEC, wildcard detection, reverse DNS.
2. **Subdomains** — Certificate Transparency (crt.sh, certspotter), plus subfinder/amass/assetfinder/findomain if installed.
3. **Ownership** — WHOIS for the domain and each resolved IP, ASN/BGP lookup.
4. **HTTP posture** — security headers, allowed HTTP methods, CORS origin reflection.
5. **TLS** — certificate dates, issuer and SANs via `openssl` (full audit with `testssl.sh` in active mode).
6. **OSINT** — Wayback Machine URLs, urlscan.io, Shodan (with `SHODAN_API_KEY`).
7. **GraphQL** — introspection check on `/graphql`.

**Recon (active, `--active`)**

8. DNS zone transfer (AXFR) against each nameserver.
9. Subdomain brute force (high-signal wordlist).
10. Port scan + service detection (`nmap`), directory brute force (`ffuf`/`gobuster`), `nuclei` templates (exposures, misconfig, CVEs).

**Crawl + scan (always)**

11. Mirrors each URL two levels deep on the same domain: HTML, JS, CSS, JSON, sourcemaps.
12. Fetches `.map` sourcemaps for every JS file, since they often contain original source.
13. Probes accidental exposures: `/.env*`, `/.git/config`, `/__/firebase/init.json`, `firebase.json`, `asset-manifest.json` and similar.
14. Runs TruffleHog (live key verification) and Gitleaks, plus Kingfisher or detect-secrets if installed. All recon output is scanned too, so secrets in archived URLs or exposed files surface.
15. Flags shell environment variables baked into bundles, such as `HOME`, `PATH` and `GH_TOKEN` appearing in JS.

Secrets are never printed in full; output shows only the first few characters.

## Output

| Tag | Meaning |
|---|---|
| `[LIVE]` | The provider confirmed the key works. Rotate it now. |
| `[unverified]` | The value matched a pattern but wasn't confirmed live. Firebase `AIza…` web keys are public by design. |

Recon warnings (open zone transfer, wildcard DNS, reflected CORS, etc.) are summarized under **Recon findings** at the end of the run.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing found |
| `1` | Bad usage or missing tools |
| `2` | Findings |

Because of these exit codes, it can run as a CI gate after deploys.

## If it finds something

1. Revoke or rotate the key at the provider first. Deleting it from the site isn't enough, because old bundles stay cached on CDNs and old hosting releases.
2. Check the provider's audit logs for use of the key.
3. Fix the build so only intended public variables reach the client.
4. Redeploy, delete old hosting releases, and run `leakcheck.sh` again.

## Legal

Only scan domains and sites you own or are explicitly authorized to test. Active mode performs intrusive scanning — get written authorization first.

## License

MIT © OpenHat Security
