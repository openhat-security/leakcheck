# leakcheck

Full domain reconnaissance + live-website secret scanning, in one script.

Frontend build tools quietly bake secrets into public JavaScript bundles, and a domain's wider surface — forgotten subdomains, dangling CNAMEs, open ports, missing email auth, sloppy headers, archived URLs, open buckets — leaks just as much. `leakcheck.sh` maps the whole surface first, then mirrors what a browser or an attacker can download and scans all of it with **TruffleHog** (800+ detectors, live verification) and **Gitleaks** (150+ rules). Every recon artifact lands under `site/`, so the scanners read it too.

## Install

```bash
brew install trufflehog gitleaks wget jq
# curl, dig, whois are usually already present
curl -fsSLO https://raw.githubusercontent.com/openhat-security/leakcheck/main/leakcheck.sh
chmod +x leakcheck.sh
```

On Linux, install `trufflehog` and `gitleaks` from their GitHub releases, and `wget`, `jq`, `curl`, `dig` (`dnsutils`/`bind-tools`) and `whois` from your package manager.

### Optional tools (more recon when present)

The script auto-detects each and skips what's missing:

- **Active scanning:** `nmap`, `nc`, `ffuf` or `gobuster`, `nuclei`, `testssl.sh`
- **Fingerprinting:** `wafw00f`, `whatweb` or `wappalyzer`
- **Subdomains:** `subfinder`, `amass`, `assetfinder`, `findomain`
- **URL harvesting:** `gau`, `waybackurls`
- **JS extraction:** `jsluice`, `linkfinder`, `getJS`
- **Extra secret scanners:** `kingfisher`, `nosey_parker`, `detect-secrets`

Set `SHODAN_API_KEY` to enable Shodan lookups.

## Usage

```bash
./leakcheck.sh https://example.com
./leakcheck.sh --active https://example.com          # add intrusive scans (ports, banners, dir brute, nuclei)
./leakcheck.sh -o out https://example.com            # save crawl + recon + findings.csv to ./out
./leakcheck.sh --no-subs https://example.com         # scan only the given URLs, skip discovered subdomains
./leakcheck.sh https://app.example.com https://admin.example.com
./leakcheck.sh https://example.com && echo clean || echo "LEAKS FOUND"
./leakcheck.sh --help
```

### Flags

| Flag | Effect |
|---|---|
| `--active` | Adds scans that touch the target directly: port/banner scan, directory brute force, nuclei, zone-transfer attempts, subdomain brute. Authorized targets only. |
| `-o DIR` / `--out DIR` | Keeps the crawled `site/` mirror and every `recon_<domain>/` artifact in `DIR`, and writes `findings.csv` there when anything is flagged. Without `-o`, all crawled files are deleted at the end and only the summary prints. |
| `--no-subs` | Scans only the URLs you pass. By default, every live subdomain discovered during recon is crawled and scanned too. |

Passive recon runs by default. **Subdomains discovered via Certificate Transparency (and optional tools) are liveness-probed and the reachable ones are automatically crawled and scanned.** Use `--no-subs` to limit the scan to the exact URLs you pass.

## What it does

### Recon — passive (default)

1. **DNS** — every record type, full `ANY` dump, DNSSEC, wildcard detection, reverse DNS.
2. **Email auth** — SPF, DMARC, common DKIM selectors, BIMI, MX; warns when SPF/DMARC are absent.
3. **Subdomains** — Certificate Transparency (crt.sh, certspotter), plus subfinder/amass/assetfinder/findomain if installed.
4. **Subdomain takeover** — flags dangling CNAMEs pointing at unclaimed providers (GitHub Pages, S3, Heroku, Netlify, Shopify, etc.).
5. **Ownership** — WHOIS for the domain and each resolved IP, ASN/BGP lookup, IP geolocation.
6. **HTTP posture** — security headers (and which are missing), allowed HTTP methods (flags TRACE/XST), CORS origin reflection, WAF detection.
7. **Tech stack** — `Server`/`X-Powered-By`, whatweb/wappalyzer fingerprint, favicon hash for Shodan pivoting.
8. **TLS** — certificate dates, issuer and SANs via `openssl`.
9. **URLs** — robots.txt, sitemap.xml, Wayback Machine, gau/waybackurls, urlscan.io.
10. **OSINT** — Shodan (with `SHODAN_API_KEY`), open S3/GCS cloud-bucket name guesses.
11. **GraphQL** — introspection probe on `/graphql`.

### Recon — active (`--active`)

12. DNS zone transfer (AXFR) against each nameserver.
13. Subdomain brute force (high-signal wordlist), merged into the subdomain list.
14. Port scan + service detection (`nmap`) and banner grabbing (`nc`) on open ports.
15. Directory brute force (`ffuf`/`gobuster`), `nuclei` templates (exposures, misconfig, CVEs), full TLS audit (`testssl.sh`).

### Crawl + scan (always)

16. Mirrors each URL two levels deep on the same domain: HTML, JS, CSS, JSON, sourcemaps.
17. Fetches `.map` sourcemaps for every JS file, since they often contain original source.
18. Probes accidental exposures: `/.env*`, `/.git/config`, `/__/firebase/init.json`, `firebase.json`, `asset-manifest.json` and similar.
19. Extracts endpoints and secrets from JS bundles with jsluice/LinkFinder/getJS if present.
20. Runs TruffleHog (live key verification) and Gitleaks, plus Kingfisher, Nosey Parker, or detect-secrets if installed. All recon output is scanned too.
21. Flags shell environment variables baked into bundles, such as `HOME`, `PATH` and `GH_TOKEN` appearing in JS.

Secrets are never printed in full; output shows only the first few characters. Recon warnings (open zone transfer, wildcard DNS, reflected CORS, missing SPF/DMARC, possible takeover, open buckets, etc.) are summarized under **Recon findings** at the end of the run.

## Output files (`-o DIR`)

With `-o DIR`, the run leaves behind:

- `DIR/site/` — the full crawled mirror plus `recon_<domain>/` directories (DNS, subdomains, WHOIS, headers, TLS, etc.).
- `DIR/th.txt`, `DIR/gl.txt`, `DIR/th.json`, `DIR/gl.json` — raw TruffleHog/Gitleaks results.
- `DIR/findings.csv` — one row per finding (written only when something is flagged), columns: `type,detail,file,status,value`. `type` is `secret:trufflehog`, `secret:gitleaks`, `bundle:shell-env`, `exposed-file`, or `recon-warning`; `status` is `LIVE`, `unverified`, `match`, or `warning`. The `value` column contains the **full raw secret** (properly CSV-escaped) so it can be fed straight into rotation tooling — treat `findings.csv` as sensitive and do not commit it.

## Output

| Tag | Meaning |
|---|---|
| `[LIVE]` | The provider confirmed the key works. Rotate it now. |
| `[unverified]` | The value matched a pattern but wasn't confirmed live. Firebase `AIza…` web keys are public by design. |

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
