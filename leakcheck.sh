#!/usr/bin/env bash
# leakcheck.sh: domain recon + live-web secret scanning.
# Maps a domain's surface (DNS, subdomains, ports, HTTP/TLS posture), mirrors what a
# browser or attacker can download, then scans everything with TruffleHog (800+
# detectors, live-verified) and Gitleaks (150+ rules). Recon output is fed to the
# scanners too, so secrets found in Wayback URLs, sourcemaps, or exposed files surface.

usage() {
  cat <<'EOF'
leakcheck.sh: domain recon + scan live websites for leaked secrets/tokens

USAGE
  leakcheck.sh [--active] <url> [url ...]
  leakcheck.sh -h | --help

EXAMPLES
  leakcheck.sh https://example.com
  leakcheck.sh --active https://example.com          # add port scan, dir brute, nuclei, subdomain brute
  leakcheck.sh https://app.example.com https://admin.example.com
  leakcheck.sh https://example.com && echo clean || echo "LEAKS FOUND"

WHAT IT DOES
  Recon (passive, default):
    - DNS: every record type, DNSSEC, wildcard check, reverse DNS
    - Subdomains: Certificate Transparency (crt.sh, certspotter) + optional tools
    - Ownership: WHOIS (domain + resolved IPs), ASN/BGP
    - HTTP posture: security headers, HTTP methods, CORS reflection
    - TLS: certificate dates/issuer/SANs (openssl)
    - OSINT: Wayback Machine URLs, urlscan.io, Shodan (if SHODAN_API_KEY set)
  Recon (active, with --active):
    - DNS zone transfer (AXFR), subdomain brute force
    - Port scan + service/banner (nmap), directory brute (ffuf/gobuster), nuclei templates
  Crawl + scan (always):
    - Mirrors each URL 2 levels deep: HTML, JS, CSS, JSON, sourcemaps
    - Probes accidental exposures: /.env*, /.git/config, firebase init, etc.
    - Runs TruffleHog (live key verification) + Gitleaks, plus optional
      Kingfisher / detect-secrets if installed
    - Flags shell env baked into bundles (HOME/PATH/GH_TOKEN in JS)
  Secrets are never printed in full, only the first few chars.

OUTPUT
  [LIVE]        key verified working with the provider -> rotate NOW
  [unverified]  matched a pattern but not confirmed live (e.g. public Firebase AIza keys)

EXIT CODES
  0 = nothing found    2 = findings    1 = bad usage / missing tools

REQUIRES
  brew install trufflehog gitleaks wget jq      # core (also need curl, dig, whois)
OPTIONAL (enable more recon when present)
  nmap ffuf gobuster nuclei testssl.sh subfinder amass assetfinder findomain kingfisher detect-secrets
EOF
}

# --- arg parsing ---
ACTIVE=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --active) ACTIVE=1 ;;
    -h|--help) usage; exit 1 ;;
    -*) echo "error: unknown flag '$a'"; echo; usage; exit 1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]:-}"
[ "${1:-}" = "" ] && { usage; exit 1; }
for u in "$@"; do [[ "$u" =~ ^https?:// ]] || { echo "error: '$u' must start with http:// or https://"; echo; usage; exit 1; }; done

# --- dependency check ---
for t in trufflehog gitleaks wget jq curl dig whois; do
  command -v "$t" >/dev/null || { echo "error: missing '$t'. Core deps: brew install trufflehog gitleaks wget jq (curl, dig, whois are usually preinstalled)"; exit 1; }
done

set -uo pipefail
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
UA="Mozilla/5.0 leakcheck"
cd "$TMP" || exit 1

have() { command -v "$1" >/dev/null 2>&1; }

recon_domain() {
  local BASE="$1" DOMAIN="$2"
  local OUT="site/recon_${DOMAIN//[^a-zA-Z0-9._-]/_}"
  mkdir -p "$OUT"
  echo ""
  echo "=== RECON: $DOMAIN ==="

  # [1] DNS records (all types)
  echo "  [dns] records"
  for rt in A AAAA CNAME MX TXT NS SOA SRV CAA DNSKEY DS NSEC NSEC3 SSHFP TLSA SVCB HTTPS SMIMEA; do
    r=$(dig +short "$DOMAIN" "$rt" 2>/dev/null)
    [ -n "$r" ] && printf '%s: %s\n' "$rt" "$r" >> "$OUT/dns_records.txt"
  done
  dig "$DOMAIN" ANY +noall +answer 2>/dev/null > "$OUT/dns_any.txt"

  # [2] DNSSEC
  dig +dnssec "$DOMAIN" 2>/dev/null | grep -E "RRSIG|DNSKEY|NSEC" > "$OUT/dnssec.txt" 2>/dev/null
  have delv && delv "$DOMAIN" 2>/dev/null | grep -E "fully validated|insecurity|Bogus" >> "$OUT/dnssec.txt" 2>/dev/null

  # [3] Wildcard check
  local wc; wc=$(dig +short "nonexistent-$(date +%s).${DOMAIN}" A 2>/dev/null)
  [ -n "$wc" ] && echo "WARNING: wildcard DNS -> $wc (all subdomains resolve)" > "$OUT/wildcard.txt"

  # [4] Reverse DNS on first A record
  local ip; ip=$(dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
  if [ -n "$ip" ]; then
    local ptr; ptr=$(dig +short -x "$ip" 2>/dev/null)
    echo "$ip -> ${ptr:-no PTR}" > "$OUT/reverse_dns.txt"
  fi

  # [5] Subdomains - passive (Certificate Transparency)
  echo "  [subs] certificate transparency"
  curl -sf -A "$UA" "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr ',' '\n' | sort -u > "$OUT/subs_crtsh.txt"
  curl -sf -A "$UA" "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" 2>/dev/null \
    | jq -r '.[].dns_names[]' 2>/dev/null | sort -u > "$OUT/subs_certspotter.txt"
  for tool in subfinder amass assetfinder findomain; do
    if have "$tool"; then
      echo "  [subs] $tool"
      case "$tool" in
        subfinder)   subfinder -d "$DOMAIN" -silent -all 2>/dev/null > "$OUT/subs_${tool}.txt" ;;
        amass)       amass enum -passive -d "$DOMAIN" -timeout 10 2>/dev/null > "$OUT/subs_${tool}.txt" ;;
        assetfinder) assetfinder "$DOMAIN" 2>/dev/null > "$OUT/subs_${tool}.txt" ;;
        findomain)   findomain -t "$DOMAIN" -q 2>/dev/null > "$OUT/subs_${tool}.txt" ;;
      esac
    fi
  done
  cat "$OUT"/subs_*.txt 2>/dev/null | sort -u | grep -v '^$' > "$OUT/subdomains_all.txt"

  # [6] WHOIS (domain + resolved IPs) and ASN
  echo "  [whois] domain + IPs"
  whois "$DOMAIN" 2>/dev/null > "$OUT/whois_domain.txt"
  for ip in $(dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9.]+$'); do
    whois "$ip" 2>/dev/null | grep -iE '^(netname|orgname|org-name|descr|country|cidr|inetnum|origin|route)' >> "$OUT/whois_ip.txt"
    curl -sf "https://bgp.tools/api/v1/prefixes?prefix=$ip/32" 2>/dev/null | jq -r '.[]? | "\(.prefix) -> AS\(.asn)"' 2>/dev/null >> "$OUT/asn.txt"
  done

  # [7] HTTP security headers, methods, CORS
  echo "  [http] headers / methods / cors"
  curl -sI -A "$UA" "$BASE" 2>/dev/null \
    | grep -iE '^(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|set-cookie|server|x-powered-by):' > "$OUT/headers.txt"
  for m in OPTIONS TRACE PUT DELETE PATCH; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" -A "$UA" "$BASE" 2>/dev/null)
    echo "$m: $code" >> "$OUT/http_methods.txt"
  done
  local acao; acao=$(curl -sI -A "$UA" -H "Origin: https://evil.example" "$BASE" 2>/dev/null | grep -i '^access-control-allow-origin:')
  if echo "$acao" | grep -qi 'evil.example\|\*'; then
    echo "WARNING: CORS reflects arbitrary origin -> $acao" > "$OUT/cors.txt"
  fi

  # [8] TLS certificate
  echo "  [tls] certificate"
  if have openssl; then
    echo | openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null \
      | openssl x509 -noout -dates -subject -issuer -ext subjectAltName 2>/dev/null > "$OUT/tls_cert.txt"
  fi
  if [ "$ACTIVE" = "1" ] && have testssl.sh; then
    echo "  [tls] testssl.sh (active)"
    testssl.sh --quiet --color 0 "$DOMAIN" 2>/dev/null > "$OUT/testssl.txt"
  fi

  # [9] OSINT - Wayback, urlscan, Shodan
  echo "  [osint] wayback / urlscan / shodan"
  curl -sf "http://web.archive.org/cdx/search/cdx?url=${DOMAIN}*&output=text&fl=original&collapse=urlkey&limit=500" 2>/dev/null > "$OUT/wayback.txt"
  curl -sf -A "$UA" "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=100" 2>/dev/null | jq -r '.results[]?.page.url' 2>/dev/null > "$OUT/urlscan.txt"
  if [ -n "${SHODAN_API_KEY:-}" ]; then
    curl -sf "https://api.shodan.io/dns/domain/${DOMAIN}?key=${SHODAN_API_KEY}" 2>/dev/null | jq . > "$OUT/shodan_dns.json" 2>/dev/null
    [ -n "${ip:-}" ] && curl -sf "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" 2>/dev/null | jq . > "$OUT/shodan_host.json" 2>/dev/null
  fi

  # [10] GraphQL introspection
  local gql; gql=$(curl -sf -A "$UA" -X POST "$BASE/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"{__schema{types{name}}}"}' 2>/dev/null)
  echo "$gql" | grep -q '__schema\|"types"' && echo "$gql" > "$OUT/graphql_introspection.json"

  # --- ACTIVE-only phases ---
  if [ "$ACTIVE" = "1" ]; then
    # Zone transfer (AXFR)
    echo "  [active] zone transfer attempt"
    for ns in $(dig +short NS "$DOMAIN" 2>/dev/null); do
      axfr=$(dig axfr "$DOMAIN" @"$ns" +time=5 +tries=1 2>/dev/null)
      if [ -n "$axfr" ] && ! echo "$axfr" | grep -q "REFUSED\|SERVFAIL\|NOTIMP\|Transfer failed"; then
        echo "WARNING: open zone transfer on $ns" >> "$OUT/axfr.txt"
        echo "$axfr" >> "$OUT/axfr.txt"
      fi
    done

    # Subdomain brute (small high-signal list)
    echo "  [active] subdomain brute"
    for sub in www api admin dev staging stg test qa uat prod internal intranet backup db mail smtp \
               ftp sftp git gitlab jenkins ci cd build deploy vault consul grafana kibana elastic \
               redis mongo postgres mysql s3 storage cdn static assets uploads files docs wiki \
               portal dashboard login auth sso oauth idp vpn proxy gateway status health metrics \
               logs sentry webhook graphql ws v1 v2 v3 app console panel phpmyadmin adminer; do
      r=$(dig +short "${sub}.${DOMAIN}" A 2>/dev/null | grep -E '^[0-9.]+$')
      [ -n "$r" ] && echo "${sub}.${DOMAIN} -> $r" >> "$OUT/subs_bruteforce.txt"
    done
    [ -f "$OUT/subs_bruteforce.txt" ] && cat "$OUT/subs_bruteforce.txt" | awk '{print $1}' >> "$OUT/subdomains_all.txt" && sort -u "$OUT/subdomains_all.txt" -o "$OUT/subdomains_all.txt"

    # Port scan
    if have nmap; then
      echo "  [active] nmap top ports"
      nmap -sV -Pn --top-ports 200 --open -T4 -oN "$OUT/nmap.txt" "$DOMAIN" >/dev/null 2>&1
    fi

    # Directory brute
    local wl=""
    for cand in /usr/share/wordlists/dirb/common.txt /opt/homebrew/share/wordlists/dirb/common.txt /usr/share/seclists/Discovery/Web-Content/common.txt; do
      [ -f "$cand" ] && { wl="$cand"; break; }
    done
    if [ -n "$wl" ]; then
      if have ffuf; then
        echo "  [active] ffuf dir brute"
        ffuf -u "$BASE/FUZZ" -w "$wl" -mc 200,204,301,302,307,401,403,500 -of json -o "$OUT/ffuf.json" -s 2>/dev/null
      elif have gobuster; then
        echo "  [active] gobuster dir brute"
        gobuster dir -q -u "$BASE" -w "$wl" -o "$OUT/gobuster.txt" 2>/dev/null
      fi
    fi

    # Nuclei
    if have nuclei; then
      echo "  [active] nuclei (exposures/misconfig/cves)"
      nuclei -u "$BASE" -t http/exposures/ -t http/misconfiguration/ -t http/cves/ \
        -severity medium,high,critical -jsonl -o "$OUT/nuclei.jsonl" -silent 2>/dev/null
    fi
  fi
}

mkdir -p site
for u in "$@"; do
  BASE=$(echo "$u" | sed -E 's#(https?://[^/]+).*#\1#')
  DOMAIN=$(echo "$BASE" | sed -E 's#https?://##')

  recon_domain "$BASE" "$DOMAIN"

  wget -q -e robots=off -U "$UA" -r -l 2 -np -H -D "$DOMAIN" \
       -A 'html,htm,js,mjs,cjs,css,json,map,txt,env,xml,webmanifest' -P site "$u"
  for p in .env .env.local .env.production .env.development .git/config config.js env.js settings.json \
           asset-manifest.json manifest.json firebase.json __/firebase/init.json __/firebase/init.js \
           .well-known/security.txt robots.txt sitemap.xml _next/static/chunks/webpack.js; do
    curl -sfL -A "$UA" "$BASE/$p" -o "site/exposed_$(echo "$p" | tr '/' '_')" 2>/dev/null
  done
done

find site -name '*.js' | while read -r f; do
  rel=${f#site/}; curl -sfL -A "$UA" "https://$rel.map" -o "$f.map" 2>/dev/null
done

n=$(find site -type f | wc -l | tr -d ' ')
echo ""
echo "Scanned $n files from: $*"
echo "=== TruffleHog (verified = key is LIVE) ==="
trufflehog filesystem site --no-update --json 2>/dev/null | \
  jq -r '"[\(if .Verified then "LIVE" else "unverified" end)] \(.DetectorName)  \(.SourceMetadata.Data.Filesystem.file | sub("^site/";""))  -> \(.Raw[0:6])…"' | sort -u | tee th.txt
echo "=== Gitleaks ==="
gitleaks dir site --no-banner --redact=90 --report-format json --report-path gl.json >/dev/null 2>&1
jq -r '.[] | "[\(.RuleID)]  \(.File | sub(".*/site/";""))  -> \(.Secret[0:8])"' gl.json 2>/dev/null | sort -u | tee gl.txt
: > kf.txt
if have kingfisher; then
  echo "=== Kingfisher ==="
  kingfisher scan site --format json 2>/dev/null | jq -r '.findings[]? | "[\(.rule.id // .rule_id)]  \(.path // .file)"' 2>/dev/null | sort -u | tee kf.txt
elif have detect-secrets; then
  echo "=== detect-secrets ==="
  detect-secrets scan site 2>/dev/null | jq -r '.results | keys[]' 2>/dev/null | sort -u | tee kf.txt
fi
echo "=== Shell env baked into bundle? ==="
grep -rlE '"(HOME|USER|SHELL|PATH|CURSOR_AGENT|TERM_PROGRAM|GH_TOKEN|GITHUB_TOKEN)" *: *"' site 2>/dev/null | sed 's#^site/##' | tee env.txt
echo "=== Exposed files that returned content ==="
find site -name 'exposed_*' -size +0 | sed 's#^site/exposed_##' | grep -vE 'robots|sitemap|security.txt|manifest' | tee exp.txt
echo "=== Recon findings (warnings) ==="
grep -rhi 'WARNING' site/recon_* 2>/dev/null | sort -u | tee recon_warn.txt

live=$(grep -c '^\[LIVE\]' th.txt 2>/dev/null || true); live=${live:-0}
total=$(( $(wc -l < th.txt) + $( [ -f gl.txt ] && wc -l < gl.txt || echo 0) + $( [ -f kf.txt ] && wc -l < kf.txt || echo 0) + $(wc -l < env.txt) ))
echo "---"
if [ "$total" -eq 0 ]; then echo "✓ No secrets found"; else echo "✗ $total secret finding(s), $live LIVE. Rotate LIVE ones immediately"; exit 2; fi
