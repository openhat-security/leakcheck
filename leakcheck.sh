#!/usr/bin/env bash
# leakcheck.sh: full domain recon + live-web secret scanning, in one file.
# Maps a domain's whole surface (DNS, email auth, subdomains, takeover risk, ports,
# banners, HTTP/TLS posture, tech stack, OSINT, archived URLs), mirrors what a browser
# or attacker can download, then scans everything with TruffleHog (800+ detectors,
# live-verified) and Gitleaks (150+ rules). All recon output lands under site/ so the
# scanners read it too: a secret in an archived URL or exposed file still surfaces.

usage() {
  cat <<'EOF'
leakcheck.sh: full domain recon + scan live websites for leaked secrets/tokens

USAGE
  leakcheck.sh [--active] [--no-subs] [-o DIR] <url> [url ...]
  leakcheck.sh -h | --help

OUTPUT DIR (-o DIR)
  Keeps the crawled site/ mirror and every recon_<domain>/ artifact in DIR, and
  writes findings.csv there when anything is flagged. Without -o, all crawled
  files are deleted when the run ends (only the summary prints).

EXAMPLES
  leakcheck.sh https://example.com
  leakcheck.sh --active https://example.com          # add intrusive scans (ports, dir brute, nuclei, banners)
  leakcheck.sh https://app.example.com https://admin.example.com
  leakcheck.sh https://example.com && echo clean || echo "LEAKS FOUND"

WHAT IT DOES
  Recon (passive, default):
    DNS            every record type + ANY dump, DNSSEC, wildcard, reverse DNS
    Email auth     SPF, DMARC, common DKIM selectors, BIMI, MX
    Subdomains     Certificate Transparency (crt.sh, certspotter) + optional tools
    Takeover       dangling-CNAME fingerprint check
    Ownership      WHOIS (domain + resolved IPs), ASN/BGP, IP geo
    HTTP posture   security headers, HTTP methods, CORS reflection, WAF detect
    Tech stack     Server/X-Powered-By, whatweb/wappalyzer (if present), favicon hash
    TLS            certificate dates/issuer/SANs (openssl)
    URLs           robots.txt + sitemap.xml, Wayback, gau/waybackurls, urlscan
    OSINT          Shodan (if SHODAN_API_KEY), cloud-bucket name guesses
    GraphQL        introspection probe
  Recon (active, with --active):
    DNS zone transfer (AXFR), subdomain brute force, nmap port+service scan,
    nc banner grab, directory brute (ffuf/gobuster), nuclei templates,
    testssl.sh full TLS audit
  Crawl + scan (always):
    Mirrors each URL + every live discovered subdomain 2 levels deep: HTML, JS, CSS, JSON, sourcemaps
    Probes accidental exposures: /.env*, /.git/config, firebase init, etc.
    Extracts endpoints/secrets from JS (jsluice/LinkFinder/getJS if present)
    Runs TruffleHog (live key verification) + Gitleaks, plus optional
      Kingfisher / detect-secrets / Nosey Parker if installed
    Flags shell env baked into bundles (HOME/PATH/GH_TOKEN in JS)
  Secrets are never printed in full, only the first few chars.

OUTPUT
  [LIVE]        key verified working with the provider -> rotate NOW
  [unverified]  matched a pattern but not confirmed live (e.g. public Firebase AIza keys)

EXIT CODES
  0 = nothing found    2 = findings    1 = bad usage / missing tools

REQUIRES
  brew install trufflehog gitleaks wget jq       # core (also need curl, dig, whois)
OPTIONAL (enable more recon when present)
  nmap nc ffuf gobuster nuclei testssl.sh wafw00f whatweb wappalyzer
  subfinder amass assetfinder findomain gau waybackurls
  jsluice linkfinder getJS kingfisher detect-secrets nosey_parker
EOF
}

# --- arg parsing ---
ACTIVE=0
OUT_DIR=""
SCAN_SUBS=1
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --active) ACTIVE=1 ;;
    -o|--out) shift; OUT_DIR="${1:-}"; [ -z "$OUT_DIR" ] && { echo "error: -o needs a directory"; exit 1; } ;;
    --no-subs) SCAN_SUBS=0 ;;
    -h|--help) usage; exit 1 ;;
    -*) echo "error: unknown flag '$1'"; echo; usage; exit 1 ;;
    *) ARGS+=("$1") ;;
  esac
  shift
done
set -- "${ARGS[@]:-}"
[ "${1:-}" = "" ] && { usage; exit 1; }
for u in "$@"; do [[ "$u" =~ ^https?:// ]] || { echo "error: '$u' must start with http:// or https://"; echo; usage; exit 1; }; done

# --- dependency check ---
for t in trufflehog gitleaks wget jq curl dig whois; do
  command -v "$t" >/dev/null || { echo "error: missing '$t'. Core deps: brew install trufflehog gitleaks wget jq (curl, dig, whois usually preinstalled)"; exit 1; }
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

  # [1] DNS records (all types) + ANY dump
  echo "  [dns] records"
  for rt in A AAAA CNAME MX TXT NS SOA SRV CAA DNSKEY DS NSEC NSEC3 SSHFP TLSA SVCB HTTPS SMIMEA PTR NAPTR; do
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

  # [5] Email authentication records (SPF / DMARC / DKIM / BIMI / MX)
  echo "  [email] spf / dmarc / dkim / bimi"
  { dig +short TXT "$DOMAIN" 2>/dev/null | grep -i 'v=spf1' | sed 's/^/SPF: /'
    dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | grep -i 'v=DMARC1' | sed 's/^/DMARC: /'
    dig +short TXT "default._bimi.${DOMAIN}" 2>/dev/null | sed 's/^/BIMI: /'
    for sel in default google selector1 selector2 k1 k2 mail smtp dkim mandrill mailjet sendgrid s1 s2 zoho; do
      d=$(dig +short TXT "${sel}._domainkey.${DOMAIN}" 2>/dev/null)
      [ -n "$d" ] && echo "DKIM[$sel]: present"
    done
    dig +short MX "$DOMAIN" 2>/dev/null | sed 's/^/MX: /'
  } > "$OUT/email_auth.txt"
  grep -qi 'v=spf1' "$OUT/email_auth.txt" || echo "WARNING: no SPF record" >> "$OUT/email_auth.txt"
  grep -qi 'DMARC:' "$OUT/email_auth.txt" || echo "WARNING: no DMARC record" >> "$OUT/email_auth.txt"

  # [6] Subdomains - passive (Certificate Transparency)
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
  cat "$OUT"/subs_*.txt 2>/dev/null | sed 's/^\.//' | grep -iE "\.?${DOMAIN}\$" | sort -u | grep -v '^$' > "$OUT/subdomains_all.txt"

  # [7] Subdomain takeover check (dangling CNAME -> known provider fingerprints)
  if [ -s "$OUT/subdomains_all.txt" ]; then
    echo "  [takeover] dangling CNAME scan"
    while read -r sub; do
      cn=$(dig +short CNAME "$sub" 2>/dev/null | head -1)
      [ -z "$cn" ] && continue
      if echo "$cn" | grep -qiE 'github\.io|herokuapp\.com|herokudns\.com|s3\.amazonaws\.com|cloudfront\.net|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|wpengine\.com|pantheonsite\.io|ghost\.io|netlify\.app|readme\.io|surge\.sh|fastly\.net|zendesk\.com|freshdesk\.com|unbouncepages\.com|bitbucket\.io|helpscoutdocs\.com|statuspage\.io|launchrock\.com|shopify\.com'; then
        body=$(curl -sfL -m 8 -A "$UA" "https://${sub}" 2>/dev/null)
        if echo "$body" | grep -qiE "no such app|there isn't a github pages|NoSuchBucket|do not have a site configured|The specified bucket does not exist|project not found|Repository not found|herokucdn|not been claimed|unrecognized domain|404 Not Found.*Fastly|Sorry, this shop is currently unavailable"; then
          echo "WARNING: possible subdomain takeover: ${sub} -> ${cn}" >> "$OUT/takeover.txt"
        fi
      fi
    done < "$OUT/subdomains_all.txt"
  fi

  # [8] WHOIS (domain + resolved IPs), ASN, geo
  echo "  [whois] domain + IPs + asn"
  whois "$DOMAIN" 2>/dev/null > "$OUT/whois_domain.txt"
  for i in $(dig +short "$DOMAIN" A 2>/dev/null | grep -E '^[0-9.]+$'); do
    whois "$i" 2>/dev/null | grep -iE '^(netname|orgname|org-name|descr|country|cidr|inetnum|origin|route)' >> "$OUT/whois_ip.txt"
    curl -sf "https://bgp.tools/api/v1/prefixes?prefix=$i/32" 2>/dev/null | jq -r '.[]? | "\(.prefix) -> AS\(.asn)"' 2>/dev/null >> "$OUT/asn.txt"
    curl -sf "https://ipinfo.io/$i/json" 2>/dev/null | jq -r '"\(.ip) \(.city // "?"), \(.region // "?"), \(.country // "?") (\(.org // "?"))"' 2>/dev/null >> "$OUT/ip_geo.txt"
  done

  # [9] HTTP security headers, methods, CORS, WAF
  echo "  [http] headers / methods / cors / waf"
  curl -sI -A "$UA" "$BASE" 2>/dev/null \
    | grep -iE '^(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|set-cookie|server|x-powered-by|x-aspnet-version|via):' > "$OUT/headers.txt"
  for h in strict-transport-security content-security-policy x-frame-options x-content-type-options; do
    grep -qi "^$h:" "$OUT/headers.txt" || echo "WARNING: missing header $h" >> "$OUT/headers_missing.txt"
  done
  for m in OPTIONS TRACE PUT DELETE PATCH; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X "$m" -A "$UA" "$BASE" 2>/dev/null)
    echo "$m: $code" >> "$OUT/http_methods.txt"
    { [ "$m" = "TRACE" ] && [ "$code" = "200" ]; } && echo "WARNING: TRACE enabled (XST)" >> "$OUT/http_methods.txt"
  done
  local acao; acao=$(curl -sI -A "$UA" -H "Origin: https://evil.example" "$BASE" 2>/dev/null | grep -i '^access-control-allow-origin:')
  echo "$acao" | grep -qi 'evil.example\|\*' && echo "WARNING: CORS reflects arbitrary origin -> $acao" > "$OUT/cors.txt"
  if have wafw00f; then wafw00f "$BASE" 2>/dev/null | grep -iE 'is behind|seems to be behind|No WAF' > "$OUT/waf.txt"; fi

  # [10] Technology fingerprint + favicon hash
  echo "  [tech] fingerprint / favicon"
  if have whatweb; then whatweb -q --color=never "$BASE" 2>/dev/null > "$OUT/whatweb.txt"
  elif have wappalyzer; then wappalyzer "$BASE" 2>/dev/null > "$OUT/wappalyzer.txt"; fi
  curl -sfL -m 10 -A "$UA" "$BASE/favicon.ico" -o "$OUT/favicon.ico" 2>/dev/null
  if [ -s "$OUT/favicon.ico" ]; then
    if have md5sum; then fh=$(md5sum "$OUT/favicon.ico" | awk '{print $1}'); else fh=$(md5 -q "$OUT/favicon.ico" 2>/dev/null); fi
    echo "favicon md5: $fh (pivot on Shodan: http.favicon.hash)" > "$OUT/favicon_hash.txt"
  fi

  # [11] TLS certificate
  echo "  [tls] certificate"
  if have openssl; then
    echo | openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null \
      | openssl x509 -noout -dates -subject -issuer -ext subjectAltName 2>/dev/null > "$OUT/tls_cert.txt"
  fi

  # [12] URL discovery: robots, sitemap, Wayback, gau/waybackurls, urlscan
  echo "  [urls] robots / sitemap / wayback / urlscan"
  curl -sfL -m 10 -A "$UA" "$BASE/robots.txt"  -o "$OUT/robots.txt" 2>/dev/null
  curl -sfL -m 10 -A "$UA" "$BASE/sitemap.xml" -o "$OUT/sitemap.xml" 2>/dev/null
  curl -sf "http://web.archive.org/cdx/search/cdx?url=${DOMAIN}*&output=text&fl=original&collapse=urlkey&limit=1000" 2>/dev/null > "$OUT/wayback.txt"
  if have gau; then gau --threads 5 "$DOMAIN" 2>/dev/null | sort -u >> "$OUT/wayback.txt"
  elif have waybackurls; then echo "$DOMAIN" | waybackurls 2>/dev/null | sort -u >> "$OUT/wayback.txt"; fi
  curl -sf -A "$UA" "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=100" 2>/dev/null | jq -r '.results[]?.page.url' 2>/dev/null > "$OUT/urlscan.txt"

  # [13] OSINT: Shodan + cloud-bucket name guesses
  echo "  [osint] shodan / buckets"
  if [ -n "${SHODAN_API_KEY:-}" ]; then
    curl -sf "https://api.shodan.io/dns/domain/${DOMAIN}?key=${SHODAN_API_KEY}" 2>/dev/null | jq . > "$OUT/shodan_dns.json" 2>/dev/null
    [ -n "${ip:-}" ] && curl -sf "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" 2>/dev/null | jq . > "$OUT/shodan_host.json" 2>/dev/null
  fi
  local stem; stem=$(echo "$DOMAIN" | sed -E 's/\.[a-z]+$//; s/\./-/g')
  for b in "$stem" "${stem}-assets" "${stem}-static" "${stem}-media" "${stem}-backup" "${stem}-backups" "${stem}-uploads" "${stem}-prod" "${stem}-dev" "${stem}-files"; do
    c=$(curl -s -o /dev/null -w '%{http_code}' -m 6 "https://${b}.s3.amazonaws.com/" 2>/dev/null)
    [ "$c" = "200" ] && echo "WARNING: open S3 bucket https://${b}.s3.amazonaws.com/ ($c)" >> "$OUT/buckets.txt"
    g=$(curl -s -o /dev/null -w '%{http_code}' -m 6 "https://storage.googleapis.com/${b}/" 2>/dev/null)
    [ "$g" = "200" ] && echo "WARNING: open GCS bucket https://storage.googleapis.com/${b}/ ($g)" >> "$OUT/buckets.txt"
  done

  # [14] GraphQL introspection
  local gql; gql=$(curl -sf -A "$UA" -X POST "$BASE/graphql" -H 'Content-Type: application/json' \
    -d '{"query":"{__schema{types{name}}}"}' 2>/dev/null)
  echo "$gql" | grep -q '__schema\|"types"' && { echo "$gql" > "$OUT/graphql_introspection.json"; echo "WARNING: GraphQL introspection enabled at $BASE/graphql" >> "$OUT/graphql.txt"; }

  # --- ACTIVE-only phases ---
  if [ "$ACTIVE" = "1" ]; then
    # [A1] Zone transfer (AXFR)
    echo "  [active] zone transfer attempt"
    for ns in $(dig +short NS "$DOMAIN" 2>/dev/null); do
      axfr=$(dig axfr "$DOMAIN" @"$ns" +time=5 +tries=1 2>/dev/null)
      if [ -n "$axfr" ] && ! echo "$axfr" | grep -q "REFUSED\|SERVFAIL\|NOTIMP\|Transfer failed"; then
        echo "WARNING: open zone transfer on $ns" >> "$OUT/axfr.txt"
        echo "$axfr" >> "$OUT/axfr.txt"
      fi
    done

    # [A2] Subdomain brute (high-signal list), merged into subdomains_all
    echo "  [active] subdomain brute"
    for sub in www api admin dev staging stg test qa uat prod internal intranet backup db mail smtp \
               ftp sftp git gitlab jenkins ci cd build deploy vault consul grafana kibana elastic \
               redis mongo postgres mysql s3 storage cdn static assets uploads files docs wiki \
               portal dashboard login auth sso oauth idp vpn proxy gateway status health metrics \
               logs sentry webhook graphql ws v1 v2 v3 app console panel phpmyadmin adminer beta demo; do
      r=$(dig +short "${sub}.${DOMAIN}" A 2>/dev/null | grep -E '^[0-9.]+$')
      [ -n "$r" ] && echo "${sub}.${DOMAIN}" >> "$OUT/subs_bruteforce.txt"
    done
    if [ -f "$OUT/subs_bruteforce.txt" ]; then cat "$OUT/subs_bruteforce.txt" "$OUT/subdomains_all.txt" 2>/dev/null | sort -u > "$OUT/.sub.tmp" && mv "$OUT/.sub.tmp" "$OUT/subdomains_all.txt"; fi

    # [A3] Port scan + [A4] banner grab
    if have nmap; then
      echo "  [active] nmap top ports"
      nmap -sV -Pn --top-ports 200 --open -T4 -oG "$OUT/nmap.gnmap" -oN "$OUT/nmap.txt" "$DOMAIN" >/dev/null 2>&1
      if have nc && [ -f "$OUT/nmap.gnmap" ]; then
        echo "  [active] nc banner grab"
        for port in $(grep -oE '[0-9]+/open' "$OUT/nmap.gnmap" | cut -d/ -f1 | sort -un); do
          echo "--- port $port ---" >> "$OUT/banners.txt"
          (printf 'HEAD / HTTP/1.0\r\n\r\n'; sleep 1) | nc -w 4 "$DOMAIN" "$port" 2>/dev/null | head -20 >> "$OUT/banners.txt"
        done
      fi
    fi

    # [A5] Directory brute
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

    # [A6] nuclei
    if have nuclei; then
      echo "  [active] nuclei (exposures/misconfig/cves)"
      nuclei -u "$BASE" -t http/exposures/ -t http/misconfiguration/ -t http/cves/ \
        -severity medium,high,critical -jsonl -o "$OUT/nuclei.jsonl" -silent 2>/dev/null
    fi

    # [A7] testssl.sh full TLS audit
    if have testssl.sh; then
      echo "  [active] testssl.sh"
      testssl.sh --quiet --color 0 "$DOMAIN" 2>/dev/null > "$OUT/testssl.txt"
    fi
  fi
}

mkdir -p site
TARGETS=()

# Phase 1: recon each input domain (also builds subdomains_all.txt per domain)
for u in "$@"; do
  BASE=$(echo "$u" | sed -E 's#(https?://[^/]+).*#\1#')
  DOMAIN=$(echo "$BASE" | sed -E 's#https?://##')
  recon_domain "$BASE" "$DOMAIN"
  TARGETS+=("$u")
done

# Phase 2: probe every discovered subdomain and add the live ones to the scan
if [ "$SCAN_SUBS" = "1" ]; then
  echo ""
  echo "=== Subdomain liveness probe ==="
  SUBS=$(cat site/recon_*/subdomains_all.txt 2>/dev/null | sort -u | grep -v '^$')
  nsub=$(printf '%s\n' "$SUBS" | grep -c . || true)
  echo "  $nsub unique subdomains discovered"
  live_n=0
  while IFS= read -r sub; do
    [ -z "$sub" ] && continue
    skip=0
    for a in "$@"; do [ "$(echo "$a" | sed -E 's#https?://##; s#/.*##')" = "$sub" ] && skip=1; done
    [ "$skip" = "1" ] && continue
    for scheme in https http; do
      code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' -A "$UA" "$scheme://$sub" 2>/dev/null)
      if [ -n "$code" ] && [ "$code" != "000" ]; then
        TARGETS+=("$scheme://$sub"); live_n=$((live_n+1)); break
      fi
    done
  done <<< "$SUBS"
  echo "  $live_n live subdomains added to scan"
fi

# Phase 3: crawl + probe every target (input URLs + live subdomains)
for u in "${TARGETS[@]}"; do
  BASE=$(echo "$u" | sed -E 's#(https?://[^/]+).*#\1#')
  DOMAIN=$(echo "$BASE" | sed -E 's#https?://##')
  wget -q -e robots=off -U "$UA" -r -l 2 -np -H -D "$DOMAIN" \
       -A 'html,htm,js,mjs,cjs,css,json,map,txt,env,xml,webmanifest' -P site "$u"
  for p in .env .env.local .env.production .env.development .git/config config.js env.js settings.json \
           asset-manifest.json manifest.json firebase.json __/firebase/init.json __/firebase/init.js \
           .well-known/security.txt robots.txt sitemap.xml _next/static/chunks/webpack.js; do
    curl -sfL -A "$UA" "$BASE/$p" -o "site/exposed_${DOMAIN}_$(echo "$p" | tr '/' '_')" 2>/dev/null
  done
done

# Fetch sourcemaps for every JS file
find site -name '*.js' | while read -r f; do
  rel=${f#site/}; curl -sfL -A "$UA" "https://$rel.map" -o "$f.map" 2>/dev/null
done

# Extract endpoints/secrets from JS bundles (optional tools)
if have jsluice || have linkfinder || have getJS; then
  echo "=== JS endpoint/secret extraction ==="
  find site -name '*.js' | while read -r f; do
    if have jsluice; then jsluice urls "$f" 2>/dev/null; jsluice secrets "$f" 2>/dev/null
    elif have linkfinder; then linkfinder -i "$f" -o cli 2>/dev/null; fi
  done | sort -u > site/js_endpoints.txt
  [ -s site/js_endpoints.txt ] && echo "  $(wc -l < site/js_endpoints.txt | tr -d ' ') endpoints/strings -> site/js_endpoints.txt"
fi

n=$(find site -type f | wc -l | tr -d ' ')
echo ""
echo "Scanned $n files from: $*"
echo "=== TruffleHog (verified = key is LIVE) ==="
trufflehog filesystem site --no-update --json 2>/dev/null > th.json
jq -r '"[\(if .Verified then "LIVE" else "unverified" end)] \(.DetectorName)  \(.SourceMetadata.Data.Filesystem.file | sub("^site/";""))  -> \(.Raw[0:6])…"' th.json 2>/dev/null | sort -u | tee th.txt
echo "=== Gitleaks ==="
gitleaks dir site --no-banner --redact=90 --report-format json --report-path gl.json >/dev/null 2>&1
jq -r '.[] | "[\(.RuleID)]  \(.File | sub(".*/site/";""))  -> \(.Secret[0:8])"' gl.json 2>/dev/null | sort -u | tee gl.txt
: > kf.txt
if have kingfisher; then
  echo "=== Kingfisher ==="
  kingfisher scan site --format json 2>/dev/null | jq -r '.findings[]? | "[\(.rule.id // .rule_id)]  \(.path // .file)"' 2>/dev/null | sort -u | tee kf.txt
elif have nosey_parker; then
  echo "=== Nosey Parker ==="
  nosey_parker scan --datastore "$TMP/np" site >/dev/null 2>&1 && nosey_parker report --datastore "$TMP/np" 2>/dev/null | grep -iE 'rule|finding' | sort -u | tee kf.txt
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
reconw=$( [ -f recon_warn.txt ] && wc -l < recon_warn.txt | tr -d ' ' || echo 0 )
expc=$( [ -f exp.txt ] && wc -l < exp.txt | tr -d ' ' || echo 0 )
anyfind=$(( total + reconw + expc ))

# Save crawl + recon artifacts and a findings CSV when -o DIR is given
if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR"
  cp -R site "$OUT_DIR/" 2>/dev/null
  for r in th.txt th.json gl.txt gl.json kf.txt env.txt exp.txt recon_warn.txt; do [ -f "$r" ] && cp "$r" "$OUT_DIR/" 2>/dev/null; done
  if [ "$anyfind" -gt 0 ]; then
    CSV="$OUT_DIR/findings.csv"
    {
      echo "type,detail,file,status,value_prefix"
      [ -f th.json ] && jq -r 'select(.DetectorName) | ["secret:trufflehog", .DetectorName, (.SourceMetadata.Data.Filesystem.file|sub("^site/";"")), (if .Verified then "LIVE" else "unverified" end), (.Raw[0:6])] | @csv' th.json 2>/dev/null | sort -u
      [ -f gl.json ] && jq -r '.[] | ["secret:gitleaks", .RuleID, (.File|sub(".*/site/";"")), "match", (.Secret[0:8])] | @csv' gl.json 2>/dev/null | sort -u
      while IFS= read -r f; do [ -n "$f" ] && printf '"bundle:shell-env","shell env vars baked into bundle","%s","warning",""\n' "$f"; done < env.txt
      while IFS= read -r f; do [ -n "$f" ] && printf '"exposed-file","returned content","%s","warning",""\n' "$f"; done < exp.txt
      while IFS= read -r w; do [ -n "$w" ] && printf '"recon-warning","%s","","warning",""\n' "$(echo "$w" | sed 's/^WARNING: //; s/\"/\"\"/g')"; done < recon_warn.txt
    } > "$CSV"
    echo "Saved crawl + recon to $OUT_DIR/  (findings CSV: $CSV)"
  else
    echo "Saved crawl + recon to $OUT_DIR/  (clean - no findings.csv written)"
  fi
fi

echo "---"
if [ "$total" -eq 0 ]; then echo "✓ No secrets found"; else echo "✗ $total secret finding(s), $live LIVE. Rotate LIVE ones immediately"; exit 2; fi
