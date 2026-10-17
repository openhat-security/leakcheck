#!/usr/bin/env bash
# leakcheck.sh: mirror a site's HTML/JS/CSS/sourcemaps, then scan with TruffleHog (800+ detectors, live-verified) + Gitleaks (150+ rules)

usage() {
  cat <<'EOF'
leakcheck.sh: scan live websites for leaked secrets/tokens

USAGE
  leakcheck.sh <url> [url ...]
  leakcheck.sh -h | --help

EXAMPLES
  leakcheck.sh https://example.com
  leakcheck.sh https://portal.example.com https://uploader.example.com
  leakcheck.sh https://example.com && echo clean || echo "LEAKS FOUND"

WHAT IT DOES
  1. Crawls each URL 2 levels deep (same domain): HTML, JS, CSS, JSON, sourcemaps
  2. Probes common accidental exposures: /.env, /.git/config, firebase init, etc.
  3. Runs TruffleHog (800+ token types, checks if keys are LIVE) and Gitleaks
  4. Flags shell env baked into bundles (HOME/PATH/GH_TOKEN in JS)
  Secrets are never printed in full, only the first few chars.

OUTPUT
  [LIVE]        key verified working with the provider -> rotate NOW
  [unverified]  matched a pattern but not confirmed live (e.g. public Firebase AIza keys)

EXIT CODES
  0 = nothing found    2 = findings    1 = bad usage / missing tools

REQUIRES
  brew install trufflehog gitleaks wget jq
EOF
}

case "${1:-}" in -h|--help|"") usage; exit 1 ;; esac
for u in "$@"; do [[ "$u" =~ ^https?:// ]] || { echo "error: '$u' must start with http:// or https://"; echo; usage; exit 1; }; done
for t in trufflehog gitleaks wget jq curl; do command -v "$t" >/dev/null || { echo "error: missing '$t'. Run: brew install trufflehog gitleaks wget jq"; exit 1; }; done

set -uo pipefail
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
UA="Mozilla/5.0 leakcheck"
cd "$TMP"

for u in "$@"; do
  BASE=$(echo "$u" | sed -E 's#(https?://[^/]+).*#\1#')
  wget -q -e robots=off -U "$UA" -r -l 2 -np -H -D "$(echo "$BASE" | sed -E 's#https?://##')" \
       -A 'html,htm,js,mjs,cjs,css,json,map,txt,env,xml,webmanifest' -P site "$u"
  mkdir -p site
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
echo "Scanned $n files from: $*"
echo "=== TruffleHog (verified = key is LIVE) ==="
trufflehog filesystem site --no-update --json 2>/dev/null | \
  jq -r '"[\(if .Verified then "LIVE" else "unverified" end)] \(.DetectorName)  \(.SourceMetadata.Data.Filesystem.file | sub("^site/";""))  -> \(.Raw[0:6])…"' | sort -u | tee th.txt
echo "=== Gitleaks ==="
gitleaks dir site --no-banner --redact=90 --report-format json --report-path gl.json >/dev/null 2>&1
jq -r '.[] | "[\(.RuleID)]  \(.File | sub(".*/site/";""))  -> \(.Secret[0:8])"' gl.json 2>/dev/null | sort -u | tee gl.txt
echo "=== Shell env baked into bundle? ==="
grep -rlE '"(HOME|USER|SHELL|PATH|CURSOR_AGENT|TERM_PROGRAM|GH_TOKEN|GITHUB_TOKEN)" *: *"' site 2>/dev/null | sed 's#^site/##' | tee env.txt
echo "=== Exposed files that returned content ==="
find site -name 'exposed_*' -size +0 | sed 's#^site/exposed_##' | grep -vE 'robots|sitemap|security.txt|manifest' | tee exp.txt

live=$(grep -c '^\[LIVE\]' th.txt 2>/dev/null || true); live=${live:-0}
total=$(( $(wc -l < th.txt) + $( [ -f gl.txt ] && wc -l < gl.txt || echo 0) + $(wc -l < env.txt) ))
echo "---"
if [ "$total" -eq 0 ]; then echo "✓ Nothing found"; else echo "✗ $total finding(s), $live LIVE. Rotate LIVE ones immediately"; exit 2; fi
