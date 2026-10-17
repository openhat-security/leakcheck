# leakcheck

Scan live websites for leaked API keys, tokens and secrets.

Frontend build tools can quietly bake secrets into public JavaScript bundles. `leakcheck.sh` mirrors what a browser (or an attacker) can download from your site and scans it with **TruffleHog** (800+ detectors, live verification) and **Gitleaks** (150+ rules).

## Install

```bash
brew install trufflehog gitleaks wget jq
curl -fsSLO https://raw.githubusercontent.com/openhat-security/leakcheck/main/leakcheck.sh
chmod +x leakcheck.sh
```

On Linux, install `trufflehog` and `gitleaks` from their GitHub releases, and `wget`, `jq` and `curl` from your package manager.

## Usage

```bash
./leakcheck.sh https://example.com
./leakcheck.sh https://app.example.com https://admin.example.com
./leakcheck.sh https://example.com && echo clean || echo "LEAKS FOUND"
./leakcheck.sh --help
```

## What it does

1. Crawls each URL two levels deep on the same domain, collecting HTML, JS, CSS, JSON and sourcemaps.
2. Fetches `.map` sourcemaps for every JS file it finds, since they often contain the original source.
3. Probes common accidental exposures: `/.env*`, `/.git/config`, `/__/firebase/init.json`, `firebase.json`, `asset-manifest.json` and similar.
4. Runs TruffleHog, which checks whether each key it finds is **live** with the provider, and Gitleaks.
5. Flags shell environment variables baked into bundles, such as `HOME`, `PATH` and `GH_TOKEN` appearing in JS.

Secrets are never printed in full; output shows only the first few characters.

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

Only scan sites you own or are authorized to test.

## License

MIT © OpenHat Security
