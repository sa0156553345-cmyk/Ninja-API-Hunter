# ðŸ¥· Ninja-API-Hunter v3.0

An async REST API recon tool built for Termux. Give it a target and a
wordlist; it finds live endpoints, pulls in extra paths from robots.txt /
sitemap.xml / API schemas, and flags secrets or obviously-exposed files in
the responses.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.0-orange)

## What changed from v2.0

v2.0 was, honestly, a path fuzzer plus response grepping with the SSL
check turned off â€” that's a fair description from a friend's review, and
it's why v3.0 exists. Specifically:

| v2.0 | v3.0 |
|---|---|
| TLS verification hardcoded off | **On by default**, `--insecure` to opt out explicitly |
| Static wordlist only | `--discover` reads robots.txt, sitemap.xml, and OpenAPI/Swagger docs and adds what they reveal |
| No recursion | `--recursive` follows same-host links found in responses (depth-limited) |
| Secret regexes only | Also flags passive exposure signatures: open `.git/HEAD`, readable `.env`, public Swagger/OpenAPI schemas, verbose stack traces, missing security headers |
| Fire-and-forget requests | Configurable `--delay`, `--retries`, and backoff |
| Single 400-line file | Split into `ninja_hunter/{scanner,discovery,detectors,cli,colors}.py` |
| No tests | 22 unit tests over the detection/discovery logic (`tests/`) |

It's still not a replacement for `ffuf`/`httpx`/`nuclei` â€” those are
mature, heavily-tested projects. This is a personal tool that now does a
few of the same ideas (schema-driven discovery, passive signature
matching) in a single Termux-friendly script.

## Installation (Termux)

```bash
pkg update && pkg upgrade
pkg install python git -y
git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
cd Ninja-API-Hunter
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan with the bundled starter wordlist
python3 run.py -t https://api.target.com -w wordlist.txt

# Smart discovery + recursion + secret/exposure extraction
python3 run.py -t https://api.target.com -w wordlist.txt \
  --discover --recursive --extract

# Local / self-signed lab target only (disables TLS verification)
python3 run.py -t https://192.168.1.50 -w wordlist.txt --insecure

# Through Burp Suite, rate-limited to be polite to the target
python3 run.py -t https://api.target.com -w wordlist.txt \
  --proxy http://127.0.0.1:8080 --delay 0.2 --threads 10

# Full run, exported to JSON
python3 run.py -t https://api.target.com -w wordlist.txt \
  --discover --recursive --extract --threads 30 -o json
```

### Flags

| Flag | Description |
|---|---|
| `-t, --target` | Target base URL (required) |
| `-w, --wordlist` | Path to wordlist file (required) |
| `-m, --method` | HTTP method (default: GET) |
| `-d, --data` | Request body for POST/PUT |
| `-H, --headers` | Custom header, repeatable |
| `--threads` | Concurrent requests (default: 20) |
| `--timeout` | Per-request timeout, seconds (default: 10) |
| `--delay` | Fixed delay between requests, seconds |
| `--retries` | Retries on timeout/connection error (default: 1) |
| `--backoff` | Base backoff seconds between retries (default: 0.5) |
| `--insecure` | Disable TLS certificate verification (off by default) |
| `--discover` | Pull extra paths from robots.txt / sitemap.xml / API schemas |
| `--recursive` | Follow same-host links found in 200 responses |
| `--max-depth` | Max recursion depth (default: 2) |
| `--extract` | Flag secrets and passive exposure signatures |
| `--proxy` | Proxy URL, e.g. Burp at `http://127.0.0.1:8080` |
| `-o, --output` | Export format: `json` or `csv` |

## Detection coverage

**Secrets** (regex, in response bodies): API keys, AWS access/secret keys,
JWTs, Bearer tokens, GitHub tokens, Google API keys, Slack tokens, Stripe
keys, PEM private keys, DB connection strings, internal RFC1918 IPs,
`"admin": true`-style flags.

**Passive exposure signatures** (content-verified, not just path-matched):
exposed `.git/HEAD`, readable `.env` files, public Swagger/OpenAPI
schemas, verbose stack traces (Python/Java/.NET/Node/PHP), missing
`Strict-Transport-Security` / `X-Content-Type-Options` / `X-Frame-Options`
/ `Content-Security-Policy` headers on HTML responses.

None of this exploits anything â€” it only recognizes things a server is
already handing back in a normal response.

## Better wordlists

The bundled `wordlist.txt` is a small starter list. For real coverage,
pull from [SecLists](https://github.com/danielmiessler/SecLists):

```bash
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -o wordlist.txt
# or, broader:
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" -o wordlist.txt
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt" -o wordlist.txt
```

## Tests

No extra dependencies needed â€” the detection/discovery logic is pure
functions, tested with the standard library:

```bash
python3 -m unittest discover -s tests -v
```

## Disclaimer

For educational purposes and **authorized security testing only**.

- Only use against systems you own or have explicit written permission to test
- Follow responsible disclosure
- Comply with local laws and the target's bug bounty / testing policy
- The author is not responsible for misuse

## License

MIT â€” see `LICENSE`.
