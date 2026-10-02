# Ninja-API-Hunter v4.0

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-4.0-orange)

An asynchronous API reconnaissance and security-assessment toolkit for
Termux and Linux, built on Python's `asyncio` + `aiohttp`.

It helps map an API's attack surface and spot common
misconfigurations: exposed secrets, missing security headers, CORS
misconfigurations, undocumented endpoints pulled from Swagger/OpenAPI
specs, and broken object-level authorization (BOLA/IDOR) between two
accounts you control.

> **Use only on systems you own or are explicitly authorized to test**
> (your own infrastructure, a client engagement with signed
> authorization, or an in-scope bug bounty target). Scanning systems
> without permission may be illegal in your jurisdiction. The authors
> take no responsibility for misuse.

## What it actually does (and doesn't)

This is a **reconnaissance and detection** tool, not an exploit
framework. It sends requests and flags *patterns* worth a human's
attention — it does not automatically confirm or exploit a
vulnerability. Specifically:

- The BOLA/IDOR check is a **heuristic differential test**. A flagged
  endpoint needs manual verification; it is not proof of a
  vulnerability on its own.
- The secret-pattern grep looks for regex shapes (JWTs, cloud keys,
  private-key headers, etc.) in response bodies. False positives are
  possible, and it cannot find secret formats it has no pattern for.
- The CORS check only verifies origin reflection and the
  `Access-Control-Allow-Credentials` header; it doesn't simulate a
  full cross-origin attack chain.

## Features

- **Async core** — `aiohttp`-based engine, capable of hundreds of
  requests/sec on modest hardware, including phones running Termux.
- **Adaptive rate limiting** — backs off automatically on `429`/`503`
  responses and speeds back up once the target recovers.
- **Passive discovery (`--discover`)** — pulls extra candidate paths
  out of `robots.txt` and `sitemap.xml`, carried forward from v3.0.
- **Swagger / OpenAPI discovery** — checks common paths, parses JSON
  or YAML specs, and expands them into a concrete endpoint list.
- **BOLA / IDOR differential testing** — pass two tokens
  (`--token-a` / `--token-b`) and compare access to the same resources.
- **CORS misconfiguration detection** — flags reflected origins
  combined with `Access-Control-Allow-Credentials: true`.
- **Sensitive-data & exposure scanning** — greps responses for likely
  secrets and stack traces, checks for missing security headers, and
  probes a short list of commonly-exposed file paths (`.git/config`,
  `.env`, etc.).
- **JSON/HTML reporting** via `-o report.json` or `--format html`.
- **30 unit tests** covering regex patterns, the rate limiter, and
  every module's pure logic — no network needed to run them.

## Installation (Termux / Linux)

```bash
pkg update && pkg install python git   # Termux only
git clone <your-fork-url> ninja-api-hunter
cd ninja-api-hunter
pip install -r requirements.txt
# optional: install as a CLI command
pip install -e .
```

## Usage

```bash
# Baseline discovery + secret/stack-trace grep over a wordlist
python3 run.py -t https://api.target.com -w wordlist.txt

# Pull extra paths from robots.txt / sitemap.xml
python3 run.py -t https://api.target.com --discover

# Auto-discover and expand a Swagger/OpenAPI spec
python3 run.py -t https://api.target.com --swagger

# Probe common exposed-file paths
python3 run.py -t https://api.target.com --exposures

# CORS misconfiguration check
python3 run.py -t https://api.target.com -w wordlist.txt --cors

# BOLA/IDOR check between two accounts you control
python3 run.py -t https://api.target.com -w wordlist.txt \
  --bola --token-a "$TOKEN_A" --token-b "$TOKEN_B"

# Everything, with an HTML report, through Burp, ignoring a self-signed cert
python3 run.py -t https://api.target.com -w wordlist.txt --all \
  --proxy http://127.0.0.1:8080 --insecure -o report.html --format html
```

Run `python3 run.py -h` for the full flag reference.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## Project layout

```
ninja-api-hunter/
├── ninja_hunter/
│   ├── cli.py              # argument parsing + orchestration
│   ├── core/
│   │   ├── engine.py        # aiohttp request engine
│   │   └── rate_limiter.py  # adaptive 429/503 backoff
│   ├── modules/
│   │   ├── bola.py
│   │   ├── cors.py
│   │   ├── discovery.py     # robots.txt / sitemap.xml (v3.0 carryover)
│   │   ├── swagger.py
│   │   └── exposures.py
│   ├── utils/
│   │   ├── logger.py
│   │   ├── reporter.py
│   │   └── helpers.py       # pure helpers, no aiohttp dependency
│   └── config.py
├── tests/
│   └── test_modules.py
├── run.py
├── requirements.txt
├── setup.py
├── LICENSE
├── .gitignore
└── README.md
```

`utils/helpers.py` isn't in the original v4.0 spec's file list — it was
split out of `cli.py` so pure logic (header parsing, status
classification, wordlist loading) can be unit-tested without needing
`aiohttp` installed, and so the test suite stays fast and
dependency-light.

## Known limitations

- No JavaScript rendering — single-page apps that build routes
  client-side won't be fully mapped by wordlist/Swagger discovery alone.
- The secret scanner is regex pattern matching, not entropy analysis,
  so it will miss custom token formats and can false-positive on
  test/sample data.
- BOLA testing compares two fixed tokens against the same URL list; it
  doesn't yet walk numeric/sequential IDs automatically.
- The `proxy` option supports HTTP(S) proxies (e.g. Burp Suite);
  SOCKS proxies would need the optional `aiohttp-socks` package.

## Changelog

- **v2.0** — single-file path fuzzer + response grep.
- **v3.0** — modular architecture, 22 unit tests, SSL verification on
  by default, robots.txt/sitemap/Swagger-aware discovery, passive
  exposure checks.
- **v4.0** — BOLA/IDOR differential testing, CORS misconfiguration
  detection, automatic Swagger/OpenAPI parsing, robots.txt/sitemap.xml
  discovery (carried forward from v3.0), adaptive rate limiting,
  JSON/HTML reporting, installable package layout.

## License

MIT — see [LICENSE](LICENSE). Edit the copyright line in that file if
you want your own name on it instead of the placeholder.
