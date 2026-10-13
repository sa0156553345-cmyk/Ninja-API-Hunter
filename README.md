# Ninja-API-Hunter v4.0

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0-orange)]()
[![Tests](https://img.shields.io/badge/tests-30%20OK-brightgreen)]()

A lightweight, asynchronous REST API reconnaissance and vulnerability-scanning toolkit — fast enough for Termux and Linux, designed to find misconfigurations and suspicious patterns so you can verify them manually.

Why this tool?
- Practical recon + detection workflow focused on APIs (not an exploit framework).
- Fast async engine (aiohttp + asyncio) with adaptive rate limiting.
- Built-in Swagger/OpenAPI expansion, robots/sitemap discovery, secret/stack-trace grep, CORS & BOLA/IDOR heuristics.
- Small, dependency-light test suite — easy to run and verify locally.

Demo (screenshots)

Below are the demo images included in this branch. If you want different filenames or higher-resolution images, replace the files in docs/ with your preferred PNGs (keep the same names or update the references below).

![Repo view](./docs/screenshot-1.png)
![CLI demo](./docs/screenshot-2.png)
![Tests OK](./docs/screenshot-3.png)

Quick Start (Termux / Linux)
1. Clone & install
   ```bash
   git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
   cd Ninja-API-Hunter
   pip install -r requirements.txt
   # Optional: install as CLI
   pip install -e .
   ```
2. Run a quick discovery scan:
   ```bash
   python3 run.py -t https://api.target.com -w wordlist.txt -o report.json
   ```
3. View results (JSON / HTML):
   - JSON: open report.json
   - HTML: open report.html in a browser (when using `--format html`)

Core features
- Async request engine (high throughput with low resources)
- Adaptive rate-limiter: backs off on 429/503 automatically
- Swagger/OpenAPI auto-discovery and path expansion
- Passive discovery from robots.txt and sitemap.xml
- BOLA/IDOR heuristic differential testing (requires two tokens)
- CORS reflection + Access-Control-Allow-Credentials checks
- Secret and stack-trace pattern scanning (configurable patterns)
- Exposed-file probes (.git/config, .env, etc.)
- JSON and HTML reporting
- 30 fast unit tests that don't require network

Typical Usage Examples
- Baseline discovery + secret grep:
  python3 run.py -t https://api.target.com -w wordlist.txt
- Pull extra paths from robots/sitemap:
  python3 run.py -t https://api.target.com --discover
- Auto-discover & expand Swagger/OpenAPI:
  python3 run.py -t https://api.target.com --swagger
- CORS check:
  python3 run.py -t https://api.target.com -w wordlist.txt --cors
- BOLA/IDOR check (two accounts you control):
  python3 run.py -t https://api.target.com -w wordlist.txt --bola \
    --token-a "$TOKEN_A" --token-b "$TOKEN_B"
- Full assessment through a proxy, ignoring self-signed certs:
  python3 run.py -t https://api.target.com -w wordlist.txt --all \
    --proxy http://127.0.0.1:8080 --insecure -o report.html --format html

Why users should try it (short sales pitch)
- Get actionable reconnaissance quickly: built to produce prioritized findings you can verify manually.
- Lightweight & portable — runs on Termux (Android) and Linux with minimal fuss.
- Tests and CI-friendly: you can validate behavior locally before trusting results.
- Good for bug-bounty recon, internal API security assessments, and triage.

Example output (excerpt)
```json
{
  "target": "https://api.target.com",
  "findings": [
    { "path": "/.git/config", "status": 200, "note": "Possible exposed repo config" },
    { "path": "/v1/users/123", "status": 200, "diff": "BOLA-like response difference between tokens" }
  ]
}
```

Configuration & flags (summary)
- -t, --target TARGET            Target base URL
- -w, --wordlist WORDLIST        Path to endpoint wordlist
- -m, --method {GET,POST,...}    HTTP methods to try
- -H, --headers HEADERS          Custom header (repeatable) e.g. -H "Authorization: Bearer X"
- --bola --token-a --token-b     BOLA/IDOR differential test (requires tokens)
- --swagger                      Parse and expand Swagger/OpenAPI
- --discover                     Pull candidate paths from robots/sitemap
- --cors                         Run CORS reflection checks
- --exposures                    Probe common sensitive paths
- --proxy PROXY                  Proxy URL (e.g., http://127.0.0.1:8080)
- -k, --insecure                 Disable SSL verification
- -o, --output OUTPUT            Report output path
- --format {json,html}           Report format

Tests
Run unit tests locally:
```bash
python3 -m unittest discover -s tests -v
# Expect: "Ran 30 tests in 0.0xxs" and OK
```

Security & Responsible Use
- Use only on systems you own or are explicitly authorized to test.
- This tool is for reconnaissance and detection; flagged results require manual verification before any exploit or disclosure.
- The authors take no responsibility for misuse.

Contributing
- Found a bug or want a feature? Please open an Issue.
- Want to contribute code? Fork, create a branch (e.g., improve/readme), make changes, run tests, and open a Pull Request.
- Add small, self-contained changes; include tests where applicable.
- See CONTRIBUTING.md (suggested) for detailed guidelines.

First-time contributor checklist
- Fork the repo
- Create a branch with descriptive name
- Run tests: python3 -m unittest discover -s tests -v
- Keep PRs focused and include a clear description

FAQ / Troubleshooting (quick)
- Q: I get SSL errors on Termux — A: Use `-k/--insecure` for self-signed, or add the CA to your system.
- Q: Too slow? — A: Check `--threads` and let the rate limiter adapt; use a local proxy (Burp) if needed.
- Q: False positives on secrets — A: Patterns are heuristics; inspect flagged items manually.

Changelog
- v4.0 — BOLA/IDOR checks, CORS detection, Swagger parsing, improved discovery, adaptive rate limiting, JSON/HTML reporting.

License
MIT — see LICENSE file.

Contact / Support
- Repo: https://github.com/sa0156553345-cmyk/Ninja-API-Hunter
- Open an issue or file a PR. If you want professional help, include repro steps and sample outputs.

Call to action
Try it now:
```bash
python3 run.py -t https://api.target.com -w wordlist.txt
```
If it helped you, please:
- Star the repository ⭐
- Open issues for problems or feature requests
- Share example reports (sanitized) so we can improve detection rules

---
(Arabic summary / ملخص عربي مختصر follows)
## ملخص عربي موجز
Ninja-API-Hunter أداة خفيفة وغير متزامنة لفحص واجهات الـ API وإيجاد أنماط قد تدل على مشاكل أمنية. مناسبة للـ Termux والـ Linux، تُنتج تقارير JSON/HTML، وتدعم تحليل Swagger، واختبارات BOLA/IDOR وCORS. استخدمها فقط لأنظمة تملك تصريحًا قانونيًا لاختبارها.
