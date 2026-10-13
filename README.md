# Ninja-API-Hunter v4.0 — API Recon & Vulnerability Scanner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0-orange)]()
[![Tests](https://img.shields.io/badge/tests-30%20OK-brightgreen)]()

Ninja-API-Hunter is a focused, production-minded toolkit for discovering and triaging API security issues. It is built for speed and practicality — designed to help bug hunters, security engineers, and red-teamers quickly find misconfigurations, exposed files, and heuristic signs of broken object-level authorization (BOLA/IDOR) so you can verify and remediate them.

Why try Ninja-API-Hunter?
- Fast, async core (aiohttp + asyncio) that runs on Termux and Linux with minimal resources.
- Practical detection-first approach: it highlights findings worth human verification — no blind exploit attempts.
- Built-in Swagger/OpenAPI parsing, robots/sitemap discovery, secret/stack-trace scanning, CORS reflection checks, and BOLA/IDOR heuristics.
- Adaptive rate-limiting and proxy support for safe, controlled scans.
- Lightweight test suite (30 unit tests) so you can verify behavior locally before trusting results.

Screenshots / Live Demo

- Repo overview: https://github.com/sa0156553345-cmyk/Ninja-API-Hunter
- CLI demo: ![CLI demo](https://github.com/sa0156553345-cmyk/Ninja-API-Hunter/blob/improve-readme/docs/screenshot-2.png)
- Tests output: ![Tests OK](https://github.com/sa0156553345-cmyk/Ninja-API-Hunter/blob/improve-readme/docs/screenshot-3.png)

Quick Start (Termux / Linux)

1) Clone and install

```bash
git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
cd Ninja-API-Hunter
pip install -r requirements.txt
# Optional: install as a CLI command
pip install -e .
```

2) Run a focused discovery scan

```bash
python3 run.py -t https://api.target.com -w wordlist.txt -o report.json
```

3) Inspect the results
- JSON: open report.json
- HTML: open report.html when using `--format html`

Core Capabilities

- Async request engine with adaptive rate limiting (handles 429/503 gracefully)
- Swagger/OpenAPI auto-discovery and expansion into concrete endpoints
- Passive discovery from robots.txt and sitemap.xml
- Heuristic BOLA/IDOR differential testing (compare two tokens you control)
- CORS reflection checks including Access-Control-Allow-Credentials detection
- Secret & stack-trace pattern scanning and checks for missing security headers
- Probes for commonly exposed files (.git/config, .env, etc.)
- JSON and HTML reporting for triage and sharing

Usage Examples

- Baseline discovery + secret grep:
  python3 run.py -t https://api.target.com -w wordlist.txt

- Pull extra paths from robots/sitemap:
  python3 run.py -t https://api.target.com --discover

- Auto-discover & expand Swagger/OpenAPI:
  python3 run.py -t https://api.target.com --swagger

- CORS check:
  python3 run.py -t https://api.target.com -w wordlist.txt --cors

- BOLA/IDOR heuristic test (two accounts you control):
  python3 run.py -t https://api.target.com -w wordlist.txt --bola \
    --token-a "$TOKEN_A" --token-b "$TOKEN_B"

Best Practices and Responsible Use

- Use only on systems you own or are explicitly authorized to test. Scanning without permission may be illegal.
- Treat flagged findings as hypotheses that require manual verification.
- Start with conservative flags and a small wordlist when testing targets you don't control directly.

Tests

Run the unit tests locally to verify behavior:

```bash
python3 -m unittest discover -s tests -v
# Expect: Ran 30 tests ... OK
```

Contributing — How you can help

Ninja-API-Hunter is open-source and community-driven. You can help by:

- Filing issues for bugs or feature requests.
- Submitting small, focused pull requests with tests.
- Sharing sanitized reports and repro steps to improve detection rules.

To contribute:
1. Fork the repo
2. Create a branch (e.g., improve/feature-name)
3. Run tests locally and add tests for new behavior
4. Open a Pull Request with a clear description

Call to action — Try it now

Give it a spin:

```bash
python3 run.py -t https://api.target.com -w wordlist.txt
```

If Ninja-API-Hunter helps you, please:
- Star the repository ⭐
- Open issues for problems or feature requests
- Share sanitized sample reports to help improve detections

Contact

Repository: https://github.com/sa0156553345-cmyk/Ninja-API-Hunter
Issues & PRs welcome — include clear repro steps for fast triage.

---

ملخص عربي مختصر

Ninja-API-Hunter أداة خفيفة وسريعة لاكتشاف المشاكل الشائعة في واجهات برمجة التطبيقات (APIs). تركز على الاكتشاف وإظهار النتائج القابلة للتحقق يدوياً. مناسبة لهواة الصيد والثغرات ومهندسي الأمن الداخلي. استخدمها فقط على أنظمة لديك تصريح قانوني لاختبارها.
