# 🥷 Ninja-API-Hunter v2.0

> Advanced API Security Scanner optimized for **Termux** and **Mobile Bug Bounty Hunting**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0-orange)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-success)

## ✨ Features

- ⚡ **AsyncIO engine** — 290+ requests/second
- 🎯 **Multi-method** — GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- 🔐 **Auth support** — Bearer tokens, API keys, custom headers
- 🔍 **Sensitive data extraction** — 15+ detection patterns
- 📊 **Export** — JSON & CSV formats
- 🌐 **Proxy support** — Burp Suite integration
- 🎨 **Color-coded output** — clean readable CLI
- 📱 **Termux optimized** — runs on Android

## 📦 Installation

```bash
git clone [https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git](https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git)
cd Ninja-API-Hunter
pip install -r requirements.txt

```bash
Usage
Basic Scan
python3 ninja_hunter_v2.py -t [https://api.target.com](https://api.target.com) -w wordlist.txt

```bash
Full Scan with Sensitive Data Extraction
python3 ninja_hunter_v2.py -t [https://api.target.com](https://api.target.com) -w wordlist.txt --extract --threads 50 -o json

```bash
POST Method with JSON Data
python3 ninja_hunter_v2.py -t [https://api.target.com](https://api.target.com) -w wordlist.txt -m POST -d '{"user":"admin"}'

```bash
With Authentication Headers
python3 ninja_hunter_v2.py -t [https://api.target.com](https://api.target.com) -w wordlist.txt -H "Authorization: Bearer YOUR_TOKEN" -H "X-API-Key: abc123"

```bash
With Burp Suite Proxy
python3 ninja_hunter_v2.py -t [https://api.target.com](https://api.target.com) -w wordlist.txt --proxy [http://127.0.0.1:8080](http://127.0.0.1:8080)

Detection Patterns

The tool detects 15+ sensitive data types in API responses:

CategoryPatternsAPI KeysGeneric API keys, x-api-key headersCloudAWS Access/Secret keys, Google API keysTokensJWT, Bearer tokens, GitHub tokensCommunicationSlack tokens, Stripe keysCryptoPrivate keys (RSA/EC/DSA)DatabasesMongoDB, PostgreSQL, MySQL, Redis URLsPersonalEmail + password combos, SSN patternsNetworkInternal IP addresses (RFC 1918)PaymentsCredit card numbers (Visa, Mastercard)PrivilegesAdmin flags, role indicators

#Sample Output
╔══════════════════════════════════╗║         SCAN SUMMARY             ║╚══════════════════════════════════╝Total Endpoints: 4751Alive (2xx/3xx): 1374JSON Exposed: 8Protected: 12🚨 SENSITIVE FINDINGS:  • JWT Token: 3 matches  • API Key: 2 matches  • Internal IP: 15 matches

All Arguments

FlagDescription-t, --targetTarget base URL (required)-w, --wordlistPath to wordlist file (required)-m, --methodHTTP method (GET/POST/PUT/DELETE/PATCH)-d, --dataRequest body data-H, --headersCustom headers (multiple allowed)--threadsConcurrent requests (default: 20)--timeoutRequest timeout (default: 10s)--extractExtract sensitive data--proxyProxy URL for Burp Suite--user-agentCustom User-Agent-o, --outputExport format (json/csv)-v, --verboseVerbose output-q, --quietMinimal output

Wordlists

Download recommended wordlists:

# API endpoints (recommended) curl -sL "[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt)" -o api-endpoints.txt # Common paths curl -sL "[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt)" -o common.txt # GraphQL curl -sL "[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt)" -o graphql.txt # Quick hits curl -sL "[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt)" -o quickhits.txt 

📱 Termux Installation

pkg update && pkg upgrade pkg install python git -y pip install aiohttp git clone [https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git](https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git) cd Ninja-API-Hunter python3 ninja_hunter_v2.py --help
Disclaimer

This tool is for educational purposes and authorized security testing only.

Only use against systems you own or have explicit permission to test

Always follow responsible disclosure practices

Comply with local laws and regulations

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

