
```markdown
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
git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
cd Ninja-API-Hunter
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Scan
```bash
python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt
```

### Full Scan with Sensitive Data Extraction
```bash
python3 ninja_hunter_v2.py -t https://api.target.com \
  -w wordlist.txt \
  --extract \
  --threads 50 \
  -o json
```

### POST Method with JSON Data
```bash
python3 ninja_hunter_v2.py -t https://api.target.com \
  -w wordlist.txt \
  -m POST \
  -d '{"user":"admin"}'
```

### With Authentication Headers
```bash
python3 ninja_hunter_v2.py -t https://api.target.com \
  -w wordlist.txt \
  -H "Authorization: Bearer eyJ0eXAi..." \
  -H "X-API-Key: abc123"
```

### With Burp Suite Proxy
```bash
python3 ninja_hunter_v2.py -t https://api.target.com \
  -w wordlist.txt \
  --proxy http://127.0.0.1:8080
```

## 🔍 Detection Patterns

The tool detects **15+ sensitive data types** in API responses:

| Category | Patterns |
|----------|----------|
| **API Keys** | Generic API keys, x-api-key headers |
| **Cloud** | AWS Access/Secret keys, Google API keys |
| **Tokens** | JWT, Bearer tokens, GitHub tokens |
| **Communication** | Slack tokens, Stripe keys |
| **Crypto** | Private keys (RSA/EC/DSA) |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis URLs |
| **Personal** | Email + password combos, SSN patterns |
| **Network** | Internal IP addresses (RFC 1918) |
| **Payments** | Credit card numbers (Visa, Mastercard) |
| **Privileges** | Admin flags, role indicators |

## 📊 Sample Output

```
╔══════════════════════════════════╗
║         SCAN SUMMARY             ║
╚══════════════════════════════════╝
Total Endpoints: 4751
Alive (2xx/3xx): 1374
JSON Exposed: 8
Protected: 12

🚨 SENSITIVE FINDINGS:
  • JWT Token: 3 matches
  • API Key: 2 matches
  • Internal IP: 15 matches
```

## 🛠️ All Arguments

| Flag | Description |
|------|-------------|
| `-t, --target` | Target base URL (required) |
| `-w, --wordlist` | Path to wordlist file (required) |
| `-m, --method` | HTTP method (GET/POST/PUT/DELETE/PATCH) |
| `-d, --data` | Request body data |
| `-H, --headers` | Custom headers (multiple allowed) |
| `--threads` | Concurrent requests (default: 20) |
| `--timeout` | Request timeout (default: 10s) |
| `--extract` | Extract sensitive data |
| `--proxy` | Proxy URL for Burp Suite |
| `--user-agent` | Custom User-Agent |
| `-o, --output` | Export format (json/csv) |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Minimal output |

## 📥 Wordlists

Download recommended wordlists:

```bash
# API endpoints (recommended)
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt" -o api-endpoints.txt

# Common paths
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o common.txt

# GraphQL
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt" -o graphql.txt

# Quick hits
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt" -o quickhits.txt
```

Source: [SecLists by Daniel Miessler](https://github.com/danielmiessler/SecLists)

## 📱 Termux Installation

```bash
pkg update && pkg upgrade
pkg install python git -y
pip install aiohttp

git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
cd Ninja-API-Hunter
python3 ninja_hunter_v2.py --help
```

## ⚠️ Disclaimer

This tool is for **educational purposes** and **authorized security testing** only. 

- Only use against systems you own or have explicit permission to test
- Always follow responsible disclosure practices
- Comply with local laws and regulations
- The author is not responsible for any misuse or damage

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Star History

If you find this tool useful, please consider giving it a star! ⭐


