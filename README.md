# 🥷 Ninja-API-Hunter v2.0

> Advanced API Security Scanner optimized for Termux and Mobile Bug Bounty Hunting

## Features

- AsyncIO engine - 290+ requests/second
- Multi-method - GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- Auth support - Bearer tokens, API keys, custom headers
- Sensitive data extraction - 15+ detection patterns
- Export - JSON & CSV formats
- Proxy support - Burp Suite integration
- Color-coded output - clean readable CLI
- Termux optimized - runs on Android

## Installation

git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
cd Ninja-API-Hunter
pip install -r requirements.txt

## Usage

Basic Scan:
python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt

Full Scan with Extraction:
python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt --extract --threads 50

Proxy Scan:
python3 ninja_hunter_v2.py -t https://api.target.com -w wordlist.txt --proxy http://127.0.0.1:8080

## Termux Installation

pkg update && pkg upgrade
pkg install python git -y
pip install aiohttp
git clone https://github.com/sa0156553345-cmyk/Ninja-API-Hunter.git
cd Ninja-API-Hunter
python3 ninja_hunter_v2.py --help
