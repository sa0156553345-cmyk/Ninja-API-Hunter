import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

print("""
    _   ___        _           _    ___ ___   _  _             _            
   / | / (_)____  (_)___ _    / \  | _ \_ _| | || |_  _ _ _  _| |_ ___ _ _  
   | .` | | / _ \ | / _` |   / _ \ |  _/| |  | __ | || | ' \|  _| -_) '_| 
   |_|\_|_| \___/ |_\__,_|  /_/ \_\|_| |___| |_||_|\_,_|_||_|\__\___|_|  
""")

def scan_endpoint(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
            print(f"[+] VULNERABLE/EXPOSED: {url} (JSON Data Found!)")
        elif response.status_code in [401, 403]:
            print(f"[-] PROTECTED: {url} (Status: {response.status_code})")
        else:
            print(f"[*] ALIVE: {url} (Status: {response.status_code})")
    except requests.RequestException:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ninja API Hunter - REST API Recon Tool")
    parser.add_argument("-t", "--target", help="Target base URL (e.g., https://api.target.com)", required=True)
    parser.add_argument("-w", "--wordlist", help="Path to wordlist", required=True)
    args = parser.parse_args()

    with open(args.wordlist, "r") as file:
        paths = [line.strip() for line in file.readlines()]

    urls = [f"{args.target}/{path}" for path in paths]
    print(f"[*] Scanning {len(urls)} endpoints on {args.target}...\n")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_endpoint, urls)
