"""
Ninja-API-Hunter v4.0
Terminal logging utilities with ANSI colors.
"""


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    return f"""{Colors.CYAN}{Colors.BOLD}
+-----------------------------------------------------------+
|        NINJA API HUNTER v4.0                               |
|        API Reconnaissance & Security-Assessment Toolkit    |
+-----------------------------------------------------------+
{Colors.END}"""


def info(msg):
    print(f"{Colors.CYAN}[*] {msg}{Colors.END}")


def success(msg):
    print(f"{Colors.GREEN}[+] {msg}{Colors.END}")


def warn(msg):
    print(f"{Colors.YELLOW}[!] {msg}{Colors.END}")


def error(msg):
    print(f"{Colors.RED}[-] {msg}{Colors.END}")


def critical(msg):
    print(f"{Colors.RED}{Colors.BOLD}[!!] {msg}{Colors.END}")
