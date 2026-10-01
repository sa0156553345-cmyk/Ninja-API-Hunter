"""Terminal color codes and the startup banner."""


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

    @staticmethod
    def banner():
        return f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║         🥷 NINJA API HUNTER v3.0                           ║
║         Async REST API Recon Tool                          ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
