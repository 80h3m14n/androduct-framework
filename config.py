# Androduct Framework Configuration
import os
from pathlib import Path

# Framework paths
FRAMEWORK_ROOT = Path(__file__).parent
LOGS_DIR = FRAMEWORK_ROOT / "logs"
MODULES_DIR = FRAMEWORK_ROOT / "modules"
BACKUPS_DIR = FRAMEWORK_ROOT / "backups"
PAYLOADS_DIR = FRAMEWORK_ROOT / "payloads"
PATCHES_DIR = FRAMEWORK_ROOT / "core" / "patcher" / "patches"

# Create directories if they don't exist
for directory in [LOGS_DIR, BACKUPS_DIR, PAYLOADS_DIR]:
    directory.mkdir(exist_ok=True)

# ADB Configuration
ADB_TIMEOUT = 30
DEFAULT_SHELL_TIMEOUT = 60

# APK Signing Configuration
KEYSTORE_FILE = "debug.keystore"
KEY_ALIAS = "androiddebugkey"
KEY_PASSWORD = "android"
STORE_PASSWORD = "android"

# Network Configuration
DEFAULT_PORTS_TO_SCAN = [22, 23, 53, 80, 135, 139,
                         443, 445, 993, 995, 1723, 3389, 5554, 5555]
NMAP_ARGS = "-sS -O -sV"

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Exploit Configuration
MSFVENOM_PATH = "/usr/bin/msfvenom"  # Adjust path as needed
PAYLOAD_FORMATS = ["apk", "raw", "elf"]

# Colors for terminal output


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


# Framework metadata
FRAMEWORK_VERSION = "0.0.1"
AUTHOR = "Androduct Team"
BANNER = f"""{Colors.RED}
    ___              __                __           __ 
   /   |  ____  ____/ /________  ____/ /_  _______/ /_
  / /| | / __ \\/ __  / ___/ __ \\/ __  / / / / ___/ __/
 / ___ |/ / / / /_/ / /  / /_/ / /_/ / /_/ / /__/ /_  
/_/  |_/_/ /_/\\__,_/_/   \\____/\\__,_/\\__,_/\\___/\\__/  
{Colors.END}
{Colors.CYAN}Android Exploitation Framework v{FRAMEWORK_VERSION}{Colors.END}
{Colors.YELLOW}Author: {AUTHOR}{Colors.END}
{Colors.RED}⚠️  For Educational and Authorized Testing Only ⚠️{Colors.END}
"""
