#!/usr/bin/env python3
"""
Information Gathering Module for Androduct Framework
Collects detailed information about target Android devices
"""

import subprocess
import json
import re
from pathlib import Path
from core.adb.device_manager import DeviceManager
from core.utils.logger import logger
from config import Colors, LOGS_DIR
from core.utils import session_manager

dm = DeviceManager()


def info_gathering_menu():
    """Main information gathering menu"""
    device = dm.get_current_device()
    if not device:
        logger.error("No device connected. Please connect a device first.")
        return

    while True:
        # show global menu header
        try:
            print(session_manager.get_menu_header())
        except Exception:
            pass
        print(f"""
{Colors.CYAN}Information Gathering Menu{Colors.END}
{Colors.CYAN}========================={Colors.END}
[1] Device System Information
[2] Installed Applications
[3] Security Settings
[4] Network Configuration
[5] Hardware Information
[6] Certificate Store Analysis
[7] User Data Locations
[8] Full Device Scan (All above)
[9] Export Report
[0] Back to Main Menu
        """)

        choice = input(f"{Colors.CYAN}info{Colors.END} > ").strip()

        try:
            if choice == "1":
                get_system_info(device)
            elif choice == "2":
                get_installed_apps(device)
            elif choice == "3":
                get_security_settings(device)
            elif choice == "4":
                get_network_config(device)
            elif choice == "5":
                get_hardware_info(device)
            elif choice == "6":
                analyze_certificates(device)
            elif choice == "7":
                find_user_data(device)
            elif choice == "8":
                perform_full_scan(device)
            elif choice == "9":
                export_device_report(device)
            elif choice == "0":
                break
            else:
                logger.warning("Invalid option selected")
        except Exception as e:
            logger.error(f"Operation failed: {str(e)}")


def execute_adb_command(device, command, shell=True):
    """Execute ADB command and return output"""
    try:
        if shell:
            cmd = ["adb", "-s", device, "shell"] + command.split()
        else:
            cmd = ["adb", "-s", device] + command.split()

        logger.log_command(" ".join(cmd), device)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logger.error(f"Command failed: {result.stderr.strip()}")
            return None
    except subprocess.TimeoutExpired:
        logger.error("Command timed out")
        return None
    except Exception as e:
        logger.error(f"Command execution failed: {str(e)}")
        return None


def get_system_info(device):
    """Gather comprehensive system information"""
    logger.info("Gathering system information...")

    info = {}

    # Basic device info
    properties = [
        ("ro.product.model", "Device Model"),
        ("ro.product.manufacturer", "Manufacturer"),
        ("ro.build.version.release", "Android Version"),
        ("ro.build.version.sdk", "SDK Version"),
        ("ro.build.version.security_patch", "Security Patch"),
        ("ro.build.fingerprint", "Build Fingerprint"),
        ("ro.product.cpu.abi", "CPU Architecture"),
        ("ro.build.type", "Build Type"),
        ("ro.debuggable", "Debuggable"),
        ("ro.secure", "Secure Boot"),
        ("ro.boot.verifiedbootstate", "Verified Boot"),
        ("persist.sys.timezone", "Timezone"),
        ("ro.boot.serialno", "Serial Number")
    ]

    print(f"{Colors.YELLOW}System Properties:{Colors.END}")
    for prop, name in properties:
        value = execute_adb_command(device, f"getprop {prop}")
        if value:
            info[name] = value
            print(f"  {name}: {Colors.GREEN}{value}{Colors.END}")

    # Memory and storage info
    print(f"\n{Colors.YELLOW}Memory & Storage:{Colors.END}")
    meminfo = execute_adb_command(device, "cat /proc/meminfo | head -5")
    if meminfo:
        for line in meminfo.split('\\n'):
            if line.strip():
                print(f"  {Colors.GREEN}{line.strip()}{Colors.END}")

    # Disk usage
    disk_usage = execute_adb_command(device, "df -h")
    if disk_usage:
        print(f"\n{Colors.YELLOW}Disk Usage:{Colors.END}")
        for line in disk_usage.split('\\n')[:6]:
            if line.strip():
                print(f"  {Colors.GREEN}{line.strip()}{Colors.END}")

    # Root detection
    check_root_status(device)

    return info


def get_installed_apps(device):
    """Get list of installed applications"""
    logger.info("Scanning installed applications...")

    print(f"{Colors.YELLOW}Installed Applications:{Colors.END}")

    # Get all packages
    packages = execute_adb_command(device, "pm list packages -f")
    if not packages:
        logger.error("Failed to get package list")
        return

    app_count = len(packages.split('\\n'))
    print(f"Total packages found: {Colors.GREEN}{app_count}{Colors.END}")

    # Get system apps
    system_apps = execute_adb_command(device, "pm list packages -f -s")
    system_count = len(system_apps.split('\\n')) if system_apps else 0

    # Get user apps
    user_apps = execute_adb_command(device, "pm list packages -f -3")
    user_count = len(user_apps.split('\\n')) if user_apps else 0

    print(f"System apps: {Colors.YELLOW}{system_count}{Colors.END}")
    print(f"User apps: {Colors.CYAN}{user_count}{Colors.END}")

    # Show recently installed apps
    print(f"\n{Colors.YELLOW}Recent User Applications:{Colors.END}")
    if user_apps:
        for line in user_apps.split('\\n')[:10]:
            if line.strip():
                package_name = line.split('=')[-1] if '=' in line else line
                print(f"  {Colors.GREEN}{package_name.strip()}{Colors.END}")

    # Check for suspicious apps
    suspicious_keywords = ['hack', 'root',
                           'super', 'xposed', 'magisk', 'frida']
    print(f"\n{Colors.RED}Potentially Suspicious Apps:{Colors.END}")
    found_suspicious = False

    for line in packages.split('\\n'):
        package_name = line.split(
            '=')[-1].lower() if '=' in line else line.lower()
        for keyword in suspicious_keywords:
            if keyword in package_name:
                print(f"  {Colors.RED}⚠️  {package_name.strip()}{Colors.END}")
                found_suspicious = True

    if not found_suspicious:
        print(f"  {Colors.GREEN}No obviously suspicious apps detected{Colors.END}")


def get_security_settings(device):
    """Analyze device security settings"""
    logger.info("Analyzing security settings...")

    print(f"{Colors.YELLOW}Security Analysis:{Colors.END}")

    # ADB status
    adb_status = execute_adb_command(device, "getprop service.adb.tcp.port")
    if adb_status and adb_status != "-1":
        print(
            f"  ADB over TCP: {Colors.RED}ENABLED (Port: {adb_status}){Colors.END}")
    else:
        print(f"  ADB over TCP: {Colors.GREEN}DISABLED{Colors.END}")

    # Developer options
    dev_options = execute_adb_command(
        device, "settings get global development_settings_enabled")
    if dev_options == "1":
        print(f"  Developer Options: {Colors.YELLOW}ENABLED{Colors.END}")
    else:
        print(f"  Developer Options: {Colors.GREEN}DISABLED{Colors.END}")

    # Screen lock
    screen_lock = execute_adb_command(
        device, "dumpsys deviceidle | grep mScreenLocked")
    if screen_lock and "true" in screen_lock.lower():
        print(f"  Screen Lock: {Colors.GREEN}ACTIVE{Colors.END}")
    else:
        print(f"  Screen Lock: {Colors.YELLOW}INACTIVE{Colors.END}")

    # Unknown sources
    unknown_sources = execute_adb_command(
        device, "settings get secure install_non_market_apps")
    if unknown_sources == "1":
        print(f"  Unknown Sources: {Colors.RED}ENABLED{Colors.END}")
    else:
        print(f"  Unknown Sources: {Colors.GREEN}DISABLED{Colors.END}")


def get_network_config(device):
    """Get network configuration details"""
    logger.info("Gathering network configuration...")

    print(f"{Colors.YELLOW}Network Configuration:{Colors.END}")

    # WiFi status
    wifi_status = execute_adb_command(device, "dumpsys wifi | grep 'Wi-Fi is'")
    print(f"  WiFi Status: {Colors.GREEN}{wifi_status}{Colors.END}")

    # IP configuration
    ip_info = execute_adb_command(device, "ip addr show wlan0")
    if ip_info:
        ip_match = re.search(r'inet (\\d+\\.\\d+\\.\\d+\\.\\d+)', ip_info)
        if ip_match:
            print(
                f"  IP Address: {Colors.GREEN}{ip_match.group(1)}{Colors.END}")

    # DNS settings
    dns1 = execute_adb_command(device, "getprop net.dns1")
    dns2 = execute_adb_command(device, "getprop net.dns2")
    if dns1:
        print(f"  Primary DNS: {Colors.GREEN}{dns1}{Colors.END}")
    if dns2:
        print(f"  Secondary DNS: {Colors.GREEN}{dns2}{Colors.END}")

    # Proxy settings
    proxy_host = execute_adb_command(device, "settings get global http_proxy")
    if proxy_host and proxy_host.strip():
        print(f"  HTTP Proxy: {Colors.YELLOW}{proxy_host}{Colors.END}")
    else:
        print(f"  HTTP Proxy: {Colors.GREEN}None{Colors.END}")


def get_hardware_info(device):
    """Get hardware information"""
    logger.info("Gathering hardware information...")

    print(f"{Colors.YELLOW}Hardware Information:{Colors.END}")

    # CPU info
    cpu_info = execute_adb_command(
        device, "cat /proc/cpuinfo | grep 'model name\\|processor\\|cpu MHz'")
    if cpu_info:
        print(f"  {Colors.GREEN}CPU Information:{Colors.END}")
        for line in cpu_info.split('\\n')[:3]:
            if line.strip():
                print(f"    {line.strip()}")

    # Battery info
    battery_info = execute_adb_command(device, "dumpsys battery")
    if battery_info:
        level_match = re.search(r'level: (\\d+)', battery_info)
        temp_match = re.search(r'temperature: (\\d+)', battery_info)
        if level_match:
            print(
                f"  Battery Level: {Colors.GREEN}{level_match.group(1)}%{Colors.END}")
        if temp_match:
            temp_celsius = int(temp_match.group(1)) / 10
            print(
                f"  Battery Temperature: {Colors.GREEN}{temp_celsius}°C{Colors.END}")


def check_root_status(device):
    """Check if device is rooted"""
    print(f"\n{Colors.YELLOW}Root Detection:{Colors.END}")

    # Check for su binary
    su_check = execute_adb_command(device, "which su")
    if su_check and "/su" in su_check:
        print(f"  SU Binary: {Colors.RED}FOUND ({su_check}){Colors.END}")
    else:
        print(f"  SU Binary: {Colors.GREEN}NOT FOUND{Colors.END}")

    # Check for common root apps
    root_apps = ["com.topjohnwu.magisk",
                 "eu.chainfire.supersu", "com.noshufou.android.su"]
    for app in root_apps:
        check = execute_adb_command(device, f"pm list packages {app}")
        if check and app in check:
            print(f"  Root App ({app}): {Colors.RED}INSTALLED{Colors.END}")
        else:
            print(f"  Root App ({app}): {Colors.GREEN}NOT FOUND{Colors.END}")


def analyze_certificates(device):
    """Analyze certificate store"""
    logger.info("Analyzing certificate store...")

    print(f"{Colors.YELLOW}Certificate Analysis:{Colors.END}")

    # System certificates
    sys_certs = execute_adb_command(
        device, "ls /system/etc/security/cacerts/ | wc -l")
    if sys_certs:
        print(
            f"  System Certificates: {Colors.GREEN}{sys_certs.strip()}{Colors.END}")

    # User certificates
    user_certs = execute_adb_command(
        device, "ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l")
    if user_certs and user_certs.strip() != "0":
        print(
            f"  User Certificates: {Colors.YELLOW}{user_certs.strip()}{Colors.END}")
    else:
        print(f"  User Certificates: {Colors.GREEN}0{Colors.END}")


def find_user_data(device):
    """Find interesting user data locations"""
    logger.info("Scanning for user data locations...")

    print(f"{Colors.YELLOW}User Data Locations:{Colors.END}")

    # Check common directories
    data_locations = [
        "/sdcard/Download/",
        "/sdcard/Pictures/",
        "/sdcard/Documents/",
        "/sdcard/DCIM/Camera/",
        "/data/data/",
        "/data/user/0/"
    ]

    for location in data_locations:
        file_count = execute_adb_command(
            device, f"find {location} -type f 2>/dev/null | wc -l")
        if file_count and file_count.strip() != "0":
            print(
                f"  {location}: {Colors.GREEN}{file_count.strip()} files{Colors.END}")


def perform_full_scan(device):
    """Perform comprehensive device scan"""
    logger.info("Performing full device scan...")

    print(f"{Colors.PURPLE}{Colors.BOLD}=== FULL DEVICE SCAN ==={Colors.END}")

    # Run all scans
    get_system_info(device)
    print()
    get_installed_apps(device)
    print()
    get_security_settings(device)
    print()
    get_network_config(device)
    print()
    get_hardware_info(device)
    print()
    analyze_certificates(device)
    print()
    find_user_data(device)

    logger.success("Full device scan completed")


def export_device_report(device):
    """Export device information to JSON report"""
    logger.info("Generating device report...")

    report = {
        "device_id": device,
        "scan_timestamp": subprocess.check_output(['date']).decode().strip(),
        "system_info": {},
        "security_info": {},
        "network_info": {},
        "hardware_info": {}
    }

    # Generate report file
    report_file = LOGS_DIR / \
        f"device_report_{device}_{report['scan_timestamp'].replace(' ', '_').replace(':', '-')}.json"

    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.success(f"Device report exported to: {report_file}")
        print(f"Report saved: {Colors.GREEN}{report_file}{Colors.END}")

    except Exception as e:
        logger.error(f"Failed to export report: {str(e)}")


if __name__ == "__main__":
    info_gathering_menu()
