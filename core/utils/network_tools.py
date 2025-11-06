import subprocess
import re
from core.adb.device_manager import DeviceManager
from core.utils import session_manager

dm = DeviceManager()


def network_tools_menu():
    device = dm.get_current_device()
    if not device:
        print("No device connected.")
        return

    while True:
        # show global menu header
        try:
            print(session_manager.get_menu_header())
        except Exception:
            pass
        print("\n[ NETWORK TOOLS ]")
        print("1. Get IP address")
        print("2. Get MAC address")
        print("3. Get Gateway IP")
        print("4. Check DNS")
        print("5. List open ports")
        print("6. Enable WiFi")
        print("7. Disable WiFi")
        print("8. Back to Main Menu")

        choice = input("> ")

        try:
            if choice == "1":
                print("IP:", get_ip(device))
            elif choice == "2":
                print("MAC:", get_mac(device))
            elif choice == "3":
                print("Gateway:", get_gateway(device))
            elif choice == "4":
                print("DNS:", check_dns(device))
            elif choice == "5":
                print(list_open_ports(device))
            elif choice == "6":
                enable_wifi(device)
            elif choice == "7":
                disable_wifi(device)
            elif choice == "8":
                break
            else:
                print("Invalid choice.")
        except Exception as e:
            print(f"[!] Error: {e}")


def get_ip(device):
    """Get the IP address of wlan0."""
    cmd = ["adb", "-s", device, "shell", "ip", "addr", "show", "wlan0"]
    output = subprocess.check_output(cmd).decode()
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
    return match.group(1) if match else "N/A"


def get_mac(device):
    """Get the MAC address of wlan0."""
    cmd = ["adb", "-s", device, "shell", "cat", "/sys/class/net/wlan0/address"]
    return subprocess.check_output(cmd).decode().strip()


def get_gateway(device):
    """Get the gateway IP address."""
    cmd = ["adb", "-s", device, "shell", "ip", "route"]
    output = subprocess.check_output(cmd).decode()
    return output.split("default via ")[1].split(" ")[0] if "default via" in output else "N/A"


def check_dns(device):
    """Check the primary DNS server."""
    cmd = ["adb", "-s", device, "shell", "getprop", "net.dns1"]
    return subprocess.check_output(cmd).decode().strip()


def list_open_ports(device):
    """List open ports using netstat."""
    cmd = ["adb", "-s", device, "shell", "netstat", "-tulpn"]
    return subprocess.check_output(cmd).decode()


def enable_wifi(device):
    """Enable WiFi on the device."""
    subprocess.run(["adb", "-s", device, "shell", "svc", "wifi", "enable"])


def disable_wifi(device):
    """Disable WiFi on the device."""
    subprocess.run(["adb", "-s", device, "shell", "svc", "wifi", "disable"])
