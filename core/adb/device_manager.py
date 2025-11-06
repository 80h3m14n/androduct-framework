import subprocess
import os
from core.utils import session_manager
from core.adb import adb_tools
from config import Colors


def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')


class DeviceManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DeviceManager, cls).__new__(cls)
            cls._instance.connected_devices = cls._instance._get_connected_devices()
            cls._instance.current_device = None
        return cls._instance

    def _get_connected_devices(self):
        result = subprocess.run(
            ['adb', 'devices'], capture_output=True, text=True)
        devices = []
        for line in result.stdout.splitlines()[1:]:
            if line.strip() and 'device' in line:
                devices.append(line.split()[0])
        return devices

    def list_devices(self):
        self.connected_devices = self._get_connected_devices()
        return self.connected_devices

    def set_current_device(self, device_id):
        if device_id in self.connected_devices:
            self.current_device = device_id
            return True
        return False

    def get_current_device(self):
        if self.current_device:
            return self.current_device
        # fallback to first connected device
        if self.connected_devices:
            self.current_device = self.connected_devices[0]
            return self.current_device
        return None


def adb_menu():
    try:
        while True:
            clear_screen()
            # show global menu header
            try:
                header = session_manager.get_menu_header()
                print(header)
            except Exception:
                pass
            print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                       {Colors.BOLD}ADB TOOLS{Colors.END}{Colors.CYAN}                              │{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}Device Management{Colors.END}{Colors.CYAN}              │ {Colors.YELLOW}Media Capture{Colors.END}{Colors.CYAN}                │{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[1]{Colors.END} Show Devices            {Colors.CYAN}│{Colors.END} {Colors.GREEN}[8]{Colors.END}  Screenshot              {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[2]{Colors.END} Connect Device          {Colors.CYAN}│{Colors.END} {Colors.GREEN}[9]{Colors.END}  Screen Record           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[3]{Colors.END} ADB Shell               {Colors.CYAN}│{Colors.END} {Colors.GREEN}[10]{Colors.END} Camera Photo            {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[4]{Colors.END} Remove Password         {Colors.CYAN}│{Colors.END} {Colors.GREEN}[11]{Colors.END} Record Audio            {Colors.CYAN}│{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}Data Extraction{Colors.END}{Colors.CYAN}               │ {Colors.YELLOW}Device Control{Colors.END}{Colors.CYAN}               │{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[5]{Colors.END} Dump SMS                {Colors.CYAN}│{Colors.END} {Colors.GREEN}[12]{Colors.END} Install APK             {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[6]{Colors.END} Dump Call Logs          {Colors.CYAN}│{Colors.END} {Colors.GREEN}[13]{Colors.END} Uninstall APK           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[7]{Colors.END} Dump Contacts           {Colors.CYAN}│{Colors.END} {Colors.GREEN}[14]{Colors.END} Current Activity        {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│                                 │{Colors.END} {Colors.GREEN}[15]{Colors.END} Enable ADB WiFi         {Colors.CYAN}│{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}File Operations{Colors.END}{Colors.CYAN}               │ {Colors.YELLOW}Advanced{Colors.END}{Colors.CYAN}                    │{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[16]{Colors.END} Pull File               {Colors.CYAN}│{Colors.END} {Colors.GREEN}[19]{Colors.END} Setup Keylogger         {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[17]{Colors.END} Push File               {Colors.CYAN}│{Colors.END} {Colors.GREEN}[20]{Colors.END} Disable ADB WiFi        {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}[18]{Colors.END} Stealth APK Install     {Colors.CYAN}│{Colors.END} {Colors.GREEN}[21]{Colors.END} Shutdown Device         {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│                                 │{Colors.END} {Colors.GREEN}[0]{Colors.END}  Back to Main Menu      {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
            """)
            choice = input(
                f"{Colors.CYAN}adb{Colors.END}{Colors.YELLOW}@{Colors.END}{Colors.GREEN}tools{Colors.END} {Colors.YELLOW}➤{Colors.END} ").strip()

            if choice == "1":
                subprocess.run(["adb", "devices"])
            elif choice == "2":
                ip = input("Enter device IP: ")
                result = subprocess.run(["adb", "connect", ip])
                if result.returncode == 0:
                    session_manager.add_session(ip, "ADB")
                else:
                    print("Failed to connect to device.")
            elif choice == "3":
                device = input("Enter device ID (or leave blank): ")
                cmd = ["adb", "shell"] if not device else [
                    "adb", "-s", device, "shell"]
                subprocess.run(cmd)
            elif choice == "4":
                adb_tools.reset_security_flow()
            elif choice == "5":
                adb_tools.dump_sms_messages()
            elif choice == "6":
                adb_tools.dump_call_logs()
            elif choice == "7":
                adb_tools.dump_contacts()
            elif choice == "8":
                adb_tools.screenshot()
            elif choice == "9":
                adb_tools.screen_record()
            elif choice == "10":
                adb_tools.capture_camera()
            elif choice == "11":
                adb_tools.record_audio()
            elif choice == "12":
                adb_tools.install_apk()
            elif choice == "13":
                adb_tools.uninstall_apk()
            elif choice == "14":
                adb_tools.get_current_activity()
            elif choice == "15":
                adb_tools.enable_adb_wifi()
            elif choice == "16":
                adb_tools.pull_file()
            elif choice == "17":
                adb_tools.push_file()
            elif choice == "18":
                adb_tools.stealth_apk_install()
            elif choice == "19":
                adb_tools.keylogger_setup()
            elif choice == "20":
                adb_tools.disable_adb_wifi()
            elif choice == "21":
                adb_tools.shutdown_device()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.END}")
                input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Exiting ADB menu.{Colors.END}")
