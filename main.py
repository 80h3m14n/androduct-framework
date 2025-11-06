#!/usr/bin/env python3

from modules.exfiltration import exfiltration_menu
from modules.persistence import persistence_menu
from modules.info_gathering import info_gathering_menu
from modules.post_exploitation import post_exploitation_menu
from core.utils.network_tools import network_tools_menu
from core.patcher.apk_patcher import patcher_menu
from core.utils import session_manager
from core.utils.terminal_commander import terminal_menu
from core.exploit import cve_launcher
from core.adb import device_manager
from core.utils.logger import logger
from config import BANNER, Colors
import sys
import os
from pathlib import Path

# Add the framework root to the Python path
framework_root = Path(__file__).parent
sys.path.insert(0, str(framework_root))


def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')


def show_banner():
    """Display the framework banner"""
    clear_screen()
    print(BANNER)


def show_main_menu():
    """Display the main menu in a compact table format"""
    # show global menu header
    try:
        from core.utils import session_manager
        print(session_manager.get_menu_header())
    except Exception:
        pass

    print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                      {Colors.BOLD}ANDRODUCT FRAMEWORK{Colors.END}{Colors.CYAN}                       │{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[1]{Colors.END} Session Manager     {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[7]{Colors.END} Post-Exploitation    {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[2]{Colors.END} ADB Tools           {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[8]{Colors.END} Persistence          {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[3]{Colors.END} Device Information  {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[9]{Colors.END} Data Exfiltration    {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[4]{Colors.END} Network Recon       {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[10]{Colors.END} Terminal Commander  {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[5]{Colors.END} CVE Exploits        {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[0]{Colors.END} Exit Framework       {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[6]{Colors.END} APK Patcher         {Colors.CYAN}│{Colors.END}                          {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
""")


def show_framework_info():
    """Display framework information"""
    from config import FRAMEWORK_VERSION, AUTHOR
    clear_screen()
    print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                    {Colors.BOLD}FRAMEWORK INFORMATION{Colors.END}{Colors.CYAN}                      │{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│{Colors.END} {Colors.GREEN}Version:{Colors.END} {FRAMEWORK_VERSION:<50} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END} {Colors.GREEN}Author:{Colors.END} {AUTHOR:<51} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END} {Colors.GREEN}Python:{Colors.END} {sys.version.split()[0]:<51} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│{Colors.END} {Colors.GREEN}Directory:{Colors.END} {os.getcwd():<46} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}

{Colors.YELLOW}Press Enter to return to main menu...{Colors.END}""")
    input()


def execute_menu_option(choice):
    """Execute the selected menu option with proper screen clearing"""
    clear_screen()

    if choice == "1":
        logger.debug("Accessing Session Manager")
        session_manager.session_menu()
    elif choice == "2":
        logger.debug("Accessing ADB Tools")
        device_manager.adb_menu()
    elif choice == "3":
        logger.debug("Accessing Device Information")
        info_gathering_menu()
    elif choice == "4":
        logger.debug("Accessing Network Tools")
        network_tools_menu()
    elif choice == "5":
        logger.debug("Accessing CVE Exploits")
        cve_launcher.exploit_menu()
    elif choice == "6":
        logger.debug("Accessing APK Patcher")
        patcher_menu()
    elif choice == "7":
        logger.debug("Accessing Post-Exploitation Tools")
        post_exploitation_menu()
    elif choice == "8":
        logger.debug("Accessing Persistence Mechanisms")
        persistence_menu()
    elif choice == "9":
        logger.debug("Accessing Data Exfiltration")
        exfiltration_menu()
    elif choice == "10":
        logger.debug("Accessing Terminal Commander")
        terminal_menu()
    elif choice.lower() in ["0", "exit"]:
        return False  # Signal to exit
    else:
        print(f"{Colors.RED}Invalid option. Please try again.{Colors.END}")
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")

    return True  # Continue running


def main():
    """Main application entry point"""
    try:
        show_banner()
        logger.info("Androduct Framework started")

        while True:
            show_main_menu()
            choice = input(
                f"{Colors.RED}androduct{Colors.END}{Colors.CYAN}@{Colors.END}{Colors.GREEN}framework{Colors.END} {Colors.YELLOW}➤{Colors.END} ").strip()

            if choice == "0":
                logger.info("Framework shutdown initiated")
                clear_screen()
                print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                        {Colors.BOLD}GOODBYE!{Colors.END}{Colors.CYAN}                              │{Colors.END}
{Colors.CYAN}│                                                                 │{Colors.END}
{Colors.CYAN}│               {Colors.GREEN}Thanks for using Androduct Framework{Colors.END}{Colors.CYAN}            │{Colors.END}
{Colors.CYAN}│                        {Colors.YELLOW}Peace out 🖖{Colors.END}{Colors.CYAN}                        │{Colors.END}
{Colors.CYAN}│                                                                 │{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
""")
                break

            # Execute the selected option
            continue_running = execute_menu_option(choice)
            if not continue_running:
                break

    except KeyboardInterrupt:
        clear_screen()
        print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                    {Colors.BOLD}INTERRUPTED{Colors.END}{Colors.CYAN}                               │{Colors.END}
{Colors.CYAN}│                                                                 │{Colors.END}
{Colors.CYAN}│              {Colors.YELLOW}Framework interrupted by user{Colors.END}{Colors.CYAN}                │{Colors.END}
{Colors.CYAN}│                     {Colors.GREEN}Exiting safely...{Colors.END}{Colors.CYAN}                      │{Colors.END}
{Colors.CYAN}│                                                                 │{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
""")
        logger.info("Framework interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        clear_screen()
        print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                       {Colors.BOLD}ERROR{Colors.END}{Colors.CYAN}                                 │{Colors.END}
{Colors.CYAN}│                                                                 │{Colors.END}
{Colors.CYAN}│ {Colors.RED}An unexpected error occurred:{Colors.END}{Colors.CYAN}                              │{Colors.END}
{Colors.CYAN}│ {Colors.RED}{str(e)[:55]:<55}{Colors.END}{Colors.CYAN} │{Colors.END}
{Colors.CYAN}│                                                                 │{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
""")
    finally:
        logger.info("Androduct Framework session ended")


if __name__ == "__main__":
    main()
