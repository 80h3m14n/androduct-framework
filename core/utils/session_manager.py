#!/usr/bin/env python3
"""
Session Manager for Androduct Framework
Manages device connections and session state
"""

import json
import subprocess
import os
from datetime import datetime
from pathlib import Path
from config import LOGS_DIR, Colors
from core.utils.logger import logger

# Global sessions dictionary
sessions = {}

# Global device state - persisted across modules
global_device_state = {
    "current_device": None,
    "connected_devices": [],
    "last_refresh": None,
    "device_info": {}
}


def refresh_device_list():
    """Refresh connected devices using adb and update global state."""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True)
        devices = []
        device_info = {}

        for line in result.stdout.splitlines()[1:]:
            if line.strip() and 'device' in line and 'offline' not in line:
                device_id = line.split()[0]
                devices.append(device_id)

                # gather basic info
                try:
                    model_result = subprocess.run(
                        ['adb', '-s', device_id, 'shell',
                            'getprop', 'ro.product.model'],
                        capture_output=True, text=True, timeout=3
                    )
                    model = model_result.stdout.strip() if model_result.returncode == 0 else 'Unknown'

                    version_result = subprocess.run(
                        ['adb', '-s', device_id, 'shell',
                            'getprop', 'ro.build.version.release'],
                        capture_output=True, text=True, timeout=3
                    )
                    version = version_result.stdout.strip(
                    ) if version_result.returncode == 0 else 'Unknown'

                    connection_type = 'WiFi' if ':' in device_id else 'USB'

                    device_info[device_id] = {
                        'model': model,
                        'android_version': version,
                        'connection_type': connection_type,
                        'status': 'connected'
                    }
                except Exception:
                    device_info[device_id] = {
                        'model': 'Unknown',
                        'android_version': 'Unknown',
                        'connection_type': 'WiFi' if ':' in device_id else 'USB',
                        'status': 'connected'
                    }

        global_device_state['connected_devices'] = devices
        global_device_state['device_info'] = device_info
        global_device_state['last_refresh'] = datetime.now().isoformat()

        # validate current_device
        if global_device_state['current_device'] and global_device_state['current_device'] not in devices:
            global_device_state['current_device'] = None

        # auto-select first device if none selected
        if not global_device_state['current_device'] and devices:
            global_device_state['current_device'] = devices[0]
            # ensure a session is created for the auto-selected device
            try:
                device_id = global_device_state['current_device']
                if device_id not in sessions:
                    conn_type = 'ADB_WIFI' if ':' in device_id else 'ADB_USB'
                    add_session(device_id, conn_type, 'Auto-added by refresh')
            except Exception:
                # don't fail refresh if session creation errors
                pass

        return devices
    except Exception as e:
        logger.error(f"Failed to refresh device list: {str(e)}")
        return []


def get_current_device():
    """Return the currently selected device (auto-refreshes list)."""
    refresh_device_list()
    return global_device_state.get('current_device')


def set_current_device(device_id):
    """Set the globally selected device if it's connected."""
    refresh_device_list()
    if device_id in global_device_state['connected_devices']:
        global_device_state['current_device'] = device_id
        # ensure session exists
        if device_id not in sessions:
            add_session(device_id, 'ADB', 'Auto-added')
        return True
    else:
        return False


def get_connected_devices():
    refresh_device_list()
    return global_device_state.get('connected_devices', [])


def get_device_info(device_id=None):
    if device_id is None:
        device_id = get_current_device()
    if not device_id:
        return {}
    return global_device_state.get('device_info', {}).get(device_id, {})


def is_device_connected(device_id=None):
    if device_id is None:
        device_id = get_current_device()
    if not device_id:
        return False
    refresh_device_list()
    return device_id in global_device_state.get('connected_devices', [])


def get_menu_header():
    """Return a single-line formatted menu header showing connected device info."""
    device = get_current_device()
    if not device:
        return f"{Colors.CYAN}Status: {Colors.YELLOW}No device connected{Colors.END}"

    info = get_device_info(device)
    model = info.get('model', 'Unknown')
    conn = info.get('connection_type', 'Unknown')
    ip = device if ':' in device else ''

    parts = []
    parts.append(f"{Colors.CYAN}Status:{Colors.END}")
    parts.append(f"{Colors.GREEN}{model}{Colors.END}")
    parts.append(f"{Colors.YELLOW}[{device}]{Colors.END}")
    if ip:
        parts.append(f"{Colors.CYAN}({ip}){Colors.END}")
    else:
        parts.append(f"{Colors.CYAN}({conn}){Colors.END}")

    return ' '.join(parts)


def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')


def session_menu():
    """Main session management menu"""
    while True:
        clear_screen()
        print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                     {Colors.BOLD}SESSION MANAGER{Colors.END}{Colors.CYAN}                         │{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[1]{Colors.END} List Active Sessions   {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[4]{Colors.END} Session Details        {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[2]{Colors.END} Add New Session        {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[5]{Colors.END} Export Session Log     {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[3]{Colors.END} Close Session          {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[6]{Colors.END} Cleanup Dead Sessions  {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│                                {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[0]{Colors.END} Back to Main Menu      {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
        """)

        choice = input(
            f"{Colors.CYAN}session{Colors.END}{Colors.YELLOW}@{Colors.END}{Colors.GREEN}manager{Colors.END} {Colors.YELLOW}➤{Colors.END} ").strip()

        if choice == "1":
            list_sessions()
        elif choice == "2":
            add_session_interactive()
        elif choice == "3":
            close_session_interactive()
        elif choice == "4":
            show_session_details()
        elif choice == "5":
            export_session_log()
        elif choice == "6":
            cleanup_dead_sessions()
        elif choice == "0":
            break
        else:
            logger.warning("Invalid option selected")
            print(f"{Colors.RED}Invalid option. Please try again.{Colors.END}")
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")


def add_session(device_id, method, details=""):
    """Add a new session"""
    sessions[device_id] = {
        "method": method,
        "status": "active",
        "start_time": datetime.now().isoformat(),
        "details": details,
        "last_activity": datetime.now().isoformat()
    }

    logger.log_session("SESSION_START", device_id,
                       f"Method: {method}, Details: {details}")
    logger.success(f"Session added: {device_id} via {method}")


def add_session_interactive():
    """Interactive session addition"""
    print(f"{Colors.YELLOW}Add New Session{Colors.END}")

    device_id = input("Device ID/IP: ").strip()
    if not device_id:
        logger.error("Device ID required")
        return

    print("Connection methods:")
    print("1. ADB USB")
    print("2. ADB WiFi")
    print("3. SSH")
    print("4. Custom")

    method_choice = input("Select method (1-4): ").strip()

    methods = {
        "1": "ADB_USB",
        "2": "ADB_WIFI",
        "3": "SSH",
        "4": "CUSTOM"
    }

    method = methods.get(method_choice, "UNKNOWN")

    if method == "ADB_WIFI":
        port = input("Port (default 5555): ").strip() or "5555"
        details = f"Port: {port}"

        # Try to connect
        try:
            result = subprocess.run(["adb", "connect", f"{device_id}:{port}"],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                logger.success(f"Connected to {device_id}:{port}")
            else:
                logger.error(f"Failed to connect: {result.stderr}")
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
    else:
        details = input("Additional details (optional): ").strip()

    add_session(device_id, method, details)


def list_sessions():
    """List all active sessions"""
    print(f"\n{Colors.YELLOW}=== Active Sessions ==={Colors.END}")

    if not sessions:
        print(f"{Colors.RED}No active sessions.{Colors.END}")
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
        return

    print(f"{'Device ID':<20} {'Method':<12} {'Status':<10} {'Started':<20}")
    print("-" * 70)

    for device_id, data in sessions.items():
        start_time = datetime.fromisoformat(
            data['start_time']).strftime("%Y-%m-%d %H:%M")
        status_color = Colors.GREEN if data['status'] == 'active' else Colors.RED

        print(
            f"{device_id:<20} {data['method']:<12} {status_color}{data['status']:<10}{Colors.END} {start_time}")
    # Pause so user can read the list before returning to the menu
    input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")


def close_session(device_id):
    """Close a specific session"""
    if device_id in sessions:
        sessions[device_id]['status'] = 'closed'
        sessions[device_id]['end_time'] = datetime.now().isoformat()

        logger.log_session("SESSION_END", device_id)
        logger.success(f"Session {device_id} closed")

        # Try to disconnect if ADB
        if sessions[device_id]['method'] in ['ADB_WIFI', 'ADB_USB']:
            try:
                subprocess.run(["adb", "disconnect", device_id],
                               capture_output=True, text=True)
            except:
                pass

        return True
    else:
        logger.error("Session not found")
        return False


def close_session_interactive():
    """Interactive session closure"""
    if not sessions:
        logger.error("No active sessions to close")
        return

    print(f"{Colors.YELLOW}Active sessions:{Colors.END}")
    active_sessions = [(k, v)
                       for k, v in sessions.items() if v['status'] == 'active']

    if not active_sessions:
        logger.error("No active sessions found")
        return

    for i, (device_id, data) in enumerate(active_sessions, 1):
        print(f"  [{i}] {device_id} via {data['method']}")

    try:
        choice = int(input("Select session to close (number): ")) - 1
        if 0 <= choice < len(active_sessions):
            device_id = active_sessions[choice][0]
            close_session(device_id)
        else:
            logger.error("Invalid selection")
    except (ValueError, IndexError):
        logger.error("Invalid selection")


def show_session_details():
    """Show detailed information about a session"""
    if not sessions:
        logger.error("No sessions available")
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
        return

    device_id = input("Enter device ID: ").strip()

    if device_id in sessions:
        session_data = sessions[device_id]

        print(f"\n{Colors.CYAN}Session Details: {device_id}{Colors.END}")
        print(f"Method: {Colors.GREEN}{session_data['method']}{Colors.END}")
        print(
            f"Status: {Colors.GREEN if session_data['status'] == 'active' else Colors.RED}{session_data['status']}{Colors.END}")
        print(
            f"Started: {Colors.YELLOW}{session_data['start_time']}{Colors.END}")

        if 'end_time' in session_data:
            print(
                f"Ended: {Colors.YELLOW}{session_data['end_time']}{Colors.END}")

        if session_data.get('details'):
            print(
                f"Details: {Colors.CYAN}{session_data['details']}{Colors.END}")

        # Test connection if active
        if session_data['status'] == 'active':
            print(f"\n{Colors.YELLOW}Testing connection...{Colors.END}")
            test_connection(device_id, session_data['method'])
        # Pause to allow user to read details
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
    else:
        logger.error("Session not found")
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")


def test_connection(device_id, method):
    """Test if connection is still active"""
    try:
        if method in ['ADB_WIFI', 'ADB_USB']:
            result = subprocess.run(["adb", "-s", device_id, "shell", "echo", "test"],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.success("Connection is active")
                update_session_activity(device_id)
            else:
                logger.error("Connection failed")
                sessions[device_id]['status'] = 'disconnected'
        else:
            logger.info("Manual connection test required")

    except subprocess.TimeoutExpired:
        logger.error("Connection test timed out")
        sessions[device_id]['status'] = 'timeout'
    except Exception as e:
        logger.error(f"Connection test failed: {str(e)}")
        sessions[device_id]['status'] = 'error'


def update_session_activity(device_id):
    """Update last activity time for a session"""
    if device_id in sessions:
        sessions[device_id]['last_activity'] = datetime.now().isoformat()


def cleanup_dead_sessions():
    """Remove sessions that are no longer active"""
    logger.info("Cleaning up dead sessions...")

    dead_sessions = []

    for device_id, session_data in sessions.items():
        if session_data['status'] in ['closed', 'disconnected', 'error']:
            dead_sessions.append(device_id)
        elif session_data['status'] == 'active':
            # Test connection
            test_connection(device_id, session_data['method'])
            if session_data['status'] != 'active':
                dead_sessions.append(device_id)

    for device_id in dead_sessions:
        del sessions[device_id]
        logger.info(f"Removed dead session: {device_id}")

    if dead_sessions:
        logger.success(f"Cleaned up {len(dead_sessions)} dead sessions")
    else:
        logger.info("No dead sessions found")


def export_session_log():
    """Export session data to JSON file"""
    if not sessions:
        logger.error("No sessions to export")
        return

    log_file = LOGS_DIR / \
        f"sessions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(log_file, 'w') as f:
            json.dump(sessions, f, indent=2)

        logger.success(f"Session log exported to: {log_file}")

    except Exception as e:
        logger.error(f"Failed to export session log: {str(e)}")


def get_active_sessions():
    """Get list of active session device IDs"""
    return [device_id for device_id, data in sessions.items() if data['status'] == 'active']


def get_session_info(device_id):
    """Get information about a specific session"""
    return sessions.get(device_id)

# Backward compatibility functions


def list_sessions_old():
    """Old list_sessions function for compatibility"""
    list_sessions()


if __name__ == "__main__":
    session_menu()
