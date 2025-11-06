import os
import shutil
import subprocess
from pathlib import Path
from core.utils import session_manager
from datetime import datetime
from config import Colors

log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
log_file = log_dir / \
    f"patch_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


def log(msg):
    with open(log_file, "a") as f:
        f.write(msg + "\n")
# Constants
# Ensure these tools are installed and available in PATH


APKTOOL = "apktool"
KEYSTORE = "debug.keystore"
KEY_ALIAS = "androiddebugkey"
KEY_PASS = "android"

# Patch map at module level
patch_map = {
    "root": "bypass_root.smali",
    "ssl": "ssl_unpin.smali",
    "emulator": "bypass_emulator.smali",
    "frida": "bypass_frida.smali",
    "xposed": "bypass_xposed.smali",
    "debug": "bypass_debug.smali",
    "webview_ssl": "webview_ssl_bypass.smali",
    "mock_location": "bypass_mocklocation.smali"
}


def patch_apk(apk_path, patch_type):
    if patch_type not in patch_map:
        msg = "[✗] Invalid patch type."
        print(msg)
        log(msg)
        return

    apk_name = Path(apk_path).stem
    work_dir = Path(f"patched_apks/{apk_name}")
    smali_patch = Path(__file__).parent / "patches" / patch_map[patch_type]

    try:
        print(f"[+] Decompiling {apk_path}")
        subprocess.run([APKTOOL, "d", apk_path, "-o",
                       str(work_dir), "--force"], check=True)
        log(f"[✓] Decompile success: {apk_path}")
    except subprocess.CalledProcessError:
        log(f"[✗] Decompile failed: {apk_path}")
        return

    print(f"[+] Locating target smali path...")
    package_path = find_target_class(work_dir, smali_patch)
    if not package_path:
        msg = "[✗] Target class not found. Aborting patch."
        print(msg)
        log(msg)
        return

    try:
        target_file = Path(package_path)
        shutil.copy(smali_patch, target_file)
        log(f"[✓] Patch injected: {target_file}")
    except Exception as e:
        log(f"[✗] Patch injection failed: {e}")
        return

    rebuilt_apk = Path(f"{apk_name}_patched.apk")
    try:
        print("[+] Rebuilding APK...")
        subprocess.run([APKTOOL, "b", str(work_dir), "-o",
                       str(rebuilt_apk)], check=True)
        log(f"[✓] Rebuild success: {rebuilt_apk}")
    except subprocess.CalledProcessError:
        log(f"[✗] Rebuild failed: {rebuilt_apk}")
        return

    try:
        print("[+] Signing APK...")
        subprocess.run([
            "jarsigner", "-verbose", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1",
            "-keystore", KEYSTORE, "-storepass", KEY_PASS,
            str(rebuilt_apk), KEY_ALIAS
        ], check=True)
        log(f"[✓] Signed APK: {rebuilt_apk}")
    except subprocess.CalledProcessError:
        log(f"[✗] Signing failed: {rebuilt_apk}")
        return

    print(f"[✓] Patched and signed APK: {rebuilt_apk}")
    log(f"[✓] Full patch flow complete for {apk_path}\n")


def find_target_class(decompiled_dir, patch_file):
    """
    Tries to match class path from the .smali template to the decompiled APK structure.
    """
    with open(patch_file, "r") as f:
        for line in f:
            if line.startswith(".class"):
                class_path = line.split(" ")[-1].strip().strip(";")
                break
        else:
            return None

    class_path = class_path.lstrip("L").replace("/", os.sep) + ".smali"

    for smali_dir in Path(decompiled_dir).rglob("smali*"):
        full_path = smali_dir / class_path
        if full_path.exists():
            return full_path

    # If not found, just inject into original location
    return Path(smali_dir) / class_path


def patcher_menu():
    while True:
        clear_screen()
        # unified menu header
        try:
            print(session_manager.get_menu_header())
        except Exception:
            pass

        print(f"""
{Colors.CYAN}APK Patcher Menu{Colors.END}
{Colors.CYAN}==============={Colors.END}
{Colors.YELLOW}🔧 Security Bypasses{Colors.END}
[1] Patch Root Detection
[2] Patch SSL Pinning
[3] Patch Emulator Detection
[4] Patch Frida Detection
[5] Patch Xposed Detection
[6] Patch Debug Detection

{Colors.YELLOW}🌐 Network Bypasses{Colors.END}
[7] Patch WebView SSL
[8] Patch Mock Location

{Colors.YELLOW}⚙️  Utilities{Colors.END}
[9] List Available Patches
[10] Custom Patch
[11] Batch Patching

[0] Back to Main Menu
        """)
        choice = input(f"{Colors.CYAN}patcher{Colors.END} > ").strip()

        if choice == "1":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "root")
        elif choice == "2":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "ssl")
        elif choice == "3":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "emulator")
        elif choice == "4":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "frida")
        elif choice == "5":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "xposed")
        elif choice == "6":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "debug")
        elif choice == "7":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "webview_ssl")
        elif choice == "8":
            apk = input("Path to APK: ").strip()
            if apk:
                patch_apk(apk, "mock_location")
        elif choice == "9":
            list_available_patches()
        elif choice == "10":
            custom_patch_menu()
        elif choice == "11":
            batch_patching_menu()
        elif choice == "12":
            install_patched_apk()
        elif choice == "13":
            extract_apk_from_device()
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
        elif choice == "14":
            show_installed_apps()
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
        elif choice == "15":
            show_apk_discovery_menu()
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")
        elif choice == "0":
            break
        else:
            print(f"{Colors.RED}Invalid option.{Colors.END}")


def list_available_patches():
    """List all available patches"""
    print(f"\n{Colors.YELLOW}Available Patches:{Colors.END}")
    print(f"{'Patch Type':<20} {'Description':<40} {'File'}")
    print("-" * 75)

    patch_descriptions = {
        "root": "Bypass root detection checks",
        "ssl": "Disable SSL certificate pinning",
        "emulator": "Bypass emulator detection",
        "frida": "Bypass Frida detection",
        "xposed": "Bypass Xposed detection",
        "debug": "Bypass debug detection",
        "webview_ssl": "Bypass WebView SSL checks",
        "mock_location": "Bypass mock location detection"
    }

    for patch_type, filename in patch_map.items():
        description = patch_descriptions.get(patch_type, "No description")
        print(f"{patch_type:<20} {description:<40} {filename}")


def custom_patch_menu():
    """Custom patch creation menu"""
    # show global menu header
    try:
        print(session_manager.get_menu_header())
    except Exception:
        pass

    print(f"\n{Colors.YELLOW}Custom Patch Options:{Colors.END}")
    print("1. Create new patch from template")
    print("2. Apply custom smali file")
    print("3. Inject custom code")

    choice = input("Select option: ").strip()

    if choice == "1":
        create_patch_template()
    elif choice == "2":
        apply_custom_smali()
    elif choice == "3":
        inject_custom_code()


def batch_patching_menu():
    """Batch patching menu"""
    # show global menu header
    try:
        print(session_manager.get_menu_header())
    except Exception:
        pass

    print(f"\n{Colors.YELLOW}Batch Patching:{Colors.END}")

    apk_dir = input("Enter directory containing APKs: ").strip()
    if not os.path.exists(apk_dir):
        print(f"{Colors.RED}Directory not found.{Colors.END}")
        return

    patches = input(
        "Enter patch types (comma-separated, e.g., root,ssl): ").strip().split(',')
    patches = [p.strip() for p in patches if p.strip() in patch_map]

    if not patches:
        print(f"{Colors.RED}No valid patches specified.{Colors.END}")
        return

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith('.apk')]

    if not apk_files:
        print(f"{Colors.RED}No APK files found in directory.{Colors.END}")
        return

    print(f"Found {len(apk_files)} APK files")
    print(f"Will apply patches: {', '.join(patches)}")

    if input("Continue? (y/N): ").lower() == 'y':
        for apk_file in apk_files:
            apk_path = os.path.join(apk_dir, apk_file)
            print(f"\n{Colors.CYAN}Processing: {apk_file}{Colors.END}")

            for patch_type in patches:
                patch_apk(apk_path, patch_type)


def create_patch_template():
    """Create a new patch template"""
    patch_name = input("Enter patch name: ").strip()
    if not patch_name:
        return

    template = f""".class public Lcom/example/security/{patch_name.title()}Check;
.super Ljava/lang/Object;

.method public static is{patch_name.title()}()Z
    .locals 1

    const/4 v0, 0x0   # Always return false
    return v0
.end method
"""

    template_file = Path(__file__).parent / "patches" / \
        f"bypass_{patch_name.lower()}.smali"

    try:
        with open(template_file, 'w') as f:
            f.write(template)

        print(f"{Colors.GREEN}Template created: {template_file}{Colors.END}")

        # Add to patch map
        patch_map[patch_name.lower()] = f"bypass_{patch_name.lower()}.smali"

    except Exception as e:
        print(f"{Colors.RED}Failed to create template: {str(e)}{Colors.END}")


def apply_custom_smali():
    """Apply a custom smali file"""
    apk_path = input("Path to APK: ").strip()
    smali_path = input("Path to custom smali file: ").strip()

    if not os.path.exists(apk_path):
        print(f"{Colors.RED}APK file not found.{Colors.END}")
        return

    if not os.path.exists(smali_path):
        print(f"{Colors.RED}Smali file not found.{Colors.END}")
        return

    apk_name = Path(apk_path).stem
    work_dir = Path(f"patched_apks/{apk_name}")

    try:
        # Decompile APK
        print(f"{Colors.YELLOW}Decompiling APK...{Colors.END}")
        subprocess.run([APKTOOL, "d", apk_path, "-o",
                       str(work_dir), "--force"], check=True)

        # Copy custom smali file
        target_dir = work_dir / "smali" / "com" / "example"
        target_dir.mkdir(parents=True, exist_ok=True)

        smali_filename = Path(smali_path).name
        target_file = target_dir / smali_filename

        shutil.copy(smali_path, target_file)
        print(f"{Colors.GREEN}Custom smali applied: {target_file}{Colors.END}")

        # Rebuild and sign
        rebuilt_apk = Path(f"{apk_name}_custom_patched.apk")

        print(f"{Colors.YELLOW}Rebuilding APK...{Colors.END}")
        subprocess.run([APKTOOL, "b", str(work_dir), "-o",
                       str(rebuilt_apk)], check=True)

        print(f"{Colors.YELLOW}Signing APK...{Colors.END}")
        subprocess.run([
            "jarsigner", "-verbose", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1",
            "-keystore", KEYSTORE, "-storepass", KEY_PASS,
            str(rebuilt_apk), KEY_ALIAS
        ], check=True)

        print(f"{Colors.GREEN}Custom patched APK created: {rebuilt_apk}{Colors.END}")

    except Exception as e:
        print(f"{Colors.RED}Custom patching failed: {str(e)}{Colors.END}")


def inject_custom_code():
    """Inject custom code into an APK"""
    print(f"{Colors.YELLOW}Custom code injection - advanced feature{Colors.END}")
    print("This feature allows injection of custom Java/Smali code")

    apk_path = input("Path to APK: ").strip()
    if not os.path.exists(apk_path):
        print(f"{Colors.RED}APK file not found.{Colors.END}")
        return

    code_type = input("Code type (java/smali): ").strip().lower()

    if code_type == "java":
        java_code = input("Enter Java code (or file path): ").strip()
        print(
            f"{Colors.YELLOW}Java code injection requires compilation to smali{Colors.END}")
        print("Consider using online Java to Smali converters")
    elif code_type == "smali":
        smali_code = input("Enter Smali code (or file path): ").strip()

        if os.path.exists(smali_code):
            with open(smali_code, 'r') as f:
                smali_content = f.read()
        else:
            smali_content = smali_code

        print(f"{Colors.GREEN}Smali code prepared for injection{Colors.END}")
        print("Manual injection required - use APK patching workflow")
    else:
        print(f"{Colors.RED}Invalid code type{Colors.END}")
