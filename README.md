## Androduct Framework (Play on abduct)

A Python-based Android security and penetration testing tool designed for ADB (Android Debug Bridge) exploitation, APK patching, and mobile red team operations Gith

## Project Structure

<details>
<summary>📂 Click to expand</summary>

```ini
Androduct-framework/
├── core/
│   ├── adb/                    # Android debug bridge (adb)
│   │   ├── shell.py
│   │   ├── file_ops.py
│   │   └── device_manager.py
│   ├── exploit/
│   │   ├── cve_launcher.py
│   │   ├── payloads.py
│   │   └── exploit_utils.py
|   |── patcher/                 # Decompile, inject, rebuild, sign
│   |   ├── __init__.py
│   |   ├── apk_patcher.py
│   |   └── patches/
│   |        ├── bypass_root.smali
│   |        └── ssl_unpin.smali
│   ├── utils/
│   │   ├── logger.py
│   │   └── netwoek_tools.py
|   |   └── session_manager.py
├── docs/                            # Documentations
├── logs/
├── modules/
│   ├── info_gathering.py
│   ├── persistence.py
│   ├── post_exploitation.py
├── main.py                        
├── config.py
└── README.md
```
</details>

## Usage

Ensure an android device is connected via USB or WiFi

```bash
python main.py
```

## Basic ADB Functionalities

- shell
- File operations (pull/push)
- Screen_record
- Screenshot
- Install an apk on a device
- Extract apk from app  
- Remove device password
- Get current activity
- Dump System Info 
- Shutdown a device


## Advanced ADB Attack Features

- Dump SMS/Call logs/Contacts	ADB + content command or SQLite DB pulls
- Keylogger (if rooted)	Use an accessibility service or custom payload
- Camera snap w/o preview	ADB call or push & run malicious app
- Live mic/audio recording	Same deal—shell into app or use intent
- Exfil file from internal storage	adb pull /data/data/<pkg>/files/* (needs root)
- App cloning or data theft	Pull APK and /data dirs, extract databases
- Start hidden persistent backdoor	Push service APK and set up auto-start
- ADB over Wi-Fi auto-enable	setprop service.adb.tcp.port 5555 && stop && start
- Frida Injection Support	Auto-push Frida-server and attach to apps


## Network Recon & MITM

- ARP scan for LAN devices	Add nmap wrapper or use scapy
- Auto MiTM setup (evil twin / rogue AP)	Integrate airgeddon or wifiphisher
- DNS spoofing / redirection	ettercap, dnsspoof, or mitmproxy
- Hijack session cookies (via mitmproxy)	Log/intercept sensitive traffic
- Scan for open ports on the Android target	Local nmap or netstat via ADB
- Auto-create reverse SSH tunnel	Enable port forwarding & reverse shell payload


## Red Team Persistence

- Set up persistent reverse shell	Inject startup script or abuse BOOT_COMPLETED
- Bypass lockscreen (via TWRP or exploits)	If rooted, edit settings.db
- Replace legit APK with trojanized one	Uninstall, repackage, and install
- Hide app from launcher	Modify manifest or use pm hide
- Use covert channels (e.g., SMS triggers)	Setup scripts that respond to SMS
- Encrypt & exfil stolen data	GPG + remote upload via ADB+curl or scp


## Toolbox Integration

- Payload Deployment	Auto-generate APK payloads via msfvenom or evil-droid
- C2 Communication	Tie in with Cobalt Strike, Sliver, or Mythic
- Exploit POCs	Include CVE scanner or LPE payload launcher
- Mobile RAT interface	Hook into a Python Flask dashboard with session controls


## Detection evasion

- Anti-forensics (log wiping)	Auto-clear logcat, remove command traces
- Auto-self-destruct payloads	Delete traces if internet goes out or timer hits
- Root-check & fingerprint	Check if device is vulnerable or rooted before going loud
- ADB command obfuscation	Randomize command structure, avoid detection by EDR-like tools


### Dependencies

- apktool (in your PATH)

- jarsigner (comes with JDK)

- debug.keystore (generate with keytool if missing)

- Your `patches/` folder with valid `.smali` templates

> This repo is for educational purposes, research, or authorized testing only. 

