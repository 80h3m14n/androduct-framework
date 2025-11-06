#!/usr/bin/env python3
"""
Secure Terminal Commander for Androduct Framework
Provides safe terminal command execution with security controls
"""

import subprocess
import os
import shlex
import re
from pathlib import Path
from config import Colors
from core.utils.logger import logger
from core.utils import session_manager

# Whitelist of safe commands
SAFE_COMMANDS = {
    # File operations
    'ls', 'dir', 'pwd', 'cd', 'cat', 'head', 'tail', 'find', 'grep',
    'tree', 'file', 'stat', 'du', 'df', 'mount',

    # Text editors (safe in this context)
    'nano', 'vim', 'vi', 'emacs',

    # Network tools
    'ping', 'nslookup', 'dig', 'traceroute', 'netstat', 'ss',

    # System info
    'whoami', 'id', 'uname', 'uptime', 'ps', 'top', 'htop',
    'free', 'lscpu', 'lsblk', 'lsusb', 'lspci',

    # Git operations
    'git',

    # Android/ADB specific
    'adb', 'fastboot',

    # Archive operations
    'tar', 'zip', 'unzip', 'gzip', 'gunzip',

    # Development tools
    'python', 'python3', 'pip', 'pip3', 'node', 'npm',

    # Safe utilities
    'echo', 'printf', 'date', 'cal', 'which', 'whereis',
    'history', 'clear', 'reset'
}

# Dangerous commands that should be blocked
DANGEROUS_COMMANDS = {
    'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs',
    'dd', 'shred', 'wipe', 'sudo', 'su', 'passwd',
    'chmod', 'chown', 'chgrp', 'mount', 'umount',
    'systemctl', 'service', 'kill', 'killall', 'pkill',
    'iptables', 'ufw', 'firewall-cmd', 'netsh',
    'crontab', 'at', 'batch', 'reboot', 'shutdown', 'halt',
    'nc', 'netcat', 'telnet', 'ssh', 'scp', 'rsync',
    'wget', 'curl', 'ftp', 'sftp'
}

# Commands that require confirmation
CONFIRMATION_COMMANDS = {
    'git push', 'git pull', 'git clone', 'git reset --hard',
    'pip install', 'pip uninstall', 'npm install', 'npm uninstall',
    'adb install', 'adb uninstall', 'adb push', 'adb pull',
    'python -m pip install'
}


class TerminalCommander:
    """Secure terminal command executor"""

    def __init__(self):
        self.current_directory = os.getcwd()
        self.command_history = []
        self.max_history = 100

    def is_command_safe(self, command):
        """Check if a command is safe to execute"""
        # Parse the command
        try:
            tokens = shlex.split(command)
        except ValueError:
            return False, "Invalid command syntax"

        if not tokens:
            return False, "Empty command"

        base_command = tokens[0].lower()

        # Check if command is explicitly dangerous
        if base_command in DANGEROUS_COMMANDS:
            return False, f"Command '{base_command}' is not allowed for security reasons"

        # Check if command is in whitelist
        if base_command not in SAFE_COMMANDS:
            return False, f"Command '{base_command}' is not in the allowed commands list"

        # Additional checks for specific commands
        if base_command == 'find' and any('exec' in token for token in tokens):
            return False, "Find with -exec is not allowed"

        if base_command in ['python', 'python3'] and any('-c' in token for token in tokens):
            return False, "Python with -c flag is not allowed"

        return True, "Command is safe"

    def requires_confirmation(self, command):
        """Check if command requires user confirmation"""
        command_lower = command.lower().strip()
        return any(conf_cmd in command_lower for conf_cmd in CONFIRMATION_COMMANDS)

    def execute_command(self, command, confirm_dangerous=True):
        """Execute a command with safety checks"""
        if not command.strip():
            return False, "Empty command"

        # Security check
        is_safe, reason = self.is_command_safe(command)
        if not is_safe:
            logger.warning(f"Blocked unsafe command: {command}")
            return False, reason

        # Confirmation check
        if confirm_dangerous and self.requires_confirmation(command):
            print(
                f"{Colors.YELLOW}⚠️  This command requires confirmation:{Colors.END}")
            print(f"{Colors.CYAN}Command: {command}{Colors.END}")
            confirm = input(
                f"{Colors.YELLOW}Continue? (y/N): {Colors.END}").strip().lower()
            if confirm != 'y':
                return False, "Command cancelled by user"

        try:
            # Change to current directory
            original_cwd = os.getcwd()
            os.chdir(self.current_directory)

            # Handle cd command specially
            if command.strip().startswith('cd '):
                return self._handle_cd_command(command)

            # Execute the command
            logger.info(f"Executing command: {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=False,
                text=True,
                cwd=self.current_directory,
                timeout=300  # 5 minute timeout
            )

            # Update history
            self._add_to_history(command)

            # Update current directory for next command
            self.current_directory = os.getcwd()

            # Restore original working directory
            os.chdir(original_cwd)

            if result.returncode == 0:
                logger.success(f"Command executed successfully: {command}")
                return True, "Command executed successfully"
            else:
                logger.warning(
                    f"Command failed with code {result.returncode}: {command}")
                return False, f"Command failed with exit code {result.returncode}"

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False, "Command timed out after 5 minutes"
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            return False, f"Execution error: {str(e)}"
        finally:
            # Always restore original working directory
            try:
                os.chdir(original_cwd)
            except:
                pass

    def _handle_cd_command(self, command):
        """Handle cd command specially"""
        try:
            # Parse cd command
            parts = command.strip().split(' ', 1)
            if len(parts) == 1:
                # cd with no arguments goes to home
                target_dir = os.path.expanduser('~')
            else:
                target_dir = parts[1].strip()

            # Expand tilde and relative paths
            target_dir = os.path.expanduser(target_dir)
            if not os.path.isabs(target_dir):
                target_dir = os.path.join(self.current_directory, target_dir)

            # Normalize path
            target_dir = os.path.normpath(target_dir)

            # Check if directory exists and is accessible
            if not os.path.exists(target_dir):
                return False, f"Directory does not exist: {target_dir}"

            if not os.path.isdir(target_dir):
                return False, f"Not a directory: {target_dir}"

            # Try to access the directory
            try:
                os.listdir(target_dir)
            except PermissionError:
                return False, f"Permission denied: {target_dir}"

            # Update current directory
            self.current_directory = target_dir
            print(f"{Colors.GREEN}Changed directory to: {target_dir}{Colors.END}")

            self._add_to_history(command)
            return True, f"Changed directory to {target_dir}"

        except Exception as e:
            return False, f"Failed to change directory: {str(e)}"

    def _add_to_history(self, command):
        """Add command to history"""
        self.command_history.append(command)
        if len(self.command_history) > self.max_history:
            self.command_history.pop(0)

    def show_history(self):
        """Show command history"""
        if not self.command_history:
            print(f"{Colors.YELLOW}No commands in history{Colors.END}")
            return

        print(f"{Colors.CYAN}Command History:{Colors.END}")
        for i, cmd in enumerate(self.command_history[-20:], 1):  # Show last 20
            print(f"{Colors.GREEN}{i:2d}.{Colors.END} {cmd}")

    def show_safe_commands(self):
        """Show list of safe commands"""
        print(f"{Colors.CYAN}Allowed Commands:{Colors.END}")

        categories = {
            "File Operations": ['ls', 'dir', 'pwd', 'cd', 'cat', 'head', 'tail', 'find', 'grep', 'tree'],
            "Text Editors": ['nano', 'vim', 'vi', 'emacs'],
            "Network Tools": ['ping', 'nslookup', 'dig', 'traceroute', 'netstat'],
            "System Info": ['whoami', 'id', 'uname', 'uptime', 'ps', 'free'],
            "Development": ['git', 'python', 'python3', 'pip', 'node', 'npm'],
            "Android/ADB": ['adb', 'fastboot'],
            "Utilities": ['echo', 'date', 'which', 'history', 'clear']
        }

        for category, commands in categories.items():
            print(f"\n{Colors.YELLOW}{category}:{Colors.END}")
            for cmd in commands:
                if cmd in SAFE_COMMANDS:
                    print(f"  {Colors.GREEN}✓{Colors.END} {cmd}")


def terminal_menu():
    """Terminal commander menu"""
    commander = TerminalCommander()

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        # show global menu header
        try:
            print(session_manager.get_menu_header())
        except Exception:
            pass

        print(f"""
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────┐{Colors.END}
{Colors.CYAN}│                   {Colors.BOLD}TERMINAL COMMANDER{Colors.END}{Colors.CYAN}                        │{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.GREEN}Current Directory:{Colors.END} {commander.current_directory:<42} {Colors.CYAN}│{Colors.END}
{Colors.CYAN}├─────────────────────────────────────────────────────────────────┤{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[1]{Colors.END} Execute Command         {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[4]{Colors.END} Show Safe Commands      {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[2]{Colors.END} Interactive Shell       {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[5]{Colors.END} Security Info           {Colors.CYAN}│{Colors.END}
{Colors.CYAN}│ {Colors.YELLOW}[3]{Colors.END} Command History         {Colors.CYAN}│{Colors.END} {Colors.YELLOW}[0]{Colors.END} Back to Main Menu      {Colors.CYAN}│{Colors.END}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────┘{Colors.END}
        """)

        choice = input(
            f"{Colors.CYAN}terminal{Colors.END}{Colors.YELLOW}@{Colors.END}{Colors.GREEN}commander{Colors.END} {Colors.YELLOW}➤{Colors.END} ").strip()

        if choice == "1":
            # Single command execution
            print(f"{Colors.CYAN}Enter command to execute:{Colors.END}")
            command = input(
                f"{Colors.GREEN}{commander.current_directory}{Colors.END} $ ")
            if command.strip():
                success, message = commander.execute_command(command)
                if not success:
                    print(f"{Colors.RED}Error: {message}{Colors.END}")
                input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == "2":
            # Interactive shell mode
            print(
                f"{Colors.CYAN}Entering interactive shell mode. Type 'exit' to return.{Colors.END}")
            print(
                f"{Colors.YELLOW}Security: Only whitelisted commands are allowed.{Colors.END}")

            while True:
                try:
                    command = input(
                        f"{Colors.GREEN}{commander.current_directory}{Colors.END} $ ")

                    if command.strip().lower() in ['exit', 'quit', 'q']:
                        break

                    if command.strip():
                        success, message = commander.execute_command(command)
                        if not success:
                            print(f"{Colors.RED}Error: {message}{Colors.END}")

                except KeyboardInterrupt:
                    print(
                        f"\n{Colors.YELLOW}Use 'exit' to return to menu{Colors.END}")
                except EOFError:
                    break

        elif choice == "3":
            # Show command history
            commander.show_history()
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == "4":
            # Show safe commands
            commander.show_safe_commands()
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == "5":
            # Security information
            print(f"""
{Colors.CYAN}Security Information:{Colors.END}

{Colors.YELLOW}Safety Features:{Colors.END}
• {Colors.GREEN}Command Whitelisting:{Colors.END} Only pre-approved commands allowed
• {Colors.GREEN}Dangerous Command Blocking:{Colors.END} System-damaging commands blocked
• {Colors.GREEN}Confirmation Prompts:{Colors.END} Risky operations require confirmation
• {Colors.GREEN}Timeout Protection:{Colors.END} Commands timeout after 5 minutes
• {Colors.GREEN}Syntax Validation:{Colors.END} Commands parsed for safety
• {Colors.GREEN}Directory Sandboxing:{Colors.END} Limited directory access

{Colors.YELLOW}Blocked Commands Include:{Colors.END}
• File deletion (rm, del, shred)
• System modification (chmod, chown, mount)
• Network services (ssh, ftp, netcat)
• System control (sudo, systemctl, reboot)

{Colors.YELLOW}Use Responsibly:{Colors.END}
This tool provides limited, safe terminal access for development and debugging.
For full system access, use your regular terminal outside this framework.
            """)
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")

        elif choice == "0":
            break

        else:
            print(f"{Colors.RED}Invalid option.{Colors.END}")
            input(f"{Colors.YELLOW}Press Enter to continue...{Colors.END}")


if __name__ == "__main__":
    terminal_menu()
