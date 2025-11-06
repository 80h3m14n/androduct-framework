import logging
import os
from datetime import datetime
from pathlib import Path
from config import LOGS_DIR, LOG_LEVEL, LOG_FORMAT, Colors


class AndroductLogger:
    """Enhanced logging for Androduct Framework"""

    def __init__(self, name="androduct"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, LOG_LEVEL))

        # Create logs directory if it doesn't exist
        LOGS_DIR.mkdir(exist_ok=True)

        # File handler
        log_file = LOGS_DIR / \
            f"androduct_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(LOG_FORMAT)
        file_handler.setFormatter(file_formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, LOG_LEVEL))
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)

        # Add handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def info(self, message):
        """Log info message with green color"""
        colored_msg = f"{Colors.GREEN}[+] {message}{Colors.END}"
        self.logger.info(colored_msg)

    def warning(self, message):
        """Log warning message with yellow color"""
        colored_msg = f"{Colors.YELLOW}[!] {message}{Colors.END}"
        self.logger.warning(colored_msg)

    def error(self, message):
        """Log error message with red color"""
        colored_msg = f"{Colors.RED}[-] {message}{Colors.END}"
        self.logger.error(colored_msg)

    def success(self, message):
        """Log success message with bright green"""
        colored_msg = f"{Colors.GREEN}{Colors.BOLD}[✓] {message}{Colors.END}"
        self.logger.info(colored_msg)

    def debug(self, message):
        """Log debug message with blue color"""
        colored_msg = f"{Colors.BLUE}[DEBUG] {message}{Colors.END}"
        self.logger.debug(colored_msg)

    def banner(self, message):
        """Log banner message with purple color"""
        colored_msg = f"{Colors.PURPLE}{Colors.BOLD}{message}{Colors.END}"
        print(colored_msg)

    def log_command(self, command, device_id=None):
        """Log executed command"""
        if device_id:
            self.debug(f"Executing on {device_id}: {command}")
        else:
            self.debug(f"Executing: {command}")

    def log_session(self, action, device_id, details=""):
        """Log session-related activities"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session_log = LOGS_DIR / "sessions.log"
        with open(session_log, "a") as f:
            f.write(f"{timestamp} | {action} | {device_id} | {details}\n")


# Global logger instance
logger = AndroductLogger()
