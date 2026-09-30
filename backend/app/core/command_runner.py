import subprocess
import shutil
from typing import Tuple, Optional
from app.config import settings
from app.core.logger import audit_logger

# Strict list of allowed binary names for defense-only auditing
ALLOWED_COMMANDS = {
    "systemctl",
    "ss",
    "netstat",
    "ufw",
    "firewall-cmd",
    "iptables",
    "nft",
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "uname",
    "uptime",
    "hostname",
    "df",
    "free",
    "lscpu",
    "whoami",
    "id",
    "groups",
    "last",
    "ps",
    "sysctl",
    "lsb_release",
    "cat",
    "find",
}

class CommandRunner:
    @staticmethod
    def is_available(cmd: str) -> bool:
        """Check if a binary exists in PATH."""
        return shutil.which(cmd) is not None

    @staticmethod
    def run(
        args: list[str],
        timeout: Optional[int] = None,
        check_allowed: bool = True
    ) -> Tuple[int, str, str]:
        """
        Safely execute a command without shell=True.
        Returns: (returncode, stdout, stderr)
        """
        if not args:
            return -1, "", "Empty command arguments."

        binary = args[0]

        if check_allowed and binary not in ALLOWED_COMMANDS:
            audit_logger.warning(f"Command not in allowlist rejected: {binary}")
            return -1, "", f"Command '{binary}' is not allowed by audit policy."

        actual_timeout = timeout or settings.COMMAND_TIMEOUT

        try:
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=actual_timeout,
                check=False
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except FileNotFoundError:
            return 127, "", f"Command not found: {binary}"
        except subprocess.TimeoutExpired:
            audit_logger.warning(f"Command timed out ({actual_timeout}s): {' '.join(args)}")
            return 124, "", f"Command timed out after {actual_timeout} seconds."
        except PermissionError:
            return 126, "", f"Permission denied executing: {binary}"
        except Exception as e:
            audit_logger.error(f"Unexpected error executing {binary}: {e}")
            return -1, "", str(e)
