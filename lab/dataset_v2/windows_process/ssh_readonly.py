"""Generic SSH argument builder; caller supplies its own lab and identity."""
from pathlib import Path

def ssh_base(host: str, user: str, key: Path) -> list[str]:
    return [
        "ssh", "-T", "-i", str(key), "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0", "-o", "ConnectionAttempts=1",
        "-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes",
        "-o", "StrictHostKeyChecking=yes", f"{user}@{host}",
    ]
