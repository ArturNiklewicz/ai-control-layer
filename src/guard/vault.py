"""sops+age sealed JSON files (pseudonym vault, consent grant). The only place guard runs sops.

Decrypting requires the age private key: possession of it is the authentication factor, and
sops' MAC makes a tampered file fail to load.
"""

import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.result import Err, Ok, Result, attempt

type Run = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True, slots=True)
class VaultError:
    detail: str


def sops(args: list[str], stdin: str, run: Run) -> Result[str, VaultError]:
    def call() -> subprocess.CompletedProcess:
        return run(
            ["sops", "--config", "/dev/null", *args], input=stdin, capture_output=True, text=True, timeout=20
        )

    def checked(p: subprocess.CompletedProcess) -> Result[str, VaultError]:
        # sops stderr names files and key ids, never plaintext values
        return (
            Ok(p.stdout)
            if p.returncode == 0
            else Err(VaultError(p.stderr.strip()[-300:]))
        )

    return attempt(
        call, (OSError, subprocess.SubprocessError), lambda e: VaultError(f"sops: {e}")
    ).bind(checked)


def load_sealed(path: Path, run: Run = subprocess.run) -> Result[dict, VaultError]:
    """Missing file = empty; anything else must decrypt and verify."""
    if not path.exists():
        return Ok({})
    return sops(["decrypt", "--output-type", "json", str(path)], "", run).bind(
        lambda out: attempt(
            lambda: dict(json.loads(out)),
            (ValueError, TypeError),
            lambda e: VaultError(f"{path}: {e}"),
        )
    )


def atomic_write(path: Path, text: str) -> None:
    """mkstemp = O_EXCL, never follows a planted name; replace = a crash never leaves half a file."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def save_sealed(
    path: Path, data: dict, recipient: str, run: Run = subprocess.run
) -> Result[Path, VaultError]:
    if not recipient.startswith("age1"):
        return Err(
            VaultError("vault.age_recipient must be an age public key (age1...)")
        )
    args = [
        "encrypt",
        "--age",
        recipient,
        "--input-type",
        "json",
        "--output-type",
        "json",
        "/dev/stdin",
    ]

    def write(sealed: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise OSError(f"{path}: refusing to write through a symlink")
        atomic_write(path, sealed)
        return path

    return sops(args, json.dumps(data), run).bind(
        lambda sealed: attempt(
            lambda: write(sealed), (OSError,), lambda e: VaultError(f"{path}: {e}")
        )
    )


# --- host-only pin: the container can write the vault file but not the pin, so it cannot swap the vault ---


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_pinned(path: Path, pin: Path, run: Run = subprocess.run) -> Result[dict, VaultError]:
    if path.is_symlink():
        return Err(VaultError(f"{path}: is a symlink"))
    if path.exists() and (not pin.exists() or pin.read_text().strip() != digest(path)):
        return Err(VaultError(f"{path}: not written by guard (host pin mismatch); remove it to start over"))
    return load_sealed(path, run)


def save_pinned(
    path: Path, data: dict, recipient: str, pin: Path, run: Run = subprocess.run
) -> Result[Path, VaultError]:
    def write_pin(p: Path) -> Path:
        pin.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(pin, digest(p))
        return p

    return save_sealed(path, data, recipient, run).bind(
        lambda p: attempt(lambda: write_pin(p), (OSError,), lambda e: VaultError(f"{pin}: {e}"))
    )
