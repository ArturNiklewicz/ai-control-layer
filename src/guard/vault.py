"""sops+age sealed JSON files (pseudonym vault, consent grant). The only place guard runs sops.

Decrypting requires the age private key: possession of it is the authentication factor, and
sops' MAC makes a tampered file fail to load.
"""

import json
import os
import subprocess
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
        tmp = path.with_suffix(".tmp")
        tmp.write_text(sealed)
        os.replace(tmp, path)  # atomic: a crash never leaves a half-written vault
        return path

    return sops(args, json.dumps(data), run).bind(
        lambda sealed: attempt(
            lambda: write(sealed), (OSError,), lambda e: VaultError(f"{path}: {e}")
        )
    )
