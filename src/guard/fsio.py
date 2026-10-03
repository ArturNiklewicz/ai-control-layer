"""Safe file writes for host-side state (anonymizer vault, spend ledger, dashboard)."""

import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, text: str) -> None:
    """mkstemp = O_EXCL, never follows a planted name; replace = a crash never leaves half a file."""
    if path.parent.is_symlink() or path.is_symlink():
        raise OSError(f"{path}: refusing to write through a symlink")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
