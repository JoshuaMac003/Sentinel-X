"""Generate and apply an initial Alembic revision if missing."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def main() -> None:
    versions = BACKEND / "alembic" / "versions"
    versions.mkdir(parents=True, exist_ok=True)
    existing = list(versions.glob("*.py"))
    py = BACKEND / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        py = Path(sys.executable)

    env = {
        **dict(**{k: v for k, v in __import__("os").environ.items()}),
    }
    # Ensure backend root on path for alembic env.py imports
    cmd_base = [str(py), "-m", "alembic"]

    if not existing:
        print("Creating initial Alembic revision...")
        subprocess.check_call(
            cmd_base + ["revision", "--autogenerate", "-m", "initial_schema"],
            cwd=str(BACKEND),
            env=env,
        )
    else:
        print(f"Alembic revisions already present: {[p.name for p in existing]}")

    print("Upgrading database to head...")
    subprocess.check_call(cmd_base + ["upgrade", "head"], cwd=str(BACKEND), env=env)
    print("Alembic OK")


if __name__ == "__main__":
    main()
