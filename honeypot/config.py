"""Load config.toml (falls back to the example) and secrets from .env."""
import os
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_env(path):
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def load():
    _load_env(ROOT / ".env")
    path = ROOT / "config.toml"
    if not path.exists():
        path = ROOT / "config.example.toml"
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"Could not read {path.name}: {e}")


def secret(name):
    return os.environ.get(name, "").strip()
