#!/usr/bin/env python3
"""Print SHA-256 hashes for trusted ML artifacts."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models.artifact_security import sha256_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash trusted Cyber Detecter model artifacts")
    parser.add_argument("models", nargs="+", help="Model artifact paths")
    args = parser.parse_args()
    for item in args.models:
        path = Path(item)
        if not path.is_file():
            parser.error(f"model not found: {path}")
        print(f"{path}: {sha256_file(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
