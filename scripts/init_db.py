#!/usr/bin/env python3
"""Database initialization and migration runner."""
import sys
import os
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def main():
    print("Running database migrations...")
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"Migration failed: {result.stderr}")
        sys.exit(1)
    print("Database migrations completed successfully.")


if __name__ == "__main__":
    main()
