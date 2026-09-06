#!/usr/bin/env python3
"""
TraceShield MVP Demo Reset Tool
Clears the SQLite cases database and cleans up generated email artifacts
so the system restarts fresh from TS-DEMO-001 for judges or live demos.
"""
import os
import sys

backend_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(backend_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from db import clear_cases, get_db_path, init_db


def reset_demo() -> None:
    db_path = get_db_path()
    print(f"[*] Resetting database at: {db_path}")
    init_db(db_path)
    clear_cases(db_path)

    # Clean generated artifacts in backend/data/artifacts and data/artifacts
    artifacts_dirs = [
        os.path.join(backend_dir, "data", "artifacts"),
        os.path.join(parent_dir, "data", "artifacts"),
    ]
    cleaned_count = 0
    for adir in set(artifacts_dirs):
        if os.path.isdir(adir):
            for fname in os.listdir(adir):
                if fname.startswith("TS-DEMO-") and fname.endswith(".eml"):
                    try:
                        os.remove(os.path.join(adir, fname))
                        cleaned_count += 1
                    except Exception as e:
                        print(f"    [!] Could not remove {fname}: {e}")

    print(f"[*] Removed {cleaned_count} generated demo artifact(s).")
    print("[✓] Demo reset complete! Your next upload will cleanly start at TS-DEMO-001.")


if __name__ == "__main__":
    reset_demo()
