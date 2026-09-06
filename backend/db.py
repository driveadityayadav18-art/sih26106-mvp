import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Path to SQLite database in backend/data/traceshield.db
BACKEND_DIR = Path(__file__).resolve().parent
DATA_DIR = BACKEND_DIR / "data"
DEFAULT_DB_PATH = str(DATA_DIR / "traceshield.db")


def get_db_path() -> str:
    """Returns dynamic DB path, supporting TRACESHIELD_DB_PATH for test isolation."""
    return os.environ.get("TRACESHIELD_DB_PATH") or DEFAULT_DB_PATH


def init_db(db_path: Optional[str] = None) -> None:
    """Creates the cases table if missing."""
    target_path = db_path or get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    conn = sqlite3.connect(target_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    sha256 TEXT,
                    created_at TEXT,
                    risk_score INTEGER,
                    risk_band TEXT,
                    analysis_json TEXT
                )
                """
            )
    finally:
        conn.close()


def save_case(case_dict: Dict[str, Any], db_path: Optional[str] = None) -> None:
    """
    Inserts or replaces a row, storing the full case dict as JSON in analysis_json.
    Extracts key fields for indexed/queried columns.
    """
    target_path = db_path or get_db_path()
    init_db(target_path)

    case_id = str(case_dict.get("case_id") or case_dict.get("id") or "")
    if not case_id:
        raise ValueError("case_dict must contain 'case_id' or 'id'")

    artifact = case_dict.get("artifact") if isinstance(case_dict.get("artifact"), dict) else {}
    risk = case_dict.get("risk") if isinstance(case_dict.get("risk"), dict) else {}

    sha256 = str(case_dict.get("sha256") or artifact.get("sha256") or "")
    created_at = str(
        case_dict.get("created_at")
        or artifact.get("received_at")
        or datetime.now(timezone.utc).isoformat()
    )

    # Risk score and band extraction
    risk_score_raw = case_dict.get("risk_score")
    if risk_score_raw is None:
        risk_score_raw = risk.get("score", 0)
    try:
        risk_score = int(risk_score_raw)
    except (TypeError, ValueError):
        risk_score = 0

    risk_band = str(case_dict.get("risk_band") or risk.get("band") or "UNKNOWN")

    # Persist created_at into case_dict if missing
    if "created_at" not in case_dict:
        case_dict["created_at"] = created_at

    analysis_json = json.dumps(case_dict)

    conn = sqlite3.connect(target_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO cases (case_id, sha256, created_at, risk_score, risk_band, analysis_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case_id, sha256, created_at, risk_score, risk_band, analysis_json),
            )
    finally:
        conn.close()


def get_case(case_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Returns the parsed dict or None."""
    target_path = db_path or get_db_path()
    init_db(target_path)
    conn = sqlite3.connect(target_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT analysis_json FROM cases WHERE case_id = ?",
            (case_id,),
        )
        row = cursor.fetchone()
        if row and row[0]:
            try:
                return json.loads(row[0])
            except json.JSONDecodeError:
                return None
        return None
    finally:
        conn.close()


def list_cases(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns id, created_at, risk_score, risk_band for all cases (not the full JSON)."""
    target_path = db_path or get_db_path()
    init_db(target_path)
    conn = sqlite3.connect(target_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT case_id, created_at, risk_score, risk_band
            FROM cases
            ORDER BY created_at DESC
            """
        )
        rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "case_id": row[0],
                "created_at": row[1],
                "risk_score": row[2],
                "risk_band": row[3],
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_all_cases(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all full case dictionaries parsed from analysis_json in SQLite."""
    target_path = db_path or get_db_path()
    init_db(target_path)
    conn = sqlite3.connect(target_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT analysis_json FROM cases ORDER BY rowid ASC")
        rows = cursor.fetchall()
        cases: List[Dict[str, Any]] = []
        for row in rows:
            if row and row[0]:
                try:
                    cases.append(json.loads(row[0]))
                except json.JSONDecodeError:
                    continue
        return cases
    finally:
        conn.close()


def count_cases(db_path: Optional[str] = None) -> int:
    """Returns the total number of cases stored in SQLite."""
    target_path = db_path or get_db_path()
    init_db(target_path)
    conn = sqlite3.connect(target_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cases")
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    finally:
        conn.close()


def get_max_case_number(db_path: Optional[str] = None) -> int:
    """
    Returns the highest integer suffix found in TS-DEMO-XXX case IDs in SQLite.
    Returns 0 if no matching cases exist.
    """
    target_path = db_path or get_db_path()
    init_db(target_path)
    conn = sqlite3.connect(target_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT case_id FROM cases")
        rows = cursor.fetchall()
        max_num = 0
        for row in rows:
            if row and row[0]:
                match = re.search(r"TS-DEMO-(\d+)", str(row[0]), re.IGNORECASE)
                if match:
                    val = int(match.group(1))
                    if val > max_num:
                        max_num = val
        return max_num
    finally:
        conn.close()


def clear_cases(db_path: Optional[str] = None) -> None:
    """Clears all records from the cases table in SQLite."""
    target_path = db_path or get_db_path()
    init_db(target_path)
    conn = sqlite3.connect(target_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cases")
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"TraceShield SQLite database initialized successfully at: {get_db_path()}")

