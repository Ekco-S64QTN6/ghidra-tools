#!/usr/bin/env python3
import sys
import os
import json
import sqlite3

DEFAULT_OUTPUT_DIR = os.environ.get("GHIDRA_REPORT_OUTPUT_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output"))
DB_PATH = os.path.abspath(os.environ.get("GHIDRA_REPORT_DB_PATH", os.path.join(DEFAULT_OUTPUT_DIR, "reports.db")))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT,
            timestamp TEXT,
            format_label TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            md5 TEXT,
            sha256 TEXT,
            imphash TEXT,
            function_count INTEGER,
            json_path TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_apis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            library TEXT,
            function TEXT,
            mitre TEXT,
            category TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            type TEXT,
            value TEXT,
            address TEXT,
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            category TEXT,
            description TEXT,
            mitre TEXT,
            weight INTEGER,
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
        )
    """)
    _migrate_report_identity(conn)
    conn.commit()
    return conn


def _has_unique_file_index(conn):
    cur = conn.cursor()
    indexes = cur.execute("PRAGMA index_list(reports)").fetchall()
    for index in indexes:
        if not index[2]:
            continue
        columns = [
            row[2]
            for row in cur.execute(f"PRAGMA index_info('{index[1]}')").fetchall()
        ]
        if columns == ["file"]:
            return True
    return False


def _migrate_report_identity(conn):
    """Remove the legacy UNIQUE(file) constraint while preserving report IDs and findings."""
    if _has_unique_file_index(conn):
        conn.commit()
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""
                CREATE TABLE reports_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file TEXT,
                    timestamp TEXT,
                    format_label TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    md5 TEXT,
                    sha256 TEXT,
                    imphash TEXT,
                    function_count INTEGER,
                    json_path TEXT
                )
            """)
            conn.execute("""
                INSERT INTO reports_new
                    (id, file, timestamp, format_label, risk_score, risk_level,
                     md5, sha256, imphash, function_count, json_path)
                SELECT id, file, timestamp, format_label, risk_score, risk_level,
                       md5, sha256, imphash, function_count, json_path
                FROM reports
            """)
            conn.execute("DROP TABLE reports")
            conn.execute("ALTER TABLE reports_new RENAME TO reports")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")

    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_json_path_unique
        ON reports(json_path)
    """)


def _output_key_for_path(json_path, filename):
    """Use the report's containing output directory to distinguish equal basenames."""
    if json_path:
        return os.path.basename(os.path.dirname(os.path.abspath(json_path))) or filename
    return filename


def index_report(json_path):
    if not os.path.exists(json_path):
        print(f"Error: JSON report not found: {json_path}", file=sys.stderr)
        return

    json_path = os.path.realpath(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    conn = get_db()
    cur = conn.cursor()

    filename = data.get("file", os.path.basename(json_path))
    # Current JSON reports use "generated"; accept "timestamp" for older reports.
    timestamp = data.get("generated") or data.get("timestamp", "")
    format_label = data.get("format_label", "")
    hashes = data.get("hashes", {})
    threat = data.get("threat_summary", {})
    stats = data.get("analysis_stats", {})

    cur.execute("""
        INSERT INTO reports (file, timestamp, format_label, risk_score, risk_level, md5, sha256, imphash, function_count, json_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(json_path) DO UPDATE SET
            file=excluded.file,
            timestamp=excluded.timestamp,
            format_label=excluded.format_label,
            risk_score=excluded.risk_score,
            risk_level=excluded.risk_level,
            md5=excluded.md5,
            sha256=excluded.sha256,
            imphash=excluded.imphash,
            function_count=excluded.function_count
    """, (
        filename,
        timestamp,
        format_label,
        threat.get("risk_score", 0),
        threat.get("risk_level", "UNKNOWN"),
        hashes.get("md5", ""),
        hashes.get("sha256", ""),
        hashes.get("imphash", ""),
        stats.get("function_count", 0),
        json_path
    ))
    
    cur.execute("SELECT id FROM reports WHERE json_path = ?", (json_path,))
    report_id = cur.fetchone()[0]

    # Clean old child records
    cur.execute("DELETE FROM suspicious_apis WHERE report_id = ?", (report_id,))
    cur.execute("DELETE FROM iocs WHERE report_id = ?", (report_id,))
    cur.execute("DELETE FROM indicators WHERE report_id = ?", (report_id,))

    # Insert suspicious APIs
    for api in data.get("suspicious_apis", []):
        cur.execute("""
            INSERT INTO suspicious_apis (report_id, library, function, mitre, category)
            VALUES (?, ?, ?, ?, ?)
        """, (report_id, api.get("library", ""), api.get("function", ""), api.get("mitre", ""), api.get("category", "")))

    # Current JSON reports use "iocs"; accept "ioc_findings" for older reports.
    ioc_rows = data.get("iocs")
    if not isinstance(ioc_rows, list):
        ioc_rows = data.get("ioc_findings", [])
    if not isinstance(ioc_rows, list):
        ioc_rows = []

    # Insert IOCs
    for ioc in ioc_rows:
        if not isinstance(ioc, dict):
            continue
        cur.execute("""
            INSERT INTO iocs (report_id, type, value, address)
            VALUES (?, ?, ?, ?)
        """, (report_id, ioc.get("type", ""), ioc.get("value", ""), ioc.get("address", "")))

    # The current JSON contract names this field "mitre_id"; keep accepting "mitre".
    indicator_rows = threat.get("indicators", [])
    if not isinstance(indicator_rows, list):
        indicator_rows = []
    for ind in indicator_rows:
        if not isinstance(ind, dict):
            continue
        cur.execute("""
            INSERT INTO indicators (report_id, category, description, mitre, weight)
            VALUES (?, ?, ?, ?, ?)
        """, (
            report_id,
            ind.get("category", ""),
            ind.get("description", ""),
            ind.get("mitre_id") or ind.get("mitre", ""),
            ind.get("weight", 0),
        ))

    conn.commit()
    conn.close()

def search_db(query):
    conn = get_db()
    cur = conn.cursor()
    q = f"%{query}%"

    print("=" * 80)
    print(f"  GHIDRA-REPORT HISTORICAL DATABASE SEARCH: \"{query}\"")
    print("=" * 80)

    # Keep json_path in every result so same-named samples remain separate.
    cur.execute("""
        SELECT id, file, format_label, risk_score, risk_level, md5, sha256, imphash, json_path
        FROM reports
        WHERE file LIKE ? OR md5 LIKE ? OR sha256 LIKE ? OR imphash LIKE ?
    """, (q, q, q, q))
    report_hits = cur.fetchall()

    cur.execute("""
        SELECT r.id, r.file, r.risk_score, r.risk_level,
               a.library, a.function, a.mitre, a.category, r.json_path
        FROM suspicious_apis a
        JOIN reports r ON a.report_id = r.id
        WHERE a.library LIKE ? OR a.function LIKE ? OR a.category LIKE ? OR a.mitre LIKE ?
    """, (q, q, q, q))
    api_hits = cur.fetchall()

    cur.execute("""
        SELECT r.id, r.file, r.risk_score, r.risk_level, i.type, i.value, r.json_path
        FROM iocs i
        JOIN reports r ON i.report_id = r.id
        WHERE i.value LIKE ? OR i.type LIKE ?
    """, (q, q))
    ioc_hits = cur.fetchall()

    cur.execute("""
        SELECT r.id, r.file, r.risk_score, r.risk_level, ind.description, ind.mitre, r.json_path
        FROM indicators ind
        JOIN reports r ON ind.report_id = r.id
        WHERE ind.description LIKE ? OR ind.mitre LIKE ?
    """, (q, q))
    ind_hits = cur.fetchall()

    total_hits = len(report_hits) + len(api_hits) + len(ioc_hits) + len(ind_hits)
    if total_hits == 0:
        print("  No matching records found across historical analysis reports.\n")
        conn.close()
        return

    files = {}

    def add_match(filename, output_path, score, level, match):
        output_key = _output_key_for_path(output_path, filename)
        files.setdefault(output_key, {
            "file": filename,
            "output_key": output_key,
            "score": score,
            "level": level,
            "matches": [],
        })
        files[output_key]["matches"].append(match)

    for row in report_hits:
        add_match(row[1], row[8], row[3], row[4], f"Metadata match: {row[1]} ({row[2]})")

    for row in api_hits:
        add_match(
            row[1], row[8], row[2], row[3],
            f"Suspicious API: {row[4]}!{row[5]} [{row[6]}] ({row[7]})",
        )

    for row in ioc_hits:
        add_match(row[1], row[6], row[2], row[3], f"IOC [{row[4]}]: {row[5]}")

    for row in ind_hits:
        add_match(row[1], row[6], row[2], row[3], f"Threat Flag: {row[4]}")

    for output_key, info in files.items():
        print(f"\n  Target Binary: {info['file']}  [Output: {output_key}]  [Risk: {info['score']}/100 - {info['level']}]")
        print("  " + "-" * 70)
        seen = set()
        for match in info["matches"]:
            if match not in seen:
                seen.add(match)
                print(f"    ● {match}")

    print()
    print("=" * 80)
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: index_report.py <index|search> <path_or_term>")
        sys.exit(1)

    cmd = sys.argv[1]
    arg = sys.argv[2]

    if cmd == "index":
        index_report(arg)
    elif cmd == "search":
        search_db(arg)
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)
