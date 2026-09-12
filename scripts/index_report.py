#!/usr/bin/env python3
import sys
import os
import json
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "reports.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT UNIQUE,
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
    conn.commit()
    return conn

def index_report(json_path):
    if not os.path.exists(json_path):
        print(f"Error: JSON report not found: {json_path}", file=sys.stderr)
        return

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    conn = get_db()
    cur = conn.cursor()

    filename = data.get("file", os.path.basename(json_path))
    timestamp = data.get("timestamp", "")
    format_label = data.get("format_label", "")
    hashes = data.get("hashes", {})
    threat = data.get("threat_summary", {})
    stats = data.get("analysis_stats", {})

    cur.execute("""
        INSERT INTO reports (file, timestamp, format_label, risk_score, risk_level, md5, sha256, imphash, function_count, json_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file) DO UPDATE SET
            timestamp=excluded.timestamp,
            format_label=excluded.format_label,
            risk_score=excluded.risk_score,
            risk_level=excluded.risk_level,
            md5=excluded.md5,
            sha256=excluded.sha256,
            imphash=excluded.imphash,
            function_count=excluded.function_count,
            json_path=excluded.json_path
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
    
    cur.execute("SELECT id FROM reports WHERE file = ?", (filename,))
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

    # Insert IOCs
    for ioc in data.get("ioc_findings", []):
        cur.execute("""
            INSERT INTO iocs (report_id, type, value, address)
            VALUES (?, ?, ?, ?)
        """, (report_id, ioc.get("type", ""), ioc.get("value", ""), ioc.get("address", "")))

    # Insert Indicators
    for ind in threat.get("indicators", []):
        cur.execute("""
            INSERT INTO indicators (report_id, category, description, mitre, weight)
            VALUES (?, ?, ?, ?, ?)
        """, (report_id, ind.get("category", ""), ind.get("description", ""), ind.get("mitre", ""), ind.get("weight", 0)))

    conn.commit()
    conn.close()

def search_db(query):
    conn = get_db()
    cur = conn.cursor()
    q = f"%{query}%"

    print("=" * 80)
    print(f"  GHIDRA-REPORT HISTORICAL DATABASE SEARCH: \"{query}\"")
    print("=" * 80)

    # Search in reports
    cur.execute("""
        SELECT id, file, format_label, risk_score, risk_level, md5, sha256, imphash, json_path
        FROM reports
        WHERE file LIKE ? OR md5 LIKE ? OR sha256 LIKE ? OR imphash LIKE ?
    """, (q, q, q, q))
    report_hits = cur.fetchall()

    # Search in suspicious APIs
    cur.execute("""
        SELECT r.id, r.file, r.risk_score, r.risk_level, a.library, a.function, a.mitre, a.category
        FROM suspicious_apis a
        JOIN reports r ON a.report_id = r.id
        WHERE a.library LIKE ? OR a.function LIKE ? OR a.category LIKE ? OR a.mitre LIKE ?
    """, (q, q, q, q))
    api_hits = cur.fetchall()

    # Search in IOCs
    cur.execute("""
        SELECT r.id, r.file, r.risk_score, r.risk_level, i.type, i.value
        FROM iocs i
        JOIN reports r ON i.report_id = r.id
        WHERE i.value LIKE ? OR i.type LIKE ?
    """, (q, q))
    ioc_hits = cur.fetchall()

    # Search in Indicators
    cur.execute("""
        SELECT r.id, r.file, r.risk_score, r.risk_level, ind.description, ind.mitre
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

    # Group matches by file
    files = {}
    for r in report_hits:
        fid = r[1]
        files.setdefault(fid, {"score": r[3], "level": r[4], "matches": []})
        files[fid]["matches"].append(f"Metadata match: {r[1]} ({r[2]})")

    for a in api_hits:
        fid = a[1]
        files.setdefault(fid, {"score": a[2], "level": a[3], "matches": []})
        files[fid]["matches"].append(f"Suspicious API: {a[4]}!{a[5]} [{a[6]}] ({a[7]})")

    for i in ioc_hits:
        fid = i[1]
        files.setdefault(fid, {"score": i[2], "level": i[3], "matches": []})
        files[fid]["matches"].append(f"IOC [{i[4]}]: {i[5]}")

    for ind in ind_hits:
        fid = ind[1]
        files.setdefault(fid, {"score": ind[2], "level": ind[3], "matches": []})
        files[fid]["matches"].append(f"Threat Flag: {ind[4]}")

    for fname, info in files.items():
        print(f"\n  Target Binary: {fname}  [Risk: {info["score"]}/100 - {info["level"]}]")
        print("  " + "-" * 70)
        # Deduplicate and limit matches
        seen = set()
        for m in info["matches"]:
            if m not in seen:
                seen.add(m)
                print(f"    ● {m}")

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
