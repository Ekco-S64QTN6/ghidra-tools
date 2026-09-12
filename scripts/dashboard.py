#!/usr/bin/env python3
"""
Lightweight, dependency-free interactive web dashboard for ghidra-report.
Serves a responsive single-page web UI backed by output/reports.db.
"""

import sys
import os
import json
import sqlite3
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
DB_PATH = os.path.join(OUTPUT_DIR, "reports.db")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ghidra-report Threat Intelligence Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --accent-glow: rgba(88, 166, 255, 0.15);
      --danger: #f85149;
      --warning: #d29922;
      --success: #3fb950;
      --info: #a371f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-badge {
      background: linear-gradient(135deg, #1f6feb, #238636);
      color: #fff;
      font-weight: 700;
      font-size: 14px;
      padding: 6px 12px;
      border-radius: 6px;
      letter-spacing: 0.5px;
    }
    h1 { font-size: 20px; font-weight: 600; color: #fff; }
    .search-box {
      display: flex;
      gap: 8px;
      width: 380px;
    }
    .search-box input {
      flex: 1;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      color: #fff;
      font-family: inherit;
      font-size: 13px;
      outline: none;
    }
    .search-box input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .stat-label { font-size: 12px; color: var(--text-muted); font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-val { font-size: 28px; font-weight: 700; color: #fff; margin-top: 4px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 24px;
      overflow: hidden;
    }
    .card-title {
      padding: 14px 18px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
      font-size: 14px;
      font-weight: 600;
      color: #fff;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th {
      text-align: left;
      padding: 10px 18px;
      background: rgba(0, 0, 0, 0.2);
      color: var(--text-muted);
      font-weight: 500;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 12px 18px;
      border-bottom: 1px solid rgba(48, 54, 61, 0.5);
    }
    tr:hover td { background: rgba(88, 166, 255, 0.03); }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-critical { background: rgba(248, 81, 73, 0.2); color: var(--danger); border: 1px solid var(--danger); }
    .badge-high { background: rgba(210, 153, 34, 0.2); color: var(--warning); border: 1px solid var(--warning); }
    .badge-medium { background: rgba(210, 153, 34, 0.15); color: #e3b341; }
    .badge-info { background: rgba(163, 113, 247, 0.2); color: var(--info); }
    .badge-low { background: rgba(63, 185, 80, 0.2); color: var(--success); }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .btn {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 500;
      text-decoration: none;
      background: #21262d;
      color: var(--text);
      border: 1px solid var(--border);
      transition: all 0.15s;
    }
    .btn:hover { background: #30363d; color: #fff; border-color: var(--text-muted); }
    .btn-primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
    .btn-primary:hover { background: #388bfd; }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    #search-results { display: none; margin-bottom: 24px; }
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <div class="logo-badge">GHIDRA-REPORT</div>
      <h1>Threat Triage & Analysis Dashboard</h1>
    </div>
    <div class="search-box">
      <input type="text" id="searchInput" placeholder="Search APIs, IOCs, strings, hashes..." oninput="handleSearch()">
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Binaries</div>
      <div class="stat-val" id="statTotal">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical / High Risk</div>
      <div class="stat-val" style="color:var(--danger)" id="statCritical">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Medium Risk</div>
      <div class="stat-val" style="color:var(--warning)" id="statMedium">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Informational / Clean</div>
      <div class="stat-val" style="color:var(--info)" id="statInfo">-</div>
    </div>
  </div>

  <div class="card" id="search-results">
    <div class="card-title">Search Results: <span id="search-query" style="color:var(--accent)"></span></div>
    <div id="search-list" style="padding: 16px;"></div>
  </div>

  <div class="card">
    <div class="card-title">Analyzed Binaries</div>
    <table>
      <thead>
        <tr>
          <th>Binary</th>
          <th>Format</th>
          <th>Threat Score</th>
          <th>Hashes</th>
          <th>PE Imphash</th>
          <th>Reports & Exports</th>
        </tr>
      </thead>
      <tbody id="binariesTable">
        <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Loading triage reports...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    async function loadReports() {
      try {
        const res = await fetch('/api/reports');
        const data = await res.json();
        renderTable(data);
        updateStats(data);
      } catch (e) {
        console.error('Failed to load reports:', e);
      }
    }

    function getBadgeClass(level) {
      switch ((level || '').toUpperCase()) {
        case 'CRITICAL': return 'badge-critical';
        case 'HIGH': return 'badge-high';
        case 'MEDIUM': return 'badge-medium';
        case 'INFORMATIONAL': return 'badge-info';
        default: return 'badge-low';
      }
    }

    function renderTable(reports) {
      const tbody = document.getElementById('binariesTable');
      if (!reports.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No binary triage reports found in database.</td></tr>';
        return;
      }

      tbody.innerHTML = reports.map(r => `
        <tr>
          <td>
            <strong>${r.file}</strong>
            <div style="font-size:11px; color:var(--text-muted);">${r.timestamp || ''}</div>
          </td>
          <td><span class="badge" style="background:#21262d; border:1px solid var(--border);">${r.format_label}</span></td>
          <td>
            <span class="badge ${getBadgeClass(r.risk_level)}">${r.risk_score} / 100 [${r.risk_level}]</span>
          </td>
          <td>
            <div class="mono" title="SHA256: ${r.sha256}">MD5: ${(r.md5 || '').substring(0, 10)}...</div>
          </td>
          <td>
            <span class="mono" style="color:${r.imphash ? 'var(--accent)' : 'var(--text-muted)'}">${r.imphash ? r.imphash.substring(0, 10) + '...' : '-'}</span>
          </td>
          <td>
            <div class="actions">
              <a class="btn btn-primary" href="/output/${r.file}/report_latest.html" target="_blank">HTML</a>
              <a class="btn" href="/output/${r.file}/report_latest.txt" target="_blank">TXT</a>
              <a class="btn" href="/output/${r.file}/report_latest.json" target="_blank">JSON</a>
              <a class="btn" href="/output/${r.file}/report_latest.md" target="_blank">MD</a>
              <a class="btn" href="/output/${r.file}/report_latest.sarif" target="_blank">SARIF</a>
              <a class="btn" href="/output/${r.file}/report_latest.yar" target="_blank">YARA</a>
              <a class="btn" href="/output/${r.file}/report_latest.misp.json" target="_blank">MISP</a>
            </div>
          </td>
        </tr>
      `).join('');
    }

    function updateStats(reports) {
      document.getElementById('statTotal').innerText = reports.length;
      let crit = 0, med = 0, info = 0;
      reports.forEach(r => {
        const lvl = (r.risk_level || '').toUpperCase();
        if (lvl === 'CRITICAL' || lvl === 'HIGH') crit++;
        else if (lvl === 'MEDIUM') med++;
        else info++;
      });
      document.getElementById('statCritical').innerText = crit;
      document.getElementById('statMedium').innerText = med;
      document.getElementById('statInfo').innerText = info;
    }

    let searchTimeout = null;
    function handleSearch() {
      clearTimeout(searchTimeout);
      const q = document.getElementById('searchInput').value.trim();
      if (!q) {
        document.getElementById('search-results').style.display = 'none';
        return;
      }
      searchTimeout = setTimeout(async () => {
        try {
          const res = await fetch('/api/search?q=' + encodeURIComponent(q));
          const data = await res.json();
          renderSearchResults(q, data);
        } catch (e) {
          console.error(e);
        }
      }, 200);
    }

    function renderSearchResults(q, results) {
      const panel = document.getElementById('search-results');
      const list = document.getElementById('search-list');
      document.getElementById('search-query').innerText = q;
      panel.style.display = 'block';

      if (!Object.keys(results).length) {
        list.innerHTML = '<div style="color:var(--text-muted); font-size:13px;">No matching records found.</div>';
        return;
      }

      list.innerHTML = Object.entries(results).map(([file, info]) => `
        <div style="margin-bottom: 12px; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 6px;">
          <div style="font-weight:600; font-size:13px; margin-bottom:4px;">
            ${file} <span class="badge ${getBadgeClass(info.level)}" style="margin-left:6px;">${info.score}/100 [${info.level}]</span>
          </div>
          <ul style="padding-left: 20px; font-size: 12px; color: var(--text);">
            ${info.matches.map(m => `<li>${m}</li>`).join('')}
          </ul>
        </div>
      `).join('');
    }

    loadReports();
  </script>
</body>
</html>
"""

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
            return

        if path == "/api/reports":
            self.handle_api_reports()
            return

        if path == "/api/search":
            qs = parse_qs(parsed.query)
            q = qs.get("q", [""])[0]
            self.handle_api_search(q)
            return

        # Static file delivery for output directory
        if path.startswith("/output/"):
            rel_path = path[len("/output/"):]
            file_path = os.path.join(OUTPUT_DIR, rel_path)
            if os.path.isfile(file_path):
                self.serve_file(file_path)
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def handle_api_reports(self):
        if not os.path.exists(DB_PATH):
            self.send_json([])
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("""
                SELECT file, timestamp, format_label, risk_score, risk_level, md5, sha256, imphash, function_count
                FROM reports ORDER BY id DESC
            """)
            rows = cur.fetchall()
            reports = []
            for r in rows:
                reports.append({
                    "file": r[0],
                    "timestamp": r[1],
                    "format_label": r[2],
                    "risk_score": r[3],
                    "risk_level": r[4],
                    "md5": r[5],
                    "sha256": r[6],
                    "imphash": r[7],
                    "function_count": r[8]
                })
            conn.close()
            self.send_json(reports)
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def handle_api_search(self, q):
        if not q or not os.path.exists(DB_PATH):
            self.send_json({})
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            query = f"%{q}%"

            # Search in reports
            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, 'Metadata', r.format_label
                FROM reports r
                WHERE r.file LIKE ? OR r.md5 LIKE ? OR r.sha256 LIKE ? OR r.imphash LIKE ?
            """, (query, query, query, query))
            m_hits = cur.fetchall()

            # Search in APIs
            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, a.library, a.function
                FROM suspicious_apis a JOIN reports r ON a.report_id = r.id
                WHERE a.library LIKE ? OR a.function LIKE ? OR a.category LIKE ? OR a.mitre LIKE ?
            """, (query, query, query, query))
            api_hits = cur.fetchall()

            # Search in IOCs
            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, i.type, i.value
                FROM iocs i JOIN reports r ON i.report_id = r.id
                WHERE i.value LIKE ? OR i.type LIKE ?
            """, (query, query))
            ioc_hits = cur.fetchall()

            # Search in indicators
            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, ind.category, ind.description
                FROM indicators ind JOIN reports r ON ind.report_id = r.id
                WHERE ind.description LIKE ? OR ind.mitre LIKE ?
            """, (query, query))
            ind_hits = cur.fetchall()

            files = {}
            for r in m_hits:
                files.setdefault(r[0], {"score": r[1], "level": r[2], "matches": []})
                files[r[0]]["matches"].append(f"Metadata match: {r[0]} ({r[4]})")

            for a in api_hits:
                files.setdefault(a[0], {"score": a[1], "level": a[2], "matches": []})
                files[a[0]]["matches"].append(f"Suspicious API: {a[3]}!{a[4]}")

            for i in ioc_hits:
                files.setdefault(i[0], {"score": i[1], "level": i[2], "matches": []})
                files[i[0]]["matches"].append(f"IOC [{i[3]}]: {i[4]}")

            for ind in ind_hits:
                files.setdefault(ind[0], {"score": ind[1], "level": ind[2], "matches": []})
                files[ind[0]]["matches"].append(f"Threat Flag: {ind[4]}")

            conn.close()
            self.send_json(files)
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def serve_file(self, file_path):
        ctype, _ = mimetypes.guess_type(file_path)
        if not ctype:
            if file_path.endswith(".sarif") or file_path.endswith(".misp.json") or file_path.endswith(".json"):
                ctype = "application/json"
            elif file_path.endswith(".yar"):
                ctype = "text/plain"
            elif file_path.endswith(".md"):
                ctype = "text/markdown"
            else:
                ctype = "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype + "; charset=utf-8" if "text" in ctype or "json" in ctype else ctype)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode("utf-8"))

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence verbose request logs
        return

def run_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, DashboardHandler)
    print(f"[*] ghidra-report Dashboard running at http://localhost:{port}/")
    print(f"[*] Connected to SQLite database: {DB_PATH}")
    print("[*] Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")
        httpd.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8080
    run_server(port)
