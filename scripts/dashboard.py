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
import base64
import hmac
import ipaddress
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

from index_report import get_db as get_history_db, fts_phrase_query

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.abspath(os.environ.get("GHIDRA_REPORT_OUTPUT_DIR", os.path.join(BASE_DIR, "output")))
DB_PATH = os.path.abspath(os.environ.get("GHIDRA_REPORT_DB_PATH", os.path.join(OUTPUT_DIR, "reports.db")))
MAX_SEARCH_LENGTH = 256
MAX_REPORTS_RESPONSE = 500
MAX_SEARCH_ROWS = 100
MAX_SERVED_FILE_BYTES = 50 * 1024 * 1024


def output_key_for_report(json_path, fallback):
    """Return a direct child output-directory name for a stored report path."""
    if not json_path:
        return fallback
    try:
        output_root = os.path.realpath(OUTPUT_DIR)
        report_path = os.path.realpath(os.path.abspath(json_path))
        output_dir = os.path.dirname(report_path)
        if os.path.dirname(output_dir) != output_root:
            return fallback
        if os.path.commonpath((output_root, output_dir)) != output_root:
            return fallback
        key = os.path.basename(output_dir)
        return key or fallback
    except (OSError, ValueError):
        return fallback


def is_loopback_bind_host(host):
    """Return True only for an explicit loopback IP or localhost hostname."""
    if not isinstance(host, str):
        return False
    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    normalized = normalized.split("%", 1)[0]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        # Treat DNS names and unknown host forms as remote. Requiring auth is
        # safer than resolving a name whose answer can vary between checks.
        return False


def resolve_output_path(relative_path):
    """Resolve a requested report path and reject traversal or symlink escapes."""
    try:
        decoded_path = relative_path
        # Decode repeatedly so double-encoded traversal is not treated as a
        # harmless literal by one layer and as a path separator by another.
        for _ in range(8):
            next_path = unquote(decoded_path)
            if next_path == decoded_path:
                break
            decoded_path = next_path
        if chr(0) in decoded_path:
            return None

        output_root = os.path.realpath(OUTPUT_DIR)
        candidate = os.path.realpath(os.path.join(output_root, decoded_path))
        if os.path.commonpath((output_root, candidate)) != output_root:
            return None
        return candidate
    except (OSError, ValueError):
        return None


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

    function escapeHtml(value) {
      const entities = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
      return String(value ?? '').replace(/[&<>"']/g, character => entities[character]);
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
            <strong>${escapeHtml(r.file)}</strong>
            <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(r.timestamp || '')}</div>
          </td>
          <td><span class="badge" style="background:#21262d; border:1px solid var(--border);">${escapeHtml(r.format_label)}</span></td>
          <td>
            <span class="badge ${getBadgeClass(r.risk_level)}">${escapeHtml(r.risk_score)} / 100 [${escapeHtml(r.risk_level)}]</span>
          </td>
          <td>
            <div class="mono" title="SHA256: ${escapeHtml(r.sha256)}">MD5: ${escapeHtml((r.md5 || '').substring(0, 10))}...</div>
          </td>
          <td>
            <span class="mono" style="color:${r.imphash ? 'var(--accent)' : 'var(--text-muted)'}">${escapeHtml(r.imphash ? r.imphash.substring(0, 10) + '...' : '-')}</span>
          </td>
          <td>
            <div class="actions">
              <a class="btn btn-primary" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.html" target="_blank" rel="noopener noreferrer">HTML</a>
              <a class="btn" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.txt" target="_blank" rel="noopener noreferrer">TXT</a>
              <a class="btn" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.json" target="_blank" rel="noopener noreferrer">JSON</a>
              <a class="btn" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.md" target="_blank" rel="noopener noreferrer">MD</a>
              <a class="btn" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.sarif" target="_blank" rel="noopener noreferrer">SARIF</a>
              <a class="btn" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.yar" target="_blank" rel="noopener noreferrer">YARA</a>
              <a class="btn" href="/output/${encodeURIComponent(r.output_key || r.file)}/report_latest.misp.json" target="_blank" rel="noopener noreferrer">MISP</a>
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
            ${escapeHtml(info.file || file)} <span class="badge ${getBadgeClass(info.level)}" style="margin-left:6px;">${escapeHtml(info.score)}/100 [${escapeHtml(info.level)}]</span>
          </div>
          <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px;">Output: ${escapeHtml(info.output_key || file)}</div>
          <ul style="padding-left: 20px; font-size: 12px; color: var(--text);">
            ${info.matches.map(m => `<li>${escapeHtml(m)}</li>`).join('')}
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
    REMOTE_AUTH_REQUIRED = False
    REMOTE_AUTH_TOKEN = ""
    AUTH_USERNAME = "ghidra-report"

    def _has_valid_remote_credentials(self):
        """Validate HTTP Basic credentials without disclosing which part failed."""
        authorization = self.headers.get("Authorization", "")
        scheme, separator, encoded = authorization.partition(" ")
        if not separator or scheme.lower() != "basic" or not encoded:
            return False
        try:
            credentials = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False

        username, separator, supplied_token = credentials.partition(":")
        if not separator:
            return False
        username_valid = hmac.compare_digest(username.encode("utf-8"), self.AUTH_USERNAME.encode("utf-8"))
        token_valid = hmac.compare_digest(
            supplied_token.encode("utf-8"), self.REMOTE_AUTH_TOKEN.encode("utf-8")
        )
        return username_valid and token_valid

    def _send_authentication_required(self):
        self.send_response(401)
        self.send_header(
            "WWW-Authenticate",
            'Basic realm="ghidra-report", charset="UTF-8"',
        )
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        body = b"Authentication required.\\n"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        """Apply defensive browser headers to the UI, APIs, and report artifacts."""
        request_path = urlparse(self.path).path
        for _ in range(8):
            decoded_path = unquote(request_path)
            if decoded_path == request_path:
                break
            request_path = decoded_path
        if request_path in ("/", "/index.html"):
            policy = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; connect-src 'self'; "
                "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            )
        elif request_path.startswith("/output/") and request_path.lower().endswith(".html"):
            # Exported reports may contain data derived from untrusted samples.
            # Keep them in an opaque sandbox and prohibit script execution.
            policy = (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                "object-src 'none'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'; sandbox"
            )
        else:
            policy = "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", policy)
        super().end_headers()

    def do_GET(self):
        # Every dashboard and artifact route is protected for remote binds.
        if self.REMOTE_AUTH_REQUIRED and not self._has_valid_remote_credentials():
            self._send_authentication_required()
            return

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

        # Static file delivery is restricted to canonical paths under output/.
        if path.startswith("/output/"):
            rel_path = path[len("/output/"):]
            file_path = resolve_output_path(rel_path)
            if file_path and os.path.isfile(file_path):
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
                SELECT file, timestamp, format_label, risk_score, risk_level, md5, sha256, imphash, function_count, json_path
                FROM reports ORDER BY id DESC LIMIT ?
            """, (MAX_REPORTS_RESPONSE,))
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
                    "function_count": r[8],
                    "output_key": output_key_for_report(r[9], r[0]),
                })
            conn.close()
            self.send_json(reports)
        except Exception:
            self.send_json({"error": "Failed to read the report index."}, status=500)

    def handle_api_search(self, q):
        if len(q) > MAX_SEARCH_LENGTH:
            self.send_json({"error": f"Search query exceeds the {MAX_SEARCH_LENGTH}-character limit."}, status=400)
            return
        if not q or not os.path.exists(DB_PATH):
            self.send_json({})
            return

        try:
            # Open through the indexer so legacy databases receive the same
            # schema/FTS migrations before dashboard search runs.
            conn = get_history_db(DB_PATH)
            cur = conn.cursor()
            query = f"%{q}%"

            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, 'Metadata', r.format_label, r.json_path
                FROM reports r
                WHERE r.file LIKE ? OR r.md5 LIKE ? OR r.sha256 LIKE ? OR r.imphash LIKE ?
                LIMIT ?
            """, (query, query, query, query, MAX_SEARCH_ROWS))
            m_hits = cur.fetchall()

            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, a.library, a.function, r.json_path
                FROM suspicious_apis a JOIN reports r ON a.report_id = r.id
                WHERE a.library LIKE ? OR a.function LIKE ? OR a.category LIKE ? OR a.mitre LIKE ?
                LIMIT ?
            """, (query, query, query, query, MAX_SEARCH_ROWS))
            api_hits = cur.fetchall()

            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, i.type, i.value, r.json_path
                FROM iocs i JOIN reports r ON i.report_id = r.id
                WHERE i.value LIKE ? OR i.type LIKE ?
                LIMIT ?
            """, (query, query, MAX_SEARCH_ROWS))
            ioc_hits = cur.fetchall()

            cur.execute("""
                SELECT r.file, r.risk_score, r.risk_level, ind.category, ind.description, r.json_path
                FROM indicators ind JOIN reports r ON ind.report_id = r.id
                WHERE ind.description LIKE ? OR ind.mitre LIKE ?
                LIMIT ?
            """, (query, query, MAX_SEARCH_ROWS))
            ind_hits = cur.fetchall()

            text_hits = []
            fts_query = fts_phrase_query(q)
            if fts_query:
                cur.execute("""
                    SELECT r.file, r.risk_score, r.risk_level, r.json_path,
                           snippet(reports_fts, 0, '[', ']', ' … ', 12)
                    FROM reports_fts
                    JOIN reports r ON r.id = reports_fts.rowid
                    WHERE reports_fts MATCH ?
                    ORDER BY bm25(reports_fts), r.timestamp DESC, r.id DESC
                    LIMIT ?
                """, (fts_query, MAX_SEARCH_ROWS))
                text_hits = cur.fetchall()

            files = {}

            def add_match(filename, json_path, score, level, match):
                output_key = output_key_for_report(json_path, filename)
                files.setdefault(output_key, {
                    "file": filename,
                    "output_key": output_key,
                    "score": score,
                    "level": level,
                    "matches": [],
                })
                files[output_key]["matches"].append(match)

            for row in m_hits:
                add_match(row[0], row[5], row[1], row[2], f"Metadata match: {row[0]} ({row[4]})")

            for row in api_hits:
                add_match(row[0], row[5], row[1], row[2], f"Suspicious API: {row[3]}!{row[4]}")

            for row in ioc_hits:
                add_match(row[0], row[5], row[1], row[2], f"IOC [{row[3]}]: {row[4]}")

            for row in ind_hits:
                add_match(row[0], row[5], row[1], row[2], f"Threat Flag: {row[4]}")

            for row in text_hits:
                add_match(row[0], row[3], row[1], row[2], f"Indexed text: {row[4]}")

            conn.close()
            self.send_json(files)
        except Exception:
            self.send_json({"error": "Failed to search the report index."}, status=500)

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
                if os.fstat(f.fileno()).st_size > MAX_SERVED_FILE_BYTES:
                    self.send_response(413)
                    self.end_headers()
                    self.wfile.write(b"Report exceeds the dashboard response size limit.")
                    return
                content = f.read(MAX_SERVED_FILE_BYTES + 1)
            if len(content) > MAX_SERVED_FILE_BYTES:
                self.send_response(413)
                self.end_headers()
                self.wfile.write(b"Report exceeds the dashboard response size limit.")
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype + "; charset=utf-8" if "text" in ctype or "json" in ctype else ctype)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except OSError:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Report not found.")

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

def create_server(port=8080, host=None, auth_token=None):
    """Create the dashboard server; non-loopback binds require a strong token."""
    bind_host = host or os.environ.get("GHIDRA_DASHBOARD_HOST", "127.0.0.1")
    handler_class = DashboardHandler
    if not is_loopback_bind_host(bind_host):
        token = (
            os.environ.get("GHIDRA_DASHBOARD_TOKEN", "")
            if auth_token is None else auth_token
        )
        if not isinstance(token, str) or len(token.encode("utf-8")) < 32:
            raise ValueError(
                "Remote dashboard binds require GHIDRA_DASHBOARD_TOKEN "
                "with at least 32 UTF-8 bytes. Protect the connection with TLS."
            )
        handler_class = type(
            "AuthenticatedDashboardHandler",
            (DashboardHandler,),
            {
                "REMOTE_AUTH_REQUIRED": True,
                "REMOTE_AUTH_TOKEN": token,
            },
        )
    return HTTPServer((bind_host, port), handler_class)


def run_server(port=8080, host=None):
    httpd = create_server(port, host)
    bind_host, bind_port = httpd.server_address[:2]
    print(f"[*] ghidra-report Dashboard listening on {bind_host}:{bind_port}")
    if is_loopback_bind_host(bind_host):
        print(f"[*] Local browser URL: http://localhost:{bind_port}/")
    else:
        print("[!] Remote access uses HTTP Basic authentication; put this server behind TLS.")
    print(f"[*] Connected to SQLite database: {DB_PATH}")
    print("[*] Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")
        httpd.server_close()

def parse_args(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Serve ghidra-report history and artifacts.")
    parser.add_argument("port", nargs="?", type=int, default=8080)
    parser.add_argument(
        "--host",
        default=os.environ.get("GHIDRA_DASHBOARD_HOST", "127.0.0.1"),
        help="bind address (default: 127.0.0.1; remote binds require GHIDRA_DASHBOARD_TOKEN)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    run_server(args.port, args.host)
