# Security Operations & SOAR Integration Guide

`ghidra-report` is designed for autonomous security pipelines, security orchestration automation and response (SOAR) engines, and threat intelligence ingestion.

---

## Standard Output Artifacts for Automation

For every analyzed binary, `ghidra-report` emits standardized formats designed for machine consumption:

| Artifact | Standard | Target Platform / Consumer |
|---|---|---|
| `report_latest.misp.json` | MISP 2.4 Event JSON | MISP Threat Sharing, OpenCTI |
| `report_latest.sarif` | OASIS SARIF v2.1.0 | GitHub Code Scanning, GitLab SAST, Azure DevOps |
| `report_latest.yar` | YARA Rule | CrowdStrike Falcon, Suricata, YARA Daemon |
| `report_latest.json` | Structured JSON Schema | Shuffle SOAR, Tines, Splunk, Elastic Security |

---

## 1. MISP & OpenCTI Ingestion

`report_latest.misp.json` contains a structured `Event` object with typed attributes:
- `sha256`, `md5`, `imphash`
- `ip-dst`, `url`, `regkey` (extracted IOCs)
- `mitre-attack-pattern` tags mapped from API usage and shellcode heuristics

### Ingestion via OpenCTI
Using the standard OpenCTI MISP Connector:
```bash
# Ingest MISP JSON directly into OpenCTI via API
curl -X POST "https://opencti.internal/api/v1/import/misp" \
  -H "Authorization: Bearer ${OPENCTI_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @output/dsetup.dll/report_latest.misp.json
```

---

## 2. Shuffle SOAR Workflow Integration

Shuffle SOAR workflows can ingest `ghidra-report` outputs via Webhook alerts or filesystem polling.

### Webhook Dispatch Trigger
Run `ghidra-report` with `--webhook`:
```bash
./ghidra-report.sh ingress/suspicious.exe --webhook "https://shuffle.internal/api/v1/hooks/webhook_12345"
```
The payload delivers:
```json
{
  "binary": "suspicious.exe",
  "risk_score": 100,
  "risk_level": "CRITICAL",
  "sha256": "38be6e355694a5c9b9cb12293881df3e08f5d078c1b6370ba054f15d97f25977",
  "high_priority_findings": [
    "[T1055] RWX memory block detected: .themida — possible shellcode staging",
    "[T1027.002] High-entropy section (.boot: 7.95 / 8.00) — likely packed or encrypted"
  ]
}
```

### Automated Playbook Actions in Shuffle:
1. **Condition**: If `risk_score >= 80`, branch to Containment.
2. **Action 1**: Post YARA rule (`report_latest.yar`) to EDR sensor.
3. **Action 2**: Block C2 IP / Domain extracted from `report_latest.json` on perimeter firewall.
4. **Action 3**: Notify SOC Tier 2 on Slack/Discord with direct link to Web Dashboard.

---

## 3. GitHub Code Scanning & CI/CD Integration

Upload `report_latest.sarif` directly to GitHub Security tab:
```yaml
- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: output/<binary_name>/report_latest.sarif
    category: ghidra-binary-triage
```
