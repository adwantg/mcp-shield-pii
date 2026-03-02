"""Lightweight compliance dashboard for viewing redaction history."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcp-shield-pii Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:#0f1117;color:#e1e4e8;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1f36 0%,#0d1025 100%);padding:24px 40px;border-bottom:1px solid #2d3348}
.header h1{font-size:24px;background:linear-gradient(90deg,#7c3aed,#06b6d4);-webkit-background-clip:text;color:transparent;font-weight:700}
.header p{color:#8b92a5;margin-top:4px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;padding:24px 40px}
.card{background:#161b2e;border:1px solid #2d3348;border-radius:12px;padding:20px}
.card .label{color:#8b92a5;font-size:12px;text-transform:uppercase;letter-spacing:1px}
.card .value{font-size:28px;font-weight:700;margin-top:8px;background:linear-gradient(90deg,#7c3aed,#06b6d4);-webkit-background-clip:text;color:transparent}
.table-wrap{padding:24px 40px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;padding:12px 16px;color:#8b92a5;border-bottom:1px solid #2d3348;font-weight:600}
td{padding:12px 16px;border-bottom:1px solid #1e2338}
tr:hover{background:#1a1f36}
.badge{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:12px;font-weight:600}
.badge-high{background:#7f1d1d;color:#fca5a5}
.badge-medium{background:#78350f;color:#fbbf24}
.badge-low{background:#064e3b;color:#6ee7b7}
</style>
</head>
<body>
<div class="header">
<h1>🛡️ mcp-shield-pii Dashboard</h1>
<p>Real-time PII redaction monitoring and compliance reporting</p>
</div>
<div class="grid">
<div class="card"><div class="label">Total Scans</div><div class="value" id="total-scans">0</div></div>
<div class="card"><div class="label">Entities Detected</div><div class="value" id="total-entities">0</div></div>
<div class="card"><div class="label">Avg Latency</div><div class="value" id="avg-latency">0ms</div></div>
<div class="card"><div class="label">Status</div><div class="value" id="status">Active</div></div>
</div>
<div class="table-wrap">
<h2 style="color:#e1e4e8;margin-bottom:16px;font-size:18px">Recent Redaction Events</h2>
<table>
<thead><tr><th>Time</th><th>Tool</th><th>Entity Type</th><th>Strategy</th><th>Confidence</th><th>Severity</th></tr></thead>
<tbody id="events-body"></tbody>
</table>
</div>
<script>
async function refresh(){
  try{
    const r=await fetch('/api/events');const d=await r.json();
    document.getElementById('total-scans').textContent=d.total_scans;
    document.getElementById('total-entities').textContent=d.total_entities;
    document.getElementById('avg-latency').textContent=d.avg_latency_ms.toFixed(1)+'ms';
    const tbody=document.getElementById('events-body');tbody.innerHTML='';
    d.events.slice(-50).reverse().forEach(e=>{
      const sev=e.severity||'medium';
      const cls='badge badge-'+sev;
      tbody.innerHTML+=`<tr><td>${e.timestamp}</td><td>${e.tool_name}</td><td>${e.entity_type}</td><td>${e.masking_strategy}</td><td>${(e.confidence*100).toFixed(0)}%</td><td><span class="${cls}">${sev}</span></td></tr>`;
    });
  }catch(e){console.error(e)}
}
refresh();setInterval(refresh,3000);
</script>
</body></html>"""


class DashboardServer:
    """Lightweight aiohttp-based dashboard for monitoring redaction activity."""

    def __init__(
        self,
        audit_log_file: str = "shield_audit.jsonl",
        host: str = "127.0.0.1",
        port: int = 8765,
    ) -> None:
        self._audit_file = Path(audit_log_file)
        self._host = host
        self._port = port

    def _read_events(self) -> list[dict[str, Any]]:
        """Read audit events from the JSONL log."""
        events: list[dict[str, Any]] = []
        if not self._audit_file.exists():
            return events
        try:
            with open(self._audit_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return events

    async def start(self) -> None:
        """Start the dashboard web server."""
        from aiohttp import web

        async def index(request: web.Request) -> web.Response:
            return web.Response(text=_DASHBOARD_HTML, content_type="text/html")

        async def api_events(request: web.Request) -> web.Response:
            events = self._read_events()
            redaction_events = [e for e in events if "entity_type" in e]
            summary_events = [e for e in events if e.get("event_type") == "scan_summary"]

            total_scans = len(summary_events)
            total_entities = sum(e.get("total_entities", 0) for e in summary_events)
            latencies = [e.get("processing_time_ms", 0) for e in summary_events if e.get("processing_time_ms")]
            avg_lat = sum(latencies) / len(latencies) if latencies else 0

            # Add severity to events
            HIGH = {"SSN", "CREDIT_CARD", "MEDICAL_ID", "API_KEY_AWS", "API_KEY_OPENAI", "PASSPORT_NUMBER", "JWT_TOKEN"}
            for e in redaction_events:
                e["severity"] = "high" if e.get("entity_type", "") in HIGH else "medium"

            return web.json_response({
                "total_scans": total_scans,
                "total_entities": total_entities,
                "avg_latency_ms": avg_lat,
                "events": redaction_events[-100:],
            })

        app = web.Application()
        app.router.add_get("/", index)
        app.router.add_get("/api/events", api_events)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self._host, self._port)
        await site.start()
        logger.info("Dashboard running at http://%s:%d", self._host, self._port)
