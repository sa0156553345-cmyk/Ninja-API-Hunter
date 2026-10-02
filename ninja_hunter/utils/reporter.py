"""
Ninja-API-Hunter v4.0
Exports scan results as JSON or a simple, self-contained HTML report.
"""
import json
import html as html_lib
from datetime import datetime


def export_json(data, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return filepath


def export_html(data, filepath):
    findings = data.get("findings", {})
    summary_rows = []
    for category, value in findings.items():
        count = len(value) if isinstance(value, (list, dict)) else 1
        summary_rows.append(f"<tr><td>{html_lib.escape(str(category))}</td><td>{count}</td></tr>")
    summary_html = "\n".join(summary_rows) or "<tr><td colspan='2'>No findings</td></tr>"
    pretty_json = html_lib.escape(json.dumps(findings, indent=2, ensure_ascii=False, default=str))

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ninja-API-Hunter Report</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Arial, sans-serif; background:#0d1117; color:#e6edf3; margin:2rem; }}
  h1 {{ color:#58a6ff; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1rem; }}
  th, td {{ border:1px solid #30363d; padding:8px 12px; text-align:left; font-size:14px; }}
  th {{ background:#161b22; }}
  tr:nth-child(even) {{ background:#161b22; }}
  .meta {{ color:#8b949e; font-size:13px; }}
  pre {{ background:#161b22; padding:1rem; overflow-x:auto; border-radius:6px; font-size:12px; }}
</style>
</head>
<body>
  <h1>Ninja-API-Hunter -- Scan Report</h1>
  <p class="meta">Target: {html_lib.escape(str(data.get('target', '')))} &middot; Generated: {datetime.now().isoformat()}</p>
  <table>
    <tr><th>Category</th><th>Items</th></tr>
    {summary_html}
  </table>
  <h2>Raw findings</h2>
  <pre>{pretty_json}</pre>
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(page)
    return filepath


def export(data, filepath, fmt="json"):
    if fmt == "html":
        return export_html(data, filepath)
    return export_json(data, filepath)
