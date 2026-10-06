#!/usr/bin/env python3
"""
generate_report.py - Professional attack report generator
Analyzes honeypot logs and creates structured security reports.
"""

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def load_logs(log_file: str) -> List[Dict[str, Any]]:
    """Load JSONL attack logs."""
    logs: List[Dict[str, Any]] = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    line = line.strip()
                    start = 0
                    while start < len(line):
                        opening = line.find('{', start)
                        if opening == -1:
                            break

                        depth = 0
                        closing = -1
                        for i in range(opening, len(line)):
                            if line[i] == '{':
                                depth += 1
                            elif line[i] == '}':
                                depth -= 1
                                if depth == 0:
                                    closing = i
                                    break

                        if closing == -1:
                            break

                        try:
                            json_obj = json.loads(line[opening:closing + 1])
                            logs.append(json_obj)
                        except json.JSONDecodeError:
                            pass

                        start = closing + 1
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)
    return logs


def analyze_attacks(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze logs and extract key metrics."""
    total_attacks = len(logs)
    if not logs:
        return {}

    logs_sorted = sorted(logs, key=lambda x: x.get("timestamp", ""))
    start_date = logs_sorted[0].get("timestamp", "")
    end_date = logs_sorted[-1].get("timestamp", "")

    threat_levels = Counter(
        log.get("threat_level", "unknown") for log in logs
    )

    endpoints = Counter(log.get("endpoint", "") for log in logs)

    attack_categories: Counter[str] = Counter()
    for log in logs:
        for cat in log.get("categories", []):
            attack_categories[cat] += 1

    detected_patterns: Counter[str] = Counter()
    for log in logs:
        for pattern in log.get("detected_patterns", []):
            detected_patterns[pattern] += 1

    countries = Counter(
        log.get("country", "Unknown") for log in logs
    )

    api_keys_attempted = len(
        [log for log in logs if log.get("api_key_tried")]
    )

    ips = Counter(log.get("ip", "") for log in logs)

    payload_sizes = [log.get("payload_size", 0) for log in logs]
    avg_payload_size = (
        sum(payload_sizes) / len(payload_sizes) if payload_sizes else 0
    )
    max_payload_size = max(payload_sizes) if payload_sizes else 0

    return {
        "total_attacks": total_attacks,
        "date_range": {"start": start_date, "end": end_date},
        "threat_levels": dict(threat_levels),
        "endpoints": dict(endpoints.most_common(10)),
        "attack_categories": dict(attack_categories.most_common(10)),
        "detected_patterns": dict(detected_patterns.most_common(10)),
        "geographic_distribution": dict(countries.most_common(10)),
        "api_key_attempts": api_keys_attempted,
        "top_attacking_ips": dict(ips.most_common(10)),
        "payload_stats": {
            "average_size": round(avg_payload_size, 2),
            "max_size": max_payload_size,
            "total_payloads": len(payload_sizes),
        },
    }


def generate_html_report(
    report_analysis: Dict[str, Any],
    output_file: str = "report.html"
) -> None:
    """Generate a professional HTML report."""
    total = report_analysis.get("total_attacks", 0)
    total_attacks = report_analysis.get("total_attacks", 0)
    api_attempts = report_analysis.get("api_key_attempts", 0)
    countries_count = len(
        report_analysis.get("geographic_distribution", {})
    )
    ips_count = len(report_analysis.get("top_attacking_ips", {}))
    date_start = report_analysis.get("date_range", {}).get("start", "")
    date_end = report_analysis.get("date_range", {}).get("end", "")

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>LLM Honeypot Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .content {{
            padding: 40px;
        }}

        .section {{
            margin-bottom: 40px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }}

        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}

        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .metric-card {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .metric-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }}

        .metric-card .label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }}

        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .threat-high {{
            color: #dc3545;
            font-weight: bold;
        }}

        .threat-medium {{
            color: #ffc107;
            font-weight: bold;
        }}

        .threat-low {{
            color: #28a745;
            font-weight: bold;
        }}

        .bar {{
            display: inline-block;
            background: #667eea;
            height: 20px;
            border-radius: 3px;
        }}

        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #999;
            border-top: 1px solid #e9ecef;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍯 LLM Honeypot Security Report</h1>
            <p>Attack Analysis &amp; Threat Intelligence</p>
        </div>

        <div class="content">
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="metrics">
                    <div class="metric-card">
                        <div class="value">{total_attacks}</div>
                        <div class="label">Total Attacks</div>
                    </div>
                    <div class="metric-card">
                        <div class="value">{api_attempts}</div>
                        <div class="label">API Key Attempts</div>
                    </div>
                    <div class="metric-card">
                        <div class="value">{countries_count}</div>
                        <div class="label">Countries</div>
                    </div>
                    <div class="metric-card">
                        <div class="value">{ips_count}</div>
                        <div class="label">Unique IPs</div>
                    </div>
                </div>
                <p>
                    <strong>Analysis Period:</strong>
                    {date_start} → {date_end}
                </p>
            </div>

            <div class="section">
                <h2>Threat Level Distribution</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Threat Level</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
"""
    for threat_level, count in sorted(
        report_analysis.get("threat_levels", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        percentage = (count / total * 100) if total > 0 else 0
        threat_class = f"threat-{threat_level}"
        bar_width = (count / total * 300) if total > 0 else 0
        html_content += f"""                        <tr>
                            <td>
                                <span class="{threat_class}">
                                    {threat_level.upper()}
                                </span>
                            </td>
                            <td>{count}</td>
                            <td>
                                <div class="bar" style="width: {bar_width}px;">
                                </div> {percentage:.1f}%
                            </td>
                        </tr>
"""

    html_content += """                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Top Attacked Endpoints</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Endpoint</th>
                            <th>Attacks</th>
                            <th>Distribution</th>
                        </tr>
                    </thead>
                    <tbody>
"""

    for endpoint, count in sorted(
        report_analysis.get("endpoints", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:10]:
        bar_width = (count / total * 300) if total > 0 else 0
        endpoint_display = endpoint or "/"
        html_content += f"""                        <tr>
                            <td><code>{endpoint_display}</code></td>
                            <td>{count}</td>
                            <td>
                                <div class="bar" style="width: {bar_width}px;">
                                </div>
                            </td>
                        </tr>
"""

    html_content += """                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Attack Categories</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Occurrences</th>
                        </tr>
                    </thead>
                    <tbody>
"""

    for category, count in sorted(
        report_analysis.get("attack_categories", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        html_content += f"""                        <tr>
                            <td>{category}</td>
                            <td>{count}</td>
                        </tr>
"""

    html_content += """                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Top Detected Patterns</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Pattern</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
"""

    for pattern, count in sorted(
        report_analysis.get("detected_patterns", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:15]:
        html_content += f"""                        <tr>
                            <td>{pattern}</td>
                            <td>{count}</td>
                        </tr>
"""

    html_content += """                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Geographic Distribution</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Country</th>
                            <th>Attacks</th>
                            <th>Distribution</th>
                        </tr>
                    </thead>
                    <tbody>
"""

    for country, count in sorted(
        report_analysis.get("geographic_distribution", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:15]:
        bar_width = (count / total * 300) if total > 0 else 0
        html_content += f"""                        <tr>
                            <td>{country}</td>
                            <td>{count}</td>
                            <td>
                                <div class="bar" style="width: {bar_width}px;">
                                </div>
                            </td>
                        </tr>
"""

    html_content += """                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Payload Statistics</h2>
                <div class="metrics">
"""

    payload_stats = report_analysis.get("payload_stats", {})
    for key, value in payload_stats.items():
        label = key.replace("_", " ").title()
        html_content += f"""                    <div class="metric-card">
                        <div class="value">{value}</div>
                        <div class="label">{label}</div>
                    </div>
"""

    html_content += f"""                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC
            </p>
            <p>LLM Honeypot Security Analysis</p>
        </div>
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ HTML report generated: {output_file}")


def generate_json_report(
    report_analysis: Dict[str, Any],
    output_file: str = "report.json"
) -> None:
    """Generate a JSON report for programmatic access."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "analysis": report_analysis,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"✅ JSON report generated: {output_file}")


def generate_markdown_report(
    report_analysis: Dict[str, Any],
    output_file: str = "REPORT.md"
) -> None:
    """Generate a Markdown report."""
    total = report_analysis.get("total_attacks", 0)

    md_content = f"""# 🍯 LLM Honeypot Security Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}

## Executive Summary

- **Total Attacks:** {report_analysis.get("total_attacks", 0)}
- **Analysis Period:** {report_analysis.get("date_range", {}).get("start")} \
→ {report_analysis.get("date_range", {}).get("end")}
- **API Key Attempts:** {report_analysis.get("api_key_attempts", 0)}
- **Unique Countries:** \
{len(report_analysis.get("geographic_distribution", {}))}
- **Unique IPs:** {len(report_analysis.get("top_attacking_ips", {}))}

## Threat Level Distribution

| Level | Count | Percentage |
|-------|-------|-----------|
"""

    for threat_level, count in sorted(
        report_analysis.get("threat_levels", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        percentage = (count / total * 100) if total > 0 else 0
        md_content += f"| **{threat_level.upper()}** | {count} | \
{percentage:.1f}% |\n"

    md_content += """
## Top Attacked Endpoints

| Endpoint | Attacks |
|----------|---------|
"""

    for endpoint, count in sorted(
        report_analysis.get("endpoints", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:10]:
        endpoint_display = endpoint or "/"
        md_content += f"| `{endpoint_display}` | {count} |\n"

    md_content += """
## Attack Categories

| Category | Count |
|----------|-------|
"""

    for category, count in sorted(
        report_analysis.get("attack_categories", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        md_content += f"| {category} | {count} |\n"

    md_content += """
## Top Detected Patterns

| Pattern | Count |
|---------|-------|
"""

    for pattern, count in sorted(
        report_analysis.get("detected_patterns", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:15]:
        md_content += f"| {pattern} | {count} |\n"

    md_content += """
## Geographic Distribution (Top 15)

| Country | Attacks |
|---------|---------|
"""

    for country, count in sorted(
        report_analysis.get("geographic_distribution", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:15]:
        md_content += f"| {country} | {count} |\n"

    payload_stats = report_analysis.get("payload_stats", {})
    md_content += f"""
## Payload Statistics

- **Average Size:** {payload_stats.get("average_size", 0)} bytes
- **Max Size:** {payload_stats.get("max_size", 0)} bytes
- **Total Payloads:** {payload_stats.get("total_payloads", 0)}

## Top Attacking IPs (Local)

| IP | Attacks |
|----|---------|
"""

    for ip, count in sorted(
        report_analysis.get("top_attacking_ips", {}).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:15]:
        md_content += f"| {ip} | {count} |\n"

    md_content += """
---

*Report generated by LLM Honeypot Security Analysis System*
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"✅ Markdown report generated: {output_file}")


if __name__ == "__main__":
    log_path = Path(__file__).parent.parent / "logs" / "attacks.jsonl"

    if len(sys.argv) > 1:
        log_path = Path(sys.argv[1])

    print(f"📊 Analyzing logs from: {log_path}")

    honeypot_logs = load_logs(str(log_path))
    report_data = analyze_attacks(honeypot_logs)

    if report_data:
        print(f"✅ Loaded {len(honeypot_logs)} attack records")

        reports_directory = Path(__file__).parent.parent / "reports"
        reports_directory.mkdir(exist_ok=True)

        generate_markdown_report(
            report_data,
            str(reports_directory / "REPORT.md")
        )
        generate_html_report(
            report_data,
            str(reports_directory / "report.html")
        )
        generate_json_report(
            report_data,
            str(reports_directory / "report.json")
        )

        print("\n📁 All reports generated in: reports/")
    else:
        print("❌ No data to analyze")
