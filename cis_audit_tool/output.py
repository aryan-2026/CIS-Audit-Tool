import csv
import json
import sys
import os


def generate_output(results, output_format="text"):
    """Generate audit output in multiple formats for both Linux and Windows."""

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # ---------- WINDOWS ----------
    if sys.platform == "win32":
        report_dir = os.path.join(script_dir, "windows")
        os.makedirs(report_dir, exist_ok=True)

        if not results:
            print("⚠️ No results found to export.")
            return

        # Normalize key names (PowerShell → Python-friendly keys)
        normalized_results = [
            {
                "id": r.get("ID", r.get("id")),
                "title": r.get("Title", r.get("title")),
                "result": r.get("Result", r.get("result")),
                "expected": r.get("Expected", r.get("expected", "")),
                "actual": r.get("Actual", r.get("actual", "")),
                "severity": r.get("Severity", r.get("severity", "")),
                "remediation": r.get("Remediation", r.get("remediation", "")),
            }
            for r in results
        ]

        # ----- JSON -----
        json_path = os.path.join(report_dir, "audit-report.json")
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(normalized_results, jf, indent=2)
        print(f"✅ JSON report saved: {json_path}")

        # ----- CSV -----
        csv_path = os.path.join(report_dir, "audit-report.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=normalized_results[0].keys())
            writer.writeheader()
            writer.writerows(normalized_results)
        print(f"✅ CSV report saved: {csv_path}")

        # ----- PSV -----
        psv_path = os.path.join(report_dir, "audit-report.psv")
        with open(psv_path, "w", newline="", encoding="utf-8") as pf:
            writer = csv.DictWriter(pf, fieldnames=normalized_results[0].keys(), delimiter="|")
            writer.writeheader()
            writer.writerows(normalized_results)
        print(f"✅ PSV report saved: {psv_path}")

        # ----- TSV -----
        tsv_path = os.path.join(report_dir, "audit-report.tsv")
        with open(tsv_path, "w", newline="", encoding="utf-8") as tf:
            writer = csv.DictWriter(tf, fieldnames=normalized_results[0].keys(), delimiter="\t")
            writer.writeheader()
            writer.writerows(normalized_results)
        print(f"✅ TSV report saved: {tsv_path}")

        # ----- TEXT -----
        txt_path = os.path.join(report_dir, "audit-report.txt")
        with open(txt_path, "w", encoding="utf-8") as tf:
            for r in normalized_results:
                tf.write(f"{r['id']}: {r['actual']} - {r['result']}\n")
        print(f"✅ Text report saved: {txt_path}")

    # ---------- LINUX ----------
    elif sys.platform == "linux":
        if not results:
            print("⚠️ No results found to export.")
            return

        if output_format == "text":
            for result in results:
                print(f"{result['id']}: {result['status']} - {result['description']}")
        elif output_format == "json":
            print(json.dumps(results, indent=2))
        elif output_format == "csv":
            writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        elif output_format == "psv":
            writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys(), delimiter="|")
            writer.writeheader()
            writer.writerows(results)
        elif output_format == "tsv":
            writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys(), delimiter="\t")
            writer.writeheader()
            writer.writerows(results)

    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    # ---------- COMMON (HTML FOR BOTH) ----------
    if output_format == "html" and results:
        # Count statuses for chart
        status_counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0}
        for r in results:
            status = (r.get("result") or r.get("status") or "").upper()
            if status in status_counts:
                status_counts[status] += 1

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>CIS Audit Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; background: #fff; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background: #eee; }}
        tr.pass {{ background: #e6ffe6; }}
        tr.fail {{ background: #ffe6e6; }}
        tr.manual {{ background: #ffffe6; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>CIS Audit Report</h1>
    <h3>Summary</h3>
    <ul>
        <li>Passed: {status_counts["PASS"]}</li>
        <li>Failed: {status_counts["FAIL"]}</li>
        <li>Manual: {status_counts["MANUAL"]}</li>
        <li>Total: {sum(status_counts.values())}</li>
    </ul>
    <canvas id="statusChart" width="300" height="300"></canvas>
    <script>
        const ctx = document.getElementById('statusChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['PASS', 'FAIL', 'MANUAL'],
                datasets: [{{
                    data: [{status_counts["PASS"]}, {status_counts["FAIL"]}, {status_counts["MANUAL"]}],
                    backgroundColor: ['#4caf50', '#f44336', '#ffeb3b'],
                }}]
            }}
        }});
    </script>
    <table>
        <tr>{"".join(f"<th>{k}</th>" for k in results[0].keys())}</tr>
"""

        for r in results:
            row_class = (r.get("result") or r.get("status") or "").lower()
            html += "<tr class='{}'>".format(row_class)
            html += "".join(f"<td>{r.get(k, '')}</td>" for k in results[0].keys())
            html += "</tr>\n"

        html += "</table></body></html>"

        html_path = os.path.join(script_dir, "cis_audit_results.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"\n✅ Interactive HTML report written to: {html_path}\n")
