import csv
import json
import sys

def generate_output(results, output_format="text"):
    """Generate output in the specified format."""
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
    elif output_format == "html":
        # Prepare summary data for chart
        status_counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0}
        for result in results:
            status = result["status"]
            if status in status_counts:
                status_counts[status] += 1

        html_content = []
        html_content.append("""
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>CIS Audit Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }}
        h1 {{ color: #333; }}
        .summary {{ margin-bottom: 30px; }}
        .chart-container {{ width: 400px; margin-bottom: 30px; }}
        table {{ border-collapse: collapse; width: 100%; background: #fff; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background: #eee; }}
        tr.pass {{ background: #e6ffe6; }}
        tr.fail {{ background: #ffe6e6; }}
        tr.manual {{ background: #ffffe6; }}
        .filter-bar {{ margin-bottom: 20px; }}
        .filter-bar label {{ margin-right: 10px; }}
        .hidden {{ display: none; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>CIS Audit Report</h1>
    <div class="summary">
        <strong>Summary:</strong>
        <ul>
            <li>Passed: {passed}</li>
            <li>Failed: {failed}</li>
            <li>Manual: {manual}</li>
            <li>Total: {total}</li>
        </ul>
    </div>
    <div class="chart-container">
        <canvas id="statusChart"></canvas>
    </div>
    <div class="filter-bar">
        <label><input type="checkbox" id="showPass" checked> Show PASS</label>
        <label><input type="checkbox" id="showFail" checked> Show FAIL</label>
        <label><input type="checkbox" id="showManual" checked> Show MANUAL</label>
    </div>
    <script>
        const ctx = document.getElementById('statusChart').getContext('2d');
        const statusChart = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['PASS', 'FAIL', 'MANUAL'],
                datasets: [{{
                    data: [{passed}, {failed}, {manual}],
                    backgroundColor: ['#4caf50', '#f44336', '#ffeb3b'],
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});

        // Filtering logic
        document.addEventListener('DOMContentLoaded', function() {{
            function updateRows() {{
                let showPass = document.getElementById('showPass').checked;
                let showFail = document.getElementById('showFail').checked;
                let showManual = document.getElementById('showManual').checked;
                document.querySelectorAll('tr.pass').forEach(tr => tr.style.display = showPass ? '' : 'none');
                document.querySelectorAll('tr.fail').forEach(tr => tr.style.display = showFail ? '' : 'none');
                document.querySelectorAll('tr.manual').forEach(tr => tr.style.display = showManual ? '' : 'none');
            }}
            document.getElementById('showPass').addEventListener('change', updateRows);
            document.getElementById('showFail').addEventListener('change', updateRows);
            document.getElementById('showManual').addEventListener('change', updateRows);
            updateRows();
        }});
    </script>
""".format(
    passed=status_counts["PASS"],
    failed=status_counts["FAIL"],
    manual=status_counts["MANUAL"],
    total=sum(status_counts.values())
))

        html_content.append("<table>")
        # Header
        html_content.append("<tr>" + "".join(f"<th>{key}</th>" for key in results[0].keys()) + "</tr>")
        # Rows
        for result in results:
            status_class = result["status"].lower()
            html_content.append(
                f"<tr class='{status_class}'>" +
                "".join(f"<td>{result[key]}</td>" for key in results[0].keys()) +
                "</tr>"
            )
        html_content.append("</table>")
        html_content.append("</body></html>")
        with open("cis_audit_results.html", "w", encoding="utf-8") as f:
            f.write("\n".join(html_content))
        print("Interactive HTML report written to cis_audit_results.html")