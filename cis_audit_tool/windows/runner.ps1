param (
    [string]$Profile = "cis-windows-11.json",
    [string]$Format = "HTML"
)

Write-Host "CIS Audit - Windows Runner"

# Build full profile path
$profilePath = Join-Path -Path "$PSScriptRoot\policies" -ChildPath $Profile

# Verify profile exists
if (-not (Test-Path $profilePath)) {
    Write-Error "Profile file not found: $profilePath"
    exit 1
}

# Load profile JSON
$profileContent = Get-Content -Path $profilePath -Raw | ConvertFrom-Json
Write-Host "Profile loaded: $Profile"

$results = @()

foreach ($check in $profileContent) {
    Write-Host "Running check: $($check.Function)"

    if (-not $check.Function) {
        Write-Host "Skipping check: $($check.Title) - Function is empty"
        continue
    }

    $fn = Get-Command $check.Function -ErrorAction SilentlyContinue
    if ($null -eq $fn) {
        Write-Host "Skipping check: $($check.Function) - Function not found"
        $results += [PSCustomObject]@{
            Control     = $check.Id
            Title       = $check.Title
            Status      = "Skipped"
            Actual      = "Function not found"
            Remediation = "Implement $($check.Function)"
        }
        continue
    }

    try {
        # Run the check without forcing Stop (functions handle Pass/Fail themselves)
        $result = & $check.Function 2>$null

        if ($null -eq $result) {
            $results += [PSCustomObject]@{
                Control     = $check.Id
                Title       = $check.Title
                Status      = "Error"
                Actual      = "Function returned no result"
                Remediation = "Check implementation of $($check.Function)"
            }
        }
        else {
            $results += [PSCustomObject]@{
                Control     = $check.Id
                Title       = $check.Title
                Status      = $result.Status
                Actual      = $result.Actual
                Remediation = $result.Remediation
            }
        }
    }
    catch {
        # Only true runtime errors reach here
        $results += [PSCustomObject]@{
            Control     = $check.Id
            Title       = $check.Title
            Status      = "Not Found/Configured"
            # Actual      = $_.Exception.Message
            Actual = "Key/Value not found or inaccessible"
            Remediation = "Review $($check.Title) and configure per CIS Benchmark"   # <-- fallback remediation
        }
    }
}

# Export results
if ($Format -eq "HTML") {
    $templatePath = "$PSScriptRoot\templates\report.html"
    if (-not (Test-Path $templatePath)) {
        Write-Warning "HTML template not found at $templatePath. Using default inline template."
        $html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>CIS Audit Summary</title>
  <style>
    body{font-family:Segoe UI,Arial;margin:20px}
    table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #ddd;padding:8px}
    th{background:#f4f4f4}
    pre{white-space:pre-wrap;font-family:Consolas,monospace}
  </style>
</head>
<body>
  <h1>CIS Audit Summary</h1>
  <table>
    <thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Actual</th><th>Remediation</th></tr></thead>
    <tbody>
      ##TABLE_ROWS##
    </tbody>
  </table>
</body>
</html>
"@
    }
    else {
        $html = Get-Content $templatePath -Raw
    }

    $rows = ""
    foreach ($r in $results) {
        $rows += "<tr><td>$($r.Control)</td><td>$($r.Title)</td><td>$($r.Status)</td><td>$($r.Actual)</td><td>$($r.Remediation)</td></tr>`n"
    }
    $html = $html -replace "##TABLE_ROWS##", $rows

    $out = "$PSScriptRoot\audit-report.html"
    $html | Out-File $out -Encoding utf8
    Write-Host "HTML report generated: $out"
}
elseif ($Format -eq "JSON") {
    $out = "$PSScriptRoot\audit-report.json"
    $results | ConvertTo-Json -Depth 4 | Out-File $out -Encoding utf8
    Write-Host "JSON report generated: $out"
}
else {
    Write-Error "Unknown format: $Format"
}

# Always generate both HTML and JSON
$out_html = "$PSScriptRoot\audit-report.html"
$out_json = "$PSScriptRoot\audit-report.json"

# HTML
# (existing HTML generation code)
$html | Out-File $out_html -Encoding utf8

# JSON
$results | ConvertTo-Json -Depth 4 | Out-File $out_json -Encoding utf8

Write-Host "Reports generated:"
Write-Host "HTML: $out_html"
Write-Host "JSON: $out_json"

# Output JSON to stdout for Python to capture
$results | ConvertTo-Json -Depth 4 | Write-Output
