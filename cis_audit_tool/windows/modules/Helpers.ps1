# Helpers.ps1
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $t = Get-Date -Format o
    "$t [$Level] $Message"
}

function New-CheckResult {
    param(
        [string]$ControlId,
        [string]$Title,
        [string]$Expected,
        [string]$Actual,
        [ValidateSet('Pass','Fail','Warn','NA')] [string]$Status,
        [string]$Remediation
    )

    return [PSCustomObject]@{
        ControlId   = $ControlId
        Title       = $Title
        Expected    = $Expected
        Actual      = $Actual
        Status      = $Status
        Remediation = $Remediation
        Timestamp   = (Get-Date).ToString('o')
        MachineName = $env:COMPUTERNAME
    }
}

function Ensure-Elevated {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script is not running as Administrator. Some checks may fail or return incomplete results. Please re-run in an elevated session."
        return $false
    }
    return $true
}

function Save-Results {
    param(
        [Parameter(Mandatory=$true)][array]$Results,
        [string]$OutDir = (Join-Path -Path (Get-Location) -ChildPath 'results')
    )

    if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
    $jsonPath = Join-Path $OutDir 'results.json'
    $csvPath  = Join-Path $OutDir 'results.csv'
    $htmlPath = Join-Path $OutDir 'summary.html'

    $Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding utf8
    $Results | Select-Object ControlId,Title,Status,Actual,Remediation,Timestamp,MachineName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

    $template = Join-Path (Split-Path $MyInvocation.MyCommand.Definition) '..\templates\report-template.html'
    if (Test-Path $template) {
        $tmpl = Get-Content $template -Raw
        $rows = $Results | ForEach-Object {
            "<tr><td>$($_.ControlId)</td><td>$($_.Title)</td><td>$($_.Status)</td><td><pre>$($_.Actual)</pre></td><td>$($_.Remediation)</td></tr>"
        } -join "`n"
        $outHtml = $tmpl -replace '##TABLE_ROWS##', $rows
        $outHtml | Out-File -FilePath $htmlPath -Encoding utf8
    }

    return @{ json = $jsonPath; csv = $csvPath; html = $htmlPath }
}
