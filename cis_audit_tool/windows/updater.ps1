param(
    [string]$Url,
    [string]$LocalPath = (Join-Path (Split-Path $MyInvocation.MyCommand.Definition) '..\policies\cis-windows-11.json')
)

if ($Url) {
    try {
        Invoke-RestMethod -Uri $Url -OutFile $LocalPath -ErrorAction Stop
        Write-Host "Updated policy file from $Url to $LocalPath"
    } catch { Write-Error "Failed to download: $($_.Exception.Message)" }
} else {
    Write-Host "No URL provided. To update policies provide a URL to a JSON file of the same schema."
}
