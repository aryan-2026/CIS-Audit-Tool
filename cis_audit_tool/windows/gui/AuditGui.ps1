Add-Type -AssemblyName PresentationFramework

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="CIS Audit Tool - Windows" Height="420" Width="700">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,10">
      <Button Name="BtnLoad" Width="120" Height="30" Margin="0,0,10,0">Load Checks</Button>
      <Button Name="BtnRun" Width="120" Height="30" Margin="0,0,10,0">Run Selected</Button>
      <Button Name="BtnRunAll" Width="120" Height="30">Run All</Button>
    </StackPanel>

    <ListBox Name="ChecksList" Grid.Row="1" SelectionMode="Extended" />

    <StatusBar Grid.Row="2">
      <StatusBarItem>
        <TextBlock Name="StatusText">Ready</TextBlock>
      </StatusBarItem>
    </StatusBar>
  </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$btnLoad = $window.FindName('BtnLoad')
$btnRun = $window.FindName('BtnRun')
$btnRunAll = $window.FindName('BtnRunAll')
$checksList = $window.FindName('ChecksList')
$statusText = $window.FindName('StatusText')

$scriptDir = Split-Path $MyInvocation.MyCommand.Definition
$policyFile = Join-Path $scriptDir '..\policies\cis-windows-11.json'
$runner = Join-Path $scriptDir '..\runner.ps1'

$btnLoad.Add_Click({
    if (-not (Test-Path $policyFile)) { [System.Windows.MessageBox]::Show("Policy file not found: $policyFile") ; return }
    $policy = Get-Content $policyFile -Raw | ConvertFrom-Json
    $checksList.Items.Clear()
    foreach ($c in $policy.checks) {
        $item = New-Object System.Windows.Controls.Primitives.ToggleButton
        $item.Content = "$($c.controlId) - $($c.title)"
        $item.Tag = $c.function
        $checksList.Items.Add($item) | Out-Null
    }
    $statusText.Text = "Loaded $($policy.checks.Count) checks"
})

function Run-SelectedChecks([string[]]$functions) {
    $statusText.Text = "Running $($functions.Count) checks..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`" -All:$false"
    $psi.Arguments = $args
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($out) { [System.Windows.MessageBox]::Show("Runner output:`n$out") }
    if ($err) { [System.Windows.MessageBox]::Show("Runner errors:`n$err") }
    $statusText.Text = 'Run complete'
}

$btnRun.Add_Click({
    $sel = @()
    foreach ($i in $checksList.Items) { if ($i.IsChecked) { $sel += $i.Tag } }
    if ($sel.Count -eq 0) { [System.Windows.MessageBox]::Show('No checks selected') ; return }
    Run-SelectedChecks -functions $sel
})

$btnRunAll.Add_Click({
    $policy = Get-Content $policyFile -Raw | ConvertFrom-Json
    $all = $policy.checks | ForEach-Object { $_.function }
    Run-SelectedChecks -functions $all
})

$window.ShowDialog() | Out-Null
