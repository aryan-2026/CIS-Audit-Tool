# Requires Pester 5.x
Describe 'CISChecks module' {
    BeforeAll { Import-Module (Join-Path $PSScriptRoot '..\modules\CISChecks.psm1') -Force }

    It 'Test-CIS_Win_1_2_1 returns structured object' {
        Mock -CommandName Get-NetFirewallProfile -MockWith { @{ Enabled = $true; DefaultInboundAction = 'Block' } }
        $res = Test-CIS_Win_1_2_1
        $res | Should -BeOfType 'System.Management.Automation.PSCustomObject'
        $res.Status | Should -Be 'Pass'
    }
}
