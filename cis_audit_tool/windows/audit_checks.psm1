# # modules/CISChecks.psm1
# function Test-WindowsFirewallEnabled {
#     <#
    #   .SYNOPSIS
#         Checks if Windows Firewall is enabled for all profiles
#     #>
#     $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled
#     $nonCompliant = $profiles | Where-Object { $_.Enabled -eq $false }
#     if ($nonCompliant) {
#         return @{
#             Status   = "Fail"
#             Actual   = ($nonCompliant | Out-String)
#             Remediate= "Enable Windows Firewall for all profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
#         }
#     }
#     else {
#         return @{
#             Status   = "Pass"
#             Actual   = "All firewall profiles enabled"
#             Remediate= "No action required"
#         }
#     }
# }

# function Test-GuestAccountDisabled {
#     $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
#     if ($guest -and $guest.Enabled) {
#         return @{
#             Status   = "Fail"
#             Actual   = "Guest account is enabled"
#             Remediate= "Disable guest account: Disable-LocalUser -Name Guest"
#         }
#     }
#     else {
#         return @{
#             Status   = "Pass"
#             Actual   = "Guest account disabled"
#             Remediate= "No action required"
#         }
#     }
# }

# function Test-PasswordHistorySize {
#     $value = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")["PasswordHistorySize"]
#     if ($value -lt 24) {
#         return @{
#             Status   = "Fail"
#             Actual   = "PasswordHistorySize = $value"
#             Remediate= "Set password history size >= 24 via GPO or registry"
#         }
#     }
#     else {
#         return @{
#             Status   = "Pass"
#             Actual   = "PasswordHistorySize = $value"
#             Remediate= "No action required"
#         }
#     }
# }

# function Test-CIS_1_1_2 {
#     $control = "CIS_Win_1.1.2"
#     $title = "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
#     $expected = "365 or fewer days, but not 0"
    
#     # Check the maximum password age policy
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MaxPasswordAge")
#     if ($policy.MaxPasswordAge -le 365 -and $policy.MaxPasswordAge -gt 0) {
#         $status = "Pass"
#         $actual = "Maximum password age = $($policy.MaxPasswordAge) days"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Maximum password age = $($policy.MaxPasswordAge) days"
#         $remediation = "Set maximum password age <= 365 and > 0 via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


# Export-ModuleMember -Function Test-*


# CISChecks.psm1
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

# Example: Ensure 'Enforce password history' is set to '24 or more password(s)'
# function Test-CIS_1_1_1 {
#     $control = 'CIS_Win_1.1.1'
#     $title = "Ensure 'Enforce password history' is set to '24 or more password(s)'"
#     $expected = "24 or more password(s)"

#     # Check password history size from registry
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordHistorySize")
#     if ($policy.PasswordHistorySize -ge 24) {
#         $status = 'Pass'
#         $actual = "Password history size = $($policy.PasswordHistorySize)"
#         $remediation = 'No action required'
#     }
#     else {
#         $status = 'Fail'
#         $actual = "Password history size = $($policy.PasswordHistorySize)"
#         $remediation = 'Set password history size >= 24 via GPO or registry'
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

# function Test-CIS_1_1_1 {
#     $control = 'CIS_Win_1.1.1'
#     $title = "Ensure 'Enforce password history' is set to '24 or more password(s)'"
#     $expected = "24 or more password(s)"

#     try {
#         $policy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordHistorySize" -ErrorAction Stop
#         $value = $policy.PasswordHistorySize
#     } catch {
#         $value = $null
#     }

#     if ($null -ne $value -and $value -ge 24) {
#         $status = 'Pass'
#         $actual = "Password history size = $value"
#         $remediation = 'No action required'
#     }
#     else {
#         $status = 'Fail'
#         $actual = if ($null -eq $value) {
#             "Password history size not set"
#         } else {
#             "Password history size = $value"
#         }
#         $remediation = 'Set password history size >= 24 via GPO or registry'
#     }

#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


function Test-CIS_1_1_1 {
    $control = 'CIS_Win_1.1.1'
    $title = "Ensure 'Enforce password history' is set to '24 or more password(s)'"
    $expected = "24 or more password(s)"

    # Export local security policy to temp file
    $cfg = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $cfg | Out-Null
    $secpol = Get-Content $cfg
    Remove-Item $cfg -Force

    $historyLine = $secpol | Where-Object { $_ -match "^PasswordHistorySize\s*=" }
    $value = ($historyLine -split "=")[1].Trim()

    if ([int]$value -ge 24) {
        $status = 'Pass'
        $actual = "Password history size = $value"
        $remediation = 'No action required'
    }
    else {
        $status = 'Fail'
        $actual = "Password history size = $value"
        $remediation = 'Set password history size >= 24 via GPO or Local Security Policy'
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# Example: Ensure Windows Firewall is enabled for all profiles

# function Test-CIS_1_1_2 {
#     $control = "CIS_Win_1.1.2"
#     $title = "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
#     $expected = "365 or fewer days, but not 0"
    
#     # Check the maximum password age policy
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MaxPasswordAge")
#     if ($policy.MaxPasswordAge -le 365 -and $policy.MaxPasswordAge -gt 0) {
#         $status = "Pass"
#         $actual = "Maximum password age = $($policy.MaxPasswordAge) days"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Maximum password age = $($policy.MaxPasswordAge) days"
#         $remediation = "Set maximum password age <= 365 and > 0 via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


# function Test-CIS_1_1_3 {
#     $control = "CIS_Win_1.1.3"
#     $title = "Ensure 'Minimum password age' is set to '1 or more day(s)'"
#     $expected = "1 or more day(s)"
    
#     # Check the minimum password age policy
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MinPasswordAge")
#     if ($policy.MinPasswordAge -ge 1) {
#         $status = "Pass"
#         $actual = "Minimum password age = $($policy.MinPasswordAge) day(s)"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Minimum password age = $($policy.MinPasswordAge) day(s)"
#         $remediation = "Set minimum password age >= 1 day via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


# function Test-CIS_1_1_4 {
#     $control = "CIS_Win_1.1.4"
#     $title = "Ensure 'Minimum password length' is set to '14 or more character(s)'"
#     $expected = "14 or more character(s)"
    
#     # Check the minimum password length policy
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "MinimumPasswordLength")
#     if ($policy.MinimumPasswordLength -ge 14) {
#         $status = "Pass"
#         $actual = "Minimum password length = $($policy.MinimumPasswordLength) character(s)"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Minimum password length = $($policy.MinimumPasswordLength) character(s)"
#         $remediation = "Set minimum password length >= 14 characters via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_1_1_2 {
    $control = "CIS_Win_1.1.2"
    $title = "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
    $expected = "365 or fewer days, but not 0"

    # Export local security policy
    $cfg = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $cfg | Out-Null
    $secpol = Get-Content $cfg
    Remove-Item $cfg -Force

    $line = $secpol | Where-Object { $_ -match "^MaximumPasswordAge\s*=" }
    $value = ($line -split "=")[1].Trim()

    if ([int]$value -le 365 -and [int]$value -gt 0) {
        $status = "Pass"
        $actual = "Maximum password age = $value days"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = if ($value) { "Maximum password age = $value days" } else { "Maximum password age not set" }
        $remediation = "Set maximum password age <= 365 and > 0 via GPO or Local Security Policy"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_1_1_3 {
    $control = "CIS_Win_1.1.3"
    $title = "Ensure 'Minimum password age' is set to '1 or more day(s)'"
    $expected = "1 or more day(s)"

    # Export local security policy
    $cfg = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $cfg | Out-Null
    $secpol = Get-Content $cfg
    Remove-Item $cfg -Force

    $line = $secpol | Where-Object { $_ -match "^MinimumPasswordAge\s*=" }
    $value = ($line -split "=")[1].Trim()

    if ([int]$value -ge 1) {
        $status = "Pass"
        $actual = "Minimum password age = $value day(s)"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = if ($value) { "Minimum password age = $value day(s)" } else { "Minimum password age not set" }
        $remediation = "Set minimum password age >= 1 day via GPO or Local Security Policy"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_1_1_4 {
    $control = "CIS_Win_1.1.4"
    $title = "Ensure 'Minimum password length' is set to '14 or more character(s)'"
    $expected = "14 or more character(s)"

    # Export local security policy
    $cfg = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $cfg | Out-Null
    $secpol = Get-Content $cfg
    Remove-Item $cfg -Force

    $line = $secpol | Where-Object { $_ -match "^MinimumPasswordLength\s*=" }
    $value = ($line -split "=")[1].Trim()

    if ([int]$value -ge 14) {
        $status = "Pass"
        $actual = "Minimum password length = $value character(s)"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = if ($value) { "Minimum password length = $value character(s)" } else { "Minimum password length not set" }
        $remediation = "Set minimum password length >= 14 characters via GPO or Local Security Policy"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_1_1_5 {
    $control = "CIS_Win_1.1.5"
    $title = "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the password complexity policy
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity")
    if ($policy.PasswordComplexity -eq 1) {
        $status = "Pass"
        $actual = "Password complexity is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Password complexity is disabled"
        $remediation = "Enable password complexity via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_1_1_6 {
    $control = "CIS_Win_1.1.6"
    $title = "Ensure 'Relax minimum password length limits' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the relax minimum password length policy
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RelaxMinimumPasswordLengthLimits")
    if ($policy.RelaxMinimumPasswordLengthLimits -eq 1) {
        $status = "Pass"
        $actual = "Relax minimum password length limits is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Relax minimum password length limits is disabled"
        $remediation = "Enable relax minimum password length limits via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_1_1_7 {
    $control = "CIS_Win_1.1.7"
    $title = "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check reversible encryption setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisablePasswordReversibleEncryption")
    if ($policy.DisablePasswordReversibleEncryption -eq 1) {
        $status = "Pass"
        $actual = "Reversible encryption is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Reversible encryption is enabled"
        $remediation = "Disable reversible encryption via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# function Test-CIS_1_2_1 {
#     $control = "CIS_Win_1.2.1"
#     $title = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
#     $expected = "15 or more minute(s)"
    
#     # Check the account lockout duration
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutDuration")
#     if ($policy.LockoutDuration -ge 15) {
#         $status = "Pass"
#         $actual = "Account lockout duration = $($policy.LockoutDuration) minute(s)"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Account lockout duration = $($policy.LockoutDuration) minute(s)"
#         $remediation = "Set account lockout duration >= 15 minutes via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_1_2_1 {
    $control = "CIS_Win_1.2.1"
    $title = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
    $expected = "15 or more minute(s)"

    try {
        # Export local security policy
        $cfgPath = "$env:TEMP\secpol.cfg"
        secedit /export /cfg $cfgPath | Out-Null

        # Read LockoutDuration value
        $line = Select-String "LockoutDuration" $cfgPath
        $value = ($line -split "=")[1].Trim()
        Remove-Item $cfgPath -Force

        if ([int]$value -ge 15) {
            $status = "Pass"
            $actual = "Account lockout duration = $value minute(s)"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "Account lockout duration = $value minute(s)"
            $remediation = "Set account lockout duration >= 15 minutes via Local Security Policy (secpol.msc) or GPO"
        }
    }
    catch {
        $status = "Error"
        $actual = "Could not read account lockout duration: $($_.Exception.Message)"
        $remediation = "Ensure secedit is available and accessible"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# function Test-CIS_1_2_2 {
#     $control = "CIS_Win_1.2.2"
#     $title = "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'"
#     $expected = "5 or fewer invalid logon attempt(s), but not 0"
    
#     # Check the account lockout threshold
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutBadCount")
#     if ($policy.LockoutBadCount -le 5 -and $policy.LockoutBadCount -gt 0) {
#         $status = "Pass"
#         $actual = "Account lockout threshold = $($policy.LockoutBadCount) invalid attempts"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Account lockout threshold = $($policy.LockoutBadCount) invalid attempts"
#         $remediation = "Set account lockout threshold <= 5 and > 0 via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


function Test-CIS_1_2_2 {
    $control = "CIS_Win_1.2.2"
    $title = "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'"
    $expected = "5 or fewer invalid logon attempt(s), but not 0"

    try {
        # Export local security policy to a temp file
        $cfgPath = "$env:TEMP\secpol.cfg"
        secedit /export /cfg $cfgPath | Out-Null

        # Get LockoutBadCount line
        $line = Select-String -Path $cfgPath -Pattern "LockoutBadCount" | ForEach-Object { $_.ToString() }
        $value = ($line -split "=")[1].Trim()

        Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue

        if ([string]::IsNullOrWhiteSpace($value)) {
            # Not configured
            $status = "Error"
            $actual = "Account lockout threshold is Not Configured"
            $remediation = "Configure account lockout threshold (<= 5 and > 0) via Local Security Policy (secpol.msc) or GPO"
        }
        elseif ([int]::TryParse($value, [ref]$null)) {
            $valInt = [int]$value
            if ($valInt -le 5 -and $valInt -gt 0) {
                $status = "Pass"
                $actual = "Account lockout threshold = $valInt invalid attempts"
                $remediation = "No action required"
            }
            else {
                $status = "Fail"
                $actual = "Account lockout threshold = $valInt invalid attempts"
                $remediation = "Set account lockout threshold <= 5 and > 0 via Local Security Policy (secpol.msc) or GPO"
            }
        }
        else {
            $status = "Error"
            $actual = "Unexpected LockoutBadCount value: '$value'"
            $remediation = "Verify secedit export output"
        }
    }
    catch {
        $status = "Error"
        $actual = "Could not read account lockout threshold: $($_.Exception.Message)"
        $remediation = "Ensure secedit is available and accessible"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_1_2_3 {
    $control = "CIS_Win_1.2.3"
    $title = "Ensure 'Allow Administrator account lockout' is set to 'Enabled'"
    $expected = "Enabled"
    
    # This is a manual check, so the script will note it for the user
    $status = "Manual Check"
    $actual = "Allow Administrator account lockout must be manually checked"
    $remediation = "Ensure that the Administrator account lockout setting is enabled via Group Policy"
    
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# function Test-CIS_1_2_4 {
#     $control = "CIS_Win_1.2.4"
#     $title = "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
#     $expected = "15 or more minute(s)"
    
#     # Check the account lockout counter reset
#     $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "ResetLockoutCount")
#     if ($policy.ResetLockoutCount -ge 15) {
#         $status = "Pass"
#         $actual = "Account lockout counter reset = $($policy.ResetLockoutCount) minute(s)"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Account lockout counter reset = $($policy.ResetLockoutCount) minute(s)"
#         $remediation = "Set lockout counter reset >= 15 minutes via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_1_2_4 {
    $control = "CIS_Win_1.2.4"
    $title = "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
    $expected = "15 or more minute(s)"

    # Export local security policy
    $cfg = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $cfg | Out-Null
    $secpol = Get-Content $cfg
    Remove-Item $cfg -Force

    # Find ResetLockoutCount value
    $line = $secpol | Where-Object { $_ -match "^ResetLockoutCount\s*=" }
    $value = ($line -split "=")[1].Trim()

    if ([int]$value -ge 15) {
        $status = "Pass"
        $actual = "Account lockout counter reset = $value minute(s)"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = if ($value) { "Account lockout counter reset = $value minute(s)" } else { "Account lockout counter reset not set" }
        $remediation = "Set lockout counter reset >= 15 minutes via GPO or Local Security Policy"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_1 {
    $control = "CIS_Win_2.2.1"
    $title = "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
    $expected = "No One"
    
    # Check the Credential Manager setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CredentialManager")
    if ($policy.CredentialManager -eq 0) {
        $status = "Pass"
        $actual = "Credential Manager access is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Credential Manager access is allowed"
        $remediation = "Restrict Credential Manager access via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_2 {
    $control = "CIS_Win_2.2.2"
    $title = "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
    $expected = "Administrators, Remote Desktop Users"
    
    # Check the network access group setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NetworkAccess")
    $allowedGroups = $policy.NetworkAccess.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "Remote Desktop Users") {
        $status = "Pass"
        $actual = "Access from network is allowed for Administrators and Remote Desktop Users"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Access from network is not configured as expected"
        $remediation = "Add 'Administrators, Remote Desktop Users' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_3 {
    $control = "CIS_Win_2.2.3"
    $title = "Ensure 'Act as part of the operating system' is set to 'No One'"
    $expected = "No One"
    
    # Check the 'Act as part of the operating system' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ActAsPartOfOS")
    if ($policy.ActAsPartOfOS -eq 0) {
        $status = "Pass"
        $actual = "'Act as part of the operating system' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Act as part of the operating system' is not restricted"
        $remediation = "Restrict the 'Act as part of the operating system' permission via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_4 {
    $control = "CIS_Win_2.2.4"
    $title = "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
    $expected = "Administrators, LOCAL SERVICE, NETWORK SERVICE"
    
    # Check the 'Adjust memory quotas for a process' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AdjustMemoryQuotas")
    $allowedGroups = $policy.AdjustMemoryQuotas.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "LOCAL SERVICE" -and $allowedGroups -contains "NETWORK SERVICE") {
        $status = "Pass"
        $actual = "'Adjust memory quotas for a process' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Adjust memory quotas for a process' is not configured correctly"
        $remediation = "Set correct permissions via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_5 {
    $control = "CIS_Win_2.2.5"
    $title = "Ensure 'Allow log on locally' is set to 'Administrators, Users'"
    $expected = "Administrators, Users"
    
    # Check the local login permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AllowLogonLocally")
    $allowedGroups = $policy.AllowLogonLocally.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "Users") {
        $status = "Pass"
        $actual = "'Allow log on locally' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Allow log on locally' is not configured correctly"
        $remediation = "Add 'Administrators, Users' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_6 {
    $control = "CIS_Win_2.2.6"
    $title = "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
    $expected = "Administrators, Remote Desktop Users"
    
    # Check the Remote Desktop login permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AllowRemoteDesktopLogon")
    $allowedGroups = $policy.AllowRemoteDesktopLogon.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "Remote Desktop Users") {
        $status = "Pass"
        $actual = "'Allow log on through Remote Desktop Services' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Allow log on through Remote Desktop Services' is not configured correctly"
        $remediation = "Add 'Administrators, Remote Desktop Users' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_7 {
    $control = "CIS_Win_2.2.7"
    $title = "Ensure 'Back up files and directories' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the backup files and directories permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "BackUpFilesAndDirs")
    $allowedGroups = $policy.BackUpFilesAndDirs.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Back up files and directories' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Back up files and directories' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_8 {
    $control = "CIS_Win_2.2.8"
    $title = "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
    $expected = "Administrators, LOCAL SERVICE"
    
    # Check the system time change permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ChangeSystemTime")
    $allowedGroups = $policy.ChangeSystemTime.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "LOCAL SERVICE") {
        $status = "Pass"
        $actual = "'Change the system time' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Change the system time' is not configured correctly"
        $remediation = "Add 'Administrators, LOCAL SERVICE' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_9 {
    $control = "CIS_Win_2.2.9"
    $title = "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'"
    $expected = "Administrators, LOCAL SERVICE, Users"
    
    # Check the system time zone change permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ChangeTimeZone")
    $allowedGroups = $policy.ChangeTimeZone.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "LOCAL SERVICE" -and $allowedGroups -contains "Users") {
        $status = "Pass"
        $actual = "'Change the time zone' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Change the time zone' is not configured correctly"
        $remediation = "Add 'Administrators, LOCAL SERVICE, Users' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_10 {
    $control = "CIS_Win_2.2.10"
    $title = "Ensure 'Create a pagefile' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the pagefile creation permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CreatePagefile")
    $allowedGroups = $policy.CreatePagefile.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Create a pagefile' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Create a pagefile' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_11 {
    $control = "CIS_Win_2.2.11"
    $title = "Ensure 'Create a token object' is set to 'No One'"
    $expected = "No One"
    
    # Check the token creation permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CreateTokenObject")
    if ($policy.CreateTokenObject -eq 0) {
        $status = "Pass"
        $actual = "'Create a token object' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Create a token object' is allowed"
        $remediation = "Restrict 'Create a token object' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_12 {
    $control = "CIS_Win_2.2.12"
    $title = "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    $expected = "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"
    
    # Check the 'Create global objects' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CreateGlobalObjects")
    $allowedGroups = $policy.CreateGlobalObjects.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "LOCAL SERVICE" -and $allowedGroups -contains "NETWORK SERVICE" -and $allowedGroups -contains "SERVICE") {
        $status = "Pass"
        $actual = "'Create global objects' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Create global objects' is not configured correctly"
        $remediation = "Add 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_13 {
    $control = "CIS_Win_2.2.13"
    $title = "Ensure 'Create permanent shared objects' is set to 'No One'"
    $expected = "No One"
    
    # Check the permanent shared objects creation permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CreatePermanentSharedObjects")
    if ($policy.CreatePermanentSharedObjects -eq 0) {
        $status = "Pass"
        $actual = "'Create permanent shared objects' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Create permanent shared objects' is allowed"
        $remediation = "Restrict 'Create permanent shared objects' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_14 {
    $control = "CIS_Win_2.2.14"
    $title = "Configure 'Create symbolic links'"
    $expected = "Configured"
    
    # Check the 'Create symbolic links' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CreateSymbolicLinks")
    if ($policy.CreateSymbolicLinks -eq 0) {
        $status = "Pass"
        $actual = "'Create symbolic links' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Create symbolic links' is allowed"
        $remediation = "Restrict 'Create symbolic links' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_15 {
    $control = "CIS_Win_2.2.15"
    $title = "Ensure 'Debug programs' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the debug programs permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DebugPrograms")
    $allowedGroups = $policy.DebugPrograms.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Debug programs' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Debug programs' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_16 {
    $control = "CIS_Win_2.2.16"
    $title = "Ensure 'Deny access to this computer from the network' to include 'Guests'"
    $expected = "Guests"
    
    # Check the deny access to network setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DenyNetworkAccess")
    $deniedGroups = $policy.DenyNetworkAccess.Split(',')
    
    if ($deniedGroups -contains "Guests") {
        $status = "Pass"
        $actual = "'Deny access to this computer from the network' includes 'Guests'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Deny access to this computer from the network' does not include 'Guests'"
        $remediation = "Add 'Guests' to the denied groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_17 {
    $control = "CIS_Win_2.2.17"
    $title = "Ensure 'Deny log on as a batch job' to include 'Guests'"
    $expected = "Guests"
    
    # Check the deny logon as a batch job setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DenyBatchLogon")
    $deniedGroups = $policy.DenyBatchLogon.Split(',')
    
    if ($deniedGroups -contains "Guests") {
        $status = "Pass"
        $actual = "'Deny log on as a batch job' includes 'Guests'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Deny log on as a batch job' does not include 'Guests'"
        $remediation = "Add 'Guests' to the denied groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_18 {
    $control = "CIS_Win_2.2.18"
    $title = "Ensure 'Deny log on as a service' to include 'Guests'"
    $expected = "Guests"
    
    # Check the deny logon as a service setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DenyServiceLogon")
    $deniedGroups = $policy.DenyServiceLogon.Split(',')
    
    if ($deniedGroups -contains "Guests") {
        $status = "Pass"
        $actual = "'Deny log on as a service' includes 'Guests'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Deny log on as a service' does not include 'Guests'"
        $remediation = "Add 'Guests' to the denied groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_19 {
    $control = "CIS_Win_2.2.19"
    $title = "Ensure 'Deny log on locally' to include 'Guests'"
    $expected = "Guests"
    
    # Check the deny logon locally setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DenyLocalLogon")
    $deniedGroups = $policy.DenyLocalLogon.Split(',')
    
    if ($deniedGroups -contains "Guests") {
        $status = "Pass"
        $actual = "'Deny log on locally' includes 'Guests'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Deny log on locally' does not include 'Guests'"
        $remediation = "Add 'Guests' to the denied groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_20 {
    $control = "CIS_Win_2.2.20"
    $title = "Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'"
    $expected = "Guests"
    
    # Check the deny Remote Desktop logon setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DenyRemoteDesktopLogon")
    $deniedGroups = $policy.DenyRemoteDesktopLogon.Split(',')
    
    if ($deniedGroups -contains "Guests") {
        $status = "Pass"
        $actual = "'Deny log on through Remote Desktop Services' includes 'Guests'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Deny log on through Remote Desktop Services' does not include 'Guests'"
        $remediation = "Add 'Guests' to the denied groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_21 {
    $control = "CIS_Win_2.2.21"
    $title = "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
    $expected = "No One"
    
    # Check the trusted for delegation setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EnableDelegation")
    if ($policy.EnableDelegation -eq 0) {
        $status = "Pass"
        $actual = "'Enable computer and user accounts to be trusted for delegation' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Enable computer and user accounts to be trusted for delegation' is enabled"
        $remediation = "Disable the delegation trust setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_22 {
    $control = "CIS_Win_2.2.22"
    $title = "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Force shutdown from a remote system' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceShutdownFromRemoteSystem")
    $allowedGroups = $policy.ForceShutdownFromRemoteSystem.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Force shutdown from a remote system' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Force shutdown from a remote system' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_23 {
    $control = "CIS_Win_2.2.23"
    $title = "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    $expected = "LOCAL SERVICE, NETWORK SERVICE"
    
    # Check the 'Generate security audits' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "GenerateSecurityAudits")
    $allowedGroups = $policy.GenerateSecurityAudits.Split(',')
    
    if ($allowedGroups -contains "LOCAL SERVICE" -and $allowedGroups -contains "NETWORK SERVICE") {
        $status = "Pass"
        $actual = "'Generate security audits' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Generate security audits' is not configured correctly"
        $remediation = "Add 'LOCAL SERVICE, NETWORK SERVICE' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_24 {
    $control = "CIS_Win_2.2.24"
    $title = "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    $expected = "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"
    
    # Check the 'Impersonate a client after authentication' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ImpersonateClientAfterAuthentication")
    $allowedGroups = $policy.ImpersonateClientAfterAuthentication.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "LOCAL SERVICE" -and $allowedGroups -contains "NETWORK SERVICE" -and $allowedGroups -contains "SERVICE") {
        $status = "Pass"
        $actual = "'Impersonate a client after authentication' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Impersonate a client after authentication' is not configured correctly"
        $remediation = "Add 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_2_2_25 {
    $control = "CIS_Win_2.2.25"
    $title = "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
    $expected = "Administrators, Window Manager\Window Manager Group"
    
    # Check the 'Increase scheduling priority' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "IncreaseSchedulingPriority")
    $allowedGroups = $policy.IncreaseSchedulingPriority.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "Window Manager\\Window Manager Group") {
        $status = "Pass"
        $actual = "'Increase scheduling priority' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Increase scheduling priority' is not configured correctly"
        $remediation = "Add 'Administrators, Window Manager\\Window Manager Group' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_26 {
    $control = "CIS_Win_2.2.26"
    $title = "Ensure 'Load and unload device drivers' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Load and unload device drivers' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LoadUnloadDeviceDrivers")
    $allowedGroups = $policy.LoadUnloadDeviceDrivers.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Load and unload device drivers' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Load and unload device drivers' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_27 {
    $control = "CIS_Win_2.2.27"
    $title = "Ensure 'Lock pages in memory' is set to 'No One'"
    $expected = "No One"
    
    # Check the 'Lock pages in memory' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LockPagesInMemory")
    if ($policy.LockPagesInMemory -eq 0) {
        $status = "Pass"
        $actual = "'Lock pages in memory' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Lock pages in memory' is allowed"
        $remediation = "Restrict 'Lock pages in memory' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_30 {
    $control = "CIS_Win_2.2.30"
    $title = "Ensure 'Manage auditing and security log' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Manage auditing and security log' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ManageAuditSecurityLog")
    $allowedGroups = $policy.ManageAuditSecurityLog.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Manage auditing and security log' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Manage auditing and security log' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_31 {
    $control = "CIS_Win_2.2.31"
    $title = "Ensure 'Modify an object label' is set to 'No One'"
    $expected = "No One"
    
    # Check the 'Modify an object label' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ModifyObjectLabel")
    if ($policy.ModifyObjectLabel -eq 0) {
        $status = "Pass"
        $actual = "'Modify an object label' is restricted"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Modify an object label' is allowed"
        $remediation = "Restrict 'Modify an object label' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_32 {
    $control = "CIS_Win_2.2.32"
    $title = "Ensure 'Modify firmware environment values' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Modify firmware environment values' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ModifyFirmwareEnvironmentValues")
    $allowedGroups = $policy.ModifyFirmwareEnvironmentValues.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Modify firmware environment values' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Modify firmware environment values' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_33 {
    $control = "CIS_Win_2.2.33"
    $title = "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Perform volume maintenance tasks' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PerformVolumeMaintenanceTasks")
    $allowedGroups = $policy.PerformVolumeMaintenanceTasks.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Perform volume maintenance tasks' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Perform volume maintenance tasks' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_34 {
    $control = "CIS_Win_2.2.34"
    $title = "Ensure 'Profile single process' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Profile single process' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ProfileSingleProcess")
    $allowedGroups = $policy.ProfileSingleProcess.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Profile single process' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Profile single process' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_35 {
    $control = "CIS_Win_2.2.35"
    $title = "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
    $expected = "Administrators, NT SERVICE\WdiServiceHost"
    
    # Check the 'Profile system performance' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ProfileSystemPerformance")
    $allowedGroups = $policy.ProfileSystemPerformance.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "NT SERVICE\\WdiServiceHost") {
        $status = "Pass"
        $actual = "'Profile system performance' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Profile system performance' is not configured correctly"
        $remediation = "Add 'Administrators, NT SERVICE\\WdiServiceHost' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_36 {
    $control = "CIS_Win_2.2.36"
    $title = "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    $expected = "LOCAL SERVICE, NETWORK SERVICE"
    
    # Check the 'Replace a process level token' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ReplaceProcessLevelToken")
    $allowedGroups = $policy.ReplaceProcessLevelToken.Split(',')
    
    if ($allowedGroups -contains "LOCAL SERVICE" -and $allowedGroups -contains "NETWORK SERVICE") {
        $status = "Pass"
        $actual = "'Replace a process level token' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Replace a process level token' is not configured correctly"
        $remediation = "Add 'LOCAL SERVICE, NETWORK SERVICE' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_37 {
    $control = "CIS_Win_2.2.37"
    $title = "Ensure 'Restore files and directories' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Restore files and directories' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestoreFilesAndDirectories")
    $allowedGroups = $policy.RestoreFilesAndDirectories.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Restore files and directories' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Restore files and directories' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_2_38 {
    $control = "CIS_Win_2.2.38"
    $title = "Ensure 'Shut down the system' is set to 'Administrators, Users'"
    $expected = "Administrators, Users"
    
    # Check the 'Shut down the system' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ShutDownSystem")
    $allowedGroups = $policy.ShutDownSystem.Split(',')
    
    if ($allowedGroups -contains "Administrators" -and $allowedGroups -contains "Users") {
        $status = "Pass"
        $actual = "'Shut down the system' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Shut down the system' is not configured correctly"
        $remediation = "Add 'Administrators, Users' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_2_39 {
    $control = "CIS_Win_2.2.39"
    $title = "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
    $expected = "Administrators"
    
    # Check the 'Take ownership of files or other objects' permission
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TakeOwnershipFiles")
    $allowedGroups = $policy.TakeOwnershipFiles.Split(',')
    
    if ($allowedGroups -contains "Administrators") {
        $status = "Pass"
        $actual = "'Take ownership of files or other objects' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Take ownership of files or other objects' is not configured correctly"
        $remediation = "Add 'Administrators' to allowed groups via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_2_3_1_1 {
    $control = "CIS_Win_2.3.1.1"
    $title = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
    $expected = "Users can't add or log on with Microsoft accounts"
    
    # Check the 'Block Microsoft accounts' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Accounts" -Name "NoConnectedUser")
    if ($policy.NoConnectedUser -eq 1) {
        $status = "Pass"
        $actual = "'Block Microsoft accounts' is configured as expected"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Block Microsoft accounts' is not configured correctly"
        $remediation = "Set 'Accounts: Block Microsoft accounts' to 'Users can't add or log on with Microsoft accounts' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_1_2 {
    $control = "CIS_Win_2.3.1.2"
    $title = "Ensure 'Accounts: Guest account status' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the Guest account status
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Accounts" -Name "GuestAccountStatus")
    if ($policy.GuestAccountStatus -eq 0) {
        $status = "Pass"
        $actual = "'Guest account status' is set to 'Disabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Guest account status' is enabled"
        $remediation = "Disable the guest account via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_1_3 {
    $control = "CIS_Win_2.3.1.3"
    $title = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Limit local account use of blank passwords' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Accounts" -Name "LimitBlankPasswordUse")
    if ($policy.LimitBlankPasswordUse -eq 1) {
        $status = "Pass"
        $actual = "'Limit local account use of blank passwords to console logon only' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Limit local account use of blank passwords' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_1_4 {
    $control = "CIS_Win_2.3.1.4"
    $title = "Configure 'Accounts: Rename administrator account'"
    $expected = "Renamed"
    
    # Check the 'Rename administrator account' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name "Administrator")
    if ($policy.Administrator -ne "Administrator") {
        $status = "Pass"
        $actual = "'Administrator' account has been renamed"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Administrator' account is still named 'Administrator'"
        $remediation = "Rename the 'Administrator' account to a non-default name"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_1_5 {
    $control = "CIS_Win_2.3.1.5"
    $title = "Configure 'Accounts: Rename guest account'"
    $expected = "Renamed"
    
    # Check the 'Rename guest account' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name "Guest")
    if ($policy.Guest -ne "Guest") {
        $status = "Pass"
        $actual = "'Guest' account has been renamed"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Guest' account is still named 'Guest'"
        $remediation = "Rename the 'Guest' account to a non-default name"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_2_1 {
    $control = "CIS_Win_2.3.2.1"
    $title = "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Force audit policy subcategory settings' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Audit" -Name "AuditSubcategoryOverride")
    if ($policy.AuditSubcategoryOverride -eq 1) {
        $status = "Pass"
        $actual = "'Force audit policy subcategory settings' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Force audit policy subcategory settings' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_2_2 {
    $control = "CIS_Win_2.3.2.2"
    $title = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Shut down system immediately if unable to log security audits' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Audit" -Name "ShutdownOnAuditFailure")
    if ($policy.ShutdownOnAuditFailure -eq 0) {
        $status = "Pass"
        $actual = "'Shut down system immediately if unable to log security audits' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Shut down system immediately if unable to log security audits' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_7_1 {
    $control = "CIS_Win_2.3.7.1"
    $title = "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Do not require CTRL+ALT+DEL' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD")
    if ($policy.DisableCAD -eq 0) {
        $status = "Pass"
        $actual = "'Do not require CTRL+ALT+DEL' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Do not require CTRL+ALT+DEL' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_7_2 {
    $control = "CIS_Win_2.3.7.2"
    $title = "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Don't display last signed-in' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName")
    if ($policy.DontDisplayLastUserName -eq 1) {
        $status = "Pass"
        $actual = "'Don't display last signed-in' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Don't display last signed-in' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



# function Test-CIS_2_3_7_4 {
#     $control = "CIS_Win_2.3.7.4"
#     $title = "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
#     $expected = "900 or fewer second(s), but not 0"
    
#     # Check the 'Machine inactivity limit' setting
#     $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs")
#     if ($policy.InactivityTimeoutSecs -le 900 -and $policy.InactivityTimeoutSecs -gt 0) {
#         $status = "Pass"
#         $actual = "'Machine inactivity limit' is set to $($policy.InactivityTimeoutSecs) seconds"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Machine inactivity limit' is set to $($policy.InactivityTimeoutSecs) seconds"
#         $remediation = "Set the machine inactivity limit to 900 seconds via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_2_3_7_4 {
    $control = "CIS_Win_2.3.7.4"
    $title = "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
    $expected = "900 or fewer second(s), but not 0"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction Stop
        $value = $policy.InactivityTimeoutSecs
    } catch {
        $value = $null
    }

    if ($null -ne $value -and [int]$value -le 900 -and [int]$value -gt 0) {
        $status = "Pass"
        $actual = "'Machine inactivity limit' is set to $value seconds"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($null -eq $value) {
            "'Machine inactivity limit' is not set"
        } else {
            "'Machine inactivity limit' is set to $value seconds"
        }
        $remediation = "Set the machine inactivity limit to 900 seconds via GPO or registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_7_5 {
    $control = "CIS_Win_2.3.7.5"
    $title = "Configure 'Interactive logon: Message text for users attempting to log on'"
    $expected = "Configured"
    
    # Check the 'Message text for users attempting to log on'
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext")
    if ($policy.legalnoticetext) {
        $status = "Pass"
        $actual = "'Message text for users attempting to log on' is configured"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Message text for users attempting to log on' is not configured"
        $remediation = "Configure the message text via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_7_6 {
    $control = "CIS_Win_2.3.7.6"
    $title = "Configure 'Interactive logon: Message title for users attempting to log on'"
    $expected = "Configured"
    
    # Check the 'Message title for users attempting to log on'
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext")
    if ($policy.legalnoticetext) {
        $status = "Pass"
        $actual = "'Message title for users attempting to log on' is configured"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Message title for users attempting to log on' is not configured"
        $remediation = "Configure the message title via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# function Test-CIS_2_3_7_7 {
#     $control = "CIS_Win_2.3.7.7"
#     $title = "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
#     $expected = "between 5 and 14 days"
    
#     # Check the 'Prompt user to change password before expiration' setting
#     $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxPWAgeWarn")
#     if ($policy.MaxPWAgeWarn -ge 5 -and $policy.MaxPWAgeWarn -le 14) {
#         $status = "Pass"
#         $actual = "Password change reminder is set to $($policy.MaxPWAgeWarn) days"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "Password change reminder is set to $($policy.MaxPWAgeWarn) days"
#         $remediation = "Set the reminder to a value between 5 and 14 days via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


function Test-CIS_2_3_7_7 {
    $control = "CIS_Win_2.3.7.7"
    $title = "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
    $expected = "between 5 and 14 days"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxPWAgeWarn" -ErrorAction Stop
        $value = $policy.MaxPWAgeWarn
    } catch {
        $value = $null
    }

    if ($null -ne $value -and [int]$value -ge 5 -and [int]$value -le 14) {
        $status = "Pass"
        $actual = "Password change reminder is set to $value days"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($null -eq $value) {
            "Password change reminder is not set"
        } else {
            "Password change reminder is set to $value days"
        }
        $remediation = "Set the reminder to a value between 5 and 14 days via GPO or registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_3_7_8 {
    $control = "CIS_Win_2.3.7.8"
    $title = "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
    $expected = "Lock Workstation or higher"
    
    # Check the 'Smart card removal behavior' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ScRemoveOption")
    if ($policy.ScRemoveOption -ge 1) {
        $status = "Pass"
        $actual = "Smart card removal behavior is set to lock workstation"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Smart card removal behavior is not set to 'Lock Workstation'"
        $remediation = "Set the smart card removal behavior to 'Lock Workstation' or higher via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_2_3_8_1 {
    $control = "CIS_Win_2.3.8.1"
    $title = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Digitally sign communications (always)' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature")
    if ($policy.EnableSecuritySignature -eq 1) {
        $status = "Pass"
        $actual = "'Digitally sign communications (always)' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Digitally sign communications (always)' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_8_2 {
    $control = "CIS_Win_2.3.8.2"
    $title = "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Digitally sign communications (if server agrees)' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature")
    if ($policy.RequireSecuritySignature -eq 1) {
        $status = "Pass"
        $actual = "'Digitally sign communications (if server agrees)' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Digitally sign communications (if server agrees)' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_8_3 {
    $control = "CIS_Win_2.3.8.3"
    $title = "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Send unencrypted password to third-party SMB servers' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword")
    if ($policy.EnablePlainTextPassword -eq 0) {
        $status = "Pass"
        $actual = "'Send unencrypted password to third-party SMB servers' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Send unencrypted password to third-party SMB servers' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_9_1 {
    $control = "CIS_Win_2.3.9.1"
    $title = "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
    $expected = "15 or fewer minute(s)"
    
    # Check the 'Amount of idle time required before suspending session' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoDisconnect")
    if ($policy.AutoDisconnect -le 15) {
        $status = "Pass"
        $actual = "'Amount of idle time before suspending session' is set to $($policy.AutoDisconnect) minutes"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Amount of idle time before suspending session' is set to $($policy.AutoDisconnect) minutes"
        $remediation = "Set the idle time to 15 minutes or less via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_9_2 {
    $control = "CIS_Win_2.3.9.2"
    $title = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Digitally sign communications (always)' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature")
    if ($policy.EnableSecuritySignature -eq 1) {
        $status = "Pass"
        $actual = "'Digitally sign communications (always)' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Digitally sign communications (always)' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_9_3 {
    $control = "CIS_Win_2.3.9.3"
    $title = "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Digitally sign communications (if client agrees)' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature")
    if ($policy.RequireSecuritySignature -eq 1) {
        $status = "Pass"
        $actual = "'Digitally sign communications (if client agrees)' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Digitally sign communications (if client agrees)' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_9_4 {
    $control = "CIS_Win_2.3.9.4"
    $title = "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Disconnect clients when logon hours expire' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableStrictNameChecking")
    if ($policy.DisableStrictNameChecking -eq 1) {
        $status = "Pass"
        $actual = "'Disconnect clients when logon hours expire' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Disconnect clients when logon hours expire' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_9_5 {
    $control = "CIS_Win_2.3.9.5"
    $title = "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
    $expected = "Accept if provided by client or higher"
    
    # Check the 'Server SPN target name validation level' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableTargetNameValidation")
    if ($policy.EnableTargetNameValidation -ge 1) {
        $status = "Pass"
        $actual = "'Server SPN target name validation level' is configured correctly"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Server SPN target name validation level' is not configured correctly"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_1 {
    $control = "CIS_Win_2.3.10.1"
    $title = "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Allow anonymous SID/Name translation' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymousSAM")
    if ($policy.RestrictAnonymousSAM -eq 1) {
        $status = "Pass"
        $actual = "'Allow anonymous SID/Name translation' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Allow anonymous SID/Name translation' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_2 {
    $control = "CIS_Win_2.3.10.2"
    $title = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Do not allow anonymous enumeration of SAM accounts' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymous")
    if ($policy.RestrictAnonymous -eq 1) {
        $status = "Pass"
        $actual = "'Do not allow anonymous enumeration of SAM accounts' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Do not allow anonymous enumeration of SAM accounts' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_3 {
    $control = "CIS_Win_2.3.10_3"
    $title = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Do not allow anonymous enumeration of SAM accounts and shares' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymousShares")
    if ($policy.RestrictAnonymousShares -eq 1) {
        $status = "Pass"
        $actual = "'Do not allow anonymous enumeration of SAM accounts and shares' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Do not allow anonymous enumeration of SAM accounts and shares' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_4 {
    $control = "CIS_Win_2.3_10_4"
    $title = "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Do not allow storage of passwords and credentials for network authentication' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisablePasswordCaching")
    if ($policy.DisablePasswordCaching -eq 1) {
        $status = "Pass"
        $actual = "'Do not allow storage of passwords and credentials' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Do not allow storage of passwords and credentials' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_5 {
    $control = "CIS_Win_2.3_10_5"
    $title = "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Let Everyone permissions apply to anonymous users' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EveryoneIncludesAnonymous")
    if ($policy.EveryoneIncludesAnonymous -eq 0) {
        $status = "Pass"
        $actual = "'Let Everyone permissions apply to anonymous users' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Let Everyone permissions apply to anonymous users' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_6 {
    $control = "CIS_Win_2.3_10_6"
    $title = "Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'"
    $expected = "None"
    
    # Check the 'Named Pipes that can be accessed anonymously' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes")
    if (-not $policy.NullSessionPipes) {
        $status = "Pass"
        $actual = "'Named Pipes that can be accessed anonymously' is set to None"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Named Pipes that can be accessed anonymously' is not set to None"
        $remediation = "Set the Named Pipes that can be accessed anonymously to 'None' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_7 {
    $control = "CIS_Win_2.3_10_7"
    $title = "Ensure 'Network access: Remotely accessible registry paths' is configured"
    $expected = "Configured"
    
    # Check the 'Remotely accessible registry paths' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares")
    if ($policy.NullSessionShares) {
        $status = "Pass"
        $actual = "'Remotely accessible registry paths' is configured"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Remotely accessible registry paths' is not configured"
        $remediation = "Configure the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_3_10_8 {
    $control = "CIS_Win_2.3_10_8"
    $title = "Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured"
    $expected = "Configured"
    
    # Check the 'Remotely accessible registry paths and sub-paths' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares")
    if ($policy.NullSessionShares) {
        $status = "Pass"
        $actual = "'Remotely accessible registry paths and sub-paths' is configured"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Remotely accessible registry paths and sub-paths' is not configured"
        $remediation = "Configure the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_9 {
    $control = "CIS_Win_2.3_10_9"
    $title = "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Restrict anonymous access to Named Pipes and Shares' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictAnonymousShares")
    if ($policy.RestrictAnonymousShares -eq 1) {
        $status = "Pass"
        $actual = "'Restrict anonymous access to Named Pipes and Shares' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Restrict anonymous access to Named Pipes and Shares' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_10 {
    $control = "CIS_Win_2.3_10_10"
    $title = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    $expected = "Administrators: Remote Access: Allow"
    
    # Check the 'Restrict clients allowed to make remote calls to SAM' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AllowRemoteRPC")
    if ($policy.AllowRemoteRPC -eq 1) {
        $status = "Pass"
        $actual = "'Restrict clients allowed to make remote calls to SAM' is configured as 'Administrators: Remote Access: Allow'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Restrict clients allowed to make remote calls to SAM' is not configured properly"
        $remediation = "Configure the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_11 {
    $control = "CIS_Win_2.3_10_11"
    $title = "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
    $expected = "None"
    
    # Check the 'Shares that can be accessed anonymously' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares" -Name "NullSessionShares")
    if (-not $policy.NullSessionShares) {
        $status = "Pass"
        $actual = "'Shares that can be accessed anonymously' is set to None"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Shares that can be accessed anonymously' is not set to None"
        $remediation = "Set the shares that can be accessed anonymously to 'None' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_10_12 {
    $control = "CIS_Win_2.3_10_12"
    $title = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
    $expected = "Classic - local users authenticate as themselves"
    
    # Check the 'Sharing and security model for local accounts' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "LocalAccountTokenFilterPolicy")
    if ($policy.LocalAccountTokenFilterPolicy -eq 1) {
        $status = "Pass"
        $actual = "'Sharing and security model for local accounts' is set to 'Classic'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Sharing and security model for local accounts' is not set to 'Classic'"
        $remediation = "Set the model to 'Classic' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_2_3_11_1 {
    $control = "CIS_Win_2.3_11_1"
    $title = "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Allow Local System to use computer identity for NTLM' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "AllowLocalSystemToUseComputerIdentityForNTLM")
    if ($policy.AllowLocalSystemToUseComputerIdentityForNTLM -eq 1) {
        $status = "Pass"
        $actual = "'Network security: Allow Local System to use computer identity for NTLM' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Allow Local System to use computer identity for NTLM' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_2 {
    $control = "CIS_Win_2.3_11_2"
    $title = "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Allow LocalSystem NULL session fallback' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AllowNullSessionFallback")
    if ($policy.AllowNullSessionFallback -eq 0) {
        $status = "Pass"
        $actual = "'Network security: Allow LocalSystem NULL session fallback' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Allow LocalSystem NULL session fallback' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_3 {
    $control = "CIS_Win_2.3_11_3"
    $title = "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Allow PKU2U authentication requests' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\KDC" -Name "AllowPKU2UAuthentication")
    if ($policy.AllowPKU2UAuthentication -eq 0) {
        $status = "Pass"
        $actual = "'Network Security: Allow PKU2U authentication requests' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network Security: Allow PKU2U authentication requests' is enabled"
        $remediation = "Disable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_4 {
    $control = "CIS_Win_2.3_11_4"
    $title = "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
    $expected = "AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types"
    
    # Check the 'Configure encryption types allowed for Kerberos' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\KDC\Parameters" -Name "SupportedEncryptionTypes")
    if ($policy.SupportedEncryptionTypes -eq 0x18) {
        $status = "Pass"
        $actual = "'Network security: Configure encryption types allowed for Kerberos' is set correctly"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Configure encryption types allowed for Kerberos' is not set correctly"
        $remediation = "Configure the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_5 {
    $control = "CIS_Win_2.3_11_5"
    $title = "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Do not store LAN Manager hash value on next password change' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "NoLMHash")
    if ($policy.NoLMHash -eq 1) {
        $status = "Pass"
        $actual = "'Network security: Do not store LAN Manager hash value on next password change' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Do not store LAN Manager hash value on next password change' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_6 {
    $control = "CIS_Win_2.3_11_6"
    $title = "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Force logoff when logon hours expire' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "ForceLogoffWhenLogonHoursExpire")
    if ($policy.ForceLogoffWhenLogonHoursExpire -eq 1) {
        $status = "Pass"
        $actual = "'Network security: Force logoff when logon hours expire' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Force logoff when logon hours expire' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_7 {
    $control = "CIS_Win_2.3_11_7"
    $title = "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
    $expected = "Send NTLMv2 response only. Refuse LM & NTLM"
    
    # Check the 'LAN Manager authentication level' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "LmCompatibilityLevel")
    if ($policy.LmCompatibilityLevel -eq 5) {
        $status = "Pass"
        $actual = "'Network security: LAN Manager authentication level' is configured correctly"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: LAN Manager authentication level' is not configured correctly"
        $remediation = "Set the LAN Manager authentication level to '5' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_8 {
    $control = "CIS_Win_2.3_11_8"
    $title = "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
    $expected = "Negotiate signing"
    
    # Check the 'LDAP client signing requirements' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\Parameters" -Name "LDAPClientSignatureRequirements")
    if ($policy.LDAPClientSignatureRequirements -ge 1) {
        $status = "Pass"
        $actual = "'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: LDAP client signing requirements' is not set to 'Negotiate signing' or higher"
        $remediation = "Configure the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_9 {
    $control = "CIS_Win_2.3_11_9"
    $title = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    $expected = "Require NTLMv2 session security, Require 128-bit encryption"
    
    # Check the 'Minimum session security for NTLM SSP based clients' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "SecDescSecLevel")
    if ($policy.SecDescSecLevel -eq 1) {
        $status = "Pass"
        $actual = "'Network security: Minimum session security for NTLM SSP based clients' is configured correctly"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Minimum session security for NTLM SSP based clients' is not configured correctly"
        $remediation = "Set to 'Require NTLMv2 session security, Require 128-bit encryption' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_2_3_11_10 {
    $control = "CIS_Win_2.3_11_10"
    $title = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    $expected = "Require NTLMv2 session security, Require 128-bit encryption"
    
    # Check the 'Minimum session security for NTLM SSP based servers' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SecDescSecLevel")
    if ($policy.SecDescSecLevel -eq 1) {
        $status = "Pass"
        $actual = "'Network security: Minimum session security for NTLM SSP based servers' is configured correctly"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Minimum session security for NTLM SSP based servers' is not configured correctly"
        $remediation = "Set to 'Require NTLMv2 session security, Require 128-bit encryption' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_11 {
    $control = "CIS_Win_2.3_11_11"
    $title = "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'"
    $expected = "Enable auditing for all accounts"
    
    # Check the 'Audit Incoming NTLM Traffic' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "AuditIncomingNTLMTraffic")
    if ($policy.AuditIncomingNTLMTraffic -eq 1) {
        $status = "Pass"
        $actual = "'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_11_12 {
    $control = "CIS_Win_2.3_11_12"
    $title = "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher"
    $expected = "Audit all"
    
    # Check the 'Restrict NTLM: Outgoing NTLM traffic to remote servers' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RestrictNTLMOutGoingTraffic")
    if ($policy.RestrictNTLMOutGoingTraffic -eq 2) {
        $status = "Pass"
        $actual = "'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is not set to 'Audit all'"
        $remediation = "Configure the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_15_1 {
    $control = "CIS_Win_2.3_15_1"
    $title = "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Require case insensitivity for non-Windows subsystems' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name "CaseInsensitiveNonWindowsSubsystems")
    if ($policy.CaseInsensitiveNonWindowsSubsystems -eq 1) {
        $status = "Pass"
        $actual = "'System objects: Require case insensitivity for non-Windows subsystems' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'System objects: Require case insensitivity for non-Windows subsystems' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_15_2 {
    $control = "CIS_Win_2.3_15_2"
    $title = "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Strengthen default permissions of internal system objects' setting
    $policy = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "StrengthenSystemObjectPermissions")
    if ($policy.StrengthenSystemObjectPermissions -eq 1) {
        $status = "Pass"
        $actual = "'System objects: Strengthen default permissions of internal system objects' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'System objects: Strengthen default permissions of internal system objects' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_1 {
    $control = "CIS_Win_2.3_17_1"
    $title = "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Admin Approval Mode for Built-in Administrator' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken")
    if ($policy.FilterAdministratorToken -eq 1) {
        $status = "Pass"
        $actual = "'User Account Control: Admin Approval Mode for the Built-in Administrator account' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Admin Approval Mode for the Built-in Administrator account' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_2 {
    $control = "CIS_Win_2.3_17_2"
    $title = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher"
    $expected = "Prompt for consent on the secure desktop"
    
    # Check the 'Behavior of the elevation prompt for administrators in Admin Approval Mode' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin")
    if ($policy.ConsentPromptBehaviorAdmin -eq 2) {
        $status = "Pass"
        $actual = "'User Account Control: Behavior of the elevation prompt for administrators' is set to 'Prompt for consent on the secure desktop'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Behavior of the elevation prompt for administrators' is not set to the correct level"
        $remediation = "Set the elevation prompt to 'Prompt for consent on the secure desktop' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_3 {
    $control = "CIS_Win_2.3_17_3"
    $title = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
    $expected = "Automatically deny elevation requests"
    
    # Check the 'Behavior of the elevation prompt for standard users' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser")
    if ($policy.ConsentPromptBehaviorUser -eq 0) {
        $status = "Pass"
        $actual = "'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Behavior of the elevation prompt for standard users' is not set correctly"
        $remediation = "Set to 'Automatically deny elevation requests' via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_4 {
    $control = "CIS_Win_2.3_17_4"
    $title = "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Detect application installations and prompt for elevation' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection")
    if ($policy.EnableInstallerDetection -eq 1) {
        $status = "Pass"
        $actual = "'User Account Control: Detect application installations and prompt for elevation' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Detect application installations and prompt for elevation' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_5 {
    $control = "CIS_Win_2.3_17_5"
    $title = "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Only elevate UIAccess applications that are installed in secure locations' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken")
    if ($policy.FilterAdministratorToken -eq 1) {
        $status = "Pass"
        $actual = "'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_6 {
    $control = "CIS_Win_2.3_17_6"
    $title = "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Run all administrators in Admin Approval Mode' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken")
    if ($policy.FilterAdministratorToken -eq 1) {
        $status = "Pass"
        $actual = "'User Account Control: Run all administrators in Admin Approval Mode' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Run all administrators in Admin Approval Mode' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_7 {
    $control = "CIS_Win_2.3_17_7"
    $title = "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Switch to the secure desktop when prompting for elevation' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop")
    if ($policy.PromptOnSecureDesktop -eq 1) {
        $status = "Pass"
        $actual = "'User Account Control: Switch to the secure desktop when prompting for elevation' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Switch to the secure desktop when prompting for elevation' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_2_3_17_8 {
    $control = "CIS_Win_2.3_17_8"
    $title = "Ensure 'User Account Control: Virtualize file and registry write failures to peruser locations' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check the 'Virtualize file and registry write failures to peruser locations' setting
    $policy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization")
    if ($policy.EnableVirtualization -eq 1) {
        $status = "Pass"
        $actual = "'User Account Control: Virtualize file and registry write failures to peruser locations' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User Account Control: Virtualize file and registry write failures to peruser locations' is disabled"
        $remediation = "Enable the setting via GPO or registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_3 {
    $control = "CIS_Win_5_3"
    $title = "Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Computer Browser' service status
    $service = Get-Service -Name "Browser"
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Computer Browser (Browser)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Computer Browser (Browser)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_5_6 {
    $control = "CIS_Win_5_6"
    $title = "Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'IIS Admin Service' status
    $service = Get-Service -Name "IISADMIN"
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'IIS Admin Service (IISADMIN)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'IIS Admin Service (IISADMIN)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_5_7 {
    $control = "CIS_Win_5_7"
    $title = "Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Infrared monitor service' status
    $service = Get-Service -Name "irmon" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Infrared monitor service (irmon)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Infrared monitor service (irmon)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_9 {
    $control = "CIS_Win_5_9"
    $title = "Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'LxssManager' service status
    $service = Get-Service -Name "LxssManager"
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'LxssManager (LxssManager)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'LxssManager (LxssManager)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_10 {
    $control = "CIS_Win_5_10"
    $title = "Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Microsoft FTP Service' status
    $service = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Microsoft FTP Service (FTPSVC)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Microsoft FTP Service (FTPSVC)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_12 {
    $control = "CIS_Win_5_12"
    $title = "Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'OpenSSH SSH Server' status
    $service = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'OpenSSH SSH Server (sshd)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'OpenSSH SSH Server (sshd)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_23 {
    $control = "CIS_Win_5_23"
    $title = "Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'RPC Locator' service status
    $service = Get-Service -Name "RpcLocator" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Remote Procedure Call (RPC) Locator' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Remote Procedure Call (RPC) Locator' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_25 {
    $control = "CIS_Win_5_25"
    $title = "Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Routing and Remote Access' service status
    $service = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Routing and Remote Access' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Routing and Remote Access' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_27 {
    $control = "CIS_Win_5_27"
    $title = "Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Simple TCP/IP Services' status
    $service = Get-Service -Name "simptcp" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Simple TCP/IP Services' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Simple TCP/IP Services' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_29 {
    $control = "CIS_Win_5_29"
    $title = "Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Special Administration Console Helper' service status
    $service = Get-Service -Name "sacsvr" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Special Administration Console Helper' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Special Administration Console Helper' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_5_30 {
    $control = "CIS_Win_5_30"
    $title = "Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'SSDP Discovery' service status
    $service = Get-Service -Name "SSDPSRV" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'SSDP Discovery (SSDPSRV)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'SSDP Discovery (SSDPSRV)' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_5_31 {
    $control = "CIS_Win_5_31"
    $title = "Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'UPnP Device Host' service status
    $service = Get-Service -Name "upnphost" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'UPnP Device Host (upnphost)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'UPnP Device Host (upnphost)' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_32 {
    $control = "CIS_Win_5_32"
    $title = "Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Web Management Service' status
    $service = Get-Service -Name "WMSvc" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Web Management Service (WMSvc)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Web Management Service (WMSvc)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_5_35 {
    $control = "CIS_Win_5_35"
    $title = "Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'Windows Media Player Network Sharing Service' status
    $service = Get-Service -Name "WMPNetworkSvc" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_36 {
    $control = "CIS_Win_5_36"
    $title = "Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Windows Mobile Hotspot Service' status
    $service = Get-Service -Name "icssvc" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Windows Mobile Hotspot Service (icssvc)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Mobile Hotspot Service (icssvc)' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_40 {
    $control = "CIS_Win_5_40"
    $title = "Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'"
    $expected = "Disabled or Not Installed"
    
    # Check the 'World Wide Web Publishing Service' status
    $service = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    if ($service -eq $null -or $service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'World Wide Web Publishing Service (W3SVC)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'World Wide Web Publishing Service (W3SVC)' is running"
        $remediation = "Disable or uninstall the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_5_41 {
    $control = "CIS_Win_5_41"
    $title = "Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Xbox Accessory Management Service' status
    $service = Get-Service -Name "XboxGipSvc" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Xbox Accessory Management Service (XboxGipSvc)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Xbox Accessory Management Service (XboxGipSvc)' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_42 {
    $control = "CIS_Win_5_42"
    $title = "Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Xbox Live Auth Manager' service status
    $service = Get-Service -Name "XblAuthManager" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Xbox Live Auth Manager (XblAuthManager)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Xbox Live Auth Manager (XblAuthManager)' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_5_43 {
    $control = "CIS_Win_5_43"
    $title = "Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check the 'Xbox Live Game Save' service status
    $service = Get-Service -Name "XblGameSave" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Stopped") {
        $status = "Pass"
        $actual = "'Xbox Live Game Save (XblGameSave)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Xbox Live Game Save (XblGameSave)' is running"
        $remediation = "Disable the service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_2_1 {
    $control = "CIS_Win_9_2_1"
    $title = "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    $expected = "On (recommended)"
    
    # Check the firewall state
    $firewall = Get-NetFirewallProfile -Profile Private
    if ($firewall.Enabled -eq $true) {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Firewall state' is On"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Private: Firewall state' is Off"
        $remediation = "Enable the firewall"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_2_2 {
    $control = "CIS_Win_9_2_2"
    $title = "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    $expected = "Block (default)"
    
    # Check inbound connections setting
    $firewall = Get-NetFirewallProfile -Profile Private
    if ($firewall.DefaultInboundAction -eq "Block") {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Inbound connections' is Blocked"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Private: Inbound connections' is Allowed"
        $remediation = "Configure the firewall to block inbound connections"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_9_2_3 {
    $control = "CIS_Win_9_2_3"
    $title = "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
    $expected = "No"
    
    # Check the firewall notification setting
    $firewall = Get-NetFirewallProfile -Profile Private
    if ($firewall.NotifyOnListen -eq $false) {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Display a notification' is Disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Private: Display a notification' is Enabled"
        $remediation = "Disable the notification"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# function Test-CIS_9_2_4 {
#     $control = "CIS_Win_9_2_4"
#     $title = "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
#     $expected = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
    
#     # Check the firewall log file location
#     $firewall = Get-NetFirewallProfile -Profile Private
#     if ($firewall.LoggingFileName -eq "$env:SystemRoot\System32\logfiles\firewall\privatefw.log") {
#         $status = "Pass"
#         $actual = "'Windows Firewall: Private: Logging: Name' is set correctly"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Windows Firewall: Private: Logging: Name' is set to $($firewall.LoggingFileName)"
#         $remediation = "Set the logging name to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


function Test-CIS_9_2_4 {
    $control = "CIS_Win_9_2_4"
    $title = "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    $expected = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"

    try {
        $firewall = Get-NetFirewallProfile -Profile Private -ErrorAction Stop
        $value = $firewall.LoggingFileName
    } catch {
        $value = $null
    }

    $expectedPath = Join-Path $env:SystemRoot "System32\logfiles\firewall\privatefw.log"

    if ($null -ne $value -and ( $value.Trim().ToLower() -eq $expectedPath.Trim().ToLower() )) {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Logging: Name' is set to $value"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ([string]::IsNullOrEmpty($value)) {
            "'Windows Firewall: Private: Logging: Name' is not set"
        } else {
            "'Windows Firewall: Private: Logging: Name' is set to $value"
        }
        $remediation = "Set the logging name to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



# function Test-CIS_9_2_5 {
#     $control = "CIS_Win_9_2_5"
#     $title = "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
#     $expected = "16,384 KB or greater"
    
#     # Check the firewall log size limit
#     $firewall = Get-NetFirewallProfile -Profile Private
#     if ($firewall.LoggingMaxSizeKilobytes -ge 16384) {
#         $status = "Pass"
#         $actual = "'Windows Firewall: Private: Logging: Size limit' is $($firewall.LoggingMaxSizeKilobytes) KB"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Windows Firewall: Private: Logging: Size limit' is $($firewall.LoggingMaxSizeKilobytes) KB"
#         $remediation = "Set the log size limit to 16,384 KB or greater"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_9_2_5 {
    $control = "CIS_Win_9_2_5"
    $title = "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $expected = "16,384 KB or greater"

    try {
        $firewall = Get-NetFirewallProfile -Profile Private -ErrorAction Stop
        $value = $firewall.LoggingMaxSizeKilobytes
    } catch {
        $value = $null
    }

    if ($null -ne $value -and [int]$value -ge 16384) {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Logging: Size limit' is $value KB"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($null -eq $value) {
            "'Windows Firewall: Private: Logging: Size limit' is not set"
        } else {
            "'Windows Firewall: Private: Logging: Size limit' is $value KB"
        }
        $remediation = "Set the log size limit to 16,384 KB or greater"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_9_2_6 {
    $control = "CIS_Win_9_2_6"
    $title = "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    $expected = "Yes"
    
    # Check the 'Log dropped packets' setting
    $firewall = Get-NetFirewallProfile -Profile Private
    if ($firewall.LogDroppedPackets -eq $true) {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Logging: Log dropped packets' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Private: Logging: Log dropped packets' is disabled"
        $remediation = "Enable logging of dropped packets"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_2_7 {
    $control = "CIS_Win_9_2_7"
    $title = "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    $expected = "Yes"
    
    # Check the 'Log successful connections' setting
    $firewall = Get-NetFirewallProfile -Profile Private
    if ($firewall.LogSuccessfulConnections -eq $true) {
        $status = "Pass"
        $actual = "'Windows Firewall: Private: Logging: Log successful connections' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Private: Logging: Log successful connections' is disabled"
        $remediation = "Enable logging of successful connections"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_3_1 {
    $control = "CIS_Win_9_3_1"
    $title = "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    $expected = "On (recommended)"
    
    # Check the firewall state for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.Enabled -eq $true) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Firewall state' is On"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Firewall state' is Off"
        $remediation = "Enable the firewall"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_9_3_2 {
    $control = "CIS_Win_9_3_2"
    $title = "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    $expected = "Block (default)"
    
    # Check inbound connections setting for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.DefaultInboundAction -eq "Block") {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Inbound connections' is Blocked"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Inbound connections' is Allowed"
        $remediation = "Configure the firewall to block inbound connections"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_9_3_3 {
    $control = "CIS_Win_9_3_3"
    $title = "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
    $expected = "No"
    
    # Check the 'Display a notification' setting for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.NotifyOnListen -eq $false) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Display a notification' is Disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Display a notification' is Enabled"
        $remediation = "Disable the notification"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_3_4 {
    $control = "CIS_Win_9_3_4"
    $title = "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    $expected = "No"
    
    # Check the 'Apply local firewall rules' setting for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.ApplyLocalRules -eq $false) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Apply local firewall rules' is Disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Apply local firewall rules' is Enabled"
        $remediation = "Disable the application of local firewall rules"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_3_5 {
    $control = "CIS_Win_9_3_5"
    $title = "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    $expected = "No"
    
    # Check the 'Apply local connection security rules' setting for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.ApplyLocalConnectionSecurityRules -eq $false) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Apply local connection security rules' is Disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Apply local connection security rules' is Enabled"
        $remediation = "Disable the application of local connection security rules"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



# function Test-CIS_9_3_6 {
#     $control = "CIS_Win_9_3_6"
#     $title = "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
#     $expected = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
    
#     # Check the firewall log file location for public profile
#     $firewall = Get-NetFirewallProfile -Profile Public
#     if ($firewall.LoggingFileName -eq "$env:SystemRoot\System32\logfiles\firewall\publicfw.log") {
#         $status = "Pass"
#         $actual = "'Windows Firewall: Public: Logging: Name' is set correctly"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Windows Firewall: Public: Logging: Name' is set to $($firewall.LoggingFileName)"
#         $remediation = "Set the logging name to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_9_3_7 {
#     $control = "CIS_Win_9_3_7"
#     $title = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
#     $expected = "16,384 KB or greater"
    
#     # Check the firewall log size limit for public profile
#     $firewall = Get-NetFirewallProfile -Profile Public
#     if ($firewall.LoggingMaxSizeKilobytes -ge 16384) {
#         $status = "Pass"
#         $actual = "'Windows Firewall: Public: Logging: Size limit' is $($firewall.LoggingMaxSizeKilobytes) KB"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Windows Firewall: Public: Logging: Size limit' is $($firewall.LoggingMaxSizeKilobytes) KB"
#         $remediation = "Set the log size limit to 16,384 KB or greater"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_9_3_6 {
    $control = "CIS_Win_9_3_6"
    $title = "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
    $expected = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"

    try {
        $firewall = Get-NetFirewallProfile -Profile Public -ErrorAction Stop
        $value = $firewall.LoggingFileName
    } catch {
        $value = $null
    }

    $expectedPath = Join-Path $env:SystemRoot "System32\logfiles\firewall\publicfw.log"

    if ($null -ne $value -and $value.Trim().ToLower() -eq $expectedPath.Trim().ToLower()) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Logging: Name' is set to $value"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = if ([string]::IsNullOrEmpty($value)) {
            "'Windows Firewall: Public: Logging: Name' is not set"
        } else {
            "'Windows Firewall: Public: Logging: Name' is set to $value"
        }
        $remediation = "Set the logging name to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_9_3_7 {
    $control = "CIS_Win_9_3_7"
    $title = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $expected = "16,384 KB or greater"

    try {
        $firewall = Get-NetFirewallProfile -Profile Public -ErrorAction Stop
        $value = $firewall.LoggingMaxSizeKilobytes
    } catch {
        $value = $null
    }

    if ($null -ne $value -and [int]$value -ge 16384) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Logging: Size limit' is $value KB"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = if ($null -eq $value) {
            "'Windows Firewall: Public: Logging: Size limit' is not set"
        } else {
            "'Windows Firewall: Public: Logging: Size limit' is $value KB"
        }
        $remediation = "Set the log size limit to 16,384 KB or greater"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_3_8 {
    $control = "CIS_Win_9_3_8"
    $title = "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    $expected = "Yes"
    
    # Check the 'Log dropped packets' setting for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.LogDroppedPackets -eq $true) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Logging: Log dropped packets' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Logging: Log dropped packets' is disabled"
        $remediation = "Enable logging of dropped packets"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_9_3_9 {
    $control = "CIS_Win_9_3_9"
    $title = "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    $expected = "Yes"
    
    # Check the 'Log successful connections' setting for public profile
    $firewall = Get-NetFirewallProfile -Profile Public
    if ($firewall.LogSuccessfulConnections -eq $true) {
        $status = "Pass"
        $actual = "'Windows Firewall: Public: Logging: Log successful connections' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows Firewall: Public: Logging: Log successful connections' is disabled"
        $remediation = "Enable logging of successful connections"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_1_1 {
    $control = "CIS_Win_17_1_1"
    $title = "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for credential validation
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.CredentialValidation -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Credential Validation' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Credential Validation' is set to $($audit.CredentialValidation)"
        $remediation = "Configure audit policy for credential validation to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_2_1 {
    $control = "CIS_Win_17_2_1"
    $title = "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for application group management
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.ApplicationGroupManagement -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Application Group Management' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Application Group Management' is set to $($audit.ApplicationGroupManagement)"
        $remediation = "Configure audit policy for application group management to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_2_2 {
    $control = "CIS_Win_17_2_2"
    $title = "Ensure 'Audit Security Group Management' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for security group management
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.SecurityGroupManagement -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Security Group Management' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Security Group Management' is set to $($audit.SecurityGroupManagement)"
        $remediation = "Configure audit policy for security group management to 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_2_3 {
    $control = "CIS_Win_17_2_3"
    $title = "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for user account management
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.UserAccountManagement -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit User Account Management' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit User Account Management' is set to $($audit.UserAccountManagement)"
        $remediation = "Configure audit policy for user account management to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_3_1 {
    $control = "CIS_Win_17_3_1"
    $title = "Ensure 'Audit PNP Activity' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for PNP activity
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.PNPActivity -eq "Success") {
        $status = "Pass"
        $actual = "'Audit PNP Activity' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit PNP Activity' is set to $($audit.PNPActivity)"
        $remediation = "Configure audit policy for PNP activity to 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_3_2 {
    $control = "CIS_Win_17_3_2"
    $title = "Ensure 'Audit Process Creation' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for process creation
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.ProcessCreation -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Process Creation' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Process Creation' is set to $($audit.ProcessCreation)"
        $remediation = "Configure audit policy for process creation to 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_5_1 {
    $control = "CIS_Win_17_5_1"
    $title = "Ensure 'Audit Account Lockout' is set to include 'Failure'"
    $expected = "Failure"
    
    # Check the audit policy for account lockout
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.AccountLockout -eq "Failure") {
        $status = "Pass"
        $actual = "'Audit Account Lockout' is set to 'Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Account Lockout' is set to $($audit.AccountLockout)"
        $remediation = "Configure audit policy for account lockout to include 'Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_5_2 {
    $control = "CIS_Win_17_5_2"
    $title = "Ensure 'Audit Group Membership' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for group membership
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.GroupMembership -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Group Membership' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Group Membership' is set to $($audit.GroupMembership)"
        $remediation = "Configure audit policy for group membership to 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_5_3 {
    $control = "CIS_Win_17_5_3"
    $title = "Ensure 'Audit Logoff' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for logoff
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.Logoff -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Logoff' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Logoff' is set to $($audit.Logoff)"
        $remediation = "Configure audit policy for logoff to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_5_4 {
    $control = "CIS_Win_17_5_4"
    $title = "Ensure 'Audit Logon' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for logon
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.Logon -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Logon' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Logon' is set to $($audit.Logon)"
        $remediation = "Configure audit policy for logon to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_5_5 {
    $control = "CIS_Win_17_5_5"
    $title = "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for other logon/logoff events
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.OtherLogonLogoffEvents -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Other Logon/Logoff Events' is set to $($audit.OtherLogonLogoffEvents)"
        $remediation = "Configure audit policy for other logon/logoff events to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_5_6 {
    $control = "CIS_Win_17_5_6"
    $title = "Ensure 'Audit Special Logon' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for special logon
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.SpecialLogon -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Special Logon' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Special Logon' is set to $($audit.SpecialLogon)"
        $remediation = "Configure audit policy for special logon to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_6_1 {
    $control = "CIS_Win_17_6_1"
    $title = "Ensure 'Audit Detailed File Share' is set to include 'Failure'"
    $expected = "Failure"
    
    # Check the audit policy for detailed file share
    $audit = Get-AuditPolicy -Category Object Access
    if ($audit.DetailedFileShare -eq "Failure") {
        $status = "Pass"
        $actual = "'Audit Detailed File Share' is set to 'Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Detailed File Share' is set to $($audit.DetailedFileShare)"
        $remediation = "Configure audit policy for detailed file share to include 'Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_6_2 {
    $control = "CIS_Win_17_6_2"
    $title = "Ensure 'Audit File Share' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for file share
    $audit = Get-AuditPolicy -Category Object Access
    if ($audit.FileShare -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit File Share' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit File Share' is set to $($audit.FileShare)"
        $remediation = "Configure audit policy for file share to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_6_3 {
    $control = "CIS_Win_17_6_3"
    $title = "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for other object access events
    $audit = Get-AuditPolicy -Category Object Access
    if ($audit.OtherObjectAccessEvents -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Other Object Access Events' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Other Object Access Events' is set to $($audit.OtherObjectAccessEvents)"
        $remediation = "Configure audit policy for other object access events to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_6_4 {
    $control = "CIS_Win_17_6_4"
    $title = "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for removable storage
    $audit = Get-AuditPolicy -Category Object Access
    if ($audit.RemovableStorage -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Removable Storage' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Removable Storage' is set to $($audit.RemovableStorage)"
        $remediation = "Configure audit policy for removable storage to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_7_1 {
    $control = "CIS_Win_17_7_1"
    $title = "Ensure 'Audit Audit Policy Change' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for audit policy change
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.AuditPolicyChange -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Audit Policy Change' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Audit Policy Change' is set to $($audit.AuditPolicyChange)"
        $remediation = "Configure audit policy for audit policy change to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_7_2 {
    $control = "CIS_Win_17_7_2"
    $title = "Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for authentication policy change
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.AuthenticationPolicyChange -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Authentication Policy Change' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Authentication Policy Change' is set to $($audit.AuthenticationPolicyChange)"
        $remediation = "Configure audit policy for authentication policy change to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_7_3 {
    $control = "CIS_Win_17_7_3"
    $title = "Ensure 'Audit Authorization Policy Change' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for authorization policy change
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.AuthorizationPolicyChange -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Authorization Policy Change' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Authorization Policy Change' is set to $($audit.AuthorizationPolicyChange)"
        $remediation = "Configure audit policy for authorization policy change to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_7_4 {
    $control = "CIS_Win_17_7_4"
    $title = "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for MPSSVC rule-level policy change
    $audit = Get-AuditPolicy -Category Policy Change
    if ($audit.MPSSVCRuleLevelPolicyChange -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit MPSSVC Rule-Level Policy Change' is set to $($audit.MPSSVCRuleLevelPolicyChange)"
        $remediation = "Configure audit policy for MPSSVC rule-level policy change to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_7_5 {
    $control = "CIS_Win_17_7_5"
    $title = "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
    $expected = "Failure"
    
    # Check the audit policy for other policy change events
    $audit = Get-AuditPolicy -Category Policy Change
    if ($audit.OtherPolicyChangeEvents -eq "Failure") {
        $status = "Pass"
        $actual = "'Audit Other Policy Change Events' is set to 'Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Other Policy Change Events' is set to $($audit.OtherPolicyChangeEvents)"
        $remediation = "Configure audit policy for other policy change events to include 'Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_9_1 {
    $control = "CIS_Win_17_9_1"
    $title = "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for IPsec driver
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.IPsecDriver -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit IPsec Driver' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit IPsec Driver' is set to $($audit.IPsecDriver)"
        $remediation = "Configure audit policy for IPsec driver to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_9_2 {
    $control = "CIS_Win_17_9_2"
    $title = "Ensure 'Audit Other System Events' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for other system events
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.OtherSystemEvents -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit Other System Events' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Other System Events' is set to $($audit.OtherSystemEvents)"
        $remediation = "Configure audit policy for other system events to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_17_9_3 {
    $control = "CIS_Win_17_9_3"
    $title = "Ensure 'Audit Security State Change' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for security state change
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.SecurityStateChange -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Security State Change' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Security State Change' is set to $($audit.SecurityStateChange)"
        $remediation = "Configure audit policy for security state change to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_9_4 {
    $control = "CIS_Win_17_9_4"
    $title = "Ensure 'Audit Security System Extension' is set to include 'Success'"
    $expected = "Success"
    
    # Check the audit policy for security system extension
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.SecuritySystemExtension -eq "Success") {
        $status = "Pass"
        $actual = "'Audit Security System Extension' is set to 'Success'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit Security System Extension' is set to $($audit.SecuritySystemExtension)"
        $remediation = "Configure audit policy for security system extension to include 'Success'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_17_9_5 {
    $control = "CIS_Win_17_9_5"
    $title = "Ensure 'Audit System Integrity' is set to 'Success and Failure'"
    $expected = "Success and Failure"
    
    # Check the audit policy for system integrity
    $audit = Get-AuditPolicy -Category Logon/Logoff
    if ($audit.SystemIntegrity -eq "Success and Failure") {
        $status = "Pass"
        $actual = "'Audit System Integrity' is set to 'Success and Failure'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Audit System Integrity' is set to $($audit.SystemIntegrity)"
        $remediation = "Configure audit policy for system integrity to 'Success and Failure'"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



# function Test-CIS_18_1_1_1 {
#     $control = "CIS_Win_18_1_1_1"
#     $title = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check the setting for lock screen camera
#     $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera"
#     if ($policy.NoLockScreenCamera -eq 1) {
#         $status = "Pass"
#         $actual = "'Prevent enabling lock screen camera' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Prevent enabling lock screen camera' is set to $($policy.NoLockScreenCamera)"
#         $remediation = "Set 'Prevent enabling lock screen camera' to 'Enabled' via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_1_1_2 {
#     $control = "CIS_Win_18_1_1_2"
#     $title = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check the setting for lock screen slide show
#     $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideShow"
#     if ($policy.NoLockScreenSlideShow -eq 1) {
#         $status = "Pass"
#         $actual = "'Prevent enabling lock screen slide show' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Prevent enabling lock screen slide show' is set to $($policy.NoLockScreenSlideShow)"
#         $remediation = "Set 'Prevent enabling lock screen slide show' to 'Enabled' via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_1_2_2 {
#     $control = "CIS_Win_18_1_2_2"
#     $title = "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check the setting for speech recognition
#     $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" -Name "AllowSpeechRecognition"
#     if ($policy.AllowSpeechRecognition -eq 0) {
#         $status = "Pass"
#         $actual = "'Allow users to enable online speech recognition services' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Allow users to enable online speech recognition services' is set to $($policy.AllowSpeechRecognition)"
#         $remediation = "Set 'Allow users to enable online speech recognition services' to 'Disabled' via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_4_1 {
#     $control = "CIS_Win_18_4_1"
#     $title = "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check RPC packet level privacy setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\RPC" -Name "NoRemoteAccess"
#     if ($policy.NoRemoteAccess -eq 1) {
#         $status = "Pass"
#         $actual = "'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Configure RPC packet level privacy setting for incoming connections' is set to $($policy.NoRemoteAccess)"
#         $remediation = "Set 'Configure RPC packet level privacy setting for incoming connections' to 'Enabled' via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_4_2 {
#     $control = "CIS_Win_18_4_2"
#     $title = "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
#     $expected = "Enabled: Disable driver"
    
#     # Check the SMB v1 client driver setting
#     $smbv1 = Get-WindowsFeature FS-SMB1
#     if ($smbv1.Installed -eq $false) {
#         $status = "Pass"
#         $actual = "'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Configure SMB v1 client driver' is set to $($smbv1.Installed)"
#         $remediation = "Disable SMB v1 client driver by running 'Uninstall-WindowsFeature FS-SMB1'"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_4_3 {
#     $control = "CIS_Win_18_4_3"
#     $title = "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check the SMB v1 server setting
#     $smbv1 = Get-WindowsFeature FS-SMB1
#     if ($smbv1.Installed -eq $false) {
#         $status = "Pass"
#         $actual = "'Configure SMB v1 server' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Configure SMB v1 server' is set to $($smbv1.Installed)"
#         $remediation = "Disable SMB v1 server by running 'Uninstall-WindowsFeature FS-SMB1'"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_4_4 {
#     $control = "CIS_Win_18_4_4"
#     $title = "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check certificate padding setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Cryptography" -Name "EnableCertPadding"
#     if ($policy.EnableCertPadding -eq 1) {
#         $status = "Pass"
#         $actual = "'Enable Certificate Padding' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Enable Certificate Padding' is set to $($policy.EnableCertPadding)"
#         $remediation = "Enable Certificate Padding via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }




# function Test-CIS_18_4_5 {
#     $control = "CIS_Win_18_4_5"
#     $title = "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check SEHOP setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Name "Sehop"
#     if ($policy.Sehop -eq 1) {
#         $status = "Pass"
#         $actual = "'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to $($policy.Sehop)"
#         $remediation = "Enable SEHOP via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


# function Test-CIS_18_4_6 {
#     $control = "CIS_Win_18_4_6"
#     $title = "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
#     $expected = "Enabled: P-node"
    
#     # Check the NetBT NodeType configuration
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType"
#     if ($policy.NodeType -eq 0x2) { # 0x2 represents P-node
#         $status = "Pass"
#         $actual = "'NetBT NodeType configuration' is set to 'Enabled: P-node'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'NetBT NodeType configuration' is set to $($policy.NodeType)"
#         $remediation = "Set NetBT NodeType to P-node (0x2) via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_4_7 {
#     $control = "CIS_Win_18_4_7"
#     $title = "Ensure 'WDigest Authentication' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check the WDigest authentication setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
#     if ($policy.UseLogonCredential -eq 0) {
#         $status = "Pass"
#         $actual = "'WDigest Authentication' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'WDigest Authentication' is set to $($policy.UseLogonCredential)"
#         $remediation = "Disable WDigest Authentication via GPO or registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_5_1 {
#     $control = "CIS_Win_18_5_1"
#     $title = "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check the AutoAdminLogon setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AutoAdminLogon"
#     if ($policy.AutoAdminLogon -eq 0) {
#         $status = "Pass"
#         $actual = "'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to $($policy.AutoAdminLogon)"
#         $remediation = "Set AutoAdminLogon to 'Disabled' via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_5_2 {
#     $control = "CIS_Win_18_5_2"
#     $title = "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'"
#     $expected = "Enabled: Highest protection"
    
#     # Check the IP source routing protection level for IPv6
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting"
#     if ($policy.DisableIPSourceRouting -eq 2) { # 2 = Highest protection, source routing completely disabled
#         $status = "Pass"
#         $actual = "'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to $($policy.DisableIPSourceRouting)"
#         $remediation = "Set IP source routing protection to highest via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_18_1_1_1 {
    $control = "CIS_Win_18_1_1_1"
    $title = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
    $expected = "Enabled"
    
    $val = Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
    if ($val -eq 1) {
        $status = "Pass"
        $actual = "'Prevent enabling lock screen camera' is set to 'Enabled'"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "'Prevent enabling lock screen camera' is set to $val"
        $remediation = "Set 'Prevent enabling lock screen camera' to 'Enabled' via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_1_1_2 {
    $control = "CIS_Win_18_1_1_2"
    $title = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    $expected = "Enabled"
    
    $val = Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideShow"
    if ($val -eq 1) {
        $status = "Pass"
        $actual = "'Prevent enabling lock screen slide show' is set to 'Enabled'"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "'Prevent enabling lock screen slide show' is set to $val"
        $remediation = "Set 'Prevent enabling lock screen slide show' to 'Enabled' via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_1_2_2 {
    $control = "CIS_Win_18_1_2_2"
    $title = "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
    $expected = "Disabled"
    
    $val = Get-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "AllowSpeechRecognition"
    if ($val -eq 0) {
        $status = "Pass"
        $actual = "'Allow users to enable online speech recognition services' is set to 'Disabled'"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "'Allow users to enable online speech recognition services' is set to $val"
        $remediation = "Set to 'Disabled' via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_4_1 {
    $control = "CIS_Win_18_4_1"
    $title = "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
    $expected = "Enabled"
    
    $val = Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows NT\RPC" "NoRemoteAccess"
    if ($val -eq 1) {
        $status = "Pass"
        $actual = "'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "'Configure RPC packet level privacy setting for incoming connections' is set to $val"
        $remediation = "Set to 'Enabled' via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

# SMBv1 Client & Server (works on Windows 10/11)
function Test-CIS_18_4_2 {
    $control = "CIS_Win_18_4_2"
    $title = "Ensure 'Configure SMB v1 client driver' is set to 'Disabled'"
    $expected = "Disabled"
    
    $val = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($val.State -eq "Disabled") {
        $status = "Pass"
        $actual = "SMB v1 client is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "SMB v1 client is $($val.State)"
        $remediation = "Disable using: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_4_3 {
    $control = "CIS_Win_18_4_3"
    $title = "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    $expected = "Disabled"
    
    $val = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -ErrorAction SilentlyContinue
    if ($val.State -eq "Disabled") {
        $status = "Pass"
        $actual = "SMB v1 server is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "SMB v1 server is $($val.State)"
        $remediation = "Disable using: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_4_4 {
    $control = "CIS_Win_18_4_4"
    $title = "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
    $expected = "Enabled"
    
    $val = Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Cryptography" "EnableCertPadding"
    if ($val -eq 1) {
        $status = "Pass"
        $actual = "'Enable Certificate Padding' is set to 'Enabled'"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "'Enable Certificate Padding' is set to $val"
        $remediation = "Enable via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_4_5 {
    $control = "CIS_Win_18_4_5"
    $title = "Ensure 'Enable SEHOP' is set to 'Enabled'"
    $expected = "Enabled"
    
    $val = Get-RegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" "Sehop"
    if ($val -eq 1) {
        $status = "Pass"
        $actual = "SEHOP is enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "SEHOP is set to $val"
        $remediation = "Enable SEHOP via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_4_6 {
    $control = "CIS_Win_18_4_6"
    $title = "Ensure 'NetBT NodeType configuration' is set to 'P-node'"
    $expected = "Enabled: P-node"
    
    $val = Get-RegistryValue "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" "NodeType"
    if ($val -eq 2) {
        $status = "Pass"
        $actual = "NetBT NodeType is set to P-node (2)"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "NetBT NodeType is set to $val"
        $remediation = "Set NodeType to 2 (P-node)"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_4_7 {
    $control = "CIS_Win_18_4_7"
    $title = "Ensure 'WDigest Authentication' is set to 'Disabled'"
    $expected = "Disabled"
    
    $val = Get-RegistryValue "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
    if ($val -eq 0) {
        $status = "Pass"
        $actual = "WDigest Authentication is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "WDigest Authentication is set to $val"
        $remediation = "Disable via GPO or registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

# function Test-CIS_18_5_1 {
#     $control = "CIS_Win_18_5_1"
#     $title = "Ensure 'AutoAdminLogon' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     $val = Get-RegistryValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "AutoAdminLogon"
#     if ($val -eq 0 -or $val -eq $null) {
#         $status = "Pass"
#         $actual = "AutoAdminLogon is disabled"
#         $remediation = "No action required"
#     } else {
#         $status = "Fail"
#         $actual = "AutoAdminLogon is set to $val"
#         $remediation = "Set AutoAdminLogon to 0 in registry"
#     }
#     return New-CheckResult $control $title $expected $actual $status $remediation
# }

# function Test-CIS_18_5_2 {
#     $control = "CIS_Win_18_5_2"
#     $title = "Ensure 'DisableIPSourceRouting IPv6' is set to '2'"
#     $expected = "Enabled: Highest protection"
    
#     $val = Get-RegistryValue "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"
#     if ($val -eq 2) {
#         $status = "Pass"
#         $actual = "IPv6 source routing protection is set to highest (2)"
#         $remediation = "No action required"
#     } else {
#         $status = "Fail"
#         $actual = "IPv6 source routing protection is set to $val"
#         $remediation = "Set DisableIPSourceRouting to 2"
#     }
#     return New-CheckResult $control $title $expected $actual $status $remediation
# }

# function Test-CIS_18_5_3 {
#     $control = "CIS_Win_18_5_3"
#     $title = "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'"
#     $expected = "Enabled: Highest protection"
    
#     # Check the IP source routing protection level
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting"
#     if ($policy.DisableIPSourceRouting -eq 2) { # 2 = Highest protection, source routing completely disabled
#         $status = "Pass"
#         $actual = "'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to $($policy.DisableIPSourceRouting)"
#         $remediation = "Set IP source routing protection to highest via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }


# function Test-CIS_18_5_5 {
#     $control = "CIS_Win_18_5_5"
#     $title = "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check the EnableICMPRedirect setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect"
#     if ($policy.EnableICMPRedirect -eq 0) {
#         $status = "Pass"
#         $actual = "'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to $($policy.EnableICMPRedirect)"
#         $remediation = "Disable ICMP redirects via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_5_7 {
#     $control = "CIS_Win_18_5_7"
#     $title = "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check the NoNameReleaseOnDemand setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand"
#     if ($policy.NoNameReleaseOnDemand -eq 1) {
#         $status = "Pass"
#         $actual = "'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to $($policy.NoNameReleaseOnDemand)"
#         $remediation = "Enable 'NoNameReleaseOnDemand' via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }




# function Test-CIS_18_5_9 {
#     $control = "CIS_Win_18_5_9"
#     $title = "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check SafeDllSearchMode setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode"
#     if ($policy.SafeDllSearchMode -eq 1) {
#         $status = "Pass"
#         $actual = "'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to $($policy.SafeDllSearchMode)"
#         $remediation = "Enable Safe DLL search mode via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_5_10 {
#     $control = "CIS_Win_18_5_10"
#     $title = "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'"
#     $expected = "Enabled: 5 or fewer seconds"
    
#     # Check ScreenSaverGracePeriod setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ScreenSaverGracePeriod"
#     if ($policy.ScreenSaverGracePeriod -le 5) {
#         $status = "Pass"
#         $actual = "'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to '$($policy.ScreenSaverGracePeriod) seconds'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to $($policy.ScreenSaverGracePeriod)"
#         $remediation = "Set ScreenSaverGracePeriod to 5 seconds or fewer via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_5_13 {
#     $control = "CIS_Win_18_5_13"
#     $title = "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
#     $expected = "Enabled: 90% or less"
    
#     # Check WarningLevel setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "WarningLevel"
#     if ($policy.WarningLevel -le 90) {
#         $status = "Pass"
#         $actual = "'MSS: (WarningLevel) Percentage threshold for the security event log' is set to '$($policy.WarningLevel)%'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'MSS: (WarningLevel) Percentage threshold for the security event log' is set to $($policy.WarningLevel)%"
#         $remediation = "Set WarningLevel to 90% or less via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_18_5_1 {
    $control = "CIS_Win_18_5_1"
    $title = "Ensure 'AutoAdminLogon' is set to 'Disabled'"
    $expected = "Disabled"
    
    $val = Get-RegistryValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "AutoAdminLogon"
    if ($val -eq 0 -or $val -eq $null) {
        $status = "Pass"
        $actual = "AutoAdminLogon is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "AutoAdminLogon is set to $val"
        $remediation = "Set AutoAdminLogon to 0 in registry"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}

function Test-CIS_18_5_2 {
    $control = "CIS_Win_18_5_2"
    $title = "Ensure 'DisableIPSourceRouting IPv6' is set to '2'"
    $expected = "Enabled: Highest protection"
    
    $val = Get-RegistryValue "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"
    if ($val -eq 2) {
        $status = "Pass"
        $actual = "IPv6 source routing protection is set to highest (2)"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "IPv6 source routing protection is set to $val"
        $remediation = "Set DisableIPSourceRouting to 2"
    }
    return New-CheckResult $control $title $expected $actual $status $remediation
}


function Test-CIS_18_5_3 {
    $control = "CIS_Win_18_5_3"
    $title = "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    $expected = "Enabled: Highest protection"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -ErrorAction Stop
        if ($policy.DisableIPSourceRouting -eq 2) {
            $status = "Pass"
            $actual = "Highest protection (2)"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "Value is $($policy.DisableIPSourceRouting)"
            $remediation = "Set DisableIPSourceRouting to 2 (Highest protection)"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set DisableIPSourceRouting to 2 (Highest protection)"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_5_5 {
    $control = "CIS_Win_18_5_5"
    $title = "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    $expected = "Disabled"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -ErrorAction Stop
        if ($policy.EnableICMPRedirect -eq 0) {
            $status = "Pass"
            $actual = "Disabled (0)"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "Value is $($policy.EnableICMPRedirect)"
            $remediation = "Set EnableICMPRedirect to 0 (Disabled)"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set EnableICMPRedirect to 0 (Disabled)"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_5_7 {
    $control = "CIS_Win_18_5_7"
    $title = "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
    $expected = "Enabled"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -ErrorAction Stop
        if ($policy.NoNameReleaseOnDemand -eq 1) {
            $status = "Pass"
            $actual = "Enabled (1)"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "Value is $($policy.NoNameReleaseOnDemand)"
            $remediation = "Set NoNameReleaseOnDemand to 1 (Enabled)"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set NoNameReleaseOnDemand to 1 (Enabled)"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_5_9 {
    $control = "CIS_Win_18_5_9"
    $title = "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'"
    $expected = "Enabled"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -ErrorAction Stop
        if ($policy.SafeDllSearchMode -eq 1) {
            $status = "Pass"
            $actual = "Enabled (1)"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "Value is $($policy.SafeDllSearchMode)"
            $remediation = "Set SafeDllSearchMode to 1 (Enabled)"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set SafeDllSearchMode to 1 (Enabled)"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_5_10 {
    $control = "CIS_Win_18_5_10"
    $title = "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds'"
    $expected = "Enabled: 5 or fewer seconds"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ScreenSaverGracePeriod" -ErrorAction Stop
        $value = [int]$policy.ScreenSaverGracePeriod
        if ($value -le 5) {
            $status = "Pass"
            $actual = "$value seconds"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "$value seconds"
            $remediation = "Set ScreenSaverGracePeriod to 5 or fewer seconds"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set ScreenSaverGracePeriod to 5 or fewer seconds"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_5_13 {
    $control = "CIS_Win_18_5_13"
    $title = "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
    $expected = "Enabled: 90% or less"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "WarningLevel" -ErrorAction Stop
        if ($policy.WarningLevel -le 90) {
            $status = "Pass"
            $actual = "$($policy.WarningLevel)%"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "$($policy.WarningLevel)%"
            $remediation = "Set WarningLevel to 90% or less"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set WarningLevel to 90% or less"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


# function Test-CIS_18_6_4_1 {
#     $control = "CIS_Win_18_6_4_1"
#     $title = "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher"
#     $expected = "Enabled: Allow DoH"
    
#     # Check DoH setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode"
#     if ($policy.DnsOverHttpsMode -eq 1) { # 1 = Allow DoH
#         $status = "Pass"
#         $actual = "'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Configure DNS over HTTPS (DoH) name resolution' is set to $($policy.DnsOverHttpsMode)"
#         $remediation = "Enable DNS over HTTPS via registry or GPO"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_6_8_1 {
#     $control = "CIS_Win_18_6_8_1"
#     $title = "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check insecure guest logon setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableInsecureGuestLogons"
#     if ($policy.EnableInsecureGuestLogons -eq 0) {
#         $status = "Pass"
#         $actual = "'Enable insecure guest logons' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Enable insecure guest logons' is set to $($policy.EnableInsecureGuestLogons)"
#         $remediation = "Disable insecure guest logons via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_6_11_2 {
#     $control = "CIS_Win_18_6_11_2"
#     $title = "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check the Network Bridge installation setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge"
#     if ($policy.NC_AllowNetBridge -eq 0) {
#         $status = "Pass"
#         $actual = "'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to $($policy.NC_AllowNetBridge)"
#         $remediation = "Set NC_AllowNetBridge to 0 via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_6_11_3 {
#     $control = "CIS_Win_18_6_11_3"
#     $title = "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
#     $expected = "Enabled"
    
#     # Check Internet Connection Sharing setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NoInternetSharing"
#     if ($policy.NoInternetSharing -eq 1) {
#         $status = "Pass"
#         $actual = "'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to $($policy.NoInternetSharing)"
#         $remediation = "Set NoInternetSharing to 1 via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_6_14_1 {
#     $control = "CIS_Win_18_6_14_1"
#     $title = "Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication', 'Require Integrity', and 'Require Privacy' set for all NETLOGON and SYSVOL shares'"
#     $expected = "Enabled"
    
#     # Check the UNC Path Hardened setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireMutualAuthentication"
#     if ($policy.RequireMutualAuthentication -eq 1 -and $policy.RequireIntegrity -eq 1 -and $policy.RequirePrivacy -eq 1) {
#         $status = "Pass"
#         $actual = "'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication', 'Require Integrity', and 'Require Privacy' for NETLOGON and SYSVOL shares'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Hardened UNC Paths' is not configured correctly"
#         $remediation = "Ensure 'Require Mutual Authentication', 'Require Integrity', and 'Require Privacy' are enabled via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_6_21_1 {
#     $control = "CIS_Win_18_6_21_1"
#     $title = "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'"
#     $expected = "Enabled: 3"
    
#     # Check the simultaneous connections setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server"
#     if ($policy.MaxConnectionsPer1_0Server -eq 3) {
#         $status = "Pass"
#         $actual = "'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to $($policy.MaxConnectionsPer1_0Server)"
#         $remediation = "Set MaxConnectionsPer1_0Server to 3 via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_6_23_2_1 {
#     $control = "CIS_Win_18_6_23_2_1"
#     $title = "Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check the auto-connect to hotspots setting
#     $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\WiFi\Connected" -Name "AllowAutoConnectToOpenHotspots"
#     if ($policy.AllowAutoConnectToOpenHotspots -eq 0) {
#         $status = "Pass"
#         $actual = "'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Allow Windows to automatically connect to suggested open hotspots' is set to $($policy.AllowAutoConnectToOpenHotspots)"
#         $remediation = "Disable auto-connect to open hotspots via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_7_1 {
#     $control = "CIS_Win_18_7_1"
#     $title = "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check Print Spooler client connections setting
#     $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Spooler" -Name "AllowClientConnections"
#     if ($policy.AllowClientConnections -eq 0) {
#         $status = "Pass"
#         $actual = "'Allow Print Spooler to accept client connections' is set to 'Disabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Allow Print Spooler to accept client connections' is set to $($policy.AllowClientConnections)"
#         $remediation = "Disable print spooler client connections via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }



# function Test-CIS_18_7_2 {
#     $control = "CIS_Win_18_7_2"
#     $title = "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
#     $expected = "Enabled: Redirection Guard Enabled"
    
#     # Check Redirection Guard setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableRedirectionGuard"
#     if ($policy.EnableRedirectionGuard -eq 1) {
#         $status = "Pass"
#         $actual = "'Configure Redirection Guard' is set to 'Enabled'"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Configure Redirection Guard' is set to $($policy.EnableRedirectionGuard)"
#         $remediation = "Enable Redirection Guard via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_18_6_4_1 {
    $control = "18.6.4.1"
    $title = "Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher"
    $expected = "Enabled: Allow DoH"
    
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
    if ($policy -and $policy.DnsOverHttpsMode -eq 1) {
        $status = "Pass"
        $actual = "'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Configure DNS over HTTPS (DoH) name resolution' is set to $($policy.DnsOverHttpsMode)" } else { "Not Configured" }
        $remediation = "Enable DNS over HTTPS via registry or GPO"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_6_8_1 {
    $control = "18.6.8.1"
    $title = "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
    $expected = "Disabled"
    
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableInsecureGuestLogons" -ErrorAction SilentlyContinue
    if ($policy -and $policy.EnableInsecureGuestLogons -eq 0) {
        $status = "Pass"
        $actual = "'Enable insecure guest logons' is set to 'Disabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Enable insecure guest logons' is set to $($policy.EnableInsecureGuestLogons)" } else { "Not Configured" }
        $remediation = "Disable insecure guest logons via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_6_11_2 {
    $control = "18.6.11.2"
    $title = "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled' (Automated)"
    $expected = "Enabled"
    
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge" -ErrorAction SilentlyContinue
    if ($policy -and $policy.NC_AllowNetBridge -eq 0) {
        $status = "Pass"
        $actual = "'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Prohibit installation and configuration of Network Bridge' is set to $($policy.NC_AllowNetBridge)" } else { "Not Configured" }
        $remediation = "Set NC_AllowNetBridge to 0 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_6_11_3 {
    $control = "18.6.11.3"
    $title = "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled' (Automated)"
    $expected = "Enabled"
    
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NoInternetSharing" -ErrorAction SilentlyContinue
    if ($policy -and $policy.NoInternetSharing -eq 1) {
        $status = "Pass"
        $actual = "'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Prohibit use of Internet Connection Sharing' is set to $($policy.NoInternetSharing)" } else { "Not Configured" }
        $remediation = "Set NoInternetSharing to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_6_14_1 {
    $control = "18.6.14.1"
    $title = "Ensure 'Hardened UNC Paths' is set to 'Enabled, with \Require Mutual Authentication\, \Require Integrity\, and \Require Privacy\ set for all NETLOGON and SYSVOL shares' (Automated)"
    $expected = "Enabled"
    
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
    if ($policy -and $policy.RequireMutualAuthentication -eq 1 -and $policy.RequireIntegrity -eq 1 -and $policy.RequirePrivacy -eq 1) {
        $status = "Pass"
        $actual = "'Hardened UNC Paths' is configured correctly"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "Hardened UNC Paths not configured correctly"
        $remediation = "Ensure 'Require Mutual Authentication', 'Require Integrity', and 'Require Privacy' are enabled via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_6_21_1 {
    $control = "18.6.21.1"
    $title = "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet' (Automated)"
    $expected = "Enabled: 3"
    
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -ErrorAction SilentlyContinue
    if ($policy -and $policy.MaxConnectionsPer1_0Server -eq 3) {
        $status = "Pass"
        $actual = "'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Minimize connections' is set to $($policy.MaxConnectionsPer1_0Server)" } else { "Not Configured" }
        $remediation = "Set MaxConnectionsPer1_0Server to 3 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_6_23_2_1 {
    $control = "18.6.23.2.1"
    $title = "Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled' (Automated)"
    $expected = "Disabled"
    
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\WiFi\Connected" -Name "AllowAutoConnectToOpenHotspots" -ErrorAction SilentlyContinue
    if ($policy -and $policy.AllowAutoConnectToOpenHotspots -eq 0) {
        $status = "Pass"
        $actual = "'Auto-connect to open hotspots' is set to 'Disabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Auto-connect to open hotspots' is set to $($policy.AllowAutoConnectToOpenHotspots)" } else { "Not Configured" }
        $remediation = "Disable auto-connect to open hotspots via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_7_1 {
    $control = "18.7.1"
    $title = "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled' (Automated)"
    $expected = "Disabled"
    
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Spooler" -Name "AllowClientConnections" -ErrorAction SilentlyContinue
    if ($policy -and $policy.AllowClientConnections -eq 0) {
        $status = "Pass"
        $actual = "'Allow Print Spooler to accept client connections' is set to 'Disabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Allow Print Spooler client connections' is set to $($policy.AllowClientConnections)" } else { "Not Configured" }
        $remediation = "Disable print spooler client connections via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_7_2 {
    $control = "18.7.2"
    $title = "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled' (Automated)"
    $expected = "Enabled: Redirection Guard Enabled"
    
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableRedirectionGuard" -ErrorAction SilentlyContinue
    if ($policy -and $policy.EnableRedirectionGuard -eq 1) {
        $status = "Pass"
        $actual = "'Configure Redirection Guard' is set to 'Enabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = if ($policy) { "'Configure Redirection Guard' is set to $($policy.EnableRedirectionGuard)" } else { "Not Configured" }
        $remediation = "Enable Redirection Guard via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}

function Test-CIS_18_7_3 {
    $control = "CIS_Win_18_7_3"
    $title = "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"
    $expected = "Enabled: RPC over TCP"
    
    # Check RPC protocol for outgoing connections
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RPC" -Name "UseRpcOverTcp"
    if ($policy.UseRpcOverTcp -eq 1) {
        $status = "Pass"
        $actual = "'RPC over TCP' is enabled for outgoing connections"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'RPC over TCP' is not enabled"
        $remediation = "Enable RPC over TCP via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_7_4 {
    $control = "CIS_Win_18_7_4"
    $title = "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
    $expected = "Enabled: Default"
    
    # Check RPC authentication setting for outgoing connections
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RPC" -Name "UseRpcAuthentication"
    if ($policy.UseRpcAuthentication -eq 1) {
        $status = "Pass"
        $actual = "'Use authentication for outgoing RPC connections' is set to 'Enabled: Default'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Use authentication for outgoing RPC connections' is not enabled"
        $remediation = "Enable authentication for RPC via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_7_5 {
    $control = "CIS_Win_18_7_5"
    $title = "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
    $expected = "Enabled: RPC over TCP"
    
    # Check RPC protocol for incoming connections
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RPC" -Name "AllowRpcTcp"
    if ($policy.AllowRpcTcp -eq 1) {
        $status = "Pass"
        $actual = "'RPC over TCP' is allowed for incoming RPC connections"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'RPC over TCP' is not allowed for incoming RPC connections"
        $remediation = "Allow RPC over TCP via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_7_6 {
    $control = "CIS_Win_18_7_6"
    $title = "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections' is set to 'Enabled: Negotiate'"
    $expected = "Enabled: Negotiate"
    
    # Check RPC authentication protocol for incoming connections
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RPC" -Name "RpcAuthenticationProtocol"
    if ($policy.RpcAuthenticationProtocol -eq 2) {
        $status = "Pass"
        $actual = "'Authentication protocol for incoming RPC connections' is set to 'Negotiate'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Authentication protocol for incoming RPC connections' is not set to 'Negotiate'"
        $remediation = "Set to Negotiate via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



# function Test-CIS_18_7_7 {
#     $control = "CIS_Win_18_7_7"
#     $title = "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"
#     $expected = "Enabled: 0"
    
#     # Check the RPC over TCP port setting
#     $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RPC" -Name "RpcPort"
#     if ($policy.RpcPort -eq 0) {
#         $status = "Pass"
#         $actual = "'RPC over TCP port' is set to 0"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'RPC over TCP port' is set to $($policy.RpcPort)"
#         $remediation = "Set RPCPort to 0 via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_18_7_7 {
    $control = "CIS_Win_18_7_7"
    $title = "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'"
    $expected = "Enabled: 0"

    try {
        $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RPC" -Name "RpcPort" -ErrorAction Stop
        if ($policy.RpcPort -eq 0) {
            $status = "Pass"
            $actual = "0"
            $remediation = "No action required"
        } else {
            $status = "Fail"
            $actual = "$($policy.RpcPort)"
            $remediation = "Set RpcPort to 0 (Disabled)"
        }
    } catch {
        $status = "Fail"
        $actual = "Not Configured"
        $remediation = "Set RpcPort to 0 (Disabled)"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_7_8 {
    $control = "CIS_Win_18_7_8"
    $title = "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check print driver installation policy
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RestrictDriverInstallationToAdministrators"
    if ($policy.RestrictDriverInstallationToAdministrators -eq 1) {
        $status = "Pass"
        $actual = "'Limits print driver installation to Administrators' is set to 'Enabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Limits print driver installation to Administrators' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_7_9 {
    $control = "CIS_Win_18_7_9"
    $title = "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'"
    $expected = "Enabled: Limit Queue-specific files to Color profiles"
    
    # Check if Queue-specific files are limited to color profiles
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "LimitQueueSpecificFilesToColorProfiles"
    if ($policy.LimitQueueSpecificFilesToColorProfiles -eq 1) {
        $status = "Pass"
        $actual = "'Queue-specific files are limited to Color profiles'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Queue-specific files' are not limited to color profiles"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_7_10 {
    $control = "CIS_Win_18_7_10"
    $title = "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'"
    $expected = "Enabled: Show warning and elevation prompt"
    
    # Check Point and Print Restrictions for installing drivers
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PointAndPrintNoWarnNoElevation"
    if ($policy.PointAndPrintNoWarnNoElevation -eq 1) {
        $status = "Fail"
        $actual = "'Show warning and elevation prompt' is not enabled"
        $remediation = "Enable via registry"
    }
    else {
        $status = "Pass"
        $actual = "'Show warning and elevation prompt' is enabled"
        $remediation = "No action required"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_7_11 {
    $control = "CIS_Win_18_7_11"
    $title = "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'"
    $expected = "Enabled: Show warning and elevation prompt"
    
    # Check Point and Print Restrictions for updating drivers
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PointAndPrintNoWarnNoElevationUpdate"
    if ($policy.PointAndPrintNoWarnNoElevationUpdate -eq 1) {
        $status = "Fail"
        $actual = "'Show warning and elevation prompt' for updating drivers is not enabled"
        $remediation = "Enable via registry"
    }
    else {
        $status = "Pass"
        $actual = "'Show warning and elevation prompt' for updating drivers is enabled"
        $remediation = "No action required"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_9_3_1 {
    $control = "CIS_Win_18_9_3_1"
    $title = "Ensure 'Include command line in process creation events' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if the command line is included in process creation events
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "IncludeCmdLineInProcCreation"
    if ($policy.IncludeCmdLineInProcCreation -eq 1) {
        $status = "Pass"
        $actual = "'Include command line in process creation events' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Include command line in process creation events' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_4_1 {
    $control = "CIS_Win_18_9_4_1"
    $title = "Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"
    $expected = "Enabled: Force Updated Clients"
    
    # Check Encryption Oracle Remediation policy
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EncryptionOracleRemediation"
    if ($policy.EncryptionOracleRemediation -eq 1) {
        $status = "Pass"
        $actual = "'Encryption Oracle Remediation' is set to 'Force Updated Clients'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Encryption Oracle Remediation' is not set to 'Force Updated Clients'"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_4_2 {
    $control = "CIS_Win_18_9_4_2"
    $title = "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check Remote host delegation of non-exportable credentials
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllowDelegationOfNonExportableCredentials"
    if ($policy.AllowDelegationOfNonExportableCredentials -eq 1) {
        $status = "Pass"
        $actual = "'Remote host allows delegation of non-exportable credentials' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Remote host allows delegation of non-exportable credentials' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_5_2 {
    $control = "CIS_Win_18_9_5_2"
    $title = "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher"
    $expected = "Secure Boot or higher"
    
    # Check Virtualization Based Security platform security level
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "PlatformSecurityLevel"
    if ($policy.PlatformSecurityLevel -eq "Secure Boot") {
        $status = "Pass"
        $actual = "'Platform Security Level' is set to 'Secure Boot'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Platform Security Level' is not set to 'Secure Boot'"
        $remediation = "Configure via Device Guard settings"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_5_3 {
    $control = "CIS_Win_18_9_5_3"
    $title = "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
    $expected = "Enabled with UEFI lock"
    
    # Check Virtualization Based Protection of Code Integrity setting
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "CodeIntegrityEnabled"
    if ($policy.CodeIntegrityEnabled -eq 1) {
        $status = "Pass"
        $actual = "'Virtualization Based Protection of Code Integrity' is enabled with UEFI lock"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Virtualization Based Protection of Code Integrity' is not enabled with UEFI lock"
        $remediation = "Enable via Device Guard settings"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_5_4 {
    $control = "CIS_Win_18_9_5_4"
    $title = "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    $expected = "True (checked)"
    
    # Check UEFI Memory Attributes Table
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "UEFIMemoryAttributesTable"
    if ($policy.UEFIMemoryAttributesTable -eq 1) {
        $status = "Pass"
        $actual = "'UEFI Memory Attributes Table' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'UEFI Memory Attributes Table' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_9_5_5 {
    $control = "CIS_Win_18_9_5_5"
    $title = "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
    $expected = "Enabled with UEFI lock"
    
    # Check Credential Guard Configuration
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "CredentialGuard"
    if ($policy.CredentialGuard -eq 1) {
        $status = "Pass"
        $actual = "'Credential Guard Configuration' is enabled with UEFI lock"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Credential Guard Configuration' is not enabled with UEFI lock"
        $remediation = "Enable via Device Guard settings"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_9_5_6 {
    $control = "CIS_Win_18_9_5_6"
    $title = "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check Secure Launch Configuration
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "SecureLaunch"
    if ($policy.SecureLaunch -eq 1) {
        $status = "Pass"
        $actual = "'Secure Launch Configuration' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Secure Launch Configuration' is not enabled"
        $remediation = "Enable via Device Guard settings"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_9_5_7 {
    $control = "CIS_Win_18_9_5_7"
    $title = "Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode'"
    $expected = "Enabled in enforcement mode"
    
    # Check Kernel-mode Hardware-enforced Stack Protection
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -Name "KernelStackProtection"
    if ($policy.KernelStackProtection -eq 1) {
        $status = "Pass"
        $actual = "'Kernel-mode Hardware-enforced Stack Protection' is enabled in enforcement mode"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Kernel-mode Hardware-enforced Stack Protection' is not enabled in enforcement mode"
        $remediation = "Enable via Device Guard settings"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_7_2 {
    $control = "CIS_Win_18_9_7_2"
    $title = "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check Device Metadata Retrieval
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceMetadata" -Name "PreventDeviceMetadataRetrieval"
    if ($policy.PreventDeviceMetadataRetrieval -eq 1) {
        $status = "Pass"
        $actual = "'Device metadata retrieval from the Internet' is prevented"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Device metadata retrieval from the Internet' is not prevented"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_13_1 {
    $control = "CIS_Win_18_9_13_1"
    $title = "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    $expected = "Enabled: Good, unknown and bad but critical"
    
    # Check Boot-Start Driver Initialization Policy
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall" -Name "BootStartPolicy"
    if ($policy.BootStartPolicy -eq 1) {
        $status = "Pass"
        $actual = "'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Boot-Start Driver Initialization Policy' is not set correctly"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



# function Test-CIS_18_9_19_2 {
#     $control = "CIS_Win_18_9_19_2"
#     $title = "Ensure 'Continue experiences on this device' is set to 'Disabled'"
#     $expected = "Disabled"
    
#     # Check Continue Experiences setting
#     $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled"
#     if ($policy.SubscribedContent-338389Enabled -eq 0) {
#         $status = "Pass"
#         $actual = "'Continue experiences on this device' is disabled"
#         $remediation = "No action required"
#     }
#     else {
#         $status = "Fail"
#         $actual = "'Continue experiences on this device' is not disabled"
#         $remediation = "Disable via registry"
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

function Test-CIS_18_9_19_2 {
    $control = "CIS_Win_18_9_19_2"
    $title = "Ensure 'Continue experiences on this device' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue
    if ($policy.EnableCdp -eq 0) {
        $status = "Pass"
        $actual = "'Continue experiences on this device' is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "'Continue experiences on this device' is enabled"
        $remediation = "Set 'EnableCdp' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_9_20_1_2 {
    $control = "CIS_Win_18_9_20_1_2"
    $title = "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check for the setting "Turn off downloading of print drivers over HTTP"
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPDriverDownload"
    if ($policy.DisableHTTPDriverDownload -eq 1) {
        $status = "Pass"
        $actual = "'Downloading print drivers over HTTP' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Downloading print drivers over HTTP' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_9_20_1_6 {
    $control = "CIS_Win_18_9_20_1_6"
    $title = "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check for the setting "Turn off Internet download for Web publishing"
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "DisableWebPublish"
    if ($policy.DisableWebPublish -eq 1) {
        $status = "Pass"
        $actual = "'Internet download for Web publishing' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Internet download for Web publishing' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_26_1 {
    $control = "CIS_Win_18_9_26_1"
    $title = "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check Allow Custom SSPs and APs setting in LSASS
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllowSSP"
    if ($policy.AllowSSP -eq 0) {
        $status = "Pass"
        $actual = "'Allow Custom SSPs and APs to be loaded into LSASS' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Allow Custom SSPs and APs to be loaded into LSASS' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_26_2 {
    $control = "CIS_Win_18_9_26_2"
    $title = "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'"
    $expected = "Enabled with UEFI Lock"
    
    # Check LSASS protected process configuration
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LSASSProtected"
    if ($policy.LSASSProtected -eq 1) {
        $status = "Pass"
        $actual = "'LSASS to run as a protected process' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'LSASS to run as a protected process' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_28_1 {
    $control = "CIS_Win_18_9_28_1"
    $title = "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if account details are blocked on sign-in
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockUserAccountDetails"
    if ($policy.BlockUserAccountDetails -eq 1) {
        $status = "Pass"
        $actual = "'Block user from showing account details on sign-in' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Block user from showing account details on sign-in' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_28_2 {
    $control = "CIS_Win_18_9_28_2"
    $title = "Ensure 'Do not display network selection UI' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if network selection UI is disabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoNetworkSelectionUI"
    if ($policy.NoNetworkSelectionUI -eq 1) {
        $status = "Pass"
        $actual = "'Network selection UI' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network selection UI' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_9_28_3 {
    $control = "CIS_Win_18_9_28_3"
    $title = "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if app notifications on the lock screen are turned off
    $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotification"
    if ($policy.NoToastApplicationNotification -eq 1) {
        $status = "Pass"
        $actual = "'App notifications on the lock screen' are turned off"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'App notifications on the lock screen' are still turned on"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_28_4 {
    $control = "CIS_Win_18_9_28_4"
    $title = "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if convenience PIN sign-in is turned off
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon"
    if ($policy.AllowDomainPINLogon -eq 0) {
        $status = "Pass"
        $actual = "'Convenience PIN sign-in' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Convenience PIN sign-in' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_33_6_1 {
    $control = "CIS_Win_18_9_33_6_1"
    $title = "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if network connectivity during connected-standby on battery is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ConnectedStandby" -Name "AllowNetworkConnectivityWhileOnBattery"
    if ($policy.AllowNetworkConnectivityWhileOnBattery -eq 0) {
        $status = "Pass"
        $actual = "'Network connectivity during connected-standby (on battery)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network connectivity during connected-standby (on battery)' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_33_6_2 {
    $control = "CIS_Win_18_9_33_6_2"
    $title = "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if network connectivity during connected-standby when plugged in is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ConnectedStandby" -Name "AllowNetworkConnectivityWhilePluggedIn"
    if ($policy.AllowNetworkConnectivityWhilePluggedIn -eq 0) {
        $status = "Pass"
        $actual = "'Network connectivity during connected-standby (plugged in)' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Network connectivity during connected-standby (plugged in)' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_33_6_5 {
    $control = "CIS_Win_18_9_33_6_5"
    $title = "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if password is required when the computer wakes up while on battery
    $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverGracePeriod"
    if ($policy.ScreenSaverGracePeriod -eq 1) {
        $status = "Pass"
        $actual = "'Password required on wake (on battery)' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Password required on wake (on battery)' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_33_6_6 {
    $control = "CIS_Win_18_9_33_6_6"
    $title = "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if password is required when the computer wakes up while plugged in
    $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "PasswordRequiredOnWake"
    if ($policy.PasswordRequiredOnWake -eq 1) {
        $status = "Pass"
        $actual = "'Password required on wake (plugged in)' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Password required on wake (plugged in)' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_35_1 {
    $control = "CIS_Win_18_9_35_1"
    $title = "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if offer remote assistance is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "OfferRemoteAssistance"
    if ($policy.OfferRemoteAssistance -eq 0) {
        $status = "Pass"
        $actual = "'Offer Remote Assistance' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Offer Remote Assistance' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_35_2 {
    $control = "CIS_Win_18_9_35_2"
    $title = "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if solicited remote assistance is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "SolicitedRemoteAssistance"
    if ($policy.SolicitedRemoteAssistance -eq 0) {
        $status = "Pass"
        $actual = "'Solicited Remote Assistance' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Solicited Remote Assistance' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_36_1 {
    $control = "CIS_Win_18_9_36_1"
    $title = "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if RPC Endpoint Mapper Client Authentication is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc" -Name "EnableEndpointMapperAuthentication"
    if ($policy.EnableEndpointMapperAuthentication -eq 1) {
        $status = "Pass"
        $actual = "'RPC Endpoint Mapper Client Authentication' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'RPC Endpoint Mapper Client Authentication' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_9_36_2 {
    $control = "CIS_Win_18_9_36_2"
    $title = "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
    $expected = "Enabled: Authenticated"
    
    # Check if unauthenticated RPC clients are restricted to authenticated only
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc" -Name "RestrictAnonymousRPCClients"
    if ($policy.RestrictAnonymousRPCClients -eq 1) {
        $status = "Pass"
        $actual = "'Restrict Unauthenticated RPC clients' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Restrict Unauthenticated RPC clients' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_9_51_1_1 {
    $control = "CIS_Win_18_9_51_1_1"
    $title = "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if the NTP Client is enabled
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpClient"
    if ($policy.NtpClient -eq 1) {
        $status = "Pass"
        $actual = "'Windows NTP Client' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Windows NTP Client' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_3_2 {
    $control = "CIS_Win_18_10_3_2"
    $title = "Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if non-admin users are prevented from installing packaged apps
    $policy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "DisableNonAdminUserAppInstall"
    if ($policy.DisableNonAdminUserAppInstall -eq 1) {
        $status = "Pass"
        $actual = "'Non-admin users' are prevented from installing packaged Windows apps"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Non-admin users' can install packaged apps"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_4_1 {
    $control = "CIS_Win_18_10_4_1"
    $title = "Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny'"
    $expected = "Enabled: Force Deny"
    
    # Check if voice activation on the lock screen is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Voice" -Name "VoiceActivationWhenLocked"
    if ($policy.VoiceActivationWhenLocked -eq 0) {
        $status = "Pass"
        $actual = "'Let Windows apps activate with voice while the system is locked' is set to 'Force Deny'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Let Windows apps activate with voice while the system is locked' is not set to 'Force Deny'"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_5_1 {
    $control = "CIS_Win_18_10_5_1"
    $title = "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if Microsoft accounts are optional
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllowMicrosoftAccounts"
    if ($policy.AllowMicrosoftAccounts -eq 1) {
        $status = "Pass"
        $actual = "'Allow Microsoft accounts to be optional' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Allow Microsoft accounts to be optional' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_7_1 {
    $control = "CIS_Win_18_10_7_1"
    $title = "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if Autoplay is disallowed for non-volume devices
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoplayForNonVolumeDevices"
    if ($policy.NoAutoplayForNonVolumeDevices -eq 1) {
        $status = "Pass"
        $actual = "'Autoplay for non-volume devices' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Autoplay for non-volume devices' is enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_7_2 {
    $control = "CIS_Win_18_10_7_2"
    $title = "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
    $expected = "Enabled: Do not execute any autorun commands"
    
    # Check if AutoRun commands are disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun"
    if ($policy.NoAutorun -eq 1) {
        $status = "Pass"
        $actual = "'AutoRun commands' are disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'AutoRun commands' are enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_7_3 {
    $control = "CIS_Win_18_10_7_3"
    $title = "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
    $expected = "Enabled: All drives"
    
    # Check if AutoPlay is disabled for all drives
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoplay"
    if ($policy.NoAutoplay -eq 1) {
        $status = "Pass"
        $actual = "'Autoplay' is turned off for all drives"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Autoplay' is enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_8_1_1 {
    $control = "CIS_Win_18_10_8_1_1"
    $title = "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if enhanced anti-spoofing is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnhancedAntiSpoofing"
    if ($policy.EnhancedAntiSpoofing -eq 1) {
        $status = "Pass"
        $actual = "'Enhanced anti-spoofing' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Enhanced anti-spoofing' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_12_1 {
    $control = "CIS_Win_18_10_12_1"
    $title = "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if cloud consumer account state content is turned off
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoCloudConsumer"
    if ($policy.NoCloudConsumer -eq 1) {
        $status = "Pass"
        $actual = "'Cloud consumer account state content' is turned off"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Cloud consumer account state content' is not turned off"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_12_3 {
    $control = "CIS_Win_18_10_12_3"
    $title = "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if Microsoft consumer experiences are turned off
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableConsumerFeatures"
    if ($policy.DisableConsumerFeatures -eq 1) {
        $status = "Pass"
        $actual = "'Microsoft consumer experiences' is turned off"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Microsoft consumer experiences' is not turned off"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_13_1 {
    $control = "CIS_Win_18_10_13_1"
    $title = "Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
    $expected = "Enabled: First Time"  # This can also be "Enabled: Always"
    
    # Check if PIN is required for Bluetooth pairing
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "BluetoothRequirePin"
    if ($policy.BluetoothRequirePin -eq 1) {
        $status = "Pass"
        $actual = "'Require pin for pairing' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Require pin for pairing' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_14_1 {
    $control = "CIS_Win_18_10_14_1"
    $title = "Ensure 'Do not display the password reveal button' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if the password reveal button is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPasswordReveal"
    if ($policy.NoPasswordReveal -eq 1) {
        $status = "Pass"
        $actual = "'Password reveal button' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Password reveal button' is not disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_14_2 {
    $control = "CIS_Win_18_10_14_2"
    $title = "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if enumerating administrator accounts on elevation is disabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken"
    if ($policy.FilterAdministratorToken -eq 1) {
        $status = "Pass"
        $actual = "'Enumerate administrator accounts on elevation' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Enumerate administrator accounts on elevation' is enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_14_3 {
    $control = "CIS_Win_18_10_14_3"
    $title = "Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if security questions for local accounts are disabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableLocalAccountSecurityQuestions"
    if ($policy.DisableLocalAccountSecurityQuestions -eq 1) {
        $status = "Pass"
        $actual = "'Security questions for local accounts' are disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Security questions for local accounts' are enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_1 {
    $control = "CIS_Win_18_10_15_1"
    $title = "Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'"
    $expected = "Enabled: Diagnostic data off (not recommended)"
    
    # Check if diagnostic data collection is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
    if ($policy.AllowTelemetry -eq 0 -or $policy.AllowTelemetry -eq 1) {
        $status = "Pass"
        $actual = "'Diagnostic Data' collection is set to 'Enabled'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Diagnostic Data' collection is not set to 'Enabled'"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_3 {
    $control = "CIS_Win_18_10_15_3"
    $title = "Ensure 'Disable OneSettings Downloads' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if OneSettings downloads are disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableOneSettings"
    if ($policy.DisableOneSettings -eq 1) {
        $status = "Pass"
        $actual = "'OneSettings downloads' are disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'OneSettings downloads' are not disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_4 {
    $control = "CIS_Win_18_10_15_4"
    $title = "Ensure 'Do not show feedback notifications' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if feedback notifications are disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisableFeedbackNotifications"
    if ($policy.DisableFeedbackNotifications -eq 1) {
        $status = "Pass"
        $actual = "'Feedback notifications' are disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Feedback notifications' are not disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_5 {
    $control = "CIS_Win_18_10_15_5"
    $title = "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if OneSettings auditing is enabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableOneSettingsAuditing"
    if ($policy.EnableOneSettingsAuditing -eq 1) {
        $status = "Pass"
        $actual = "'OneSettings Auditing' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'OneSettings Auditing' is not enabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_6 {
    $control = "CIS_Win_18_10_15_6"
    $title = "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if diagnostic log collection is limited
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection"
    if ($policy.LimitDiagnosticLogCollection -eq 1) {
        $status = "Pass"
        $actual = "'Diagnostic log collection' is limited"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Diagnostic log collection' is not limited"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_7 {
    $control = "CIS_Win_18_10_15_7"
    $title = "Ensure 'Limit Dump Collection' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if dump collection is limited
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LimitDumpCollection"
    if ($policy.LimitDumpCollection -eq 1) {
        $status = "Pass"
        $actual = "'Dump collection' is limited"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Dump collection' is not limited"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_15_8 {
    $control = "CIS_Win_18_10_15_8"
    $title = "Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if user control over Insider builds is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Group Policy\History" -Name "EnableInsiderBuilds"
    if ($policy.EnableInsiderBuilds -eq 0) {
        $status = "Pass"
        $actual = "'Control over Insider builds' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Control over Insider builds' is not disabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_16_1 {
    $control = "CIS_Win_18_10_16_1"
    $title = "Ensure 'Download Mode' is NOT set to 'Enabled: Internet'"
    $expected = "Disabled"
    
    # Check if Download Mode is set to 'Internet'
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "DownloadMode"
    if ($policy.DownloadMode -ne 1) {
        $status = "Pass"
        $actual = "'Download Mode' is not set to 'Enabled: Internet'"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Download Mode' is set to 'Enabled: Internet'"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_17_1 {
    $control = "CIS_Win_18_10_17_1"
    $title = "Ensure 'Enable App Installer' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if App Installer is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableAppInstaller"
    if ($policy.EnableAppInstaller -eq 0) {
        $status = "Pass"
        $actual = "'App Installer' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'App Installer' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_17_2 {
    $control = "CIS_Win_18_10_17_2"
    $title = "Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if App Installer Experimental Features are disabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableAppInstallerExperimentalFeatures"
    if ($policy.EnableAppInstallerExperimentalFeatures -eq 0) {
        $status = "Pass"
        $actual = "'App Installer Experimental Features' are disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'App Installer Experimental Features' are enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_17_3 {
    $control = "CIS_Win_18_10_17_3"
    $title = "Ensure 'Enable App Installer Hash Override' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if App Installer Hash Override is disabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableAppInstallerHashOverride"
    if ($policy.EnableAppInstallerHashOverride -eq 0) {
        $status = "Pass"
        $actual = "'App Installer Hash Override' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'App Installer Hash Override' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_17_4 {
    $control = "CIS_Win_18_10_17_4"
    $title = "Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if ms-appinstaller protocol is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Classes" -Name "ms-appinstaller"
    if ($policy.'ms-appinstaller' -eq $null) {
        $status = "Pass"
        $actual = "'ms-appinstaller' protocol is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'ms-appinstaller' protocol is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_25_1_1 {
    $control = "CIS_Win_18_10_25_1_1"
    $title = "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Application Event Log behavior is controlled
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\Application" -Name "Retention"
    if ($policy.Retention -eq 0) {
        $status = "Pass"
        $actual = "'Event Log retention' behavior is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Event Log retention' behavior is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_25_1_2 {
    $control = "CIS_Win_18_10_25_1_2"
    $title = "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $expected = "Enabled"
    
    # Check the maximum size for Application Event Log
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize"
    if ($policy.MaxSize -ge 32768) {
        $status = "Pass"
        $actual = "'Application Event Log size' is 32,768 KB or greater"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Application Event Log size' is less than 32,768 KB"
        $remediation = "Increase via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_25_2_1 {
    $control = "CIS_Win_18_10_25_2_1"
    $title = "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Security Event Log behavior is controlled
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\Security" -Name "Retention"
    if ($policy.Retention -eq 0) {
        $status = "Pass"
        $actual = "'Security Event Log retention' behavior is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Security Event Log retention' behavior is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_25_2_2 {
    $control = "CIS_Win_18_10_25_2_2"
    $title = "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
    $expected = "Enabled"
    
    # Check the maximum size for Security Event Log
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize"
    if ($policy.MaxSize -ge 196608) {
        $status = "Pass"
        $actual = "'Security Event Log size' is 196,608 KB or greater"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Security Event Log size' is less than 196,608 KB"
        $remediation = "Increase via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_25_3_1 {
    $control = "CIS_Win_18_10_25_3_1"
    $title = "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Setup Event Log behavior is controlled
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\Setup" -Name "Retention"
    if ($policy.Retention -eq 0) {
        $status = "Pass"
        $actual = "'Setup Event Log retention' behavior is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Setup Event Log retention' behavior is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_25_3_2 {
    $control = "CIS_Win_18_10_25_3_2"
    $title = "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $expected = "Enabled"
    
    # Check the maximum size for Setup Event Log
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\Setup" -Name "MaxSize"
    if ($policy.MaxSize -ge 32768) {
        $status = "Pass"
        $actual = "'Setup Event Log size' is 32,768 KB or greater"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Setup Event Log size' is less than 32,768 KB"
        $remediation = "Increase via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_25_4_1 {
    $control = "CIS_Win_18_10_25_4_1"
    $title = "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if System Event Log behavior is controlled
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\System" -Name "Retention"
    if ($policy.Retention -eq 0) {
        $status = "Pass"
        $actual = "'System Event Log retention' behavior is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'System Event Log retention' behavior is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_25_4_2 {
    $control = "CIS_Win_18_10_25_4_2"
    $title = "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $expected = "Enabled"
    
    # Check the maximum size for System Event Log
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\EventLog\System" -Name "MaxSize"
    if ($policy.MaxSize -ge 32768) {
        $status = "Pass"
        $actual = "'System Event Log size' is 32,768 KB or greater"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'System Event Log size' is less than 32,768 KB"
        $remediation = "Increase via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_28_3 {
    $control = "CIS_Win_18_10_28_3"
    $title = "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Data Execution Prevention is off for Explorer
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" -Name "DisableDEPForExplorer"
    if ($policy.DisableDEPForExplorer -eq 0) {
        $status = "Pass"
        $actual = "'Data Execution Prevention' for Explorer is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Data Execution Prevention' for Explorer is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_28_4 {
    $control = "CIS_Win_18_10_28_4"
    $title = "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if heap termination on corruption is turned off
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Name "HeapTerminationOnCorruption"
    if ($policy.HeapTerminationOnCorruption -eq 0) {
        $status = "Pass"
        $actual = "'Heap termination on corruption' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Heap termination on corruption' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_28_5 {
    $control = "CIS_Win_18_10_28_5"
    $title = "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if shell protocol protected mode is turned off
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "ShellProtocolProtectedMode"
    if ($policy.ShellProtocolProtectedMode -eq 0) {
        $status = "Pass"
        $actual = "'Shell Protocol Protected Mode' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Shell Protocol Protected Mode' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_41_1 {
    $control = "CIS_Win_18_10_41_1"
    $title = "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if Microsoft account authentication is blocked
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AccountManager" -Name "BlockMicrosoftAccount"
    if ($policy.BlockMicrosoftAccount -eq 1) {
        $status = "Pass"
        $actual = "'Consumer Microsoft account user authentication' is blocked"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Consumer Microsoft account user authentication' is allowed"
        $remediation = "Block via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_5_1 {
    $control = "CIS_Win_18_10_42_5_1"
    $title = "Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if local setting override for Microsoft MAPS reporting is disabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "EnableLocalSetting"
    if ($policy.EnableLocalSetting -eq 0) {
        $status = "Pass"
        $actual = "'Local setting override for Microsoft MAPS' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Local setting override for Microsoft MAPS' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_6_1_1 {
    $control = "CIS_Win_18_10_42_6_1_1"
    $title = "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if Attack Surface Reduction rules are enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\ASR" -Name "EnableAttackSurfaceReduction"
    if ($policy.EnableAttackSurfaceReduction -eq 1) {
        $status = "Pass"
        $actual = "'Attack Surface Reduction rules' are enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Attack Surface Reduction rules' are disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_6_1_2 {
    $control = "CIS_Win_18_10_42_6_1_2"
    $title = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured"
    $expected = "Configured"
    
    # Check if the state for ASR rules is set
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\ASR" -Name "ASRRuleState"
    if ($policy.ASRRuleState) {
        $status = "Pass"
        $actual = "'ASR Rule state' is configured"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'ASR Rule state' is not configured"
        $remediation = "Configure the ASR rule states via Group Policy"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_42_6_3_1 {
    $control = "CIS_Win_18_10_42_6_3_1"
    $title = "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
    $expected = "Enabled"
    
    # Check if blocking of dangerous websites is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SmartScreen" -Name "EnableAppInstallControl"
    if ($policy.EnableAppInstallControl -eq 1) {
        $status = "Pass"
        $actual = "'Prevent users and apps from accessing dangerous websites' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Prevent users and apps from accessing dangerous websites' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_7_1 {
    $control = "CIS_Win_18_10_42_7_1"
    $title = "Ensure 'Enable file hash computation feature' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if file hash computation feature is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Features" -Name "EnableFileHashComputation"
    if ($policy.EnableFileHashComputation -eq 1) {
        $status = "Pass"
        $actual = "'File hash computation feature' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'File hash computation feature' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_10_1 {
    $control = "CIS_Win_18_10_42_10_1"
    $title = "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if all downloaded files and attachments are being scanned
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "ScanFiles"
    if ($policy.ScanFiles -eq 1) {
        $status = "Pass"
        $actual = "'Scan all downloaded files and attachments' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Scan all downloaded files and attachments' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_10_2 {
    $control = "CIS_Win_18_10_42_10_2"
    $title = "Ensure 'Turn off real-time protection' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if real-time protection is turned off
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring"
    if ($policy.DisableRealtimeMonitoring -eq 0) {
        $status = "Pass"
        $actual = "'Real-time protection' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Real-time protection' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_10_3 {
    $control = "CIS_Win_18_10_42_10_3"
    $title = "Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if behavior monitoring is turned on
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Behavior Monitoring" -Name "EnableBehaviorMonitoring"
    if ($policy.EnableBehaviorMonitoring -eq 1) {
        $status = "Pass"
        $actual = "'Behavior monitoring' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Behavior monitoring' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_10_4 {
    $control = "CIS_Win_18_10_42_10_4"
    $title = "Ensure 'Turn on script scanning' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if script scanning is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\ScriptScanning" -Name "EnableScriptScanning"
    if ($policy.EnableScriptScanning -eq 1) {
        $status = "Pass"
        $actual = "'Script scanning' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Script scanning' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_13_1 {
    $control = "CIS_Win_18_10_42_13_1"
    $title = "Ensure 'Scan packed executables' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if packed executables are being scanned
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusion" -Name "ScanPackedExecutables"
    if ($policy.ScanPackedExecutables -eq 1) {
        $status = "Pass"
        $actual = "'Scan packed executables' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Scan packed executables' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_42_13_2 {
    $control = "CIS_Win_18_10_42_13_2"
    $title = "Ensure 'Scan removable drives' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if removable drives are being scanned
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Removable" -Name "ScanRemovable"
    if ($policy.ScanRemovable -eq 1) {
        $status = "Pass"
        $actual = "'Scan removable drives' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Scan removable drives' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_13_3 {
    $control = "CIS_Win_18_10_42_13_3"
    $title = "Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if e-mail scanning is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Email" -Name "EnableEmailScanning"
    if ($policy.EnableEmailScanning -eq 1) {
        $status = "Pass"
        $actual = "'Email scanning' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Email scanning' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_16 {
    $control = "CIS_Win_18_10_42_16"
    $title = "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    $expected = "Enabled"
    
    # Check if detection for potentially unwanted applications is set to Block
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\PUA" -Name "EnablePUADetection"
    if ($policy.EnablePUADetection -eq 1) {
        $status = "Pass"
        $actual = "'Detection for potentially unwanted applications' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Detection for potentially unwanted applications' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_42_17 {
    $control = "CIS_Win_18_10_42_17"
    $title = "Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Microsoft Defender AntiVirus is turned off
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus"
    if ($policy.DisableAntiVirus -eq 0) {
        $status = "Pass"
        $actual = "'Microsoft Defender AntiVirus' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Microsoft Defender AntiVirus' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_43_1 {
    $control = "CIS_Win_18_10_43_1"
    $title = "Ensure 'Allow auditing events in Microsoft Defender Application Guard' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if auditing events are allowed in Microsoft Defender Application Guard
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Application Guard" -Name "AllowAuditEvents"
    if ($policy.AllowAuditEvents -eq 1) {
        $status = "Pass"
        $actual = "'Auditing events in Microsoft Defender Application Guard' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Auditing events in Microsoft Defender Application Guard' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_43_2 {
    $control = "CIS_Win_18_10_43_2"
    $title = "Ensure 'Allow camera and microphone access in Microsoft Defender Application Guard' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if camera and microphone access is allowed in Microsoft Defender Application Guard
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Application Guard" -Name "AllowCameraMicrophone"
    if ($policy.AllowCameraMicrophone -eq 0) {
        $status = "Pass"
        $actual = "'Camera and microphone access in Microsoft Defender Application Guard' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Camera and microphone access in Microsoft Defender Application Guard' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_43_3 {
    $control = "CIS_Win_18_10_43_3"
    $title = "Ensure 'Allow data persistence for Microsoft Defender Application Guard' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if data persistence is allowed in Microsoft Defender Application Guard
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Application Guard" -Name "AllowDataPersistence"
    if ($policy.AllowDataPersistence -eq 0) {
        $status = "Pass"
        $actual = "'Data persistence in Microsoft Defender Application Guard' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Data persistence in Microsoft Defender Application Guard' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_43_4 {
    $control = "CIS_Win_18_10_43_4"
    $title = "Ensure 'Allow files to download and save to the host operating system from Microsoft Defender Application Guard' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if files can be downloaded and saved to host OS
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Application Guard" -Name "AllowFileDownload"
    if ($policy.AllowFileDownload -eq 0) {
        $status = "Pass"
        $actual = "'File download to host OS from Microsoft Defender Application Guard' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'File download to host OS from Microsoft Defender Application Guard' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_43_5 {
    $control = "CIS_Win_18_10_43_5"
    $title = "Ensure 'Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host'"
    $expected = "Enabled"
    
    # Check if clipboard operation from isolated session to the host is enabled
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Application Guard" -Name "AllowClipboardToHost"
    if ($policy.AllowClipboardToHost -eq 1) {
        $status = "Pass"
        $actual = "'Clipboard operation from isolated session to host' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Clipboard operation from isolated session to host' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_43_6 {
    $control = "CIS_Win_18_10_43_6"
    $title = "Ensure 'Turn on Microsoft Defender Application Guard in Managed Mode' is set to 'Enabled: 1'"
    $expected = "Enabled: 1"
    
    # Check if Microsoft Defender Application Guard is turned on in Managed Mode
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Application Guard" -Name "EnableApplicationGuard"
    if ($policy.EnableApplicationGuard -eq 1) {
        $status = "Pass"
        $actual = "'Microsoft Defender Application Guard in Managed Mode' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Microsoft Defender Application Guard in Managed Mode' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_50_1 {
    $control = "CIS_Win_18_10_50_1"
    $title = "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if OneDrive is disabled for file storage
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync"
    if ($policy.DisableFileSync -eq 1) {
        $status = "Pass"
        $actual = "'OneDrive file storage usage' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'OneDrive file storage usage' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_10_56_2_3 {
    $control = "CIS_Win_18_10_56_2_3"
    $title = "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if saving passwords is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "DoNotSavePasswords"
    if ($policy.DoNotSavePasswords -eq 1) {
        $status = "Pass"
        $actual = "'Saving passwords' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Saving passwords' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_10_56_3_3_3 {
    $control = "CIS_Win_18_10_56_3_3_3"
    $title = "Ensure 'Do not allow drive redirection' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if drive redirection is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives"
    if ($policy.NoDrives -eq 1) {
        $status = "Pass"
        $actual = "'Drive redirection' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Drive redirection' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_56_3_9_1 {
    $control = "CIS_Win_18_10_56_3_9_1"
    $title = "Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if password prompt upon connection is enabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptForPassword"
    if ($policy.PromptForPassword -eq 1) {
        $status = "Pass"
        $actual = "'Password prompt upon connection' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Password prompt upon connection' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_56_3_9_2 {
    $control = "CIS_Win_18_10_56_3_9_2"
    $title = "Ensure 'Require secure RPC communication' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if secure RPC communication is required
    $policy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\RPC" -Name "RequireSecurity"
    if ($policy.RequireSecurity -eq 1) {
        $status = "Pass"
        $actual = "'Secure RPC communication' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Secure RPC communication' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_56_3_9_3 {
    $control = "CIS_Win_18_10_56_3_9_3"
    $title = "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
    $expected = "Enabled: SSL"
    
    # Check if specific security layer is set to SSL for RDP connections
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer"
    if ($policy.SecurityLayer -eq 1) {
        $status = "Pass"
        $actual = "'Specific security layer for RDP connections' is SSL"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Specific security layer for RDP connections' is not SSL"
        $remediation = "Set via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_56_3_9_4 {
    $control = "CIS_Win_18_10_56_3_9_4"
    $title = "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if user authentication for RDP using Network Level Authentication is required
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "UserAuthentication"
    if ($policy.UserAuthentication -eq 1) {
        $status = "Pass"
        $actual = "'User authentication for remote connections' is enabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'User authentication for remote connections' is disabled"
        $remediation = "Enable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_56_3_9_5 {
    $control = "CIS_Win_18_10_56_3_9_5"
    $title = "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
    $expected = "Enabled: High Level"
    
    # Check if the client connection encryption level is set to High Level
    $policy = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "MinEncryptionLevel"
    if ($policy.MinEncryptionLevel -eq 3) {
        $status = "Pass"
        $actual = "'Client connection encryption level' is set to High"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Client connection encryption level' is not set to High"
        $remediation = "Set via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_56_3_11_1 {
    $control = "CIS_Win_18_10_56_3_11_1"
    $title = "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if the deletion of temp folders upon exit is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DeleteTempFilesOnExit"
    if ($policy.DeleteTempFilesOnExit -eq 0) {
        $status = "Pass"
        $actual = "'Delete temp files on exit' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Delete temp files on exit' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_57_1 {
    $control = "CIS_Win_18_10_57_1"
    $title = "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if the downloading of enclosures is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation"
    if ($policy.SaveZoneInformation -eq 1) {
        $status = "Pass"
        $actual = "'Downloading of enclosures' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Downloading of enclosures' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_58_3 {
    $control = "CIS_Win_18_10_58_3"
    $title = "Ensure 'Allow Cortana' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Cortana is disabled
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowCortana"
    if ($policy.AllowCortana -eq 0) {
        $status = "Pass"
        $actual = "'Cortana' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Cortana' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_10_58_4 {
    $control = "CIS_Win_18_10_58_4"
    $title = "Ensure 'Allow Cortana above lock screen' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Cortana is allowed above the lock screen
    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowCortanaAboveLockScreen"
    if ($policy.AllowCortanaAboveLockScreen -eq 0) {
        $status = "Pass"
        $actual = "'Cortana above lock screen' is disabled"
        $remediation = "No action required"
    }
    else {
        $status = "Fail"
        $actual = "'Cortana above lock screen' is enabled"
        $remediation = "Disable via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_58_5 {
    $control = "CIS_Win_18_10_58_5"
    $title = "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if indexing of encrypted files is disabled
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems"
    if ($policy.AllowIndexingEncryptedStoresOrItems -eq 0) {
        $status = "Pass"
        $actual = "Indexing of encrypted files is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Indexing of encrypted files is enabled"
        $remediation = "Set 'AllowIndexingEncryptedStoresOrItems' to 0 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_58_6 {
    $control = "CIS_Win_18_10_58_6"
    $title = "Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if Cortana/search can use location
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"
    if ($policy.AllowCortana -eq 0) {
        $status = "Pass"
        $actual = "Cortana search location usage is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Cortana search location usage is enabled"
        $remediation = "Set 'AllowCortana' to 0 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_65_2 {
    $control = "CIS_Win_18_10_65_2"
    $title = "Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if only private store is displayed
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps"
    if ($policy.DisableStoreApps -eq 1) {
        $status = "Pass"
        $actual = "Only private store is displayed"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Public store is accessible"
        $remediation = "Set 'DisableStoreApps' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_65_3 {
    $control = "CIS_Win_18_10_65_3"
    $title = "Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check automatic updates setting
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
    if ($policy.NoAutoUpdate -eq 0) {
        $status = "Pass"
        $actual = "Automatic updates are enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Automatic updates are disabled"
        $remediation = "Set 'NoAutoUpdate' to 0 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_65_4 {
    $control = "CIS_Win_18_10_65_4"
    $title = "Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if offer to update Windows is disabled
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableOSUpgrade"
    if ($policy.DisableOSUpgrade -eq 1) {
        $status = "Pass"
        $actual = "Offer to update Windows is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Offer to update Windows is enabled"
        $remediation = "Set 'DisableOSUpgrade' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_10_71_1 {
    $control = "CIS_Win_18_10_71_1"
    $title = "Ensure 'Allow widgets' is set to 'Disabled'"
    $expected = "Disabled"
    
    # Check if widgets are allowed
    $policy = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableWidgets"
    if ($policy.EnableWidgets -eq 0) {
        $status = "Pass"
        $actual = "Widgets are disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Widgets are enabled"
        $remediation = "Set 'EnableWidgets' to 0 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_75_1_1 {
    $control = "CIS_Win_18_10_75_1_1"
    $title = "Ensure 'Automatic Data Collection' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check automatic data collection
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDataCollection"
    if ($policy.AllowDataCollection -eq 1) {
        $status = "Pass"
        $actual = "Automatic Data Collection is enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Automatic Data Collection is disabled"
        $remediation = "Set 'AllowDataCollection' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_75_1_2 {
    $control = "CIS_Win_18_10_75_1_2"
    $title = "Ensure 'Notify Malicious' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if malicious notifications are enabled
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender\SmartScreen" -Name "EnableSmartScreen"
    if ($policy.EnableSmartScreen -eq 1) {
        $status = "Pass"
        $actual = "Malicious notifications are enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Malicious notifications are disabled"
        $remediation = "Set 'EnableSmartScreen' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_75_1_3 {
    $control = "CIS_Win_18_10_75_1_3"
    $title = "Ensure 'Notify Password Reuse' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check password reuse notification setting
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\PasswordPolicies" -Name "EnablePasswordReuseNotification"
    if ($policy.EnablePasswordReuseNotification -eq 1) {
        $status = "Pass"
        $actual = "Password reuse notifications are enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Password reuse notifications are disabled"
        $remediation = "Set 'EnablePasswordReuseNotification' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_10_75_1_4 {
    $control = "CIS_Win_18_10_75_1_4"
    $title = "Ensure 'Notify Unsafe App' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if unsafe app notifications are enabled
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "EnableAppProtection"
    if ($policy.EnableAppProtection -eq 1) {
        $status = "Pass"
        $actual = "Unsafe app notifications are enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Unsafe app notifications are disabled"
        $remediation = "Set 'EnableAppProtection' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_75_1_5 {
    $control = "CIS_Win_18_10_75_1_5"
    $title = "Ensure 'Service Enabled' is set to 'Enabled'"
    $expected = "Enabled"
    
    # Check if the service is enabled
    $policy = Get-Service -Name "WindowsDefender" | Select-Object -ExpandProperty Status
    if ($policy -eq "Running") {
        $status = "Pass"
        $actual = "Windows Defender service is enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Windows Defender service is not running"
        $remediation = "Enable Windows Defender service"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_75_2_1 {
    $control = "CIS_Win_18_10_75_2_1"
    $title = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
    $expected = "Enabled: Warn and prevent bypass"
    
    # Check SmartScreen configuration
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\SmartScreen" -Name "EnableSmartScreen"
    if ($policy.EnableSmartScreen -eq 1) {
        $status = "Pass"
        $actual = "SmartScreen is enabled to warn and prevent bypass"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "SmartScreen is not enabled"
        $remediation = "Set 'EnableSmartScreen' to 1 via registry"
    }
    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_77_1 {
    $control = "CIS_Win_18_10_77_1"
    $title = "Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
    $expected = "Disabled"

    # Check Game DVR setting
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR"
    if ($policy.AllowGameDVR -eq 0) {
        $status = "Pass"
        $actual = "Game Recording and Broadcasting is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Game Recording and Broadcasting is enabled"
        $remediation = "Set 'AllowGameDVR' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_78_1 {
    $control = "CIS_Win_18_10_78_1"
    $title = "Ensure 'Enable ESS with Supported Peripherals' is set to 'Enabled: 1'"
    $expected = "Enabled: 1"

    # Check ESS support setting
    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "EnableESS"
    if ($policy.EnableESS -eq 1) {
        $status = "Pass"
        $actual = "Enhanced Storage Support is enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Enhanced Storage Support is disabled"
        $remediation = "Set 'EnableESS' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_79_2 {
    $control = "CIS_Win_18_10_79_2"
    $title = "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Enabled: Disabled'"
    $expected = "On (disallow above lock) or Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace"
    if ($policy.AllowWindowsInkWorkspace -eq 0 -or $policy.AllowWindowsInkWorkspace -eq 2) {
        $status = "Pass"
        $actual = "Windows Ink Workspace is compliant"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Windows Ink Workspace is non-compliant"
        $remediation = "Set 'AllowWindowsInkWorkspace' to 0 (Disabled) or 2 (On but disallow above lock) via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}




function Test-CIS_18_10_80_1 {
    $control = "CIS_Win_18_10_80_1"
    $title = "Ensure 'Allow user control over installs' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl"
    if ($policy.EnableUserControl -eq 0) {
        $status = "Pass"
        $actual = "User control over installs is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "User control over installs is enabled"
        $remediation = "Set 'EnableUserControl' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_80_2 {
    $control = "CIS_Win_18_10_80_2"
    $title = "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
    if ($policy.AlwaysInstallElevated -eq 0) {
        $status = "Pass"
        $actual = "Always install with elevated privileges is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Always install with elevated privileges is enabled"
        $remediation = "Set 'AlwaysInstallElevated' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_81_1 {
    $control = "CIS_Win_18_10_81_1"
    $title = "Ensure 'Enable MPR notifications for the system' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" -Name "HwNotify"
    if ($policy.HwNotify -eq 0) {
        $status = "Pass"
        $actual = "MPR notifications are disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "MPR notifications are enabled"
        $remediation = "Set 'HwNotify' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_81_2 {
    $control = "CIS_Win_18_10_81_2"
    $title = "Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAutomaticRestartSignOn"
    if ($policy.DisableAutomaticRestartSignOn -eq 1) {
        $status = "Pass"
        $actual = "Automatic sign-in after restart is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Automatic sign-in after restart is enabled"
        $remediation = "Set 'DisableAutomaticRestartSignOn' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_88_1_1 {
    $control = "CIS_Win_18_10_88_1_1"
    $title = "Ensure 'Allow Basic authentication' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic"
    if ($policy.AllowBasic -eq 0) {
        $status = "Pass"
        $actual = "Basic authentication is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Basic authentication is enabled"
        $remediation = "Set 'AllowBasic' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_88_1_2 {
    $control = "CIS_Win_18_10_88_1_2"
    $title = "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic"
    if ($policy.AllowUnencryptedTraffic -eq 0) {
        $status = "Pass"
        $actual = "Unencrypted traffic is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Unencrypted traffic is enabled"
        $remediation = "Set 'AllowUnencryptedTraffic' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_88_1_3 {
    $control = "CIS_Win_18_10_88_1_3"
    $title = "Ensure 'Disallow Digest authentication' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest"
    if ($policy.AllowDigest -eq 0) {
        $status = "Pass"
        $actual = "Digest authentication is disallowed"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Digest authentication is allowed"
        $remediation = "Set 'AllowDigest' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_88_2_1 {
    $control = "CIS_Win_18_10_88_2_1"
    $title = "Ensure 'Allow Basic authentication' is set to 'Disabled' for WinRM Service"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic"
    if ($policy.AllowBasic -eq 0) {
        $status = "Pass"
        $actual = "Basic authentication for WinRM Service is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Basic authentication for WinRM Service is enabled"
        $remediation = "Set 'AllowBasic' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_88_2_3 {
    $control = "CIS_Win_18_10_88_2_3"
    $title = "Ensure 'Allow unencrypted traffic' is set to 'Disabled' for WinRM Service"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic"
    if ($policy.AllowUnencryptedTraffic -eq 0) {
        $status = "Pass"
        $actual = "Unencrypted traffic for WinRM Service is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Unencrypted traffic for WinRM Service is enabled"
        $remediation = "Set 'AllowUnencryptedTraffic' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_88_2_4 {
    $control = "CIS_Win_18_10_88_2_4"
    $title = "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs"
    if ($policy.DisableRunAs -eq 1) {
        $status = "Pass"
        $actual = "WinRM is disallowed from storing RunAs credentials"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "WinRM is allowed to store RunAs credentials"
        $remediation = "Set 'DisableRunAs' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_90_1 {
    $control = "CIS_Win_18_10_90_1"
    $title = "Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection"
    if ($policy.AllowClipboardRedirection -eq 0) {
        $status = "Pass"
        $actual = "Clipboard sharing with Sandbox is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Clipboard sharing with Sandbox is enabled"
        $remediation = "Set 'AllowClipboardRedirection' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_90_2 {
    $control = "CIS_Win_18_10_90_2"
    $title = "Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking"
    if ($policy.AllowNetworking -eq 0) {
        $status = "Pass"
        $actual = "Networking in Sandbox is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Networking in Sandbox is enabled"
        $remediation = "Set 'AllowNetworking' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_91_2_1 {
    $control = "CIS_Win_18_10_91_2_1"
    $title = "Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode"
    if ($policy.DODownloadMode -eq 0) {
        $status = "Pass"
        $actual = "Users are prevented from modifying Delivery Optimization settings"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Users can modify Delivery Optimization settings"
        $remediation = "Set 'DODownloadMode' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_1_1 {
    $control = "CIS_Win_18_10_92_1_1"
    $title = "Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers"
    if ($policy.NoAutoRebootWithLoggedOnUsers -eq 0) {
        $status = "Pass"
        $actual = "Auto-restart is allowed when users are logged on"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Auto-restart is prevented while users are logged on"
        $remediation = "Set 'NoAutoRebootWithLoggedOnUsers' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_2_1 {
    $control = "CIS_Win_18_10_92_2_1"
    $title = "Ensure 'Configure Automatic Updates' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
    if ($policy.NoAutoUpdate -eq 0) {
        $status = "Pass"
        $actual = "Automatic Updates is enabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Automatic Updates is disabled"
        $remediation = "Set 'NoAutoUpdate' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_2_2 {
    $control = "CIS_Win_18_10_92_2_2"
    $title = "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
    $expected = "0 (Every day)"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay"
    if ($policy.ScheduledInstallDay -eq 0) {
        $status = "Pass"
        $actual = "Scheduled install day is set to 0 (Every day)"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Scheduled install day is not set to 0 (Every day)"
        $remediation = "Set 'ScheduledInstallDay' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_2_3 {
    $control = "CIS_Win_18_10_92_2_3"
    $title = "Ensure 'Enable features introduced via servicing that are off by default' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "EnableOptionalUUPContent"
    if ($policy.EnableOptionalUUPContent -eq 0) {
        $status = "Pass"
        $actual = "Optional UUP content is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Optional UUP content is enabled"
        $remediation = "Set 'EnableOptionalUUPContent' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_2_4 {
    $control = "CIS_Win_18_10_92_2_4"
    $title = "Ensure 'Remove access to Pause updates feature' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess"
    if ($policy.SetDisablePauseUXAccess -eq 1) {
        $status = "Pass"
        $actual = "Pause Updates feature is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Pause Updates feature is available"
        $remediation = "Set 'SetDisablePauseUXAccess' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_4_1 {
    $control = "CIS_Win_18_10_92_4_1"
    $title = "Ensure 'Manage preview builds' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds"
    if ($policy.ManagePreviewBuilds -eq 0) {
        $status = "Pass"
        $actual = "Preview builds are disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Preview builds are enabled"
        $remediation = "Set 'ManagePreviewBuilds' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_4_2 {
    $control = "CIS_Win_18_10_92_4_2"
    $title = "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'"
    $expected = "Enabled: 180+ days"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays"
    if ($policy.DeferFeatureUpdatesPeriodInDays -ge 180) {
        $status = "Pass"
        $actual = "Feature updates are deferred $($policy.DeferFeatureUpdatesPeriodInDays) days"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Feature updates are deferred $($policy.DeferFeatureUpdatesPeriodInDays) days (less than 180)"
        $remediation = "Set 'DeferFeatureUpdatesPeriodInDays' to at least 180 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_4_2 {
    $control = "CIS_Win_18_10_92_4_2"
    $title = "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'"
    $expected = "Enabled: 180+ days"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays"
    if ($policy.DeferFeatureUpdatesPeriodInDays -ge 180) {
        $status = "Pass"
        $actual = "Feature updates are deferred $($policy.DeferFeatureUpdatesPeriodInDays) days"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Feature updates are deferred $($policy.DeferFeatureUpdatesPeriodInDays) days (less than 180)"
        $remediation = "Set 'DeferFeatureUpdatesPeriodInDays' to at least 180 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_18_10_92_4_3 {
    $control = "CIS_Win_18_10_92_4_3"
    $title = "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
    $expected = "Enabled: 0 days"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays"
    if ($policy.DeferQualityUpdatesPeriodInDays -eq 0) {
        $status = "Pass"
        $actual = "Quality updates are deferred 0 days"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Quality updates are deferred $($policy.DeferQualityUpdatesPeriodInDays) days"
        $remediation = "Set 'DeferQualityUpdatesPeriodInDays' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_18_10_92_4_4 {
    $control = "CIS_Win_18_10_92_4_4"
    $title = "Ensure 'Enable optional updates' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AllowOptionalContent"
    if ($policy.AllowOptionalContent -eq 0) {
        $status = "Pass"
        $actual = "Optional updates are disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Optional updates are enabled"
        $remediation = "Set 'AllowOptionalContent' to 0 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_5_1_1 {
    $control = "CIS_Win_19_5_1_1"
    $title = "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications"
    if ($policy.DisableLockScreenAppNotifications -eq 1) {
        $status = "Pass"
        $actual = "Toast notifications on lock screen are disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Toast notifications are enabled on lock screen"
        $remediation = "Set 'DisableLockScreenAppNotifications' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_7_5_1 {
    $control = "CIS_Win_19_7_5_1"
    $title = "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation"
    if ($policy.SaveZoneInformation -eq 2 -or $policy.SaveZoneInformation -eq $null) {
        $status = "Pass"
        $actual = "Zone information is preserved in file attachments"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Zone information is not preserved in file attachments"
        $remediation = "Set 'SaveZoneInformation' to 2 (or remove key) via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_7_5_2 {
    $control = "CIS_Win_19_7_5_2"
    $title = "Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus"
    if ($policy.ScanWithAntiVirus -eq 3) {
        $status = "Pass"
        $actual = "Antivirus notification is enabled for file attachments"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Antivirus notification is disabled for file attachments"
        $remediation = "Set 'ScanWithAntiVirus' to 3 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_7_8_1 {
    $control = "CIS_Win_19_7_8_1"
    $title = "Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'"
    $expected = "Disabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight"
    if ($policy.ConfigureWindowsSpotlight -eq 2) {
        $status = "Pass"
        $actual = "Windows Spotlight on lock screen is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Windows Spotlight is enabled on lock screen"
        $remediation = "Set 'ConfigureWindowsSpotlight' to 2 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_7_8_2 {
    $control = "CIS_Win_19_7_8_2"
    $title = "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions"
    if ($policy.DisableThirdPartySuggestions -eq 1) {
        $status = "Pass"
        $actual = "Third-party suggestions in Windows Spotlight are disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Third-party suggestions in Windows Spotlight are enabled"
        $remediation = "Set 'DisableThirdPartySuggestions' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}


function Test-CIS_19_7_8_5 {
    $control = "CIS_Win_19_7_8_5"
    $title = "Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -ErrorAction SilentlyContinue
    if ($policy.DisableSpotlightCollectionOnDesktop -eq 1) {
        $status = "Pass"
        $actual = "Spotlight collection on Desktop is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Spotlight collection on Desktop is enabled"
        $remediation = "Set 'DisableSpotlightCollectionOnDesktop' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_7_26_1 {
    $control = "CIS_Win_19_7_26_1"
    $title = "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
    $expected = "Enabled"

    $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -ErrorAction SilentlyContinue
    if ($policy.NoInplaceSharing -eq 1) {
        $status = "Pass"
        $actual = "Users are prevented from sharing files within their profile"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Users can share files within their profile"
        $remediation = "Set 'NoInplaceSharing' to 1 via registry"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}



function Test-CIS_19_7_42_1 {
    $control = "CIS_Win_19_7_42_1"
    $title = "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    $expected = "Disabled"

    $policyLM = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $policyCU = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

    if (($policyLM.AlwaysInstallElevated -ne 1) -and ($policyCU.AlwaysInstallElevated -ne 1)) {
        $status = "Pass"
        $actual = "Always install with elevated privileges is disabled"
        $remediation = "No action required"
    } else {
        $status = "Fail"
        $actual = "Always install with elevated privileges is enabled"
        $remediation = "Set 'AlwaysInstallElevated' to 0 in both HKLM and HKCU"
    }

    return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
}





####################################################################################################################################################################################################
                                                                #(BITLOCKER)
####################################################################################################################################################################################################








# function Test-CIS_1_1_2 {
#     $control = 'CIS_Win_1.1.2'
#     $title = "Ensure Windows Firewall is enabled for all profiles"
#     $expected = "All profiles enabled"

#     # Check Windows Firewall status for all profiles
#     $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled
#     $nonCompliant = $profiles | Where-Object { $_.Enabled -eq $false }
#     if ($nonCompliant) {
#         $status = 'Fail'
#         $actual = ($nonCompliant | Out-String)
#         $remediation = 'Enable Windows Firewall for all profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'
#     } else {
#         $status = 'Pass'
#         $actual = 'All firewall profiles enabled'
#         $remediation = 'No action required'
#     }
#     return New-CheckResult -ControlId $control -Title $title -Expected $expected -Actual $actual -Status $status -Remediation $remediation
# }

# More checks can be added for other controls...

Export-ModuleMember -Function Test-CIS_*