<#
.SYNOPSIS
    Applies mitigations for speculative execution vulnerabilities on Windows.

.DESCRIPTION
    This script ensures the registry and system settings are configured to mitigate vulnerabilities 
    related to speculative execution, based on vendor recommendations.

.NOTES
    Author: Dave Quichocho
    Date: 21Jan25
    Version: 1.4
#>

# Function to ensure registry keys and values are set
function Apply-RegistrySetting {
    param (
        [string]$KeyPath,
        [string]$ValueName,
        [object]$ValueData
    )

    # Check if the registry key exists; create it if missing
    if (-not (Test-Path -Path "Registry::$KeyPath")) {
        Write-Output "Creating missing key: $KeyPath"
        New-Item -Path "Registry::$KeyPath" -Force | Out-Null
    }

    # Check if the registry value exists
    $ExistingValue = Get-ItemProperty -Path "Registry::$KeyPath" -Name $ValueName -ErrorAction SilentlyContinue

    if ($ExistingValue -eq $null) {
        # Create the registry value if it doesn't exist
        Write-Output "Creating value: $KeyPath -> $ValueName = $ValueData"
        Set-ItemProperty -Path "Registry::$KeyPath" -Name $ValueName -Value $ValueData
    } else {
        # Update the registry value if it exists
        Write-Output "Updating value: $KeyPath -> $ValueName = $ValueData"
        Set-ItemProperty -Path "Registry::$KeyPath" -Name $ValueName -Value $ValueData
    }

    Write-Output "Applied setting: $KeyPath -> $ValueName = $ValueData"
}

# Apply mitigations
Write-Output "Applying mitigations for speculative execution vulnerabilities..."

# Branch Target Injection (BTI) mitigation
Apply-RegistrySetting -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                      -ValueName "FeatureSettingsOverride" -ValueData 0x400

Apply-RegistrySetting -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                      -ValueName "FeatureSettingsOverrideMask" -ValueData 0x400

# Speculative Store Bypass (SSB) mitigation
Apply-RegistrySetting -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                      -ValueName "FeatureSettingsOverride" -ValueData 0x400

# Rogue Data Cache Load (RDCL) mitigation
Apply-RegistrySetting -KeyPath "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" `
                      -ValueName "FeatureSettingsOverrideMask" -ValueData 3

# L1 Terminal Fault (L1TF) mitigation
Apply-RegistrySetting -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                      -ValueName "FeatureSettingsOverride" -ValueData 3

# Enable microcode updates (Intel systems)
Apply-RegistrySetting -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Microcode Update" `
                      -ValueName "Update" -ValueData 1

# Speculative Execution Side-Channel Mitigations Enabled
Apply-RegistrySetting -KeyPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                      -ValueName "FeatureSettingsOverrideMask" -ValueData 0x1

Write-Output "All mitigations have been applied. Please restart your system for changes to take effect."
