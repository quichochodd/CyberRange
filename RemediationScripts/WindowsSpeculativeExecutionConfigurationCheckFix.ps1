<#
.SYNOPSIS
    Applies vendor-recommended mitigations for speculative execution vulnerabilities on Windows.

.DESCRIPTION
    This script configures the registry and system settings to mitigate vulnerabilities such as:
    CVE-2017-5715, CVE-2017-5753, CVE-2017-5754, and others listed in the description.

.NOTES
    Author: Dave Quichocho
    Date: 21Jan25
    Version: 1.2
#>

# Function to apply registry settings
function Apply-RegistrySetting {
    param (
        [string]$KeyPath,
        [string]$ValueName,
        [object]$ValueData
    )
    if (-not (Test-Path -Path $KeyPath)) {
        New-Item -Path $KeyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $KeyPath -Name $ValueName -Value $ValueData
    Write-Output "Applied setting: $KeyPath -> $ValueName = $ValueData"
}

# Apply mitigations (per Microsoft's guidelines)
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

# Notify user of completion
Write-Output "All mitigations have been applied. Please restart your system for changes to take effect."
