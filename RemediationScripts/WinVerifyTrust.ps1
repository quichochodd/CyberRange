<#
.SYNOPSIS
    Mitigates the WinVerifyTrust Signature Validation CVE-2013-3900 vulnerability by enabling the EnableCertPaddingCheck registry setting.
.DESCRIPTION
    This script creates or updates the EnableCertPaddingCheck registry key on both 32-bit and 64-bit systems.
.NOTES
    Author       : Dave Quichocho
    Created Date : 2025-01-21
    Version      : 1.0
    Usage        : Run this script as Administrator.
#>

# Function to create or update a registry key
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    try {
        # Check if the registry path exists, create it if not
        if (-not (Test-Path -Path $Path)) {
            Write-Output "Creating registry path: $Path"
            New-Item -Path $Path -Force | Out-Null
        }

        # Set or update the registry value
        Write-Output "Setting $Name to $Value at $Path"
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    } catch {
        Write-Error "Failed to set $Name at $Path. Error: $_"
    }
}

# Define the registry paths and values
$registryPaths = @(
    "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",               # For 32-bit systems
    "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"    # For 64-bit systems
)

$registryValueName = "EnableCertPaddingCheck"
$registryValueData = 1

# Apply the settings for all paths
foreach ($path in $registryPaths) {
    Set-RegistryValue -Path $path -Name $registryValueName -Value $registryValueData
}

# Confirm the changes
Write-Output "`nVerification of changes:"
foreach ($path in $registryPaths) {
    if (Test-Path -Path $path) {
        Get-ItemProperty -Path $path | Select-Object PSPath, $registryValueName
    } else {
        Write-Output "Path not found: $path"
    }
}

Write-Output "`nCVE-2013-3900 mitigation applied successfully. Please restart the system for changes to take effect."
