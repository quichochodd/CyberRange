<#
.SYNOPSIS
    Mitigates the "SMB Signing not required" medium vulnerability by enabling the following:
        - Microsoft network client: Digitally sign communications (always)
        - Microsoft network server: Digitally sign communications (always)
.DESCRIPTION
    This script 
.NOTES
    Author       : Dave Quichocho
    Created Date : 2025-01-21
    Version      : 1.0
    Usage        : Run this script as Administrator.
#>

# Enable SMB signing for client and server
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Verify changes
Write-Output "SMB signing has been enabled. Restart your system for changes to take effect."
