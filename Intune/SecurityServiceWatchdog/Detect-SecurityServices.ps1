<#
.SYNOPSIS
    Detection script for the Intune Remediation "Endpoint security services".

.DESCRIPTION
    Reports whether Microsoft Defender Antivirus (WinDefend), Microsoft Defender
    for Endpoint (Sense) and the Huntress services are installed and running.

    Keep the service list here in sync with the Services block in
    Repair-SecurityServices.ps1.

    Exit 0 = compliant, nothing to do.
    Exit 1 = non-compliant, Intune runs Repair-SecurityServices.ps1.

    Intune only keeps the last 2048 characters of STDOUT, so the output is a
    single short line.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Name = Windows service name, Required = alert when the service is missing.
$Services = @(
    @{ Name = 'WinDefend';       Required = $true  }
    @{ Name = 'Sense';           Required = $true  }
    @{ Name = 'HuntressAgent';   Required = $true  }
    @{ Name = 'HuntressUpdater'; Required = $false }
    @{ Name = 'HuntressRio';     Required = $false }
)

try {
    $problems = New-Object System.Collections.Generic.List[string]

    foreach ($def in $Services) {
        $svc = $null
        try { $svc = Get-Service -Name $def.Name -ErrorAction Stop } catch { $svc = $null }

        if (-not $svc) {
            if ($def.Required) { $problems.Add("$($def.Name)=missing") }
            continue
        }
        if ($svc.Status -ne 'Running') {
            $problems.Add("$($def.Name)=$($svc.Status)")
        }
    }

    if ($problems.Count -gt 0) {
        Write-Output ("Non-compliant: " + ($problems -join ', '))
        exit 1
    }

    Write-Output 'Compliant: all monitored security services running.'
    exit 0

} catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 1
}
