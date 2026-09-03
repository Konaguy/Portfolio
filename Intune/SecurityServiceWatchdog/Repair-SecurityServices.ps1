<#
.SYNOPSIS
    Verifies that the endpoint security services (Microsoft Defender Antivirus,
    Microsoft Defender for Endpoint / SENSE, and Huntress) are running, restarts
    any that are stopped, and emails a support ticket for anything it cannot fix.

.DESCRIPTION
    Designed to be deployed from Microsoft Intune, either as a Platform Script
    (Devices > Scripts) or - preferred - as the remediation half of a Remediation
    (Devices > Remediations), paired with Detect-SecurityServices.ps1.

    Runs in the SYSTEM context, 64-bit PowerShell host, Windows PowerShell 5.1.

    For each configured service the script will:
      1. Read its current state and start type.
      2. Re-enable the start type if it has been set to Disabled (optional).
      3. Start the service, retrying with a delay, and wait for it to reach Running.
      4. Re-check the state, and record whether the repair held.

    Anything still not running afterwards - plus any required service that is not
    installed at all - is collected into a single ticket email that includes the
    device details, the per-service before/after state, the underlying error, and
    Defender's running mode / registered AV products for triage context.

    Alert e-mails are rate limited per service (see Alerting.CooldownHours) so a
    persistently broken agent does not open a new ticket on every run.

.PARAMETER ServiceName
    Overrides the configured service list. Useful for testing a single service.

.PARAMETER NoEmail
    Check and repair only. Never sends mail. Useful for a first pilot run.

.PARAMETER Force
    Ignores the alert cooldown and sends mail even if this device already
    reported the same service recently.

.PARAMETER TestEmail
    Sends a sample ticket using the configured transport and exits. Use this to
    validate SMTP relay / Graph settings before rolling the script out.

.NOTES
    Exit codes:  0 = all monitored services healthy (or repaired successfully)
                 1 = one or more services still down (ticket raised)
                 2 = script-level failure (configuration or unhandled error)

    Tamper Protection: with Tamper Protection enabled, WinDefend and Sense are
    protected from being reconfigured, and Set-Service / Start-Service may return
    access denied even when running as SYSTEM. That is expected - the script
    records the error and raises the ticket rather than trying to work around it.
#>

[CmdletBinding()]
param(
    [string[]] $ServiceName,
    [switch]   $NoEmail,
    [switch]   $Force,
    [switch]   $TestEmail
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

#region ---------------------------------------------------------------- CONFIG
# Everything an admin needs to change lives in this block.

$Script:Config = @{

    # Shown in the e-mail subject / body so tickets are attributable.
    Organization = 'CONTOSO'

    # Services to monitor, in the order they should be repaired.
    #   Name     - the Windows service name (not the display name)
    #   Friendly - what to call it in the ticket
    #   Required - $true  : alert if the service is missing from the device
    #              $false : silently skip if the service is not installed
    Services = @(
        @{ Name = 'WinDefend';       Friendly = 'Microsoft Defender Antivirus';            Required = $true  }
        @{ Name = 'Sense';           Friendly = 'Microsoft Defender for Endpoint (SENSE)'; Required = $true  }
        @{ Name = 'HuntressAgent';   Friendly = 'Huntress Agent';                          Required = $true  }
        @{ Name = 'HuntressUpdater'; Friendly = 'Huntress Updater';                        Required = $false }
        @{ Name = 'HuntressRio';     Friendly = 'Huntress EDR (Rio)';                      Required = $false }
    )

    Repair = @{
        StartAttempts        = 3      # how many times to try Start-Service
        RetryDelaySeconds    = 5      # pause between attempts
        StartTimeoutSeconds  = 90     # how long to wait for Running per attempt
        RepairStartType      = $true  # set Disabled services back to Automatic
        StopPendingWaitSecs  = 30     # wait out a StopPending service before starting
    }

    Alerting = @{
        # Do not re-open a ticket for the same service on the same device more
        # often than this. Set to 0 to alert on every run.
        CooldownHours = 12
    }

    Email = @{
        # Smtp  - relay through an internal / authenticated SMTP host
        # Graph - Microsoft Graph sendMail with an app registration
        # None  - never send (log only)
        Transport     = 'Smtp'

        To            = @('support@contoso.com')     # ticket queue address
        From          = 'intune-alerts@contoso.com'
        SubjectPrefix = '[Security Agent Down]'

        Smtp = @{
            Server  = 'smtp.contoso.com'
            Port    = 25
            UseSsl  = $false
            # Leave blank for an anonymous internal relay (recommended for
            # SYSTEM-context scripts). To authenticate, point CredentialFile at
            # a CLIXML credential exported by the SYSTEM account on the device,
            # or supply a username + DPAPI-protected password file.
            CredentialFile = ''
        }

        Graph = @{
            TenantId  = ''
            ClientId  = ''
            # Sending mailbox (UPN or object id) the app has Mail.Send rights to.
            Sender    = ''
            # Do not paste a secret into this file - anything shipped in an
            # Intune script is readable by anyone who can read the policy.
            # Provide it via one of these instead:
            SecretEnvironmentVariable = 'SECWATCH_GRAPH_SECRET'
            SecretFile                = ''   # file containing only the secret
        }
    }

    # Log + state location. Must be writable by SYSTEM.
    StateRoot = (Join-Path $env:ProgramData 'SecurityServiceWatchdog')

    Logging = @{
        MaxLogSizeBytes = 1MB
        KeepRotations   = 3
    }
}

#endregion ------------------------------------------------------------- CONFIG


#region ------------------------------------------------------------- UTILITIES

function Initialize-Workspace {
    if (-not (Test-Path -LiteralPath $Script:Config.StateRoot)) {
        New-Item -Path $Script:Config.StateRoot -ItemType Directory -Force | Out-Null
    }
    $Script:LogFile   = Join-Path $Script:Config.StateRoot 'Repair-SecurityServices.log'
    $Script:StateFile = Join-Path $Script:Config.StateRoot 'alert-state.json'

    if (Test-Path -LiteralPath $Script:LogFile) {
        $log = Get-Item -LiteralPath $Script:LogFile
        if ($log.Length -gt $Script:Config.Logging.MaxLogSizeBytes) {
            $keep = $Script:Config.Logging.KeepRotations
            for ($i = $keep; $i -ge 1; $i--) {
                $older = "$Script:LogFile.$i"
                $newer = if ($i -eq 1) { $Script:LogFile } else { "$Script:LogFile.$($i - 1)" }
                if (Test-Path -LiteralPath $newer) {
                    Move-Item -LiteralPath $newer -Destination $older -Force
                }
            }
        }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    # Verbose only: Intune reads stdout, so the script keeps stdout to one summary line.
    Write-Verbose $line
    if ($Script:LogFile) {
        try { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Get-DeviceContext {
    $ctx = [ordered]@{
        ComputerName  = $env:COMPUTERNAME
        Domain        = 'unknown'
        Serial        = 'unknown'
        Manufacturer  = 'unknown'
        Model         = 'unknown'
        OperatingSystem = 'unknown'
        OSBuild       = 'unknown'
        LastBoot      = 'unknown'
        LoggedOnUser  = 'none'
        IPv4          = 'unknown'
        Timestamp     = (Get-Date).ToString('u')
    }
    try {
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $ctx.Domain          = $cs.Domain
        $ctx.Serial          = $bios.SerialNumber
        $ctx.Manufacturer    = $cs.Manufacturer
        $ctx.Model           = $cs.Model
        $ctx.OperatingSystem = $os.Caption
        $ctx.OSBuild         = $os.Version
        $ctx.LastBoot        = $os.LastBootUpTime
        if ($cs.UserName) { $ctx.LoggedOnUser = $cs.UserName }
    } catch {
        Write-Log "Could not read device inventory: $($_.Exception.Message)" 'WARN'
    }
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
              Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
              Select-Object -First 1 -ExpandProperty IPAddress
        if ($ip) { $ctx.IPv4 = $ip }
    } catch { }
    return $ctx
}

function Get-SecurityContext {
    # Extra triage detail for whoever picks up the ticket: Defender can legitimately
    # sit in passive mode when a third-party AV owns real-time protection.
    $ctx = [ordered]@{
        DefenderRunningMode = 'unavailable'
        RealTimeProtection  = 'unavailable'
        SignatureAge        = 'unavailable'
        TamperProtection    = 'unavailable'
        RegisteredAV        = 'unavailable'
        SenseOnboarded      = 'unavailable'
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.PSObject.Properties.Name -contains 'AMRunningMode') {
            $ctx.DefenderRunningMode = [string]$mp.AMRunningMode
        }
        $ctx.RealTimeProtection = [string]$mp.RealTimeProtectionEnabled
        $ctx.SignatureAge       = '{0} day(s)' -f $mp.AntivirusSignatureAge
        if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected') {
            $ctx.TamperProtection = [string]$mp.IsTamperProtected
        }
    } catch {
        Write-Log "Get-MpComputerStatus unavailable: $($_.Exception.Message)" 'WARN'
    }
    try {
        $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        if ($av) { $ctx.RegisteredAV = ($av.displayName -join ', ') }
    } catch {
        # Not present on Server SKUs - not an error.
    }
    try {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        if (Test-Path -LiteralPath $key) {
            $onboarded = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).OnboardingState
            $ctx.SenseOnboarded = if ($onboarded -eq 1) { 'Yes' } else { "No ($onboarded)" }
        } else {
            $ctx.SenseOnboarded = 'No (not onboarded)'
        }
    } catch { }
    return $ctx
}

#endregion ---------------------------------------------------------- UTILITIES


#region --------------------------------------------------------------- REPAIR

function Get-TargetService {
    param([Parameter(Mandatory)][string] $Name)
    try {
        return Get-Service -Name $Name -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-ServiceStartType {
    param([Parameter(Mandatory)][string] $Name)
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($svc) { return $svc.StartMode }   # Auto | Manual | Disabled | Boot | System
    } catch { }
    return 'Unknown'
}

function Enable-ServiceStartType {
    <# Puts a Disabled service back to Automatic so it can be started. #>
    param([Parameter(Mandatory)][string] $Name)
    try {
        Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
        Write-Log "$Name start type set to Automatic."
        return @{ Success = $true; Error = $null }
    } catch {
        $msg = $_.Exception.Message
        Write-Log "$Name start type could not be changed: $msg" 'WARN'
        return @{ Success = $false; Error = $msg }
    }
}

function Start-TargetService {
    <#
        Starts a service and waits for it to actually reach Running.
        Returns a hashtable: Success, Attempts, Error.
    #>
    param([Parameter(Mandatory)][string] $Name)

    $cfg      = $Script:Config.Repair
    $lastErr  = $null
    $attempts = 0

    for ($i = 1; $i -le $cfg.StartAttempts; $i++) {
        $attempts = $i
        try {
            $svc = Get-Service -Name $Name -ErrorAction Stop

            if ($svc.Status -eq 'StopPending') {
                Write-Log "$Name is StopPending - waiting up to $($cfg.StopPendingWaitSecs)s for it to settle."
                try {
                    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($cfg.StopPendingWaitSecs))
                } catch { }
                $svc.Refresh()
            }

            if ($svc.Status -eq 'StartPending') {
                Write-Log "$Name is StartPending - waiting for it to finish starting."
                try {
                    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds($cfg.StartTimeoutSeconds))
                } catch { }
                $svc.Refresh()
            }

            if ($svc.Status -eq 'Paused') {
                Write-Log "$Name is Paused - resuming."
                $svc.Continue()
            } elseif ($svc.Status -ne 'Running') {
                Write-Log "$Name start attempt $i of $($cfg.StartAttempts)."
                Start-Service -Name $Name -ErrorAction Stop
            }

            $svc.Refresh()
            $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds($cfg.StartTimeoutSeconds))
            $svc.Refresh()

            if ($svc.Status -eq 'Running') {
                Write-Log "$Name is running."
                return @{ Success = $true; Attempts = $attempts; Error = $null }
            }
            $lastErr = "Service reported status '$($svc.Status)' after start."
        } catch {
            $lastErr = $_.Exception.Message
            Write-Log "$Name start attempt $i failed: $lastErr" 'WARN'
        }

        if ($i -lt $cfg.StartAttempts) { Start-Sleep -Seconds $cfg.RetryDelaySeconds }
    }

    return @{ Success = $false; Attempts = $attempts; Error = $lastErr }
}

function Get-ServiceLastError {
    <# Pulls the most recent System-log error for the service, for the ticket. #>
    param([Parameter(Mandatory)][string] $Name)
    try {
        $evt = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7000, 7001, 7009, 7011, 7023, 7024, 7031, 7034
            StartTime = (Get-Date).AddDays(-3)
        } -MaxEvents 60 -ErrorAction Stop |
            Where-Object { $_.Message -match [regex]::Escape($Name) } |
            Select-Object -First 1
        if ($evt) {
            return ('{0} - Event {1}: {2}' -f $evt.TimeCreated, $evt.Id, ($evt.Message -replace '\s+', ' ').Trim())
        }
    } catch { }
    return $null
}

function Invoke-ServiceCheck {
    <#
        Checks one configured service, repairs it if needed, and returns a
        result object for the report.
    #>
    param([Parameter(Mandatory)][hashtable] $Definition)

    $name   = $Definition.Name
    $result = [ordered]@{
        Name          = $name
        Friendly      = $Definition.Friendly
        Required      = $Definition.Required
        Installed     = $true
        StatusBefore  = 'NotInstalled'
        StartType     = 'Unknown'
        ActionTaken   = 'None'
        StatusAfter   = 'NotInstalled'
        Healthy       = $false
        Alertable     = $false
        Error         = $null
        EventLogHint  = $null
    }

    $svc = Get-TargetService -Name $name
    if (-not $svc) {
        $result.Installed = $false
        $result.Error     = 'Service is not installed on this device.'
        if ($Definition.Required) {
            $result.Alertable = $true
            Write-Log "$name ($($Definition.Friendly)) is NOT INSTALLED - flagged for ticket." 'ERROR'
        } else {
            $result.Healthy     = $true   # optional component, nothing to do
            $result.StatusAfter = 'Not installed (optional)'
            Write-Log "$name is not installed - optional component, skipping."
        }
        return $result
    }

    $result.StatusBefore = [string]$svc.Status
    $result.StartType    = Get-ServiceStartType -Name $name

    if ($svc.Status -eq 'Running') {
        $result.StatusAfter = 'Running'
        $result.Healthy     = $true
        Write-Log "$name ($($Definition.Friendly)) is running - no action needed."
        return $result
    }

    Write-Log "$name ($($Definition.Friendly)) is $($svc.Status) (start type $($result.StartType)) - attempting repair." 'WARN'
    $actions = New-Object System.Collections.Generic.List[string]

    if ($result.StartType -eq 'Disabled' -and $Script:Config.Repair.RepairStartType) {
        $enable = Enable-ServiceStartType -Name $name
        if ($enable.Success) {
            $actions.Add('Start type re-enabled (Disabled -> Automatic)')
            $result.StartType = Get-ServiceStartType -Name $name
        } else {
            $actions.Add("Start type change failed: $($enable.Error)")
        }
    }

    $start = Start-TargetService -Name $name
    $actions.Add("Start attempted $($start.Attempts) time(s)")
    $result.ActionTaken = ($actions -join '; ')

    $svcAfter = Get-TargetService -Name $name
    $result.StatusAfter = if ($svcAfter) { [string]$svcAfter.Status } else { 'Unknown' }

    if ($start.Success -and $result.StatusAfter -eq 'Running') {
        $result.Healthy = $true
        Write-Log "$name recovered - now Running."
    } else {
        $result.Healthy      = $false
        $result.Alertable    = $true
        $result.Error        = $start.Error
        $result.EventLogHint = Get-ServiceLastError -Name $name
        Write-Log "$name could NOT be restarted: $($start.Error)" 'ERROR'
    }

    return $result
}

#endregion ------------------------------------------------------------ REPAIR


#region -------------------------------------------------------------- ALERTING

function Get-AlertState {
    if (Test-Path -LiteralPath $Script:StateFile) {
        try {
            $raw = Get-Content -LiteralPath $Script:StateFile -Raw -ErrorAction Stop
            if ($raw.Trim()) { return (ConvertFrom-Json $raw) }
        } catch {
            Write-Log "Alert state unreadable, starting fresh: $($_.Exception.Message)" 'WARN'
        }
    }
    return (New-Object PSObject)
}

function Test-AlertSuppressed {
    <# $true when every failing service already alerted inside the cooldown. #>
    param([Parameter(Mandatory)][string[]] $Names)

    $hours = $Script:Config.Alerting.CooldownHours
    if ($Force -or $hours -le 0) { return $false }

    $state  = Get-AlertState
    $cutoff = (Get-Date).AddHours(-$hours)

    foreach ($n in $Names) {
        $prop = $state.PSObject.Properties[$n]
        if (-not $prop) { return $false }                       # never alerted
        $last = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$prop.Value, [ref] $last)) { return $false }
        if ($last -lt $cutoff) { return $false }                # cooldown expired
    }
    return $true
}

function Set-AlertState {
    param([Parameter(Mandatory)][string[]] $Names)
    $state = Get-AlertState
    $stamp = (Get-Date).ToString('o')
    foreach ($n in $Names) {
        $state | Add-Member -NotePropertyName $n -NotePropertyValue $stamp -Force
    }
    try {
        $state | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $Script:StateFile -Encoding UTF8
    } catch {
        Write-Log "Could not persist alert state: $($_.Exception.Message)" 'WARN'
    }
}

function New-TicketBody {
    param(
        [Parameter(Mandatory)] $Device,
        [Parameter(Mandatory)] $Security,
        [Parameter(Mandatory)] [object[]] $Results
    )

    $failed    = @($Results | Where-Object { $_.Alertable })
    $recovered = @($Results | Where-Object { $_.Healthy -and $_.ActionTaken -ne 'None' })

    $esc = { param($t) if ($null -eq $t) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$t) } }

    $rows = foreach ($r in $Results) {
        $colour = if ($r.Alertable) { '#b00020' } elseif ($r.Healthy) { '#1b7f37' } else { '#8a6d00' }
        @"
<tr>
  <td>$(& $esc $r.Friendly)<br/><small>$(& $esc $r.Name)</small></td>
  <td>$(& $esc $r.StatusBefore)</td>
  <td>$(& $esc $r.StartType)</td>
  <td>$(& $esc $r.ActionTaken)</td>
  <td style="color:$colour;font-weight:bold">$(& $esc $r.StatusAfter)</td>
  <td>$(& $esc $r.Error)$(if ($r.EventLogHint) { '<br/><small>' + (& $esc $r.EventLogHint) + '</small>' })</td>
</tr>
"@
    }

    $deviceRows = foreach ($k in $Device.Keys) {
        "<tr><td><b>$(& $esc $k)</b></td><td>$(& $esc $Device[$k])</td></tr>"
    }
    $securityRows = foreach ($k in $Security.Keys) {
        "<tr><td><b>$(& $esc $k)</b></td><td>$(& $esc $Security[$k])</td></tr>"
    }

    $failedList = ($failed | ForEach-Object { "<li>$(& $esc $_.Friendly) (<code>$(& $esc $_.Name)</code>) - $(& $esc $_.StatusAfter)</li>" }) -join ''
    if (-not $failedList) { $failedList = '<li>None</li>' }

    $recoveredList = ($recovered | ForEach-Object { "<li>$(& $esc $_.Friendly) restarted successfully</li>" }) -join ''
    if (-not $recoveredList) { $recoveredList = '<li>None</li>' }

    return @"
<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#222">
<h2 style="margin-bottom:4px">Endpoint security service failure</h2>
<p style="margin-top:0;color:#555">Automated check from Intune on <b>$(& $esc $Device.ComputerName)</b> at $(& $esc $Device.Timestamp).</p>

<h3>Could not be restarted - needs a technician</h3>
<ul>$failedList</ul>

<h3>Automatically recovered</h3>
<ul>$recoveredList</ul>

<h3>Service detail</h3>
<table cellpadding="6" cellspacing="0" border="1" style="border-collapse:collapse;border-color:#ccc">
<tr style="background:#f2f2f2">
  <th align="left">Service</th><th align="left">Status before</th><th align="left">Start type</th>
  <th align="left">Action taken</th><th align="left">Status after</th><th align="left">Error / last event</th>
</tr>
$($rows -join "`n")
</table>

<h3>Device</h3>
<table cellpadding="4" cellspacing="0" border="1" style="border-collapse:collapse;border-color:#ccc">$($deviceRows -join "`n")</table>

<h3>Security posture</h3>
<table cellpadding="4" cellspacing="0" border="1" style="border-collapse:collapse;border-color:#ccc">$($securityRows -join "`n")</table>

<p style="color:#777;font-size:11px">
Sent by Repair-SecurityServices.ps1 ($($Script:Config.Organization) endpoint security watchdog).
Local log: $(& $esc $Script:LogFile)
</p>
</body></html>
"@
}

function Get-GraphSecret {
    $g = $Script:Config.Email.Graph
    if ($g.SecretEnvironmentVariable) {
        $fromEnv = [Environment]::GetEnvironmentVariable($g.SecretEnvironmentVariable, 'Machine')
        if (-not $fromEnv) { $fromEnv = [Environment]::GetEnvironmentVariable($g.SecretEnvironmentVariable, 'Process') }
        if ($fromEnv) { return $fromEnv }
    }
    if ($g.SecretFile -and (Test-Path -LiteralPath $g.SecretFile)) {
        return (Get-Content -LiteralPath $g.SecretFile -Raw).Trim()
    }
    throw 'No Graph client secret available (set the environment variable or SecretFile).'
}

function Send-TicketViaSmtp {
    param([string] $Subject, [string] $HtmlBody)

    $e = $Script:Config.Email
    $client = New-Object System.Net.Mail.SmtpClient($e.Smtp.Server, [int]$e.Smtp.Port)
    try {
        $client.EnableSsl = [bool]$e.Smtp.UseSsl
        $client.Timeout   = 60000

        if ($e.Smtp.CredentialFile -and (Test-Path -LiteralPath $e.Smtp.CredentialFile)) {
            $cred = Import-Clixml -LiteralPath $e.Smtp.CredentialFile
            $client.Credentials = New-Object System.Net.NetworkCredential(
                $cred.UserName, $cred.GetNetworkCredential().Password)
        } else {
            $client.UseDefaultCredentials = $false
        }

        $msg = New-Object System.Net.Mail.MailMessage
        try {
            $msg.From       = New-Object System.Net.Mail.MailAddress($e.From)
            foreach ($to in $e.To) { $msg.To.Add($to) }
            $msg.Subject    = $Subject
            $msg.Body       = $HtmlBody
            $msg.IsBodyHtml = $true
            $client.Send($msg)
        } finally {
            $msg.Dispose()
        }
    } finally {
        $client.Dispose()
    }
}

function Send-TicketViaGraph {
    param([string] $Subject, [string] $HtmlBody)

    $g      = $Script:Config.Email.Graph
    $secret = Get-GraphSecret

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $tokenBody = @{
        client_id     = $g.ClientId
        client_secret = $secret
        scope         = 'https://graph.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }
    $token = Invoke-RestMethod -Method Post -UseBasicParsing `
        -Uri "https://login.microsoftonline.com/$($g.TenantId)/oauth2/v2.0/token" `
        -ContentType 'application/x-www-form-urlencoded' -Body $tokenBody

    $recipients = foreach ($to in $Script:Config.Email.To) {
        @{ emailAddress = @{ address = $to } }
    }
    $payload = @{
        message = @{
            subject      = $Subject
            body         = @{ contentType = 'HTML'; content = $HtmlBody }
            toRecipients = @($recipients)
        }
        saveToSentItems = $false
    } | ConvertTo-Json -Depth 6

    Invoke-RestMethod -Method Post -UseBasicParsing `
        -Uri "https://graph.microsoft.com/v1.0/users/$($g.Sender)/sendMail" `
        -Headers @{ Authorization = "Bearer $($token.access_token)" } `
        -ContentType 'application/json; charset=utf-8' `
        -Body ([Text.Encoding]::UTF8.GetBytes($payload)) | Out-Null
}

function Send-Ticket {
    <# Returns 'Sent', 'Skipped' (deliberately not sent) or 'Failed'. #>
    param([Parameter(Mandatory)][string] $Subject, [Parameter(Mandatory)][string] $HtmlBody)

    # Always keep a copy on the device so a technician can see exactly what was
    # raised, even if mail delivery is broken.
    try {
        $copy = Join-Path $Script:Config.StateRoot 'last-ticket.html'
        Set-Content -LiteralPath $copy -Value $HtmlBody -Encoding UTF8
        Write-Log "Ticket copy written to $copy."
    } catch {
        Write-Log "Could not write ticket copy: $($_.Exception.Message)" 'WARN'
    }

    $transport = $Script:Config.Email.Transport
    if ($NoEmail) {
        Write-Log 'NoEmail specified - ticket not sent.' 'WARN'
        return 'Skipped'
    }
    if ($transport -eq 'None') {
        Write-Log 'Email transport is None - ticket not sent.' 'WARN'
        return 'Skipped'
    }

    try {
        switch ($transport) {
            'Smtp'  { Send-TicketViaSmtp  -Subject $Subject -HtmlBody $HtmlBody }
            'Graph' { Send-TicketViaGraph -Subject $Subject -HtmlBody $HtmlBody }
            default { throw "Unknown email transport '$transport'." }
        }
        Write-Log "Ticket e-mail sent via $transport to $($Script:Config.Email.To -join ', ')."
        return 'Sent'
    } catch {
        Write-Log "FAILED to send ticket via ${transport}: $($_.Exception.Message)" 'ERROR'
        return 'Failed'
    }
}

#endregion ----------------------------------------------------------- ALERTING


#region ----------------------------------------------------------------- MAIN

try {
    Initialize-Workspace
    Write-Log '--- Endpoint security service check starting ---'

    if ($TestEmail) {
        $device   = Get-DeviceContext
        $security = Get-SecurityContext
        $sample   = @([ordered]@{
            Name = 'WinDefend'; Friendly = 'Microsoft Defender Antivirus'; Required = $true
            Installed = $true; StatusBefore = 'Stopped'; StartType = 'Auto'
            ActionTaken = 'Start attempted 3 time(s)'; StatusAfter = 'Stopped'
            Healthy = $false; Alertable = $true; Error = 'TEST MESSAGE - no real failure'
            EventLogHint = $null
        })
        $body = New-TicketBody -Device $device -Security $security -Results $sample
        $sendResult = Send-Ticket -Subject "$($Script:Config.Email.SubjectPrefix) TEST - $($device.ComputerName)" -HtmlBody $body
        Write-Output "Test ticket: $sendResult (see $Script:LogFile)."
        exit $(if ($sendResult -eq 'Sent') { 0 } else { 2 })
    }

    $definitions = $Script:Config.Services
    if ($ServiceName) {
        $definitions = $definitions | Where-Object { $ServiceName -contains $_.Name }
        if (-not $definitions) { throw "None of the requested services are in the configured list." }
    }

    $results = foreach ($def in $definitions) { Invoke-ServiceCheck -Definition $def }
    $results = @($results)

    $failed = @($results | Where-Object { $_.Alertable })
    $fixed  = @($results | Where-Object { $_.Healthy -and $_.ActionTaken -ne 'None' })

    if ($failed.Count -eq 0) {
        $summary = if ($fixed.Count -gt 0) {
            "OK - restarted: $((($fixed | ForEach-Object { $_.Friendly }) -join ', ')). All monitored services running."
        } else {
            'OK - all monitored security services running.'
        }
        Write-Log $summary
        Write-Output $summary
        exit 0
    }

    $failedNames = @($failed | ForEach-Object { $_.Name })
    Write-Log "Unrecoverable: $($failedNames -join ', ')" 'ERROR'

    if (Test-AlertSuppressed -Names $failedNames) {
        $summary = "FAIL - $($failedNames -join ', ') down. Ticket suppressed (alerted within the last $($Script:Config.Alerting.CooldownHours)h)."
        Write-Log $summary 'WARN'
        Write-Output $summary
        exit 1
    }

    $device   = Get-DeviceContext
    $security = Get-SecurityContext
    $subject  = '{0} {1} - {2} on {3}' -f `
        $Script:Config.Email.SubjectPrefix,
        $device.ComputerName,
        (($failed | ForEach-Object { $_.Friendly }) -join ', '),
        $Script:Config.Organization
    $body = New-TicketBody -Device $device -Security $security -Results $results

    switch (Send-Ticket -Subject $subject -HtmlBody $body) {
        'Sent' {
            Set-AlertState -Names $failedNames
            $summary = "FAIL - $($failedNames -join ', ') could not be restarted. Support ticket e-mailed."
        }
        'Skipped' {
            $summary = "FAIL - $($failedNames -join ', ') could not be restarted. E-mail disabled, ticket not sent."
        }
        default {
            $summary = "FAIL - $($failedNames -join ', ') could not be restarted AND the ticket e-mail failed. See $Script:LogFile."
        }
    }

    Write-Log $summary 'ERROR'
    Write-Output $summary
    exit 1

} catch {
    $msg = "Script error: $($_.Exception.Message)"
    try { Write-Log $msg 'ERROR' } catch { }
    Write-Output $msg
    exit 2
} finally {
    Write-Log '--- Endpoint security service check finished ---'
}

#endregion -------------------------------------------------------------- MAIN
