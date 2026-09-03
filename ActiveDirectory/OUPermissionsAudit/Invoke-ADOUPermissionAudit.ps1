#Requires -Version 5.1

<#
.SYNOPSIS
    Read-only audit of Active Directory OU structure, delegated permissions and
    administrative rights, rendered as a self-contained interactive HTML report.

.DESCRIPTION
    Walks the OU tree from a search base, reads the security descriptor of every
    organisational unit (and optionally the container objects), resolves every
    trustee to a name, classifies each access control entry by what it actually
    lets the trustee do, and writes one HTML file you can drill into.

    The report answers the questions an OU delegation review is usually asked:

      * Which security groups hold rights where, and what do those rights allow?
      * Which permissions are explicitly delegated on an OU versus inherited
        from a parent, and which parent granted them?
      * Where does someone outside Tier 0 hold full control, modify-permissions,
        write-owner, DCSync, or write access to attributes that lead to account
        takeover?
      * Who is in the privileged groups, including nested and primary-group
        membership?
      * Who can edit the GPOs linked to an OU?

    NOTHING IS WRITTEN TO ACTIVE DIRECTORY. The script only performs LDAP reads:
    it binds read-only, uses System.DirectoryServices searches, and never calls a
    Set-*, New-*, Remove-*, Move-*, Rename-* or Restore-* cmdlet, nor CommitChanges().
    The only thing it creates is the report file (and the optional data exports).

    No RSAT required. The script uses System.DirectoryServices, which ships with
    Windows, so it runs from any domain-joined machine. The ActiveDirectory
    module is not used.

.PARAMETER SearchBase
    One or more distinguished names to audit. Defaults to the domain naming
    context of the current (or specified) domain. Everything below each base is
    included, subject to -MaxDepth.

.PARAMETER Server
    Domain controller or domain DNS name to bind to. Defaults to the DC located
    for the current domain.

.PARAMETER Credential
    Credential used for the LDAP bind. Defaults to the running user. A plain
    domain user can read almost every DACL in the directory; no admin rights are
    needed to run the audit.

.PARAMETER OutputPath
    Path of the HTML report to write. Defaults to
    .\AD-OU-Permission-Audit_<domain>_<yyyyMMdd-HHmmss>.html

.PARAMETER MaxDepth
    Limit how many OU levels below each search base are audited. 0 (default) is
    unlimited.

.PARAMETER IncludeContainers
    Also audit container objects (CN=Users, CN=Computers, CN=Managed Service
    Accounts and similar). Off by default because most delegation lives on OUs.
    Containers under CN=System are always skipped except AdminSDHolder, which is
    audited regardless.

.PARAMETER DelegationsOnly
    Keep only explicit (non-inherited) access control entries in the report.
    Produces a much smaller file that shows delegation without the inherited
    defaults. Findings that depend on inherited rights are still reported.

.PARAMETER SkipObjectCounts
    Do not count the users, computers, groups and OUs under each OU. Saves one
    subtree query on very large directories.

.PARAMETER SkipPrivilegedGroups
    Do not enumerate privileged group membership.

.PARAMETER SkipGpo
    Do not read Group Policy objects, their links or their edit permissions.

.PARAMETER ExportData
    Also write the raw audit data next to the report as .json, and the access
    control entries as .csv.

.PARAMETER Show
    Open the report when it has been written.

.PARAMETER PassThru
    Emit the audit result object to the pipeline.

.EXAMPLE
    .\Invoke-ADOUPermissionAudit.ps1

    Audits the current domain and writes the report to the current directory.

.EXAMPLE
    .\Invoke-ADOUPermissionAudit.ps1 -SearchBase 'OU=Corp,DC=contoso,DC=com' -Show

    Audits one branch of the tree and opens the report.

.EXAMPLE
    .\Invoke-ADOUPermissionAudit.ps1 -Server dc01.contoso.com -Credential (Get-Credential) `
        -IncludeContainers -ExportData -OutputPath C:\Audit\contoso.html

    Audits another domain with explicit credentials, includes containers, and
    writes contoso.html plus contoso.json and contoso.csv.

.NOTES
    Author : Portfolio - Active Directory
    Version: 1.0.0
    Requires: Windows PowerShell 5.1 or PowerShell 7+ on Windows, LDAP access to
              a domain controller. Read-only; no directory changes are made.
#>

[CmdletBinding()]
param(
    [string[]] $SearchBase,

    [string] $Server,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [string] $OutputPath,

    [ValidateRange(0, 64)]
    [int] $MaxDepth = 0,

    [switch] $IncludeContainers,
    [switch] $DelegationsOnly,
    [switch] $SkipObjectCounts,
    [switch] $SkipPrivilegedGroups,
    [switch] $SkipGpo,
    [switch] $ExportData,
    [switch] $Show,
    [switch] $PassThru
)

$ScriptVersion = '1.0.0'

#region ------------------------------------------------------------- constants

# Well-known SIDs that are independent of the domain.
$Script:WellKnownSidNames = @{
    'S-1-0-0'      = 'NULL SID'
    'S-1-1-0'      = 'Everyone'
    'S-1-2-0'      = 'LOCAL'
    'S-1-3-0'      = 'CREATOR OWNER'
    'S-1-3-1'      = 'CREATOR GROUP'
    'S-1-3-4'      = 'OWNER RIGHTS'
    'S-1-5-2'      = 'NETWORK'
    'S-1-5-4'      = 'INTERACTIVE'
    'S-1-5-6'      = 'SERVICE'
    'S-1-5-7'      = 'ANONYMOUS LOGON'
    'S-1-5-9'      = 'ENTERPRISE DOMAIN CONTROLLERS'
    'S-1-5-10'     = 'SELF'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-12'     = 'RESTRICTED'
    'S-1-5-13'     = 'TERMINAL SERVER USER'
    'S-1-5-14'     = 'REMOTE INTERACTIVE LOGON'
    'S-1-5-15'     = 'This Organization'
    'S-1-5-17'     = 'IUSR'
    'S-1-5-18'     = 'SYSTEM'
    'S-1-5-19'     = 'LOCAL SERVICE'
    'S-1-5-20'     = 'NETWORK SERVICE'
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'
    'S-1-5-32-546' = 'BUILTIN\Guests'
    'S-1-5-32-547' = 'BUILTIN\Power Users'
    'S-1-5-32-548' = 'BUILTIN\Account Operators'
    'S-1-5-32-549' = 'BUILTIN\Server Operators'
    'S-1-5-32-550' = 'BUILTIN\Print Operators'
    'S-1-5-32-551' = 'BUILTIN\Backup Operators'
    'S-1-5-32-552' = 'BUILTIN\Replicator'
    'S-1-5-32-554' = 'BUILTIN\Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'BUILTIN\Remote Desktop Users'
    'S-1-5-32-556' = 'BUILTIN\Network Configuration Operators'
    'S-1-5-32-557' = 'BUILTIN\Incoming Forest Trust Builders'
    'S-1-5-32-558' = 'BUILTIN\Performance Monitor Users'
    'S-1-5-32-559' = 'BUILTIN\Performance Log Users'
    'S-1-5-32-560' = 'BUILTIN\Windows Authorization Access Group'
    'S-1-5-32-561' = 'BUILTIN\Terminal Server License Servers'
    'S-1-5-32-562' = 'BUILTIN\Distributed COM Users'
    'S-1-5-32-568' = 'BUILTIN\IIS_IUSRS'
    'S-1-5-32-569' = 'BUILTIN\Cryptographic Operators'
    'S-1-5-32-573' = 'BUILTIN\Event Log Readers'
    'S-1-5-32-574' = 'BUILTIN\Certificate Service DCOM Access'
    'S-1-5-32-578' = 'BUILTIN\Hyper-V Administrators'
    'S-1-5-32-579' = 'BUILTIN\Access Control Assistance Operators'
    'S-1-5-32-580' = 'BUILTIN\Remote Management Users'
}

# Principals that are meant to hold sweeping rights. Their ACEs are reported but
# marked "expected" so they can be filtered out of the noise.
$Script:Tier0Sids       = @('S-1-5-18', 'S-1-5-9', 'S-1-5-32-544', 'S-1-5-10', 'S-1-5-32-560')
$Script:Tier0DomainRids = @(512, 516, 518, 519, 521, 498, 526, 527)

# Principals almost every account in the domain belongs to. A write right held
# by one of these is an escalation path for anyone who can log on.
$Script:BroadSids       = @('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-4', 'S-1-5-2',
                            'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-32-547', 'S-1-5-32-554')
$Script:BroadDomainRids = @(513, 514, 515, 501)

# Groups enumerated for the privileged membership review. Key = RID, value =
# @(scope, note). Scope 'domain' = per-domain RID, 'builtin' = S-1-5-32-<rid>,
# 'forest' = root domain only.
$Script:PrivilegedGroupRids = @(
    @{ Rid = 512; Scope = 'domain';  Note = 'Full control of the domain.' }
    @{ Rid = 519; Scope = 'forest';  Note = 'Full control of every domain in the forest.' }
    @{ Rid = 518; Scope = 'forest';  Note = 'Can modify the schema.' }
    @{ Rid = 520; Scope = 'domain';  Note = 'Can create Group Policy objects.' }
    @{ Rid = 517; Scope = 'domain';  Note = 'Can publish certificates to the directory.' }
    @{ Rid = 526; Scope = 'domain';  Note = 'Can write key credentials on any account.' }
    @{ Rid = 527; Scope = 'forest';  Note = 'Can write key credentials forest wide.' }
    @{ Rid = 516; Scope = 'domain';  Note = 'Domain controller computer accounts.' }
    @{ Rid = 521; Scope = 'domain';  Note = 'Read-only domain controller accounts.' }
    @{ Rid = 498; Scope = 'forest';  Note = 'Read-only domain controllers, forest wide.' }
    @{ Rid = 525; Scope = 'domain';  Note = 'Members are protected from delegation and NTLM. Membership here is good.' }
    @{ Rid = 544; Scope = 'builtin'; Note = 'Local administrators of the domain controllers.' }
    @{ Rid = 548; Scope = 'builtin'; Note = 'Legacy. Members can modify most user, group and computer accounts.' }
    @{ Rid = 549; Scope = 'builtin'; Note = 'Legacy. Members can log on to and shut down domain controllers.' }
    @{ Rid = 550; Scope = 'builtin'; Note = 'Legacy. Members can log on to domain controllers locally.' }
    @{ Rid = 551; Scope = 'builtin'; Note = 'Legacy. Members can back up and restore any file on a domain controller.' }
    @{ Rid = 552; Scope = 'builtin'; Note = 'Legacy replication account group. Should be empty.' }
    @{ Rid = 554; Scope = 'builtin'; Note = 'Legacy. Grants read of most directory attributes. Should be empty.' }
    @{ Rid = 557; Scope = 'builtin'; Note = 'Can create incoming forest trusts.' }
    @{ Rid = 578; Scope = 'builtin'; Note = 'Full control of Hyper-V on domain controllers, if any.' }
)

# Privileged groups that have no fixed RID, matched by sAMAccountName.
$Script:PrivilegedGroupNames = @(
    @{ Name = 'DnsAdmins';                   Note = 'Historically able to load a DLL into the DNS service on a domain controller.' }
    @{ Name = 'Organization Management';     Note = 'Exchange. Holds broad rights over recipients and, in older versions, over the domain.' }
    @{ Name = 'Exchange Trusted Subsystem';  Note = 'Exchange. Holds write access to many directory objects.' }
    @{ Name = 'Exchange Windows Permissions';Note = 'Exchange. Historically able to write the domain DACL.' }
)

# Attributes whose write access leads to control of the object or of an account.
$Script:HighRiskAttributes = @{
    'member'                                     = 'can add or remove group members'
    'msds-keycredentiallink'                     = 'can add shadow credentials and authenticate as the account'
    'ms-ds-keycredentiallink'                    = 'can add shadow credentials and authenticate as the account'
    'serviceprincipalname'                       = 'can set an SPN and request a crackable service ticket'
    'msds-allowedtoactonbehalfofotheridentity'   = 'can configure resource based constrained delegation and impersonate any user'
    'ms-ds-allowedtoactonbehalfofotheridentity'  = 'can configure resource based constrained delegation and impersonate any user'
    'msds-allowedtodelegateto'                   = 'can configure constrained delegation'
    'useraccountcontrol'                         = 'can disable pre-authentication or enable delegation on the account'
    'scriptpath'                                 = 'can point the logon script at code it controls'
    'msds-supportedencryptiontypes'              = 'can downgrade Kerberos encryption for the account'
    'gplink'                                     = 'can link a Group Policy object and run code on everything below'
    'gpoptions'                                  = 'can change Group Policy inheritance for the OU'
    'ntsecuritydescriptor'                       = 'can rewrite the object permissions'
    'sidhistory'                                 = 'can inject a privileged SID into the account'
    'msds-groupmsamembership'                    = 'can read the password of the managed service account'
    'ms-ds-groupmsamembership'                   = 'can read the password of the managed service account'
    'msds-managedpassword'                       = 'can read the managed password of the account'
    'ms-mcs-admpwd'                              = 'can read the local administrator password (LAPS)'
    'mslaps-password'                            = 'can read the local administrator password (LAPS)'
    'mslaps-encryptedpassword'                   = 'can read the encrypted local administrator password (LAPS)'
    'unixuserpassword'                           = 'can set a password hash on the account'
    'userpassword'                               = 'can set a password on the account'
}

# Extended rights, by GUID, used when the schema lookup is unavailable and for
# risk scoring by name.
$Script:KnownExtendedRights = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'
    '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Self-Membership'
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f' = 'Reanimate-Tombstones'
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' = 'DS-Clone-Domain-Controller'
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Allowed-To-Authenticate'
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939' = 'Apply-Group-Policy'
    'ba33815a-4f93-4c76-87f3-57574bff8109' = 'Migrate-SID-History'
    '280f369c-67c7-438e-ae98-1d46f3c6f541' = 'Update-Password-Not-Required-Bit'
    'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' = 'Unexpire-Password'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'User-Account-Restrictions'
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Group-Membership'
    '77b5b886-944a-11d1-aebd-0000f80367c1' = 'Personal-Information'
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf' = 'General-Information'
    'e45795b2-9455-11d1-aebd-0000f80367c1' = 'Phone-and-Mail-Options'
    'e45795b3-9455-11d1-aebd-0000f80367c1' = 'Web-Information'
    '5f202010-79a5-11d0-9020-00c04fc2d4cf' = 'User-Logon'
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8' = 'Private-Information'
    '037088f8-0ae1-11d2-b422-00a0c968f939' = 'RAS-Information'
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a' = 'Domain-Password-And-Lockout-Policies'
    'e48d0154-bcf8-11d1-8702-00c04fb96050' = 'Public-Information'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Allowed-To-Authenticate'
}

# Object classes used to describe CreateChild / DeleteChild rights when the
# schema is not readable.
$Script:KnownClassGuids = @{
    'bf967aba-0de6-11d0-a285-00aa003049e2' = 'user'
    'bf967a86-0de6-11d0-a285-00aa003049e2' = 'computer'
    'bf967a9c-0de6-11d0-a285-00aa003049e2' = 'group'
    'bf967aa5-0de6-11d0-a285-00aa003049e2' = 'organizationalUnit'
    'bf967a0a-0de6-11d0-a285-00aa003049e2' = 'pwdLastSet'
    '4828cc14-1437-45bc-9b07-ad6f015e5f28' = 'inetOrgPerson'
    '5cb41ed0-0e4c-11d0-a286-00aa003049e2' = 'contact'
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1' = 'groupPolicyContainer'
    'bf967aa8-0de6-11d0-a285-00aa003049e2' = 'printQueue'
    'bf967a92-0de6-11d0-a285-00aa003049e2' = 'volume'
    '7b8b558a-93a5-4af7-adca-c017e67f1057' = 'msDS-GroupManagedServiceAccount'
    'ce206244-5827-4a86-ba1c-1c0c386c1b64' = 'msDS-ManagedServiceAccount'
    'bf967aa7-0de6-11d0-a285-00aa003049e2' = 'organizationalPerson'
    'bf967a0b-0de6-11d0-a285-00aa003049e2' = 'nTDSDSA'
}

$Script:SeverityOrder = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1; 'Info' = 0 }

#endregion

#region ---------------------------------------------------------------- state

$Script:Ctx = @{
    Server         = $null
    Credential     = $null
    RootDse        = $null
    DomainDn       = $null
    ConfigDn       = $null
    SchemaDn       = $null
    DomainSid      = $null
    RootDomainSid  = $null
    DomainName     = $null
    ForestName     = $null
    GuidMap        = @{}
    TrusteeCache   = @{}
    TrusteeById    = @{}
    Warnings       = ([System.Collections.Generic.List[string]]::new())
}

#endregion

#region --------------------------------------------------------------- helpers

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('Info', 'Warn', 'Step')][string] $Level = 'Info'
    )
    switch ($Level) {
        'Step' { Write-Host "  $Message" -ForegroundColor Cyan }
        'Warn' {
            Write-Host "  ! $Message" -ForegroundColor Yellow
            [void]$Script:Ctx.Warnings.Add($Message)
        }
        default { Write-Verbose $Message }
    }
}

function Split-DistinguishedName {
    <#
        Splits a DN on unescaped commas, so components containing "\," survive.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Dn)

    $parts = [System.Collections.Generic.List[string]]::new()
    $sb = New-Object System.Text.StringBuilder
    $escaped = $false

    foreach ($ch in $Dn.ToCharArray()) {
        if ($escaped) { [void]$sb.Append($ch); $escaped = $false; continue }
        if ($ch -eq '\') { [void]$sb.Append($ch); $escaped = $true; continue }
        if ($ch -eq ',') { [void]$parts.Add($sb.ToString()); [void]$sb.Clear(); continue }
        [void]$sb.Append($ch)
    }
    if ($sb.Length -gt 0) { [void]$parts.Add($sb.ToString()) }

    , $parts.ToArray()
}

function Get-ParentDistinguishedName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Dn)

    $parts = Split-DistinguishedName -Dn $Dn
    if ($parts.Count -le 1) { return $null }
    ($parts[1..($parts.Count - 1)] -join ',')
}

function Get-DnDepth {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Dn)
    (Split-DistinguishedName -Dn $Dn).Count
}

function ConvertTo-LdapFilterValue {
    <#
        Escapes the characters that are special inside an LDAP search filter.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Value)

    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\'     { [void]$sb.Append('\5c') }
            '('     { [void]$sb.Append('\28') }
            ')'     { [void]$sb.Append('\29') }
            '*'     { [void]$sb.Append('\2a') }
            "`0"    { [void]$sb.Append('\00') }
            '/'     { [void]$sb.Append('\2f') }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function Get-SidRid {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Sid)

    $i = $Sid.LastIndexOf('-')
    if ($i -lt 0) { return -1 }
    $rid = 0
    if ([int]::TryParse($Sid.Substring($i + 1), [ref]$rid)) { return $rid }
    -1
}

function Get-SidDomainPrefix {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Sid)

    $i = $Sid.LastIndexOf('-')
    if ($i -lt 0) { return $Sid }
    $Sid.Substring(0, $i)
}

function Get-MaxSeverity {
    [CmdletBinding()]
    param([string[]] $Severity)

    $best = 'Info'
    foreach ($s in $Severity) {
        if ($s -and $Script:SeverityOrder[$s] -gt $Script:SeverityOrder[$best]) { $best = $s }
    }
    $best
}

function Step-Severity {
    <#
        Raises (or lowers, with a negative step) a severity by n levels.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Severity,
        [int] $By = 1
    )
    $names = @('Info', 'Low', 'Medium', 'High', 'Critical')
    $i = [Math]::Max(0, [Math]::Min(4, $Script:SeverityOrder[$Severity] + $By))
    $names[$i]
}

#endregion

#region ------------------------------------------------------- directory access

function Initialize-AuditContext {
    [CmdletBinding()]
    param(
        [string] $Server,
        [System.Management.Automation.PSCredential] $Credential
    )

    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    } catch {
        throw "System.DirectoryServices is not available on this host. Run the audit from a Windows machine that can reach a domain controller. ($($_.Exception.Message))"
    }

    $Script:Ctx.Server = $Server
    if ($Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $Script:Ctx.Credential = $Credential
    }

    try {
        $rootDse = New-AdEntry -Path 'RootDSE'
        $null = $rootDse.RefreshCache()
    } catch {
        throw "Could not read RootDSE from '$(if ($Server) { $Server } else { 'the current domain' })'. $($_.Exception.Message)"
    }

    $Script:Ctx.DomainDn = [string]$rootDse.Properties['defaultNamingContext'][0]
    $Script:Ctx.ConfigDn = [string]$rootDse.Properties['configurationNamingContext'][0]
    $Script:Ctx.SchemaDn = [string]$rootDse.Properties['schemaNamingContext'][0]
    $rootDomainDn        = [string]$rootDse.Properties['rootDomainNamingContext'][0]
    $Script:Ctx.Server   = [string]$rootDse.Properties['dnsHostName'][0]

    $Script:Ctx.DomainName = ((Split-DistinguishedName -Dn $Script:Ctx.DomainDn) |
        Where-Object { $_ -match '^(?i)DC=' } | ForEach-Object { $_.Substring(3) }) -join '.'
    $Script:Ctx.ForestName = ((Split-DistinguishedName -Dn $rootDomainDn) |
        Where-Object { $_ -match '^(?i)DC=' } | ForEach-Object { $_.Substring(3) }) -join '.'

    $domain = Get-AdObjectProperties -Dn $Script:Ctx.DomainDn -Properties @('objectSid')
    if ($domain -and $domain['objectSid']) {
        $Script:Ctx.DomainSid = (New-Object System.Security.Principal.SecurityIdentifier($domain['objectSid'], 0)).Value
    }

    if ($rootDomainDn -eq $Script:Ctx.DomainDn) {
        $Script:Ctx.RootDomainSid = $Script:Ctx.DomainSid
    } else {
        $rootDomain = Get-AdObjectProperties -Dn $rootDomainDn -Properties @('objectSid')
        if ($rootDomain -and $rootDomain['objectSid']) {
            $Script:Ctx.RootDomainSid = (New-Object System.Security.Principal.SecurityIdentifier($rootDomain['objectSid'], 0)).Value
        }
    }

    Write-AuditLog -Level Step "Connected to $($Script:Ctx.Server) - domain $($Script:Ctx.DomainName), forest $($Script:Ctx.ForestName)"
}

function New-AdEntry {
    <#
        Builds a read-only DirectoryEntry for a DN, RootDSE or GUID/SID binding
        string, honouring -Server and -Credential.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    $ldapPath = if ($Script:Ctx.Server) { "LDAP://$($Script:Ctx.Server)/$Path" } else { "LDAP://$Path" }

    if ($Script:Ctx.Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $ldapPath,
            $Script:Ctx.Credential.UserName,
            $Script:Ctx.Credential.GetNetworkCredential().Password,
            [System.DirectoryServices.AuthenticationTypes]::Secure)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    }
}

function Invoke-AdSearch {
    <#
        Runs a paged LDAP search and returns the results as a list. The searcher
        and its result collection are disposed before returning; SearchResult
        objects are snapshots and stay valid.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $SearchRoot,
        [string] $Filter = '(objectClass=*)',
        [string[]] $Properties = @('distinguishedName'),
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string] $Scope = 'Subtree',
        [switch] $WithSecurityDescriptor
    )

    $root = $null; $searcher = $null; $found = $null
    $list = [System.Collections.Generic.List[object]]::new()

    try {
        $root = New-AdEntry -Path $SearchRoot
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter          = $Filter
        $searcher.SearchScope     = $Scope
        $searcher.PageSize        = 1000
        $searcher.SizeLimit       = 0
        $searcher.CacheResults    = $false
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None

        foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }

        if ($WithSecurityDescriptor) {
            $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Owner -bor
                                      [System.DirectoryServices.SecurityMasks]::Group -bor
                                      [System.DirectoryServices.SecurityMasks]::Dacl
        }

        $found = $searcher.FindAll()
        foreach ($r in $found) { [void]$list.Add($r) }
    } finally {
        if ($found)    { try { $found.Dispose() }    catch { } }
        if ($searcher) { try { $searcher.Dispose() } catch { } }
        if ($root)     { try { $root.Dispose() }     catch { } }
    }

    , $list
}

function Get-ResultValue {
    <#
        First value of a property on a SearchResult, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)][string] $Name
    )
    $p = $Result.Properties[$Name.ToLowerInvariant()]
    if ($p -and $p.Count -gt 0) { return $p[0] }
    $null
}

function Get-ResultValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)][string] $Name
    )
    $p = $Result.Properties[$Name.ToLowerInvariant()]
    if ($p -and $p.Count -gt 0) { return @($p) }
    @()
}

function Get-AdObjectProperties {
    <#
        Base-scope read of one object. Returns a hashtable of first values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Dn,
        [string[]] $Properties = @('distinguishedName')
    )

    try {
        $res = Invoke-AdSearch -SearchRoot $Dn -Filter '(objectClass=*)' -Scope Base -Properties $Properties
        if ($res.Count -eq 0) { return $null }
        $out = @{}
        foreach ($p in $Properties) { $out[$p] = Get-ResultValue -Result $res[0] -Name $p }
        return $out
    } catch {
        Write-AuditLog -Level Info "Base read of '$Dn' failed: $($_.Exception.Message)"
        return $null
    }
}

function Get-DirectoryGuidMap {
    <#
        GUID -> friendly name for every schema class, every attribute and every
        control access right (extended rights and property sets). Falls back to
        the built-in tables when the schema cannot be read.
    #>
    [CmdletBinding()]
    param()

    $map = @{}
    foreach ($kv in $Script:KnownClassGuids.GetEnumerator())     { $map[$kv.Key] = @{ Name = $kv.Value; Kind = 'class' } }
    foreach ($kv in $Script:KnownExtendedRights.GetEnumerator()) { $map[$kv.Key] = @{ Name = $kv.Value; Kind = 'right' } }

    try {
        $schema = Invoke-AdSearch -SearchRoot $Script:Ctx.SchemaDn `
            -Filter '(&(schemaIDGUID=*)(|(objectClass=classSchema)(objectClass=attributeSchema)))' `
            -Properties @('lDAPDisplayName', 'schemaIDGUID', 'objectClass')

        foreach ($r in $schema) {
            $bytes = Get-ResultValue -Result $r -Name 'schemaIDGUID'
            $name  = [string](Get-ResultValue -Result $r -Name 'lDAPDisplayName')
            if (-not $bytes -or -not $name) { continue }
            $guid = (New-Object System.Guid(, [byte[]]$bytes)).ToString()
            $kind = if (@(Get-ResultValues -Result $r -Name 'objectClass') -contains 'classSchema') { 'class' } else { 'attribute' }
            $map[$guid] = @{ Name = $name; Kind = $kind }
        }
        Write-AuditLog -Level Step "Read $($schema.Count) schema entries for permission naming"
    } catch {
        Write-AuditLog -Level Warn "Schema could not be read, permission names fall back to the built-in table: $($_.Exception.Message)"
    }

    try {
        $rights = Invoke-AdSearch -SearchRoot "CN=Extended-Rights,$($Script:Ctx.ConfigDn)" `
            -Filter '(objectClass=controlAccessRight)' `
            -Properties @('displayName', 'rightsGuid', 'validAccesses', 'cn')

        foreach ($r in $rights) {
            $guid = [string](Get-ResultValue -Result $r -Name 'rightsGuid')
            if (-not $guid) { continue }
            $name = [string](Get-ResultValue -Result $r -Name 'displayName')
            if (-not $name) { $name = [string](Get-ResultValue -Result $r -Name 'cn') }
            $valid = [int](Get-ResultValue -Result $r -Name 'validAccesses')
            # validAccesses 48 = read/write property, i.e. a property set rather
            # than a control access right.
            $kind = if ($valid -band 0x100) { 'right' } elseif ($valid -band 0x30) { 'propertySet' } else { 'right' }
            $map[$guid.ToLowerInvariant()] = @{ Name = $name; Kind = $kind }
        }
        Write-AuditLog -Level Step "Read $($rights.Count) extended rights and property sets"
    } catch {
        Write-AuditLog -Level Warn "Extended rights could not be read: $($_.Exception.Message)"
    }

    $map
}

#endregion

#region ---------------------------------------------------------- trustee model

function Resolve-Trustee {
    <#
        Turns a SID into a described principal, cached for the run. Returns the
        trustee hashtable; the caller reads .Id for the report index.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Sid)

    if ($Script:Ctx.TrusteeCache.ContainsKey($Sid)) { return $Script:Ctx.TrusteeCache[$Sid] }

    $t = @{
        id          = $Script:Ctx.TrusteeCache.Count
        sid         = $Sid
        name        = $Sid
        short       = $Sid
        domain      = ''
        class       = 'unresolved'
        dn          = ''
        scope       = ''
        description = ''
        adminCount  = $false
        privileged  = $false
        broad       = $false
        tier0       = $false
        wellKnown   = $false
        memberCount = 0
        members     = @()
    }

    # 1. Well-known SIDs that do not live in the directory.
    if ($Script:WellKnownSidNames.ContainsKey($Sid)) {
        $t.name      = $Script:WellKnownSidNames[$Sid]
        $t.class     = 'wellKnown'
        $t.wellKnown = $true
    }

    # 2. Objects in this domain, read directly through a SID bind.
    if ($t.class -eq 'unresolved' -or $Sid -like 'S-1-5-21-*') {
        try {
            $res = Invoke-AdSearch -SearchRoot "<SID=$Sid>" -Filter '(objectClass=*)' -Scope Base -Properties @(
                'distinguishedName', 'sAMAccountName', 'objectClass', 'adminCount', 'groupType', 'description', 'objectCategory')
            if ($res.Count -gt 0) {
                $r = $res[0]
                $classes = @(Get-ResultValues -Result $r -Name 'objectClass')
                $t.dn          = [string](Get-ResultValue -Result $r -Name 'distinguishedName')
                $t.description = [string](Get-ResultValue -Result $r -Name 'description')
                $t.adminCount  = ([int](Get-ResultValue -Result $r -Name 'adminCount')) -eq 1
                $sam           = [string](Get-ResultValue -Result $r -Name 'sAMAccountName')

                $t.class = if ($classes -contains 'group') { 'group' }
                           elseif ($classes -contains 'computer') { 'computer' }
                           elseif ($classes -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' }
                           elseif ($classes -contains 'user') { 'user' }
                           elseif ($classes -contains 'foreignSecurityPrincipal') { 'foreign' }
                           else { 'other' }

                if ($t.class -eq 'group') {
                    $gt = [int](Get-ResultValue -Result $r -Name 'groupType')
                    $t.scope = if ($gt -band 0x8) { 'Universal' } elseif ($gt -band 0x2) { 'Global' } elseif ($gt -band 0x4) { 'Domain local' } else { 'Builtin local' }
                    if (-not ($gt -band 0x80000000)) { $t.scope += ' (distribution)' }
                }

                if ($sam) {
                    $prefix = if ($Sid -like 'S-1-5-32-*') { 'BUILTIN' }
                              else { ($Script:Ctx.DomainName -split '\.')[0].ToUpperInvariant() }
                    $t.name = "$prefix\$sam"
                } elseif ($t.dn) {
                    $t.name = $t.dn
                }
            }
        } catch {
            Write-Verbose "SID bind failed for $Sid : $($_.Exception.Message)"
        }
    }

    # 3. Anything else: ask the local LSA / a trusted domain to translate it.
    if ($t.class -eq 'unresolved') {
        try {
            $nt = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
            if ($nt) { $t.name = $nt; $t.class = 'external' }
        } catch {
            $t.name  = $Sid
            $t.class = 'unresolved'
        }
    }

    if ($t.name -match '\\') {
        $t.domain = $t.name.Split('\')[0]
        $t.short  = $t.name.Split('\')[-1]
    } else {
        $t.short = $t.name
    }

    $rid    = Get-SidRid -Sid $Sid
    $prefix = Get-SidDomainPrefix -Sid $Sid

    $t.tier0 = ($Script:Tier0Sids -contains $Sid) -or
               (($prefix -eq $Script:Ctx.DomainSid -or $prefix -eq $Script:Ctx.RootDomainSid) -and $Script:Tier0DomainRids -contains $rid)

    $t.broad = ($Script:BroadSids -contains $Sid) -or
               (($prefix -eq $Script:Ctx.DomainSid -or $prefix -eq $Script:Ctx.RootDomainSid) -and $Script:BroadDomainRids -contains $rid)

    $t.privileged = $t.tier0

    $Script:Ctx.TrusteeCache[$Sid] = $t
    $Script:Ctx.TrusteeById[$t.id]  = $t
    $t
}

function Get-TrusteeById {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()] $Id)

    if ($null -eq $Id) { return $null }
    if ($Script:Ctx.TrusteeById.ContainsKey($Id)) { return $Script:Ctx.TrusteeById[$Id] }
    $null
}

#endregion

#region ------------------------------------------------------------ ACE analysis

function Get-GuidName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Guid)

    if (-not $Guid -or $Guid -eq '00000000-0000-0000-0000-000000000000') { return $null }
    $key = $Guid.ToLowerInvariant()
    if ($Script:Ctx.GuidMap.ContainsKey($key)) { return $Script:Ctx.GuidMap[$key] }
    @{ Name = $Guid; Kind = 'unknown' }
}

function Get-AceAppliesTo {
    <#
        Renders the inheritance flags of an ACE the way the Windows ACL editor
        does: which objects below this one the entry actually applies to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $InheritanceType,
        [AllowEmptyString()][string] $InheritedObjectClass
    )

    $target = if ($InheritedObjectClass) { "$InheritedObjectClass objects" } else { 'objects' }

    switch ($InheritanceType) {
        'None'           { 'This object only' }
        'Children'       { if ($InheritedObjectClass) { "Descendant $target" } else { 'Immediate child objects' } }
        'Descendents'    { if ($InheritedObjectClass) { "Descendant $target" } else { 'All descendant objects' } }
        'SelfAndChildren'{ if ($InheritedObjectClass) { "This object and descendant $target" } else { 'This object and immediate child objects' } }
        'All'            { if ($InheritedObjectClass) { "This object and descendant $target" } else { 'This object and all descendant objects' } }
        default          { $InheritanceType }
    }
}

function ConvertTo-PermissionList {
    <#
        Turns the rights mask plus the ObjectType GUID of an ACE into the list of
        plain-language permissions it grants.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Rights,
        [AllowNull()] $ObjectTypeInfo
    )

    $R    = [System.DirectoryServices.ActiveDirectoryRights]
    $list = [System.Collections.Generic.List[string]]::new()
    $obj  = if ($ObjectTypeInfo) { $ObjectTypeInfo.Name } else { $null }
    $kind = if ($ObjectTypeInfo) { $ObjectTypeInfo.Kind } else { 'all' }

    if (($Rights -band $R::GenericAll) -eq $R::GenericAll) {
        [void]$list.Add('Full control')
        return , $list.ToArray()
    }

    if ($Rights -band $R::CreateChild) {
        [void]$list.Add($(if ($obj) { "Create $obj objects" } else { 'Create all child objects' }))
    }
    if ($Rights -band $R::DeleteChild) {
        [void]$list.Add($(if ($obj) { "Delete $obj objects" } else { 'Delete all child objects' }))
    }
    if ($Rights -band $R::ReadProperty) {
        [void]$list.Add($(if ($obj) { "Read $obj" } else { 'Read all properties' }))
    }
    if ($Rights -band $R::WriteProperty) {
        [void]$list.Add($(if ($obj) { "Write $obj" } else { 'Write all properties' }))
    }
    if ($Rights -band $R::Self) {
        [void]$list.Add($(if ($obj) { "Validated write to $obj" } else { 'All validated writes' }))
    }
    if ($Rights -band $R::ExtendedRight) {
        [void]$list.Add($(if ($obj) { $obj } else { 'All extended rights' }))
    }
    if ($Rights -band $R::Delete)               { [void]$list.Add('Delete this object') }
    if ($Rights -band $R::DeleteTree)           { [void]$list.Add('Delete subtree') }
    if ($Rights -band $R::ListChildren)         { [void]$list.Add('List contents') }
    if ($Rights -band $R::ListObject)           { [void]$list.Add('List object') }
    if ($Rights -band $R::ReadControl)          { [void]$list.Add('Read permissions') }
    if ($Rights -band $R::WriteDacl)            { [void]$list.Add('Modify permissions') }
    if ($Rights -band $R::WriteOwner)           { [void]$list.Add('Modify owner') }
    if ($Rights -band $R::AccessSystemSecurity) { [void]$list.Add('Modify auditing') }

    if ($list.Count -eq 0) { [void]$list.Add([string]$Rights) }

    , $list.ToArray()
}


function Get-AceAssessment {
    <#
        Scores one access control entry: what it lets the trustee do, how much
        that matters, and whether it is a directory default rather than a
        delegation someone made.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Rights,
        [AllowNull()] $ObjectTypeInfo,
        [Parameter(Mandatory)] $Trustee,
        [Parameter(Mandatory)][string] $AccessType
    )

    $R       = [System.DirectoryServices.ActiveDirectoryRights]
    $cats    = [System.Collections.Generic.List[string]]::new()
    $notes   = [System.Collections.Generic.List[string]]::new()
    $objName = if ($ObjectTypeInfo) { $ObjectTypeInfo.Name } else { $null }
    $objKey  = if ($objName) { $objName.ToLowerInvariant() } else { '' }

    # A reference type, so the helper below can raise the score from its own scope.
    $state = New-Object psobject -Property @{ Severity = 'Info' }

    $bump = {
        param([string] $Level, [string] $Category, [string] $Note)
        if ($Script:SeverityOrder[$Level] -gt $Script:SeverityOrder[$state.Severity]) { $state.Severity = $Level }
        if ($Category -and -not $cats.Contains($Category)) { [void]$cats.Add($Category) }
        if ($Note -and -not $notes.Contains($Note)) { [void]$notes.Add($Note) }
    }

    if ($AccessType -eq 'Deny') {
        # Deny entries do not grant anything. They are listed because they change
        # the meaning of the allow entries around them.
        $cat = if (($Rights -band $R::Delete) -or ($Rights -band $R::DeleteTree)) { 'Deletion protection' } else { 'Deny' }
        return @{
            Severity = 'Info'; RawSeverity = 'Info'; Categories = @($cat)
            Notes = @('Deny entry. It removes access rather than granting it.'); Expected = $true
        }
    }

    if (($Rights -band $R::GenericAll) -eq $R::GenericAll) {
        & $bump 'High' 'Full control' 'Full control of this object and everything the entry applies to.'
    }
    if ($Rights -band $R::WriteDacl) {
        & $bump 'High' 'Modify permissions' 'Can rewrite the permissions and grant itself anything else.'
    }
    if ($Rights -band $R::WriteOwner) {
        & $bump 'High' 'Take ownership' 'Can take ownership, which brings the right to rewrite permissions.'
    }
    if (($Rights -band $R::WriteProperty) -and -not $objName) {
        & $bump 'High' 'Write all properties' 'Can write every attribute of the objects the entry applies to.'
    }
    if (($Rights -band $R::ExtendedRight) -and -not $objName) {
        & $bump 'High' 'All extended rights' 'Includes password reset and every other control access right.'
    }
    if (($Rights -band $R::CreateChild) -or ($Rights -band $R::DeleteChild)) {
        $what = if ($objName) { $objName } else { 'any class of' }
        & $bump 'Medium' 'Create or delete objects' "Can create or delete $what objects here."
        if ($objKey -in @('computer', 'user', 'inetorgperson', 'group', 'msds-groupmanagedserviceaccount')) {
            & $bump 'Medium' 'Account management' $null
        }
        if ($objKey -eq 'organizationalunit') {
            & $bump 'Medium' 'OU structure' 'Can create or delete organisational units, which moves the delegation boundary.'
        }
    }
    if (($Rights -band $R::Delete) -or ($Rights -band $R::DeleteTree)) {
        & $bump 'Medium' 'Delete' 'Can delete the objects the entry applies to.'
    }

    # Attribute, property set and extended right specific rules.
    if ($objName -and (($Rights -band $R::WriteProperty) -or ($Rights -band $R::Self) -or ($Rights -band $R::ExtendedRight))) {
        if ($Script:HighRiskAttributes.ContainsKey($objKey)) {
            & $bump 'High' 'Sensitive attribute' ("Write access to $objName - " + $Script:HighRiskAttributes[$objKey] + '.')
        }
        switch -Regex ($objKey) {
            '^(ds-replication-get-changes(-all|-in-filtered-set)?|replicating directory changes.*)$' {
                & $bump 'Critical' 'Directory replication' 'Replication rights allow every credential in the domain to be read (DCSync).'
            }
            '^(user-force-change-password|reset password)$' {
                & $bump 'Medium' 'Password reset' 'Can set a new password without knowing the old one. Normal for a service desk, serious over privileged accounts.'
            }
            '^(self-membership|add/remove self as member)$' {
                & $bump 'Medium' 'Group membership' 'Can add or remove itself from the groups the entry applies to.'
            }
            '^(group-membership)$' {
                & $bump 'High' 'Group membership' 'Property set covering group membership.'
            }
            '^(user-account-restrictions)$' {
                & $bump 'High' 'Sensitive attribute' 'Property set including userAccountControl, so delegation and pre-authentication can be changed.'
            }
            '^(reanimate-tombstones|migrate-sid-history|ds-clone-domain-controller|ds-install-replica)$' {
                & $bump 'High' 'Directory maintenance' 'A forest level maintenance right that is rarely delegated on purpose.'
            }
            '^(apply group policy|apply-group-policy)$' {
                & $bump 'Info' 'Group Policy' $null
            }
        }
    }

    if ($state.Severity -eq 'Info' -and (($Rights -band $R::ReadProperty) -or ($Rights -band $R::ListChildren) -or ($Rights -band $R::ReadControl))) {
        & $bump 'Info' 'Read' $null
    }

    $raw = $state.Severity

    if ($Trustee.broad -and $Script:SeverityOrder[$raw] -ge $Script:SeverityOrder['Medium']) {
        $state.Severity = Step-Severity -Severity $raw -By 1
        [void]$cats.Add('Broad principal')
        [void]$notes.Add("$($Trustee.name) covers effectively every account that can authenticate, so this right is held by everyone.")
    }

    $expected = $false
    if ($Trustee.tier0) {
        $expected = $true
        $state.Severity = 'Info'
        [void]$notes.Add("$($Trustee.name) is a Tier 0 principal, so this entry is expected.")
    }

    @{
        Severity    = $state.Severity
        RawSeverity = $raw
        Categories  = $cats.ToArray()
        Notes       = $notes.ToArray()
        Expected    = $expected
    }
}

#endregion

#region ------------------------------------------------------------ collection

function Get-OuNodes {
    <#
        Reads every OU (and optionally container) below the search bases together
        with its security descriptor, and returns them as unlinked node records.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]] $SearchBase,
        [switch] $IncludeContainers
    )

    $classes = @('(objectClass=organizationalUnit)', '(objectClass=domainDNS)')
    if ($IncludeContainers) { $classes += @('(objectClass=container)', '(objectClass=builtinDomain)') }
    $filter = '(|' + ($classes -join '') + ')'

    $props = @('distinguishedName', 'name', 'objectClass', 'gPLink', 'gPOptions', 'description',
               'managedBy', 'whenCreated', 'whenChanged', 'isCriticalSystemObject', 'nTSecurityDescriptor')

    $nodes = [System.Collections.Generic.List[object]]::new()
    $seen  = @{}

    foreach ($base in $SearchBase) {
        Write-AuditLog -Level Step "Reading directory objects and permissions under $base"
        $results = Invoke-AdSearch -SearchRoot $base -Filter $filter -Properties $props -WithSecurityDescriptor

        $i = 0
        foreach ($r in $results) {
            $i++
            $dn = [string](Get-ResultValue -Result $r -Name 'distinguishedName')
            if (-not $dn -or $seen.ContainsKey($dn)) { continue }

            if ($i % 25 -eq 0) {
                Write-Progress -Activity 'Reading permissions' -Status $dn -PercentComplete (($i / [Math]::Max(1, $results.Count)) * 100)
            }

            # CN=System holds the directory's own plumbing. AdminSDHolder is
            # audited separately; the rest is noise in an OU delegation review.
            if ($IncludeContainers -and $dn -match '(?i),CN=System,DC=') { continue }

            $node = ConvertTo-OuNode -Result $r -Dn $dn
            if ($node) {
                $seen[$dn] = $true
                [void]$nodes.Add($node)
            }
        }
        Write-Progress -Activity 'Reading permissions' -Completed
    }

    # AdminSDHolder governs the permissions that are stamped back onto every
    # protected account, so it belongs in an administrative permission review.
    $adminSdHolderDn = "CN=AdminSDHolder,CN=System,$($Script:Ctx.DomainDn)"
    if (-not $seen.ContainsKey($adminSdHolderDn)) {
        try {
            $res = Invoke-AdSearch -SearchRoot $adminSdHolderDn -Filter '(objectClass=*)' -Scope Base -Properties $props -WithSecurityDescriptor
            if ($res.Count -gt 0) {
                $node = ConvertTo-OuNode -Result $res[0] -Dn $adminSdHolderDn
                if ($node) { $node.type = 'AdminSDHolder'; [void]$nodes.Add($node) }
            }
        } catch {
            Write-AuditLog -Level Info "AdminSDHolder could not be read: $($_.Exception.Message)"
        }
    }

    , $nodes
}

function ConvertTo-OuNode {
    <#
        Builds one node record - identity, Group Policy links and the parsed
        access control list - from a search result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)][string] $Dn
    )

    $classes = @(Get-ResultValues -Result $Result -Name 'objectClass')
    $type = if ($classes -contains 'domainDNS') { 'Domain' }
            elseif ($classes -contains 'organizationalUnit') { 'OU' }
            elseif ($classes -contains 'builtinDomain') { 'Builtin' }
            else { 'Container' }

    $node = @{
        dn           = $Dn
        name         = [string](Get-ResultValue -Result $Result -Name 'name')
        type         = $type
        description  = [string](Get-ResultValue -Result $Result -Name 'description')
        managedBy    = [string](Get-ResultValue -Result $Result -Name 'managedBy')
        whenCreated  = $null
        whenChanged  = $null
        critical     = [bool](Get-ResultValue -Result $Result -Name 'isCriticalSystemObject')
        gpLinkRaw    = [string](Get-ResultValue -Result $Result -Name 'gPLink')
        gpOptions    = [int](Get-ResultValue -Result $Result -Name 'gPOptions')
        owner        = $null
        ownerSid     = $null
        inheritanceBlocked  = $false
        protectedFromDelete = $false
        aces         = ([System.Collections.Generic.List[object]]::new())
        aclError     = $null
    }

    if ($type -eq 'Domain') { $node.name = $Script:Ctx.DomainName }

    foreach ($f in @('whenCreated', 'whenChanged')) {
        $v = Get-ResultValue -Result $Result -Name $f
        if ($v -is [datetime]) { $node[$f] = $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    }

    $sdBytes = Get-ResultValue -Result $Result -Name 'nTSecurityDescriptor'
    if (-not $sdBytes) {
        $node.aclError = 'The security descriptor could not be read with the current credentials.'
        return $node
    }

    try {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$sdBytes)

        $node.inheritanceBlocked = $sd.AreAccessRulesProtected

        try {
            $ownerSid = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
            if ($ownerSid) { $node.ownerSid = $ownerSid.Value }
        } catch { }

        foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            $ace = @{
                sid          = $sid
                accessType   = $rule.AccessControlType.ToString()
                rights       = [int]$rule.ActiveDirectoryRights
                rightsText   = $rule.ActiveDirectoryRights.ToString()
                objectGuid   = $rule.ObjectType.ToString()
                inheritGuid  = $rule.InheritedObjectType.ToString()
                inheritType  = $rule.InheritanceType.ToString()
                inherited    = [bool]$rule.IsInherited
            }
            [void]$node.aces.Add($ace)

            if ($ace.accessType -eq 'Deny' -and $sid -eq 'S-1-1-0' -and -not $ace.inherited -and
                (($ace.rights -band [System.DirectoryServices.ActiveDirectoryRights]::Delete) -or
                 ($ace.rights -band [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree))) {
                $node.protectedFromDelete = $true
            }
        }
    } catch {
        $node.aclError = "The security descriptor could not be parsed: $($_.Exception.Message)"
    }

    $node
}

function Get-ObjectCountsByContainer {
    <#
        One subtree pass that counts the users, computers, groups and contacts
        that live directly under each container.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]] $SearchBase)

    $counts = @{}
    $filter = '(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=contact)(objectClass=msDS-GroupManagedServiceAccount))'

    foreach ($base in $SearchBase) {
        Write-AuditLog -Level Step "Counting objects under $base"
        $results = Invoke-AdSearch -SearchRoot $base -Filter $filter -Properties @('distinguishedName', 'objectClass')

        foreach ($r in $results) {
            $dn = [string](Get-ResultValue -Result $r -Name 'distinguishedName')
            if (-not $dn) { continue }
            $parent = Get-ParentDistinguishedName -Dn $dn
            if (-not $parent) { continue }

            $classes = @(Get-ResultValues -Result $r -Name 'objectClass')
            $kind = if ($classes -contains 'computer') { 'computer' }
                    elseif ($classes -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' }
                    elseif ($classes -contains 'group') { 'group' }
                    elseif ($classes -contains 'contact') { 'contact' }
                    else { 'user' }

            $key = $parent.ToLowerInvariant()
            if (-not $counts.ContainsKey($key)) {
                $counts[$key] = @{ user = 0; computer = 0; group = 0; contact = 0; gMSA = 0 }
            }
            $counts[$key][$kind] = $counts[$key][$kind] + 1
        }
    }

    $counts
}

function Get-GpoInventory {
    <#
        Every Group Policy object in the domain with the trustees that can edit
        it. Editing a GPO is equivalent to running code on everything it applies to.
    #>
    [CmdletBinding()]
    param()

    $gpos = [System.Collections.Generic.List[object]]::new()
    $policiesDn = "CN=Policies,CN=System,$($Script:Ctx.DomainDn)"

    try {
        $results = Invoke-AdSearch -SearchRoot $policiesDn -Filter '(objectClass=groupPolicyContainer)' -Properties @(
            'distinguishedName', 'cn', 'displayName', 'whenCreated', 'whenChanged', 'versionNumber',
            'flags', 'gPCFileSysPath', 'nTSecurityDescriptor') -WithSecurityDescriptor
    } catch {
        Write-AuditLog -Level Warn "Group Policy objects could not be read: $($_.Exception.Message)"
        return , $gpos
    }

    $R = [System.DirectoryServices.ActiveDirectoryRights]
    $editMask = $R::GenericAll -bor $R::WriteProperty -bor $R::WriteDacl -bor $R::WriteOwner -bor $R::CreateChild -bor $R::DeleteChild -bor $R::Delete

    foreach ($r in $results) {
        $dn = [string](Get-ResultValue -Result $r -Name 'distinguishedName')
        $g = @{
            dn       = $dn
            guid     = [string](Get-ResultValue -Result $r -Name 'cn')
            name     = [string](Get-ResultValue -Result $r -Name 'displayName')
            created  = $null
            changed  = $null
            version  = [int](Get-ResultValue -Result $r -Name 'versionNumber')
            flags    = [int](Get-ResultValue -Result $r -Name 'flags')
            editors  = ([System.Collections.Generic.List[object]]::new())
            links    = ([System.Collections.Generic.List[object]]::new())
        }
        if (-not $g.name) { $g.name = $g.guid }

        foreach ($f in @(@('whenCreated', 'created'), @('whenChanged', 'changed'))) {
            $v = Get-ResultValue -Result $r -Name $f[0]
            if ($v -is [datetime]) { $g[$f[1]] = $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        }

        $sdBytes = Get-ResultValue -Result $r -Name 'nTSecurityDescriptor'
        if ($sdBytes) {
            try {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm([byte[]]$sdBytes)
                foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }
                    if (-not ([int]$rule.ActiveDirectoryRights -band [int]$editMask)) { continue }

                    $trustee = Resolve-Trustee -Sid $rule.IdentityReference.Value
                    $objInfo = Get-GuidName -Guid $rule.ObjectType.ToString()
                    $perms   = ConvertTo-PermissionList -Rights $rule.ActiveDirectoryRights -ObjectTypeInfo $objInfo

                    [void]$g.editors.Add(@{
                        t         = $trustee.id
                        perms     = $perms
                        inherited = [bool]$rule.IsInherited
                        expected  = $trustee.tier0
                    })
                }
            } catch {
                Write-AuditLog -Level Info "Permissions on GPO '$($g.name)' could not be parsed: $($_.Exception.Message)"
            }
        }

        [void]$gpos.Add($g)
    }

    Write-AuditLog -Level Step "Read $($gpos.Count) Group Policy objects"
    , $gpos
}

function Get-GroupMembership {
    <#
        Direct, nested and primary-group members of one group. Nested membership
        uses LDAP_MATCHING_RULE_IN_CHAIN so the server does the recursion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $GroupDn,
        [int] $Rid = -1
    )

    $members = @{}
    $escaped = ConvertTo-LdapFilterValue -Value $GroupDn
    $props   = @('distinguishedName', 'sAMAccountName', 'objectClass', 'userAccountControl', 'adminCount', 'objectSid')

    $add = {
        param($Result, [string] $Via)

        $dn = [string](Get-ResultValue -Result $Result -Name 'distinguishedName')
        if (-not $dn) { return }

        $key = $dn.ToLowerInvariant()
        if ($members.ContainsKey($key)) {
            if ($members[$key].via -eq 'nested' -and $Via -eq 'direct') { $members[$key].via = 'direct' }
            return
        }

        $classes = @(Get-ResultValues -Result $Result -Name 'objectClass')
        $uac     = [int](Get-ResultValue -Result $Result -Name 'userAccountControl')
        $cls     = if ($classes -contains 'computer') { 'computer' }
                   elseif ($classes -contains 'group') { 'group' }
                   elseif ($classes -contains 'msDS-GroupManagedServiceAccount') { 'gMSA' }
                   elseif ($classes -contains 'foreignSecurityPrincipal') { 'foreign' }
                   else { 'user' }

        $members[$key] = @{
            dn         = $dn
            name       = [string](Get-ResultValue -Result $Result -Name 'sAMAccountName')
            class      = $cls
            via        = $Via
            disabled   = [bool]($uac -band 0x2)
            adminCount = ([int](Get-ResultValue -Result $Result -Name 'adminCount')) -eq 1
        }
        if (-not $members[$key].name) { $members[$key].name = (Split-DistinguishedName -Dn $dn)[0] -replace '^(?i)CN=', '' }
    }

    try {
        foreach ($r in (Invoke-AdSearch -SearchRoot $Script:Ctx.DomainDn -Filter "(memberOf=$escaped)" -Properties $props)) {
            & $add $r 'direct'
        }
        foreach ($r in (Invoke-AdSearch -SearchRoot $Script:Ctx.DomainDn -Filter "(memberOf:1.2.840.113556.1.4.1941:=$escaped)" -Properties $props)) {
            & $add $r 'nested'
        }
        if ($Rid -gt 0) {
            foreach ($r in (Invoke-AdSearch -SearchRoot $Script:Ctx.DomainDn -Filter "(primaryGroupID=$Rid)" -Properties $props)) {
                & $add $r 'primary group'
            }
        }
    } catch {
        Write-AuditLog -Level Info "Membership of '$GroupDn' could not be read in full: $($_.Exception.Message)"
    }

    , @($members.Values)
}

function Get-PrivilegedGroupReport {
    <#
        The groups that carry administrative power in the domain, with their
        effective membership.
    #>
    [CmdletBinding()]
    param()

    $report = [System.Collections.Generic.List[object]]::new()
    $done   = @{}

    $targets = [System.Collections.Generic.List[object]]::new()

    foreach ($spec in $Script:PrivilegedGroupRids) {
        $sid = switch ($spec.Scope) {
            'builtin' { "S-1-5-32-$($spec.Rid)" }
            'forest'  { if ($Script:Ctx.RootDomainSid) { "$($Script:Ctx.RootDomainSid)-$($spec.Rid)" } else { $null } }
            default   { if ($Script:Ctx.DomainSid) { "$($Script:Ctx.DomainSid)-$($spec.Rid)" } else { $null } }
        }
        if ($sid) { [void]$targets.Add(@{ Sid = $sid; Rid = $spec.Rid; Note = $spec.Note }) }
    }

    foreach ($spec in $Script:PrivilegedGroupNames) {
        $name = ConvertTo-LdapFilterValue -Value $spec.Name
        try {
            $found = Invoke-AdSearch -SearchRoot $Script:Ctx.DomainDn -Filter "(&(objectClass=group)(sAMAccountName=$name))" -Properties @('objectSid')
            foreach ($f in $found) {
                $raw = Get-ResultValue -Result $f -Name 'objectSid'
                if ($raw) {
                    $sid = (New-Object System.Security.Principal.SecurityIdentifier($raw, 0)).Value
                    [void]$targets.Add(@{ Sid = $sid; Rid = (Get-SidRid -Sid $sid); Note = $spec.Note })
                }
            }
        } catch { }
    }

    $i = 0
    foreach ($t in $targets) {
        $i++
        if ($done.ContainsKey($t.Sid)) { continue }
        $done[$t.Sid] = $true

        $trustee = Resolve-Trustee -Sid $t.Sid
        if ($trustee.class -eq 'unresolved') { continue }

        Write-Progress -Activity 'Reading privileged group membership' -Status $trustee.name -PercentComplete (($i / $targets.Count) * 100)

        $members = @()
        if ($trustee.dn) {
            $rid = if ($t.Sid -like 'S-1-5-32-*') { -1 } else { $t.Rid }
            $members = Get-GroupMembership -GroupDn $trustee.dn -Rid $rid
        }

        $trustee.privileged  = $true
        $trustee.memberCount = @($members).Count
        $trustee.members     = @($members)

        [void]$report.Add(@{
            t       = $trustee.id
            name    = $trustee.name
            sid     = $t.Sid
            dn      = $trustee.dn
            note    = $t.Note
            direct  = @($members | Where-Object { $_.via -eq 'direct' }).Count
            nested  = @($members | Where-Object { $_.via -eq 'nested' }).Count
            primary = @($members | Where-Object { $_.via -eq 'primary group' }).Count
            total   = @($members).Count
            members = @($members)
        })
    }
    Write-Progress -Activity 'Reading privileged group membership' -Completed

    Write-AuditLog -Level Step "Read membership of $($report.Count) privileged groups"
    , $report
}

function Get-AdminCountObjects {
    <#
        Accounts stamped by AdminSDHolder. A stamp that no longer matches current
        group membership is a leftover from a past privilege assignment.
    #>
    [CmdletBinding()]
    param()

    $list = [System.Collections.Generic.List[object]]::new()
    try {
        $results = Invoke-AdSearch -SearchRoot $Script:Ctx.DomainDn `
            -Filter '(&(adminCount=1)(|(objectClass=user)(objectClass=computer))(!(objectClass=group)))' `
            -Properties @('distinguishedName', 'sAMAccountName', 'objectClass', 'userAccountControl')

        foreach ($r in $results) {
            $uac = [int](Get-ResultValue -Result $r -Name 'userAccountControl')
            [void]$list.Add(@{
                dn       = [string](Get-ResultValue -Result $r -Name 'distinguishedName')
                name     = [string](Get-ResultValue -Result $r -Name 'sAMAccountName')
                disabled = [bool]($uac -band 0x2)
            })
        }
    } catch {
        Write-AuditLog -Level Info "adminCount objects could not be read: $($_.Exception.Message)"
    }
    , $list
}

#endregion

#region ----------------------------------------------------------- model build

function Build-AuditModel {
    <#
        Links the collected nodes into a tree, folds the access control entries
        into a deduplicated table, works out which parent each inherited entry
        came from, and attaches Group Policy links and object counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Nodes,
        $ObjectCounts = @{},
        $Gpos = @(),
        [int] $MaxDepth = 0,
        [switch] $DelegationsOnly
    )

    # --- order, index and link -------------------------------------------------
    $ordered = @($Nodes | Sort-Object @{ Expression = { (Get-DnDepth -Dn $_.dn) } }, @{ Expression = { $_.dn } })

    $byDn = @{}
    foreach ($n in $ordered) { $byDn[$n.dn.ToLowerInvariant()] = $n }

    $resolveParent = {
        param([string] $Dn)
        $p = Get-ParentDistinguishedName -Dn $Dn
        while ($p) {
            if ($byDn.ContainsKey($p.ToLowerInvariant())) { return $byDn[$p.ToLowerInvariant()] }
            $p = Get-ParentDistinguishedName -Dn $p
        }
        $null
    }

    foreach ($n in $ordered) {
        $parent = & $resolveParent $n.dn
        $n.parentNode = $parent
        $n.depth = if ($parent) { $parent.depth + 1 } else { 0 }
        $n.path  = if ($parent) { "$($parent.path)/$($n.name)" } else { $n.name }
    }

    if ($MaxDepth -gt 0) {
        $ordered = @($ordered | Where-Object { $_.depth -le $MaxDepth })
        $byDn = @{}
        foreach ($n in $ordered) { $byDn[$n.dn.ToLowerInvariant()] = $n }
    }

    $id = 0
    foreach ($n in $ordered) { $n.id = $id; $id++ }
    foreach ($n in $ordered) {
        $n.parent = if ($n.parentNode -and $byDn.ContainsKey($n.parentNode.dn.ToLowerInvariant())) { $n.parentNode.id } else { $null }
    }

    # --- Group Policy links ----------------------------------------------------
    $gpoByDn = @{}
    for ($i = 0; $i -lt @($Gpos).Count; $i++) {
        $Gpos[$i].id = $i
        $gpoByDn[$Gpos[$i].dn.ToLowerInvariant()] = $Gpos[$i]
    }

    foreach ($n in $ordered) {
        $n.gpo = @()
        if (-not $n.gpLinkRaw) { continue }

        $links = [System.Collections.Generic.List[object]]::new()
        foreach ($m in [regex]::Matches($n.gpLinkRaw, '\[LDAP://(?<dn>[^;\]]+);(?<opt>\d+)\]')) {
            $linkDn = $m.Groups['dn'].Value.Trim()
            $opt    = [int]$m.Groups['opt'].Value
            $gpo    = if ($gpoByDn.ContainsKey($linkDn.ToLowerInvariant())) { $gpoByDn[$linkDn.ToLowerInvariant()] } else { $null }

            $entry = @{
                gpo      = if ($gpo) { $gpo.id } else { $null }
                name     = if ($gpo) { $gpo.name } else { ((Split-DistinguishedName -Dn $linkDn)[0] -replace '^(?i)CN=', '') }
                dn       = $linkDn
                disabled = [bool]($opt -band 1)
                enforced = [bool]($opt -band 2)
            }
            [void]$links.Add($entry)

            if ($gpo) {
                [void]$gpo.links.Add(@{ node = $n.id; enforced = $entry.enforced; disabled = $entry.disabled })
            }
        }
        $n.gpo = @($links)
    }

    # --- access control entries ------------------------------------------------
    $aceDefs  = [System.Collections.Generic.List[object]]::new()
    $defByKey = @{}

    foreach ($n in $ordered) {
        $explicitKeys = @{}
        $refs = [System.Collections.Generic.List[object]]::new()

        foreach ($ace in $n.aces) {
            $trustee = Resolve-Trustee -Sid $ace.sid
            $objInfo = Get-GuidName -Guid $ace.objectGuid
            $iotInfo = Get-GuidName -Guid $ace.inheritGuid

            $matchKey = '{0}|{1}|{2}|{3}|{4}' -f $ace.sid, $ace.accessType, $ace.rights, $ace.objectGuid, $ace.inheritGuid
            if (-not $ace.inherited) { $explicitKeys[$matchKey] = $true }

            $defKey = '{0}|{1}' -f $matchKey, $ace.inheritType
            if (-not $defByKey.ContainsKey($defKey)) {
                $assessment = Get-AceAssessment -Rights $ace.rights -ObjectTypeInfo $objInfo -Trustee $trustee -AccessType $ace.accessType

                $def = @{
                    id       = $aceDefs.Count
                    t        = $trustee.id
                    type     = $ace.accessType
                    # No @() here: the helper already returns the array intact, and wrapping it again nests it.
                    perms    = ConvertTo-PermissionList -Rights $ace.rights -ObjectTypeInfo $objInfo
                    applies  = Get-AceAppliesTo -InheritanceType $ace.inheritType -InheritedObjectClass $(if ($iotInfo) { $iotInfo.Name } else { '' })
                    obj      = $(if ($objInfo) { $objInfo.Name } else { '' })
                    objKind  = $(if ($objInfo) { $objInfo.Kind } else { '' })
                    sev      = $assessment.Severity
                    raw      = $assessment.RawSeverity
                    cats     = @($assessment.Categories)
                    notes    = @($assessment.Notes)
                    expected = $assessment.Expected
                    mask     = $ace.rightsText
                }
                $defByKey[$defKey] = $def
                [void]$aceDefs.Add($def)
            }

            [void]$refs.Add(@{
                d   = $defByKey[$defKey].id
                i   = [int][bool]$ace.inherited
                key = $matchKey
                src = $null
            })
        }

        $n.explicitKeys = $explicitKeys
        $n.aceRefs = $refs
    }

    # --- where did each inherited entry come from ------------------------------
    $byId = @{}
    foreach ($n in $ordered) { $byId[$n.id] = $n }

    foreach ($n in $ordered) {
        foreach ($ref in $n.aceRefs) {
            if ($ref.i -ne 1) { continue }
            $cursor = if ($null -ne $n.parent) { $byId[$n.parent] } else { $null }
            while ($cursor) {
                if ($cursor.explicitKeys.ContainsKey($ref.key)) { $ref.src = $cursor.id; break }
                $cursor = if ($null -ne $cursor.parent) { $byId[$cursor.parent] } else { $null }
            }
        }
    }

    # --- counts, badges and payload shaping ------------------------------------
    foreach ($n in $ordered) {
        $direct = $ObjectCounts[$n.dn.ToLowerInvariant()]
        $n.counts = @{
            user     = if ($direct) { $direct.user } else { 0 }
            computer = if ($direct) { $direct.computer } else { 0 }
            group    = if ($direct) { $direct.group } else { 0 }
            contact  = if ($direct) { $direct.contact } else { 0 }
            gMSA     = if ($direct) { $direct.gMSA } else { 0 }
        }
        $n.subtree   = @{ user = $n.counts.user; computer = $n.counts.computer; group = $n.counts.group; ou = 0 }
        $n.childCount = 0
    }

    foreach ($n in $ordered) {
        if ($null -ne $n.parent) { $byId[$n.parent].childCount++ }
    }

    # Deepest first, so each node has already collected its own children.
    foreach ($n in ($ordered | Sort-Object -Property @{ Expression = { $_.depth } } -Descending)) {
        if ($null -eq $n.parent) { continue }
        $p = $byId[$n.parent]
        $p.subtree.user     += $n.subtree.user
        $p.subtree.computer += $n.subtree.computer
        $p.subtree.group    += $n.subtree.group
        $p.subtree.ou       += ($n.subtree.ou + 1)
    }

    $payloadNodes = [System.Collections.Generic.List[object]]::new()
    foreach ($n in $ordered) {
        $ownerTrustee = if ($n.ownerSid) { Resolve-Trustee -Sid $n.ownerSid } else { $null }

        $refs = @($n.aceRefs | Where-Object { -not $DelegationsOnly -or $_.i -eq 0 })
        $explicitSevs = @()
        $allSevs      = @()
        foreach ($r in $n.aceRefs) {
            $s = $aceDefs[$r.d].sev
            $allSevs += $s
            if ($r.i -eq 0) { $explicitSevs += $s }
        }

        [void]$payloadNodes.Add(@{
            id            = $n.id
            dn            = $n.dn
            name          = $n.name
            path          = $n.path
            type          = $n.type
            parent        = $n.parent
            depth         = $n.depth
            description   = $n.description
            managedBy     = $n.managedBy
            created       = $n.whenCreated
            changed       = $n.whenChanged
            critical      = $n.critical
            owner         = $(if ($ownerTrustee) { $ownerTrustee.id } else { $null })
            blocked       = $n.inheritanceBlocked
            protected     = $n.protectedFromDelete
            gpoBlocked    = [bool]($n.gpOptions -band 1)
            gpo           = @($n.gpo)
            counts        = $n.counts
            subtree       = $n.subtree
            childCount    = $n.childCount
            aclError      = $n.aclError
            explicitCount = @($n.aceRefs | Where-Object { $_.i -eq 0 }).Count
            aceCount      = @($n.aceRefs).Count
            maxSev        = Get-MaxSeverity -Severity $explicitSevs
            maxSevAll     = Get-MaxSeverity -Severity $allSevs
            aces          = @($refs | ForEach-Object { @{ d = $_.d; i = $_.i; s = $_.src } })
        })
    }

    @{
        Nodes    = $payloadNodes
        AceDefs  = $aceDefs
        Internal = $ordered
    }
}

#endregion

#region --------------------------------------------------------------- findings

function Get-AuditFindings {
    <#
        Turns the model into a reviewable list of observations, worst first.
        Everything here is derived from what was read; nothing is guessed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Model,
        $Gpos = @(),
        $PrivilegedGroups = @(),
        $AdminCountObjects = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $defs     = $Model.AceDefs
    $nodes    = $Model.Nodes
    $nodeById = @{}
    foreach ($n in $nodes) { $nodeById[$n.id] = $n }

    $add = {
        param([string] $Sev, [string] $Cat, [string] $Title, [string] $Detail, $NodeId, $TrusteeId, $GpoId)
        [void]$findings.Add(@{
            id = $findings.Count; sev = $Sev; cat = $Cat; title = $Title; detail = $Detail
            node = $NodeId; trustee = $TrusteeId; gpo = $GpoId
        })
    }

    # --- rights that matter, grouped per node and trustee ----------------------
    foreach ($n in $nodes) {
        if ($n.aclError) {
            & $add 'Low' 'Coverage' "Permissions on $($n.path) could not be read" $n.aclError $n.id $null $null
            continue
        }

        $byTrustee = @{}
        foreach ($ref in $n.aces) {
            if ($ref.i -ne 0) { continue }          # explicit entries are the delegations
            $def = $defs[$ref.d]
            if ($def.expected -or $def.type -eq 'Deny') { continue }
            if ($Script:SeverityOrder[$def.sev] -lt $Script:SeverityOrder['Medium']) { continue }

            if (-not $byTrustee.ContainsKey($def.t)) {
                $byTrustee[$def.t] = @{ sev = 'Info'; topCat = ''; perms = ([System.Collections.Generic.List[string]]::new());
                                        cats = ([System.Collections.Generic.List[string]]::new());
                                        notes = ([System.Collections.Generic.List[string]]::new()) }
            }
            $agg = $byTrustee[$def.t]
            # The headline follows the worst entry, so the title and the severity agree.
            if ($Script:SeverityOrder[$def.sev] -gt $Script:SeverityOrder[$agg.sev]) {
                $agg.sev = $def.sev
                if (@($def.cats).Count -gt 0) { $agg.topCat = @($def.cats)[0] }
            }
            foreach ($p in $def.perms) { if (-not $agg.perms.Contains($p)) { [void]$agg.perms.Add("$p ($($def.applies))") } }
            foreach ($c in $def.cats)  { if (-not $agg.cats.Contains($c))  { [void]$agg.cats.Add($c) } }
            foreach ($x in $def.notes) { if (-not $agg.notes.Contains($x)) { [void]$agg.notes.Add($x) } }
        }

        foreach ($tid in $byTrustee.Keys) {
            $agg = $byTrustee[$tid]
            $trustee = Get-TrusteeById -Id $tid
            $name = if ($trustee) { $trustee.name } else { "trustee $tid" }
            $topCat = if ($agg.topCat) { $agg.topCat } elseif ($agg.cats.Count -gt 0) { $agg.cats[0] } else { 'permissions' }
            $detail = "Permissions granted directly on this object: " + (($agg.perms | Select-Object -First 8) -join '; ') + '.'
            if ($agg.notes.Count -gt 0) { $detail += ' ' + ($agg.notes -join ' ') }
            & $add $agg.sev $topCat "$name holds $($topCat.ToLowerInvariant()) on $($n.path)" $detail $n.id $tid $null
        }

        # --- structural observations -------------------------------------------
        if ($n.owner) {
            $owner = Get-TrusteeById -Id $n.owner
            if ($owner -and -not $owner.tier0) {
                & $add 'Medium' 'Ownership' "$($n.path) is owned by $($owner.name)" `
                    'The owner of an object can always rewrite its permissions, whatever the access control list says. Ownership of an OU normally sits with Domain Admins or the built-in Administrators group.' `
                    $n.id $n.owner $null
            }
        }

        if ($n.blocked) {
            & $add 'Low' 'Inheritance' "Inheritance is blocked on $($n.path)" `
                'This object does not inherit permissions from its parent, so delegation applied higher up does not reach it and changes made there will not take effect here.' `
                $n.id $null $null
        }

        if ($n.type -eq 'OU' -and -not $n.protected) {
            & $add 'Low' 'Hygiene' "$($n.path) is not protected from accidental deletion" `
                'The OU has no explicit deny on Delete and Delete subtree for Everyone, so a mistaken delete removes it and everything under it.' `
                $n.id $null $null
        }
    }

    # --- trustees that need attention ------------------------------------------
    $explicitTrustees = @{}
    foreach ($n in $nodes) {
        foreach ($ref in $n.aces) {
            if ($ref.i -ne 0) { continue }
            $def = $defs[$ref.d]
            if (-not $explicitTrustees.ContainsKey($def.t)) { $explicitTrustees[$def.t] = [System.Collections.Generic.List[object]]::new() }
            [void]$explicitTrustees[$def.t].Add($n.id)
        }
    }

    foreach ($t in $Script:Ctx.TrusteeCache.Values) {
        if (-not $explicitTrustees.ContainsKey($t.id)) { continue }
        $where = @($explicitTrustees[$t.id] | Select-Object -Unique)

        if ($t.class -eq 'unresolved') {
            & $add 'Low' 'Hygiene' "Unresolvable SID $($t.sid) holds permissions" `
                "This SID appears in the access control list of $($where.Count) object(s) but no longer resolves to an account. It is usually the residue of a deleted principal and should be cleaned up." `
                $where[0] $t.id $null
        }
        if ($t.class -in @('user', 'computer')) {
            & $add 'Low' 'Manageability' "Permissions are delegated to the account $($t.name)" `
                "Rights are granted to an individual account on $($where.Count) object(s) rather than to a group. Account level delegation is invisible in group membership reviews and is missed when the person changes role." `
                $where[0] $t.id $null
        }
    }

    # --- Group Policy -----------------------------------------------------------
    foreach ($g in $Gpos) {
        $linkedNodes = @($g.links | ForEach-Object { $nodeById[$_.node] } | Where-Object { $_ })
        $computers   = ($linkedNodes | ForEach-Object { $_.subtree.computer } | Measure-Object -Sum).Sum
        if (-not $computers) { $computers = 0 }

        foreach ($e in $g.editors) {
            if ($e.expected) { continue }
            $trustee = Get-TrusteeById -Id $e.t
            if (-not $trustee -or $trustee.tier0) { continue }
            if ($trustee.sid -eq 'S-1-3-0') { continue }   # CREATOR OWNER on a GPO is the default

            $sev = if ($computers -gt 0) { 'High' } elseif ($g.links.Count -gt 0) { 'Medium' } else { 'Low' }
            $scope = if ($g.links.Count -eq 0) { 'The policy is not linked anywhere at the moment.' }
                     else { "The policy is linked to $($g.links.Count) object(s) covering $computers computer(s)." }

            & $add $sev 'Group Policy' "$($trustee.name) can edit the GPO '$($g.name)'" `
                "Write access to a Group Policy object means the ability to run code and change settings on everything the policy applies to. $scope" `
                $(if ($linkedNodes.Count -gt 0) { $linkedNodes[0].id } else { $null }) $e.t $g.id
        }
    }

    # --- privileged groups ------------------------------------------------------
    $legacy = @{
        'S-1-5-32-548' = @('High',   'Account Operators can modify most user, group and computer accounts and is not protected by AdminSDHolder. Microsoft recommends it stays empty.')
        'S-1-5-32-549' = @('Medium', 'Server Operators can log on to domain controllers and manage their services, which is equivalent to domain compromise.')
        'S-1-5-32-550' = @('Medium', 'Print Operators can load drivers on domain controllers and log on to them locally.')
        'S-1-5-32-551' = @('Medium', 'Backup Operators can read and write any file on a domain controller, including the database.')
        'S-1-5-32-552' = @('Medium', 'Replicator is a legacy service group and should have no members.')
        'S-1-5-32-554' = @('Medium', 'Pre-Windows 2000 Compatible Access grants read of most directory attributes to its members. Anonymous or wide membership here exposes the directory.')
    }

    foreach ($pg in $PrivilegedGroups) {
        $members = @($pg.members)
        if ($legacy.ContainsKey($pg.sid) -and $members.Count -gt 0) {
            & $add $legacy[$pg.sid][0] 'Privileged group' "$($pg.name) has $($members.Count) member(s)" `
                ($legacy[$pg.sid][1] + ' Members: ' + (($members | Select-Object -First 12 | ForEach-Object { $_.name }) -join ', ') + '.') `
                $null $pg.t $null
        }

        if ($pg.name -match '(?i)DnsAdmins' -and $members.Count -gt 0) {
            & $add 'Medium' 'Privileged group' "DnsAdmins has $($members.Count) member(s)" `
                'Members have historically been able to load an arbitrary DLL into the DNS service, which runs as SYSTEM on a domain controller. Treat membership as Tier 0.' `
                $null $pg.t $null
        }

        $nestedGroups = @($members | Where-Object { $_.class -eq 'group' })
        if ($nestedGroups.Count -gt 0 -and $pg.sid -match '-(512|519|518)$') {
            & $add 'Medium' 'Privileged group' "$($pg.name) contains nested group(s)" `
                ("Membership is granted through " + (($nestedGroups | ForEach-Object { $_.name }) -join ', ') + ". Anyone who can change those groups can grant themselves the privilege, so they inherit the same Tier 0 status.") `
                $null $pg.t $null
        }

        $disabled = @($members | Where-Object { $_.disabled })
        if ($disabled.Count -gt 0) {
            & $add 'Low' 'Privileged group' "$($pg.name) contains $($disabled.Count) disabled account(s)" `
                ('Disabled accounts still carry the privilege if they are re-enabled: ' + (($disabled | Select-Object -First 12 | ForEach-Object { $_.name }) -join ', ') + '.') `
                $null $pg.t $null
        }

        if ($pg.sid -match '-512$' -and $members.Count -gt 10) {
            & $add 'Low' 'Privileged group' "Domain Admins has $($members.Count) effective members" `
                'A large Domain Admins group is hard to review and widens the blast radius of any single compromised account. Move day to day work into delegated roles.' `
                $null $pg.t $null
        }
    }

    # --- AdminSDHolder residue ---------------------------------------------------
    if (@($AdminCountObjects).Count -gt 0 -and @($PrivilegedGroups).Count -gt 0) {
        $protectedDns = @{}
        foreach ($pg in $PrivilegedGroups) {
            foreach ($m in $pg.members) { $protectedDns[$m.dn.ToLowerInvariant()] = $true }
        }
        $stale = @($AdminCountObjects | Where-Object { -not $protectedDns.ContainsKey($_.dn.ToLowerInvariant()) })
        if ($stale.Count -gt 0) {
            & $add 'Low' 'Hygiene' "$($stale.Count) account(s) still carry the AdminSDHolder stamp" `
                ('These accounts have adminCount set to 1 but are no longer members of a protected group, so they keep a locked down access control list and no longer inherit from their OU: ' +
                 (($stale | Select-Object -First 15 | ForEach-Object { $_.name }) -join ', ') + '.') `
                $null $null $null
        }
    }

    $sorted = @($findings | Sort-Object -Property `
        @{ Expression = { $Script:SeverityOrder[$_.sev] }; Descending = $true }, `
        @{ Expression = { $_.title }; Descending = $false })

    $i = 0
    foreach ($f in $sorted) { $f.id = $i; $i++ }

    , $sorted
}

#endregion

#region -------------------------------------------------------------- reporting

function ConvertTo-ReportJson {
    <#
        JSON for embedding in a script element: the three characters that could
        end the element early are escaped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Data)

    $json = $Data | ConvertTo-Json -Depth 12 -Compress
    $json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
}

function New-AuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Data,
        [Parameter(Mandatory)][string] $Path
    )

    $html = (Get-ReportTemplate).Replace('/*__AUDIT_DATA__*/null', (ConvertTo-ReportJson -Data $Data))
    $html = $html.Replace('__REPORT_TITLE__', [System.Net.WebUtility]::HtmlEncode("AD permission audit - $($Data.meta.domain)"))

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $html, $utf8)
    $Path
}

function Export-AuditCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Data,
        [Parameter(Mandatory)][string] $Path
    )

    $nodeById = @{}
    foreach ($n in $Data.nodes) { $nodeById[$n.id] = $n }
    $trusteeById = @{}
    foreach ($t in $Data.trustees) { $trusteeById[$t.id] = $t }

    $rows = foreach ($n in $Data.nodes) {
        foreach ($ref in $n.aces) {
            $def = $Data.aceDefs[$ref.d]
            $t   = $trusteeById[$def.t]
            [pscustomobject][ordered]@{
                Path          = $n.path
                DistinguishedName = $n.dn
                ObjectType    = $n.type
                Trustee       = $t.name
                TrusteeSid    = $t.sid
                TrusteeClass  = $t.class
                AccessType    = $def.type
                Permissions   = ($def.perms -join '; ')
                AppliesTo     = $def.applies
                Inherited     = [bool]$ref.i
                InheritedFrom = $(if ($null -ne $ref.s -and $nodeById.ContainsKey($ref.s)) { $nodeById[$ref.s].path } else { '' })
                Severity      = $def.sev
                Categories    = ($def.cats -join '; ')
                ExpectedDefault = $def.expected
                RightsMask    = $def.mask
            }
        }
    }

    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    $Path
}

#endregion

#region ------------------------------------------------------------------- main

function Invoke-Main {
    [CmdletBinding()]
    param(
        [string[]] $SearchBase,
        [string] $Server,
        $Credential,
        [string] $OutputPath,
        [int] $MaxDepth,
        [switch] $IncludeContainers,
        [switch] $DelegationsOnly,
        [switch] $SkipObjectCounts,
        [switch] $SkipPrivilegedGroups,
        [switch] $SkipGpo,
        [switch] $ExportData,
        [switch] $Show,
        [switch] $PassThru,
        [string] $Version
    )

    $started = Get-Date
    Write-Host ''
    Write-Host 'Active Directory OU permission audit' -ForegroundColor White
    Write-Host 'Read only. No object in the directory is created, changed or deleted.' -ForegroundColor DarkGray
    Write-Host ''

    Initialize-AuditContext -Server $Server -Credential $Credential

    if (-not $SearchBase -or $SearchBase.Count -eq 0) { $SearchBase = @($Script:Ctx.DomainDn) }

    $Script:Ctx.GuidMap = Get-DirectoryGuidMap

    $nodes = Get-OuNodes -SearchBase $SearchBase -IncludeContainers:$IncludeContainers
    if (@($nodes).Count -eq 0) { throw "No organisational units were returned for search base(s) '$($SearchBase -join ', ')'." }
    Write-AuditLog -Level Step "Read $(@($nodes).Count) objects"

    $counts = if ($SkipObjectCounts) { @{} } else { Get-ObjectCountsByContainer -SearchBase $SearchBase }
    $gpos   = if ($SkipGpo) { @() } else { Get-GpoInventory }

    $model = Build-AuditModel -Nodes $nodes -ObjectCounts $counts -Gpos $gpos -MaxDepth $MaxDepth -DelegationsOnly:$DelegationsOnly

    $privileged = if ($SkipPrivilegedGroups) { @() } else { Get-PrivilegedGroupReport }
    $adminCount = if ($SkipPrivilegedGroups) { @() } else { Get-AdminCountObjects }

    Write-AuditLog -Level Step 'Assessing permissions'
    $findings = Get-AuditFindings -Model $model -Gpos $gpos -PrivilegedGroups $privileged -AdminCountObjects $adminCount

    # --- statistics --------------------------------------------------------------
    $sevCounts     = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    $findingCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    $explicitTotal = 0

    foreach ($n in $model.Nodes) {
        foreach ($ref in $n.aces) {
            if ($ref.i -ne 0) { continue }
            $explicitTotal++
            $sevCounts[$model.AceDefs[$ref.d].sev]++
        }
    }
    foreach ($f in $findings) { $findingCounts[$f.sev]++ }

    $trustees = @($Script:Ctx.TrusteeCache.Values | Sort-Object -Property @{ Expression = { $_.id } })

    $data = @{
        meta = @{
            generated    = $started.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            generatedText= $started.ToString('yyyy-MM-dd HH:mm:ss')
            domain       = $Script:Ctx.DomainName
            forest       = $Script:Ctx.ForestName
            domainDn     = $Script:Ctx.DomainDn
            domainSid    = $Script:Ctx.DomainSid
            server       = $Script:Ctx.Server
            searchBase   = @($SearchBase)
            runAs        = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
            computer     = [Environment]::MachineName
            version      = $Version
            duration     = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
            warnings     = @($Script:Ctx.Warnings)
            options      = @{
                includeContainers    = [bool]$IncludeContainers
                delegationsOnly      = [bool]$DelegationsOnly
                skipObjectCounts     = [bool]$SkipObjectCounts
                skipPrivilegedGroups = [bool]$SkipPrivilegedGroups
                skipGpo              = [bool]$SkipGpo
                maxDepth             = $MaxDepth
            }
        }
        stats = @{
            nodes         = @($model.Nodes).Count
            aceDefs       = @($model.AceDefs).Count
            explicitAces  = $explicitTotal
            trustees      = $trustees.Count
            gpos          = @($gpos).Count
            severity      = $sevCounts
            findings      = $findingCounts
        }
        nodes            = @($model.Nodes)
        aceDefs          = @($model.AceDefs)
        trustees         = $trustees
        gpos             = @($gpos)
        privilegedGroups = @($privileged)
        adminCount       = @($adminCount)
        findings         = @($findings)
    }

    if (-not $OutputPath) {
        $stamp = $started.ToString('yyyyMMdd-HHmmss')
        $safe  = ($Script:Ctx.DomainName -replace '[^\w\.-]', '_')
        $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath "AD-OU-Permission-Audit_${safe}_$stamp.html"
    }
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath $OutputPath
    }

    $reportPath = New-AuditReport -Data $data -Path $OutputPath

    $written = @($reportPath)
    if ($ExportData) {
        $base = [System.IO.Path]::ChangeExtension($reportPath, $null).TrimEnd('.')
        $jsonPath = "$base.json"
        $csvPath  = "$base.csv"
        ($data | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        $null = Export-AuditCsv -Data $data -Path $csvPath
        $written += @($jsonPath, $csvPath)
    }

    # --- console summary ----------------------------------------------------------
    Write-Host ''
    Write-Host ("  {0,-28} {1}" -f 'Domain', $data.meta.domain)
    Write-Host ("  {0,-28} {1}" -f 'Objects audited', $data.stats.nodes)
    Write-Host ("  {0,-28} {1}" -f 'Explicit delegations', $data.stats.explicitAces)
    Write-Host ("  {0,-28} {1}" -f 'Distinct trustees', $data.stats.trustees)
    Write-Host ("  {0,-28} {1}" -f 'Group Policy objects', $data.stats.gpos)
    Write-Host ''
    foreach ($s in @('Critical', 'High', 'Medium', 'Low')) {
        $colour = switch ($s) { 'Critical' { 'Red' } 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'DarkGray' } }
        Write-Host ("  {0,-28} {1}" -f "$s findings", $findingCounts[$s]) -ForegroundColor $colour
    }
    Write-Host ''
    foreach ($w in $written) { Write-Host "  Written: $w" -ForegroundColor Green }
    Write-Host ("  Completed in {0} seconds." -f $data.meta.duration) -ForegroundColor DarkGray
    Write-Host ''

    if ($Show) {
        try { Start-Process -FilePath $reportPath } catch { Write-AuditLog -Level Warn "Could not open the report: $($_.Exception.Message)" }
    }

    if ($PassThru) { $data }
}

#endregion

#region -------------------------------------------------------------- template

function Get-ReportTemplate {
    <#
        The report is one self-contained HTML file: no scripts, fonts or styles
        are loaded from anywhere, so it opens on an isolated management host and
        can be handed to an auditor as a single artefact.
    #>
    [CmdletBinding()]
    param()

    @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__REPORT_TITLE__</title>
<style>
:root{
  --bg:#f4f6f8; --panel:#fff; --panel2:#fafbfc; --ink:#14171c; --muted:#5d6673; --faint:#8b95a3;
  --line:#e0e4ea; --line2:#eef1f5; --accent:#2b5fd9; --accent-soft:#e8effc;
  --crit:#a8071a; --high:#d4380d; --med:#c07600; --low:#2b6cb0; --info:#6b7280;
  --crit-bg:#fdecec; --high-bg:#fdefe8; --med-bg:#fdf5e3; --low-bg:#eaf2fb; --info-bg:#f0f2f5;
  --ok:#1f7a4d; --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.10);
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
html[data-theme="dark"]{
  --bg:#0f1218; --panel:#161a21; --panel2:#1b2029; --ink:#e7ebf1; --muted:#9aa5b4; --faint:#727d8c;
  --line:#262c37; --line2:#1f242d; --accent:#6f9dff; --accent-soft:#1b2740;
  --crit:#ff7875; --high:#ff9c6e; --med:#ffc53d; --low:#69a9f5; --info:#9aa5b4;
  --crit-bg:#2a1618; --high-bg:#2a1c14; --med-bg:#2a2413; --low-bg:#141f2e; --info-bg:#1c212a;
  --ok:#52c48a; --shadow:0 1px 2px rgba(0,0,0,.4);
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0;background:var(--bg);color:var(--ink);
  font:13.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
button{font:inherit;color:inherit}
code,.mono{font-family:var(--mono);font-size:.92em}

/* ---------- chrome ---------- */
.topbar{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:12px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{display:flex;flex-direction:column;gap:2px;min-width:220px}
.brand h1{margin:0;font-size:15px;font-weight:650;letter-spacing:-.01em}
.brand .sub{color:var(--muted);font-size:12px}
.topmeta{display:flex;gap:16px;flex-wrap:wrap;margin-left:auto;align-items:center}
.kv{display:flex;flex-direction:column;line-height:1.35}
.kv .k{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint)}
.kv .v{font-size:12.5px;font-weight:550}
.tools{display:flex;gap:8px}
.btn{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:6px 11px;cursor:pointer;font-size:12.5px;transition:background .12s,border-color .12s}
.btn:hover{background:var(--panel2);border-color:var(--muted)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{filter:brightness(1.08)}

.tabs{display:flex;gap:2px;padding:0 14px;background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:20;overflow-x:auto}
.tab{border:0;background:none;padding:10px 14px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:520;border-bottom:2px solid transparent;white-space:nowrap}
.tab:hover{color:var(--ink)}
.tab[aria-selected="true"]{color:var(--accent);border-bottom-color:var(--accent)}
.tab .cnt{display:inline-block;margin-left:6px;padding:1px 6px;border-radius:9px;background:var(--info-bg);color:var(--muted);font-size:11px;font-weight:600}

main{padding:18px 20px 60px}
.view{display:none}
.view.active{display:block}
h2.section{margin:0 0 12px;font-size:15px;font-weight:640}
h3.sub{margin:22px 0 10px;font-size:13px;font-weight:640;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow)}
.pad{padding:14px 16px}

/* ---------- cards ---------- */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 15px;box-shadow:var(--shadow)}
.card .n{font-size:25px;font-weight:660;letter-spacing:-.02em;line-height:1.15}
.card .l{color:var(--muted);font-size:12px;margin-top:2px}
.card .foot{color:var(--faint);font-size:11.5px;margin-top:6px}
.card.sev-crit .n{color:var(--crit)} .card.sev-high .n{color:var(--high)}
.card.sev-med .n{color:var(--med)} .card.sev-low .n{color:var(--low)}

/* ---------- badges ---------- */
.badge{display:inline-flex;align-items:center;gap:5px;padding:1.5px 8px;border-radius:20px;font-size:11px;font-weight:620;white-space:nowrap;border:1px solid transparent}
.badge.Critical{background:var(--crit-bg);color:var(--crit);border-color:color-mix(in srgb,var(--crit) 25%,transparent)}
.badge.High{background:var(--high-bg);color:var(--high);border-color:color-mix(in srgb,var(--high) 25%,transparent)}
.badge.Medium{background:var(--med-bg);color:var(--med);border-color:color-mix(in srgb,var(--med) 25%,transparent)}
.badge.Low{background:var(--low-bg);color:var(--low);border-color:color-mix(in srgb,var(--low) 25%,transparent)}
.badge.Info{background:var(--info-bg);color:var(--info);border-color:var(--line)}
.badge.plain{background:var(--info-bg);color:var(--muted);border-color:var(--line);font-weight:550}
.badge.ok{background:color-mix(in srgb,var(--ok) 12%,transparent);color:var(--ok);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.dot.Critical{background:var(--crit)} .dot.High{background:var(--high)} .dot.Medium{background:var(--med)}
.dot.Low{background:var(--low)} .dot.Info{background:transparent;border:1px solid var(--line)}

/* ---------- tables ---------- */
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel);box-shadow:var(--shadow)}
table{border-collapse:collapse;width:100%;font-size:12.8px}
th{text-align:left;font-weight:620;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--line);background:var(--panel2);white-space:nowrap;position:sticky;top:0}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--ink)}
th .arrow{opacity:.45;font-size:10px}
td{padding:8px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--panel2)}
tr.clickable{cursor:pointer}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.empty{padding:26px;text-align:center;color:var(--faint)}

/* ---------- filters ---------- */
.filters{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
input[type=search],input[type=text],select{
  background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:6px 10px;color:var(--ink);font:inherit;font-size:12.5px;min-width:180px
}
input:focus,select:focus{outline:2px solid var(--accent-soft);border-color:var(--accent)}
label.chk{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:12.5px;cursor:pointer;user-select:none}
.count{color:var(--faint);font-size:12px;margin-left:auto}

/* ---------- split ---------- */
.split{display:grid;grid-template-columns:minmax(300px,400px) 1fr;gap:14px;align-items:start}
@media (max-width:1000px){.split{grid-template-columns:1fr}}
.pane{background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);overflow:hidden}
.pane-head{padding:10px 12px;border-bottom:1px solid var(--line);background:var(--panel2);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.pane-body{max-height:calc(100vh - 260px);overflow:auto}
.pane-body.tall{max-height:calc(100vh - 210px)}

/* ---------- tree ---------- */
.tnode{display:flex;align-items:center;gap:6px;padding:4px 10px 4px 0;cursor:pointer;border-left:2px solid transparent;font-size:12.8px}
.tnode:hover{background:var(--panel2)}
.tnode.sel{background:var(--accent-soft);border-left-color:var(--accent)}
.tnode .caret{width:16px;flex:none;text-align:center;color:var(--faint);font-size:10px;transition:transform .12s}
.tnode .caret.open{transform:rotate(90deg)}
.tnode .caret.leaf{opacity:0;cursor:default}
.tnode .ico{flex:none;opacity:.75}
.tnode .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tnode .tag{flex:none;font-size:10.5px;color:var(--faint);font-variant-numeric:tabular-nums}
.tnode.hit .nm{background:color-mix(in srgb,var(--med) 25%,transparent);border-radius:3px}
.tkids.collapsed{display:none}

/* ---------- detail ---------- */
.dhead{padding:14px 16px;border-bottom:1px solid var(--line)}
.dhead h2{margin:0 0 4px;font-size:16px;font-weight:650;letter-spacing:-.01em}
.dhead .dn{font-family:var(--mono);font-size:11.5px;color:var(--muted);word-break:break-all}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px 20px;padding:14px 16px;border-bottom:1px solid var(--line)}
.fact .k{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint)}
.fact .v{font-size:13px;margin-top:1px;word-break:break-word}
.subtabs{display:flex;gap:2px;padding:0 12px;border-bottom:1px solid var(--line);background:var(--panel2);flex-wrap:wrap}
.subtab{border:0;background:none;padding:9px 12px;cursor:pointer;color:var(--muted);font-size:12.5px;border-bottom:2px solid transparent}
.subtab[aria-selected="true"]{color:var(--accent);border-bottom-color:var(--accent)}
.dbody{padding:0}
.dbody table th{background:var(--panel)}

.notelist{margin:4px 0 0;padding-left:16px;color:var(--muted);font-size:12px}
.notelist li{margin:2px 0}
.perms{margin:0;padding:0;list-style:none}
.perms li{padding:1px 0}
.src{color:var(--faint);font-size:11.5px}
.linkish{color:var(--accent);cursor:pointer}
.linkish:hover{text-decoration:underline}

/* ---------- findings ---------- */
.finding{border:1px solid var(--line);border-left:3px solid var(--info);border-radius:9px;background:var(--panel);padding:12px 14px;margin-bottom:9px;box-shadow:var(--shadow)}
.finding.Critical{border-left-color:var(--crit)} .finding.High{border-left-color:var(--high)}
.finding.Medium{border-left-color:var(--med)} .finding.Low{border-left-color:var(--low)}
.finding h4{margin:0 0 5px;font-size:13.5px;font-weight:620;display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.finding p{margin:0;color:var(--muted);font-size:12.5px}
.finding .refs{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap}

/* ---------- misc ---------- */
.note{background:var(--med-bg);border:1px solid color-mix(in srgb,var(--med) 25%,transparent);color:var(--ink);border-radius:9px;padding:11px 14px;font-size:12.5px;margin-bottom:14px}
.prose{max-width:760px}
.prose p{color:var(--muted);margin:0 0 12px}
.prose h3{font-size:13.5px;margin:20px 0 8px}
.prose ul{color:var(--muted);padding-left:18px;margin:0 0 12px}
.prose li{margin:4px 0}
.bar{display:flex;height:9px;border-radius:5px;overflow:hidden;background:var(--line2);margin:10px 0 4px}
.bar span{display:block}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted)}
.legend i{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:5px}
@media print{
  .tabs,.tools,.filters,.pane-head{display:none!important}
  .view{display:block!important}
  body{background:#fff}
  .panel,.card,.tablewrap,.finding{box-shadow:none}
  .pane-body{max-height:none!important;overflow:visible!important}
}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <h1 id="hDomain">Active Directory permission audit</h1>
    <div class="sub" id="hSub">OU structure, delegation and administrative rights</div>
  </div>
  <div class="topmeta" id="topmeta"></div>
  <div class="tools">
    <button class="btn" id="btnTheme" title="Switch between light and dark">Theme</button>
    <button class="btn" id="btnPrint">Print</button>
  </div>
</header>

<nav class="tabs" id="tabs" role="tablist"></nav>

<main>
  <section class="view" id="view-overview"></section>

  <section class="view" id="view-tree">
    <div class="split">
      <div class="pane">
        <div class="pane-head">
          <input type="search" id="treeSearch" placeholder="Filter the tree (name or DN)" style="flex:1">
          <button class="btn" id="btnExpand">Expand</button>
          <button class="btn" id="btnCollapse">Collapse</button>
          <label class="chk"><input type="checkbox" id="onlyDelegated"> Only objects with explicit delegation</label>
        </div>
        <div class="pane-body tall" id="tree"></div>
      </div>
      <div class="pane" id="ouDetail"></div>
    </div>
  </section>

  <section class="view" id="view-delegations">
    <div class="filters">
      <input type="search" id="dSearch" placeholder="Search trustee, permission or path">
      <select id="dSev">
        <option value="">Any severity</option>
        <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option>
      </select>
      <select id="dCat"><option value="">Any category</option></select>
      <label class="chk"><input type="checkbox" id="dInherited"> Include inherited</label>
      <label class="chk"><input type="checkbox" id="dExpected"> Include Tier 0 defaults</label>
      <button class="btn" id="btnCsv">Download CSV</button>
      <span class="count" id="dCount"></span>
    </div>
    <div class="tablewrap"><table id="dTable"></table></div>
  </section>

  <section class="view" id="view-principals">
    <div class="split">
      <div class="pane">
        <div class="pane-head">
          <input type="search" id="pSearch" placeholder="Search principals" style="flex:1">
          <select id="pKind">
            <option value="">All principals</option>
            <option value="withRights">With explicit rights</option>
            <option value="group">Groups</option>
            <option value="user">Users</option>
            <option value="computer">Computers</option>
            <option value="privileged">Privileged</option>
            <option value="broad">Broad</option>
            <option value="unresolved">Unresolvable</option>
          </select>
        </div>
        <div class="pane-body tall" id="pList"></div>
      </div>
      <div class="pane" id="pDetail"></div>
    </div>
  </section>

  <section class="view" id="view-groups"></section>
  <section class="view" id="view-gpo"></section>

  <section class="view" id="view-findings">
    <div class="filters">
      <input type="search" id="fSearch" placeholder="Search findings">
      <select id="fSev">
        <option value="">Any severity</option>
        <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
      </select>
      <select id="fCat"><option value="">Any category</option></select>
      <span class="count" id="fCount"></span>
    </div>
    <div id="fList"></div>
  </section>

  <section class="view" id="view-method"></section>
</main>

<script>
const DATA = /*__AUDIT_DATA__*/null;
</script>
<script>
(function () {
"use strict";

if (!DATA) {
  document.querySelector("main").innerHTML =
    '<div class="note">This report was opened from an unfilled template: no audit data is embedded.</div>';
  return;
}

/* ------------------------------------------------------------------ helpers */
const SEV = ["Critical", "High", "Medium", "Low", "Info"];
const SEVRANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const ICON = { Domain: "◆", OU: "▢", Container: "□", Builtin: "□", AdminSDHolder: "⚙" };
const CLSICON = { group: "◉", user: "●", computer: "■", gMSA: "◈", wellKnown: "○", foreign: "◌", external: "◌", unresolved: "✗", other: "○" };

const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));

function el(tag, cls, txt) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt !== undefined && txt !== null) n.textContent = String(txt);
  return n;
}
function frag() { return document.createDocumentFragment(); }
function num(n) { return (n === null || n === undefined) ? "" : Number(n).toLocaleString(); }
function arr(a) { return Array.isArray(a) ? a : (a === null || a === undefined ? [] : [a]); }
function badge(sev, label) { return el("span", "badge " + sev, label || sev); }
function plain(label) { return el("span", "badge plain", label); }
function dot(sev) { const d = el("span", "dot " + sev); d.title = sev; return d; }
/* An entry that is not a delegation: a directory default, or a deny entry. */
function flag(def) { return plain(def.type === "Deny" ? "deny" : "default"); }

function cell(row, content, cls) {
  const td = el("td", cls || null);
  if (content instanceof Node) td.appendChild(content);
  else if (content !== undefined && content !== null) td.textContent = String(content);
  row.appendChild(td);
  return td;
}
function headRow(table, cols) {
  const thead = el("thead"), tr = el("tr");
  cols.forEach(c => {
    const th = el("th", c.cls || null, c.label);
    if (c.sort) { th.classList.add("sortable"); th.dataset.key = c.sort; th.appendChild(el("span", "arrow", " ▼")); }
    tr.appendChild(th);
  });
  thead.appendChild(tr); table.appendChild(thead);
  return thead;
}
function emptyRow(table, cols, msg) {
  const tb = el("tbody"), tr = el("tr"), td = el("td", "empty", msg);
  td.colSpan = cols; tr.appendChild(td); tb.appendChild(tr); table.appendChild(tb);
}
function linkish(txt, fn) {
  const s = el("span", "linkish", txt);
  s.addEventListener("click", fn);
  return s;
}

/* -------------------------------------------------------------------- index */
const nodes = arr(DATA.nodes), defs = arr(DATA.aceDefs), trustees = arr(DATA.trustees);
const gpos = arr(DATA.gpos), pgroups = arr(DATA.privilegedGroups), findings = arr(DATA.findings);

const nodeById = {}, trusteeById = {}, gpoById = {}, kids = {}, roots = [];
nodes.forEach(n => { nodeById[n.id] = n; kids[n.id] = []; });
nodes.forEach(n => { if (n.parent === null || n.parent === undefined || !(n.parent in nodeById)) roots.push(n); else kids[n.parent].push(n); });
trustees.forEach(t => trusteeById[t.id] = t);
gpos.forEach(g => gpoById[g.id] = g);

const T = id => trusteeById[id] || { id: id, name: "(unknown principal)", short: "(unknown)", class: "unresolved", sid: "" };
const N = id => nodeById[id] || null;

/* every access control entry as a flat row */
const rows = [];
nodes.forEach(n => arr(n.aces).forEach(r => {
  const d = defs[r.d];
  if (!d) return;
  rows.push({ node: n, def: d, inherited: r.i === 1, src: (r.s === null || r.s === undefined) ? null : N(r.s), t: T(d.t) });
}));

const rowsByTrustee = {};
rows.forEach(r => { (rowsByTrustee[r.t.id] = rowsByTrustee[r.t.id] || []).push(r); });

const pgByTrustee = {};
pgroups.forEach(g => pgByTrustee[g.t] = g);

const editorsByTrustee = {};
gpos.forEach(g => arr(g.editors).forEach(e => { (editorsByTrustee[e.t] = editorsByTrustee[e.t] || []).push({ gpo: g, e: e }); }));

const findingsByNode = {}, findingsByTrustee = {};
findings.forEach(f => {
  if (f.node !== null && f.node !== undefined) (findingsByNode[f.node] = findingsByNode[f.node] || []).push(f);
  if (f.trustee !== null && f.trustee !== undefined) (findingsByTrustee[f.trustee] = findingsByTrustee[f.trustee] || []).push(f);
});

const allCats = {};
defs.forEach(d => arr(d.cats).forEach(c => allCats[c] = true));

/* ------------------------------------------------------------------- chrome */
const meta = DATA.meta || {}, stats = DATA.stats || {};
document.title = "AD permission audit - " + (meta.domain || "");
$("#hDomain").textContent = meta.domain || "Active Directory";
$("#hSub").textContent = "OU structure, delegation and administrative rights";

(function topmeta() {
  const box = $("#topmeta");
  [["Generated", meta.generatedText || ""], ["Domain controller", meta.server || ""],
   ["Run as", meta.runAs || ""], ["Scope", arr(meta.searchBase).length + " search base(s)"]]
  .forEach(([k, v]) => {
    const d = el("div", "kv"); d.appendChild(el("div", "k", k)); d.appendChild(el("div", "v", v)); box.appendChild(d);
  });
})();

const THEME_KEY = "adaudit-theme";
try { const s = localStorage.getItem(THEME_KEY); if (s) document.documentElement.dataset.theme = s; } catch (e) {}
if (!document.documentElement.dataset.theme) {
  document.documentElement.dataset.theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
$("#btnTheme").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
});
$("#btnPrint").addEventListener("click", () => window.print());

/* --------------------------------------------------------------------- tabs */
const TABS = [
  { id: "overview", label: "Overview" },
  { id: "tree", label: "OU explorer", count: nodes.length },
  { id: "delegations", label: "Delegations", count: rows.filter(r => !r.inherited && !r.def.expected).length },
  { id: "principals", label: "Principals", count: trustees.length },
  { id: "groups", label: "Privileged groups", count: pgroups.length },
  { id: "gpo", label: "Group Policy", count: gpos.length },
  { id: "findings", label: "Findings", count: findings.length },
  { id: "method", label: "Method" }
];
const tabBar = $("#tabs");
TABS.forEach(t => {
  const b = el("button", "tab", t.label);
  b.setAttribute("role", "tab"); b.dataset.view = t.id;
  if (t.count !== undefined) b.appendChild(el("span", "cnt", num(t.count)));
  b.addEventListener("click", () => show(t.id));
  tabBar.appendChild(b);
});
function show(id) {
  $$(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + id));
  $$(".tab").forEach(b => b.setAttribute("aria-selected", b.dataset.view === id ? "true" : "false"));
  window.scrollTo(0, 0);
}

function goNode(id) { show("tree"); selectNode(id, true); }
function goTrustee(id) { show("principals"); selectTrustee(id, true); }

/* ----------------------------------------------------------------- overview */
(function overview() {
  const v = $("#view-overview");
  const sev = stats.severity || {}, fin = stats.findings || {};

  const cards = el("div", "cards");
  const mk = (n, l, foot, cls) => {
    const c = el("div", "card" + (cls ? " " + cls : ""));
    c.appendChild(el("div", "n", num(n)));
    c.appendChild(el("div", "l", l));
    if (foot) c.appendChild(el("div", "foot", foot));
    return c;
  };
  cards.appendChild(mk(stats.nodes, "Objects audited", (nodes.filter(n => n.type === "OU").length) + " organisational units"));
  cards.appendChild(mk(stats.explicitAces, "Explicit permission entries", "delegated on the objects themselves"));
  cards.appendChild(mk(trustees.filter(t => (rowsByTrustee[t.id] || []).some(r => !r.inherited)).length, "Principals with delegated rights", trustees.length + " principals seen in total"));
  cards.appendChild(mk(fin.Critical || 0, "Critical findings", "", "sev-crit"));
  cards.appendChild(mk(fin.High || 0, "High findings", "", "sev-high"));
  cards.appendChild(mk(fin.Medium || 0, "Medium findings", "", "sev-med"));
  v.appendChild(cards);

  if (arr(meta.warnings).length) {
    const w = el("div", "note");
    w.appendChild(el("strong", null, "Collection warnings: "));
    w.appendChild(document.createTextNode(arr(meta.warnings).join(" ")));
    v.appendChild(w);
  }

  /* severity distribution of explicit entries */
  const total = SEV.reduce((a, s) => a + (sev[s] || 0), 0) || 1;
  const panel = el("div", "panel pad");
  panel.appendChild(el("h2", "section", "Explicit permission entries by severity"));
  const bar = el("div", "bar");
  SEV.forEach(s => {
    const w = ((sev[s] || 0) / total) * 100;
    if (!w) return;
    const sp = el("span");
    sp.style.width = w + "%";
    sp.style.background = "var(--" + ({ Critical: "crit", High: "high", Medium: "med", Low: "low", Info: "info" })[s] + ")";
    sp.title = s + ": " + num(sev[s] || 0);
    bar.appendChild(sp);
  });
  panel.appendChild(bar);
  const leg = el("div", "legend");
  SEV.forEach(s => {
    const i = el("i"); i.style.background = "var(--" + ({ Critical: "crit", High: "high", Medium: "med", Low: "low", Info: "info" })[s] + ")";
    const sp = el("span"); sp.appendChild(i); sp.appendChild(document.createTextNode(s + " " + num(sev[s] || 0)));
    leg.appendChild(sp);
  });
  panel.appendChild(leg);
  v.appendChild(panel);

  /* most delegated objects */
  v.appendChild(el("h3", "sub", "Objects carrying the most explicit delegation"));
  const t1 = el("table");
  headRow(t1, [{ label: "Object" }, { label: "Type" }, { label: "Explicit entries", cls: "num" }, { label: "Highest severity" }, { label: "Users", cls: "num" }, { label: "Computers", cls: "num" }]);
  const b1 = el("tbody");
  nodes.slice().sort((a, b) => (b.explicitCount - a.explicitCount) || (SEVRANK[b.maxSev] - SEVRANK[a.maxSev])).slice(0, 12).forEach(n => {
    const tr = el("tr", "clickable");
    tr.addEventListener("click", () => goNode(n.id));
    cell(tr, n.path); cell(tr, n.type); cell(tr, num(n.explicitCount), "num");
    cell(tr, badge(n.maxSev)); cell(tr, num((n.subtree || {}).user), "num"); cell(tr, num((n.subtree || {}).computer), "num");
    b1.appendChild(tr);
  });
  t1.appendChild(b1);
  const w1 = el("div", "tablewrap"); w1.appendChild(t1); v.appendChild(w1);

  /* principals holding the most */
  v.appendChild(el("h3", "sub", "Principals holding the most delegated rights"));
  const t2 = el("table");
  headRow(t2, [{ label: "Principal" }, { label: "Type" }, { label: "Objects", cls: "num" }, { label: "Highest severity" }, { label: "What it can do" }]);
  const b2 = el("tbody");
  trustees.map(t => {
    const rs = (rowsByTrustee[t.id] || []).filter(r => !r.inherited && !r.def.expected);
    const objs = {}; rs.forEach(r => objs[r.node.id] = true);
    let top = "Info"; const cats = {};
    rs.forEach(r => { if (SEVRANK[r.def.sev] > SEVRANK[top]) top = r.def.sev; arr(r.def.cats).forEach(c => cats[c] = true); });
    return { t: t, n: Object.keys(objs).length, sev: top, cats: Object.keys(cats) };
  }).filter(x => x.n > 0)
    .sort((a, b) => (SEVRANK[b.sev] - SEVRANK[a.sev]) || (b.n - a.n)).slice(0, 12)
    .forEach(x => {
      const tr = el("tr", "clickable");
      tr.addEventListener("click", () => goTrustee(x.t.id));
      cell(tr, x.t.name); cell(tr, x.t.class); cell(tr, num(x.n), "num");
      cell(tr, badge(x.sev)); cell(tr, x.cats.slice(0, 4).join(", "));
      b2.appendChild(tr);
    });
  t2.appendChild(b2);
  const w2 = el("div", "tablewrap"); w2.appendChild(t2); v.appendChild(w2);
})();

/* --------------------------------------------------------------- OU explorer */
const treeBox = $("#tree");
const collapsed = {};
let selectedNode = null;

nodes.forEach(n => { if (n.depth >= 2) collapsed[n.id] = true; });

function nodeMatches(n, q) {
  if (!q) return true;
  return (n.name || "").toLowerCase().indexOf(q) >= 0 || (n.dn || "").toLowerCase().indexOf(q) >= 0;
}

function buildTree() {
  const q = $("#treeSearch").value.trim().toLowerCase();
  const onlyDel = $("#onlyDelegated").checked;
  treeBox.innerHTML = "";

  const keep = {};
  if (q || onlyDel) {
    const hit = n => (q ? nodeMatches(n, q) : true) && (onlyDel ? n.explicitCount > 0 : true);
    nodes.forEach(n => {
      if (!hit(n)) return;
      let c = n;
      while (c) { keep[c.id] = true; c = (c.parent === null || c.parent === undefined) ? null : N(c.parent); }
    });
  }

  const render = (list, host) => {
    list.forEach(n => {
      if ((q || onlyDel) && !keep[n.id]) return;
      const children = kids[n.id].filter(c => (q || onlyDel) ? keep[c.id] : true);
      const row = el("div", "tnode");
      row.dataset.id = n.id;
      row.style.paddingLeft = (6 + n.depth * 14) + "px";
      if (selectedNode === n.id) row.classList.add("sel");
      if (q && nodeMatches(n, q)) row.classList.add("hit");

      const caret = el("span", "caret" + (children.length ? "" : " leaf"), "▶");
      if (children.length && !collapsed[n.id]) caret.classList.add("open");
      row.appendChild(caret);
      row.appendChild(el("span", "ico", ICON[n.type] || "□"));
      const nm = el("span", "nm", n.name); nm.title = n.dn; row.appendChild(nm);

      if (n.blocked) { const b = el("span", "tag", "⛨"); b.title = "Inheritance is blocked on this object"; row.appendChild(b); }
      if (arr(n.gpo).length) { const g = el("span", "tag", "GPO " + arr(n.gpo).length); g.title = arr(n.gpo).map(x => x.name).join("\n"); row.appendChild(g); }
      if (n.explicitCount) { const c = el("span", "tag", n.explicitCount + " ace"); c.title = n.explicitCount + " explicit permission entries"; row.appendChild(c); }
      if (SEVRANK[n.maxSev] > 0) row.appendChild(dot(n.maxSev));

      host.appendChild(row);

      const kidHost = el("div", "tkids" + (collapsed[n.id] && !q ? " collapsed" : ""));
      host.appendChild(kidHost);

      caret.addEventListener("click", ev => {
        ev.stopPropagation();
        collapsed[n.id] = !collapsed[n.id];
        buildTree();
      });
      row.addEventListener("click", () => selectNode(n.id));

      if (children.length && (!collapsed[n.id] || q)) render(children, kidHost);
    });
  };
  render(roots, treeBox);
}

function selectNode(id, reveal) {
  selectedNode = id;
  if (reveal) {
    let c = N(id);
    while (c && c.parent !== null && c.parent !== undefined) { collapsed[c.parent] = false; c = N(c.parent); }
  }
  buildTree();
  renderNodeDetail(N(id));
  const row = treeBox.querySelector('.tnode[data-id="' + id + '"]');
  if (row && reveal) row.scrollIntoView({ block: "center" });
}

let nodeSubtab = "perms";
let showInherited = false;

function renderNodeDetail(n) {
  const host = $("#ouDetail");
  host.innerHTML = "";
  if (!n) {
    host.appendChild(el("div", "empty", "Select an object on the left to see who holds permissions on it."));
    return;
  }

  const head = el("div", "dhead");
  head.appendChild(el("h2", null, n.path));
  head.appendChild(el("div", "dn", n.dn));
  const chips = el("div", "chips");
  chips.appendChild(plain(n.type));
  if (n.blocked) chips.appendChild(badge("Low", "Inheritance blocked"));
  if (n.protected) chips.appendChild(el("span", "badge ok", "Protected from deletion"));
  else if (n.type === "OU") chips.appendChild(badge("Low", "Not protected from deletion"));
  if (n.gpoBlocked) chips.appendChild(badge("Low", "Policy inheritance blocked"));
  if (n.critical) chips.appendChild(plain("Critical system object"));
  if (SEVRANK[n.maxSev] > 0) chips.appendChild(badge(n.maxSev, "Highest delegated severity: " + n.maxSev));
  head.appendChild(chips);
  host.appendChild(head);

  const facts = el("div", "facts");
  const fact = (k, v) => {
    const f = el("div", "fact");
    f.appendChild(el("div", "k", k));
    const val = el("div", "v");
    if (v instanceof Node) val.appendChild(v); else val.textContent = (v === null || v === undefined || v === "") ? "—" : String(v);
    f.appendChild(val); facts.appendChild(f);
  };
  const owner = (n.owner === null || n.owner === undefined) ? null : T(n.owner);
  fact("Owner", owner ? linkish(owner.name, () => goTrustee(owner.id)) : "—");
  fact("Explicit entries", num(n.explicitCount) + " of " + num(n.aceCount) + " total");
  fact("Child objects", num(n.childCount) + " below this object");
  fact("Users / computers / groups here", num((n.counts || {}).user) + " / " + num((n.counts || {}).computer) + " / " + num((n.counts || {}).group));
  fact("Users / computers in subtree", num((n.subtree || {}).user) + " / " + num((n.subtree || {}).computer));
  fact("Group Policy links", num(arr(n.gpo).length));
  fact("Description", n.description);
  fact("Changed", n.changed ? n.changed.replace("T", " ").replace("Z", " UTC") : "—");
  host.appendChild(facts);

  const nf = findingsByNode[n.id] || [];
  const bar = el("div", "subtabs");
  [["perms", "Permissions"], ["gpo", "Group Policy (" + arr(n.gpo).length + ")"], ["findings", "Findings (" + nf.length + ")"]].forEach(([k, label]) => {
    const b = el("button", "subtab", label);
    b.setAttribute("aria-selected", nodeSubtab === k ? "true" : "false");
    b.addEventListener("click", () => { nodeSubtab = k; renderNodeDetail(n); });
    bar.appendChild(b);
  });
  const toggle = el("label", "chk");
  const cb = el("input"); cb.type = "checkbox"; cb.checked = showInherited;
  cb.addEventListener("change", () => { showInherited = cb.checked; renderNodeDetail(n); });
  toggle.appendChild(cb); toggle.appendChild(document.createTextNode(" Show inherited"));
  toggle.style.marginLeft = "auto"; toggle.style.padding = "0 6px";
  bar.appendChild(toggle);
  host.appendChild(bar);

  const body = el("div", "dbody");
  if (nodeSubtab === "perms") body.appendChild(nodePermTable(n));
  else if (nodeSubtab === "gpo") body.appendChild(nodeGpoTable(n));
  else body.appendChild(findingList(nf, true));
  host.appendChild(body);
}

function nodePermTable(n) {
  const wrap = el("div");
  if (n.aclError) {
    const w = el("div", "note", n.aclError);
    wrap.appendChild(w);
  }
  const list = rows.filter(r => r.node.id === n.id && (showInherited || !r.inherited));
  list.sort((a, b) => (SEVRANK[b.def.sev] - SEVRANK[a.def.sev]) || (a.inherited - b.inherited) || a.t.name.localeCompare(b.t.name));

  const t = el("table");
  headRow(t, [{ label: "Severity" }, { label: "Trustee" }, { label: "Type" }, { label: "Permissions" }, { label: "Applies to" }, { label: "Source" }]);
  if (!list.length) { emptyRow(t, 6, showInherited ? "No permission entries were read on this object." : "No permissions are set directly on this object. Tick “Show inherited” to see what it inherits."); wrap.appendChild(t); return wrap; }

  const tb = el("tbody");
  list.forEach(r => {
    const tr = el("tr");
    const sc = cell(tr, null); sc.appendChild(badge(r.def.sev));
    if (r.def.expected) { sc.appendChild(document.createTextNode(" ")); sc.appendChild(flag(r.def)); }
    const tc = cell(tr, null);
    tc.appendChild(linkish(r.t.name, () => goTrustee(r.t.id)));
    if (r.t.class) tc.appendChild(el("div", "src", r.t.class + (r.t.scope ? " · " + r.t.scope : "")));
    cell(tr, r.def.type);
    const pc = cell(tr, null);
    const ul = el("ul", "perms");
    arr(r.def.perms).forEach(p => ul.appendChild(el("li", null, p)));
    pc.appendChild(ul);
    if (arr(r.def.notes).length) {
      const nl = el("ul", "notelist");
      arr(r.def.notes).forEach(x => nl.appendChild(el("li", null, x)));
      pc.appendChild(nl);
    }
    cell(tr, r.def.applies);
    const src = cell(tr, null);
    if (!r.inherited) src.appendChild(el("span", null, "Set here"));
    else if (r.src) src.appendChild(linkish("Inherited from " + r.src.path, () => goNode(r.src.id)));
    else src.appendChild(el("span", "src", "Inherited from above the audit scope"));
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  wrap.appendChild(t);
  return wrap;
}

function nodeGpoTable(n) {
  const t = el("table");
  headRow(t, [{ label: "Order" }, { label: "Policy" }, { label: "State" }, { label: "Who can edit it" }]);
  const links = arr(n.gpo);
  if (!links.length) { emptyRow(t, 4, "No Group Policy objects are linked to this object."); return t; }
  const tb = el("tbody");
  links.forEach((l, i) => {
    const tr = el("tr");
    cell(tr, i + 1, "num");
    const g = (l.gpo === null || l.gpo === undefined) ? null : gpoById[l.gpo];
    const c = cell(tr, null);
    c.appendChild(el("span", null, l.name));
    if (g) c.appendChild(el("div", "src", g.guid));
    const st = cell(tr, null);
    if (l.enforced) st.appendChild(badge("Low", "Enforced"));
    if (l.disabled) st.appendChild(plain("Link disabled"));
    if (!l.enforced && !l.disabled) st.appendChild(el("span", "src", "Normal"));
    const ed = cell(tr, null);
    if (!g) ed.appendChild(el("span", "src", "Policy is outside the audited domain"));
    else {
      const nonDefault = arr(g.editors).filter(e => !e.expected);
      if (!nonDefault.length) ed.appendChild(el("span", "src", "Tier 0 principals only"));
      else nonDefault.forEach(e => {
        const t2 = T(e.t);
        const d = el("div");
        d.appendChild(linkish(t2.name, () => goTrustee(t2.id)));
        d.appendChild(el("span", "src", " — " + arr(e.perms).join(", ")));
        ed.appendChild(d);
      });
    }
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  return t;
}

$("#treeSearch").addEventListener("input", buildTree);
$("#onlyDelegated").addEventListener("change", buildTree);
$("#btnExpand").addEventListener("click", () => { nodes.forEach(n => collapsed[n.id] = false); buildTree(); });
$("#btnCollapse").addEventListener("click", () => { nodes.forEach(n => collapsed[n.id] = n.depth >= 1); buildTree(); });
buildTree();
if (roots.length) selectNode(roots[0].id);

/* -------------------------------------------------------------- delegations */
(function delegations() {
  const sel = $("#dCat");
  Object.keys(allCats).sort().forEach(c => { const o = el("option", null, c); o.value = c; sel.appendChild(o); });

  let sortKey = "sev", sortDir = -1;
  const MAX = 600;

  function current() {
    const q = $("#dSearch").value.trim().toLowerCase();
    const sv = $("#dSev").value, ct = $("#dCat").value;
    const inh = $("#dInherited").checked, exp = $("#dExpected").checked;

    let list = rows.filter(r => {
      if (!inh && r.inherited) return false;
      if (!exp && r.def.expected) return false;
      if (sv && r.def.sev !== sv) return false;
      if (ct && arr(r.def.cats).indexOf(ct) < 0) return false;
      if (q) {
        const hay = (r.t.name + " " + r.node.path + " " + arr(r.def.perms).join(" ") + " " + r.def.applies + " " + arr(r.def.cats).join(" ")).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });

    const key = {
      sev: r => SEVRANK[r.def.sev],
      trustee: r => r.t.name.toLowerCase(),
      object: r => r.node.path.toLowerCase(),
      type: r => r.def.type,
      applies: r => r.def.applies.toLowerCase(),
      inherited: r => (r.inherited ? 1 : 0)
    }[sortKey] || (r => SEVRANK[r.def.sev]);

    list.sort((a, b) => {
      const ka = key(a), kb = key(b);
      if (ka < kb) return -sortDir;
      if (ka > kb) return sortDir;
      return a.node.path.localeCompare(b.node.path) || a.t.name.localeCompare(b.t.name);
    });
    return list;
  }

  function render() {
    const list = current();
    const table = $("#dTable");
    table.innerHTML = "";
    const cols = [
      { label: "Severity", sort: "sev" }, { label: "Trustee", sort: "trustee" }, { label: "Object", sort: "object" },
      { label: "Type", sort: "type" }, { label: "Permissions" }, { label: "Applies to", sort: "applies" }, { label: "Source", sort: "inherited" }
    ];
    const thead = headRow(table, cols);
    $$("th.sortable", thead).forEach(th => {
      const active = th.dataset.key === sortKey;
      th.style.color = active ? "var(--ink)" : "";
      $(".arrow", th).textContent = active ? (sortDir === 1 ? " ▲" : " ▼") : "";
      th.addEventListener("click", () => {
        if (sortKey === th.dataset.key) sortDir = -sortDir; else { sortKey = th.dataset.key; sortDir = -1; }
        render();
      });
    });

    $("#dCount").textContent = list.length > MAX
      ? "Showing the first " + num(MAX) + " of " + num(list.length) + " entries"
      : num(list.length) + " entries";

    if (!list.length) { emptyRow(table, cols.length, "Nothing matches these filters."); return; }

    const tb = el("tbody");
    list.slice(0, MAX).forEach(r => {
      const tr = el("tr");
      const sc = cell(tr, null); sc.appendChild(badge(r.def.sev));
      if (r.def.expected) { sc.appendChild(document.createTextNode(" ")); sc.appendChild(flag(r.def)); }
      const tc = cell(tr, null);
      tc.appendChild(linkish(r.t.name, () => goTrustee(r.t.id)));
      tc.appendChild(el("div", "src", r.t.class + (r.t.scope ? " · " + r.t.scope : "")));
      const oc = cell(tr, null);
      oc.appendChild(linkish(r.node.path, () => goNode(r.node.id)));
      cell(tr, r.def.type);
      const pc = cell(tr, null);
      const ul = el("ul", "perms");
      arr(r.def.perms).forEach(p => ul.appendChild(el("li", null, p)));
      pc.appendChild(ul);
      cell(tr, r.def.applies);
      cell(tr, r.inherited ? (r.src ? "Inherited from " + r.src.path : "Inherited") : "Set here", "src");
      tb.appendChild(tr);
    });
    table.appendChild(tb);
  }

  ["dSearch", "dSev", "dCat", "dInherited", "dExpected"].forEach(id => {
    $("#" + id).addEventListener("input", render);
    $("#" + id).addEventListener("change", render);
  });

  $("#btnCsv").addEventListener("click", () => {
    const list = current();
    const head = ["Severity", "Trustee", "TrusteeSid", "TrusteeClass", "Object", "DistinguishedName", "AccessType", "Permissions", "AppliesTo", "Inherited", "InheritedFrom", "Categories", "ExpectedDefault"];
    const q = v => '"' + String(v === null || v === undefined ? "" : v).replace(/"/g, '""') + '"';
    const lines = [head.join(",")];
    list.forEach(r => lines.push([
      r.def.sev, r.t.name, r.t.sid, r.t.class, r.node.path, r.node.dn, r.def.type,
      arr(r.def.perms).join("; "), r.def.applies, r.inherited ? "Yes" : "No",
      r.src ? r.src.path : "", arr(r.def.cats).join("; "), r.def.expected ? "Yes" : "No"
    ].map(q).join(",")));
    const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = "ad-delegations-" + (meta.domain || "domain") + ".csv";
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  });

  render();
})();

/* ---------------------------------------------------------------- principals */
let selectedTrustee = null;

function principalList() {
  const q = $("#pSearch").value.trim().toLowerCase();
  const kind = $("#pKind").value;
  return trustees.filter(t => {
    const rs = rowsByTrustee[t.id] || [];
    const explicit = rs.filter(r => !r.inherited);
    if (kind === "withRights" && !explicit.length) return false;
    if (kind === "group" && t.class !== "group") return false;
    if (kind === "user" && t.class !== "user") return false;
    if (kind === "computer" && t.class !== "computer" && t.class !== "gMSA") return false;
    if (kind === "privileged" && !t.privileged && !t.tier0) return false;
    if (kind === "broad" && !t.broad) return false;
    if (kind === "unresolved" && t.class !== "unresolved") return false;
    if (q && (t.name + " " + t.sid + " " + (t.dn || "")).toLowerCase().indexOf(q) < 0) return false;
    return true;
  }).map(t => {
    const rs = (rowsByTrustee[t.id] || []).filter(r => !r.inherited);
    let top = "Info"; rs.forEach(r => { if (SEVRANK[r.def.sev] > SEVRANK[top]) top = r.def.sev; });
    const objs = {}; rs.forEach(r => objs[r.node.id] = true);
    return { t: t, n: Object.keys(objs).length, sev: top };
  }).sort((a, b) => (SEVRANK[b.sev] - SEVRANK[a.sev]) || (b.n - a.n) || a.t.name.localeCompare(b.t.name));
}

function buildPrincipals() {
  const host = $("#pList");
  host.innerHTML = "";
  const list = principalList();
  if (!list.length) { host.appendChild(el("div", "empty", "No principals match.")); return; }
  list.forEach(x => {
    const row = el("div", "tnode" + (selectedTrustee === x.t.id ? " sel" : ""));
    row.style.paddingLeft = "10px";
    row.appendChild(el("span", "ico", CLSICON[x.t.class] || "○"));
    const nm = el("span", "nm", x.t.name); nm.title = x.t.sid; row.appendChild(nm);
    if (x.t.tier0) row.appendChild(plain("Tier 0"));
    else if (x.t.broad) row.appendChild(badge("High", "broad"));
    if (x.n) row.appendChild(el("span", "tag", x.n + " obj"));
    if (SEVRANK[x.sev] > 0) row.appendChild(dot(x.sev));
    row.addEventListener("click", () => selectTrustee(x.t.id));
    host.appendChild(row);
  });
}

function selectTrustee(id, reveal) {
  selectedTrustee = id;
  const t = T(id);
  if (reveal) {
    const list = principalList();
    if (!list.some(x => x.t.id === id)) { $("#pSearch").value = ""; $("#pKind").value = ""; }
  }
  buildPrincipals();
  renderTrusteeDetail(t);
  const sel = $(".tnode.sel", $("#pList"));
  if (sel && reveal) sel.scrollIntoView({ block: "center" });
}

function renderTrusteeDetail(t) {
  const host = $("#pDetail");
  host.innerHTML = "";
  if (!t) { host.appendChild(el("div", "empty", "Select a principal to see everywhere it holds rights.")); return; }

  const head = el("div", "dhead");
  head.appendChild(el("h2", null, t.name));
  head.appendChild(el("div", "dn", t.dn || t.sid));
  const chips = el("div", "chips");
  chips.appendChild(plain(t.class + (t.scope ? " · " + t.scope : "")));
  if (t.tier0) chips.appendChild(el("span", "badge ok", "Tier 0 principal"));
  if (t.broad) chips.appendChild(badge("High", "Broad principal"));
  if (t.adminCount) chips.appendChild(plain("adminCount = 1"));
  if (pgByTrustee[t.id]) chips.appendChild(badge("Medium", "Privileged group"));
  head.appendChild(chips);
  host.appendChild(head);

  const facts = el("div", "facts");
  const fact = (k, v) => {
    const f = el("div", "fact"); f.appendChild(el("div", "k", k));
    const val = el("div", "v");
    if (v instanceof Node) val.appendChild(v); else val.textContent = (v === null || v === undefined || v === "") ? "—" : String(v);
    f.appendChild(val); facts.appendChild(f);
  };
  const rs = rowsByTrustee[t.id] || [];
  const explicit = rs.filter(r => !r.inherited);
  const objs = {}; explicit.forEach(r => objs[r.node.id] = true);
  fact("Security identifier", el("span", "mono", t.sid));
  fact("Objects with rights set here", num(Object.keys(objs).length));
  fact("Total entries seen", num(rs.length) + " (including inherited copies)");
  fact("Description", t.description);
  const pg = pgByTrustee[t.id];
  if (pg) fact("Effective members", num(pg.total) + " (" + num(pg.direct) + " direct, " + num(pg.nested) + " nested)");
  host.appendChild(facts);

  const gpoEdits = editorsByTrustee[t.id] || [];
  const tf = findingsByTrustee[t.id] || [];

  const body = el("div", "dbody");

  body.appendChild(el("h3", "sub", "Rights held", null));
  $$(".sub", body).forEach(h => h.style.padding = "14px 16px 0");
  const t1 = el("table");
  headRow(t1, [{ label: "Severity" }, { label: "Object" }, { label: "Permissions" }, { label: "Applies to" }, { label: "Source" }]);
  if (!rs.length) emptyRow(t1, 5, "This principal holds no permissions on the audited objects.");
  else {
    const tb = el("tbody");
    rs.slice().sort((a, b) => (a.inherited - b.inherited) || (SEVRANK[b.def.sev] - SEVRANK[a.def.sev]) || a.node.path.localeCompare(b.node.path))
      .slice(0, 400).forEach(r => {
        const tr = el("tr");
        const sc = cell(tr, null); sc.appendChild(badge(r.def.sev));
        if (r.def.expected) { sc.appendChild(document.createTextNode(" ")); sc.appendChild(flag(r.def)); }
        const oc = cell(tr, null); oc.appendChild(linkish(r.node.path, () => goNode(r.node.id)));
        const pc = cell(tr, null);
        const ul = el("ul", "perms"); arr(r.def.perms).forEach(p => ul.appendChild(el("li", null, p))); pc.appendChild(ul);
        cell(tr, r.def.applies);
        cell(tr, r.inherited ? (r.src ? "Inherited from " + r.src.path : "Inherited") : "Set here", "src");
        tb.appendChild(tr);
      });
    t1.appendChild(tb);
  }
  body.appendChild(t1);

  if (gpoEdits.length) {
    const h = el("h3", "sub", "Group Policy objects it can edit"); h.style.padding = "18px 16px 0"; body.appendChild(h);
    const t2 = el("table");
    headRow(t2, [{ label: "Policy" }, { label: "Permissions" }, { label: "Linked to" }]);
    const tb2 = el("tbody");
    gpoEdits.forEach(x => {
      const tr = el("tr");
      cell(tr, x.gpo.name);
      cell(tr, arr(x.e.perms).join(", "));
      const lc = cell(tr, null);
      const links = arr(x.gpo.links);
      if (!links.length) lc.appendChild(el("span", "src", "Not linked"));
      else links.forEach(l => { const n = N(l.node); if (n) { lc.appendChild(linkish(n.path, () => goNode(n.id))); lc.appendChild(el("div")); } });
      tb2.appendChild(tr);
    });
    t2.appendChild(tb2);
    body.appendChild(t2);
  }

  if (pg && arr(pg.members).length) {
    const h = el("h3", "sub", "Members"); h.style.padding = "18px 16px 0"; body.appendChild(h);
    body.appendChild(memberTable(pg));
  }

  if (tf.length) {
    const h = el("h3", "sub", "Findings"); h.style.padding = "18px 16px 0"; body.appendChild(h);
    const w = el("div"); w.style.padding = "0 16px 16px";
    w.appendChild(findingList(tf, true));
    body.appendChild(w);
  }

  host.appendChild(body);
}

function memberTable(pg) {
  const t = el("table");
  headRow(t, [{ label: "Member" }, { label: "Type" }, { label: "Through" }, { label: "State" }]);
  const members = arr(pg.members).slice().sort((a, b) => (a.via || "").localeCompare(b.via || "") || (a.name || "").localeCompare(b.name || ""));
  if (!members.length) { emptyRow(t, 4, "The group is empty."); return t; }
  const tb = el("tbody");
  members.forEach(m => {
    const tr = el("tr");
    const c = cell(tr, null);
    c.appendChild(el("span", null, m.name));
    c.appendChild(el("div", "src", m.dn));
    cell(tr, m.class);
    cell(tr, m.via === "direct" ? "Direct member" : (m.via === "primary group" ? "Primary group" : "Nested group"));
    const st = cell(tr, null);
    if (m.disabled) st.appendChild(plain("disabled"));
    else st.appendChild(el("span", "src", "enabled"));
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  return t;
}

$("#pSearch").addEventListener("input", buildPrincipals);
$("#pKind").addEventListener("change", buildPrincipals);
buildPrincipals();
renderTrusteeDetail(null);

/* ---------------------------------------------------------- privileged groups */
(function privileged() {
  const v = $("#view-groups");
  v.appendChild(el("h2", "section", "Privileged group membership"));
  const p = el("p"); p.className = "prose";
  p.appendChild(el("p", null, "These groups carry administrative power over the domain or the domain controllers themselves. Membership is resolved through nested groups and through primaryGroupID, so an account that hides its privilege in either place still shows up here."));
  v.appendChild(p);

  if (!pgroups.length) { v.appendChild(el("div", "empty", "Privileged group collection was skipped.")); return; }

  const summary = el("table");
  headRow(summary, [{ label: "Group" }, { label: "Note" }, { label: "Direct", cls: "num" }, { label: "Nested", cls: "num" }, { label: "Primary", cls: "num" }, { label: "Effective", cls: "num" }]);
  const tb = el("tbody");
  pgroups.slice().sort((a, b) => (b.total - a.total) || a.name.localeCompare(b.name)).forEach(g => {
    const tr = el("tr", "clickable");
    tr.addEventListener("click", () => goTrustee(g.t));
    const c = cell(tr, null);
    c.appendChild(linkish(g.name, () => goTrustee(g.t)));
    c.appendChild(el("div", "src", g.sid));
    cell(tr, g.note);
    cell(tr, num(g.direct), "num"); cell(tr, num(g.nested), "num"); cell(tr, num(g.primary), "num");
    const tc = cell(tr, null, "num");
    tc.appendChild(el("strong", null, num(g.total)));
    tb.appendChild(tr);
  });
  summary.appendChild(tb);
  const w = el("div", "tablewrap"); w.appendChild(summary); v.appendChild(w);

  const stale = arr(DATA.adminCount);
  if (stale.length) {
    v.appendChild(el("h3", "sub", "Accounts stamped by AdminSDHolder (adminCount = 1)"));
    const t = el("table");
    headRow(t, [{ label: "Account" }, { label: "Distinguished name" }, { label: "State" }, { label: "Still privileged" }]);
    const protectedDns = {};
    pgroups.forEach(g => arr(g.members).forEach(m => protectedDns[(m.dn || "").toLowerCase()] = true));
    const tb2 = el("tbody");
    stale.forEach(a => {
      const tr = el("tr");
      cell(tr, a.name); cell(tr, a.dn);
      cell(tr, a.disabled ? "disabled" : "enabled");
      const c = cell(tr, null);
      if (protectedDns[(a.dn || "").toLowerCase()]) c.appendChild(el("span", "badge ok", "yes"));
      else c.appendChild(badge("Low", "stale stamp"));
      tb2.appendChild(tr);
    });
    t.appendChild(tb2);
    const w2 = el("div", "tablewrap"); w2.appendChild(t); v.appendChild(w2);
  }
})();

/* --------------------------------------------------------------- group policy */
(function grouppolicy() {
  const v = $("#view-gpo");
  v.appendChild(el("h2", "section", "Group Policy objects"));
  const intro = el("div", "prose");
  intro.appendChild(el("p", null, "Editing a Group Policy object is equivalent to running code on every computer and in every user session the policy reaches. The audit lists who holds write access to each policy and which audited objects it is linked to."));
  v.appendChild(intro);

  if (!gpos.length) { v.appendChild(el("div", "empty", "Group Policy collection was skipped or no policies were readable.")); return; }

  const t = el("table");
  headRow(t, [{ label: "Policy" }, { label: "Links" }, { label: "Non default editors" }, { label: "Changed" }]);
  const tb = el("tbody");
  gpos.slice().sort((a, b) => arr(b.editors).filter(e => !e.expected).length - arr(a.editors).filter(e => !e.expected).length || a.name.localeCompare(b.name)).forEach(g => {
    const tr = el("tr");
    const c = cell(tr, null);
    c.appendChild(el("span", null, g.name));
    c.appendChild(el("div", "src", g.guid));
    const lc = cell(tr, null);
    const links = arr(g.links);
    if (!links.length) lc.appendChild(el("span", "src", "Not linked to any audited object"));
    else links.forEach(l => {
      const n = N(l.node);
      const d = el("div");
      if (n) d.appendChild(linkish(n.path, () => goNode(n.id)));
      if (l.enforced) { d.appendChild(document.createTextNode(" ")); d.appendChild(badge("Low", "enforced")); }
      if (l.disabled) { d.appendChild(document.createTextNode(" ")); d.appendChild(plain("disabled")); }
      lc.appendChild(d);
    });
    const ec = cell(tr, null);
    const nonDefault = arr(g.editors).filter(e => !e.expected);
    if (!nonDefault.length) ec.appendChild(el("span", "src", "Tier 0 principals only"));
    else nonDefault.forEach(e => {
      const t2 = T(e.t);
      const d = el("div");
      d.appendChild(linkish(t2.name, () => goTrustee(t2.id)));
      d.appendChild(el("span", "src", " — " + arr(e.perms).join(", ") + (e.inherited ? " (inherited)" : "")));
      ec.appendChild(d);
    });
    cell(tr, g.changed ? g.changed.replace("T", " ").replace("Z", "") : "", "src");
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  const w = el("div", "tablewrap"); w.appendChild(t); v.appendChild(w);
})();

/* -------------------------------------------------------------------- findings */
function findingList(list, compact) {
  const host = el("div");
  if (!list.length) { host.appendChild(el("div", "empty", "Nothing to report here.")); return host; }
  list.forEach(f => {
    const c = el("div", "finding " + f.sev);
    const h = el("h4");
    h.appendChild(badge(f.sev));
    if (f.cat) h.appendChild(plain(f.cat));
    h.appendChild(el("span", null, f.title));
    c.appendChild(h);
    c.appendChild(el("p", null, f.detail));
    if (!compact) {
      const refs = el("div", "refs");
      if (f.node !== null && f.node !== undefined && N(f.node)) refs.appendChild(linkish("Open " + N(f.node).path, () => goNode(f.node)));
      if (f.trustee !== null && f.trustee !== undefined) refs.appendChild(linkish("Open " + T(f.trustee).name, () => goTrustee(f.trustee)));
      if (refs.childNodes.length) c.appendChild(refs);
    }
    host.appendChild(c);
  });
  return host;
}

(function findingsView() {
  const catSel = $("#fCat");
  const cats = {}; findings.forEach(f => { if (f.cat) cats[f.cat] = true; });
  Object.keys(cats).sort().forEach(c => { const o = el("option", null, c); o.value = c; catSel.appendChild(o); });

  function render() {
    const q = $("#fSearch").value.trim().toLowerCase();
    const sv = $("#fSev").value, ct = catSel.value;
    const list = findings.filter(f => {
      if (sv && f.sev !== sv) return false;
      if (ct && f.cat !== ct) return false;
      if (q && (f.title + " " + f.detail).toLowerCase().indexOf(q) < 0) return false;
      return true;
    });
    $("#fCount").textContent = num(list.length) + " of " + num(findings.length) + " findings";
    const host = $("#fList");
    host.innerHTML = "";
    host.appendChild(findingList(list.slice(0, 400), false));
    if (list.length > 400) host.appendChild(el("div", "empty", "Only the first 400 findings are shown. Narrow the filters to see the rest."));
  }
  ["fSearch", "fSev", "fCat"].forEach(id => {
    $("#" + id).addEventListener("input", render);
    $("#" + id).addEventListener("change", render);
  });
  render();
})();

/* ---------------------------------------------------------------------- method */
(function method() {
  const v = $("#view-method");
  const o = meta.options || {};
  const box = el("div", "prose");
  box.appendChild(el("h2", "section", "How this report was produced"));

  const p1 = el("p", null, "The audit is read only. It binds to a domain controller over LDAP, reads the security descriptor of each organisational unit and the objects listed below, and resolves every trustee. No object in the directory is created, changed or deleted, and no group membership is altered.");
  box.appendChild(p1);

  box.appendChild(el("h3", null, "Scope of this run"));
  const ul = el("ul");
  [["Domain", meta.domain], ["Forest", meta.forest], ["Domain controller", meta.server],
   ["Search bases", arr(meta.searchBase).join("  |  ")], ["Objects audited", num(stats.nodes)],
   ["Containers included", o.includeContainers ? "yes" : "no (organisational units only)"],
   ["Inherited entries kept", o.delegationsOnly ? "no, explicit delegation only" : "yes"],
   ["Object counts", o.skipObjectCounts ? "skipped" : "collected"],
   ["Privileged groups", o.skipPrivilegedGroups ? "skipped" : "collected"],
   ["Group Policy", o.skipGpo ? "skipped" : "collected"],
   ["Depth limit", o.maxDepth ? o.maxDepth + " levels" : "none"],
   ["Run as", meta.runAs], ["Run from", meta.computer], ["Duration", meta.duration + " seconds"],
   ["Script version", meta.version]
  ].forEach(([k, x]) => {
    const li = el("li");
    li.appendChild(el("strong", null, k + ": "));
    li.appendChild(document.createTextNode(x === null || x === undefined || x === "" ? "—" : String(x)));
    ul.appendChild(li);
  });
  box.appendChild(ul);

  box.appendChild(el("h3", null, "How severity is decided"));
  const ul2 = el("ul");
  [
    "Critical — replication rights (DCSync), or a rights of Medium or above held by a principal that contains everyone who can authenticate.",
    "High — full control, modify permissions, take ownership, write to all properties, all extended rights, or write access to an attribute that leads to control of an account (member, msDS-KeyCredentialLink, servicePrincipalName, userAccountControl, resource based delegation, gPLink, LAPS passwords and similar).",
    "Medium — create or delete child objects, delete, password reset, self membership, and ownership of an object by a principal outside Tier 0.",
    "Low — hygiene and manageability: blocked inheritance, missing accidental deletion protection, unresolvable SIDs, rights delegated to individual accounts, stale AdminSDHolder stamps.",
    "Info — read access, deny entries, and anything held by a Tier 0 principal, which is marked as a directory default.",
    "An entry marked “default” is one held by SYSTEM, Administrators, Domain or Enterprise Admins, Domain Controllers, Key Admins, SELF or Enterprise Domain Controllers. It is shown but not treated as a finding."
  ].forEach(x => ul2.appendChild(el("li", null, x)));
  box.appendChild(ul2);

  box.appendChild(el("h3", null, "What the report does not tell you"));
  const ul3 = el("ul");
  [
    "Permissions are read as they are stored. Effective access for a specific person also depends on group membership evaluated at logon, deny entries, and any claims or central access policies in use.",
    "Only the DACL is read. System access control lists (auditing) need SeSecurityPrivilege and are out of scope.",
    "An inherited entry is attributed to the nearest ancestor inside the audit scope that holds a matching explicit entry. If the entry came from above the search base, the source column says so.",
    "Group membership is resolved inside this domain. Members from other domains appear as foreign security principals.",
    "The audit reflects the directory at the moment it ran; it is a snapshot, not a monitor."
  ].forEach(x => ul3.appendChild(el("li", null, x)));
  box.appendChild(ul3);

  if (arr(meta.warnings).length) {
    box.appendChild(el("h3", null, "Warnings raised during collection"));
    const ul4 = el("ul");
    arr(meta.warnings).forEach(x => ul4.appendChild(el("li", null, x)));
    box.appendChild(ul4);
  }

  v.appendChild(box);
})();

show("overview");

document.addEventListener("keydown", e => {
  if (e.key === "/" && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) {
    e.preventDefault();
    const active = $(".view.active");
    const box = active ? $("input[type=search]", active) : null;
    if (box) box.focus();
  }
});

})();
</script>
</body>
</html>

'@
}

#endregion

#region ---------------------------------------------------------------- invoke

# Dot-sourcing the file loads the functions without running the audit, which is
# how the analysis functions are unit tested.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-Main -SearchBase $SearchBase -Server $Server -Credential $Credential -OutputPath $OutputPath `
            -MaxDepth $MaxDepth -IncludeContainers:$IncludeContainers -DelegationsOnly:$DelegationsOnly `
            -SkipObjectCounts:$SkipObjectCounts -SkipPrivilegedGroups:$SkipPrivilegedGroups -SkipGpo:$SkipGpo `
            -ExportData:$ExportData -Show:$Show -PassThru:$PassThru -Version $ScriptVersion
    } catch {
        Write-Host ''
        Write-Error "The audit stopped: $($_.Exception.Message)"
        Write-Host '  Nothing was written to Active Directory.' -ForegroundColor DarkGray
        exit 1
    }
}

#endregion
