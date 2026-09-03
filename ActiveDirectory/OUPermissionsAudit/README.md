# Active Directory OU permission audit

Reads the OU tree and every security descriptor on it, works out what each
access control entry actually lets its trustee do, and writes one interactive
HTML file you can drill into.

**The script is read only.** It performs LDAP reads and nothing else: no
`Set-*`, `New-*`, `Remove-*`, `Move-*` or `Rename-*` call, no `CommitChanges()`,
no group membership change. The only things it creates are the report file and,
with `-ExportData`, the JSON and CSV next to it.

No RSAT. It uses `System.DirectoryServices`, which ships with Windows, so it
runs from any domain-joined machine. The ActiveDirectory module is not used.

## What it answers

- Which security groups hold rights where, and what do those rights allow in
  plain language ("Create computer objects", "Write msDS-KeyCredentialLink",
  "Replicating Directory Changes All") rather than a rights mask.
- Which entries are **set on an OU** and which are **inherited**, and which
  parent OU each inherited entry came from.
- Where someone outside Tier 0 holds full control, modify permissions, write
  owner, DCSync, or write access to an attribute that leads to account takeover.
- Who is in the privileged groups, including nested groups and members that
  join through `primaryGroupID`.
- Who can edit the GPOs linked to an OU, which is the ability to run code on
  everything below it.

## Files

- `Invoke-ADOUPermissionAudit.ps1` — the whole thing. The HTML report template
  is embedded, so a single file can be copied to a management host.

## Run it

```powershell
# current domain, report in the current directory
.\Invoke-ADOUPermissionAudit.ps1

# one branch of the tree, open the report when it is done
.\Invoke-ADOUPermissionAudit.ps1 -SearchBase 'OU=Corp,DC=contoso,DC=com' -Show

# another domain, with containers, and the raw data alongside the report
.\Invoke-ADOUPermissionAudit.ps1 -Server dc01.contoso.com -Credential (Get-Credential) `
    -IncludeContainers -ExportData -OutputPath C:\Audit\contoso.html
```

A plain domain user can run it. Reading a DACL needs `READ_CONTROL`, which
Authenticated Users hold on almost every object, so no administrative rights are
required — and giving the audit account none is the point.

### Parameters

| Parameter | What it does |
|---|---|
| `-SearchBase` | One or more DNs to audit. Default: the domain naming context. |
| `-Server` | Domain controller or domain DNS name. Default: the located DC. |
| `-Credential` | Bind credential. Default: the running user. |
| `-OutputPath` | Report path. Default: `.\AD-OU-Permission-Audit_<domain>_<stamp>.html` |
| `-MaxDepth` | Stop after n OU levels below each search base. `0` = unlimited. |
| `-IncludeContainers` | Also audit containers (`CN=Users`, `CN=Computers`, …). |
| `-DelegationsOnly` | Drop inherited entries from the report. Smaller file, delegation only. |
| `-SkipObjectCounts` | Skip the pass that counts users, computers and groups per OU. |
| `-SkipPrivilegedGroups` | Skip privileged group membership and the AdminSDHolder review. |
| `-SkipGpo` | Skip Group Policy objects, their links and their permissions. |
| `-ExportData` | Also write `.json` and `.csv` next to the report. |
| `-Show` | Open the report when it is written. |
| `-PassThru` | Emit the audit object to the pipeline. |

## The report

One self-contained HTML file. No CDN, no fonts, no network calls, so it opens on
an isolated management host and can be handed to an auditor as a single artefact.
It follows the light or dark theme of the machine it is opened on.

- **Overview** — counts, the severity spread of every explicit entry, the objects
  carrying the most delegation, and the principals holding the most.
- **OU explorer** — the tree, with a badge per node for explicit entries, blocked
  inheritance, linked GPOs and worst severity. Selecting a node shows its owner,
  object counts, GPO links and the full permission table, with a toggle for
  inherited entries and a link back to the OU each one came from.
- **Delegations** — every entry as one flat, sortable, filterable table. The CSV
  button exports exactly what the filters are showing.
- **Principals** — pick a group and see everywhere it holds rights, which GPOs it
  can edit, and, for a privileged group, its effective membership.
- **Privileged groups** — Domain Admins, Enterprise Admins, the built-in
  operator groups, DnsAdmins and the rest, with direct, nested and primary group
  members separated.
- **Group Policy** — every GPO, where it is linked, and who can edit it.
- **Findings** — the observations, worst first.
- **Method** — what was collected, how severity was decided, and what the report
  deliberately does not tell you.

Everything cross-links: a trustee in the OU table jumps to that principal, an
object in a finding jumps to that node in the tree.

## How severity is decided

| Severity | What earns it |
|---|---|
| **Critical** | Replication rights (DCSync). Anything Medium or above held by a principal that contains everyone who can authenticate. |
| **High** | Full control, modify permissions, take ownership, write all properties, all extended rights, or write access to an attribute that leads to control of an account: `member`, `msDS-KeyCredentialLink`, `servicePrincipalName`, `userAccountControl`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `gPLink`, `sIDHistory`, LAPS password attributes and similar. |
| **Medium** | Create or delete child objects, delete, password reset, self membership, and ownership of an OU by a principal outside Tier 0. |
| **Low** | Hygiene: blocked inheritance, missing accidental deletion protection, unresolvable SIDs left in a DACL, rights delegated to an individual account instead of a group, stale AdminSDHolder stamps. |
| **Info** | Read access, deny entries, and anything held by a Tier 0 principal. |

An entry held by SYSTEM, BUILTIN\Administrators, Domain or Enterprise Admins,
Domain Controllers, Key Admins, SELF or Enterprise Domain Controllers is marked
**default**: it is shown, and can be filtered out, but it is not a finding.
A "broad" principal — Everyone, Authenticated Users, Domain Users, Domain
Computers, Guests, Pre-Windows 2000 Compatible Access and the like — raises the
severity of anything above read by one level, because a right held there is a
right held by every account that can log on.

## Things to know

- **Stored permissions, not effective access.** The report shows the access
  control lists as they are. What a specific person can do also depends on the
  group memberships evaluated at their logon, on deny entries, and on any
  claims or central access policies in use.
- **DACL only.** Auditing entries (the SACL) need `SeSecurityPrivilege` and are
  out of scope.
- **Inheritance attribution is nearest-ancestor.** An inherited entry is matched
  to the closest ancestor inside the audit scope that holds an equivalent
  explicit entry. If it came from above the search base, the source column says
  so rather than guessing.
- **Blocked inheritance changes what you see.** When inheritance is turned off
  on an OU, Windows copies the previously inherited entries onto the object, so
  they appear as explicit entries there. The OU is flagged, and the reason for
  the sudden pile of explicit entries is in the flag.
- **Group membership is resolved inside the audited domain.** Members from other
  domains appear as foreign security principals.
- **Size.** Inherited entries are deduplicated: identical entries share one
  definition and each object only stores a reference, so a large directory stays
  a manageable file. `-DelegationsOnly` shrinks it further.
- The audit is a snapshot of the moment it ran, not a monitor.

## Testing without a directory

Dot-sourcing the file loads the functions without running the audit:

```powershell
. .\Invoke-ADOUPermissionAudit.ps1
Get-AceAssessment -Rights ([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) `
    -ObjectTypeInfo $null -AccessType 'Allow' `
    -Trustee @{ name = 'CONTOSO\Test'; broad = $false; tier0 = $false }
```

That is how the classification, the tree build and the HTML generation are
exercised against fabricated directory data before the script is pointed at a
real domain.
