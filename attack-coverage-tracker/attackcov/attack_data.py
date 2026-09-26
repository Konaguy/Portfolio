"""
A curated snapshot of the MITRE ATT&CK Enterprise matrix: the 14 tactics and a
representative set of techniques (with the tactics each belongs to and its
sub-techniques' names).

This is a *snapshot subset*, not the full matrix — enough that the coverage
denominator is meaningful and the heatmap renders a credible matrix, and it
includes every technique referenced by the detections in this portfolio. To
regenerate the full catalog from the official MITRE CTI STIX bundle, run
`scripts/build_catalog.py` (network required); the parser/coverage/dashboard
code is unchanged by catalog size.

ATT&CK and the technique IDs are © The MITRE Corporation, redistributed under
the ATT&CK Terms of Use.
"""

from __future__ import annotations

# Enterprise tactics in kill-chain order: shortname -> (ATT&CK id, display name)
TACTICS: dict[str, tuple[str, str]] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

# Top-level techniques: id -> (name, [tactic shortnames])
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    # Reconnaissance
    "T1595": ("Active Scanning", ["reconnaissance"]),
    "T1592": ("Gather Victim Host Information", ["reconnaissance"]),
    "T1589": ("Gather Victim Identity Information", ["reconnaissance"]),
    "T1590": ("Gather Victim Network Information", ["reconnaissance"]),
    "T1598": ("Phishing for Information", ["reconnaissance"]),
    # Resource Development
    "T1583": ("Acquire Infrastructure", ["resource-development"]),
    "T1587": ("Develop Capabilities", ["resource-development"]),
    "T1588": ("Obtain Capabilities", ["resource-development"]),
    "T1608": ("Stage Capabilities", ["resource-development"]),
    # Initial Access
    "T1566": ("Phishing", ["initial-access"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1133": ("External Remote Services", ["initial-access", "persistence"]),
    "T1078": ("Valid Accounts", ["initial-access", "defense-evasion", "persistence", "privilege-escalation"]),
    "T1189": ("Drive-by Compromise", ["initial-access"]),
    "T1195": ("Supply Chain Compromise", ["initial-access"]),
    "T1199": ("Trusted Relationship", ["initial-access"]),
    # Execution
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1204": ("User Execution", ["execution"]),
    "T1053": ("Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]),
    "T1569": ("System Services", ["execution"]),
    "T1047": ("Windows Management Instrumentation", ["execution"]),
    "T1106": ("Native API", ["execution"]),
    "T1129": ("Shared Modules", ["execution"]),
    "T1203": ("Exploitation for Client Execution", ["execution"]),
    # Persistence
    "T1547": ("Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"]),
    "T1136": ("Create Account", ["persistence"]),
    "T1543": ("Create or Modify System Process", ["persistence", "privilege-escalation"]),
    "T1546": ("Event Triggered Execution", ["persistence", "privilege-escalation"]),
    "T1505": ("Server Software Component", ["persistence"]),
    "T1098": ("Account Manipulation", ["persistence", "privilege-escalation"]),
    "T1197": ("BITS Jobs", ["persistence", "defense-evasion"]),
    # Privilege Escalation
    "T1548": ("Abuse Elevation Control Mechanism", ["privilege-escalation", "defense-evasion"]),
    "T1068": ("Exploitation for Privilege Escalation", ["privilege-escalation"]),
    "T1055": ("Process Injection", ["privilege-escalation", "defense-evasion"]),
    # Defense Evasion
    "T1027": ("Obfuscated Files or Information", ["defense-evasion"]),
    "T1218": ("System Binary Proxy Execution", ["defense-evasion"]),
    "T1070": ("Indicator Removal", ["defense-evasion"]),
    "T1112": ("Modify Registry", ["defense-evasion"]),
    "T1562": ("Impair Defenses", ["defense-evasion"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["defense-evasion"]),
    "T1036": ("Masquerading", ["defense-evasion"]),
    "T1497": ("Virtualization/Sandbox Evasion", ["defense-evasion", "discovery"]),
    # Credential Access
    "T1003": ("OS Credential Dumping", ["credential-access"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1558": ("Steal or Forge Kerberos Tickets", ["credential-access"]),
    "T1555": ("Credentials from Password Stores", ["credential-access"]),
    "T1552": ("Unsecured Credentials", ["credential-access"]),
    "T1556": ("Modify Authentication Process", ["credential-access", "defense-evasion", "persistence"]),
    "T1187": ("Forced Authentication", ["credential-access"]),
    # Discovery
    "T1087": ("Account Discovery", ["discovery"]),
    "T1082": ("System Information Discovery", ["discovery"]),
    "T1083": ("File and Directory Discovery", ["discovery"]),
    "T1057": ("Process Discovery", ["discovery"]),
    "T1018": ("Remote System Discovery", ["discovery"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1016": ("System Network Configuration Discovery", ["discovery"]),
    "T1069": ("Permission Groups Discovery", ["discovery"]),
    # Lateral Movement
    "T1021": ("Remote Services", ["lateral-movement"]),
    "T1570": ("Lateral Tool Transfer", ["lateral-movement"]),
    "T1550": ("Use Alternate Authentication Material", ["lateral-movement", "defense-evasion"]),
    "T1080": ("Taint Shared Content", ["lateral-movement"]),
    # Collection
    "T1560": ("Archive Collected Data", ["collection"]),
    "T1005": ("Data from Local System", ["collection"]),
    "T1114": ("Email Collection", ["collection"]),
    "T1056": ("Input Capture", ["collection", "credential-access"]),
    "T1113": ("Screen Capture", ["collection"]),
    # Command and Control
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1571": ("Non-Standard Port", ["command-and-control"]),
    "T1573": ("Encrypted Channel", ["command-and-control"]),
    "T1090": ("Proxy", ["command-and-control"]),
    "T1568": ("Dynamic Resolution", ["command-and-control"]),
    "T1219": ("Remote Access Software", ["command-and-control"]),
    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", ["exfiltration"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["exfiltration"]),
    "T1567": ("Exfiltration Over Web Service", ["exfiltration"]),
    "T1030": ("Data Transfer Size Limits", ["exfiltration"]),
    # Impact
    "T1486": ("Data Encrypted for Impact", ["impact"]),
    "T1490": ("Inhibit System Recovery", ["impact"]),
    "T1489": ("Service Stop", ["impact"]),
    "T1485": ("Data Destruction", ["impact"]),
    "T1498": ("Network Denial of Service", ["impact"]),
    "T1491": ("Defacement", ["impact"]),
}

# Named sub-techniques we want to render nicely. Any sub-technique not listed
# still resolves to its parent for coverage; this is just for display names.
SUBTECHNIQUES: dict[str, str] = {
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1204.002": "Malicious File",
    "T1204.001": "Malicious Link",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.001": "Remote Desktop Protocol",
    "T1569.002": "Service Execution",
    "T1071.001": "Web Protocols",
    "T1078.004": "Cloud Accounts",
    "T1110.003": "Password Spraying",
    "T1558.003": "Kerberoasting",
    "T1548.002": "Bypass User Account Control",
    "T1562.001": "Disable or Modify Tools",
}


def parent_of(technique_id: str) -> str:
    """Return the top-level technique id for a technique or sub-technique id."""
    return technique_id.split(".")[0].upper()


def technique_name(technique_id: str) -> str:
    tid = technique_id.upper()
    if tid in SUBTECHNIQUES:
        return SUBTECHNIQUES[tid]
    if tid in TECHNIQUES:
        return TECHNIQUES[tid][0]
    return tid


def tactics_for(technique_id: str) -> list[str]:
    parent = parent_of(technique_id)
    if parent in TECHNIQUES:
        return TECHNIQUES[parent][1]
    return []


def techniques_in_tactic(tactic_shortname: str) -> list[str]:
    return [tid for tid, (_, tactics) in TECHNIQUES.items() if tactic_shortname in tactics]


def is_known(technique_id: str) -> bool:
    return parent_of(technique_id) in TECHNIQUES
