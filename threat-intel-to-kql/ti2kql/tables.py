"""
A catalog of the Microsoft Defender advanced-hunting tables the translator
targets, with the columns that matter for IOC hunting.

Used two ways: injected into the LLM prompt so it grounds queries in real
schema, and by the validator to reject queries that reference an unknown table
or hunt an IOC type in a column that can't hold it.
"""

from __future__ import annotations

# table -> set of columns commonly used for hunting on that table.
DEFENDER_TABLES: dict[str, set[str]] = {
    "DeviceNetworkEvents": {
        "Timestamp", "DeviceId", "DeviceName", "RemoteIP", "RemotePort", "RemoteUrl",
        "LocalIP", "InitiatingProcessFileName", "InitiatingProcessSHA256", "ActionType",
    },
    "DeviceProcessEvents": {
        "Timestamp", "DeviceId", "DeviceName", "FileName", "FolderPath", "ProcessCommandLine",
        "SHA256", "SHA1", "MD5", "InitiatingProcessFileName", "InitiatingProcessCommandLine",
        "AccountName", "AccountUpn",
    },
    "DeviceFileEvents": {
        "Timestamp", "DeviceId", "DeviceName", "FileName", "FolderPath", "SHA256", "SHA1",
        "MD5", "ActionType", "InitiatingProcessFileName",
    },
    "DeviceRegistryEvents": {
        "Timestamp", "DeviceId", "DeviceName", "RegistryKey", "RegistryValueName",
        "RegistryValueData", "ActionType", "InitiatingProcessFileName",
    },
    "DeviceImageLoadEvents": {
        "Timestamp", "DeviceId", "DeviceName", "FileName", "FolderPath", "SHA256", "SHA1", "MD5",
    },
    "DeviceEvents": {
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "SHA256",
        "RemoteIP", "RemoteUrl", "InitiatingProcessFileName",
    },
    "DeviceLogonEvents": {
        "Timestamp", "DeviceId", "DeviceName", "AccountName", "AccountUpn", "LogonType",
        "RemoteIP", "ActionType",
    },
    "DeviceNetworkInfo": {"Timestamp", "DeviceId", "DeviceName", "IPAddresses"},
    "DeviceInfo": {"Timestamp", "DeviceId", "DeviceName", "OSPlatform", "PublicIP"},
    "DeviceTvmSoftwareVulnerabilities": {
        "DeviceId", "DeviceName", "CveId", "VulnerabilitySeverityLevel", "SoftwareName",
        "SoftwareVendor", "RecommendedSecurityUpdate",
    },
    "EmailEvents": {
        "Timestamp", "NetworkMessageId", "SenderFromAddress", "RecipientEmailAddress",
        "Subject", "SenderIPv4", "DeliveryAction", "ThreatTypes",
    },
    "EmailUrlInfo": {"Timestamp", "NetworkMessageId", "Url", "UrlDomain"},
    "EmailAttachmentInfo": {
        "Timestamp", "NetworkMessageId", "FileName", "FileType", "SHA256", "ThreatTypes",
    },
    "IdentityLogonEvents": {
        "Timestamp", "AccountUpn", "AccountSid", "IPAddress", "LogonType", "Protocol",
        "DeviceName", "Application",
    },
    "IdentityDirectoryEvents": {
        "Timestamp", "AccountUpn", "AccountSid", "ActionType", "TargetAccountUpn", "IPAddress",
    },
    "UrlClickEvents": {"Timestamp", "AccountUpn", "Url", "ActionType", "IPAddress"},
}

# Which tables/columns are the natural home for each IOC type -- used to
# suggest queries and to sanity-check the LLM's table choice.
IOC_TABLE_HINTS: dict[str, list[tuple[str, str]]] = {
    "ipv4": [("DeviceNetworkEvents", "RemoteIP"), ("DeviceLogonEvents", "RemoteIP")],
    "ipv6": [("DeviceNetworkEvents", "RemoteIP")],
    "domain": [("DeviceNetworkEvents", "RemoteUrl"), ("EmailUrlInfo", "UrlDomain")],
    "url": [("DeviceNetworkEvents", "RemoteUrl"), ("EmailUrlInfo", "Url")],
    "md5": [("DeviceFileEvents", "MD5"), ("DeviceProcessEvents", "MD5")],
    "sha1": [("DeviceFileEvents", "SHA1"), ("DeviceProcessEvents", "SHA1")],
    "sha256": [("DeviceFileEvents", "SHA256"), ("DeviceProcessEvents", "SHA256")],
    "cve": [("DeviceTvmSoftwareVulnerabilities", "CveId")],
    "email": [("EmailEvents", "SenderFromAddress")],
    "file_path": [("DeviceProcessEvents", "FolderPath"), ("DeviceFileEvents", "FolderPath")],
    "registry_key": [("DeviceRegistryEvents", "RegistryKey")],
}


def known_tables() -> set[str]:
    return set(DEFENDER_TABLES)


def schema_for_prompt() -> str:
    """A compact schema summary to ground the LLM."""
    lines = []
    for table, cols in DEFENDER_TABLES.items():
        preview = ", ".join(sorted(cols)[:8])
        lines.append(f"- {table}: {preview}")
    return "\n".join(lines)
