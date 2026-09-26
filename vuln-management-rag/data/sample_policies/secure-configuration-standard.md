# Secure Configuration Standard

## Deprecated protocols

The following protocols are prohibited on production systems and must be
disabled wherever a scanner reports them enabled:

- **SMBv1** must be disabled on all Windows hosts. SMBv1 is used by ransomware
  for lateral movement and cannot be secured; enable SMB signing and use SMBv2
  or later.
- **SSLv3 and TLS 1.0/1.1** must be disabled on all services. Services must
  support TLS 1.2 or later only.
- **3DES and other 64-bit block ciphers** must be removed from TLS cipher
  suites (Sweet32).

## Transport security

All services exposing data over the network must present a certificate signed
by a trusted certificate authority. Self-signed or untrusted certificates are
permitted only on isolated management networks and must be tracked as
exceptions.

## Remote access

Remote Desktop (RDP) must not be exposed directly to the internet. Where RDP
is required it must sit behind a VPN or bastion, with Network Level
Authentication enabled. SSH servers must disable weak key-exchange, cipher,
and MAC algorithms and must not permit password authentication for
administrative accounts.

## Windows services hardening

The Print Spooler service must be disabled on servers that do not print,
particularly domain controllers, to reduce exposure to spooler-based remote
code execution. Point and Print must be restricted via Group Policy.
