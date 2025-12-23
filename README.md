# Kerbo_Catch

**Active Directory Identity Threat Hunting Engine**

Kerbo_Catch is a PowerShell-based threat hunting engine for detecting high-fidelity Active Directory identity attacks. It ingests Windows Security logs (live or offline CSV), normalizes events into a consistent schema, and applies strict detection logic to surface cryptographic and behavioral indicators of identity abuse.

---

## Purpose

Kerbo_Catch is built to identify identity-based attacks that often evade signature-driven detection. Rather than alerting on Event IDs alone, it evaluates Kerberos metadata, account context, access rights, and behavior to distinguish legitimate domain activity from malicious use.

---

## Attack Coverage

Kerbo_Catch focuses on the following identity attack vectors:

- Kerberoasting (SPN abuse)
    
- AS-REP Roasting (pre-authentication disabled accounts)
    
- DCSync (directory replication abuse)
    
- Golden Ticket artifacts (forged TGT indicators)
    
- Persistence (privileged group modification)
    

---

## Usage

### Prerequisites

- PowerShell 5.1 or higher
    
- Administrator privileges (required for live Security log access)
    
- Domain Controller access or exported DC Security logs
    

---

## Modes of Operation

Kerbo_Catch supports two modes:

### Import-CSV

Analyzes offline Windows Security logs exported to CSV.  
Intended for forensic review and historical analysis.

### Live System Triage

Queries the local Windows Security Event Log in real time.  
Designed for active incident response.

Both modes produce the same normalized event objects, ensuring identical detection behavior regardless of input source.

---

## Execution

Run from an elevated PowerShell terminal:

```
.\kerbo_catchV2.ps1
```

---

## Detection Logic

Kerbo_Catch uses high-signal, operator-grade logic designed to reduce false positives. Detections are based on protocol misuse and context rather than Event ID presence alone.

### Kerberoasting

- Event: 4769
    
- RC4 encryption (0x17)
    
- Excludes machine accounts and `krbtgt`
    

Detects intentional encryption downgrades used for offline password cracking.

### AS-REP Roasting

- Event: 4768
    
- PreAuthType 0
    
- RC4 encryption
    

Identifies accounts vulnerable to credential extraction without authentication.

### DCSync

- Event: 4662
    
- AccessMask 0x100
    
- Excludes machine accounts
    
- Validates directory replication GUIDs
    

Isolates user-initiated replication activity indicative of DCSync abuse.

### Golden Ticket Artifacts

- Events: 4624, 4672, 4769
    
- Case-sensitive domain name inspection
    

Flags lowercase domain artifacts commonly left by forged TGTs.

### Privileged Group Modification

- Events: 4728, 4732, 4756
    
- Monitors Domain Admins, Enterprise Admins, Administrators, Schema Admins
    

Detects persistence via privileged group abuse.

---

## Kerbo_Catch v1 vs v2

Kerbo_Catch v2 builds on the original design with improved performance, accuracy, and operational usability.

Key changes:

- Unified normalized event schema across CSV and Live modes
    
- Single-pass, stream-based detection using filters and functions
    
- Centralized detection logic in `Invoke-DetectionLogic`
    
- Improved DC Sync attribution using replication GUIDs
    
- Normalized structured output with automatic CSV export
    

v2 evaluates all detections in one pass over the data, significantly improving performance on large Security logs while reducing false positives.

---

## Summary

Kerbo_Catch is designed for defenders who need high-confidence identity threat detection without noise. By focusing on cryptographic intent, access rights, and protocol abuse, it is well suited for:

- Active Directory incident response
    
- Threat hunting
    
- Purple team exercises
    
- Forensic review of Domain Controller Security logs
