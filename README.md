# Kerbo_Catch
# Kerbo_Catch — Active Directory Identity Threat Hunting Engine

A PowerShell-based threat hunting engine designed to detect high-fidelity Active Directory identity attacks. This tool ingests Windows Security Logs (either live or via offline CSV export) and filters for specific cryptographic and behavioral anomalies associated with advanced persistent threats.

---

## Purpose

The purpose of this tool is to identify **identity-based attacks** that often bypass standard signature-based detection. It moves beyond generic event alerting by enforcing strict logic filters that separate legitimate Active Directory replication and authentication traffic from malicious operator behavior.

It focuses on five specific attack vectors:

- **Kerberoasting** (Service Principal Name theft)
- **AS-REP Roasting** (Pre-authentication disabled accounts)
- **DCSync** (Domain replication privilege abuse)
- **Golden Ticket** (Forged TGTs / Mimikatz artifacts)
- **Persistence** (Privileged group modification)

---

## Usage

### Prerequisites

- **PowerShell 5.1 or higher**
- **Administrator privileges**  
  Required for *Live System Triage* to access the Windows Security Event Log.
- **Domain Controller access**  
  For best results, run directly on a Domain Controller or analyze logs exported from one.

---

## Modes of Operation

Upon launch, the script offers two operating modes:

### 1. Import-CSV
Analyzes offline Windows Security Event logs that have been converted to CSV format.  
Best suited for **forensic analysis**, evidence review, and historical investigations.

### 2. Live System Triage
Queries the local Windows Security Event Log in real time.  
Designed for **active incident response** on a potentially compromised host.

---

## Execution

Run the script from an **elevated PowerShell terminal**:

```powershell
.\Kerbo_Catch.ps1
```
## Detection Logic

This tool uses **operator-grade logic** to reduce false positives.  
It does **not** alert solely on Event IDs; it inspects **Kerberos cryptographic metadata** and **behavioral context**.

---

### 1. Kerberoasting

**Target Event:**

- `4769` — Kerberos Service Ticket Request
    

**Logic:**

- Excludes machine accounts (names ending in `$`)
    
- Excludes the `krbtgt` account
    
- Filters for **Ticket Encryption Type `0x17` (RC4-HMAC)**
    

**Why it works:**  
Modern Windows domains default to AES encryption. A service ticket request using RC4 from a non-machine account strongly indicates an attacker intentionally downgrading encryption to crack the ticket offline.

---

### 2. AS-REP Roasting

**Target Event:**

- `4768` — Kerberos Authentication Ticket Request
    

**Logic:**

- Filters for **Pre-Authentication Type `0` (or `0x0`)**
    
- Filters for **Ticket Encryption Type `0x17` (RC4)**
    

**Why it works:**  
Identifies accounts configured with _“Do not require Kerberos preauthentication.”_ Attackers target these accounts to retrieve crackable authentication material without submitting credentials to the Domain Controller.

---

### 3. DCSync

**Target Event:**

- `4662` — Operation Performed on an Object
    

**Logic:**

- Filters for **Access Mask `0x100` (Control Access)**
    
- **Critical filter:** excludes `SubjectUserName` ending in `$`
    

**Why it works:**  
Domain Controllers legitimately replicate data using this permission. Excluding machine accounts isolates **user-initiated replication attempts**, which is a definitive indicator of a DCSync attack (e.g., `mimikatz lsadump::dcsync`).

---

### 4. Golden Ticket

**Target Events:**

- `4624` — Logon
    
- `4672` — Special Logon
    
- `4769` — Ticket Request
    

**Logic:**

- Performs **case-sensitive matching** (`-cmatch`) on `TargetDomainName`
    
- Flags any domain name containing **lowercase characters** (`[a-z]`)
    

**Why it works:**  
Windows authentication normalizes domain names to **UPPERCASE**. Many attack tools allow operators to manually specify the domain name. If entered in lowercase, this artifact persists throughout the authentication chain—exposing a forged TGT.

---

### 5. Persistence (Privileged Group Modification)

**Target Events:**

- `4728`, `4732`, `4756` — Member Added to Security Group
    

**Logic:**

- Monitors additions to:
    
    - `Domain Admins`
        
    - `Enterprise Admins`
        
    - `Administrators`
        
    - `Schema Admins`
        

**Why it works:**  
Immediate detection of privileged group modification is one of the fastest ways to identify an attacker establishing **long-term persistence** after initial compromise.

---

## Summary

Kerbo_Catch is designed for defenders who need **high-signal detection** without noise.  
It prioritizes **cryptographic intent**, **account context**, and **protocol abuse**—not just event volume.

This makes it especially effective during:

- Active Directory incident response
    
- Purple team exercises
    
- Threat hunting operations
    
- Forensic review of DC security logs
