# [ATT&CK] Brute Force (T1110.001) — Multiple RDP Failures From One Source

**Platform:** Windows  
**ATT&CK Technique:** T1110.001 — Password Guessing  
**Tactic(s):** Credential Access  
**Severity:** Medium  
**Data Sources:** Windows Security (EventCode=4625)

## Detection Logic (SPL)
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625 Logon_Type=10
| eval user=coalesce(TargetUserName, Account_Name)
| eval src=coalesce(IpAddress, Source_Network_Address)
| eval dest=host
| where isnotnull(src) AND src!="-"
| bin _time span=10m
| stats count AS failed by dest, src, user, _time
| where failed>=10
| sort -failed
```

## Rationale
Brute force attempts against RDP accounts often appear as multiple failed login events (4625) from the same source IP within a short period of time. This detection highlights ≥10 failures in 10 minutes, which balances catching true brute force behavior while ignoring occasional password typos. Since RDP brute force is one of the most common initial access techniques used by ransomware operators and remote attackers, this rule provides early visibility into potentially serious threats.

---

## Triage
When this detection triggers, analysts should:

### Validate the Source IP
- Determine if it’s internal, external, or a known management system.  
- External IPs repeatedly failing RDP logins are high-risk.  

### Check the Account
- Confirm whether the targeted account is valid, disabled, or a service account.  
- Pay close attention if the account has administrative or domain-level privileges.  

### Correlate Events
- Look for a 4624 (successful logon) after the failures.  
- See if the same source IP is targeting multiple accounts or endpoints.  

### Rule Out False Positives
- Consider vulnerability scanners, penetration tests, or misconfigured scripts that could cause repeated login attempts.  

---

## Response
If the brute force is confirmed malicious:

### Containment
- Block or firewall the source IP if external.  
- If internal, isolate and investigate the host responsible.  

### Account Protection
- Lock or reset the targeted account’s password.  
- Enable MFA for RDP access or disable RDP where unnecessary.  

### Threat Hunting
- Search for other failed and successful logons from the same IP or user.  
- Look for lateral movement attempts following any successful login.  

### Exposure Review
- Audit RDP exposure in the environment.  
- Restrict RDP to VPN only or disable where not required.  

### Documentation
- Record details (source IP, targeted account, destination host, failure count) for incident tracking and reporting.  



