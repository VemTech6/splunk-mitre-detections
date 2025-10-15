# [ATT&CK] Reconnaissance — Network Scanning Activity (T1595)

**Platform:** Windows / Network  
**ATT&CK Technique:** T1595 — Active Scanning  
**Tactic(s):** Reconnaissance  
**Severity:** High  
**Data Sources:** Firewall Logs, Zeek / Suricata Network Data, Sysmon (NetworkConnect), Windows Security (EventCode=5156)


## Detection Logic (SPL)
```spl
index=network_traffic OR index=firewall OR index=sysmon
| stats dc(dest_ip) AS unique_targets, values(dest_port) AS ports, count BY src_ip
| where unique_targets > 20 OR count > 100
| sort -unique_targets
```

## Rationale 
This detection identifies hosts that are connecting to a large number of unique IP's or ports within a short period of time,
which may indicate network scanning or active reconnaissance.
Adversaries often use tool like Nmap, Masscam, or custom PowerShell scripts to enumerate open ports and identify vulnerable systems before systems before exploitaion.

## Triage 
- Review the source IP(src_ip) generating the traffic, is it an authorized vulnerability scanner or a user workstation?
- Inspect the destination ports to determine the nature of the scan (SMB/445, RDP/3389, SSH/22).
- Check if the scan is horizonatal (many hosts, same port) or vertical (one host, many ports)
- Correlate with authentication logs to see if the same system attempted logons afterward.

## Response 
- Contain or monitor the host performing the scan
- If unauthorized, block outbound traffic from the scanning IP to prevent further reconnaissance.
- Review network logs and EDR telemetry for additional discovery or exploitation behavior.
- Consider deploying rate-limiting or IDS rules to detect future scan attempts more quickly.

## Notes/False Positives
- Vulnerability scanners, inventory systems, and security monitoring tools may generate high connection volumes that look similar.
- Validate whether the source IP belongs to IT operations or vulnerability management systems.
- Adjust thresholds (unique_targets > 20 or count > 100) based on your environment’s typical network behavior.

