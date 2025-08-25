# Splunk MITRE ATT&CK Detections

This repository contains custom Splunk detection rules mapped directly to MITRE ATT&CK techniques and sub-techniques. Each detection is fully documented with its logic, rationale, triage steps, and response guidance.  

The goal of this project is to build a structured collection of detections that not only align with industry frameworks but also provide deep documentation of the process behind creating and refining them.  

## Key Features
- **MITRE Mapping** — every detection links to a corresponding ATT&CK technique.  
- **Heavy Documentation** — each rule includes goals, rationale, triage notes, and response steps.  
- **Process-Oriented** — methodology, design choices, and references are captured for clarity.  
- **Living Repository** — new techniques and detections will be added over time.  

## Structure
- `detections/` → SPL rules, one per ATT&CK technique/sub-technique.  
- `notes/` → project goals, methodology, and MITRE reference notes.  

## Example Coverage
- T1059.001 PowerShell Execution  
- T1003.001 LSASS Credential Dumping  
- T1110.001 RDP Brute Force  

This repo serves as a growing catalog of well-documented Splunk detections aligned with MITRE ATT&CK.



