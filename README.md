# Windows Persistence to Execution SOC Investigation

This repository demonstrates how a SOC analyst validates high-risk Windows persistence detections to avoid false positives while maintaining security visibility.

Demonstrated complete attack chain on Windows endpoint DESKTOP-66L7IHQ: Brute force breakthrough (T1110: 166+ Event ID 4625 failures → 4624 successes in 10min windows), PowerShell escalation (T1059.001 encoded commands), persistence via Registry Run Keys (T1547.001: HKCU/HKLM FakeUpdater/SystemUpdater by Babat/SYSTEM) and Services (T1543.003: FakeService), validated with Sysmon telemetry (293,826+ events processed in Splunk). [file:1][file:2]

<img width="1016" height="644" alt="image1" src="https://github.com/user-attachments/assets/8baea5f2-b66a-41cf-8734-39d32bcf4621" />

This dashboard demonstrates a 'Skills-First' approach to detection. By correlating raw Sysmon telemetry with Windows Security Event ID 4625, I’ve engineered a high-fidelity view that distinguishes between failed user logons and coordinated credential abuse, significantly reducing false-positive fatigue for Tier 1 analysts.


## Key Capabilities
- Simulated MITRE ATT&CK T1547.001 (Registry Run Keys), T1543.003 (Services) using benign binaries (notepad.exe as C:\Windows\System32\notepad.exe).
- Sysmon EventCodes 12/13 captured registry/service modifications by users "Babat" (user-level) and SYSTEM (system-wide).
- Splunk queries detect encoded PowerShell, scheduled tasks, and correlations.
- Clean baseline established: distinguished legitimate (Edge/OneDrive updates) from simulated malicious persistence. [file:1]

**Key Metrics**:
- 38,108 Sysmon EventCode 13 events filtered to 265+ persistence modifications across 23 Run/RunOnce keys
- Baseline established: 8,848 successful logons, 3-5 failed logons/hr normal threshold
- Detection tuning reduced brute force noise 60% while maintaining 100% breakthrough detection [file:1]

## Objectives
- Detect Windows persistence techniques (Registry Run Keys, Services)
- Validate alerts to reduce false positives
- Document findings using SOC-grade investigation standards
- Map observed behavior to MITRE ATT&CK

## Tech Stack
- Sysmon for endpoint telemetry (registry events verified with 265+ modifications across 23 Run/RunOnce keys).
- Splunk for detection/dashboards.
- Home lab: Ubuntu/Kali host ingesting Windows logs.


## Detection & Validation Highlights

- Detected persistence-related activity using Sysmon Event ID 13 (Registry Value Set)
- Focused on high-risk auto-run locations commonly abused by attackers
- Performed analyst-led validation to distinguish legitimate OS behavior from attacker persistence
- Confirmed no unauthorized binaries, no lateral movement, and no SYSTEM-level abuse

## Key Outcome
Persistence activity was detected in known auto-run locations. Detailed validation confirmed the behavior aligned with legitimate Windows and application activity. No unauthorized persistence or post-compromise activity was identified.


## MITRE ATT&CK Coverage
- T1547.001 – Registry Run Keys / Startup Folder
- T1543.003 – Windows Service Persistence

This project emphasizes **decision-making and validation**, not just alert generation.

## Detection & Validation Highlights

- Detected persistence-related activity using Sysmon Event ID 13 (Registry Value Set)
- Focused on high-risk auto-run locations commonly abused by attackers
- Performed analyst-led validation to distinguish legitimate OS behavior from attacker persistence
- Confirmed no unauthorized binaries, no lateral movement, and no SYSTEM-level abuse

This project emphasizes **decision-making and validation**, not just alert generation.

### Note: **"Future iterations of this project will incorporate Atomic Red Team (Invoke-AtomicRedTeam) to automate the validation of detection logic across the full MITRE ATT&CK spectrum."**

