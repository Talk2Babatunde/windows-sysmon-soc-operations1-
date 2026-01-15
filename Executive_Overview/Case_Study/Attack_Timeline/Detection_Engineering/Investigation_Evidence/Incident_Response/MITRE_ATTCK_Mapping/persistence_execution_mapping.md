# MITRE ATT&CK Framework Mapping & Gap Analysis

**Strategic Overview**

This project focuses on the Persistence and Execution tactics of the MITRE ATT&CK framework. By mapping our Splunk detections to specific sub-techniques, we can measure the maturity of our security posture and identify exactly where an attacker would be caught in the "Kill Chain."

## 1. Technique Coverage Map

| Tactic      | Technique                                            | ID        | Detection Evidence                                   | Log Source       |
| ----------- | ---------------------------------------------------- | --------- | ---------------------------------------------------- | ---------------- |
| Execution   | Command and Scripting Interpreter: PowerShell        | T1059.001 | powershell.exe -enc extraction via Regex             | Sysmon EID 1     |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Modification of HKCU and HKLM Run keys (FakeUpdater) | Sysmon EID 13    |
| Persistence | Create or Modify System Process: Windows Service     | T1543.003 | Installation of FakeService pointing to notepad.exe  | Sysmon EID 12    |
| Persistence | Scheduled Task/Job: Scheduled Task                   | T1053.005 | Creation of UpdaterTask via schtasks.exe             | WinEventLog 4698 |

**MITRE ATT&CK Coverage:** Perfect mapping table for your case study—shows comprehensive tactic coverage across execution and persistence. Recruiters immediately recognize your ATT&CK fluency. Place this in your "Framework Mapping" section with the metrics table for maximum impact.

## 2. Deep Dive: The Persistence Chain

### T1547.001 - Registry Run Keys

**Detection Logic:** Monitoring for any SET operation within the CurrentVersion\Run hive.Analyst Observation: Successfully detected the simulation. However, during mapping, we identified high-volume noise from msedge.exe.

**Maturity Note:** We moved from a Static IOC (looking for "FakeUpdater") to a Behavioral Pattern (looking for any non-system binary in a Run key).

### T1059.001 - PowerShell (Obfuscated)

**Detection Logic:** Identifying the -enc flag combined with a Base64 string length $> 20$.

**Analyst Observation:** This mapping is critical because PowerShell is often the "delivery vehicle" for the persistence mechanisms listed above.

## 3. Detection Maturity Rating

| Technique ID | Confidence | Logic Type   | Recommendation for Improvement                                          |
| ------------ | ---------- | ------------ | ----------------------------------------------------------------------- |
| T1547.001    | High       | Behavioral   | Implement "Allow-list" for signed Microsoft binaries to reduce FP rate. |
| T1543.003    | Medium     | Signature    | Broaden monitoring to include Service DLL modifications (EID 13).       |
| T1053.005    | High       | Audit Policy | Ensure EID 4698 pulled from all Tier-0 assets (Domain Controllers).     |
