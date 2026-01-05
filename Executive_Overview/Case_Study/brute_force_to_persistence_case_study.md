# Brute Force to Persistence Case Study

**Scenario**: Attacker gains initial access via brute force, escalates via PowerShell, persists using registry Run keys and services—common in RATs/info-stealers. [file:1]

**Simulation Steps** (Safe, LOLBin-only):
1. User-level: `reg add HKCU\Run /v FakeUpdater /t REG_SZ /d "C:\Windows\System32\notepad.exe"` – Triggers on logon.
2. System-wide: `reg add HKLM\Run /v SystemUpdater /t REG_SZ /d "C:\Windows\System32\notepad.exe"` (admin).
3. Service: `sc create FakeService binPath= "C:\Windows\System32\notepad.exe" start= auto`.

**Detection Evidence**: Sysmon EventCode 13 (registry value set) on TargetObject=*Run*, Details=notepad.exe, User=Babat/SYSTEM. Splunk confirmed post-reboot execution. [file:1]

**Detection Evidence**:
Splunk: index=windows (4625 OR 4624) | transaction AccountName maxspan=10m | where failurecount>=2 AND successcount>=1
Sysmon: EventCode=13 TargetObject=Run Details="C:\Windows\System32\notepad.exe"

## Detection Validation (Critical SOC Step)

Although persistence-related registry modifications were detected, escalation was intentionally paused to perform validation.

Validation steps included:
- Verifying user context (interactive user vs SYSTEM)
- Confirming binary path and signature
- Reviewing timing relative to system activity
- Checking for business justification

This process prevented misclassification of legitimate Windows behavior as malicious activity.



**Lessons**: User-hive (HKCU) evades admin detection; baseline vs. anomaly critical.
