# From Brute Force to Registry Persistence 

## 1. Executive Summary

This case study documents a simulated attack lifecycle targeting a Windows 10 endpoint. The goal was to validate the transition from Credential Abuse (T1110) to Persistence (T1547.001) and test the analyst's ability to distinguish between automated malware behavior and local interactive administration.

## 2. The Attack Simulation (Telemetry Generation)

To generate realistic telemetry without using malware, I leveraged Living-off-the-Land Binaries (LOLBins):

**Initial Foothold:** Simulated brute-force attempts via runas.

**Persistence Mechanism:** * 
     
      reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v FakeUpdater /t REG_SZ /d "C:\Windows\System32\notepad.exe"

**Privilege Escalation Simulation:** 
      
      sc create FakeService binPath= "C:\Windows\System32\notepad.exe" start= auto

## 3. Splunk Detection Logic

### A. Correlation of Credential Stress

Most analysts look for failed logins. I looked for the Pivot—where a failure streak ends in a success.

Splunk SPL Query

      index=windows (EventCode=4625 OR EventCode=4624) 
      | transaction Account_Name maxspan=10m 
      | where eventcount > 5 AND last(EventCode)=4624
      | table _time, Account_Name, eventcount, src_ip

**Analyst Note:** This query identifies a "Successful Brute Force" by finding accounts with multiple failures followed by a single success within a 10-minute window.

### B. Registry Persistence Monitoring 

Using Sysmon Event ID 13, I monitored the specific "Run" keys that attackers use to survive reboots.

Splunk SPL Query

      index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
      | table _time, User, Image, TargetObject, Details

## 4. The Validation Pivot

Stop! An alert is not an incident. Before escalating, I performed Contextual Validation:

| Validation Check  | Finding                               | Verdict                                              |
| ----------------- | ------------------------------------- | ---------------------------------------------------- |
| User Context      |**User:** Babat                           |  **Low Risk:** Local interactive session via EID 4624   |
| Binary Integrity  | **Path:** C:\\Windows\\System32\\notepad.exe |  **Benign:** Standard path, signed Microsoft executable |
| Temporal Analysis | Activity during business hours        |  **Expected:** Aligns with normal maintenance windows   |

**Final Verdict:** BENIGN. The activity, while matching an attacker technique, was verified as a local administrative test. No escalation required.

## 5. Lessons for the SOC

**Telemetry is Policy:** Event ID 4698 (Scheduled Tasks) was missing until I manually updated the Advanced Audit Policy. Visibility is a requirement, not a default.

**Context over Content:** A registry key is just data. A registry key + a SYSTEM user context is a Crisis. A registry key + a Local User context is a Checklist.
