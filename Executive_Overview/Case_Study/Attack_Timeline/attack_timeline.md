# Incident Reconstruction: Persistence & Execution Timeline

**Executive Summary of the Attack Chain**

This timeline reconstructs a multi-stage attack lifecycle on DESKTOP-66L7IHQ. By correlating Windows Security Logs with Sysmon Telemetry, I have mapped the progression from initial Credential Access (Brute Force) to Persistence (Registry/Services/Tasks) and final Execution.

## 1. Chronological Event Sequence

| Timestamp (Approx)  | Phase       | Technical Event                 | Log Source      | Evidence / Indicators                                                 |
| ------------------- | ----------- | ------------------------------- | --------------- | --------------------------------------------------------------------- |
| T0: Ingestion Start | Baseline    | System Audit & Log Verification | WinEventLog     | Confirmed 293k events; msedge.exe RunOnce baseline established.       |
| T1: Discovery       | Persistence | Registry Run Key Modification   | Sysmon (EID 13) | HKCU\\...\\Run\\FakeUpdater → notepad.exe. User: Babat.               |
| T2: Elevation       | Persistence | System-Wide Service Creation    | Sysmon (EID 12) | TargetObject=FakeService. State: Created/Stopped.                     |
| T3: Execution       | Persistence | Post-Reboot Process Launch      | Sysmon (EID 1)  | notepad.exe spawned from explorer.exe (User) + services.exe (System). |


## 2. Technical Evidence Deep-Dive

**Stage 1: The Registry Pivot (T1547.001)**

The attacker (simulated) attempted to hide a persistence trigger in the user hive.

**SPL Query:** 
     
     index=sysmon EventCode=13 TargetObject="\Run\Fake" 
     | table _time, User, TargetObject, Details

> **Note:** While `HKLM` requires Admin, `HKCU` modifications by the user `Babat` show how threats can persist without immediate administrative privileges.



**Stage 2: Service Installation (T1543.003)**

To ensure survival across all user sessions, a service was created.

* **SPL Evidence:** ```spl

      index=sysmon EventCode=12 TargetObject="*Services*" 
      | search Details="*FakeService*"

## 3. Forensic Verdict & Validation

**Final Status:** Simulation Confirmed.

**Validation Logic:**

**Binary Path:** All triggered executions originated from C:\Windows\System32\. No masquerading or path-hitching detected.

**Naming Convention:** The use of "Fake*" strings consistently identified this as a controlled detection engineering test.

**Lateral Movement:** Zero network telemetry (Sysmon EID 3) was observed following the execution, confirming no C2 (Command & Control) check-ins occurred.
