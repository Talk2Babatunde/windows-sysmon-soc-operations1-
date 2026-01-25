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

### Stage 1: Authentication Flow (Brute Force to Entry)

To validate the **"Account Compromise"** hypothesis, I reconstructed the authentication flow. This identified the specific source IP and timeframe where the threat actor transitioned from failed guesses to a successful session.

**SPL Query:**

      index=windows (EventCode=4625 OR EventCode=4624)
      | sort _time
      | table _time, host, Account_Name, EventCode, src_ip, Logon_Type

<img width="980" height="616" alt="image2" src="https://github.com/user-attachments/assets/c944d381-d5b2-4ac4-8355-057ff2f557fa" />

<i><b>Forensic Correlation:</b> Chronological reconstruction of Windows Event IDs 4625 (Failed) and 4624 (Success) to identify the precise moment of account compromise following brute-force attempts.</i> </p>


### **Stage 2: Service Installation (T1543.003)**

To ensure survival across all user sessions and elevate persistence to a system-level context, a new service was created. This illustrates the transition from user-level persistence to machine-level persistence.

* **SPL Evidence:** ```spl

      index=sysmon EventCode=12 TargetObject="*Services*" 
      | search Details="*FakeService*"


Note: Event ID 12 (Object Deleted or Created) was used here to catch the initial footprint of the service before it was even started.

### **Stage 3: The Registry Pivot (T1547.001)**

The attacker attempted to hide a persistence trigger in the user hive. While HKLM requires **Admin**, HKCU modifications by the user **Babat**show how threats can persist without immediate administrative privileges.

**SPL Query:** 
     
     index=sysmon EventCode=13 TargetObject="\Run\Fake" 
     | table _time, User, TargetObject, Details

> **Note:** While `HKLM` requires Admin, `HKCU` modifications by the user `Babat` show how threats can persist without immediate administrative privileges.


## 3. Forensic Verdict & Validation

**Final Status:** Simulation Confirmed.

**Validation Logic:**

**Binary Path:** All triggered executions originated from ****C:\Windows\System32\****.  No masquerading or path-hitching detected.

**Naming Convention:** The use of **Fake**" strings consistently identified this as a controlled detection engineering test.

**Lateral Movement:** Zero network telemetry (Sysmon EID 3) was observed following the execution, confirming no C2 (Command & Control) check-ins occurred.
