# Incident Investigation Summary: WIN-PERSIST-001

## 1. Incident Overview

**Incident ID:** 2026-JAN-15-SEC-001

**Trigger:** Alert triggered on T1547.001 (Registry Run Key Modification) and T1053.005 (Scheduled Task Creation).

**Scope:** 1 Host (DESKTOP-66L7IHQ), 1 User (Babat).

**Verdict:** Closed - Benign Simulation / Controlled Test.

## 2. Evidence & Timeline Reconstruction

The investigation analyzed a 293k event dataset to correlate a series of suspicious indicators.

**Initial Detection:** High-fidelity monitoring captured the creation of a registry key FakeUpdater pointing to notepad.exe.

**Correlated Activity:** Subsequent detection of Event ID 4698 (Scheduled Task: UpdaterTask) and Event ID 12 (Service Creation: FakeService).

**PowerShell Profiling:** Identified repeated executions of PowerShell by the Splunk Universal Forwarder. Analysis of the CommandLine confirmed these were native metric collection scripts and not C2 beaconing.

## 3. Validation Logic (The "Pivot")

| Investigation Step  | Method                  | Result                                                                                   |
| ------------------- | ----------------------- | ---------------------------------------------------------------------------------------- |
| Integrity Check     | reg query & sc query    | Verified paths existed and pointed to signed binaries.                                   |
| Binary Verification | Sysmon EID 1 (Hashes)   | notepad.exe hash matched known-good Microsoft baseline.                                  |
| Contextual Analysis | Logon Type Verification | Activity mapped to Logon Type 2 (Interactive) - user-initiated test, not remote exploit. |

## 4. Final Disposition & SOC Decision
 
 **Verdict:** Benign Activity.

**Rationale:**

1. The naming conventions (Fake*) and the use of benign binaries (notepad.exe) were consistent with a Detection Engineering Simulation. 

2. No indicators of secondary attack stages were found (e.g., credential dumping, lateral movement, or network exfiltration).

3. The activity aligned exactly with the "Lab Reproduction" timestamps.

## 5. Post-Incident Actions (Hardening)

Even though this was a simulation, I have recommended the following Tuning to improve future response:

**Suppression:** Refined Splunk detection logic to suppress known-good Universal Forwarder PowerShell activity.

**Cleanup:** All simulated artifacts were successfully removed using the following:

      reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v FakeUpdater /f

      sc delete FakeService
I utilized a cross-telemetry validation method to confirm the nature of the activity:
