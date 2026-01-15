# SOC Playbook: Windows Persistence Detection (T1547 / T1543)

## 1. Playbook Objective

To provide a standardized workflow for investigating unauthorized persistence mechanisms in Windows environments, specifically targeting Registry Run Keys and Service Installations.

## 2. Phase I: Triage & Identification

**Goal:** Confirm the alert and identify the "Blast Radius."

**Execute Primary Hunt Query:**

Splunk SPL

      index=sysmon (EventCode=12 OR EventCode=13) TargetObject="*CurrentVersion\\Run*"
      | table _time, Computer, User, Image, TargetObject, Details, ProcessGuid

**Identify the Actor:** Check the User and LogonID. Is it a standard user (Babat), a Service Account, or SYSTEM?

**Cross-Reference Execution:** Pivot using the ProcessGuid to see what process created this entry.

## 3. Phase II: Technical Validation (The "Analysis")
   
**Goal:** Determine if the activity is a False Positive (FP) or a True Positive (TP).

| Check       | Action                               | Indicator of Malice                                    |
| ----------- | ------------------------------------ | ------------------------------------------------------ |
| Binary Path | Verify Image location                | Resides in \\Temp, \\AppData, or \\Public.             |
| Signature   | Check file entropy/signature via EDR | Unsigned or "Unknown" publisher.                       |
| Logic       | Analyze Details field                | Encoded PowerShell strings or LOLBin abuse (regsvr32). |
| Timing      | Compare to system baseline           | Occurs outside maintenance windows/Patch Tuesdays.     |

## 4. Phase III: Containment & Eradication

If TP (Unauthorized):

**Isolate Host:** Move the endpoint to a "Containment" VLAN via EDR.

**Kill Process:** Terminate the malicious process tree identified in Phase I.

**Remove Persistence:** * Registry: reg delete [Key_Path] /v [Value_Name] /f

**Service:** sc delete [Service_Name]

If FP (Benign):

**Baseline:** Document the legitimate application (e.g., OneDrive, Edge).

**Tune:** Add the binary hash to the "Authorized Persistence" lookup table in Splunk.

## 5. Phase IV: Documentation & Reporting

Use the following template for the Incident Ticket:

**Summary:**

Detected modification of [TargetObject] by [User] on [Computer]. 

**Technical Findings:** Binary [Image] was verified as [Signed/Unsigned]. Correlation via ProcessGuid [ID] shows the parent process was [ParentImage]. 

**MITRE Mapping:** T1547.001 (Persistence). Verdict: [Benign/Malicious].

**Action Taken:** [Cleanup Performed / Alert Suppressed].
