# Analyst Investigation Journal

**Incident ID: WIN-PERSIST-001**

**Status:** Closed (Resolved as Benign/False Positive)

**Assigned Analyst:** Babatunde Qodri

## 1. Initial Triage & Scope

The investigation was initiated following the detection of multiple Registry Value Set (Sysmon EID 13) events targeting known persistence hives (Run / RunOnce).

Total Events Scanned: 265 registry modifications.

Scope: 23 unique registry keys across HKCU and HKLM.

Primary Observed Activity: High-volume telemetry associated with Microsoft Edge and Windows Update background processes.

## 2. Technical Findings & Evidence

During the deep-dive analysis, the following anomalies were isolated and scrutinized:

| Indicator     | Location                 | Context         | Findings                                                   |
| ------------- | ------------------------ | --------------- | ---------------------------------------------------------- |
| FakeUpdater   | HKCU\\...\\Run           | User: Babat     | Observed execution of notepad.exe. Binary path legitimate. |
| SystemUpdater | HKLM\\...\\Run           | User: SYSTEM    | Admin-level persistence simulation.                        |
| FakeService   | System\\CurrentControlSet | Service Control | Created to test service-based persistence detection logic. |

## 3. Behavioral Analysis (Threat Hunting)

To confirm if the **"Fake"** indicators were part of a larger compromise, I pivoted to Process and Network telemetry:

**Binary Integrity:** All observed binaries (e.g., notepad.exe, msedge.exe) were Microsoft-signed and residing in C:\Windows\System32\ or C:\Program Files\.

**Heuristic Check:** No persistence entries referenced user-writable directories (\AppData\, \Temp\) or known LOLBins (e.g., rundll32.exe, mshta.exe).

**Sequence Validation:** Activity timing aligned with system maintenance windows and the established lab baseline.

## 4. Validation Decision Rationale (The "Why")

**Final Verdict:** Benign / False Positive.

While the registry locations are high-value targets for malware (T1547.001), the evidence does not support an active compromise. The presence of "Fake*" naming conventions was identified as part of a Controlled Simulation Exercise. In a production environment, the lack of follow-on malicious activity (C2 beaconing, lateral movement) and the presence of trusted signatures would lead to the same non-escalation decision.

## 5. Proposed Tuning & Hardening

**Tuning:** Filter out signed Microsoft binaries in C:\Program Files\ from the P3 Alert to reduce noise.

**Hardening:** Recommend implementing Attack Surface Reduction (ASR) rules to block process creations from Office or unauthorized persistence in HKCU.
