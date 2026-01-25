# Containment & Remediation Strategy

**The Analyst's Dilemma**

Containment must balance Security with Operational Continuity. In this investigation, because the activity was identified as a controlled simulation, no active containment was executed. However, had this been a True Positive (TP), the following tiered containment strategy would have been implemented.

## 1. Tactical Containment (Immediate Action)

If the FakeUpdater or FakeService had shown signs of malicious intent (e.g., C2 beaconing or credential dumping), the following steps would be taken:

**Endpoint Isolation:** Utilize an EDR tool (or Windows Firewall) to isolate DESKTOP-66L7IHQ from the network, allowing only a management tunnel for forensic analysis.

**Process Termination:** Kill the parent and child process trees associated with the persistent binary.

**Command:** taskkill /F /PID [Malicious_PID] /T

**Credential Revocation:** Immediately disable the Babat user account and force a global password reset for all sessions originating from the affected host.

## 2. Strategic Hardening (GPO & Policy)

To prevent the technique (T1547.001) from being used again, I recommend the following system-wide hardening:

| Recommendation    | Implementation Method                                                | Impact                                                          |
| ----------------- | -------------------------------------------------------------------- | --------------------------------------------------------------- |
| Restrict Run Keys | GPO: Registry Path Shielding                                         | Prevents standard users from writing to HKCU\\...\\Run.         |
| ASR Rules         | Attack Surface Reduction (Rule: Block process creations from Office) | Prevents malicious attachments from achieving persistence.      |
| Service Control   | Group Policy: Restricted Groups                                      | Limits local users from creating or modifying Windows Services. |

## 3. Proactive Hunting (The "Lookback")

Once the immediate threat is contained, the SOC should perform a "Lookback" to ensure no other endpoints are affected.

**The "Clean-Up" Hunt Query:**

Splunk SPL

      index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
      | search NOT (Image="C:\\Windows\\*" OR Image="C:\\Program Files\\*")
      | stats values(Details) as Binary_Path by Computer, User

**Logic:** This query ignores standard Microsoft directories to find "Low-Reputation" binaries hiding in user-writable paths like **\AppData\Local\.**

## 4. Remediation & Recovery

**Registry Cleaning:** Manually or via script remove the FakeUpdater and SystemUpdater keys.

**Service Removal:** Delete the FakeService using the Service Control Manager.

**Command:** sc delete FakeService

**Integrity Check:** Run SFC /scannow to ensure no core system binaries were replaced.
