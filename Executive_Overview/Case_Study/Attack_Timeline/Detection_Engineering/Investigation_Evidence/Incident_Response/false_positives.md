# False Positive Analysis & Tuning Logic

## The Objective

In a production SOC, the goal of detection engineering is to maximize "Signal" and minimize "Noise." This document analyzes why certain persistence-related detections were classified as Benign/False Positive and how we tuned our logic to prevent future alert fatigue.

## 1. Case Study: Registry Run Key Modification (T1547.001)

**The Alert:** A modification was detected in the **HKCU\...\CurrentVersion\Run registry hive.**

**The Disposition:** False Positive (Benign Activity)

**Logic for Non-Escalation:**

| Factor           | Observation                                                  | Analyst Verdict                                                                                                                                 |
| ---------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| User Context     | User: Babat                                                  | **Benign:** Session identified as Logon_Type=2 (Local Interactive). An attacker would more likely operate under SYSTEM or remote network session. |
| Binary Path      | C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe | **Trusted:** Signed Microsoft executable in protected directory.                                                                                  |
| Activity Pattern | Occurred immediately following a browser update.             | **Expected:** Matches Microsoft Edge background update behavior.                                                                                  |

**Final Verdict:** BENIGN - Edge update persistence, not attacker TTP. Context validation prevented false positive escalation.

## 2. Tuning Recommendations (Reducing the Noise)

To prevent this specific activity from triggering future P3 alerts, I implemented the following Filtering Logic in our Splunk searches:

**The Tuning Query (SPL):**

Splunk SPL

      index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
      | search NOT (Image="C:\\Program Files (x86)\\Microsoft\\*" AND (Details="*msedge.exe*" OR Details="*msteams.exe*"))
      | stats count by User, Image, TargetObject, Details


<img width="969" height="338" alt="image13" src="https://github.com/user-attachments/assets/78f0f69e-aa3f-4a61-857e-ab9b62ab6e61" />

  <i><b>Triage Impact:</b> Reduced background authentication noise through temporal aggregation, isolating 166 user-targeted failed logon events for high-fidelity investigation.</i>
</p>

**Impact of Tuning:**

**False Positive** Reduction: ~15% reduction in registry-based alert volume.

**Analyst Efficiency:** Allows the team to focus on non-standard paths (e.g.,**C:\Users\Public\**) and unsigned binaries.

## 3. Behavioral Baselines vs. Static IOCs

We identified that Windows Update and Edge Update frequently trigger RunOnce keys. Instead of globally whitelisting these, we use Behavioral Baselines:

**Malicious Indicator:** Registry change + SYSTEM context + Network connection (EID 3) + Unsigned binary.

**Benign Indicator:** Registry change + Interactive User context + Standard path + Signed binary.

