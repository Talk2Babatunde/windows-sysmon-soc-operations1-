# High-Fidelity Telemetry with Sysmon

The **"Visibility Gap"** in Standard Logging

Native Windows Security logs (Event ID 4688) often provide the **"Who"** and **"When,"** but they lack the forensic **"How."** In this project, I integrated Sysmon (System Monitor) to provide the deep-level telemetry required for high-confidence investigation and automated correlation.

## 1. Anatomy of an Attack: Sysmon Event ID 1 (Process Creation)

Sysmon Event ID 1 is the cornerstone of endpoint visibility. It captures critical metadata that allows an analyst to reconstruct the Attack Chain with surgical precision.

### The Forensic Hunt Query:

Splunk SPL

      index=sysmon EventCode=1 
      | table _time, Computer, User, Image, Commandline, ParentImage, ParentCommandLine, ProcessGuid, Hashes
      | sort - _time

### Key Forensic Fields Analyzed:

**ParentCommandLine:** Reveals the exact command that triggered the process, exposing "Living-off-the-Land" (LotL) techniques.

**ProcessGuid:** A unique identifier that allows us to track a process across its entire lifecycle, even across reboots, providing a reliable "Primary Key" for Splunk joins.

**Hashes (SHA256):** Provides the cryptographic fingerprint of the executable for instant integration with Threat Intelligence (e.g., VirusTotal).

## 2. Evidence Capture: Encoded PowerShell (T1027)

During the simulation, I identified a PowerShell process utilizing obfuscation. While native logs showed the execution, Sysmon captured the full encoded blob.

**The "Encoding Detection" Query:**

**Splunk SPL**

      index=sysmon EventCode=1 (CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")
      | rex field=CommandLine "(?<encoded_blob>[A-Za-z0-9+/=]{20,})"
      | table _time, User, Image, encoded_blob, ProcessGuid

The screenshot sysmon_event_details.png confirms that the encoded_blob was captured in full. By utilizing the rex command in Splunk, I can extract this blob for automated decoding, moving from "Detection" to "Intelligence" in seconds.

## 3. Registry Visibility: Event ID 13 (Value Set)

Attackers survive reboots by modifying the Registry. Sysmon Event ID 13 provides the TargetObject and Details fields, showing exactly what was written to the system.

**The "Persistence Hunt" Query:**

**Splunk SPL**

      index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
      | table _time, User, Image, TargetObject, Details, ProcessGuid

## 4. Technical Comparison: Why Sysmon?

I built this comparison to demonstrate the ROI of enhanced telemetry in a modern SOC environment.

| Feature             | Windows Event ID 4688        | Sysmon Event ID 1             |
| ------------------- | ---------------------------- | ----------------------------- |
| Command Line        | Often Truncated/Incomplete   | Full & Enriched             |
| Parent Process      | PID only (volatile/reusable) | ProcessGuid (Unique/Static) |
| File Hashes         | ❌ Not available              | MD5, SHA256, IMPHASH        |
| Registry Monitoring | ❌ Complex to configure       | Native (EID 12, 13, 14)     |

## Summary

By integrating Sysmon into Splunk, we transform the SIEM from a simple log aggregator into a Forensic Powerhouse. The fields shown in this section are the "connective tissue" that allows an analyst to prove Intent and Persistence with absolute certainty.
