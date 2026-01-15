# Multi-Source Event Correlation Analysis

**The "Attack Path" Reconstruction**

In this investigation, I moved beyond single-alert monitoring to perform Temporal and Behavioral Correlation. By linking disparate events across Sysmon and Windows Security logs, I reconstructed the full lifecycle of the persistence attempt.

## 1. The Persistence Chain (The "Story")

By correlating three distinct Event Codes, I identified the following sequence of activity:

| Phase            | Event            | Event ID  | Technical Context                                  |
| ---------------- | ---------------- | --------- | -------------------------------------------------- |
| I. Modification  | Registry Set     | Sysmon 13 | HKCU\\...\\Run\\FakeUpdater was created.           |
| II. Installation | Service Creation | Sysmon 12 | New service FakeService registered to same binary. |
| III. Activation  | Process Launch   | Sysmon 1  | notepad.exe executed automatically on trigger.     |

The Correlation Key: I utilized the ProcessGuid provided by Sysmon to verify that the same parent process initiated both the registry and service modifications.

## 2. The Correlation Engine (The "Logic")

I developed the following Splunk query to automatically link these events in a single view. This reduces the investigation time from minutes to seconds.

**Splunk SPL:**

      (index=sysmon EventCode=1 OR EventCode=12 OR EventCode=13)
      | stats values(TargetObject) as registry_service, values(Image) as process_path, values(CommandLine) as cmd by       ProcessGuid
      | where mvcount(process_path) > 0 AND (mvcount(registry_service) > 0)

This query filters for "Execution + Modification" pairs. It isolates instances where a process didn't just run, but also changed the system's persistent state.

## 3. Findings: Simulation vs. Noise

During the correlation process, a "Data Volume Analysis" was performed to distinguish the simulated attack from background operations.

**High-Volume (Benign):** I observed thousands of Registry modifications from msedge.exe. Correlation showed these were linked to Microsoft-signed update binaries—ruling out a threat.

**Low-Volume (Simulated):** The FakeUpdater chain appeared as a singleton event (one-time execution). In a production environment, singleton events in sensitive keys are a primary indicator of compromise (IoC).

## 4. Privilege Escalation Check

**Verification:** I cross-referenced the LogonID and User fields across the chain.

**Result:** While the service was created under the SYSTEM context, no unauthorized privilege escalation (e.g., from a standard user to a Domain Admin) was detected beyond the scope of the simulation.
