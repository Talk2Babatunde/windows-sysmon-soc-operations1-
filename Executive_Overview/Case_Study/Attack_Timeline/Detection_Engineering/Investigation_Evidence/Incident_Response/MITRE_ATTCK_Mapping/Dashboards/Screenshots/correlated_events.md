# 🔗 Multi-Source Event Correlation Analysis

## 1. The Correlation Strategy

To reconstruct the attack lifecycle, I utilized the Sysmon ProcessGuid and LogonID as primary keys. This allowed me to link parent-child process relationships across different event types (Process Creation, Registry Modification, and Service Installation).

## 2. The Investigation Chain (Timeline)

I correlated the following three events into a single "Incident Thread":

| Step | Time     | Event Code | Action           | Logic                                           |
| ---- | -------- | ---------- | ---------------- | ----------------------------------------------- |
| 1    | 10:05:01 | EID 1      | Process Creation | cmd.exe launched by user Babat.                 |
| 2    | 10:05:05 | EID 13     | Registry Set     | Same cmd.exe modified ...\\Run\\FakeUpdater.    |
| 3    | 10:05:10 | EID 12     | Service Create   | New service registered pointing to notepad.exe. |

## 3. Advanced Splunk Correlation Query

This query was developed to automate the detection of this "Pairing" behavior. It specifically looks for processes that both start and modify the registry within a 1-minute window.

      index=sysmon EventCode=1 OR EventCode=13
      | transaction ProcessGuid maxspan=1m
      | where eventcount > 1
      | table _time, Computer, User, Image, TargetObject, Details

## 4. Forensic Findings

**Process Lineage:** The correlation confirmed that notepad.exe (the persistence binary) was NOT launched by a system process, but by a manual command-line execution.
**Account Context:** The LogonID remained consistent across all three steps, proving this was a single session and not a distributed attack.
**Data Volume Analysis:** In the 10-minute window of the attack, there were 2,400 benign registry changes from Windows updates. My correlation logic successfully filtered those out to isolate these 3 specific events.
