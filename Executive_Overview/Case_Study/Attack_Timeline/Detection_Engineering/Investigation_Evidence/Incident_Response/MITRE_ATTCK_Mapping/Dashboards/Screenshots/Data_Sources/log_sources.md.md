# 📊 Telemetry Coverage & Data Integrity

## The "Data Reality Check"

In a production SOC, detection is only as good as the underlying telemetry. Before writing detection logic, I performed a Telemetry Coverage Validation to ensure no visibility gaps existed across the endpoint's security-critical event logs.

## 1. Primary Log Sources

| Source Type      | Visibility Provided           | Critical Event IDs                           |
| ---------------- | ----------------------------- | -------------------------------------------- |
| Windows Security | Authentication & Audit Policy | 4624 (Success), 4625 (Failure), 4698 (Tasks) |
| Sysmon           | Deep Endpoint Forensics       | 1 (Process), 12/13/14 (Registry), 11 (File)  |
| PowerShell       | Script Execution              | 4104 (Script Block Logging)                  |

## 2. Ingestion Validation (The "Heartbeat" Search)

I ran the following SPL to confirm that all three critical data streams were actively reporting and that the event volume matched the expected baseline for an active workstation.

SPL Query:

      index=windows OR index=sysmon 
      | stats count by sourcetype, host 
      | rename count as "Event Count", sourcetype as "Log Source"
      | sort - "Event Count"


Telemetry Health Check: Verifying multi-source ingestion across Sysmon and Windows Event Logs to ensure zero visibility gaps.

**Analyst Observation:** * Confirmed 293,826+ total events ingested.

**WinEventLog:** Security (8,260+ baseline events) provides the authoritative authentication trail.

**XmlWinEventLog:** Microsoft-Windows-Sysmon/Operational provides the high-fidelity process and registry telemetry required for T1547.001 mapping.

## 3. Telemetry Enrichment Strategy

To go beyond standard logging, I implemented a SOC-grade Sysmon configuration (SwiftOnSecurity). This enables Registry Monitoring for specific high-value keys:

      RegistryEvent = *CurrentVersion\Run*

      RegistryEvent = *CurrentVersion\RunOnce*

      RegistryEvent = *System\CurrentControlSet\Services*

## 4. Verification of Service Health

Manual verification was performed on the endpoint to ensure the data pipeline was healthy at the source:

**Command:** sc query sysmon64 (Status: RUNNING)

**Policy Check:** auditpol /get /category:"Object Access" (Status: Success enabled for Scheduled Tasks)
