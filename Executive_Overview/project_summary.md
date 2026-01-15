# 🛡️ Executive Summary: Endpoint Detection & Visibility Engineering

## 1. Objective

This project establishes a high-fidelity Security Operations Center (SOC) pipeline designed to detect and validate post-exploitation persistence mechanisms. By leveraging Sysmon and Splunk, I engineered a workflow that bridges the gap between raw telemetry ingestion and actionable, context-aware incident response.

## 2. The Problem: The "Persistence Noise" Gap

Modern enterprise environments are plagued by "Alert Fatigue." Windows services and update agents (like Microsoft Edge) frequently utilize registry keys (T1547.001) in a manner that mimics malware behavior. Without advanced filtering and analyst validation, these events create a "Noise floor" that hides actual threats.

## 3. The Solution: A Validated Detection Pipeline

This investigation successfully ingested and analyzed 293,826 events from a Windows 10 endpoint, focusing on the transition from Credential Stress to Persistence.

**Key Technical Achievements:**

**Visibility Engineering:** Enabled Advanced Audit Policies to eliminate the "Silent Failure" of Scheduled Task logging (EID 4698).

**Telemetry Enrichment:** Deployed a custom Sysmon configuration to capture ProcessGuids and Hashes, providing the forensic data required for 100% accurate correlation.

**Contextual Triage:** Developed a validation framework that distinguishes between a SYSTEM process (High Risk) and a Local Interactive process (Benign User Activity).

## 4. Tactical Results

| Metric                    | Result                                                   |
| ------------------------- | -------------------------------------------------------- |
| Log Fidelity              | 100% Ingestion of Sysmon + WinEventLog                   |
| True Positive Detection   | Simulated Brute-Force & Registry Injection               |
| False Positive Mitigation | Successfully suppressed 15% of "Noise" from Edge updates |
| Framework Mapping         | 100% Coverage of MITRE ATT&CK Persistence & Execution    |

## 5. Why This Project Demonstrates ROI

In a production environment, this pipeline represents Operational Efficiency. By automating the detection of encoded PowerShell and registry anomalies, and providing analysts with a structured "Validation Logic," we reduce Mean Time to Respond (MTTR) and ensure the SOC remains focused on high-confidence threats.

**Contextual Triage:** Developed a validation framework that distinguishes between a SYSTEM process (High Risk) and a Local Interactive process (Benign User Activity).
