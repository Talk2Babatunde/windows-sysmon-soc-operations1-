# Encoded PowerShell Execution (T1027)

**Objective**

To detect and analyze obfuscated PowerShell commands. Attackers frequently use the -enc flag to hide malicious payloads in Base64, bypassing simple string-based security alerts. This detection focuses on identifying these "Living-off-the-Land" (LotL) techniques.

## Phase 1: Broad Detection & Obfuscation Identification

The first step is identifying any PowerShell instance using encoding flags. This query provides a broad view of suspicious command-line activity.

SPL Query:

Splunk SPL
      index=sysmon EventCode=1 (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
      | table _time, host, User, Image, CommandLine
      | rename CommandLine AS "Obfuscated_Command"

<img width="980" height="616" alt="image5" src="https://github.com/user-attachments/assets/64651438-f790-43bb-a39c-36a92963ca1e" />

<i><b>Figure 1:</b> Sysmon Event ID 1 capturing multiple instances of encoded PowerShell execution. The "Obfuscated_Command" column highlights the Base64 blobs used to hide the actual script intent.</i> </p>

## Phase 2: Advanced Extraction & Payload Profiling

Standard logging often truncates long strings, making manual decoding difficult. I engineered this advanced query to use Regular Expressions (Regex) to extract the Base64 blob specifically. This allows the SOC to prioritize alerts based on the size and complexity of the payload.

**Splunk SPL**

      index=sysmon EventCode=1 (CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")
      | rex field=CommandLine "(?<encoded_blob>[A-Za-z0-9+/=]{20,})"
      | eval blob_length = len(encoded_blob)
      | where blob_length > 20
      | table _time, User, host, CommandLine, blob_length
      | sort - blob_length


Analyst Value:

**Data Parsing:** Uses rex to isolate the payload from the rest of the command string.

**Risk Scoring:** By calculating blob_length, we can immediately identify large, complex scripts (high risk) versus short, one-liner commands (potentially lower risk).

## Final Take

This two-phased approach ensures that the SOC isn't just looking for "powershell.exe," but is actively hunting for obfuscated tradecraft. By isolating the encoded blob, we significantly reduce the time required for a Tier 2 analyst to perform manual de-obfuscation and reverse engineering of the attack.

