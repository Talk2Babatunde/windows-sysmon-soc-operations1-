# Windows Endpoint SOC Investigation – Registry Persistence Validation

## Objective

The objective of this investigation was to detect potential persistence mechanisms on a Windows endpoint and validate whether the observed activity represented malicious behavior or legitimate system operations.
The focus was on commonly abused persistence techniques while maintaining accuracy and avoiding false positives.

## Data Sources

### Sysmon Event Logs
Used for high-fidelity endpoint telemetry, including process execution and registry modifications.

### Windows Security Event Logs
Used to monitor authentication activity, privilege escalation, and scheduled task creation.

## Methodology
### Step 1: Privilege Escalation Validation

Queries were executed against Windows Security Event ID 4672 to identify assignments of special privileges.
This step ensured that elevated permissions were not being abused by unauthorized users.

### Outcome:
Only expected SYSTEM-level activity was observed. No evidence of privilege escalation abuse or anomalous user elevation was detected.

Step 2: PowerShell Activity Analysis

PowerShell activity was analyzed using PowerShell Script Block Logging (Event ID 4104) and Sysmon process execution events.

Outcome:
No encoded commands, suspicious script content, or attacker-controlled PowerShell activity was identified. Observed executions aligned with normal administrative or system behavior.

Step 3: Persistence Mechanism Detection

Persistence techniques were evaluated across multiple vectors commonly abused by attackers:

Registry Run / RunOnce keys

Windows Services

Scheduled Tasks (Event ID 4698)

Correlation queries were used to link persistence events with execution activity to determine whether persistence resulted in malicious follow-on actions.

Outcome:
No unauthorized services or scheduled tasks were created. Registry persistence activity was limited to known, legitimate applications.

## Findings

Privilege Escalation:
SYSTEM privileges were present only where expected. No misuse by standard user accounts was detected.

PowerShell Activity:
No malicious or suspicious PowerShell execution was identified during the investigation period.

Registry Persistence:
A registry Run key entry was observed corresponding to Microsoft Edge auto-launch behavior.
The binary was:

A known Windows application

Digitally signed

Located in an expected file path

This behavior aligns with legitimate Windows and application startup activity, despite occurring in a persistence location commonly abused by attackers.

## Conclusion

Persistence-related activity was detected in high-risk autorun registry locations, but thorough validation confirmed the behavior was legitimate Windows application activity.
No indicators of compromise, lateral movement, or post-compromise execution were identified.

This investigation demonstrates the importance of analyst-led validation, emphasizing accurate decision-making rather than alert-driven assumptions.

## Timeline

A time-ordered correlation of authentication, persistence, and execution events was created to validate activity flow and confirm the absence of malicious progression.

(Timeline table included separately in repository for reference.)
