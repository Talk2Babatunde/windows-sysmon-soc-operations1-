# Windows Persistence Playbook

**Triage**:
1. Query EventCode 13 TargetObject=*Run*.
2. Validate path/user/timing.
3. Benign? Baseline. Anomalous? Escalate.

**Verdict Template**: "Registry Run key modified; aligns with simulation. MITRE T1547.001. Low risk." [file:1]

## Windows Persistence Investigation Playbook

1. Detect persistence-related events (Registry, Services)
2. Identify affected user and host
3. Validate binary path and signature
4. Assess business justification
5. Determine escalation necessity
6. Document findings and close or escalate

This workflow mirrors real-world SOC operations.
