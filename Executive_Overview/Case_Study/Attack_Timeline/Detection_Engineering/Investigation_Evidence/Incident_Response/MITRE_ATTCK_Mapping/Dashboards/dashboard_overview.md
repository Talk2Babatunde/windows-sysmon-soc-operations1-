# 📊 SOC Visibility Dashboard: Persistence & Obfuscation

**Dashboard Design Philosophy**

This dashboard was engineered to provide a "Single Pane of Glass" for incident responders. Rather than pivoting between multiple search heads, this view correlates telemetry from WinEventLog:Security and Sysmon to visualize the attack lifecycle in real-time.

## 1. Executive KPI Panel (The "Health" Check)

Before investigating threats, an analyst must verify data integrity.

**Query:** 

Splunk SPL

      index=windows OR index=sysmon 
      | stats count as total_events, earliest(_time) as first_event, latest(_time) as last_event
      | eval "Data Window" = strftime(first_event, "%Y-%m-%d") . " to " . strftime(last_event, "%Y-%m-%d")
      | table total_events, "Data Window"

## 2. Threat Detection: Obfuscated PowerShell (T1027)

This panel tracks attempts to bypass static signature-based detection through Base64 encoding.

**Query:**

Splunk SPL

      index=sysmon EventCode=1 (CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")
      | timechart count by User

Visual: Stacked Area Chart.
**Analyst Value:** Identifies spikes in automated script execution that deviate from the user's daily baseline.

## 3. Persistence Monitoring (T1547.001 & T1543.003)

A high-fidelity table that captures unauthorized modifications to sensitive registry hives and service creation events.

**Query:**

Splunk SPL

      index=sysmon (EventCode=12 OR EventCode=13) 
      | eval action=if(EventCode=12, "Service Created", "Registry Modified")
      | table _time, User, Computer, action, TargetObject, Details, ProcessGuid
      | sort - _time

Visual: Statistics Table with Conditional Formatting (Red text for HKLM changes).

**4. Behavioral Correlation (Brute Force → Persistence)**

This identifies the pattern of an account being compromised before a persistence mechanism is installed.

**Query:**

Splunk SPL

      (index=windows EventCode=4625) OR (index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*")
      | transaction User maxspan=1h
      | where eventcount > 1 AND count(eval(EventCode=4625)) > 0 AND count(eval(EventCode=13)) > 0
      | table _time, User, eventcount, TargetObject

Visual: Marker Map or Bar Chart showing "High Risk Users."

## 5. Data Model Mapping (CIM Compliance)

To ensure this dashboard scales to an enterprise environment, all fields are mapped to the Splunk Common Information Model (CIM).

| Dashboard Panel  | CIM Data Model     | Source Type           |
| ---------------- | ------------------ | --------------------- |
| Logon Activity   | Authentication     | WinEventLog:Security  |
| Process Tracking | Endpoint.Processes | XmlWinEventLog:Sysmon |
| Registry Changes | Endpoint.Registry  | XmlWinEventLog:Sysmon |

**View the full dashaboard below:**
https://1drv.ms/b/c/b3322d5b87e2e949/IQDUCInUJB0QQawr_191EDbZAdapLm9blTWr-JfqM5ZjyZE?e=xacpcI





