# powershell_encoded_execution.spl

Goal: Show off Regex (rex) and Data Parsing skills.

Splunk SPL

      index=sysmon EventCode=1 (CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")
      | rex field=CommandLine "(?<encoded_blob>[A-Za-z0-9+/=]{20,})"
      | eval blob_length = len(encoded_blob)
      | where blob_length > 20
      | table _time, User, Computer, CommandLine, blob_length
      | sort - blob_length

My final take: "Standard command-line logging often truncates long strings. This query uses Regex to extract the Base64 blob specifically, allowing the SOC to prioritize alerts based on the size and complexity of the encoded payload (T1027)."
