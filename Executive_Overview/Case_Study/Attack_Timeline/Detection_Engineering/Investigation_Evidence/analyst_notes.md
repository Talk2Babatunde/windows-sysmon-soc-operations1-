# Analyst Notes

- Verified Sysmon config: RegistryEvent on TargetObject=*Run*, *Services*. 265 mods across 23 keys—mostly benign (Edge updates). [file:1]
- Anomalies: FakeUpdater (HKCU, Babat), SystemUpdater (HKLM, SYSTEM), FakeService—simulated, notepad.exe path legitimate.
- No unsigned bins, LOLBins (rundll32), or AppData paths. Single user/host; timing matches lab.
- Baseline: RunOnce=Windows Updates; distinguished via path/signature. [file:1]

## Analyst Notes

- Persistence locations detected: Registry Run keys and Services
- All binaries observed were Microsoft-signed and executed from trusted paths
- No persistence entries referenced user-writable or temporary directories
- Activity timing aligned with normal system and application behavior
- No indicators of attacker-controlled persistence observed


### Validation Decision Rationale

Although the registry locations observed are commonly abused by malware, all entries referenced trusted Microsoft-signed binaries executed from known system directories. Activity occurred under a single user and host with no indicators of follow-on actions.

Based on this evidence, escalation was not justified.
