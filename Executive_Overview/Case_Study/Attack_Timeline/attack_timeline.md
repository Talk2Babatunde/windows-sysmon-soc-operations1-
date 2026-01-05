# Attack Timeline

| Time Range | Event | Evidence | Interpretation |
|------------|--------|----------|----------------|
| Lab Start (2025-12-11 to 2026-01-02) | Registry Run Key Modified | Sysmon Event ID 13, TargetObject=HKCU/HKLM\Run\Fake*, Details=C:\Windows\System32\notepad.exe | Simulated persistence; user Babat (HKCU), SYSTEM (HKLM). Legitimate baseline: Edge/OneDrive RunOnce. [file:1] |
| Post-Command | Service Created | EventCode 12, TargetObject=*FakeService*, STATE=STOPPED | T1543.003; survives reboot. |
| Logon/Reboot | Execution | Repeated notepad.exe launches | Persistence validated; no C2/lateral. |

Single host (DESKTOP-66L7IHQ); no escalation beyond simulation. [file:1]


| Validation Phase | Persistence Reviewed | Registry + Service Analysis | Benign activity confirmed |
