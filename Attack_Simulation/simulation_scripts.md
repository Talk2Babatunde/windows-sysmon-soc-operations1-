# 🛠️ Custom Attack Simulation Scripts

To validate my detection logic, I developed custom scripts to execute the following techniques. These scripts utilize "Living off the Land" (LotL) binaries to minimize the chance of signature-based detection.

### **Technique: T1547.001 (Registry Run Keys)**
**Script:**
`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "FakeUpdater" /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f`

**Objective:** To verify if Splunk captures the `Registry Value Set` 
event (Sysmon EID 13) when a non-standard binary is added to the Run 
key.
## Safety Notice
All simulations are benign and executed solely for defensive security research.


This folder contains **controlled, non-malicious attack simulations** used to generate realistic Windows telemetry for SOC detection and investigation.
