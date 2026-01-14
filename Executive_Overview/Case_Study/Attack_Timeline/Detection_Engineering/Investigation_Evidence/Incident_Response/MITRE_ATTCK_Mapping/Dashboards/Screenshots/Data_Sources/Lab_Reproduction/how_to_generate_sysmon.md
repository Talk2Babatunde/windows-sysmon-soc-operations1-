# Lab Reproduction & Telemetry Generation Guide

This guide outlines the exact steps to reproduce the telemetry used in this investigation. This ensures a repeatable and consistent testing environment for detection validation.

## 1. Endpoint Instrumentation (Sysmon)

To enhance native Windows logging, Sysmon must be installed with a high-fidelity configuration (e.g., SwiftOnSecurity).

Command: 

      ```bash sysmon.exe -accepteula -i sysmonconfig.xml

**Validation:** Run sc query sysmon64 to ensure the service is active.

## 2. Credential Stress Simulation (T1110)

To generate Event ID 4625 (Failed Logon), use the following command. Repeat multiple times to trigger brute-force detection logic.

Command:

Bash

      runas /user:fakeuser cmd

Expected Result: Splunk should index a series of failed logons followed by a success if a valid credential is provided.

## 3.Persistence Simulation (T1547.001 & T1053.005)

We simulated persistence using two common vectors: Registry Run Keys and Scheduled Tasks.

### A. Registry Run Key (User Level)
Command:

Bash

      reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v FakeUpdater /t REG_SZ /d                                   "C:\Windows\System32\notepad.exe" /f

### B. Scheduled Task Creation
Command:

Bash

      schtasks /create /sc minute /mo 5 /tn "UpdaterTask" /tr "cmd.exe /c whoami" /f

## 4.Post-Simulation Cleanup

To return the endpoint to a baseline state and prevent persistent execution of test binaries:

Remove Registry Key:       
      
      reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v FakeUpdater /f

Delete Scheduled Task:       
      
      schtasks /delete /tn "UpdaterTask" /f
