# Correlation_persistence_execution.spl

**Goal:** This show correlation (Linking two different behaviors). This query looks for an account that failed to log in multiple times, then succeeded, and then immediately modified a registry run key. 

**Splunk SPL**

      (index=windows EventCode=4625) OR (index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*")
      | transaction User maxspan=1h
      | where eventcount > 1 AND count(eval(EventCode=4625)) > 0 AND count(eval(EventCode=13)) > 0
      | table _time, User, eventcount, TargetObject, Details


<img width="988" height="363" alt="image22" src="https://github.com/user-attachments/assets/41b12aa0-7c98-4b7c-8621-af2d6cdea574" />


**Why this is important, because:**

It allows me to use transaction to group events by User.

It helps me filters for a specific pattern: Brute Force (4625) followed by Persistence (13).

It shows me how to understand the Attack Lifecycle, not just isolated events.
