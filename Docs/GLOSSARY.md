# Glossary of SOC Investigation Terms

## Local Interactive User: 

**A security context indicating that a user is logged into the machine directly (via keyboard/mouse) or via a remote desktop session. In your investigation, seeing the user Babat confirms the activity is tied to a known, authenticated human session rather than an automated system process.
**
## Persistence: **A technique used by both legitimate software and attackers to ensure a program or script restarts automatically after a system reboot. Common persistence locations include "Run" registry keys.
**
## Binary Path Validation: **The process of verifying that an executable is located in its official, trusted directory. Finding msedge.exe in C:\Program Files (x86)\... is a key indicator that the file is a legitimate system binary and not a malicious masquerader.
**
## User Context Analysis: **Evaluating which account (e.g., SYSTEM vs. a Local User) initiated a change. Identifying a local user context helps analysts rule out Privilege Escalation, as the activity is confined to that specific user's permissions.
**
## **Benign Verdict: A final analyst decision that the observed activity—while technically a persistence mechanism—is legitimate, expected, and poses no threat to the environment.**
