# Scheduled_task_persistence.spl

**Objective**: Demonstrate the transition from basic event monitoring to advanced, high-fidelity detection engineering.

**Phase 1:** Basic Telemetry Capture

Initially, I utilized a standard search to verify the ingestion of Event ID 4688 and 4698. While this confirmed data was flowing, the results were cluttered with automated system activity.

**Splunk SPL**

      index=windows EventCode=4698 
      | rename TaskName as "Scheduled_Task_Name"
      | table _time, Scheduled_Task_Name, Author, Command, User, ComputerName


**Phase 2:** High-Fidelity Engineering 

To reduce alert fatigue for Tier 1 analysts, I developed a more sophisticated query. This version uses xmlkv to parse nested XML data on-the-fly and filters out NT AUTHORITY\SYSTEM to isolate human-initiated persistence.      

      index=windows EventCode=4698
      | xmlkv Message 
      | table _time, host, TaskName, Command, Author
      | search NOT (Author="NT AUTHORITY\SYSTEM")



<img width="980" height="616" alt="image4" src="https://github.com/user-attachments/assets/4d037719-6c78-47dd-9906-272815a9e578" />

<i><b>Figure:</b> Evidence of successful noise reduction. The final query successfully filtered out background system tasks (Author: Microsoft Corporation), allowing the <b>'cmd.exe'</b> task created by user <b>'Babat'</b> to surface immediately as a high-priority lead.</i> </p>


**My final take:** This detection relies on Event ID 4698. Crucially, I identified that this telemetry is not enabled by default in Windows. I updated the 'Advanced Audit Policy' for 'Object Access' to ensure visibility into T1053.005."
