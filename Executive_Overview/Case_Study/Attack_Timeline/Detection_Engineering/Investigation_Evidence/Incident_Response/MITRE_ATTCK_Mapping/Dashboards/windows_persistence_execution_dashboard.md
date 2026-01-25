# soc_performance_dashboard.json

**Goal:** To provide SOC analysts and Management with a real-time "Health Check" of the authentication environment, enabling immediate identification of brute-force spikes.

**Core Logic & Components**
This dashboard is built on two high-fidelity SPL queries designed for speed and clarity:

### Total Failed Logons (KPI):

**Splunk SPL**
     
      index=windows EventCode=4625 | stats count as total_failed_logons

Provides a "Single Pane of Glass" view of the current attack surface volume.

### Authentication Failure Trend (Temporal Analysis):

**Splunk SPL**
     
      index=windows EventCode=4625 | timechart span=1h count as failed_logons

Visualizes patterns of brute-force activity over time, allowing for a clear distinction between random "fat-finger" typos and automated, persistent attacks.

**Technical Evidence**


<img width="980" height="616" alt="image11" src="https://github.com/user-attachments/assets/9cf4c29a-1489-4c67-b42e-c4e0622d538e" />


<i><b>"The Executive Summary Dashboard"</b>: A high-fidelity visualization capturing a total of 166 failed logon events. The trend chart clearly identifies the critical brute-force spike occurring in early November, providing the necessary temporal context for the subsequent investigation.</i> </p>


