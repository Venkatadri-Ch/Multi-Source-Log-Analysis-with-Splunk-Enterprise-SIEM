# Analyzing SSH Logs Using Splunk SIEM

### Introduction 

SSH (Secure Shell) log files hold important details about who’s accessing your servers remotely  including login attempts, commands run, and session activity. By analyzing these logs in Splunk SIEM, security teams can keep a close eye on access to critical systems, quickly spot unusual behavior, and identify potential security threats before they become serious issues.

### Objective 

The goal of this project is to analyze SSH authentication logs to detect:

- Successful logins (who connected, from where)
- Failed login attempts (possible brute-force or password spraying)
- Multiple failed authentication attempts (indicators of brute-force)
- Connections without authentication (potential scanning or incomplete sessions)

### Prerequisites

- Splunk is installed and configured.
- [SSH log dataset](https://drive.google.com/drive/folders/1BL-kVlc3yCRcAH8NnDmAyRm_3j_2mNLM?usp=sharing)

Note: The steps to upload the sample SSH log to Splunk are the same as those used for the previous DNS log analysis. However, I created a separate index for this one named “loganalysis.”

### Total events after uploading the SSH dataset into Splunk
<img width="932" height="419" alt="tptal Events 1" src="https://github.com/user-attachments/assets/0615168e-894c-43f1-90c1-21f299a1daa0" />


# Analyzing SSH Logs with Splunk

### 1. SSH Event Types
```
index=ssh_log | stats count by event_type
```
This is used to count how many times each type of SSH event happens.

For example, it can show how many successful logins, failed logins, or connection attempts occurred.

<img width="929" height="403" alt="event type 2" src="https://github.com/user-attachments/assets/33f09e3a-e1df-41c1-a794-f9b0c30d9b3d" />

Event types such as connections without authentication, failed SSH logins, and multiple failed authentication attempts were detected.

### 2. Analyzing Failed Login Attempts
```
index=loganalysis event_type="Failed SSH Login"
| stats count by id.orig_h
```
Note: id.orig_h (source IP),
      id.resp_h (destination host)

- Look in the ssh_logs for all failed SSH login attempts.
- Count how many times each source IP (id.orig_h) tried and failed to log in.

<img width="931" height="401" alt="failed ssh logins 3" src="https://github.com/user-attachments/assets/4d91271c-dadd-45e9-94ef-ce44ba9a05ad" />

- In this analysis, the IP address 10.0.0.30 had 22 failed SSH login attempts.

<img width="936" height="410" alt="bar graph 4" src="https://github.com/user-attachments/assets/61d35ce9-ee52-443f-bdbc-aef46091ed16" />

This chart shows the count of failed SSH login attempts from each source IP, helping to identify potential unauthorized access or attacks.

### 3.Detecting Multiple Failed Authentication Attempts (Brute Force) 

  ```
index=loganalysis event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h, id.resp_h
```
- This Search the ssh_logs for events labeled "Multiple Failed Authentication Attempts."

- Count how many times these failed attempts happened, grouped by both:

- id.orig_h → the source IP (where the login attempts came from)

- id.resp_h → the destination IP (the server they tried to access)

This helps identify which source IPs are repeatedly failing to log in to which servers, making it easier to spot targeted attacks or suspicious activity between specific machines.

<img width="934" height="392" alt="multiple failed attempts 5" src="https://github.com/user-attachments/assets/40ec5871-3ab4-466a-a318-281bb7a455ee" />

- The IP 10.0.0.28 tried and failed to authenticate 5 times on the server at 10.0.1.1.

- Several other IPs (like 10.0.0.11, 10.0.0.21, etc.) have made 3 failed login attempts each on different destination IPs.

### 4. Track Successful Logins

  ```
  index=loganalysis event_type="Successful SSH Login"
  | stats count by id.orig_h, id.resp_h
  ```
- It shows how many times each source IP successfully logged into each destination server.

<img width="938" height="407" alt="sucessfull login 6" src="https://github.com/user-attachments/assets/1851b1b2-ff6b-4697-afc4-761ede62fdc8" />

- This output helps identify which users or devices (source IPs) are successfully accessing which servers and how frequently.

 ### 5. Detecting Suspicious Connections Without Authentication

 ```
index=loganalysis event_type="Connection Without Authentication"
| stats count by id.orig_h
```
- It shows which IP addresses are making connections to the server without trying to authenticate, which could be suspicious or indicate scanning or probing activity.

<img width="929" height="409" alt="connection without authentication 7" src="https://github.com/user-attachments/assets/8ac233c1-dc65-4538-a5ed-5379d79106ae" />

From the analysis of “Connection Without Authentication” events:
- The IP addresses 10.0.0.14 and 10.0.0.18 each attempted to connect to the server 13 times without authenticating.
- The IP addresses 10.0.0.27, 10.0.0.44, and 10.0.0.53 each made 10 such attempts.

#### Created a timechart visualization to monitor such events over time:
```
index=loganalysis event_type="Connection Without Authentication"
| timechart count by id.orig_h
```
It creates a time-based chart showing which IPs are repeatedly connecting without authenticating and when these attempts occur, making it easier to spot patterns or spikes in suspicious activity.

<img width="937" height="256" alt="timechart 8" src="https://github.com/user-attachments/assets/273fa5c4-9aa8-4316-9220-9faa1f6085ab" />

 At 2025-04-24 15:50:09, IPs 10.0.0.14 and 10.0.0.18 had 13 connections without authentication; 10.0.0.27, 10.0.0.44, and 10.0.0.53 had 10 each; others ranged from 8 to 9; the rest totaled 186 attempts.

 ## Conclusion 

Analyzing SSH log files using Splunk SIEM, I found several suspicious activities. Some IPs, like 10.0.0.30, had multiple failed login  attempts, indicating possible unauthorized access attempts. Additionally, IPs like 10.0.0.14 and 10.0.0.18 connected repeatedly without authentication, suggesting potential network scanning. These IPs should be closely monitored to maintain system security.










