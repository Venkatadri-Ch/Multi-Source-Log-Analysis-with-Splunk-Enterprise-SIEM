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

  In this analysis, the IP address 10.0.0.30 had 22 failed SSH login attempts.

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






