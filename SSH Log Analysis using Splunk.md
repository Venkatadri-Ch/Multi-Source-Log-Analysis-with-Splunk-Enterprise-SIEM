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


