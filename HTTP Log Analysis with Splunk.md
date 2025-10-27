# Analyzing HTTP Logs Using Splunk SIEM

### Introduction

HTTP (Hypertext Transfer Protocol) logs provide important insights into web server activity, capturing details such as requests, responses, user agents, and other relevant information. By analyzing these logs using Splunk SIEM, security professionals can effectively monitor web traffic, detect unusual patterns, and identify potential security threats.

### Project Overview

In this project, we will upload sample HTTP logs into Splunk SIEM and analyze them to gain insights into web server activity across the network. The analysis will help us understand traffic patterns, identify anomalies, and explore potential security concerns.

### Prerequisites

Before starting the project, ensure the following:

- Splunk is installed and configured.
- HTTP log dataset.

Note: The steps to upload the sample HTTP log to Splunk are the same as those used for the previous DNS log analysis.

I have given the source type name as httplogs and the description as This is HTTP log data.

<img width="931" height="413" alt="httplogs source type 1" src="https://github.com/user-attachments/assets/33f6abe7-0ce7-40f8-8879-15c5c0b2211c" />

# Analyzing HTTP Logs with Splunk

### 1. Search for HTTP Events

Open the Splunk interface and go to the Search bar.
To view the HTTP events, run the following search query:
```
index=_* or index=* sourcetype=httplogs
```
This query retrieves all the HTTP events from the specified index and source type.

<img width="943" height="421" alt="full http events 3" src="https://github.com/user-attachments/assets/fcb0ca31-c09f-479b-85d5-dc81932fbb6d" />

### 2. Extracted Fields

Using the same field extraction steps as in the previous DNS log analysis, I extracted the src_port, dst_port, and status (I mean HTTP status codes) fields.

<img width="946" height="407" alt="extracted(dp,sp,status) 4" src="https://github.com/user-attachments/assets/6d3f4860-a582-453a-b4f0-ada0c2c8f319" />













