# Analyzing FTP Log Files Using Splunk SIEM

### Introduction

FTP (File Transfer Protocol) logs record all the file transfer activity that happens across a network. When analyzed with Splunk, these logs can reveal a lot, from who’s transferring files to unusual patterns that might signal a security issue. This project shows how to use Splunk SIEM to analyze FTP log data, making it easier to monitor activity, spot anomalies, and strengthen overall network security.

## Prerequisites
- Splunk is installed and configured.
- [FTP log dataset](https://www.secrepo.com/maccdc2012/ftp.log.gz)
  
Note: The steps to upload the sample FTP log dataset to Splunk are the same as those used for the previous DNS log analysis.
I have given the source type name as ftplogs and the description as This is ftp log dataset.

<img width="917" height="429" alt="source type 1" src="https://github.com/user-attachments/assets/217dd609-b9a9-47e4-9838-4c897330e123" />

# Analyzing FTP Logs with Splunk

### 1. Search for FTP Events

```
index="log_analysis" sourcetype="ftplogs"
```
- This query retrieves all the HTTP events from the specified index and source type.

<img width="926" height="439" alt="total raw data 2" src="https://github.com/user-attachments/assets/c3dc62cb-a940-42a0-a6fa-f4171228eacb" />

- I identified a total of 5,796 FTP events and I didn’t find any interesting fields, so we’ll need to extract them manually.

<img width="927" height="433" alt="no fields 3" src="https://github.com/user-attachments/assets/e0914a50-2734-4e7f-838b-43d9fd4e77bf" />

### 2. Extracted Fields

- Using the same field extraction steps as in the previous DNS log analysis, I extracted the following fields: src_port, dst_port, src_ip, dst_ip, user, password,            reply_code, reply_message, timestamp, and uid.

<img width="928" height="400" alt="extracted new fields 4" src="https://github.com/user-attachments/assets/fe236b77-c7cc-4fae-8346-b03110207f2f" />

### 3. FTP Login and Transfer Event Summary by IP and User
```
index=log_analysis sourcetype=ftplogs
| stats count by src_ip, user, reply_code, reply_msg
```
Groups the events by these fields:

- src_ip — the IP address of the FTP client connecting to the server.
- user — the username used for FTP login.
- reply_code — the FTP server’s numeric response code (like 220, 230, 530).
- reply_msg — the message text from the FTP server corresponding to the reply code.

Counts how many times each combination of these fields occurs.

<img width="941" height="434" alt="Summarize failed logins 5" src="https://github.com/user-attachments/assets/268125aa-a063-4fa4-94df-60b0d5a1e0dc" />

From this analysis, we can:

- Identify which IP addresses are connecting to the FTP server and the usernames they use.
- Determine the success or failure of login attempts by looking at reply codes like 230 (successful login) and 530 (login failed).
- Track file transfer activity by noting reply codes such as 226 (transfer complete).
- Detect repeated failed login attempts or disabled accounts that may indicate suspicious activity.
- Understand FTP server behavior through messages like “Entering Passive Mode” which shows connection details.

### 4. Failed Login Attempts by IP
```
index=* sourcetype=ftplogs reply_code=530
| stats count by src_ip, user, reply_msg
| sort -count
```
- This search helps us find failed FTP login attempts by looking for events with the 530 reply code. It shows which IP addresses and users are repeatedly failing to log in, along with the server’s response messages. By sorting the results by count, we can quickly see the most frequent failures, which makes it easier to spot suspicious activity.

<img width="935" height="410" alt="Show failed login attempts by IP 6" src="https://github.com/user-attachments/assets/adbe17f3-5bdb-4f91-b982-1bf3e19262ca" />

- I analyzed failed FTP login attempts and found that the IP address 192.168.202.102 using the username anonymous had repeated failures. There were 10 attempts with the      server response “Not logged in, user account has been disabled” and 9 attempts with “Login or password incorrect.” This shows that this IP repeatedly tried to access the   server unsuccessfully, which could indicate suspicious activity or a possible brute-force attack.

### 5. Successful Login Followed by Data Transfer
```
index=* sourcetype=ftplogs 
| search reply_code IN (230,226)
| stats count by src_ip, user
```
- This SPL identifies successful FTP activity by selecting events with reply codes 230 (login successful) and 226 (file transfer completed). 
- It groups the results by source IP and username to show which clients logged in and performed transfers, along with how many times each occurred.

  <img width="938" height="410" alt="Successful logins followed by data transfer 7" src="https://github.com/user-attachments/assets/c7ced307-7bcb-4807-a48f-256463d3e499" />

- I analyzed successful FTP activity and found that multiple clients logged in and performed file transfers. The IP 192.168.202.102 using anonymous logged in 5 times,        while 192.168.202.94 logged in 86 times. Other users with the username ftp had fewer logins and transfers, such as 1–2 events per IP. This shows which clients are          actively using the FTP server and how frequently they perform successful logins and data transfers.

Note: If you want to count only logins filter only for reply_code=230, If you want to count only transfers filter only for reply_code=226:

- If you want separate counts in the same table:
```
index=log_analysis sourcetype=ftplogs reply_code IN (230,226)
| stats count(eval(reply_code=230)) AS logins count(eval(reply_code=226)) AS transfers by src_ip, user
```
### 6. FTP Reply Code Frequency Over Time
```
index=log_analysis sourcetype=ftplogs
| timechart count by reply_code
```
- This SPL searches all FTP log events and creates a time-based chart (timechart) that counts how many times each FTP reply code appears.

<img width="931" height="390" alt="visualizing login activity 8" src="https://github.com/user-attachments/assets/6938ee5c-c647-4f64-8568-6978492d4ee7" />

- This search counts different FTP reply codes within a very short time window—just one second. It shows many passive mode connections (227), several completed transfers     (226), some successful logins (230), and a few login failures (530), providing a quick snapshot of FTP activity during that exact second.

### 7. Time-Based Analysis of FTP File Transfers
```
index=log_analysis sourcetype=ftplogs reply_code=226 OR command IN ("STOR", "RETR", "APPE")
| timechart span=1h count AS file_transfer_count
```
- This SPL helps track FTP file transfer activity by looking for events with reply code 226 (transfer completed) or commands STOR, RETR, and APPE (upload, download, or       append). It then groups these events into hourly intervals and counts how many transfers occurred in each hour. This provides a clear view of file transfer frequency       over time, helping monitor usage patterns and detect unusual spikes in activity.

<img width="923" height="419" alt="Frequency of file transfers 9" src="https://github.com/user-attachments/assets/b416ab7e-8721-4dc3-9af2-b0defbd9a921" />

- I analyzed FTP file transfer activity and found that at 07:30 on 29th October 2025, there were 157 FTP file transfers recorded. This shows a high level of activity         during that hour, with multiple files being uploaded, downloaded, or appended. Tracking such peaks helps monitor server usage and can highlight unusual or heavy activity   periods.




