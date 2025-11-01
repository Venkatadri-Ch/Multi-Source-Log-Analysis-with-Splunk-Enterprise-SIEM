# Analyzing  SMTP Logs Using Splunk

### Introduction

SMTP (Simple Mail Transfer Protocol) logs record key details of email communication, including sender and recipient addresses, timestamps, and subjects. Using Splunk SIEM to analyze these logs helps us to monitor email activity, detect anomalies, and identify threats such as phishing or spam, thereby improving overall email security.

### Prerequisites

- Splunk is installed and configured.
- [SMTP log dataset](https://www.secrepo.com/maccdc2012/smtp.log.gz)

  Note: The steps to upload the sample SMTP log dataset to Splunk are the same as those used for the previous DNS log analysis. I have given the source type name as "smtp".

  ## Analyzing SMTP Logs with Splunk

  ### 1. Search for SMTP Events

  ```
  index="log_analysis" sourcetype="smtp"
  ```
  <img width="929" height="443" alt="total events 1" src="https://github.com/user-attachments/assets/6121ceb4-2b45-45af-93a3-01cc8f850164" />

  I identified a total of 194 SMTP events and I didn’t find any interesting fields, so extracted them manually.

  ### 2. Extracted Fields

   - Using the same field extraction steps as in the previous DNS log analysis, I extracted the following fields: src_port, dst_port, src_ip, dst_ip, client_hostname,            reply_code, reply_text, recipient_ips, ts.
 
  
- timestamp-The exact date and time when the SMTP transaction occurred.	
- src_ip-IP address of the system that initiated the SMTP connection (sending mail server).	
- dst_ip-IP address of the destination mail server receiving the SMTP connection.	
- src_port-Network port on the sender’s host used to initiate the SMTP connection.	
- dst_port-Network port on the destination host (port 25 for SMTP).	
- client_hostname-The hostname of the SMTP client that connected to the mail server.	
- reply_code-Numeric SMTP response code returned by the server (e.g., 250, 550).	
- reply_text-The descriptive text accompanying the reply code.
- recipient_ips-IP addresses of recipient mail servers or target hosts.

 <img width="926" height="433" alt="extracted 2" src="https://github.com/user-attachments/assets/1c98577a-3281-4ea0-9fa2-35b45c2d38d3" />

 ### 3. Analyzing top senders 

```
index=* OR index=* sourcetype=smtp
| eval sender_ip=src_ip, sender_hostname=client_hostname
| top limit=10 sender_ip sender_hostname
```
- index=* OR index=* sourcetype=smtp - Retrieves all SMTP log events from all indexes.

- | eval sender_ip=src_ip, sender_hostname=client_hostname - Creates readable fields for sender IP and hostname.

- | top limit=10 sender_ip sender_hostname - Lists the top 10 most frequent senders with counts and percentages, helping identify active or suspicious sources.

  <img width="934" height="422" alt="Analyze Top Senders (SMTP Clients) 3" src="https://github.com/user-attachments/assets/c3fb4c62-e642-405f-8492-1ce482e3949c" />

 - Most SMTP activity comes from 192.168.202.110, contributing 91% of the traffic, while 192.168.202.138 accounts for only 9%. Both share the hostname “nessus”, likely         indicating the same system or network host. This helps identify the most active senders and monitor for unusual or automated email activity.

   ### 4. Identifying top destination servers
   ```
   index=log_analysis sourcetype=smtp
    | top limit=10 dst_ip
   ```

   The query searches the log_analysis index for events with sourcetype=smtp.It then uses the top command to list the top 10 destination IP addresses (dst_ip) by event         count.
   The results table shows the IP addresses, the number of events for each, and their percentage of the total.

   <img width="928" height="424" alt="Identify Top Recipient Servers (SMTP Destinations) 4" src="https://github.com/user-attachments/assets/8049be24-de6b-4103-918a-f3f74cc5e162" />

 The destination IP 192.168.27.107 received the most SMTP traffic, accounting for about 12% of all events, followed by 192.168.229.251 and 192.168.27.101. Several other IPs  also saw notable activity, showing which servers are the main recipients of email in the network. This helps in spotting busy servers, unusual patterns, and prioritizing    security monitoring for the most frequently contacted hosts.

 ### 5. Top SMTP Source-Destination Pairs

 ```
index=log_analysis sourcetype=smtp
| stats count by src_ip dst_ip
| sort - count
| head 10
```
- stats count by src_ip dst_ip
Counts how many times each unique combination of source IP (src_ip) and destination IP (dst_ip) appears in the SMTP logs.

- | sort - count
Sorts the results in descending order based on the count.

- | head 10
Limits the output to only the top 10 pairs.

<img width="920" height="424" alt="You can also display both sender and recipient IPs 5" src="https://github.com/user-attachments/assets/452df05a-730f-4936-87ba-73e69d6d711e" />

The results show that the source IP 192.168.207.110 is the most active sender, communicating with multiple destination IPs. The highest traffic was sent to 192.168.27.182 with 27 emails, while other destinations like 192.168.239.251, 192.168.27.202, and 192.168.27.203 received between 10–15 emails each. This highlights which destination servers are the primary recipients of emails from this source.

### 6. Analyzing response codes
```
index=log_analysis sourcetype=smtp
| stats count by reply_code, reply_text
| sort - count
| head 10
```
- | stats count by reply_code, reply_text
Counts how many times each SMTP reply code and its accompanying reply text appear in the logs.
Shows which responses (like 250 OK, 550 User unknown) are most common.

- | sort - count
  Sorts the results in descending order by count, so the most frequent reply codes appear first.

- | head 10
  Displays only the top 10 reply codes, highlighting the most common SMTP responses.

  <img width="924" height="433" alt="Analyze Response Codes 6" src="https://github.com/user-attachments/assets/e79858cd-b012-4816-b3a9-aaeb3711b097" />

- Most SMTP activity appears normal, with 221 “Bye” and 250 responses indicating successful sessions. However, repeated 500 and 530 errors suggest misconfigured clients or   unauthorized command attempts, while occasional 550 errors point to emails sent to invalid users, possibly spam or phishing. Monitoring these reply codes helps detect      suspicious activity and strengthen email security.

### 7. Daily Email Activity by Sender Hostname
```
index=* OR index= sourcetype=smtp
| eval sender_hostname=client_hostname
| timechart span=1d count by sender_hostname
```
- | eval sender_hostname=client_hostname
Creates a new field called sender_hostname by copying the client_hostname field.
Makes it easier to track and visualize email activity by hostname.

- | timechart span=1d count by sender_hostname
Creates a time-based chart showing the number of emails sent per day, grouped by sender hostname.
Helps identify daily trends, spikes, or unusual activity for specific hosts.

<img width="925" height="394" alt="replace 7" src="https://github.com/user-attachments/assets/0d031b0f-919d-4ad5-81bb-fd76e37962eb" />

- The table shows the number of SMTP events sent by each sender hostname over two days:
- On 2023-10-28, the most active senders were example.com (44 events) and example.org (35 events), followed by 192.168.202.110 (10 events).
- On 2023-10-29, there was a spike from 168.22.102 (35 events) and 8 events with no hostname. Other senders had lower activity.
- Some hostnames, like mail.nessus.org and nessus, had little or no activity, while nmap.scanner.org appeared only once, possibly indicating scanning or automated activity.
- Spikes in email activity from unknown or unexpected hostnames could indicate suspicious behavior.

### 8. Failed Authentication Attempts

```
index=_* OR index=* sourcetype=smtp
| eval user=client_hostname
| search reply_code="503" AND reply_text="*authentication*"
| stats count by user
| sort - count
```
- | eval user=client_hostname
Creates a new field user based on client_hostname to simplify reporting.

- | search reply_code="503" AND reply_text="*authentication*"
Filters events to only include SMTP responses with code 503 and text containing “authentication”.
These indicate attempts to send emails without proper authentication.

- | stats count by user
Counts the number of authentication failures per user (hostname).

- | sort - count
Sorts the results in descending order, showing users with the most authentication failures first.

<img width="927" height="308" alt="To count failed authentication attempts per source" src="https://github.com/user-attachments/assets/32dabe4b-e836-440a-8d71-7f900095b573" />

This show's that example.com experienced 9 SMTP authentication failures. This indicates repeated attempts to send emails without proper authentication, which could point to misconfigured clients or potential unauthorized access attempts. Monitoring such activity helps detect and prevent email abuse, etc..

### 9. SMTP Error Analysis by User for Security Monitoring
```
index=* OR index=* sourcetype=smtp
| eval user=client_hostname
| search reply_code IN ("502","503","550")
| stats count by user reply_code reply_text
| sort - count
```
- | eval user=client_hostname
Creates a new field user based on client_hostname for easier reporting.

- | search reply_code IN ("502","503","550")
Filters the events to only include SMTP responses with reply codes 502, 503, or 550.
These codes indicate errors such as command issues (502), authentication problems (503), or recipient rejections (550).

- | stats count by user reply_code reply_text
Aggregates the data by user, reply code, and reply text, showing how many times each error occurred per user.

- | sort - count
Sorts the results in descending order, so the users with the most SMTP errors appear at the top.

<img width="927" height="390" alt="see all failed SMTP responses 9" src="https://github.com/user-attachments/assets/1a12f3f2-31b1-491b-97ca-0ae1df1b426e" />

I analyzed that example.com showed multiple 550 authentication failures and attempts to send to invalid recipients, while example.org had repeated 503 command errors. These indicate misconfigured clients or potential unauthorized email activity.

### 10. Email Activity Count by User/Host
```
index=* OR index=* sourcetype=smtp
| eval user=client_hostname
| stats count by user
```
- | eval user=client_hostname
  Creates a new field user based on client_hostname for easier reporting.
  This allows tracking email activity by host or user.

- | stats count by user
  Counts the total number of SMTP events per user/host.
  Provides a simple overview of which hosts or users are sending the most emails.

<img width="922" height="424" alt="Monitor user behavior related to email communication 10" src="https://github.com/user-attachments/assets/326cb32c-954a-424c-ada8-c1ecf79f49e7" />

I analyzed that example.com (44) and example.org (35) were the most active senders. nmap.scanme.org (39) indicates potential scanning activity rather than normal email traffic. Moderate activity came from nessus and email.nessus.org, while a few internal IPs sent low-volume emails. Unidentified hostnames (8 events) may point to misconfigured or unknown sources. 

### 11. Detecting high volume senders
```
index=* sourcetype=smtp
| eval client=src_ip
| timechart span=1h count by client
```
- | eval client=src_ip
  Creates a new field called client using the src_ip (source IP address).
  Makes it easier to track email activity by source IP.

- | timechart span=1h count by client
  Generates a time-based chart showing the number of emails sent per hour for each client IP.
  Helps visualize trends, spikes, or unusual activity over time.

<img width="933" height="394" alt="Detect high-volume senders 11" src="https://github.com/user-attachments/assets/b0a474c4-44e4-4057-a823-26820a50f656" />

I analyzed that At 10:30 AM, 192.168.202.136 sent 111 emails, showing a major spike in activity. Other IPs like 192.168.202.120 and 192.168.202.108 had minimal activity, while most recorded none. This spike could indicate normal high-volume sending or suspicious behavior, such as automated scripts or mass mailing.

# Conclusion

The analysis of SMTP logs using Splunk revealed overall email activity patterns, top senders, and destination trends. Most events appeared legitimate, coming from expected hosts like example.com and example.org, while some spikes and unusual sources, such as nmap.scanme.org or high-volume IPs, indicate potential scanning or automated activity. SMTP errors, including authentication failures (503/550) and invalid recipients, highlight misconfigured clients or possible unauthorized attempts. Monitoring reply codes, sender behavior, and hourly trends helps identify abnormal activity and strengthens email security. Overall, this analysis provides valuable insights for detecting suspicious email behavior and preventing potential threats.



  


 
 

  
    
  
