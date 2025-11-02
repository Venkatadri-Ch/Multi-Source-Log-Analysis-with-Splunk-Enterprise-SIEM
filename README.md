# Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM
This project uses Splunk Enterprise to analyze logs from different sources like DNS, HTTP, SSH, FTP, SMTP, Tunnel dataset's. The main goal was to find patterns, detect unusual activity, and visualize useful security insights.

# Projects

1-<a href="https://github.com/Venkatadri-Ch/Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM/blob/main/DNS%20Log%20Analysis%20using%20Splunk.md">
DNS Log Analysis Using Splunk
</a>: This analysis walks through how to examine DNS (Domain Name System) log files using Splunk SIEM. It explains how to upload sample logs, extract key fields, study DNS query patterns, detect unusual behavior, and monitor overall DNS traffic.

2-<a href="https://github.com/Venkatadri-Ch/Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM/blob/main/HTTP%20Log%20Analysis%20using%20Splunk.md">
HTTP Log Analysis Using Splunk
</a>: This analysis shows how to explore HTTP (Hypertext Transfer Protocol) logs in Splunk SIEM. It includes examining status codes, destination ports, traffic patterns, errors, and login activity to detect unusual behavior. By reviewing these patterns, I was able to identify potential issues and understand how the web server is performing. 

3-<a href="https://github.com/Venkatadri-Ch/Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM/blob/main/SSH%20Log%20Analysis%20using%20Splunk.md">
SSH Log Analysis Using Splunk
</a>: This analysis shows how to explore SSH (Secure Shell) log files using Splunk SIEM. It includes identifying suspicious activities such as multiple failed login attempts, which may indicate unauthorized access attempts. It also highlights repeated connections without successful authentication, suggesting potential network scanning. By monitoring these patterns, this analysis helps maintain system security and detect potential threats early.

4-<a href="https://github.com/Venkatadri-Ch/Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM/blob/main/FTP%20Log%20Analysis%20using%20Splunk.md">
FTP Log Analysis Using Splunk
</a>: This analysis shows how to explore FTP (File Transfer Protocol) log files using Splunk SIEM. It includes tracking login attempts, file transfers, and user activity to understand how the server is being used. Failed login attempts, especially from anonymous users, may indicate unauthorized access attempts or configuration issues, while successful logins and file transfers reveal active users. This analysis helps track file activity, identify the most active users, and detect unusual or suspicious behavior that requires further investigation.

5-<a href="https://github.com/Venkatadri-Ch/Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM/blob/main/Analysis%20of%20SMTP%20logs%20using%20splunk.md">
Analysis of SMTP Logs Using Splunk
</a>: This analysis shows how to explore SMTP (Simple Mail Transfer Protocol) log files using Splunk SIEM. It includes examining overall email activity, identifying top senders, and observing destination trends. While most events are legitimate, unusual spikes or high-volume activity may indicate scanning or automated behavior. Monitoring errors, such as authentication failures and invalid recipients, helps detect misconfigured clients or potential unauthorized attempts. This analysis provides insights to identify abnormal email activity and strengthen email security.

6-<a href="https://github.com/Venkatadri-Ch/Multi-Source-Log-Analysis-with-Splunk-Enterprise-SIEM/blob/main/Analysis%20of%20Tunnel%20Logs%20using%20splunk.md">
Analysis of Tunnel Logs Using Splunk
</a>: This analysis shows how to explore Teredo tunnel activity using Zeek IDS logs in Splunk SIEM. It includes examining tunnel lifetimes, connection patterns, and source-destination activity. Most tunnels were short-lived, properly started and closed, and distributed across multiple hosts. Monitoring the data over time revealed occasional spikes, which were flagged as unusual but not harmful, helping identify the most active hosts and endpoints.


