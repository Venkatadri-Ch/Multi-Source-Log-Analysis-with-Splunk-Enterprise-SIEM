### Introduction

DNS (Domain Name System) logs are essential for understanding what’s happening on a network and spotting potential security issues. Using Splunk SIEM, these logs can be analyzed effectively to detect unusual behavior or signs of malicious activity. In this project, we focus on collecting, analyzing, and visualizing DNS logs to gain actionable insights and improve network security monitoring.

### Prerequisites


Before analyzing DNS logs in Splunk, ensure the following:

- Splunk instance is installed and configured.

- DNS log data.

### Steps to Upload Sample DNS Log File to Splunk SIEM

  ### 1. Preparing Sample DNS Log Files

I started by downloading a sample [DNS log file](https://www.secrepo.com/maccdc2012/dns.log.gz) from [SecRepo](https://www.secrepo.com/)


 ### 2. Uploading Log Files to Splunk

 - Log in to the Splunk web interface.
 - Navigate to Settings > Add Data.
   <img width="934" height="411" alt="Settings+Add data 1" src="https://github.com/user-attachments/assets/ea7a1649-abf7-4971-97f6-eae8b744e943" />

 - Then Select Upload as the data input method as shown in below
   <img width="839" height="404" alt="Upload 2" src="https://github.com/user-attachments/assets/e7a0ad2c-b93f-4f13-bfd2-444872a19475" />

 - Select the downloaded file or drag and drop it, and then click Next. At this step, specify the source type. I have entered dnslogs as the name and provided the description "This is DNS log data."
   <img width="904" height="382" alt="save Source type 3" src="https://github.com/user-attachments/assets/9f3f5a65-05e1-442d-9956-9f72a869d7e7" />

   


