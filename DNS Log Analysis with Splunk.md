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

#### 3. Choose File and Set Source Type

 - Select the downloaded file or drag and drop it, and then click Next. At this step, specify the source type. I have entered dnslogs as the name and provided the description "This is DNS log data."
   
   <img width="904" height="382" alt="save Source type 3" src="https://github.com/user-attachments/assets/9f3f5a65-05e1-442d-9956-9f72a869d7e7" />

### 4. Review Settings and click upload 

 - Then we will see the input settings. Keep everything as default and click Review and submit. Once the upload process is complete, click Start Searching to begin  our search.
   
  <img width="926" height="400" alt="file uploaded 4" src="https://github.com/user-attachments/assets/62f74621-e44a-445d-9bf0-b602f8ac89a3" />

### 5. Verify Upload

- After uploading, I was navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded DNS events are visible.

  ```spl
  index=* sourcetype="dnslogs"
  
<img width="950" height="427" alt="logs identified 5" src="https://github.com/user-attachments/assets/1c880533-0845-43ea-93dd-8bf540e1f449" />

### Extracting New Fields

Extracting new fields in Splunk helps turn raw log data into useful, searchable information. It lets us:

- Search more accurately by targeting specific details in your logs.
- Build clearer reports and dashboards for better insights.
- Connect related events across different data sources.

In this case, we’ll extract new fields from the DNS log data to easily analyze query types, source IPs, and domain names.

 ### Steps to Extract New Fields

# 1. Run a Search

- Go to Search & Reporting app.
- Run a search that returns the events containing the data you want to extract fields from.
 
 # 2. Open the Fields Sidebar

- On the left side of the search page, expand the Fields sidebar if it’s not already open.

# 3. Click “Extract New Fields”

- In the Fields section, click Extract New Fields.
- This opens the Field Extractor (FX) tool.

 # 4. Select an Event

- identify an event that contains the fields you want to extract and click next.

  <img width="913" height="404" alt="select any event 6" src="https://github.com/user-attachments/assets/d4a18440-3a16-436b-9919-b6c17073fabc" />

 # 5. Choose an Extraction Method

Splunk gives you two options:

 - Regular expression — for custom, pattern-based extraction.
 - Delimited — for data with consistent separators (e.g., commas, pipes, tabs).
   I choose the regular expression.

  <img width="936" height="419" alt="select regular expression 7" src="https://github.com/user-attachments/assets/9d0b8209-c8cb-4304-a281-6ce6c8a43f6d" />

 # 6. Define the Fields 

 - Assign a name to each required value by double-clicking on the value and add extraction and click on next.

  <img width="941" height="389" alt="give name for each field 8" src="https://github.com/user-attachments/assets/0869853e-37df-4813-bdaf-d787fde5375e" />

 # 7. Validate and save 

 - Then validate and save the extraction, and click on "Explore the fields I just created in Search". You will then be able to see the extracted fields.

   <img width="943" height="421" alt="fields extracted sucessfully 9" src="https://github.com/user-attachments/assets/abc3f840-4718-4377-abca-31067352aa92" />


  - The extracted fields have also been identified.

    <img width="939" height="428" alt="extracted fields identified 10" src="https://github.com/user-attachments/assets/65d4bc12-f78b-46f7-aa67-61bc1c44c4c2" />

# Analyzing DNS Log files

### 1. Identify Anomalies
```
index=_* OR index=* sourcetype=dnslogs  | stats count by domain
```
This search groups DNS queries by domain to spot unusual activity. By checking domains with very high counts or strange names, you can uncover anomalies like misconfigurations, DNS tunneling, or malware communication. It’s a quick way to detect spikes and suspicious DNS behavior in your network.

<img width="935" height="407" alt="stats by count 11" src="https://github.com/user-attachments/assets/31b5df02-29b2-4be2-89a3-2b084a51b5c7" />

### 2. Most quired Domain's

```
index=* sourcetype=dnslogs | top limit=10 domain
```
This search finds the top 10 domains that appear most often in your DNS logs. It’s a quick way to see where most of the traffic is going and to spot anything unusual or suspicious that might need a closer look.

<img width="920" height="412" alt="top limit 12" src="https://github.com/user-attachments/assets/8ec11ba9-5ec9-4103-9ac7-5732d0b131e2" />

### 3. Investigate Suspicious Domains
```
index=* sourcetype=dns_sample domain="maliciousdomain.com"
```
This search looks for any DNS activity related to maliciousdomain.com. It helps you check if any systems in your network have tried to reach that domain, which could indicate a possible security issue or compromise.

<img width="931" height="431" alt="particular domain 13" src="https://github.com/user-attachments/assets/ce481634-7d6f-4c6e-a3e8-f17fdd6a221d" />

### 4. Analyze DNS Traffic Flow
```
index=* sourcetype=dns_sample | table src_ip,src_port,dst_ip,dst_port
```
This search lists the source and destination IP addresses and ports from DNS logs. It helps you see where the traffic is coming from and where it’s going, making it easier to trace connections and identify any unusual communication patterns.

<img width="923" height="401" alt="table 14" src="https://github.com/user-attachments/assets/a25d662d-fa8a-4e08-8eb1-a48489c75d1a" />

## Conclusion

By working through these steps, we can see how powerful Splunk is for analyzing DNS logs. Uploading logs, extracting useful fields, and running searches allows us to identify unusual activity, spot suspicious domains, and understand how DNS traffic flows across the network. These insights make it easier to detect potential security issues, investigate anomalies, and improve overall network security monitoring




    

   


 


  
