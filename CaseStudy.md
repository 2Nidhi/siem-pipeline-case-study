**Case Study**
**End-to-End SIEM Pipeline: Detecting and Responding to Attacks Using Splunk and ELK Stack**

**Abstract**  
A **Security Information and Event Management (SIEM) system** is a critical cornerstone for bolstering digital resilience and achieving **unified security** in modern enterprises. This project details the design, implementation, and comparison of an **End-to-End SIEM Pipeline** using the proprietary **Splunk Enterprise Security** and the open-source **ELK Stack (Elasticsearch, Logstash, Kibana)**. The goal was to establish a scalable log analysis platform capable of overcoming challenges related to **large volumes of logs** and the **difficulty in correlating events across diverse systems**.

A hands-on lab environment was established to simulate real-world cyberattacks, including **Nmap scans, brute-force attempts, SQL injections, and Metasploit exploitation**, replicating an SOC analyst workflow. The methodology focused on architecting a complete log flow, covering collection (via **Splunk Forwarders/Beats**), processing (via **Logstash**), indexing (via **Elasticsearch/Splunk Indexer**), and visualization (via **Kibana/Splunk Dashboards**).

Custom detection logic, utilizing **Search Processing Language (SPL)** and specialized filtering, successfully identified all simulated threats, providing **real-time event monitoring**. Comparative analysis reveals that **Splunk Enterprise Security** has a higher Analyst Rating (**93**) and excels in **UEBA** and user-friendly dashboards, while the **ELK Stack** (Analyst Rating **82**) is praised by users (90% 'excellent' sentiment) for its **scalability** and **cost-effectiveness** due to its open-source core. The project concludes that both platforms enable proactive defense, with future enhancements recommending **SOAR integration** for automated response.

**1\. Introduction**

**1.1 Context and Background**  
A SIEM system aggregates and analyzes event data from various sources to identify security threats. SIEM platforms have become indispensable, pulling in log data from across environments, surfacing threats, and helping teams respond quickly. This capability is critical because IT environments generate **extensive logfiles** that record the minutiae of daily operations, and without a centralized solution, this volume of data quickly becomes unwieldy.  
**Splunk Enterprise Security** is a robust SIEM solution, tailored for large enterprises, and praised for features like real-time event monitoring, threat intelligence integration, and comprehensive security capabilities. Splunk uses a proprietary search language called **Search Processing Language (SPL)** for traversing and executing contextual queries against large data sets.  
The **ELK Stack** (Elasticsearch, Logstash, Kibana) is a consolidated log analysis and visualization platform. **Elasticsearch** is the distributed search/analytics engine used for indexing, **Logstash** is the data processing pipeline, and **Kibana** is the data visualization interface. More recently, **Beats** was added to the stack as a lightweight method to collect data from various sources.

**1.2 Problem Statement**  
Effective cybersecurity is challenged by the lack of **real-time detection of attacks**. Organizations struggle due to:  
• **Large Volumes of Logs:** Logs are generated from diverse sources (servers, firewalls, applications), making the data difficult to manage.  
• **Correlation Difficulty:** It is challenging to correlate events across systems to identify multi-stage attack campaigns.  
• **Delayed Visibility:** Security compromise often progresses until damage occurs because of a lack of visibility into suspicious activity.  
The project addresses the need for a scalable pipeline that can efficiently normalize logs and rapidly detect common attack patterns, strengthening the overall security posture.



**2\. Methodology and Technical Implementation**

**2.1 SIEM Pipeline Architecture (Conceptual Flow)**  
The end-to-end SIEM pipeline requires event data to move through a structured workflow. This architecture is designed to replicate a **real-world SOC analyst workflow**.

| Stage | Function | Splunk Component | ELK Stack Component |
| :---- | :---- | :---- | :---- |
| **Log Generation** | Creating security events (e.g., failed logins, scans). | Victim/Target Machine. | Linux VMs (Kali, Ubuntu) for attacker/server. |
| **Collection** | Shipping logs from endpoints to the processing stage. | **Splunk Forwarder**. | **Beats** (e.g., Filebeat for logs). |
| **Processing** | Filtering, transforming, and enriching (e.g., with threat intelligence). | **props.conf/transforms.conf** | **Logstash** (the data processing pipeline). |
| **Indexing** | Storing and organizing processed data for fast retrieval. | **Splunk Indexes**. | **Elasticsearch** (the distributed search engine). |
| **Visualization** | Providing graphical views for analysis. | **Splunk Dashboards**. | **Kibana Dashboards**. |
| **Detection** | Applying correlation rules to trigger alerts. | **SPL Queries**. | **ELK Queries/Rules** (e.g., via ElastAlert). |

**2.2 Lab Setup and Simulated Attacks**  
The project used a virtualized lab setup. The **ELK Stack** was hosted on an **Ubuntu Server VM**, and an **attacker VM (Kali Linux)** was used for running offensive tools like **Nmap, Metasploit, and John the Ripper**. **Filebeat** was installed on the target machine to forward logs to **Logstash**.  
The project configured custom alerts to detect simulated attacks, which included:  
1\. **Nmap scans** and **excessive port access attempts.**  
2\. **Brute-Force Attacks** (John the Ripper) and **Repeated Failed Logins**.  
3\. **SQL injection attempts**.  
4\. **Metasploit Exploitation** (reverse shell attempts and privilege escalation).



**3\. Technical Implementation and Code Examples**

**3.1 Splunk Detection Queries (Search Processing Language—SPL)**  
Splunk searches are crucial for proactive defense and detecting suspicious behavior.

**A. Brute Force Login Detection (Use Case 2\)**  
This query searches secure logs (`sourcetype=secure*`) for failed authentication events and aggregates them by user and source IP:

*index=\* sourcetype=secure\**   
*| search "failed password" OR "authentication failure"*   
*| rex "(?\<user\>\[\\w.-\]+)"*   
*| rex "(?\<src\_ip\> (\[3, 11, 26, 38-43\]{1,3}\\.){3}\[3, 11, 26, 38-43\]{1,3})"*   
*| stats count as failed\_attempts by user, src\_ip*   
*| where failed\_attempts \> 5*

• **Detection Logic:** Filters for users or IPs that show **more than five failed login attempts**, which indicates a possible brute force attack.  
• **Response:** Block the attacking IP address or enable MFA for targeted accounts.

**B. Port Scanning Detection (Use Case 3\)**

This query identifies source IPs that attempt to access multiple, different ports, indicating reconnaissance activity:

*index=\* sourcetype=secure-2*   
*| search "Failed password"*   
*| rex "from (?\<src\_ip\>\\d+\\.\\d+\\.\\d+\\.\\d+) port (?\<dest\_port\>\\d+)"*   
*| stats count by src\_ip, dest\_port*   
*| stats count as port\_attempts by src\_ip*   
*| where port\_attempts \> 5*   
*| sort \- port\_attempts*

• **Detection Logic:** Filters for source IPs that have attempted more than five different port accesses, then sorts by attempt count.  
• **Response:** Immediate action includes blocking the identified IP addresses and implementing IDS/IPS.

**3.2 ELK Implementation Example: Logstash and Data Processing**

Logstash is responsible for collecting, transforming, and enriching data before indexing.

**A. Logstash Configuration (Beats Input/Elasticsearch Output)**   
A basic `logstash.conf` file defines input from Beats on port 5044 and outputs to Elasticsearch, indexing to `threat intelligence:`

*input {*   
    *beats { port: 5044 }*   
*}*   
*output {*   
    *elasticsearch {*   
        *hosts \=\> \["localhost:9200"\]*   
        *index \=\> "threat-intelligence"*   
    *}*   
*}*  
\# Logstash is started via: sudo service logstash start \[41, 42\]

**B. Threat Intelligence Data Processing Logic (Python Example)**   
This Python snippet demonstrates the logic used to transform raw threat intelligence data, analogous to processing and enrichment filters within Logstash:

*\# Example 1: Threat Intelligence Data Processing*

*\# Define sample raw threat intelligence data*  
*threat\_intelligence\_data \= \[*   
    *{ "id": "TID-123", "type": "IP", "data": "192.168.1.1" },*   
    *{ "id": "TID-456", "type": "DOMAIN", "data": "example.com" }*   
*\]* 

*\# Function to process and transform the data*  
*def process\_threat\_intelligence(data):*   
    *\# Transform the data structure*  
    *transformed\_data \= {}*   
    *transformed\_data\["log\_message"\] \= data\["data"\]*   
    *transformed\_data\["threat\_id"\] \= data\["id"\]*   
    *transformed\_data\["threat\_type"\] \= data\["type"\]*   
    *return transformed\_data* 

*\# Process the data*  
*processed\_threat\_intelligence\_data \= \[\]*   
*for threat\_intelligence in threat\_intelligence\_data:*   
    *processed\_threat\_intelligence \= process\_threat\_intelligence(threat\_intelligence)*   
    *processed\_threat\_intelligence\_data.append(processed\_threat\_intelligence)*  
*\# The resulting processed data is ready for indexing in Elasticsearch \[43\].*



**4\. Results: Real-Life Threat Detection and Advanced Use Cases**

The pipeline demonstrated successful detection of basic threats (brute force, port scan) and was validated against high-level, real-world SIEM use cases.

**4.1 Case Example: Correlating Advanced Persistent Threats (APTs)**

SIEMs detect APTs by correlating long-term, seemingly benign events into a broader threat picture. APT campaigns often unfold over weeks or months.  
• **Threat Scenario:** Detecting slow-moving intruders stealing sensitive intellectual property.  
• **SIEM Action:** The SIEM correlates unusual DNS queries, unauthorized access attempts to databases, and small, repeated outbound data transfers over non-standard ports.  
• **Business Value:** This correlation reveals the multi-stage nature of the APT, enabling the detection of sophisticated threats and providing **enhanced support for retrospective investigations and forensic timelines**.

**4.2 Case Example: Cloud Visibility and Misconfiguration Detection**

Modern SIEMs must integrate with cloud platforms to provide unified visibility into environments like AWS and Azure.  
• **Threat Scenario:** Unauthorized privilege escalation or misconfiguration in AWS.  
• **SIEM Action:** The SIEM ingests **AWS IAM access logs** and **S3 access logs** (e.g., via a Logstash S3 input configuration for CloudTrail logs). It then detects the **creation of a new IAM user with administrator privileges** during non-business hours, followed by access to sensitive S3 buckets.  
• **Business Value:** Enables **centralized monitoring** of cloud assets and identities, facilitating the detection of misconfigurations and unauthorized access.

**4.3 Case Example: Automated Response via SOAR Integration**  
SIEM integration with SOAR (Security Orchestration, Automation, and Response) technology allows automated response workflows. Splunk offers native SOAR capability (rated 100/100 support for automation of security response workflows).  
• **Threat Scenario:** Identifying and containing active ransomware activity (e.g., mass file encryption).  
• **SIEM Action:** The SIEM detects signs of ransomware, such as **mass file encryption attempts** and **registry modifications**. This triggers the SOAR platform.  
• **Response:** The SOAR platform **automatically isolates the affected machine** from the network, sends notifications, and creates a case in the ticketing system.  
• **Business Value:** Provides **minimized response time** and containment of threats, reducing analyst fatigue and human error.

**4.4 Case Example: Monitoring User Behavior (UEBA)**  
Modern SIEMs track user behavior to identify anomalies, often leveraging **UEBA (User and Entity Behavior Analytics)**.  
• **Threat Scenario:** Insider threat or compromised credentials.  
• **SIEM Action:** The SIEM detects a user who typically accesses systems during business hours from a local IP now **accessing a critical finance server at 3 a.m. from a foreign IP**. This deviation triggers a medium-severity alert.  
• **Business Value:** Enables **detection of suspicious user behavior patterns** and provides an early warning for compromised credentials.



**5\. Comparative Analysis and Findings**

The comparison highlights the primary differences between the two leading SIEM platforms.

**5.1 Analyst and User Ratings Comparison**

| Metric | Splunk Enterprise Security | Elastic Security (ELK) | Details/Source |
| :---- | :---- | :---- | :---- |
| **Analyst Rating** | **93** (Highest among comparable tools) | 82 | Based on SelectHub’s 400+ point analysis. |
| **User Sentiment Rating** | 87% ('great') | **90% ('excellent')** | Based on aggregate user reviews. |
| **UEBA Support** | **100/100** (Tier 1: Fully supported out-of-the-box) | 60/100 (Tier 3: Requires custom development/partner integrations) | Splunk leads significantly in native behavioral analytics. |
| **SOAR Support** | 60/100 (Tier 2: Supported with workarounds/add-ons) | **100/100** (Tier 1: Fully supported out-of-the-box) | Elastic fully supports SOAR natively. |
| **Dashboards & Reporting** | **100/100** (Tier 1 Support) | 75/100 (Tier 1 Support 71%) | Splunk dashboards are highly refined and intuitive. |
| **Learning Curve** | Moderate/Steep | Surprisingly Flat/Moderate | ELK is often cited as easier to learn for log processing. |

**5.2 Key Findings Summary**

The sources confirm that both platforms are powerful, enterprise-grade log management and analysis platforms.  
• **Splunk Strengths:** Splunk provides **advanced threat detection** capabilities and comprehensive security capabilities. It has a more user-friendly interface focused on **search-based analytics** and **easy-to-use SPL queries**. Users find it highly effective for real-time monitoring and incident response.

• **Splunk Weaknesses:** The primary barriers are the **high proprietary licensing cost**, the **complex initial setup**, and the **learning curve** required for specialized analyses.

• **ELK Strengths:** The ELK Stack is based on open-source components, offering **superior scalability** for large datasets. It is highly customizable and supports standard **RESTful APIs and JSON** for extensibility. It is known for effective threat detection and behavioral analytics.

• **ELK Weaknesses:** The **complex initial setup** and configuration can be challenging, requiring dedicated expertise. Although the software is free, the **total cost of ownership (TCO) can be substantial** due to hardware and storage requirements for expansive infrastructures.



**6\. Conclusion and Future Work**

**6.1 Conclusion**

The project successfully demonstrated the implementation of a robust, end-to-end SIEM pipeline using both Splunk and the ELK Stack, proving that both architectures can achieve the goal of **unified threat detection, investigation, and response (TDIR)**. All stages of the pipeline—from log collection via **Beats/Forwarders** to alert generation via **Kibana/SPL**—were validated through simulated attacks and applied to real-world threat detection use cases (APTs, cloud misconfiguration).

The choice between platforms depends heavily on organizational strategy:  
• **Splunk** is the leader for organizations prioritizing **out-of-the-box advanced features** (like **UEBA**), **ease of use** (SPL), and strong **enterprise readiness**, despite the high premium cost.  
• **The ELK Stack** (Elastic Security) is the ideal choice for budget-minded organizations requiring **unmatched scalability**, **flexibility**, and a customizable open-source core, provided they invest in the necessary technical expertise for complex configuration and ongoing maintenance.

**6.2 Future Enhancements**

Future iterations of this SIEM project should focus on enhancing **automation** to move beyond detection and into robust incident remediation.  
1\. **SOAR Integration:** Integrate the SIEM with **SOAR** technology (supported natively by Splunk and fully supported by Elastic) to **automatically execute playbooks** in response to high-severity alerts (e.g., blocking an IP detected in a port scan or isolating a host upon ransomware detection).  
2\. **Expanded Endpoint Detection:** Integrate dedicated **Endpoint Detection and Response (EDR) telemetry** to allow the SIEM to correlate endpoint behavior (like suspicious PowerShell processes) with broader network and authentication data, improving alert confidence.  
3\. **Advanced Alerting:** For the ELK Stack, automate detection rules using tools like **ElastAlert**.



**7\. References**  
**• ELK Documentation: [Elastic.co/docs](http://Elastic.co/docs).**  
**• Splunk SIEM Resources: \[[IBM Knowledge Cente](https://www.google.com/url?sa=E&q=https%3A%2F%2Fwww.ibm.com%2Fsupport%2Fknowledgecenter)r\].**  
**• Splunk SPL Examples: \[[GitHub \- root4oz/SIEM-Analysis](http://%20root4oz/SIEM-Analysis)\].**  
**• ELK Lab Implementation: \[[GitHub \- 00112244/SIEM-Implementation-with-ELK-Stack](https://github.com/00112244/SIEM-Implementation-with-ELK-Stack)\].**  
**• Logstash Configuration: \[Codez Up\]**

[image1]: <data:image/png;base64,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>
