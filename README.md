# NIDS-using-Snort
# Infotact Solutions  

## Month-1 Deliverable Report  

---

### 📌 Week 1: Introduction to NIDS and Snort – Installation and Setup  

#### What is NIDS (Network Intrusion Detection System)?  
A **Network Intrusion Detection System (NIDS)** is a cybersecurity tool that monitors network traffic for suspicious activity or known threats and alerts the user/admin.  
- Works passively (does not block traffic, only detects & reports).  

#### What is Snort?  
Snort is an open-source NIDS tool developed by Cisco. It captures and analyzes packets in real-time to detect malicious activity using rules and signatures.  

**Key features of Snort:**  
- Packet sniffing  
- Real-time traffic analysis  
- Protocol analysis  
- Content matching with rule-based detection  

#### ✅ Tasks Performed:  
1. **Linux Installation (Ubuntu/Kali)**  
   - Installed using a virtual machine.  
   - Base OS for installing Snort.  
   - *Screenshot 1: Linux UI after installation.*  

2. **Snort Installation**  
   ```bash
   sudo apt install snort
   snort --version
   ```
### Week 2: Configuring Snort and Monitoring Live Network Traffic
#### Identifying Active Network Interface
```bash
ifconfig
# or
ip a
```

#### Configuring Snort for IP Range

```bash
Edited HOME_NET in /etc/snort/snort.conf:

var HOME_NET 10.0.2.0/24
```

#### Running Snort in Detection Mode
```bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast
```

#### Parameters explained:
```bash
-c /etc/snort/snort.lua → configuration file

-i eth0 → interface to monitor

-A alert_fast → fast alert output
```

#### Monitoring Live Traffic
```bash
ping -c 4 <gateway_ip>
```

Alerts stored in /var/log/snort/alert


### Week 3: Simulating Network Attacks and Analyzing Snort Alerts
#### Purpose of Simulated Attacks

Used in controlled environments to test IDS effectiveness.

Example: ICMP flood attacks for stress testing.

#### Generating Suspicious Traffic (Ping Flood)
```bash
ping -f <target_ip>
```

Sends ICMP packets rapidly (DoS simulation).


#### Capturing & Viewing Snort Alerts

Logs stored at:
```bash
/var/log/snort/alert
```

#### View alerts:
```bash
cat /var/log/snort/alert
```

#### Interpreting Alerts

Each alert contains:

Alert message & priority

Classification (e.g., ICMP flood attack)

Source & destination IPs

Protocol & port numbers


### Week 4: Writing and Testing Custom Snort Rules
#### Understanding Rule Syntax

Format:
```bash
action protocol src_ip src_port -> dst_ip dst_port (options)
```

Example:
```bash
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001;)
```

Explanation:

alert → action

icmp → protocol

any any -> any any → source/destination IP & port

msg → alert message

sid → unique Snort ID

#### Writing a Custom Rule

Added this rule in /etc/snort/rules/local.rules:
```bash
alert icmp any any -> any any (msg:"Custom ICMP Alert"; sid:1000002;)
```

Included it in Snort config:
```bash
include $RULE_PATH/local.rules
```

#### Testing the Custom Rule

Generate ICMP traffic:
```bash
ping <target_ip>
```

#### Run Snort:
```bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast -l /var/log/snort
```

#### Verifying Logs

Check alerts for custom rule message (Custom ICMP Alert):
```bash 
cat /var/log/snort/alert
# or
nano /var/log/snort/alert
```

## Month-2   

### Intermediate Tasks  


---

### Snort Rule Syntax and Custom Rule Writing  

Snort rules consist of two parts: the **header** and the **options**.  

**Header Syntax:**  
```bash
action protocol src_ip src_port -> dst_ip dst_port
```
**Options:** Located in parentheses `()`, options like `msg`, `content`, `sid`, and `rev` define the alert message and identification.  

#### Custom Rules  

Two custom rules were written and added to `/etc/snort/rules/local.rules`. The rule file was then included in the main Snort configuration.  

**Custom Rule 1 – TCP Port Scan Detection**  
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Custom TCP Port Scan Attempt Detected"; flags:S,1; sid:1000001; rev:1;)
Detects TCP SYN scans by looking for packets with only the SYN flag set.
```
Custom Rule 2 – SSH Brute-Force Attempt Detection

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Custom SSH Brute-Force Attempt Detected"; flow:to_server,established; content:"SSH-"; sid:1000002; rev:1;)
```
Detects SSH brute-force attempts by inspecting traffic to port 22 containing the SSH- string.

Configuration step:
Add the local rule file to Snort configuration:

```bash
include '/etc/snort/rules/local.rules'
```
#### Simulated Attacks and Alert Verification
To test the rules, simulated attacks were performed.

TCP Port Scan (Nmap)
```bash
sudo nmap -sS -p 1-100 10.0.2.15
-sS: TCP SYN stealth scan
```
-p 1-100: Scan ports 1 through 100

Target: 10.0.2.15

SSH Brute-Force (Hydra)
```bash
sudo hydra -L /usr/share/wordlists/rockyou.txt --password-file /usr/share/wordlists/rockyou.txt ssh://10.0.2.15
```
-L: Usernames list

--password-file: Passwords list

Target: SSH service on 10.0.2.15

#### Running Snort and Viewing Alerts
```bash
sudo snort -c /etc/snort/snort.lua -i eth0 -A full -l /var/log/snort
cat /var/log/snort/alert.log
```
Verification:

Alerts successfully triggered for both custom rules.

Correct sid values (1000001 and 1000002) appeared in logs.

False Positives:

Legitimate tools triggered the port scan rule.

Highlighted need for rule optimization.

Rule Optimization and Precision Tuning
To reduce false positives, rules were refined.

#### Improved Port Scan Rule
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Custom TCP Port Scan Attempt Detected"; flags:S,1; flow:stateless; threshold:type limit, track by_src, count 10, seconds 60; sid:1000001; rev:2;)
```
Changes made:

Added threshold option to trigger alerts only if multiple packets are detected within 60 seconds.

Reduces noise from single SYN packets.

Suppressing Noisy Alerts
Suppressing specific alerts helps manage benign activity.

Example suppression rule (suppress.conf):

```bash
suppress gen_id 1, sig_id 1000001
```
This prevents Snort from alerting on signature ID 1000001 when known to be benign.



## Month-3  

---

### Multi-Output Alert Logging and Notifications  

#### Configuring Multi-Output Logging  
To improve flexibility, Snort was configured to log alerts in multiple destinations: a detailed log file and the system syslog.  

**Configuration snippet (snort.lua):**  
```lua
-- Output to a full alert file
alert_file = {
    path = '/var/log/snort',
    name = 'alert.log',
    format = 'full'
}
```
-- Output to syslog
syslog = {
    facility = 'LOG_AUTH',
    priority = 'LOG_INFO'
}
This setup ensures persistent forensic logs and real-time syslog alerts for administrators.

#### Setting Up Alert Notifications
A bash script was created to monitor Snort’s alert log and send email notifications in real-time.

#### Installation:

```bash
Copy code
sudo apt install mailutils
```
Notifier script (alert_notifier.sh):

```bash
#!/bin/bash
tail -f /var/log/snort/alert.log | while read line; do
  echo "$line" | mail -s "Snort Alert" your_email@example.com
```
#### Run in background:

```bash
chmod +x alert_notifier.sh
./alert_notifier.sh &
```
Performance Optimization and Resource Monitoring
Rule Tuning for Performance
Disabled unused rules irrelevant to the environment.

Refined custom rules using pcre and content to detect specific patterns instead of broad signatures.

Using Preprocessors
Preprocessors reassemble and normalize traffic before Snort analysis.

Example (snort.lua):

```lua
Copy code
stream = {
    tcp = {
        -- TCP stream reassembly options
    }
}

http_inspect = {
    -- HTTP traffic inspection options
}
```
These reduce false negatives and improve detection efficiency.

#### Monitoring Resources
Checked Snort’s CPU and memory usage with:

```bash
top
# or
htop
```
Optimizations reduced CPU load significantly during high-traffic periods.

#### Alert Visualization and Dashboards
Implementing Alert Visualization (ELK Stack)
Logstash was configured to parse Snort’s alert logs and forward them into Elasticsearch.

Logstash configuration (snort.conf):

```conf
Copy code
input {
  file {
    path => "/var/log/snort/alert.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}
filter {
  grok {
    match => { "message" => "%{SNORTALERT}" }
  }
}
output {
  elasticsearch { hosts => ["localhost:9200"] }
}
```
Start Logstash:

```bash
sudo systemctl start logstash
```
#### Building Dashboards in Kibana
Using Kibana, interactive dashboards were built for visualization.

Examples:

Alert Count Over Time → Bar chart by hour/day.

Top Alert SIDs → Pie chart of most frequent alerts.

Alert Source Map → Geographic mapping of source IPs.

All visualizations were combined into a comprehensive dashboard for monitoring network activity.

