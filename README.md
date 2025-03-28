
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation][https://github.com/JonathanGribe/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md]

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `torshoppinglist.txt` on the desktop at `2025-03-25T15:18:09.6556477Z`. These events began at `2025-03-25T14:51:53.7171402Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "employeeworksta" 
| where  InitiatingProcessAccountName =="jonuser"
| where FileName startswith "tor"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc 

```
![image](https://github.com/user-attachments/assets/cfc97358-a054-4506-b37c-baedc0b2367e)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-03-25T14:59:26.7481335Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "employeeworksta"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath,  ProcessCommandLine 

```
![image](https://github.com/user-attachments/assets/a573ec65-dd3d-4253-85db-1db86ed46e70)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-03-25T15:11:53.1323055Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "employeeworksta"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/200a305b-84e7-4857-846a-21550a0f0bf6)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-25T15:01:19.1208627Z`, an employee on the "employeeworksta" device successfully established a connection to the remote IP address `91.132.145.245` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "employeeworksta"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName , ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName,  InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/4054569b-4bf0-4855-b5f2-5449643cb2c9)

![image](https://github.com/user-attachments/assets/caeee6e8-2e91-4ca5-aaa2-05c3b8d67ffb)



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-25T14:51:53.7171402Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\jonUser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe  /S`
- **File Path:** `C:\Users\jonUser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-25T15:01:05.3026855Z`
- **Event:** User "jonUser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\jonUser\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-25T15:01:19.1208627Z`
- **Event:** A network connection to IP `91.132.145.245` on port `9001` by user "jonUser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\jonuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-25T15:01:21.703987Z` - Connected to `171.25.193.20` on port `80`.
  - `2025-03-25T15:01:35.4257941Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-25T15:13:29.8543242Z`
- **Event:** The user "jonUser" created a file named `torshoppinglist.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\jonUser\Desktop\torshoppinglist.txt`

---

## Summary

The user "jonUser" on the "employeeworksta" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `torshoppinglist.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `employeeworksta` by the user `jonUser`. The device was isolated, and the user's direct manager was notified.

---
