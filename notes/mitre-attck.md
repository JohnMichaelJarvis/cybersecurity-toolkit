# MITRE ATT&CK Framework

The MITRE ATT&CK framework categorizes the behaviors and techniques adversaries use across various stages of an attack. It is structured around tactics (goals) and techniques (how those goals are achieved).

---

## Tactics (High-Level Objectives)

- **Initial Access** – Gaining entry into a target network or system.
- **Execution** – Running malicious code.
- **Persistence** – Maintaining access between sessions or reboots.
- **Privilege Escalation** – Gaining higher-level permissions.
- **Defense Evasion** – Avoiding detection or security controls.
- **Credential Access** – Stealing account credentials.
- **Discovery** – Learning about the environment and internal structure.
- **Lateral Movement** – Moving through the network to other systems.
- **Collection** – Gathering targeted data.
- **Command and Control (C2)** – Communicating with compromised systems.
- **Exfiltration** – Stealing data out of the network.
- **Impact** – Damaging systems or data (e.g., ransomware, wiping).

---

## Example Techniques

- **Phishing (T1566)** – Delivering malicious content through email to trick users.
- **PowerShell (T1059.001)** – Using PowerShell to execute commands or scripts.
- **Credential Dumping (T1003)** – Extracting credentials from memory or storage.
- **Remote Services (T1021)** – Using legitimate remote tools for lateral movement.
- **Data Staged (T1074)** – Preparing data for exfiltration.

---

For full details, see: [https://attack.mitre.org](https://attack.mitre.org)
