# **MITRE ATT\&CK Mapping**

The table below maps potential attack methods and situations to known MITRE ATT\&CK TTPs (tactics, techniques, and procedures). The items in this table come from the tabletop exercise of walking through the scenario along with the playbook.

| \# | Tactic | Technique | What happened |
| :---: | :---: | :---: | :---: |
| **1** | Initial Access | Phishing: Spearphishing Link (T1566.002) | Targeted email with a link to a fake login page |
| **2** | Credential Access | Steal Web Session Cookie (T1539)  | Proxy captures the user’s session cookie after MFA |
| **3** | Lateral Movement | Use Alternate Authentication Material: Web Session Cookie (T1550.004) | Attacker replays the stolen session from their own machine |
| **4** | Persistence | Account Manipulation: Device Registration (T1098.005) | Attacker registers their own MFA method on the account |
| **5** | Stealth | Hide Artifacts: Email Hiding Rules (T1564.008) | Inbox rule hides security-related emails |
| **6** | Collection | Data from Information Repositories: SharePoint (T1213.002) | Attacker searches file shares for VPN and server information |
| **7** | Initial Access | External Remote Services (T1133) | Attacker connects to the VPN with the compromised account |
| **8** | Discovery | Account Discovery: Domain Account (T1087.002) & Network Service Discovery (T1046) | Attacker enumerates Active Directory and scans for open ports |
| **9** | Lateral Movement | Remote Services: Remote Desktop Protocol (T1021.001) | Remote Desktop to a server using the compromised account’s group access |
| **10** | Credential Access | OS Credential Dumping: LSASS Memory (T1003.001) | Credentials dumped from memory on the server |
| **11** | Lateral Movement | Use Alternate Authentication Material: Pass the Hash (T1550.002) | Shared local admin hash used to log on to another server |
| **12** | Privilege Escalation | Valid Accounts: Domain Accounts (T1078.002) | Stolen Domain Admin credentials used on a domain controller |
| **13** | Persistence | Create Account: Domain Account (T1136.002) & Additional Local or Domain Groups (T1098.007) | New account created and added to a privileged group |

