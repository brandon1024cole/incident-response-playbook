**Incident Response Playbook**

Identity Compromise with Lateral Movement

Harborline Freight Partners (fictional organization)

| Field | Value |
| :---- | :---- |
| Version | 0.1.1 |
| Author | Brandon Cole |
| Framework | CompTIA CySA+ CS0-004 incident response lifecycle (7 phases), mapped to NIST SP 800-61 Rev. 3 / CSF 2.0 |
| Status | Scoping |

# **Contents** {#contents}

[**Contents	2**](#contents)

[**1\. Purpose and Scope	3**](#1.-purpose-and-scope)

[**2\. Organization Profile	3**](#2.-organization-profile)

[**3\. Roles and Responsibilities	3**](#3.-roles-and-responsibilities)

[**4\. Severity Classification	3**](#4.-severity-classification)

[**5\. Incident Response Lifecycle	4**](#5.-incident-response-lifecycle)

[5.1 Preparation	4](#5.1-preparation)

[5.2 Detection	4](#5.2-detection)

[5.3 Analysis	4](#5.3-analysis)

[5.4 Containment	4](#5.4-containment)

[5.5 Eradication	4](#5.5-eradication)

[5.6 Recovery	4](#5.6-recovery)

[5.7 Post-Incident Activity	4](#5.7-post-incident-activity)

[**6\. MITRE ATT\&CK Mapping	5**](#6.-mitre-att&ck-mapping)

[**7\. Communication Plan	5**](#7.-communication-plan)

[**8\. Evidence Handling	5**](#8.-evidence-handling)

[**Appendix A. NIST SP 800-61 Rev. 3 / CSF 2.0 Mapping**](#appendix-a.-nist-sp-800-61-rev.-3-/-csf-2.0-mapping)	**[5](#heading=h.6mt8mr7elkkm)**

# **1\. Purpose and Scope** {#1.-purpose-and-scope}

This playbook exists to help SOC analysts and IR teams handle cybersecurity incidents related to identity and access management (IAM), as well as lateral movement. It provides clarity on the proper course of action if there is no supervisor available at the moment an identity compromise or lateral movement attack occurs. 

Identity compromise is an attacker using valid credentials or session tokens to impersonate a legitimate employee and gain access to the organization’s systems (user, service, and/or admin accounts). For example, gaining access to sensitive files through an employee’s login credentials, or being able to send and receive emails from the employee’s email address. Lateral movement is using the newly gained permissions from a compromised account to establish persistence, move to other systems, or gain more privileges. For example, logging into another system that uses shared credentials as the compromised ones, a user running commands in PowerShell when they shouldn’t be, or sending emails from the compromised user's account to internal HR/IT employees. Things to look for that are relevant to this playbook: 

- Risky or unfamiliar logins  
- A new MFA source registered without previously notifying the IT team  
- New email forwarding or deletion rules created  
- Credential dumping or reuse  
- Changes to privileged groups  
- New admin accounts created unexpectedly  
- User reports of logins or MFA prompts they did not initiate

The steps in this playbook are to be followed when there is a credible suspicion of possible identity compromise or lateral movement. Other related cybersecurity attacks, such as phishing or ransomware, are not covered in this playbook, even though they might be used as a vector or the end goal of committing an identity compromise attack. For other types of attacks, see the dedicated playbook directly associated with them.

# **2\. Organization Profile** {#2.-organization-profile}

## **2.1 Business overview** 

Harborline is a freight brokerage company with about 520 employees. The workforce is primarily hybrid, although the HQ is located in Baltimore, MD, along with 3 other regional offices. Regular business hours are 9:00 AM to 5:00 PM.

Harborline runs on a Transportation Management System (TMS), and if that goes down, then no trucks can get booked.

## **2.2 Critical assets**

| Asset | Notes |
| ----- | ----- |
| **SQL01** | The TMS database server, the crown jewel of the company. If this is compromised, it would interrupt business processes. |
| **DC01/02** | Domain controllers that manage and authenticate every account and machine in the domain. Can control everything in AD |
| **Cloud Identity \+ MFA** | Allows users to log in and verify their identity. The company’s IAM and directory service (Entra ID). |
| **FS02** | Internal file server on a legacy system that contains financial records for the organization |

## **2.3 Identity architecture**

Active Directory manages local infrastructure, network assets, and file shares. It connects to Entra ID through Entra Connect, using password hash-sync. This means a user’s on-premises password and cloud password are the same.

MFA is used as an additional layer of security for logins. It is a push notification for most employees; only admin accounts use FIDO2 keys for MFA.

Harborline conditional access policies require MFA for all sign-ins and block only high-risk sign-ins.

For remote access to organizational servers and materials, a VPN is used, which authenticates using Entra ID. Devices do not have to be screened or managed by the organization to connect.

## **2.4 Security tools and log sources**

| Tool | What it Does | Known Gaps |
| ----- | ----- | ----- |
| **Microsoft Sentinel** | Central place to search and correlate all sources below, build a timeline, and manage incidents | Only sees sources connected to it; anything not forwarded from the sources below is invisible |
| **Entra ID sign-in logs** | Monitors who signed in, from where, and at what time. Also tells what device and browser, which app, whether MFA passed, as well as the sign-in risk level | A replayed stolen session can look like a normal, successful sign-in with MFA satisfied |
| **Entra ID audit logs** | Monitors changes to identities: MFA methods added or removed, password resets, group and role changes, app permissions | Shows *that* an MFA method was added; attacker-registered methods look like normal user changes, so this cannot be the only cause for escalation |
| **Entra ID Protection**  | Risky sign-ins and risky users, with the reason | Medium-risk sign-ins are only logged, not blocked; flagged sign-ins can go unreviewed if the queue is not monitored |
| **Office 365 audit log** | Monitors mailbox and file activity: inbox rules created, files searched for and downloaded, sharing changes | None known |
| **Defender for Office 365**  | Who received a given email, whether it was delivered or blocked, and who clicked the link | Can miss phishing links on new domains with no reputation yet |
| **VPN logs** | Displays which user connected, from what public IP, which **internal IP** they were assigned, and when, linking network activity back to a user | Shows who connected but not what they did |
| **Defender for Endpoint**  | Processes, network connections, and logons on managed machines; alerts for credential dumping and pass-the-hash; can isolate a device | The legacy file server does not run EDR |
| **Defender for Identity** | Watches domain controller traffic for reconnaissance, pass-the-hash and pass-the-ticket, Kerberoasting, and suspicious group changes | None known |
| **Windows Security Event logs** | Logons and their type (network, Remote Desktop), accounts created, group membership changes | Doesn’t log processes or commands run |

## **2.5 Security team and coverage hours**

The security team has 3 people: 2 SOC Analysts and one Security Manager, along with 8 IT Operations team members. 

Outside of business hours, a MDR provides 24x7 monitoring and phones the on-call analyst for high-severity alerts. The MDR does not take containment/eradication related actions.

## 

## **2.6 Known limitations**

| Asset | Vulnerability | Impact on Response |
| :---- | :---- | :---- |
| MFA | Users can register new MFA methods from anywhere once logged in. MFA for most employees is push-based and is vulnerable to AiTM attacks. | Resetting an account password won’t evict the attacker; responders must also revoke sessions and reinforce new MFA |
| Servers | Every server shares the same local administrator password | Large blast radius; if we know the adversary got into one server, we know they have the means to get into all |
| Users | Some admins use the same account for daily work and admin tasks | If an adversary gets access to an admin’s daily account, it must be considered a domain-level compromise |
| Legacy File Server | The legacy file server with the financial files still offers remote desktop access and has no EDR | Analysts will have to collect native Windows logs manually |
| VPN  | Devices do not need to be managed in any way to connect | Devices connected over VPN may have no EDR; investigators must rely on VPN and server logs, and containment must include ending active VPN sessions. |

# **3\. Roles and Responsibilities** {#3.-roles-and-responsibilities}

| Role | Who | Responsibilities |
| :---- | :---- | :---- |
| **Incident Commander (IC)** | Security Manager | Owns the incident, declares severity, makes containment calls, runs bridge calls |
| **Lead Analyst** | Security Analyst I/II (2 on staff) | Triage, investigation, timeline, evidence collection, KQL hunting |
| **Identity / IT Ops Lead** | IT Systems Administrator | Executes account actions (reset, revoke sessions, block), mail rule removal |
| **MDR Provider** | External SOC | 24x7 detection, initial triage, escalation to IC |
| **Communications Lead** | Director of Marketing & Comms | Internal comms, customer/carrier messaging (approved by Legal) |
| **Legal Counsel** | General Counsel \+ outside breach counsel | Privilege, notification obligations, law enforcement contact |
| **Finance Lead** | Controller | Payment holds, bank recall requests, vendor banking verification |
| **Executive Sponsor** | CIO (CFO for financial-loss incidents) | Approves business-impacting decisions, board/insurer communication |

## RACI Chart

*R \= Responsible (does it) · A \= Accountable · C \= Consulted · I \= Informed*

| Activity | IC | Analyst | IT Ops | MDR | Comms | Legal | Finance | Exec |
| :---- | :---- | ----- | :---- | :---- | :---- | :---- | :---- | :---- |
| Initial triage & validation | A | R | – | R | – | – | – | – |
| Declare incident & severity | A/R | C | – | C | – | I | – | I |
| Contain compromised account | A | C | R | C | – | – | – | I |
| Freeze / recall payments | C | – | – | – | – | C | A/R | I |
| Evidence collection & preservation | A | R | C | C | – | C | – | – |
| Determine notification obligations | C | C | – | – | C | A/R | – | I |
| External communication | C | – | – | – | R | A | C | I |
| Eradication & recovery | A | R | R | C | – | – | – | I |
| Lessons learned / after-action report | A/R | R | C | C | C | C | C | I |

# **4\. Severity Classification** {#4.-severity-classification}

| Level | Criteria | Generic Example | Response Target (time) | Who to Notify |
| ----- | ----- | ----- | ----- | ----- |
| Low | Suspicious sign-in activity; no evidence the attacker got in | User reports password reset attempts | Next business day | IT Team / Security Analyst |
| Medium | Attempted compromise, or a suspected single compromised account still being investigated | Unusual logins with impossible travel, new devices connected via VPN, MFA prompts without request from user | 1.5 hours, 24/7 | IC / Security Analyst / IT Team |
| High  | Confirmed compromise of a standard account, or lateral movement to non-critical systems, or sensitive data accessed or changed | Newly registered MFA method, inbox rules hiding emails, replayed session confirmed, remote logons from the compromised account to non-critical servers, credential dumping on a server | 30 mins, 24/7 | IC / Security Analyst / Legal Counsel / IT Team |
| Critical | Privileged or domain-level compromise, or access to crown-jewel systems, or sensitive data stolen, or business operations disrupted | Crown jewel server or domain controllers have been accessed, new account created or added to a privileged group |  15 mins, 24/7 | IC / Legal Counsel / Finance Lead / CFO / IT Team / Communications team |

- When a situation fits criteria for two different severity levels or when the evidence is unclear, choose the higher level. It is better to overreact and be wrong rather than to underreact and be wrong.   
- Severity is reassessed upon every new finding, and every hour for high and critical severity incidents  
- IT Ops, Security Analysts, and the IC can raise severity, but only the IC and Security Analysts can lower it

# **5\. Incident Response Lifecycle** {#5.-incident-response-lifecycle}

Each phase follows the same structure:

* Entry criteria: what must be true to begin this phase

* Actions: who does what, with decision points

* Exit criteria: what must be true to move to the next phase

## **5.1 Preparation** {#5.1-preparation}

What must be in place before an incident: people, tools, logging, access, training.

*PENDING*

## **5.2 Detection** {#5.2-detection}

How the incident is first noticed: alert sources, user reports, MDR escalation.

*PENDING*

## **5.3 Analysis** {#5.3-analysis}

Validate, scope, build the timeline, and assign severity.

*PENDING*

## **5.4 Containment** {#5.4-containment}

Stop the attacker's movement: isolate accounts, sessions, and hosts.

*PENDING*

## **5.5 Eradication** {#5.5-eradication}

Remove attacker access and persistence; fix the root cause.

*PENDING*

## **5.6 Recovery** {#5.6-recovery}

Restore and verify systems and accounts; release them from isolation; monitor.

*PENDING*

## **5.7 Post-Incident Activity** {#5.7-post-incident-activity}

Lessons learned, root cause analysis, corrective actions, metrics.

*PENDING*

# **6\. MITRE ATT\&CK Mapping** {#6.-mitre-att&ck-mapping}

*PENDING — techniques observed in this scenario and the detection or log source for each.*

# **7\. Communication Plan** {#7.-communication-plan}

*PENDING — internal and external communication, approvals, templates.*

# **8\. Evidence Handling** {#8.-evidence-handling}

*PENDING — chain of custody, preservation, legal hold.*

# **Appendix A. NIST SP 800-61 Rev. 3 / CSF 2.0 Mapping** {#appendix-a.-nist-sp-800-61-rev.-3-/-csf-2.0-mapping}

*PENDING — table mapping the seven phases to Govern, Identify, Protect, Detect, Respond, Recover.*