**Incident Response Playbook**

Identity Compromise with Lateral Movement

Harborline Freight Partners (fictional organization)

| Field | Value |
| :---- | :---- |
| Version | 0.1 |
| Author | Brandon Cole |
| Framework | CompTIA CySA+ CS0-004 incident response lifecycle (7 phases), mapped to NIST SP 800-61 Rev. 3 / CSF 2.0 |
| Status | Scoping |

# **Contents**

- [**1\. Purpose and Scope**](#1.-purpose-and-scope)

- [**2\. Organization Profile**](#2.-organization-profile)

- [**3\. Roles and Responsibilities**](#3.-roles-and-responsibilities)

- [**4\. Severity Classification**](#4.-severity-classification)

- [**5\. Incident Response Lifecycle**](#5.-incident-response-lifecycle)

  - [5.1 Preparation](#5.1-preparation)

  - [5.2 Detection](#5.2-detection)

  - [5.3 Analysis](#5.3-analysis)

  - [5.4 Containment](#5.4-containment)

  - [5.5 Eradication](#5.5-eradication)

  - [5.6 Recovery](#5.6-recovery)

  - [5.7 Post-Incident Activity](#5.7-post-incident-activity)

- [**6\. MITRE ATT\&CK Mapping**](#att&ck-mapping)

- [**7\. Communication Plan**](#7.-communication-plan)

- [**8\. Evidence Handling**](#8.-evidence-handling)

- [**Appendix A. NIST SP 800-61 Rev. 3 / CSF 2.0 Mapping**](#appendix-a.-nist-sp-800-61-rev.-3-/-csf-2.0-mapping)	**[5](#heading=h.6mt8mr7elkkm)**

# **1\. Purpose and Scope**

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

# **2\. Organization Profile**

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

## **2.6 Known limitations**

| Asset | Vulnerability | Impact on Response |
| :---- | :---- | :---- |
| MFA | Users can register new MFA methods from anywhere once logged in. MFA for most employees is push-based and is vulnerable to AiTM attacks. | Resetting an account password won’t evict the attacker; responders must also revoke sessions and reinforce new MFA |
| Servers | Every server shares the same local administrator password | Large blast radius; if we know the adversary got into one server, we know they have the means to get into all |
| Users | Some admins use the same account for daily work and admin tasks | If an adversary gets access to an admin’s daily account, it must be considered a domain-level compromise |
| Legacy File Server | The legacy file server with the financial files still offers remote desktop access and has no EDR | Analysts will have to collect native Windows logs manually |
| VPN  | Devices do not need to be managed in any way to connect | Devices connected over VPN may have no EDR; investigators must rely on VPN and server logs, and containment must include ending active VPN sessions. |
# **3\. Roles and Responsibilities** 

| Role | Who | Responsibilities |
|------|-----------------|------------------|
| **Incident Commander** | Security Manager | Owns the incident, declares severity, makes containment calls, runs bridge calls |
| **Lead Analyst** | Security Analyst | Triage, investigation, timeline, evidence collection|
| **Identity / IT Ops Lead** | IT Systems Administrator | Executes account actions (reset, revoke sessions, block), mail rule removal |
| **MDR Provider** | External SOC | 24x7 detection, initial triage, escalation to IC |
| **Communications Lead** | Director of Marketing & Comms | Internal comms, customer/carrier messaging (approved by Legal) |
| **Legal Counsel** | General Counsel + outside breach counsel | Privilege, notification obligations, law enforcement contact |
| **Finance Lead** | Controller | Payment holds, bank recall requests, vendor banking verification |
| **Executive Sponsor** | CIO (CFO for financial-loss incidents) | Approves business-impacting decisions, board/insurer communication |

## RACI Chart

*R = Responsible (does the activity) · A = Accountable · C = Consulted · I = Informed*
 
| Activity | IC | Analyst | IT Ops | MDR | Comms | Legal | Finance | Exec |
|----------|----|---------|--------|-----|-------|-------|---------|------|
| Initial triage & validation | A | R | – | R | – | – | – | – |
| Declare incident & severity | A/R | C | – | C | – | I | – | I |
| Contain compromised account | A | C | R | C | – | – | – | I |
| Freeze / recall payments | C | – | – | – | – | C | A/R | I |
| Evidence collection & preservation | A | R | C | C | – | C | – | – |
| Determine notification obligations | C | C | – | – | C | A/R | – | I |
| External communication | C | – | – | – | R | A | C | I |
| Eradication & recovery | A | R | R | C | – | – | – | I |
| Lessons learned / after-action report | A/R | R | C | C | C | C | C | I |
# **4\. Severity Classification**

| Level | Criteria | Generic Example | Response Target | Who to Notify |
| ----- | ----- | ----- | ----- | ----- |
| Low | Suspicious sign-in activity; no evidence the attacker got in | User reports password reset attempts | Next business day | IT Team / Security Analyst |
| Medium | Attempted compromise, or a suspected single compromised account still being investigated | Unusual logins with impossible travel, new devices connected via VPN, MFA prompts without request from user | 1.5 hours, 24/7 | IC / Security Analyst / IT Team |
| High  | Confirmed compromise of a standard account, or lateral movement to non-critical systems, or sensitive data accessed or changed | Newly registered MFA method, inbox rules hiding emails, replayed session confirmed, remote logons from the compromised account to non-critical servers, credential dumping on a server | 30 mins, 24/7 | IC / Security Analyst / Legal Counsel / IT Team |
| Critical | Privileged or domain-level compromise, or access to crown-jewel systems, or sensitive data stolen, or business operations disrupted | Crown jewel server or domain controllers have been accessed, new account created or added to a privileged group |  15 mins, 24/7 | IC / Legal Counsel / Finance Lead / CFO / IT Team / Communications team |

- When a situation fits criteria for two different severity levels or when the evidence is unclear, choose the higher level. It is better to overreact and be wrong rather than to underreact and be wrong.   
- Severity is reassessed upon every new finding, and every hour for high and critical severity incidents  
- IT Ops, Security Analysts, and the IC can raise severity, but only the IC and Security Analysts can lower it

# **5\. Incident Response Lifecycle** 

## **5.1 Preparation** 

Preparation is ongoing and is not triggered by an incident. This section is reviewed once a year and after every High or Critical incident.

People:
1.  Rotating team of on-call Security Analysts trained on this playbook, so that MDR alerts and High and Critical incidents can be addressed 24/7
2.  IT operations team trained on this playbook and aware of where to find it
3.  Contact list for the Incident Commander (including a backup), legal team, finance team, communications team, and the business owner. Stored somewhere that is still accessible if email and AD are down

Process:
1.  An out-of-band communications channel, separate from normal organizational communication methods and tested before an incident 
2.  Identity verification procedures for password resets and re-registering MFA. For example, an in-person or virtual ID check against HR records and a call back to the number on file
3.  Evidence handling procedures are documented, and staff are aware and trained on what to do
4.  A tabletop discussion on using this playbook, once a year

Technology:
1.  The log sources are connected to the SIEM and are kept for at least 90 days. 
2.  EDR is installed on all workstations and servers and can isolate a device remotely. Devices with no EDR have some way to be isolated from the network in case quarantine is needed.
3.  IT Operations can revoke sessions, disable accounts, remove/disable MFA methods, and remove inbox rules in the cloud and Active Directory.
4.  Backups of file servers, domain controllers, and the crown jewel are taken regularly, ensuring that the Recovery Point Objective can be achieved
5.  A written procedure for KRBTGT double reset

## **5.2 Detection**

Entry Criteria: Any trigger listed in Section 1 

1.  Security Analyst acknowledges the report and creates an incident record to start building a timeline. 
    
2.  Make sure this incident is within IAM and lateral movement scope and not another related incident. They also assign an initial severity.
    
3.  If the signal alone meets High or Critical (Section 4): assign that severity and notify the IC immediately, then verify.
    
4.  Security Analyst reaches out to the specific user (out-of-band) to confirm whether or not the activity was theirs.
    
    1.  Record “yes or no”; can be used to make a timeline in later steps
        
5.  Check for corresponding data to match user answer (known travel, usual device, approved IT change)
    
    1.  If the activity is fully explained, close and record evidence and reason
    2.  If not, **continue**  

6.  Security Analyst notifies the roles listed according to Section 4.

Exit criteria:  
*   If the suspicion is ruled out as fully explained. 
*   If suspicion of an attack is not ruled out. Incident record open, initial severity assigned, required roles notified.

## **5.3 Analysis**

Entry criteria: Detection exit criteria met

1.  Security Analyst pulls sign-in data for the targeted user or access data from the targeted system from logs
    
2.  Security Analyst tracks sign-in path and timeline (IP, user, session, MFA requests, device, time, VPN logs) 
    
    1.  If all activity is explained and suspicions of compromise can be dismissed without a reasonable doubt, close and record the evidence and reason.
    2.  If not, continue.
        
3.  Security Analyst preserve logs and system evidence per Section 8 before manual inspection
    
4.  Security Analyst measures the scope (credential dumping, associated logins on separate users/devices/servers)
    
5.  Security Analyst measures the impact and persistence (new MFA methods, inbox rules, password resets, group changes, files and servers accessed)
    
    1.  If crown jewels or domain controllers have evidence of being accessed, escalate to Critical severity and notify corresponding groups (Section 4)
    2.  If non-critical assets have evidence of being accessed, escalate to High severity and notify corresponding groups (Section 4)
        
6.  Security Analyst identifies the initial access vector, then searches for other users exposed to it; repeats steps 1-5 for every new account or system
    
7.  Security Analyst adds all IOCs and updated timeline to the incident record 
    
8.  Security Analyst reassesses severity and notifies the roles listed according to Section 4
    

For High or Critical incidents, the IC may begin containing confirmed accounts while scoping continues.

Exit criteria:
*   If all activity is explained, and compromise can be ruled out without a reasonable doubt
*   If the compromise is confirmed and the full scope of affected systems and users has been determined

## **5.4 Containment** 

Entry Criteria: Analysis exit criteria met, or Incident Commander authorizes early containment due to High or Critical severity

1.  Incident Commander moves all communication out-of-band
    
2.  Security Analyst preserves all logs of attacker activity for future use (legal)
    
3.  Incident Commander and IT Operations review the scope list and incident record from Analysis. Decide a plan of action with the business owners about the crown jewel. Incident Commander approves the plan; all actions are executed together so the attacker isn’t warned.
    
4.  IT Operations disables compromised privileged and attacker-created accounts.  
    
5.  IT Operations changes the shared local admin password. 
    
6.  IT Operations blocks known attacker IPs and disables VPN sessions for associated accounts. Focus on privileged and attacker-created accounts. 
    
7.  IT Operations revokes active sessions (cloud and AD) and forces a password reset of all other associated accounts. Then disables all MFA sources and blocks known attacker IPs.
    
8.  IT Operations disables active email sessions for associated accounts and removes all new rules the attacker established.
    
9.  IT Operations isolates associated endpoint devices and servers using EDR, and isolates devices without EDR on a separate VLAN.
    
10.  Security Analyst verifies containment by monitoring logs for known IOCs or activity from known malicious IPs
    1.  If activity continues, go back to 5.3 Analysis
    2.  If not, continue
        
11.  IT Operations records all actions taken as they happen, including the time and who on the team did them 
    
Exit Criteria: 
*   Containment verified: no known attacker access remains
*   All containment actions have been documented and added to the incident record
*   All logs and related sources have been preserved as evidence

## **5.5 Eradication**

Entry Criteria: Containment exit criteria met.

1.  Security Analyst compares with persistence checks in Analysis phase and searches for things Analysis may have missed
    1.  Cloud: OAuth app consents, new app registrations, forwarding rules, MFA methods on other accounts.
    2.  On-premises: new accounts, scheduled tasks, services, and changes to admin groups.
    3.  If a new persistence shows up, contain it (5.4) and run analysis (5.3) on it.
        
2.  IT Operations forces password resets and removes any remaining forms of persistence: new user accounts (normal and privileged), new rules, new MFA sources added.
    
3.  Incident Commander and business owner approve a time to reset servers. IT Operations rebuilds the file server and crown jewel from a known clean backup that predates the compromise.
    
4.  Incident Commander approves a KRBTGT reset, and IT Operations performs it to make sure no new Kerberos tickets can be forged.
    1.  Reset once and wait for tickets to expire and for the new change to replicate so that we don’t break old, legitimate tickets across the whole domain.
    2.  Reset twice to push out the previously saved (and potentially compromised) hash.
        
5.  Security Analyst identifies which weaknesses (Section 2.6 ) enabled the attack. IT Operations remediates them.
    1.  If a fix can’t currently be completed, the Incident Commander records it as a Post-Incident corrective action with an owner and a due date, or as an accepted risk.
        
6.  Security Analyst documents all changes and steps taken as they go.
    
Exit Criteria: 
*   Eradication confirmed: all known persistence and access are removed.
*   Compromised systems rebuilt or verified clean.
*   Root cause remediated, or tracked as an accepted risk with owner approval.
*   All actions documented.
    

## **5.6 Recovery**

Entry Criteria: All Eradication exit criteria are met.

1.  Security Analyst and IT Operations validate servers are clean in an isolated environment before putting them back in production. This validation is approved by the Incident Commander, and only then can the restored servers be returned to production.
    1.  Domain controllers first because they authenticate everything else. Then the crown jewel, then everything else.
    2.  Business owner confirms that the services work
    
2.  After validation and approval from the Incident Commander, IT Operations releases endpoint stations from Isolation
    
3.  IT Operations verify the identity of users by performing an ID check against HR records. Then restore user accounts and enforce new MFA. Send users a new account link through out-of-band communication methods. Enforce admins to use separate accounts for daily and admin tasks.
    
4.  Security Analyst monitors for similar IOCs for the next 30 days, as this is when attackers are most likely to reattempt attacks.
    1.  If attack activity re-emerges, return to Analysis (5.3)
        
5.  Security Analyst and IT Operations document all recovery steps as they go.
    

Exit Criteria: 
*   Business operations are back to where they were pre-incident
*   Monitoring window has passed with no recurrence 
*   All recovery steps have been recorded
*   IC approves closing the incident

## **5.7 Post-Incident Activity**

Entry Criteria: The Incident Commander has closed the incident.

1.  Incident Commander, IT Operations, and Security Analysts hold a “Lessons Learned” meeting within 1 week. Include the business owner and legal team for High and Critical Incidents. Remember that the meeting is blameless. Ask:
    1.  What went well?
    2.  What was slow or confusing?
    3.  What did we not have that would’ve helped prevent this or minimize damage?
        
2.  Security Analyst constructs an after-action report. This includes the timeline, root cause, impact, decisions made, and metrics (time to detect, respond, contain, recover)
    
3.  Incident Commander, IT Operations, and Security Analysts decide on corrective actions and what needs to change to prevent this from happening again. Each action is assigned to a responsible party along with a projected due date. If any risks are accepted, they must be approved by the business owner.
    
4.  Security Analyst and IT Operations update the playbook based on where it fell short. Add new rules and IOCs with threat intelligence partners.
    
5.  Legal team determines how long to keep evidence for in coordination with the security analyst. 
    
Exit Criteria:
*   After-action report approved by the Incident Commander
*   Corrective actions assigned and tracked to completion
*   Playbook and detections updated
*   Evidence retention decided

# **6\. MITRE ATT\&CK Mapping** 

See the ATT&CK mapping file in ./docs.

# **7\. Communication Plan**

During an incident, the team talks only through the out-of-band channel set up in Preparation (5.1). Normal email and chat are off limits until the Incident Commander says otherwise, because we have to assume the attacker can read them.

The severity table in Section 4 decides who gets told what. The Incident Commander owns those updates and gives them at least every few hours for High and Critical incidents, sooner if something changes.

Nothing goes outside the company without sign-off from the Incident Commander, legal team, and Communications. That includes questions from customers, partners, vendors, and the press. Employees who get asked about the incident send the person to Communications and don’t comment themselves.

The legal team decides whether customers, regulators, or law enforcement have to be notified, and by when. Some notification deadlines start counting from when we first suspect a breach, so the legal team is brought in as soon as there’s any sign that sensitive data was accessed. 

# **8\. Evidence Handling**
### **Preservation**
Before isolating, rebooting, removing rules, or rebuilding, the Security Analyst collects the evidence first. The order is as follows:
- Memory from compromised hosts
- Logs (cloud sign-in and audit, Windows Security events, VPN)
- Disk images of systems that will be rebuilt 

Cloud logs are exported before they pass their retention window.

### **Integrity** 
Each item is hashed when it’s collected, and the hash is checked again whenever the item is used. Analysts work on copies, never the original logs.

### **Chain of custody**
Every item has a record of what it is, its hash, who collected it, when, and from where, plus every handoff after that. Evidence is stored somewhere separate from the domain, with access limited to the Incident Response team.

### **Retention**
Legal Counsel decides how long evidence is kept and can place a legal hold. Nothing related to the incident is deleted until Legal releases it.

# **Appendix A. NIST SP 800-61 Rev. 3 / CSF 2.0 Mapping**


| Playbook Section | CSF 2.0 Function | Categories |
| :---: | :---: | :---: |
| 5.1: Preparation | Govern, Identify, Protect | Policy, roles, asset management, access control, training |
| 5.2: Detection | Detect | DE.CM Continuous Monitoring, DE.AE Adverse Event Analysis |
| 5.3: Analysis | Detect, Respond | DE.AE Adverse Event Analysis, RS.AN Incident Analysis |
| 5.4: Containment | Respond | RS.MI Incident Mitigation, RS.MA Incident Management |
| 5.5: Eradication | Respond | RS.MI Incident Mitigation |
| 5.6: Recovery | Recover | RC.RP Incident Recovery Plan Execution, RC.CO Recovery Communication |
| 5.7: Post-Incident  | Identify | ID.IM Improvement |
| 7\. Communication | Respond, Recover | RS.CO Incident Response Reporting and Communication, RC.CO |