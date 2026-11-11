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

- [**6\. MITRE ATT\&CK Mapping**](#6.-mitre-att&ck-mapping)

- [**7\. Communication Plan**](#7.-communication-plan)

- [**8\. Evidence Handling**](#8.-evidence-handling)

- [**Appendix A. NIST SP 800-61 Rev. 3 / CSF 2.0 Mapping**](#appendix-a.-nist-sp-800-61-rev.-3-/-csf-2.0-mapping)	**[5](#heading=h.6mt8mr7elkkm)**

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

*PENDING — company overview, crown jewels, technology stack, known gaps.*

# **3\. Roles and Responsibilities** {#3.-roles-and-responsibilities}

*PENDING — IR team roster and RACI chart.*

# **4\. Severity Classification** {#4.-severity-classification}

*PENDING — Low / Medium / High / Critical criteria and escalation timelines.*

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