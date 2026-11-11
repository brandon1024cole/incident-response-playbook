# Design Scenario: AiTM Phishing → Hybrid Lateral Movement

> Secnario designed with assistance from Claude.

---

## Part A: The Environment

**Harborline Freight Partners**: freight brokerage, ~520 employees, HQ in Baltimore, MD, plus 3 regional offices. Hybrid workforce. The Transportation Management System (TMS) runs dispatch; if it's down, no trucks get booked.

### Identity
| Component | Detail |
|---|---|
| On-prem Active Directory | `corp.harborline.local`; 2 domain controllers (DC01, DC02) at HQ |
| Cloud identity | Microsoft Entra ID P2, synced from AD via Entra Connect (password hash sync) |
| MFA | Microsoft Authenticator push for all users (**not phishing-resistant**) |
| Conditional Access | MFA required everywhere; Identity Protection **blocks High-risk sign-ins only**; **no compliant-device requirement** |
| MFA registration | Users can add new MFA methods from **any location**, using an existing session |

### Email
| Component | Detail |
|---|---|
| Exchange Online + Defender for Office 365 P2 | Safe Links and Safe Attachments on; external-sender banner on |

### Network & systems
| System | Role | Notes |
|---|---|---|
| SSL VPN | Remote access to the internal network | Authenticates through Entra ID (SSO + MFA); **unmanaged devices allowed** |
| FS02 | Legacy file server (Finance shares) | Windows Server 2016; **no EDR agent installed** |
| SQL01 | TMS database server | Crown jewel; Defender for Endpoint installed |
| DC01 / DC02 | Domain controllers | Defender for Endpoint and Defender for Identity installed |
| Workstations | Windows 11, Intune-managed | Defender for Endpoint on all |

### Security operations
| Item | Detail |
|---|---|
| SIEM | Microsoft Sentinel: Entra ID sign-in & audit logs, Office 365 audit, Defender XDR (including email events), Windows Security Events from DCs and servers, VPN logs |
| Team | Security Manager (Incident Commander), 2 Security Analysts, IT Ops team of 8 |
| After hours | MDR provider monitors 24x7 and phones the on-call analyst for High alerts |

### Known weaknesses (the auditors flagged these last year; none are fixed yet)
1. MFA is push-based, so a **phishing proxy can relay it**. Admins only were moved to FIDO2 keys.
2. Users can register new MFA methods from anywhere, with no extra verification.
3. No LAPS: **every server shares the same local Administrator password**.
4. IT admin **J. Smith uses one account** for email, daily work, *and* Domain Admin tasks.
5. A legacy AD group, `Finance-RDP`, still grants Remote Desktop access to FS02 to all Finance staff.
6. FS02 was never onboarded to EDR.
7. An IT onboarding document on SharePoint describes how to connect to the VPN, and a `server_inventory.xlsx` spreadsheet is readable by all staff.

---

## Part B: What You Know at Detection

**Thursday, 8:15 PM ET.** You are the on-call Security Analyst. The MDR provider calls you:

> "We have two High-severity alerts for Harborline in the last hour:
> 1. **Defender for Endpoint on SQL01:** *Possible pass-the-hash.* A logon used the local Administrator account from internal IP 10.20.5.12.
> 2. **Sentinel analytic:** *User added to privileged group.* A new account, `svc_backup2`, was created at 7:41 PM and added to **Domain Admins** by **jsmith**.
>
> We have not taken any action. How do you want to proceed?"

That is everything you have. Everything else, you have to find.

---

## Part C: Ground Truth (what actually happened)

*Use this to check whether your playbook would uncover each step. Players won't see it during the tabletop.*

| Time (Thu) | Attacker activity | Evidence it leaves behind |
|---|---|---|
| Earlier that week | Researches Harborline Finance staff on LinkedIn; sets up a phishing proxy on a look-alike domain (`harborline-docs[.]com`) | None in Harborline's logs |
| 3:58 PM | Sends 14 Finance employees an email: "Updated carrier rate confirmation – please review," linking to a page that **looks like** SharePoint | Email delivery events; Safe Links did **not** block the link (domain was 3 days old with no reputation) |
| 4:12 PM | **Maria Lopez** (Senior Accountant) clicks, enters her password, and approves the Authenticator push. The proxy relays everything to the real Microsoft login and **steals her session cookie**. She sees a "document unavailable" page and moves on. | URL click event; Entra sign-in from Maria's home IP (legitimate-looking) |
| 4:19 PM | Attacker **replays the stolen session cookie** from their own server and is now signed in as Maria, **without needing her password or MFA again** | Entra sign-in from a **new IP and different browser** using the same session; Identity Protection **Medium** risk alert (not blocked) |
| 4:24 PM | Registers **their own Authenticator app** on Maria's account (so access survives if the cookie expires) and creates an **inbox rule** moving emails containing "security", "sign-in", or "MFA" to the RSS Feeds folder | Entra audit log: security info registered; Office 365 audit: `New-InboxRule` |
| 4:35 PM | Searches SharePoint for "VPN", "password", "server"; downloads the onboarding doc and `server_inventory.xlsx` | Office 365 audit log: `SearchQueryPerformed`, `FileDownloaded` |
| 5:20 PM | Connects to the VPN as maria.lopez from an unmanaged laptop, approving MFA with **their own** Authenticator; assigned internal IP **10.20.5.12** | VPN logs; Entra sign-in to the VPN app |
| 5:35 PM | Enumerates Active Directory and scans the server subnet for open SMB/RDP ports | Defender for Identity: reconnaissance alert (Medium); DC security events |
| 6:10 PM | Uses `Finance-RDP` membership to open Remote Desktop to **FS02** | Windows Event 4624 (logon type 10) on FS02 |
| 6:30 PM | Dumps credentials from memory on FS02 and gets: (a) the shared **local Administrator** hash; (b) **jsmith**'s cached Domain Admin credentials from his maintenance logon earlier that day | **Nothing from EDR** (FS02 has none); only native Windows logs, if collected |
| 7:05 PM | Pass-the-hash with the local Administrator account to **SQL01** | Defender for Endpoint High alert (**Alert 1**) |
| 7:40 PM | Logs on to **DC01** as jsmith; creates `svc_backup2` and adds it to Domain Admins | Events 4720, 4728; Sentinel High alert (**Alert 2**) |
| 8:15 PM | MDR calls you | |

**Still unknown at 8:15 PM:** the attacker's goal. It could be data theft (carrier banking records, customer data), ransomware staging, or both. **13 other Finance employees received the same email.** Nobody has checked whether any of them clicked.