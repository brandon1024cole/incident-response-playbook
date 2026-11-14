# Incident Response Playbook: Identity Compromise with Lateral Movement

An incident response playbook for a fictional 520-person hybrid company (Microsoft Entra ID + on-prem Active Directory), structured on the CompTIA CySA+ (CS0-004) incident response lifecycle and mapped to NIST SP 800-61 Rev. 3 and MITRE ATT&CK.

> All organizations, people, and data in this repo are fictional.

## Contents
- [Playbook](docs/playbook.md): scope, org profile, roles/RACI, severity matrix, 7-phase response lifecycle, communication plan, evidence handling
- [Design scenario](docs/scenario.md): AiTM phishing → hybrid lateral movement → Domain Admin, used to test each section
- [ATT&CK mapping](docs/attack-mapping.md): scenario techniques mapped to detections and coverage gaps

## How it was built
Each section was written by hand for a generic scenario, then tested against the design scenario's attack timeline to find gaps before the tabletop exercise.

## Status
- [x] Project scoping
- [x] Organization profile
- [x] Playbook v1.0
- [ ] Tabletop exercise
- [ ] After-action report and playbook v1.1