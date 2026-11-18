# SOC Incident Reports

Security incident investigations written in the format a SOC analyst would use: summary, timeline, evidence, indicators of compromise, MITRE ATT&CK mapping, root cause, containment and recommendations.

The investigations use the [SOC home lab](https://github.com/Krishpatel175/soc-home-lab) (Splunk, Sysmon, Windows 10, Kali) and public practice datasets. All activity is simulated in an isolated lab.

## Reports

| # | Incident | Data source | Status |
|---|---|---|---|
| 001 | [Unauthorized admin account with persistence](incidents/INC-001-unauthorized-admin-persistence.md) | Lab: Windows endpoint | ✅ Closed |
| 002 | [SMB brute-force from an internal host (successful)](incidents/INC-002-smb-brute-force.md) | Lab: Kali to Windows | ✅ Closed |
| 003 | [Phishing email impersonating a bank rewards program](incidents/INC-003-phishing-bank-rewards-lure.md) | Public dataset: phishing_pot | ✅ Closed |
