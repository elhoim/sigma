## BLUF

- **What:** corrects ATT&CK tags on 30 rules whose tactic tags were not backed by any tagged technique (pack 3 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 24 unsupported tactic tags removed; 17 rules gained a missing or corrected technique.

**Priority:** Low

### Summary of the Pull Request

For every rule, each tactic tag that no tagged technique backed was resolved from what the detection actually observes:

- **Drop the tactic** when it does not describe the detected behaviour (most often `execution` next to stealth-only proxy-execution techniques such as T1218/T1202, which ATT&CK v19 maps to stealth only).
- **Add the technique** that backs the tactic when the rule genuinely observes it (e.g. T1021.002 for remote SMB/RPC service or task creation, T1068 for privilege-escalation exploits).
- **Replace a wrong technique** when the existing one does not describe the rule (details in the table).
- Where a tagged technique has additional tactics in v19.2, those tactics are added so the SigmaHQ validator's technique/tactic consistency check passes.

Rules whose correct mapping was ambiguous were left out of these PRs on purpose. After this PR every technique on these rules is active in v19.2, every tactic is backed by a tagged technique, and every tactic of a tagged technique is present. Following the SigmaHQ v19 tag migration convention (#5966), tag-only changes do not bump `modified` or `author`.

#### Per-rule changes

| Rule | Removed | Added | Reason |
|---|---|---|---|
| Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted | impact, credential-access, t1485, t1496, t1489 | persistence, privilege-escalation, t1098.006 | drop tactic credential-access: No credential access is observed; replace technique impact → T1098.006 (replaces T1485): The description targets malicious RoleBinding creation or patching, which is literally T1098.006 Additional Container Cluster Roles (persistence, privilege-escalation). T1485/T1496/T1489 are copied boilerplate |
| Azure Network Firewall Policy Modified or Deleted | impact | - | drop tactic impact: Covered by T1686.001 defense-impairment; no impact |
| New Root Certificate Authority Added | - | t1484.002 | add technique privilege-escalation → T1484.002: Adding an attacker-controlled trusted CA to the tenant is a tenant trust modification that lets them authenticate as any user, e.g. Global Admin (T1484.002: defense-impairment, privilege-escalation) |
| Google Workspace Government Attack Warning | impact, t1078 | t1078.004 | drop tactic impact: A flagged login attempt has no impact component; replace technique initial-access → T1078.004 (replaces T1078): Workspace accounts are cloud accounts. More specific, same tactics, and consistent with gcp_gworkspace_suspicious_login.yml |
| Data Compressed | exfiltration | - | drop tactic exfiltration: Archiving is collection (T1560.001); no data leaves the host in what is observed |
| Potentially Suspicious Malware Callback Communication - Linux | persistence | - | drop tactic persistence: Outbound C2 on non-standard ports is command-and-control only |
| Kaspersky Endpoint Security Stopped Via CommandLine - Linux | execution | - | drop tactic execution: Stopping the AV service is defense impairment (T1685); running systemctl is incidental |
| Mount Execution With Hidepid Parameter | credential-access | - | drop tactic credential-access: Hiding processes from other users is stealth (T1564); nothing credential-related is observed |
| Setuid and Setgid | persistence | - | drop tactic persistence: Setuid/setgid abuse (T1548.001) is privilege escalation only in ATT&CK |
| Potential Linux Amazon SSM Agent Hijacking | persistence, t1219.002 | t1219 | drop tactic persistence: No persistence technique backs it in v19.2; hijacked SSM agent is a remote access tool (C2); replace technique command-and-control → T1219 (replaces T1219.002): SSM agent is not remote desktop software; parent Remote Access Tools is more accurate (Windows twin proc_creation_win_ssm_agent_abuse.yml has same tags/issue) |
| Process Execution From Shared Memory Directory | execution | - | drop tactic execution: Rule point is fileless staging (T1027.011, stealth); no execution technique (user execution, interpreter, API) specifically describes running a binary from /dev/shm |
| Linux HackTool Execution | execution, t1587 | t1588.002 | replace technique resource-development → T1588.002 (replaces T1587): Running public hacktools = obtained Tool (T1588.002), not developed capabilities; matches Windows hktl rules; drop tactic execution: Generic tool execution has no specific execution technique; tools span many tactics |
| Mask System Power Settings Via Systemctl | impact | - | drop tactic impact: Preventing sleep is Power Settings (T1653, persistence), not impact |
| Suspicious Execution via macOS Script Editor | persistence | - | drop tactic persistence: No persistence mechanism observed; child process of Script Editor is execution/initial access |
| PUA - Advanced IP/Port Scanner Update Check | reconnaissance, t1590 | t1046 | replace technique discovery → T1046 (replaces T1590): Tool performs internal network/port scanning = Network Service Discovery; matches the file_event/process_creation Advanced IP Scanner rules (T1046); drop tactic reconnaissance: Only backed by T1590 which does not describe internal scanning by an installed tool |
| F5 BIG-IP iControl Rest API Command Execution - Webserver | - | t1059.004 | add technique execution → T1059.004: Endpoint executes bash commands on the BIG-IP |
| MSSQL Destructive Query | exfiltration | - | drop tactic exfiltration: Destroying data is impact (T1485); nothing is exfiltrated |
| Admin User Remote Logon | - | t1021.001 | add technique lateral-movement → T1021.001: LogonType 10 is an RDP logon |
| RottenPotato Like Attack Pattern | - | stealth, t1134.001 | add technique privilege-escalation → T1134.001: Potato attacks relay local auth to steal/impersonate a SYSTEM token; add stealth (tactic of a tagged technique, required by the SigmaHQ validator) |
| Remote Task Creation via ATSVC Named Pipe | - | t1021.002 | add technique lateral-movement → T1021.002: Remote task creation via ATSVC pipe over SMB IPC$; consistent with svcctl twin |
| Possible DC Shadow Attack | credential-access | - | drop tactic credential-access: DCShadow is Rogue Domain Controller (T1207, defense-impairment); SPN registration itself accesses no credentials |
| Addition of SID History to Active Directory Object | - | t1098 | add technique persistence → T1098: Writing SID history on an account is a known AD persistence backdoor = account manipulation; alt: drop persistence |
| Suspicious Remote Logon with Explicit Credentials | - | t1021 | add technique lateral-movement → T1021: Explicit creds used against a remote server by remote-admin tools (winrs=WinRM, net=SMB, wmic); parent Remote Services since protocol varies |
| Uncommon Outbound Kerberos Connection - Security | t1558.003 | t1558, t1550.003 | add technique lateral-movement → T1550.003: Description cites lateral movement via Rubeus tickets; align with twin net_connection_win_susp_outbound_kerberos_connection.yml (T1558 + T1550.003); replace technique credential-access → T1558 (replaces T1558.003): Non-lsass Kerberos traffic covers any ticket request/forging, not just Kerberoasting; twin uses T1558 |
| Remote Service Activity via SVCCTL Named Pipe | - | privilege-escalation, t1543.003 | add technique persistence → T1543.003: Remote SCM access is used to create/modify Windows services; add privilege-escalation (tactic of a tagged technique, required by the SigmaHQ validator) |
| ISATAP Router Address Was Set | initial-access, privilege-escalation, execution | - | drop tactic execution: No execution observed; drop tactic initial-access: AiTM on internal network, not initial access; drop tactic privilege-escalation: No privesc technique observed |
| Active Directory Certificate Services Denied Certificate Enrollment Request | defense-impairment, t1553.004 | t1649 | replace technique credential-access → T1649 (replaces T1553.004): Denied enrollment (template permission/signature issues) indicates attempted certificate abuse (ESC-style), i.e. Steal or Forge Authentication Certificates; not installing a root cert; drop tactic defense-impairment: Only backed by the wrong T1553.004 |
| Local Privilege Escalation Indicator TabTip | execution | privilege-escalation, stealth, t1134.001 | drop tactic execution: DCOM activation error is an LPE artefact, not execution; add technique privilege-escalation → T1134.001: Rule is an LPE indicator; potato attacks impersonate SYSTEM token - tactic missing entirely today; add stealth (tactic of a tagged technique, required by the SigmaHQ validator) |
| Windows Update Error | impact, resource-development, t1584 | - | drop tactic impact: Update failures are not an adversary impact; replace technique resource-development (replaces T1584): Compromise Infrastructure is unrelated; no ATT&CK technique fits an informational update-error rule - remove all attack tags |
| Mimikatz Use | - | t1550.003 | add technique lateral-movement → T1550.003: kerberos::ptt / kerberos::ptc keywords are pass-the-ticket |

### Changelog

chore: Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted - ATT&CK v19.2 tags: remove impact, credential-access, t1485, t1496, t1489; add persistence, privilege-escalation, t1098.006
chore: Azure Network Firewall Policy Modified or Deleted - ATT&CK v19.2 tags: remove impact
chore: New Root Certificate Authority Added - ATT&CK v19.2 tags: add t1484.002
chore: Google Workspace Government Attack Warning - ATT&CK v19.2 tags: remove impact, t1078; add t1078.004
chore: Data Compressed - ATT&CK v19.2 tags: remove exfiltration
chore: Potentially Suspicious Malware Callback Communication - Linux - ATT&CK v19.2 tags: remove persistence
chore: Kaspersky Endpoint Security Stopped Via CommandLine - Linux - ATT&CK v19.2 tags: remove execution
chore: Mount Execution With Hidepid Parameter - ATT&CK v19.2 tags: remove credential-access
chore: Setuid and Setgid - ATT&CK v19.2 tags: remove persistence
chore: Potential Linux Amazon SSM Agent Hijacking - ATT&CK v19.2 tags: remove persistence, t1219.002; add t1219
chore: Process Execution From Shared Memory Directory - ATT&CK v19.2 tags: remove execution
chore: Linux HackTool Execution - ATT&CK v19.2 tags: remove execution, t1587; add t1588.002
chore: Mask System Power Settings Via Systemctl - ATT&CK v19.2 tags: remove impact
chore: Suspicious Execution via macOS Script Editor - ATT&CK v19.2 tags: remove persistence
chore: PUA - Advanced IP/Port Scanner Update Check - ATT&CK v19.2 tags: remove reconnaissance, t1590; add t1046
chore: F5 BIG-IP iControl Rest API Command Execution - Webserver - ATT&CK v19.2 tags: add t1059.004
chore: MSSQL Destructive Query - ATT&CK v19.2 tags: remove exfiltration
chore: Admin User Remote Logon - ATT&CK v19.2 tags: add t1021.001
chore: RottenPotato Like Attack Pattern - ATT&CK v19.2 tags: add stealth, t1134.001
chore: Remote Task Creation via ATSVC Named Pipe - ATT&CK v19.2 tags: add t1021.002
chore: Possible DC Shadow Attack - ATT&CK v19.2 tags: remove credential-access
chore: Addition of SID History to Active Directory Object - ATT&CK v19.2 tags: add t1098
chore: Suspicious Remote Logon with Explicit Credentials - ATT&CK v19.2 tags: add t1021
chore: Uncommon Outbound Kerberos Connection - Security - ATT&CK v19.2 tags: remove t1558.003; add t1558, t1550.003
chore: Remote Service Activity via SVCCTL Named Pipe - ATT&CK v19.2 tags: add privilege-escalation, t1543.003
chore: ISATAP Router Address Was Set - ATT&CK v19.2 tags: remove initial-access, privilege-escalation, execution
chore: Active Directory Certificate Services Denied Certificate Enrollment Request - ATT&CK v19.2 tags: remove defense-impairment, t1553.004; add t1649
chore: Local Privilege Escalation Indicator TabTip - ATT&CK v19.2 tags: remove execution; add privilege-escalation, stealth, t1134.001
chore: Windows Update Error - ATT&CK v19.2 tags: remove impact, resource-development, t1584
chore: Mimikatz Use - ATT&CK v19.2 tags: add t1550.003

### Example Log Event

N/A (no detection change)

### Fixed Issues

N/A

### SigmaHQ Rule Creation Conventions

- If your PR adds new rules, please consider following and applying these [conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/)

### Validation

- Diff touches only `tags:` lines; each technique checked against the ATT&CK v19.2 STIX bundle (active, tactic coverage both ways).
- Local replica of the repo CI: yamllint (strict), `tests/test_logsource.py`, `tests/test_rules.py`, `sigma check` with the SigmaHQ validators, and 463/463 regression tests pass.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
