## BLUF

- **What:** corrects ATT&CK tags on 30 rules whose tactic tags were not backed by any tagged technique (pack 2 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 24 unsupported tactic tags removed; 12 rules gained a missing or corrected technique.

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
| ADCS - Certighost CDC Chase Certificate Request (CVE-2026-54121) | - | t1068 | add technique privilege-escalation → T1068: Exploits CA vulnerability CVE-2026-54121 to obtain a DC certificate -> domain-level privilege |
| ADCS - Certighost Certificate Issued via CDC Chase (CVE-2026-54121) | - | t1068 | add technique privilege-escalation → T1068: Exploits CA vulnerability CVE-2026-54121 to obtain a DC certificate -> domain-level privilege |
| ADCS - Certighost Ghost Machine Account Creation | - | t1068 | add technique privilege-escalation → T1068: High-fidelity indicator of the Certighost exploit tool; consistent with sibling rules. Alternative: drop privesc since account creation itself is only a precursor |
| Interactive Logon to Server Systems | lateral-movement | - | drop tactic lateral-movement: LogonType 2 is local console logon, not remote; RDP (type 10) is not matched |
| Inbox Rules Creation Or Update Activity in O365 | exfiltration | - | drop tactic exfiltration: Rule matches hiding/filtering parameters, not ForwardTo/RedirectTo; no exfil observed. T1114.003 already covers the forwarding/collection angle |
| Clipboard Data Collection Via Pbpaste | credential-access | - | drop tactic credential-access: Clipboard read is T1115 Collection; possible passwords in clipboard does not make it a credential-access technique |
| Low Reputation Effective Top-Level Domain (eTLD) | initial-access | - | drop tactic initial-access: DNS resolution of bad-reputation domains is C2/beaconing evidence (T1071.004); nothing ties it to an initial-access vector |
| Compress-Archive Cmdlet Execution | exfiltration | - | drop tactic exfiltration: Archiving is T1560 Collection; no transfer is observed |
| Inbox Rules Creation Or Update Activity Via ExchangePowerShell Cmdlet | exfiltration | - | drop tactic exfiltration: Same as the M365 twin: matches hiding parameters, not forwarding; no exfil observed |
| Diskshadow Child Process Spawned | execution | - | drop tactic execution: LOLBin proxy execution; T1218 (stealth) is the point. The rules/ twins (diskshadow_child_process_susp, script_mode_susp_*) carry only stealth/T1218 |
| Diskshadow Script Mode Execution | execution | - | drop tactic execution: Same as the diskshadow child-process twin: proxy execution via T1218 only; the rules/ twins carry only stealth/T1218 |
| Process Execution From WebDAV Share | lateral-movement | t1204.002 | add technique execution → T1204.002: Remote payload runs from an attacker WebDAV share, usually after a user opens a lure (CVE-2025-33053 .url case); drop tactic lateral-movement: DavWWWRoot servers are typically external and attacker-controlled; no remote-service technique (T1021.002 is SMB, not WebDAV) fits |
| Arbitrary Command Execution Using WSL | execution | - | drop tactic execution: Rule is about proxy/indirect execution via a LOLBin (T1202/T1218, stealth). Twin proc_creation_win_wsl_child_processes_anomalies.yml has the same execution issue; wsl_windows_binaries_execution also tags execution with only T1202 |
| Github Delete Action Invoked | collection, t1213.003 | t1485 | replace technique impact → T1485 (replaces T1213.003): Deleting repos, projects or environments is Data Destruction (impact). T1213.003 (collecting data from code repos) does not describe deletion; drop tactic collection: Only backed by the removed T1213.003; nothing is collected |
| Github Fork Private Repositories Setting Enabled/Cleared | persistence | - | drop tactic persistence: Allowing private forks enables copying code to another account (T1537, exfiltration); no persistence mechanism |
| GitHub Repository Pages Site Changed to Public | collection | - | drop tactic collection: Exposing content publicly is exfil/exposure (T1567.001); nothing is collected |
| Github Repository/Organization Transferred | persistence | - | drop tactic persistence: Transferring a repo or org out is exfiltration (T1537); no persistence. T1020 (automated) is a weak fit but was left alone |
| Github Self Hosted Runner Changes Detected | impact | - | drop tactic impact: Runner changes are not an impact technique. The existing T1526/T1213.003/T1078.004 set is also loose (a malicious runner is closer to execution or persistence) but was out of scope and left alone |
| OpenCanary - FTP Login Attempt | exfiltration | - | drop tactic exfiltration: A login attempt is not data transfer. Folder twin opencanary_tftp_request.yml also uses exfiltration/T1041 |
| OpenCanary - HTTPPROXY Login Attempt | initial-access | - | drop tactic initial-access: Using an open proxy is T1090 C2/proxy activity; no initial-access vector |
| OpenCanary - Telnet Login Attempt | command-and-control | - | drop tactic command-and-control: A telnet login is remote-service access (T1133/T1078), not C2. The SSH twins use lateral-movement/T1021 instead |
| Remote Schedule Task Lateral Movement via ATSvc | - | t1021.002 | add technique lateral-movement → T1021.002: ATSvc is reached over the \\pipe\atsvc SMB named pipe. The T1021.002 text names remote RPC over admin shares with Scheduled Task as the execution method |
| Remote Schedule Task Lateral Movement via ITaskSchedulerService | t1053.002 | t1053.005, t1021.002 | add technique lateral-movement → T1021.002: Remote task registration over RPC via admin-share/SMB named pipe, as the T1021.002 text describes (the interface can also run over TCP); replace technique execution → T1053.005 (replaces T1053.002): ITaskSchedulerService is the Task Scheduler (schtasks) interface, not the At service. Tactics unchanged |
| Remote Registry Lateral Movement | - | t1021.002 | add technique lateral-movement → T1021.002: Remote Registry is RPC over the \\pipe\winreg SMB named pipe with admin creds (T1021.002). T1112 already covers the modification itself |
| Remote Server Service Abuse for Lateral Movement | - | t1021.002 | add technique lateral-movement → T1021.002: PsExec-style remote service control over \\pipe\svcctl SMB named pipe. The rule description wrongly says MS-EFSR; the UUID and reference are MS-SCMR |
| Remote Schedule Task Lateral Movement via SASec | - | t1021.002 | add technique lateral-movement → T1021.002: Remote scheduled-task RPC over SMB named pipe, as with the ATSvc and ITaskSchedulerService twins. T1053.002 vs .005 for SASec (legacy Task Scheduler agent) is debatable and was left alone |
| Potential Malicious Usage of CloudTrail System Manager | privilege-escalation, initial-access, t1566, t1566.002 | execution, t1651 | replace technique privilege-escalation → T1651 (replaces T1566): SSM Run Command is exactly T1651 Cloud Administration Command (execution). T1566/T1566.002 Phishing are wrong, so both privilege-escalation and initial-access go |
| Azure Firewall Modified or Deleted | impact | - | drop tactic impact: Firewall modification is defense impairment (T1686.001); no impact technique |
| Azure Firewall Rule Collection Modified or Deleted | impact | - | drop tactic impact: Same as the firewall twin: covered by T1686.001 |
| Azure Kubernetes Network Policy Change | impact, credential-access, t1485, t1496, t1489 | defense-impairment, t1686.001 | drop tactic credential-access: Nothing credential-related is observed; replace technique impact → T1686.001 (replaces T1485): The copied T1485/T1496/T1489 set does not describe policy changes. Loosening NetworkPolicies is disabling a cloud firewall (T1686.001, defense-impairment). The same copied set appears on azure_kubernetes_role_access, secret_or_config_object_access, cluster_created_or_deleted and service_account_modified_or_deleted |

### Changelog

chore: ADCS - Certighost CDC Chase Certificate Request (CVE-2026-54121) - ATT&CK v19.2 tags: add t1068
chore: ADCS - Certighost Certificate Issued via CDC Chase (CVE-2026-54121) - ATT&CK v19.2 tags: add t1068
chore: ADCS - Certighost Ghost Machine Account Creation - ATT&CK v19.2 tags: add t1068
chore: Interactive Logon to Server Systems - ATT&CK v19.2 tags: remove lateral-movement
chore: Inbox Rules Creation Or Update Activity in O365 - ATT&CK v19.2 tags: remove exfiltration
chore: Clipboard Data Collection Via Pbpaste - ATT&CK v19.2 tags: remove credential-access
chore: Low Reputation Effective Top-Level Domain (eTLD) - ATT&CK v19.2 tags: remove initial-access
chore: Compress-Archive Cmdlet Execution - ATT&CK v19.2 tags: remove exfiltration
chore: Inbox Rules Creation Or Update Activity Via ExchangePowerShell Cmdlet - ATT&CK v19.2 tags: remove exfiltration
chore: Diskshadow Child Process Spawned - ATT&CK v19.2 tags: remove execution
chore: Diskshadow Script Mode Execution - ATT&CK v19.2 tags: remove execution
chore: Process Execution From WebDAV Share - ATT&CK v19.2 tags: remove lateral-movement; add t1204.002
chore: Arbitrary Command Execution Using WSL - ATT&CK v19.2 tags: remove execution
chore: Github Delete Action Invoked - ATT&CK v19.2 tags: remove collection, t1213.003; add t1485
chore: Github Fork Private Repositories Setting Enabled/Cleared - ATT&CK v19.2 tags: remove persistence
chore: GitHub Repository Pages Site Changed to Public - ATT&CK v19.2 tags: remove collection
chore: Github Repository/Organization Transferred - ATT&CK v19.2 tags: remove persistence
chore: Github Self Hosted Runner Changes Detected - ATT&CK v19.2 tags: remove impact
chore: OpenCanary - FTP Login Attempt - ATT&CK v19.2 tags: remove exfiltration
chore: OpenCanary - HTTPPROXY Login Attempt - ATT&CK v19.2 tags: remove initial-access
chore: OpenCanary - Telnet Login Attempt - ATT&CK v19.2 tags: remove command-and-control
chore: Remote Schedule Task Lateral Movement via ATSvc - ATT&CK v19.2 tags: add t1021.002
chore: Remote Schedule Task Lateral Movement via ITaskSchedulerService - ATT&CK v19.2 tags: remove t1053.002; add t1053.005, t1021.002
chore: Remote Registry Lateral Movement - ATT&CK v19.2 tags: add t1021.002
chore: Remote Server Service Abuse for Lateral Movement - ATT&CK v19.2 tags: add t1021.002
chore: Remote Schedule Task Lateral Movement via SASec - ATT&CK v19.2 tags: add t1021.002
chore: Potential Malicious Usage of CloudTrail System Manager - ATT&CK v19.2 tags: remove privilege-escalation, initial-access, t1566, t1566.002; add execution, t1651
chore: Azure Firewall Modified or Deleted - ATT&CK v19.2 tags: remove impact
chore: Azure Firewall Rule Collection Modified or Deleted - ATT&CK v19.2 tags: remove impact
chore: Azure Kubernetes Network Policy Change - ATT&CK v19.2 tags: remove impact, credential-access, t1485, t1496, t1489; add defense-impairment, t1686.001

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
