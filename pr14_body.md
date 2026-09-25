## BLUF

- **What:** corrects ATT&CK tags on 30 rules whose tactic tags were not backed by any tagged technique (pack 6 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 26 unsupported tactic tags removed; 17 rules gained a missing or corrected technique.

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
| Exports Registry Key To a File | exfiltration | - | drop tactic exfiltration: Exporting a key to a local file is not exfiltration; Query Registry (discovery) covers it. Twin critical-keys rule same |
| Renamed Jusched.EXE Execution | execution | - | drop tactic execution: Rule detects masquerading via renamed utility (stealth); execution only because a process starts |
| Visual Studio NodejsTools PressAnyKey Renamed Execution | t1218 | t1127, t1036.003 | replace technique execution → T1127 (replaces T1218): Visual Studio developer utility used as LOLBin -> Trusted Developer Utilities Proxy Execution (stealth+execution); consistent with twin pressanykey_lolbin_execution; add technique stealth → T1036.003: The rule's core observation is a renamed legitimate utility |
| Shell32 DLL Execution in Suspicious Directory | execution | - | drop tactic execution: Rundll32 proxy execution is T1218.011 (stealth) |
| Potentially Suspicious Rundll32.EXE Execution of UDL File | - | t1204.002 | add technique execution → T1204.002: Explorer parent + file in Downloads = user opening a delivered malicious .udl file (User Execution: Malicious File) |
| Rundll32 UNC Path Execution | execution | - | drop tactic execution: Rundll32 proxy execution is stealth (T1218.011). Note: T1021.002/lateral-movement is also questionable - loading a DLL from a share is not remote service use |
| Service StartupType Change Via Sc.EXE | execution | - | drop tactic execution: Point is disabling services (defense impairment); sc.exe use is incidental. Twin powershell_set_service_disabled same |
| Potential SSH Tunnel Persistence Install Using A Scheduled Task | - | t1572 | add technique command-and-control → T1572: scheduled ssh/sshd reverse tunnel to attacker server = Protocol Tunneling |
| Arbitrary File Download Via Squirrel.EXE | execution | command-and-control, t1105 | drop tactic execution: rule observes a download via a signed proxy binary, nothing is executed; add technique command-and-control → T1105: optional but matches title (arbitrary file download); consistent with dns_query_win_appinstaller twin tagging T1105 |
| Process Proxy Execution Via Squirrel.EXE | execution | - | drop tactic execution: point is proxy execution via signed binary (T1218, stealth); twin squirrel_download has same issue |
| Potential Amazon SSM Agent Hijacking | persistence, t1219.002 | t1219 | drop tactic persistence: no ATT&CK persistence technique cleanly describes re-registering a remote-management agent; behaviour is remote access/C2; replace technique command-and-control → T1219 (replaces T1219.002): SSM agent is not remote desktop (GUI) software; parent Remote Access Tools fits |
| Writing Of Malicious Files To The Fonts Folder | t1211, persistence | t1036.005 | drop tactic persistence: rule only observes staging files in Fonts folder; no persistence mechanism; replace technique stealth → T1036.005 (replaces T1211): no exploitation involved; hiding payload in a legitimate system directory = Match Legitimate Resource Name or Location |
| Suspicious LNK Command-Line Padding with Whitespace Characters | initial-access | stealth, t1027.010 | drop tactic initial-access: delivery (phishing) is not observed; rule sees user-executed LNK (T1204.002 execution); add technique stealth → T1027.010: optional: core intent is hiding the command beyond the UI limit via padding = Command Obfuscation |
| Potential File Download Via MS-AppInstaller Protocol Handler | execution | command-and-control, t1105 | drop tactic execution: rule observes a download through a protocol handler, not execution; add technique command-and-control → T1105: optional; matches title and derived dns_query_win_appinstaller rule which tags T1105 |
| Suspicious Velociraptor Child Process | persistence | - | drop tactic persistence: children observed are tunnel/remote access and payload download, not a persistence mechanism (T1219 is C2 only) |
| Sysinternals PsService Execution | - | t1007 | add technique discovery → T1007: description names service reconnaissance = System Service Discovery |
| Sysinternals PsSuspend Execution | privilege-escalation, discovery, persistence, t1543.003 | defense-impairment, t1685 | drop tactic discovery: suspending processes is not discovery; replace technique defense-impairment → T1685 (replaces T1543.003): PsSuspend does not create/modify services; abuse is suspending security processes; matches similar rule pssuspend_susp_execution (defense-impairment, t1685); drops the privilege-escalation/persistence it wrongly backed |
| Potential Binary Impersonating Sysinternals Tools | execution, t1218, t1202 | - | drop tactic execution: rule detects masquerading, not an execution technique; replace technique stealth → T1036.005 (replaces T1218, T1202): no proxy/indirect execution is observed; remove t1218 and t1202, T1036.005 already tagged and backs stealth |
| Compressed File Creation Via Tar.EXE | exfiltration | - | drop tactic exfiltration: archiving is collection (T1560.001); no exfiltration observed |
| Compressed File Extraction Via Tar.EXE | collection, exfiltration, t1560, t1560.001 | stealth, t1140 | drop tactic exfiltration: extraction is not exfiltration; replace technique stealth → T1140 (replaces T1560, T1560.001): extracting an archive is not Archive Collected Data; description says decompressing to avoid detection = Deobfuscate/Decode Files; also drops collection |
| CMSTP UAC Bypass via COM Object Access | execution | - | drop tactic execution: UAC bypass (priv-esc) plus CMSTP proxy (stealth); no execution technique observed |
| UAC Bypass Using IDiagnostic Profile | execution | - | drop tactic execution: rule observes a UAC bypass (T1548.002), privilege-escalation only |
| Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | - | privilege-escalation, t1546 | add technique persistence → T1546: script configured to run on VM power/resume/suspend events = Event Triggered Execution (no fitting sub-technique); same fix for _susp twin |
| Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | - | privilege-escalation, t1546 | add technique persistence → T1546: VM state-change script = Event Triggered Execution; keep consistent with non-susp twin |
| VMToolsd Suspicious Child Process | - | privilege-escalation, t1546 | add technique persistence → T1546: children of vmtoolsd are the VM state-change scripts firing (description: persistence setup) = Event Triggered Execution; could alternatively DROP since rule observes the trigger not setup |
| Potentially Suspicious Child Process Of VsCode | t1218 | t1127 | replace technique execution → T1127 (replaces T1218): VS Code is a trusted developer utility, not a system binary; T1127 Trusted Developer Utilities Proxy Execution backs both stealth and execution. Alternative: keep T1218 and add T1059 |
| Whoami.EXE Execution From Privileged Process | privilege-escalation | - | drop tactic privilege-escalation: rule observes user discovery (T1033) in a privileged context; the escalation itself is not observed |
| Security Privileges Enumeration Via Whoami.EXE | privilege-escalation | - | drop tactic privilege-escalation: enumerating privileges is discovery (T1033); no escalation observed |
| Suspicious Processes Spawned by WinRM | t1190, initial-access, persistence, privilege-escalation | lateral-movement, t1021.006 | drop tactic persistence: no persistence mechanism observed; drop tactic privilege-escalation: no escalation observed; replace technique lateral-movement → T1021.006 (replaces T1190): WinRM remote session is Remote Services: WinRM, not exploitation of a public-facing app; also drops initial-access |
| Computer System Reconnaissance Via Wmic.EXE | - | t1082 | add technique discovery → T1082: computersystem query = System Information Discovery |

### Changelog

chore: Exports Registry Key To a File - ATT&CK v19.2 tags: remove exfiltration
chore: Renamed Jusched.EXE Execution - ATT&CK v19.2 tags: remove execution
chore: Visual Studio NodejsTools PressAnyKey Renamed Execution - ATT&CK v19.2 tags: remove t1218; add t1127, t1036.003
chore: Shell32 DLL Execution in Suspicious Directory - ATT&CK v19.2 tags: remove execution
chore: Potentially Suspicious Rundll32.EXE Execution of UDL File - ATT&CK v19.2 tags: add t1204.002
chore: Rundll32 UNC Path Execution - ATT&CK v19.2 tags: remove execution
chore: Service StartupType Change Via Sc.EXE - ATT&CK v19.2 tags: remove execution
chore: Potential SSH Tunnel Persistence Install Using A Scheduled Task - ATT&CK v19.2 tags: add t1572
chore: Arbitrary File Download Via Squirrel.EXE - ATT&CK v19.2 tags: remove execution; add command-and-control, t1105
chore: Process Proxy Execution Via Squirrel.EXE - ATT&CK v19.2 tags: remove execution
chore: Potential Amazon SSM Agent Hijacking - ATT&CK v19.2 tags: remove persistence, t1219.002; add t1219
chore: Writing Of Malicious Files To The Fonts Folder - ATT&CK v19.2 tags: remove t1211, persistence; add t1036.005
chore: Suspicious LNK Command-Line Padding with Whitespace Characters - ATT&CK v19.2 tags: remove initial-access; add stealth, t1027.010
chore: Potential File Download Via MS-AppInstaller Protocol Handler - ATT&CK v19.2 tags: remove execution; add command-and-control, t1105
chore: Suspicious Velociraptor Child Process - ATT&CK v19.2 tags: remove persistence
chore: Sysinternals PsService Execution - ATT&CK v19.2 tags: add t1007
chore: Sysinternals PsSuspend Execution - ATT&CK v19.2 tags: remove privilege-escalation, discovery, persistence, t1543.003; add defense-impairment, t1685
chore: Potential Binary Impersonating Sysinternals Tools - ATT&CK v19.2 tags: remove execution, t1218, t1202
chore: Compressed File Creation Via Tar.EXE - ATT&CK v19.2 tags: remove exfiltration
chore: Compressed File Extraction Via Tar.EXE - ATT&CK v19.2 tags: remove collection, exfiltration, t1560, t1560.001; add stealth, t1140
chore: CMSTP UAC Bypass via COM Object Access - ATT&CK v19.2 tags: remove execution
chore: UAC Bypass Using IDiagnostic Profile - ATT&CK v19.2 tags: remove execution
chore: Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script - ATT&CK v19.2 tags: add privilege-escalation, t1546
chore: Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script - ATT&CK v19.2 tags: add privilege-escalation, t1546
chore: VMToolsd Suspicious Child Process - ATT&CK v19.2 tags: add privilege-escalation, t1546
chore: Potentially Suspicious Child Process Of VsCode - ATT&CK v19.2 tags: remove t1218; add t1127
chore: Whoami.EXE Execution From Privileged Process - ATT&CK v19.2 tags: remove privilege-escalation
chore: Security Privileges Enumeration Via Whoami.EXE - ATT&CK v19.2 tags: remove privilege-escalation
chore: Suspicious Processes Spawned by WinRM - ATT&CK v19.2 tags: remove t1190, initial-access, persistence, privilege-escalation; add lateral-movement, t1021.006
chore: Computer System Reconnaissance Via Wmic.EXE - ATT&CK v19.2 tags: add t1082

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
