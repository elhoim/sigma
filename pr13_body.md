## BLUF

- **What:** corrects ATT&CK tags on 30 rules whose tactic tags were not backed by any tagged technique (pack 5 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 25 unsupported tactic tags removed; 9 rules gained a missing or corrected technique.

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
| Active Directory Structure Export Via Csvde.EXE | exfiltration | - | drop tactic exfiltration: Export to a local file is AD enumeration (T1087.002), not data leaving the network |
| Uncommon Child Process Of Defaultpack.EXE | execution | - | drop tactic execution: Proxy execution via a signed MS binary = T1218 (stealth only in v19); twins appvlp/defaultpack/devinit share this issue |
| Arbitrary MSI Download Via Devinit.EXE | execution | - | drop tactic execution: Proxy execution/download via signed binary (T1218, stealth); same pattern as appvlp/defaultpack. T1105 would be the optional extra for the download aspect |
| PowerShell Web Access Feature Enabled Via DISM | privilege-escalation, t1548.002 | initial-access, t1133 | replace technique persistence → T1133 (replaces T1548.002): T1548.002 (UAC bypass) is wrong - enabling a Windows feature is not a UAC bypass; privilege-escalation drops with it. PWA = externally reachable remote PowerShell gateway (T1133; alt T1505.003), same choice as twin posh_ps_powershell_web_access_installation; add initial-access (tactic of a tagged technique, required by the SigmaHQ validator) |
| Binary Proxy Execution Via Dotnet-Trace.EXE | t1218 | t1127 | replace technique execution → T1127 (replaces T1218): dotnet-trace is a .NET developer utility, not a system binary; T1127 Trusted Developer Utilities Proxy Execution backs both stealth and execution |
| HackTool - PCHunter Execution | execution | - | drop tactic execution: Tool-execution only; rule is about a system inspection/anti-rootkit tool, execution adds nothing |
| HackTool - SharpWSUS/WSUSpendu Execution | t1210 | t1072 | replace technique execution → T1072 (replaces T1210): Pushing payloads via WSUS is Software Deployment Tools (execution+lateral-movement), not exploitation of a remote service vulnerability |
| HackTool - winPEAS Execution | privilege-escalation | - | drop tactic privilege-escalation: winPEAS only enumerates privesc paths; the rule observes discovery, not an escalation |
| Suspicious ZipExec Execution | execution | - | drop tactic execution: Rule targets credential staging for zipfldr-based indirect execution (stealth); T1202/T1218 are stealth-only. Note: T1218 is a weak fit (cmdkey is not a proxy); T1027.015 Compression may be more precise |
| Arbitrary File Download Via IMEWDBLD.EXE | execution | - | drop tactic execution: LOLBin download of arbitrary file; proxy/stealth point, execution not observed. Note: T1105 (command-and-control) would describe the download better, as other download LOLBin rules do |
| MpiExec Lolbin | execution | - | drop tactic execution: Proxy execution via signed HPC binary is T1218 (stealth); execution only because a binary runs |
| Indirect Command Execution By Program Compatibility Wizard | execution | - | drop tactic execution: Proxy/indirect execution (stealth); T1202 would also fit the title but T1218 matches LOLBAS |
| Execute Pcwrun.EXE To Leverage Follina | - | t1203 | add technique execution → T1203: Rule explicitly targets exploitation of the Follina msdt vulnerability to run code: Exploitation for Client Execution |
| Use of Scriptrunner.exe | execution | - | drop tactic execution: Proxy execution / AWL bypass is stealth (T1218) |
| Use Of The SFTP.EXE Binary As A LOLBIN | execution | - | drop tactic execution: Proxy execution via system binary is stealth (T1218) |
| MMC20 Lateral Movement | execution | - | drop tactic execution: Remote DCOM activation is covered by T1021.003; twin mmc_susp_child_process uses lateral-movement only. Alternative: T1559.001 (COM) if execution is wanted |
| MSDT Execution Via Answer File | execution | - | drop tactic execution: msdt proxy execution is T1218 (stealth) |
| Arbitrary File Download Via MSEDGE_PROXY.EXE | execution | - | drop tactic execution: LOLBin download of arbitrary file; proxy/stealth point, execution not observed. Note: T1105 (command-and-control) would describe the download better, as other download LOLBin rules do |
| Remotely Hosted HTA File Executed Via Mshta.EXE | execution | - | drop tactic execution: Mshta proxy execution is T1218.005 (stealth); script-interpreter execution inside the HTA is not observed |
| Arbitrary File Download Via MSOHTMED.EXE | execution | - | drop tactic execution: LOLBin download of arbitrary file; proxy/stealth point, execution not observed. Note: T1105 (command-and-control) would describe the download better, as other download LOLBin rules do |
| Arbitrary File Download Via MSPUB.EXE | execution | - | drop tactic execution: LOLBin download of arbitrary file; proxy/stealth point, execution not observed. Note: T1105 (command-and-control) would describe the download better, as other download LOLBin rules do |
| Suspicious Child Process Of SQL Server | t1505.003, privilege-escalation | t1505.001 | drop tactic privilege-escalation: Nothing in the rule indicates escalation; child runs as the SQL service account; replace technique persistence → T1505.001 (replaces T1505.003): Web Shell is wrong for sqlservr.exe children; xp_cmdshell/stored-procedure abuse is T1505.001 SQL Stored Procedures |
| New Port Forwarding Rule Added Via Netsh.EXE | lateral-movement | - | drop tactic lateral-movement: Rule observes proxy/pivot configuration (C2), not use of a remote service. Note: T1090.001 Internal Proxy is more specific than T1090. Registry twin registry_event_portproxy_registry_key.yml has same issue |
| Service StartupType Change Via PowerShell Set-Service | execution | - | drop tactic execution: Point is disabling services (defense impairment); PowerShell use is incidental. Twin sc_disable_service same |
| Arbitrary File Download Via PresentationHost.EXE | execution | - | drop tactic execution: LOLBin download of arbitrary file; proxy/stealth point, execution not observed. Note: T1105 (command-and-control) would describe the download better, as other download LOLBin rules do |
| XBAP Execution From Uncommon Locations Via PresentationHost.EXE | execution | - | drop tactic execution: XBAP proxy execution to bypass AWL is T1218 (stealth) |
| Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution | t1218 | t1127 | replace technique execution → T1127 (replaces T1218): PressAnyKey is a Visual Studio developer utility; Trusted Developer Utilities Proxy Execution (stealth+execution) is the precise technique |
| PUA - Crassus Execution | reconnaissance, t1590.001 | t1083 | replace technique discovery → T1083 (replaces T1590.001): Crassus runs on the host parsing ProcMon data for writable paths/missing DLLs; T1590.001 (pre-compromise Domain Properties recon) is wrong. T1083 is the closest discovery technique; T1574.001 (planning DLL hijacks) is an alternative; drop tactic reconnaissance: Post-compromise host tool, not pre-compromise reconnaissance; loses its only backing once T1590.001 is removed |
| PUA - Wsudo Suspicious Execution | - | stealth, t1134.002 | add technique privilege-escalation → T1134.002: Launching processes as SYSTEM/TrustedInstaller via stolen/duplicated tokens is Access Token Manipulation: Create Process with Token (T1134/T1134.001 are alternatives); add stealth (tactic of a tagged technique, required by the SigmaHQ validator) |
| Exports Critical Registry Keys To a File | exfiltration | credential-access, t1003.002 | drop tactic exfiltration: Exporting a key to a local file is not exfiltration; add technique credential-access → T1003.002: Export of SAM/SYSTEM/SECURITY hives is the rule's real intent: OS Credential Dumping: Security Account Manager |

### Changelog

chore: Active Directory Structure Export Via Csvde.EXE - ATT&CK v19.2 tags: remove exfiltration
chore: Uncommon Child Process Of Defaultpack.EXE - ATT&CK v19.2 tags: remove execution
chore: Arbitrary MSI Download Via Devinit.EXE - ATT&CK v19.2 tags: remove execution
chore: PowerShell Web Access Feature Enabled Via DISM - ATT&CK v19.2 tags: remove privilege-escalation, t1548.002; add initial-access, t1133
chore: Binary Proxy Execution Via Dotnet-Trace.EXE - ATT&CK v19.2 tags: remove t1218; add t1127
chore: HackTool - PCHunter Execution - ATT&CK v19.2 tags: remove execution
chore: HackTool - SharpWSUS/WSUSpendu Execution - ATT&CK v19.2 tags: remove t1210; add t1072
chore: HackTool - winPEAS Execution - ATT&CK v19.2 tags: remove privilege-escalation
chore: Suspicious ZipExec Execution - ATT&CK v19.2 tags: remove execution
chore: Arbitrary File Download Via IMEWDBLD.EXE - ATT&CK v19.2 tags: remove execution
chore: MpiExec Lolbin - ATT&CK v19.2 tags: remove execution
chore: Indirect Command Execution By Program Compatibility Wizard - ATT&CK v19.2 tags: remove execution
chore: Execute Pcwrun.EXE To Leverage Follina - ATT&CK v19.2 tags: add t1203
chore: Use of Scriptrunner.exe - ATT&CK v19.2 tags: remove execution
chore: Use Of The SFTP.EXE Binary As A LOLBIN - ATT&CK v19.2 tags: remove execution
chore: MMC20 Lateral Movement - ATT&CK v19.2 tags: remove execution
chore: MSDT Execution Via Answer File - ATT&CK v19.2 tags: remove execution
chore: Arbitrary File Download Via MSEDGE_PROXY.EXE - ATT&CK v19.2 tags: remove execution
chore: Remotely Hosted HTA File Executed Via Mshta.EXE - ATT&CK v19.2 tags: remove execution
chore: Arbitrary File Download Via MSOHTMED.EXE - ATT&CK v19.2 tags: remove execution
chore: Arbitrary File Download Via MSPUB.EXE - ATT&CK v19.2 tags: remove execution
chore: Suspicious Child Process Of SQL Server - ATT&CK v19.2 tags: remove t1505.003, privilege-escalation; add t1505.001
chore: New Port Forwarding Rule Added Via Netsh.EXE - ATT&CK v19.2 tags: remove lateral-movement
chore: Service StartupType Change Via PowerShell Set-Service - ATT&CK v19.2 tags: remove execution
chore: Arbitrary File Download Via PresentationHost.EXE - ATT&CK v19.2 tags: remove execution
chore: XBAP Execution From Uncommon Locations Via PresentationHost.EXE - ATT&CK v19.2 tags: remove execution
chore: Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution - ATT&CK v19.2 tags: remove t1218; add t1127
chore: PUA - Crassus Execution - ATT&CK v19.2 tags: remove reconnaissance, t1590.001; add t1083
chore: PUA - Wsudo Suspicious Execution - ATT&CK v19.2 tags: add stealth, t1134.002
chore: Exports Critical Registry Keys To a File - ATT&CK v19.2 tags: remove exfiltration; add credential-access, t1003.002

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
