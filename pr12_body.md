## BLUF

- **What:** corrects ATT&CK tags on 30 rules whose tactic tags were not backed by any tagged technique (pack 4 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 24 unsupported tactic tags removed; 13 rules gained a missing or corrected technique.

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
| PSExec and WMI Process Creations Block | - | t1021.002 | add technique lateral-movement → T1021.002: PsExec (psexesvc) is remote execution over SMB admin shares |
| DNS Query Request By QuickAssist.EXE | initial-access, lateral-movement, t1071.001, t1210 | t1219.002 | drop tactic initial-access: Rule sees a remote-support session; the vishing (T1566.004) that precedes it is not observable here. Twin proc_creation_win_quickassist_execution uses only C2/T1219.002; replace technique lateral-movement → T1219.002 (replaces T1210): T1210 (exploitation of remote services) is wrong; T1071.001 also imprecise. Quick Assist = remote desktop software (C2); lateral-movement drops with T1210; replace technique command-and-control → T1219.002 (replaces T1071.001): Align with twin rule: remote access software, not generic web protocol C2 |
| Created Files by Microsoft Sync Center | execution | - | drop tactic execution: Rule is about injection into/abuse of mobsync (T1055/T1218); no execution technique observed. Twin net_connection_win_susp_outbound_mobsync_connection has same issue |
| Potential File Extension Spoofing Using Right-to-Left Override | execution | - | drop tactic execution: Observes spoofed file name creation (masquerading); user execution (T1204.002) not observed. Twin proc_creation_win_susp_right_to_left_override uses stealth/T1036.002 only |
| Process Explorer Driver Creation By Non-Sysinternals Binary | persistence | - | drop tactic persistence: Driver is dropped briefly for privilege abuse/EDR killing, not for persistence; only file creation is observed. Twin file_event_win_susp_procexplorer_driver_created_in_tmp_folder uses defense-impairment/T1685 (possible alternative for procexp: T1685, AUKill) |
| Process Monitor Driver Creation By Non-Sysinternals Binary | persistence | - | drop tactic persistence: Driver is dropped briefly for privilege abuse/EDR killing, not for persistence; only file creation is observed. Twin file_event_win_susp_procexplorer_driver_created_in_tmp_folder uses defense-impairment/T1685 (possible alternative for procexp: T1685, AUKill) |
| PSEXEC Remote Execution File Artefact | t1136.002 | t1569.002 | add technique execution → T1569.002: PsExec executes commands via a remotely created service (Service Execution); replace technique persistence (replaces T1136.002): T1136.002 (create domain account) is unrelated to PsExec; remove. Persistence remains backed by T1543.003 |
| UAC Bypass Using IDiagnostic Profile - File | execution | - | drop tactic execution: UAC bypass (T1548.002) is privilege escalation; nothing execution-specific observed |
| Wmiexec Default Output File | - | t1021.002 | add technique lateral-movement → T1021.002: wmiexec writes command output to an admin share and retrieves it over SMB; the observed file is that admin-share artefact |
| Writing Local Admin Share | privilege-escalation, persistence, t1546.002 | t1021.002 | replace technique lateral-movement → T1021.002 (replaces T1546.002): T1546.002 (Screensaver) is plainly wrong; reference is the Atomic T1021.002 test. Priv-esc/persistence were only backed by the wrong technique and are dropped |
| WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load | lateral-movement | - | drop tactic lateral-movement: Local event consumer execution; rule cannot tell if the subscription was created remotely and no lateral-movement technique fits (remote WMI maps to T1047/execution). Twin proc_creation_win_wmi_persistence_script_event_consumer uses persistence/priv-esc/T1546.003 only |
| Outbound Network Connection Initiated By Microsoft Dialer | execution | - | drop tactic execution: Rule observes C2 traffic from a hollowed/injected dialer; no execution technique. (T1055 would be the extra candidate if desired, but not needed) |
| Network Connection Initiated Via Notepad.EXE | execution | t1071 | add technique command-and-control → T1071: Connection from an injected beacon is C2; protocol/port unconstrained so parent Application Layer Protocol; drop tactic execution: Nothing execution-specific observed; injection covered by T1055 |
| Remote Access Tool - AnyDesk Incoming Connection | persistence | - | drop tactic persistence: Remote-access-tool C2 session; all sibling AnyDesk/RAT rules use only command-and-control/T1219.002 |
| Rundll32 Internet Connection | execution | - | drop tactic execution: Rundll32 proxy execution is stealth only in v19 (T1218.011) |
| Potentially Suspicious Malware Callback Communication | persistence | - | drop tactic persistence: Non-standard-port C2 traffic; nothing persistence-related. Same issue in its similar/twin callback-port rule |
| Communication To Uncommon Destination Ports | persistence | - | drop tactic persistence: Non-standard-port C2 traffic; nothing persistence-related. Same issue in its similar/twin callback-port rule |
| Microsoft Sync Center Suspicious Network Connections | execution | - | drop tactic execution: Same as twin file_event_win_susp_creation_by_mobsync: injection/proxy, no execution technique |
| Outbound Network Connection To Public IP Via Winlogon | execution, t1218.011 | privilege-escalation, t1055, t1071 | replace technique stealth → T1055 (replaces T1218.011): T1218.011 (Rundll32) is wrong - winlogon is not rundll32; BlackLotus injects its payload into winlogon.exe; add technique command-and-control → T1071: Outbound C2 from injected winlogon; BlackLotus uses HTTP but the rule does not constrain protocol, so parent T1071; drop tactic execution: No execution technique observed; add privilege-escalation (tactic of a tagged technique, required by the SigmaHQ validator) |
| PowerShell ADRecon Execution | - | t1087.002 | add technique discovery → T1087.002: ADRecon enumerates AD users/groups/GPOs/trusts; T1087.002 is the core behaviour (T1069.002/T1482/T1615 also apply, cf. AdFind rule tagging) |
| AMSI Bypass Pattern Assembly GetType | execution | - | drop tactic execution: Rule's point is AMSI tampering (defense impairment); execution only because PowerShell runs |
| PowerShell Credential Prompt | - | collection, t1056.002 | add technique credential-access → T1056.002: GUI Input Capture; matches credui image-load rule tagging; add collection (tactic of a tagged technique, required by the SigmaHQ validator) |
| Potential Adplus.EXE Abuse | - | stealth, t1127 | add technique execution → T1127: AdPlus (Windows SDK debugging tools) can run arbitrary commands via -sc/-c = Trusted Developer Utilities Proxy Execution (stealth+execution); add stealth (tactic of a tagged technique, required by the SigmaHQ validator) |
| Uncommon Child Process Of Appvlp.EXE | execution | - | drop tactic execution: Proxy execution via a signed MS binary = T1218 (stealth only in v19); twins appvlp/defaultpack/devinit share this issue |
| Potential Data Stealing Via Chromium Headless Debugging | - | t1539 | add technique credential-access → T1539: Referenced technique (cookie_crimes) dumps session cookies via DevTools = Steal Web Session Cookie |
| Browser Started with Remote Debugging | - | t1539 | add technique credential-access → T1539: References (cookie_crimes, firefox-cookiemonster, LastPass) use debugging to steal cookies/secrets; consistent with derived headless rule |
| File Download From IP Based URL Via CertOC.EXE | execution | - | drop tactic execution: Pure ingress tool transfer; twin proc_creation_win_certoc_download is C2/T1105 only |
| Potential Arbitrary File Download Via Cmdl32.EXE | execution, t1202 | command-and-control, t1105 | drop tactic execution: Rule is about a download via a signed binary, not execution; replace technique command-and-control → T1105 (replaces T1202): Title/LOLBAS mapping is file download (T1105); T1202 indirect command execution does not describe cmdl32 abuse |
| CMSTP Execution Process Creation | execution | - | drop tactic execution: CMSTP proxy execution is stealth-only T1218.003 in v19 |
| Control Panel Items | execution | - | drop tactic execution: CPL proxy execution is T1218.002 (stealth); CPL registration covered by persistence/T1546 |

### Changelog

chore: PSExec and WMI Process Creations Block - ATT&CK v19.2 tags: add t1021.002
chore: DNS Query Request By QuickAssist.EXE - ATT&CK v19.2 tags: remove initial-access, lateral-movement, t1071.001, t1210; add t1219.002
chore: Created Files by Microsoft Sync Center - ATT&CK v19.2 tags: remove execution
chore: Potential File Extension Spoofing Using Right-to-Left Override - ATT&CK v19.2 tags: remove execution
chore: Process Explorer Driver Creation By Non-Sysinternals Binary - ATT&CK v19.2 tags: remove persistence
chore: Process Monitor Driver Creation By Non-Sysinternals Binary - ATT&CK v19.2 tags: remove persistence
chore: PSEXEC Remote Execution File Artefact - ATT&CK v19.2 tags: remove t1136.002; add t1569.002
chore: UAC Bypass Using IDiagnostic Profile - File - ATT&CK v19.2 tags: remove execution
chore: Wmiexec Default Output File - ATT&CK v19.2 tags: add t1021.002
chore: Writing Local Admin Share - ATT&CK v19.2 tags: remove privilege-escalation, persistence, t1546.002; add t1021.002
chore: WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load - ATT&CK v19.2 tags: remove lateral-movement
chore: Outbound Network Connection Initiated By Microsoft Dialer - ATT&CK v19.2 tags: remove execution
chore: Network Connection Initiated Via Notepad.EXE - ATT&CK v19.2 tags: remove execution; add t1071
chore: Remote Access Tool - AnyDesk Incoming Connection - ATT&CK v19.2 tags: remove persistence
chore: Rundll32 Internet Connection - ATT&CK v19.2 tags: remove execution
chore: Potentially Suspicious Malware Callback Communication - ATT&CK v19.2 tags: remove persistence
chore: Communication To Uncommon Destination Ports - ATT&CK v19.2 tags: remove persistence
chore: Microsoft Sync Center Suspicious Network Connections - ATT&CK v19.2 tags: remove execution
chore: Outbound Network Connection To Public IP Via Winlogon - ATT&CK v19.2 tags: remove execution, t1218.011; add privilege-escalation, t1055, t1071
chore: PowerShell ADRecon Execution - ATT&CK v19.2 tags: add t1087.002
chore: AMSI Bypass Pattern Assembly GetType - ATT&CK v19.2 tags: remove execution
chore: PowerShell Credential Prompt - ATT&CK v19.2 tags: add collection, t1056.002
chore: Potential Adplus.EXE Abuse - ATT&CK v19.2 tags: add stealth, t1127
chore: Uncommon Child Process Of Appvlp.EXE - ATT&CK v19.2 tags: remove execution
chore: Potential Data Stealing Via Chromium Headless Debugging - ATT&CK v19.2 tags: add t1539
chore: Browser Started with Remote Debugging - ATT&CK v19.2 tags: add t1539
chore: File Download From IP Based URL Via CertOC.EXE - ATT&CK v19.2 tags: remove execution
chore: Potential Arbitrary File Download Via Cmdl32.EXE - ATT&CK v19.2 tags: remove execution, t1202; add command-and-control, t1105
chore: CMSTP Execution Process Creation - ATT&CK v19.2 tags: remove execution
chore: Control Panel Items - ATT&CK v19.2 tags: remove execution

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
