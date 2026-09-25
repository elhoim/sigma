## BLUF

- **What:** corrects ATT&CK tags on 30 rules whose tactic tags were not backed by any tagged technique (pack 1 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 20 unsupported tactic tags removed; 21 rules gained a missing or corrected technique.

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
| Fireball Archer Install | execution | - | drop tactic execution: Rule is about rundll32 proxy execution (stealth); no separate execution technique observed |
| Equation Group C2 Communication | - | t1071 | add technique command-and-control → T1071: Traffic to known C2 infrastructure; C2 is the primary behaviour. Protocol unknown (IP-only), T1095 is an alternative; T1071 is the conventional choice |
| APT29 2018 Phishing Campaign CommandLine Indicators | - | t1059.001 | add technique execution → T1059.001: First selection is a PowerShell command line (-noni -ep bypass) from the LNK payload |
| Potential Ursnif Malware Activity - Registry | execution | - | drop tactic execution: Registry key creation only; nothing executes. T1112 already backs persistence/defense-impairment |
| APT31 Judgement Panda Activity | - | t1570 | add technique lateral-movement → T1570: selection_lateral_movement copies attacker tools to \\host\c$ = Lateral Tool Transfer (T1021.002 SMB/Admin Shares is an acceptable alternative/addition) |
| CVE-2020-1048 Exploitation Attempt - Suspicious New Printer Ports - Registry | execution | - | drop tactic execution: Registry modification only; no execution observed. Twin proc_creation rule has a related persistence ambiguity |
| Exploitation Attempt Of CVE-2020-1472 - Execution of ZeroLogon PoC | execution | - | drop tactic execution: Rule identifies the exploit tool run; the payload is either taskkill or powershell so no specific interpreter is reliably observed. T1059.001 would only cover half the logic |
| GALLIUM Artefacts - Builtin | credential-access | - | drop tactic credential-access: Only C2 domain lookups observed; credential-access was inherited from the derived proc_creation rule (which has T1212) |
| TAIDOOR RAT DLL Load | execution | - | drop tactic execution: Rule observes rundll32 DLL-export proxy execution (stealth). Note: T1218.011 would describe the observed behaviour better than T1055.001, which is not visible in the command line |
| CVE-2021-1675 Print Spooler Exploitation Filename Pattern | execution, resource-development, t1587 | t1068 | replace technique privilege-escalation → T1068 (replaces T1587): Artifact of Print Spooler LPE exploitation; T1587 Develop Capabilities (resource-development) is not observable on a victim host and is wrong; drop tactic execution: File write artifact only; no execution technique observed (twin rules use T1574/T1569 for DLL load/service behaviours); drop tactic resource-development: Falls away with T1587 replacement |
| CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum | credential-access | - | drop tactic credential-access: Only malware file drops observed; nothing credential-related is detected |
| CVE-2021-31979 CVE-2021-33771 Exploits | credential-access | - | drop tactic credential-access: COM hijack registry change, nothing credential-related. Note: the observed behaviour is really T1546.015 COM Hijacking (persistence/privilege-escalation); consider adding it |
| Suspicious RazerInstaller Explorer Subprocess | defense-impairment, t1553 | t1068 | replace technique privilege-escalation → T1068 (replaces T1553): Abuse of a SYSTEM installer UI to spawn a SYSTEM process is exploitation for privilege escalation; nothing subverts trust controls; drop tactic defense-impairment: Only backed by the wrong T1553 |
| CVE-2022-24527 Microsoft Connected Cache LPE | - | t1068 | add technique privilege-escalation → T1068: Planting a module later loaded by SYSTEM to exploit CVE-2022-24527 LPE |
| Hermetic Wiper TG Process Patterns | t1021.001 | t1047, t1021.002 | add technique execution → T1047: '1> \\127.0.0.1\ADMIN$\__<ts>' is the Impacket wmiexec output pattern (remote WMI command execution); replace technique lateral-movement → T1021.002 (replaces T1021.001): Nothing RDP-related is observed; activity is Impacket over SMB/ADMIN$ admin share. (T1003.001 for the comsvcs MiniDump would add credential-access) |
| Potential Compromised 3CXDesktopApp Execution | stealth, t1218, execution | initial-access, t1195.002 | drop tactic execution: Rule flags a trojanized legit app running; no execution technique is observed (T1204.002 would be a stretch); replace technique stealth → T1195.002 (replaces T1218): 3CXDesktopApp is not a system binary proxy; the behaviour is a compromised software supply chain (initial-access). Stealth has no backing after replacement and is dropped |
| Potential Suspicious Child Process Of 3CXDesktopApp | command-and-control | t1059 | add technique execution → T1059: Children include cmd, PowerShell, wscript/cscript interpreters; drop tactic command-and-control: No network activity observed; C2 is covered by sibling proxy/DNS/net_connection rules |
| Potential Compromised 3CXDesktopApp Update Activity | stealth, t1218, execution | initial-access, t1195.002 | drop tactic execution: Update download command line, not an execution technique; replace technique stealth → T1195.002 (replaces T1218): update.exe is not a system binary proxy; behaviour is delivery of a compromised software update (supply chain). Stealth dropped as unbacked |
| CVE-2024-50623 Exploitation Attempt - Cleo | - | t1059.001 | add technique execution → T1059.001: cmd.exe command line launches PowerShell (-enc, .Download) |
| Potential Raspberry Robin CPL Execution Activity | execution | - | drop tactic execution: Rule's point is proxy execution of a CPL via rundll32/control (stealth). T1218.002 Control Panel would be a more precise addition |
| Kapeka Backdoor Configuration Persistence | t1553.003 | t1112 | replace technique persistence → T1112 (replaces T1553.003): Kapeka stores its encrypted config in this key; no SIP/trust provider is registered. T1112 Modify Registry backs persistence and defense-impairment in v19 (T1027.011 Fileless Storage/stealth is an alternative) |
| Potential SAP NetWeaver Webshell Creation - Linux | t1059.003 | t1059.004, t1505.003 | add technique persistence → T1505.003: Webshell dropped/used in SAP NetWeaver web root; replace technique execution → T1059.004 (replaces T1059.003): T1059.003 is Windows Command Shell; Linux rule should use Unix Shell |
| Potential SAP NetWeaver Webshell Creation | - | t1505.003 | add technique persistence → T1505.003: Webshell dropped/used in SAP NetWeaver web root; note T1059.003 is not actually observed by a file-creation rule |
| Suspicious Child Process of SAP NetWeaver - Linux | t1059.003 | t1059.004, t1505.003 | add technique persistence → T1505.003: Webshell dropped/used in SAP NetWeaver web root; replace technique execution → T1059.004 (replaces T1059.003): T1059.003 is Windows Command Shell; Linux rule should use Unix Shell |
| Suspicious Child Process of SAP NetWeaver | - | t1505.003 | add technique persistence → T1505.003: Webshell dropped/used in SAP NetWeaver web root |
| Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Image Load | lateral-movement | t1574.008 | add technique execution → T1574.008: Exploit abuses Process.Start() search order (working dir on WebDAV) so a signed binary runs attacker's route.exe; drop tactic lateral-movement: Remote WebDAV payload hosting is covered by T1105 (C2); no lateral movement between internal hosts |
| Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Process Access | lateral-movement | t1574.008 | add technique execution → T1574.008: Exploit abuses Process.Start() search order (working dir on WebDAV) so a signed binary runs attacker's route.exe; drop tactic lateral-movement: Remote WebDAV payload hosting is covered by T1105 (C2); no lateral movement between internal hosts |
| Potential Exploitation of RCE Vulnerability CVE-2025-33053 | lateral-movement | t1574.008 | add technique execution → T1574.008: Exploit abuses Process.Start() search order (working dir on WebDAV) so a signed binary runs attacker's route.exe; drop tactic lateral-movement: Remote WebDAV payload hosting is covered by T1105 (C2); no lateral movement between internal hosts |
| Shai-Hulud 2.0 Malicious NPM Package Installation - Linux | - | t1204.005 | add technique execution → T1204.005: User installing a malicious npm package (whose install scripts execute) = Malicious Library. Twin node_bun rules use T1203, which is imprecise |
| Shai-Hulud 2.0 Malicious NPM Package Installation | - | t1204.005 | add technique execution → T1204.005: User installing a malicious npm package (whose install scripts execute) = Malicious Library. Twin node_bun rules use T1203, which is imprecise |

### Changelog

chore: Fireball Archer Install - ATT&CK v19.2 tags: remove execution
chore: Equation Group C2 Communication - ATT&CK v19.2 tags: add t1071
chore: APT29 2018 Phishing Campaign CommandLine Indicators - ATT&CK v19.2 tags: add t1059.001
chore: Potential Ursnif Malware Activity - Registry - ATT&CK v19.2 tags: remove execution
chore: APT31 Judgement Panda Activity - ATT&CK v19.2 tags: add t1570
chore: CVE-2020-1048 Exploitation Attempt - Suspicious New Printer Ports - Registry - ATT&CK v19.2 tags: remove execution
chore: Exploitation Attempt Of CVE-2020-1472 - Execution of ZeroLogon PoC - ATT&CK v19.2 tags: remove execution
chore: GALLIUM Artefacts - Builtin - ATT&CK v19.2 tags: remove credential-access
chore: TAIDOOR RAT DLL Load - ATT&CK v19.2 tags: remove execution
chore: CVE-2021-1675 Print Spooler Exploitation Filename Pattern - ATT&CK v19.2 tags: remove execution, resource-development, t1587; add t1068
chore: CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum - ATT&CK v19.2 tags: remove credential-access
chore: CVE-2021-31979 CVE-2021-33771 Exploits - ATT&CK v19.2 tags: remove credential-access
chore: Suspicious RazerInstaller Explorer Subprocess - ATT&CK v19.2 tags: remove defense-impairment, t1553; add t1068
chore: CVE-2022-24527 Microsoft Connected Cache LPE - ATT&CK v19.2 tags: add t1068
chore: Hermetic Wiper TG Process Patterns - ATT&CK v19.2 tags: remove t1021.001; add t1047, t1021.002
chore: Potential Compromised 3CXDesktopApp Execution - ATT&CK v19.2 tags: remove stealth, t1218, execution; add initial-access, t1195.002
chore: Potential Suspicious Child Process Of 3CXDesktopApp - ATT&CK v19.2 tags: remove command-and-control; add t1059
chore: Potential Compromised 3CXDesktopApp Update Activity - ATT&CK v19.2 tags: remove stealth, t1218, execution; add initial-access, t1195.002
chore: CVE-2024-50623 Exploitation Attempt - Cleo - ATT&CK v19.2 tags: add t1059.001
chore: Potential Raspberry Robin CPL Execution Activity - ATT&CK v19.2 tags: remove execution
chore: Kapeka Backdoor Configuration Persistence - ATT&CK v19.2 tags: remove t1553.003; add t1112
chore: Potential SAP NetWeaver Webshell Creation - Linux - ATT&CK v19.2 tags: remove t1059.003; add t1059.004, t1505.003
chore: Potential SAP NetWeaver Webshell Creation - ATT&CK v19.2 tags: add t1505.003
chore: Suspicious Child Process of SAP NetWeaver - Linux - ATT&CK v19.2 tags: remove t1059.003; add t1059.004, t1505.003
chore: Suspicious Child Process of SAP NetWeaver - ATT&CK v19.2 tags: add t1505.003
chore: Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Image Load - ATT&CK v19.2 tags: remove lateral-movement; add t1574.008
chore: Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Process Access - ATT&CK v19.2 tags: remove lateral-movement; add t1574.008
chore: Potential Exploitation of RCE Vulnerability CVE-2025-33053 - ATT&CK v19.2 tags: remove lateral-movement; add t1574.008
chore: Shai-Hulud 2.0 Malicious NPM Package Installation - Linux - ATT&CK v19.2 tags: add t1204.005
chore: Shai-Hulud 2.0 Malicious NPM Package Installation - ATT&CK v19.2 tags: add t1204.005

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
