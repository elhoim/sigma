## BLUF

- **What:** fixes ATT&CK tags on 28 rules (T1574 Hijack Execution Flow family, pack 4 of 4) so they match Enterprise ATT&CK v19.2.
- **Why:** v19 moved T1574 and its sub-techniques from persistence / privilege-escalation to stealth / execution; these rules still carried tactics no tagged technique backs.
- **Impact:** tag metadata only; no detection logic changes. 50 stale tactic tags removed; 12 rule(s) gained or had a technique corrected (listed below).

**Priority:** Low

### Summary of the Pull Request

Each rule was read and its full `attack.*` tag set re-assessed against Enterprise ATT&CK v19.2 (2026-08-05):

- Stale `attack.persistence` / `attack.privilege-escalation` tags are removed where nothing the rule observes is persistence or privilege escalation (DLL side-loading alone is neither).
- Where the rule genuinely observes that outcome, the backing technique is added instead of dropping the tactic (e.g. T1543.003 for service ImagePath changes, T1068 for exploit artefacts).
- Techniques that did not describe the detected behaviour were corrected (see the table below).

After this PR, every technique on these rules is active in v19.2, every tactic tag is backed by at least one tagged technique, and every tactic of a tagged technique is present. Following the SigmaHQ v19 tag migration convention (#5966), tag-only changes do not bump `modified` or `author`.

#### Rules where a technique was added or replaced

| Rule | Removed | Added | Why |
|---|---|---|---|
| Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574.011` | `attack.t1564` | Removed stale persistence/privilege-escalation; replaced T1574.011 with T1564 Hide Artifacts (the rule detects a service DACL change that hides the service, not a registry-permission hijack); dropped execution, which only T1574 backed |
| Abuse of Service Permissions to Hide Services Via Set-Service - PS | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574.011` | `attack.t1564` | Removed stale persistence/privilege-escalation; replaced T1574.011 with T1564 Hide Artifacts (the rule detects a service DACL change that hides the service, not a registry-permission hijack); dropped execution, which only T1574 backed |
| Abuse of Service Permissions to Hide Services Via Set-Service | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574.011` | `attack.t1564` | Removed stale persistence/privilege-escalation; replaced T1574.011 with T1564 Hide Artifacts (the rule detects a service DACL change that hides the service, not a registry-permission hijack); dropped execution, which only T1574 backed |
| Changing Existing Service ImagePath Value Via Reg.EXE | - | `attack.t1543.003` | added T1543.003 (modifying an existing service ImagePath is Windows Service persistence/privesc) to back persistence/privilege-escalation |
| DLL Execution Via Register-cimprovider.exe | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574` | `attack.t1218` | replaced generic T1574 with T1218 (signed-binary proxy execution, not hijacking); removed stale privilege-escalation/persistence and unbacked execution |
| Potential Privilege Escalation via Service Permissions Weakness | - | `attack.t1543.003` | added T1543.003 (service configuration modification) to back persistence/privilege-escalation; kept T1574.011 |
| Regsvr32 DLL Execution With Uncommon Extension | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574` | `attack.t1218.010` | replaced generic T1574 with T1218.010 Regsvr32 proxy execution; removed stale privilege-escalation/persistence and unbacked execution |
| Possible Privilege Escalation via Weak Service Permissions | - | `attack.t1543.003` | added T1543.003 (sc config binPath modifies an existing service) to back persistence/privilege-escalation |
| Service DACL Abuse To Hide Services Via Sc.EXE | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574.011` | `attack.t1564` | Removed stale persistence/privilege-escalation; replaced T1574.011 with T1564 Hide Artifacts (the rule detects a service DACL change that hides the service, not a registry-permission hijack); dropped execution, which only T1574 backed |
| Service Security Descriptor Tampering Via Sc.EXE | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574.011` | `attack.t1564` | Removed stale persistence/privilege-escalation; replaced T1574.011 with T1564 Hide Artifacts (the rule detects a service DACL change that hides the service, not a registry-permission hijack); dropped execution, which only T1574 backed |
| Potential Registry Persistence Attempt Via DbgManagedDebugger | - | `attack.t1546` | added T1546 Event Triggered Execution (crash-triggered debugger launch persistence) to back persistence/privilege-escalation |
| Suspicious Printer Driver Empty Manufacturer | `attack.persistence` | `attack.t1068` | added T1068 (PrintNightmare exploitation for privilege escalation, per cve tag) to back privilege-escalation; removed stale persistence |

### Changelog

chore: Suspicious Service DACL Modification Via Set-Service Cmdlet - PS - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574.011; add t1564
chore: Abuse of Service Permissions to Hide Services Via Set-Service - PS - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574.011; add t1564
chore: Potential DLL Sideloading Via DeviceEnroller.EXE - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DLL Sideloading by VMware Xfer Utility - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE - ATT&CK v19.2 tags: remove privilege-escalation
chore: Suspicious GUP Usage - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: HackTool - SharpUp PrivEsc Tool Execution - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potentially Suspicious Child Process of KeyScrambler.exe - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Using SettingSyncHost.exe as LOLBin - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Mpclient.DLL Sideloading Via Defender Binaries - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Abuse of Service Permissions to Hide Services Via Set-Service - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574.011; add t1564
chore: Changing Existing Service ImagePath Value Via Reg.EXE - ATT&CK v19.2 tags: add t1543.003
chore: DLL Execution Via Register-cimprovider.exe - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574; add t1218
chore: Potential Privilege Escalation via Service Permissions Weakness - ATT&CK v19.2 tags: add t1543.003
chore: Regsvr32 DLL Execution With Uncommon Extension - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574; add t1218.010
chore: Renamed Vmnat.exe Execution - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Possible Privilege Escalation via Weak Service Permissions - ATT&CK v19.2 tags: add t1543.003
chore: Service DACL Abuse To Hide Services Via Sc.EXE - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574.011; add t1564
chore: Service Security Descriptor Tampering Via Sc.EXE - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574.011; add t1564
chore: Setup16.EXE Execution With Custom .Lst File - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Tasks Folder Evasion - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Xwizard.EXE Execution From Non-Default Location - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Registry Persistence Attempt Via DbgManagedDebugger - ATT&CK v19.2 tags: add t1546
chore: DHCP Callout DLL Installation - ATT&CK v19.2 tags: remove privilege-escalation
chore: New DNS ServerLevelPluginDll Installed - ATT&CK v19.2 tags: remove privilege-escalation
chore: Enabling COR Profiler Environment Variables - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Registry Modification for OCI DLL Redirection - ATT&CK v19.2 tags: remove privilege-escalation
chore: Suspicious Printer Driver Empty Manufacturer - ATT&CK v19.2 tags: remove persistence; add t1068

### Example Log Event

N/A (no detection change)

### Fixed Issues

N/A

### SigmaHQ Rule Creation Conventions

- If your PR adds new rules, please consider following and applying these [conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/)

### Validation

- Diff touches only `tags:` lines; each technique checked against the ATT&CK v19.2 STIX bundle (active, tactic coverage).
- Local replica of the repo CI: yamllint (strict), `tests/test_logsource.py`, `tests/test_rules.py`, `sigma check` with the SigmaHQ validators, and 463/463 regression tests pass.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
