## BLUF

- **What:** fixes ATT&CK tags on 30 rules (T1574 Hijack Execution Flow family, pack 1 of 4) so they match Enterprise ATT&CK v19.2.
- **Why:** v19 moved T1574 and its sub-techniques from persistence / privilege-escalation to stealth / execution; these rules still carried tactics no tagged technique backs.
- **Impact:** tag metadata only; no detection logic changes. 55 stale tactic tags removed; 5 rule(s) gained or had a technique corrected (listed below).

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
| Potential PrintNightmare Exploitation Attempt | `attack.persistence` | `attack.t1068` | removed persistence; added T1068 to back privilege-escalation (CVE-2021-1675 LPE exploitation) |
| Windows Spooler Service Suspicious Binary Load | `attack.persistence` | `attack.t1068` | removed persistence; added T1068 to back privilege-escalation (spooler LPE exploitation loads attacker DLL as SYSTEM) |
| Pingback Backdoor Activity | - | `attack.t1543.003` | added T1543.003 (sc config msdtc start= auto reconfigures a Windows service for persistence); it backs both persistence and privilege-escalation, so both kept (sigma CI requires all technique tactics) |
| Potential Notepad++ CVE-2025-49144 Exploitation | `attack.persistence` | `attack.t1068` | removed persistence; added T1068 to back privilege-escalation (exploitation of installer LPE CVE); T1574.008 kept |
| Use Of Hidden Paths Or Files | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.t1574.001` | `attack.t1564.001` | replaced T1574.001 with T1564.001 (rule and reference are about hidden files, not DLL hijack); removed persistence, privilege-escalation, execution (unbacked) |

### Changelog

chore: Potential PlugX Activity - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: APT27 - Emissary Panda Activity - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Exploiting SetupComplete.cmd CVE-2019-1378 - ATT&CK v19.2 tags: remove persistence
chore: Winnti Malware HK University Campaign - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Winnti Pipemon Characteristics - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential PrintNightmare Exploitation Attempt - ATT&CK v19.2 tags: remove persistence; add t1068
chore: Windows Spooler Service Suspicious Binary Load - ATT&CK v19.2 tags: remove persistence; add t1068
chore: Pingback Backdoor File Indicators - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Pingback Backdoor DLL Loading Activity - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Pingback Backdoor Activity - ATT&CK v19.2 tags: add t1543.003
chore: Small Sieve Malware CommandLine Indicator - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DLL Names Used By SVR For GraphicalProton Backdoor - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Diamond Sleet APT DLL Sideloading Indicators - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Lazarus APT DLL Sideloading Activity - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Raspberry Robin Aclui Dll SideLoading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Notepad++ CVE-2025-49144 Exploitation - ATT&CK v19.2 tags: remove persistence; add t1068
chore: Use Of Hidden Paths Or Files - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, t1574.001; add t1564.001
chore: Modification of ld.so.preload - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Code Injection by ld.so Preload - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DNS Server Error Failed Loading the ServerLevelPluginDLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Service Registry Key Read Access Request - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Microsoft Defender Blocked from Loading Unsigned DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Unsigned Binary Loaded From Suspicious Location - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DHCP Server Loaded the CallOut DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DHCP Server Error Failed Loading the CallOut DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Creation Of Non-Existent System DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DLL Search Order Hijackig Via Additional Space in Path - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: HackTool - Powerup Write Hijack DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Initial Access via DLL Search Order Hijacking - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Malicious DLL File Dropped in the Teams or OneDrive Folder - ATT&CK v19.2 tags: remove persistence, privilege-escalation

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
