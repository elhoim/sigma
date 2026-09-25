## BLUF

- **What:** fixes ATT&CK tags on 30 rules (T1574 Hijack Execution Flow family, pack 3 of 4) so they match Enterprise ATT&CK v19.2.
- **Why:** v19 moved T1574 and its sub-techniques from persistence / privilege-escalation to stealth / execution; these rules still carried tactics no tagged technique backs.
- **Impact:** tag metadata only; no detection logic changes. 58 stale tactic tags removed; 1 rule(s) gained or had a technique corrected (listed below).

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
| Trusted Path Bypass via Windows Directory Spoofing | `attack.persistence`, `attack.t1574.007` | `attack.t1574.001` | removed stale persistence (no backing technique; DLL/flow hijack alone is not persistence/privesc in v19.2); kept privilege-escalation (backed by T1548.002 UAC bypass); replaced T1574.007 (PATH env var interception) with T1574.001: behaviour is DLL hijack via mock trusted directory, no PATH variable involved |

### Changelog

chore: Potential DLL Sideloading Of MsCorSvc.DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of Non-Existent DLLs From System Folders - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Microsoft Office DLL Sideload - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Python DLL SideLoading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Rcdll.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential RjvPlatform.DLL Sideloading From Default Location - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential RjvPlatform.DLL Sideloading From Non-Default Location - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential RoboForm.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: DLL Sideloading Of ShellChromeAPI.DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential ShellDispatch.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential SmadHook.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential SolidPDFCreator.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Third Party Software DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Fax Service DLL Search Order Hijack - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Vcruntime140 DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Vivaldi_elf.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: VMGuestLib DLL Sideload - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: VMMap Signed Dbghelp.DLL Potential Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: VMMap Unsigned Dbghelp.DLL Potential Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Via VMware Xfer - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Waveedit.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Wazuh Security Platform DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Mpclient.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential WWlib.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Unsigned Module Loaded by ClickOnce Application - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Suspicious Unsigned Thor Scanner Execution - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: UAC Bypass With Fake DLL - ATT&CK v19.2 tags: remove persistence
chore: Trusted Path Bypass via Windows Directory Spoofing - ATT&CK v19.2 tags: remove persistence, t1574.007; add t1574.001
chore: Registry-Free Process Scope COR_PROFILER - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Service Registry Permissions Weakness Check - ATT&CK v19.2 tags: remove persistence, privilege-escalation

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
