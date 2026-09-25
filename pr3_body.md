## BLUF

- **What:** fixes ATT&CK tags on 30 rules (T1574 Hijack Execution Flow family, pack 2 of 4) so they match Enterprise ATT&CK v19.2.
- **Why:** v19 moved T1574 and its sub-techniques from persistence / privilege-escalation to stealth / execution; these rules still carried tactics no tagged technique backs.
- **Impact:** tag metadata only; no detection logic changes. 61 stale tactic tags removed; 2 rule(s) gained or had a technique corrected (listed below).

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
| Potential Azure Browser SSO Abuse | `attack.execution`, `attack.persistence`, `attack.privilege-escalation`, `attack.stealth`, `attack.t1574.001` | `attack.credential-access`, `attack.t1528` | Removed stale persistence/privilege-escalation; replaced T1574.001 (no hijack occurs) with T1528 Steal Application Access Token, since the rule detects a process requesting Azure SSO refresh tokens via MicrosoftAccountTokenProvider.dll |
| Potential DLL Sideloading Via comctl32.dll | `attack.persistence` | `attack.t1068` | Removed persistence; kept privilege-escalation and added T1068: rule targets the DirCreate2System arbitrary-dir-create exploit whose purpose/outcome is SYSTEM code execution in privileged binaries |

### Changelog

chore: Creation of WerFault.exe/Wer.dll in Unusual Folder - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Azure Browser SSO Abuse - ATT&CK v19.2 tags: remove execution, persistence, privilege-escalation, stealth, t1574.001; add credential-access, t1528
chore: Unsigned .node File Loaded - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential 7za.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Antivirus Software DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential appverifUI.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Aruba Network Service Potential DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential AVKkid.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential CCleanerDU.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential CCleanerReactivator.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Chrome Frame Helper DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Via ClassicExplorer32.dll - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Via comctl32.dll - ATT&CK v19.2 tags: remove persistence; add t1068
chore: System Control Panel Item Loaded From Uncommon Location - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of DBGCORE.DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of DBGHELP.DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of DbgModel.DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential EACore.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Edputil.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential System DLL Sideloading From Non System Locations - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Goopdate.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Iviewers.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential JLI.dll Side-Loading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Via JsSchHlp - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Libvlc.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential Mfdetours.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Unsigned Mfdetours.DLL Sideloading - ATT&CK v19.2 tags: remove persistence, privilege-escalation
chore: Potential DLL Sideloading Of MpSvc.DLL - ATT&CK v19.2 tags: remove persistence, privilege-escalation

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
