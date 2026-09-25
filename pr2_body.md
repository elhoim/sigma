## BLUF

- **What:** corrects ATT&CK technique tags on 5 rules of the T1574 Hijack Execution Flow family (pack 1 of 4) against Enterprise ATT&CK v19.2.
- **Why:** these rules either lacked the technique behind a tactic they claim, or carried a technique that does not describe what they detect.
- **Impact:** tag metadata only; no detection logic changes and **no tactic tags removed**.

**Priority:** Low

### Summary of the Pull Request

Each rule in the T1574 family was re-read against Enterprise ATT&CK v19.2 (2026-08-05). Only technique-level corrections are proposed here; all existing tactic tags are kept as they are.

- **Added techniques** back a tactic the rule genuinely observes (e.g. T1543.003 for service ImagePath / binPath changes, T1068 for privilege-escalation exploit artefacts, T1546 for crash-triggered debugger persistence).
- **Replaced techniques** did not describe the detected behaviour (e.g. service-DACL hiding is T1564 Hide Artifacts, not T1574.011; register-cimprovider / regsvr32 are T1218 proxy execution, not hijacking). Where a replacement technique has a tactic the rule lacked, that tactic is added so the SigmaHQ validator's technique/tactic consistency check passes.

Following the SigmaHQ v19 tag migration convention (#5966), tag-only changes do not bump `modified` or `author`.

| Rule | Removed technique | Added | Reason |
|---|---|---|---|
| Potential PrintNightmare Exploitation Attempt | - | t1068 | T1068 backs the existing privilege-escalation tactic (CVE-2021-1675 local privilege escalation) |
| Windows Spooler Service Suspicious Binary Load | - | t1068 | T1068 backs privilege-escalation (spooler exploitation loads an attacker DLL as SYSTEM) |
| Pingback Backdoor Activity | - | t1543.003 | `sc config msdtc start= auto` reconfigures a Windows service: T1543.003 backs the existing persistence and privilege-escalation tactics |
| Potential Notepad++ CVE-2025-49144 Exploitation | - | t1068 | T1068 backs privilege-escalation (installer local privilege escalation CVE); T1574.008 kept |
| Use Of Hidden Paths Or Files | t1574.001 | t1564.001 | the rule and its Atomic Red Team reference are about hidden files and directories, not DLL hijacking |

### Changelog

chore: Potential PrintNightmare Exploitation Attempt - ATT&CK v19.2 techniques: add t1068
chore: Windows Spooler Service Suspicious Binary Load - ATT&CK v19.2 techniques: add t1068
chore: Pingback Backdoor Activity - ATT&CK v19.2 techniques: add t1543.003
chore: Potential Notepad++ CVE-2025-49144 Exploitation - ATT&CK v19.2 techniques: add t1068
chore: Use Of Hidden Paths Or Files - ATT&CK v19.2 techniques: replace t1574.001 with t1564.001

### Example Log Event

N/A (no detection change)

### Fixed Issues

N/A

### SigmaHQ Rule Creation Conventions

- If your PR adds new rules, please consider following and applying these [conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/)

### Validation

- Diff touches only `tags:` lines and removes no tactic tag; each technique checked against the ATT&CK v19.2 STIX bundle.
- Local replica of the repo CI: yamllint (strict), `tests/test_logsource.py`, `tests/test_rules.py`, `sigma check` with the SigmaHQ validators, and 463/463 regression tests pass.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
