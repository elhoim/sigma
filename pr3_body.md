## BLUF

- **What:** corrects ATT&CK technique tags on 2 rules of the T1574 Hijack Execution Flow family (pack 2 of 4) against Enterprise ATT&CK v19.2.
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
| Potential Azure Browser SSO Abuse | t1574.001 | credential-access, t1528 | the rule detects a process requesting Azure SSO refresh tokens via MicrosoftAccountTokenProvider.dll; no hijack occurs. T1528 Steal Application Access Token needs credential-access |
| Potential DLL Sideloading Via comctl32.dll | - | t1068 | the rule targets the DirCreate2System exploit, whose outcome is SYSTEM code execution: T1068 backs privilege-escalation |

### Changelog

chore: Potential Azure Browser SSO Abuse - ATT&CK v19.2 techniques: replace t1574.001 with t1528; add credential-access
chore: Potential DLL Sideloading Via comctl32.dll - ATT&CK v19.2 techniques: add t1068

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
