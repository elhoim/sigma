## BLUF

- **What:** corrects ATT&CK technique tags on 1 rule of the T1574 Hijack Execution Flow family (pack 3 of 4) against Enterprise ATT&CK v19.2.
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
| Trusted Path Bypass via Windows Directory Spoofing | t1574.007 | t1574.001 | T1574.007 is PATH environment variable interception; the rule detects DLL hijacking via a mock `C:\Windows \System32` directory, which is T1574.001 |

### Changelog

chore: Trusted Path Bypass via Windows Directory Spoofing - ATT&CK v19.2 techniques: replace t1574.007 with t1574.001

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
