## BLUF

- **What:** corrects ATT&CK technique tags on 12 rules of the T1574 Hijack Execution Flow family (pack 4 of 4) against Enterprise ATT&CK v19.2.
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
| Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | t1574.011 | t1564 | setting a service security descriptor that hides the service is T1564 Hide Artifacts, not a registry-permission hijack (T1574.011) |
| Abuse of Service Permissions to Hide Services Via Set-Service - PS | t1574.011 | t1564 | setting a service security descriptor that hides the service is T1564 Hide Artifacts, not a registry-permission hijack (T1574.011) |
| Abuse of Service Permissions to Hide Services Via Set-Service | t1574.011 | t1564 | setting a service security descriptor that hides the service is T1564 Hide Artifacts, not a registry-permission hijack (T1574.011) |
| Changing Existing Service ImagePath Value Via Reg.EXE | - | t1543.003 | modifying an existing service's ImagePath is Windows Service modification (T1543.003), backing persistence and privilege-escalation |
| DLL Execution Via Register-cimprovider.exe | t1574 | t1218 | register-cimprovider executing a DLL is signed-binary proxy execution (T1218), not execution-flow hijacking |
| Potential Privilege Escalation via Service Permissions Weakness | - | t1543.003 | service configuration modification (ImagePath / FailureCommand / ServiceDll) is T1543.003; T1574.011 kept |
| Regsvr32 DLL Execution With Uncommon Extension | t1574 | t1218.010 | regsvr32 loading a DLL is T1218.010 Regsvr32 proxy execution, not hijacking |
| Possible Privilege Escalation via Weak Service Permissions | - | t1543.003 | `sc config binPath` modifies an existing service (T1543.003) |
| Service DACL Abuse To Hide Services Via Sc.EXE | t1574.011 | t1564 | setting a service security descriptor that hides the service is T1564 Hide Artifacts, not a registry-permission hijack (T1574.011) |
| Service Security Descriptor Tampering Via Sc.EXE | t1574.011 | t1564 | setting a service security descriptor that hides the service is T1564 Hide Artifacts, not a registry-permission hijack (T1574.011) |
| Potential Registry Persistence Attempt Via DbgManagedDebugger | - | t1546 | a crash-triggered debugger launch is event-triggered execution (T1546), backing persistence |
| Suspicious Printer Driver Empty Manufacturer | - | t1068 | PrintNightmare (CVE-2021-1675) exploitation artefact: T1068 backs privilege-escalation |

### Changelog

chore: Suspicious Service DACL Modification Via Set-Service Cmdlet - PS - ATT&CK v19.2 techniques: replace t1574.011 with t1564
chore: Abuse of Service Permissions to Hide Services Via Set-Service - PS - ATT&CK v19.2 techniques: replace t1574.011 with t1564
chore: Abuse of Service Permissions to Hide Services Via Set-Service - ATT&CK v19.2 techniques: replace t1574.011 with t1564
chore: Changing Existing Service ImagePath Value Via Reg.EXE - ATT&CK v19.2 techniques: add t1543.003
chore: DLL Execution Via Register-cimprovider.exe - ATT&CK v19.2 techniques: replace t1574 with t1218
chore: Potential Privilege Escalation via Service Permissions Weakness - ATT&CK v19.2 techniques: add t1543.003
chore: Regsvr32 DLL Execution With Uncommon Extension - ATT&CK v19.2 techniques: replace t1574 with t1218.010
chore: Possible Privilege Escalation via Weak Service Permissions - ATT&CK v19.2 techniques: add t1543.003
chore: Service DACL Abuse To Hide Services Via Sc.EXE - ATT&CK v19.2 techniques: replace t1574.011 with t1564
chore: Service Security Descriptor Tampering Via Sc.EXE - ATT&CK v19.2 techniques: replace t1574.011 with t1564
chore: Potential Registry Persistence Attempt Via DbgManagedDebugger - ATT&CK v19.2 techniques: add t1546
chore: Suspicious Printer Driver Empty Manufacturer - ATT&CK v19.2 techniques: add t1068

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
