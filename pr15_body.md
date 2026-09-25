## BLUF

- **What:** corrects ATT&CK tags on 8 rules whose tactic tags were not backed by any tagged technique (pack 7 of 7).
- **Why:** each rule was read and its tags re-assessed against Enterprise ATT&CK v19.2; tactics were either unsupported by the detection or missing the technique that justifies them.
- **Impact:** tag metadata only; no detection logic changes. 8 unsupported tactic tags removed; 0 rules gained a missing or corrected technique.

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
| WSL Child Process Anomaly | execution | - | drop tactic execution: description: evading parent/child detections via WSL = Indirect Command Execution (stealth); T1202 names WSL explicitly. Alternative: add T1059 for the spawned interpreters |
| Windows Binary Executed From WSL | execution | - | drop tactic execution: point is masking parent-child relationship via WSL = T1202 (stealth) |
| Proxy Execution Via Wuauclt.EXE | execution | - | drop tactic execution: proxy DLL execution via signed binary = T1218 (stealth only) |
| CMSTP App Paths Registry Key Modification | execution | - | drop tactic execution: CMSTP abuse is T1218.003 (stealth only); no execution technique observed |
| Registry Entries For Azorult Malware | execution | - | drop tactic execution: a service registry key write is not execution; persistence/defense-impairment backed by T1112 (T1543.003 would arguably be more precise for persistence) |
| New PortProxy Registry Entry Added | lateral-movement | - | drop tactic lateral-movement: port forwarding is a proxy/pivot (T1090, C2); no lateral-movement technique observed. T1090.001 Internal Proxy would be a more specific option |
| DLL Load via LSASS | execution | - | drop tactic execution: LSASS extension DLL registration = T1547.008 (persistence/priv-esc); no execution technique |
| Potential Persistence Via Logon Scripts - Registry | lateral-movement | - | drop tactic lateral-movement: logon script registration is persistence/priv-esc (T1037.001); no lateral movement |

### Changelog

chore: WSL Child Process Anomaly - ATT&CK v19.2 tags: remove execution
chore: Windows Binary Executed From WSL - ATT&CK v19.2 tags: remove execution
chore: Proxy Execution Via Wuauclt.EXE - ATT&CK v19.2 tags: remove execution
chore: CMSTP App Paths Registry Key Modification - ATT&CK v19.2 tags: remove execution
chore: Registry Entries For Azorult Malware - ATT&CK v19.2 tags: remove execution
chore: New PortProxy Registry Entry Added - ATT&CK v19.2 tags: remove lateral-movement
chore: DLL Load via LSASS - ATT&CK v19.2 tags: remove execution
chore: Potential Persistence Via Logon Scripts - Registry - ATT&CK v19.2 tags: remove lateral-movement

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
