## BLUF

- **What:** removes `attack.ds0005` (WMI data source) from `posh_ps_create_volume_shadow_copy.yml`.
- **Why:** ATT&CK has deprecated its data sources; DS0005 is marked deprecated in Enterprise ATT&CK v19.2.
- **Impact:** tag metadata only; detection logic and matches are unchanged. This was the last `attack.ds*` tag in the repo.

**Priority:** Cosmetic

### Summary of the Pull Request

The rule carried the data source tag `attack.ds0005` next to its technique tag. ATT&CK has replaced data sources with data components and detection strategies, and Enterprise ATT&CK v19.2 (2026-08-05) marks `x-mitre-data-source` DS0005 (WMI) as deprecated. The remaining tags (`attack.credential-access`, `attack.t1003.003`) are consistent: T1003.003 NTDS is an active credential-access technique in v19.2.

Following the v19 tag migration convention (#5966), this tag-only change does not bump `modified`.

### Changelog

chore: Create Volume Shadow Copy with Powershell - remove deprecated ATT&CK data source tag `attack.ds0005`

### Example Log Event

N/A (no detection change)

### Fixed Issues

N/A

### SigmaHQ Rule Creation Conventions

- If your PR adds new rules, please consider following and applying these [conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/)

### Validation

Local replica of the repo CI: yamllint (strict), `tests/test_logsource.py`, `tests/test_rules.py`, `sigma check` with the SigmaHQ validators (ATT&CK v19.2 data), and 463/463 regression tests pass.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
