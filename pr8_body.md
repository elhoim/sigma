## BLUF

- **What:** fixes 14 Sigma rules: overly broad short values, filters that never excluded anything, non-existent field names, misleading titles and missing ATT&CK techniques.
- **Why:** found in a full review of the rule set; every issue was verified against the rule source and Sigma semantics before fixing.
- **Impact:** fewer false positives on noisy rules and correct metadata, with no loss of true-positive coverage. Rules whose detection logic changed credit the contributor in `author` and bump `modified`.

**Priority:** Low

### Summary of the Pull Request

| Rule | Problem | Fix |
|---|---|---|
| `proc_creation_win_powershell_non_interactive_execution.yml / proc_creation_win_attrib_hiding_files.yml` | Windows Update and Intel filters were exact matches on partial paths or contained literal `*`: never excluded anything | `ParentImage|endswith`; Intel filter rebuilt with contains/endswith and a case-insensitive regex |
| `proc_creation_win_defender_default_action_modified.yml` | Values `'6'` / `'9'` matched any digit (e.g. `SysWOW64`) | One `|re|i` binding 6/9/Allow/NoAction to the `*ThreatDefaultAction` / `-xtdefac` parameter |
| `proc_creation_win_dsacls_abuse_permissions.yml` | Two-letter tokens matched almost any dsacls call; DCSync-relevant `CA` missing | Token must follow the trustee colon; adds `CA` and `WO` |
| `posh_pm_alternate_powershell_hosts.yml` | `\??\C:Windows` filter entries (missing backslash) never matched | Backslash added |
| `proc_creation_lnx_susp_sensitive_file_access.yml` | Looked for `>` in the child's argv, but the shell consumes redirections | Detects redirection to sensitive paths in the shell's `-c` command line |
| `aws_ec2_vm_export_failure.yml` | Title says failure but the logic detects export tasks that did not fail | Title corrected to "AWS EC2 VM Export Task Created" (metadata only) |
| `proc_creation_lnx_php/perl/ruby_reverse_shell.yml` | No ATT&CK technique tag | Adds T1059.004 (metadata only) |
| `azure_conditional_access_failure.yml / azure_auditlogs_laps_credential_dumping.yml` | Non-existent field names `Resultdescription`, `activityType` | `ResultDescription`, `activityDisplayName` |
| `proc_creation_win_exploit_cve_2025_55182_susp_nodejs_server_child_process.yml (ET)` | `java` / `lua` substrings hit `javascript`, `evaluate` | Specific `java -`, `java.exe`, `javaw`, `lua `, `lua.exe`; concrete false-positive guidance |
| `netflow_cleartext_protocols.yml (compliance)` | Missing technique; falsepositives `Unknown` | `attack.discovery`, T1040; concrete false-positive guidance (metadata only) |

All other rule content is unchanged. ATT&CK tags on the touched rules were checked against Enterprise ATT&CK v19.2 (every technique active, every tactic backed by a tagged technique).

### Changelog

chore: Cleartext Protocol Usage Via Netflow - metadata
fix: Windows Suspicious Child Process from Node.js - React2Shell
chore: AWS EC2 VM Export Task Created - metadata
fix: Windows LAPS Credential Dump From Entra ID
fix: Sign-in Failure Due to Conditional Access Requirements Not Met
chore: Potential Perl Reverse Shell Execution - metadata
chore: Potential PHP Reverse Shell - metadata
chore: Potential Ruby Reverse Shell - metadata
fix: Potential Suspicious Change To Sensitive/Critical Files
fix: Alternate PowerShell Hosts - PowerShell Module
fix: Hiding Files with Attrib.exe
fix: PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction'
fix: Potentially Over Permissive Permissions Granted Using Dsacls.EXE
fix: Non Interactive PowerShell Process Spawned

### Example Log Event

N/A. These are fixes to logic that could never match, bypassable filters or field names; no false-positive event is being tuned out.

### Fixed Issues

N/A

### SigmaHQ Rule Creation Conventions

- If your PR adds new rules, please consider following and applying these [conventions](https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/)

### Validation

- Local replica of the repo CI: yamllint (strict), `tests/test_logsource.py`, `tests/test_rules.py`, `sigma check` with the SigmaHQ validators, and 463/463 regression tests pass (rules with regression data still match their samples).
- Every changed rule converts with `sigma convert -t splunk --without-pipeline` (placeholder rules excepted).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
