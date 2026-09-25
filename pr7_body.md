## BLUF

- **What:** fixes 21 Sigma rules: filters an attacker can satisfy (writable folders, bare image names, substrings of the command line), case-sensitive regexes against case-randomising tools, and missing tool variants/extensions.
- **Why:** found in a full review of the rule set; every issue was verified against the rule source and Sigma semantics before fixing.
- **Impact:** each change removes a trivial evasion path while keeping legitimate exclusions anchored to real install paths. Rules whose detection logic changed credit the contributor in `author` and bump `modified`.

**Priority:** Medium

### Summary of the Pull Request

| Rule | Problem | Fix |
|---|---|---|
| `proc_creation_win_rundll32_no_params.yml` | Parent filter excluded anything under `\AppData\Local\` (where loaders run) | Only Edge / EdgeUpdate under Program Files are excluded |
| `proc_creation_win_googleupdate_susp_child_process.yml` | Excluded any child whose path contains `\Google` or ends in `setup.exe` | Anchored to `:\Program Files (x86)\Google\`, `:\Program Files\Google\` and the per-user `\AppData\Local\Google\...\Update\` install |
| `proc_creation_win_susp_elevated_system_shell_uncommon_parent.yml` | Main filter whitelisted parents in user-writable `:\ProgramData\` and `:\Windows\Temp\` | Removed; narrow optional filters for Defender Platform, Package Cache and `.tmp` installers in Windows\Temp |
| `proc_creation_win_hktl_relay_attacks_tools.yml` | Potato coverage stopped at 2021-era tools; `execution` tactic unbacked | Adds GodPotato, SigmaPotato, PrintNotifyPotato, RemotePotato0, SharpEfsPotato; tags: privilege-escalation/stealth + T1134.001, T1187 instead of `execution` |
| `posh_ps / posh_pm / win_system / win_security invoke_obfuscation_obfuscated_iex (4 rules)` | Case-sensitive `|re` against a tool that randomises case; `\\*mdr` and `\String\]` regex typos | All patterns `|re|i`, typos fixed, the four rules aligned |
| `posh_ps_copy_item_system_directory.yml` | Case-sensitive regex, dependent on `-Destination` order | Single `|re|i` pattern covering aliases, any `-D...` abbreviation and parameter order |
| `proc_access_win_lsass_memdump.yml` | Main filter dropped every access from `NT AUTHORITY` users | The SYSTEM filter now also requires SourceImage under Program Files, Defender Platform, System32 or SysWOW64 (note: `rundll32 comsvcs` from System32 as SYSTEM remains filtered to avoid FP floods) |
| `proc_access_win_susp_direct_ntopenprocess_call.yml` | Optional filters checked only the target or a bare name | Discord / Evernote filters also check SourceImage; leading backslash on endswith values |
| `net_connection_win_domain_dropbox_api.yml` | High-level rule excluded any process path containing `\Dropbox` | Program Files installs in the main filter; per-user `\AppData\Local\Dropbox\Client\` / `\AppData\Roaming\Dropbox\bin\` as an optional filter |
| `registry_set_susp_service_installed.yml` | Sysinternals filter paired a bare image name with a substring driver path | Driver path anchored (`:\WINDOWS\system32\Drivers\PROCEXP152.SYS` and exact `%SystemRoot%` / `\SystemRoot\` forms), combined with the image filter |
| `file_event_win_office_startup_persistence.yml` | Missing add-in / binary workbook extensions; Office filter checked only the image name | Adds `.dotx .wll .xla .xlam .xll .xlsb .xltx`; filter requires Office install paths |
| `win_system_service_install_sliver.yml` | Case-sensitive regex on `windows\temp` | `|re|i` |
| `proc_creation_lnx_security_tools_disabling.yml` | `chkconfig ... stop` (not a chkconfig verb); `setenforce Permissive` bypassed the rule | chkconfig `off`; SELinux selection matches `0` and `Permissive` |
| `proc_creation_macos_create_hidden_account.yml` | Unanchored UID<500 regex / `contains '1'` matched any digit | Regex anchored to `UniqueID`; single `IsHidden true|yes|1` selection |
| `proc_creation_macos_network_service_scanning.yml` | Listen-mode filter `contains: 'l'` dropped most scans (any letter l) | Flag-anchored regex for `-l` / `--listen` |
| `net_connection_win_susp_azurefd_connection.yml (threat hunting)` | Bypass via process name and tenant-chosen FD hostname | `endswith '.azurefd.net'`, exact benign domains, browsers anchored to install paths, SearchApp anchored to SystemApps |
| `proc_creation_win_malware_qakbot_rundll32_fake_dll_execution.yml / proc_creation_win_malware_dridex.yml (ET)` | `.dll` anywhere in the command line satisfied the filter | Extension must be anchored (`.dll,` / `.dll #` / endswith `.dll`) |

All other rule content is unchanged. ATT&CK tags on the touched rules were checked against Enterprise ATT&CK v19.2 (every technique active, every tactic backed by a tagged technique).

### Changelog

chore: Potential SMB Relay Attack Tool Execution - correct ATT&CK tags
chore: Potential SMB Relay Attack Tool Execution - replace unbacked execution with privilege-escalation/stealth backed by T1134.001 (Potato token impersonation) and add T1187 (PetitPotam/SpoolSample coercion)
fix: Potential Dridex Activity
fix: Qakbot Rundll32 Fake DLL Extension Execution
fix: Potentially Suspicious Azure Front Door Connection
fix: Disabling Security Tools
fix: Hidden User Creation
fix: MacOS Network Service Scanning
fix: Invoke-Obfuscation Obfuscated IEX Invocation - Security
fix: Invoke-Obfuscation Obfuscated IEX Invocation - System
fix: Sliver C2 Default Service Installation
fix: Potential Persistence Via Microsoft Office Startup Folder
fix: Suspicious Dropbox API Usage
fix: Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module
fix: Powershell Install a DLL in System Directory
fix: Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell
fix: Potential Credential Dumping Activity Via LSASS
fix: Potential Direct Syscall of NtOpenProcess
fix: Potentially Suspicious GoogleUpdate Child Process
fix: Potential SMB Relay Attack Tool Execution
fix: Rundll32 Execution Without CommandLine Parameters
fix: Elevated System Shell Spawned From Uncommon Parent Location
fix: Suspicious Service Installed

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
