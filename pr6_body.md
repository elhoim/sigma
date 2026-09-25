## BLUF

- **What:** fixes 20 Sigma rules: rules or rule branches that can never match any real event: exact matches where a modifier was intended, typos, placeholder values, wrong field names and non-existent cloud event sources/names.
- **Why:** found in a full review of the rule set; every issue was verified against the rule source and Sigma semantics before fixing.
- **Impact:** these rules silently provide zero coverage today; each fix restores the detection the title and description promise. Rules whose detection logic changed credit the contributor in `author` and bump `modified`.

**Priority:** High

### Summary of the Pull Request

| Rule | Problem | Fix |
|---|---|---|
| `proc_creation_win_xwizard_runwizard_com_object_exec.yml` | `CommandLine: 'RunWizard'` (exact match) ANDed with a GUID regex on the same field: never matches | Split into an image selection (`\xwizard.exe` / OriginalFileName) and a CLI selection (`CommandLine|contains: RunWizard` + GUID regex) |
| `proc_creation_win_remote_access_tools_teamviewer_incoming_connection.yml` | `Image`/`ParentImage` compared by exact bare file name; both fields always hold full paths | `|endswith` with a leading backslash |
| `proc_creation_win_hktl_quarks_pwdump.yml` | Flag values (`' -dhl'`, ...) are exact matches on the whole command line, so the CLI branch (renamed binaries) is dead | `CommandLine|contains` |
| `proc_creation_win_cmd_path_traversal.yml` | `ParentCommandLine: '/../../'` is an exact match: branch dead | `ParentCommandLine|contains` |
| `proc_creation_win_agentexecutor_potential_abuse.yml` | `Image: '\AgentExecutor.exe'` exact match never equals a full path | `Image|endswith` |
| `registry_event_new_dll_added_to_appcertdlls_registry_key.yml` | Typo `CurentControlSet` in the rename branch; exact key match misses values written under the key | `|contains: '\Control\Session Manager\AppCertDlls'` (also covers ControlSet00x) |
| `posh_pm_susp_zip_compress.yml` | `ContextInfo|contains|all` over three mutually exclusive destinations: can never match | Drop `|all` so the list is OR, like the ps_script / ps_classic siblings |
| `aws_route_53_domain_transferred_lock_disabled.yml / aws_route_53_domain_transferred_to_another_account.yml` | eventSource `route53.amazonaws.com`, but domain events are logged by `route53domains.amazonaws.com`: never fire | Correct eventSource; drop `credential-access` (not backed by T1098) |
| `aws_s3_data_management_tampering.yml` | eventNames that CloudTrail never emits (API action names) | `PutBucketEncryption`, `DeleteBucketEncryption`, `PutBucketLifecycle`, `PutBucketReplication`, `DeleteBucketReplication`; `ReplicateObject` dropped |
| `aws_elasticache_security_group_modified_or_deleted.yml` | `AuthorizeCacheSecurityGroupEgress` / `RevokeCacheSecurityGroupEgress` do not exist in the ElastiCache API | Removed the two non-existent eventNames |
| `azure_user_password_change.yml` | Placeholder literal `'UPN'` and non-schema fields (`Initiatedby`, `Target`, `ActivityType`): never matches | Rewrite on AuditLogs `OperationName` (self-service/user password change and reset) with `InitiatedBy.user.userPrincipalName|fieldref: TargetResources.userPrincipalName`; drop `credential-access` (not backed by T1078.004) |
| `zeek_smb_converted_win_atsvc_task.yml / zeek_smb_converted_win_lm_namedpipe.yml` | Windows 5145 literal `\\*\IPC$` (escaped star) on Zeek `path`; lm_namedpipe filter was an unbound keyword list | `path|endswith: '\IPC$'`, pipe filters on `name|contains`; atsvc gains T1021.002 to back its lateral-movement tactic |
| `kubernetes_audit_hostpath_mount.yml / kubernetes_audit_privileged_pod_creation.yml` | Top-level `hostPath` / `capabilities` fields do not exist in Kubernetes audit events | `requestObject.spec.volumes.hostPath.path|exists`; privileged: `securityContext.privileged`, dangerous `capabilities.add`, `hostPID`, `hostNetwork` |
| `zeek_http_executable_download_from_webdav.yml` | Proxy field names (`c-useragent`, `c-uri`) on Zeek http.log | Zeek fields `user_agent`, `uri` |
| `proc_creation_win_powershell_susp_child_processes.yml (threat hunting)` | `''` inside `CommandLine|contains` filter matches everything, excluding every wmic child | Removed the empty value |
| `azure_ad_account_created_deleted_nonapproved_user.yml (placeholder)` | `Status: Sucess` and field `Initiatied.By`: never fires | `Success`; `properties.initiatedBy|contains|expand: '%ApprovedUserUpn%'` as a filter |
| `dns_query_win_wscript_cscript_resolution.yml (placeholder)` | `oscp.` typos in the OCSP allowlist | `ocsp.comodoca.com`, `ocsp.sectigo.com`, `ocsp.starfieldtech.com` |

All other rule content is unchanged. ATT&CK tags on the touched rules were checked against Enterprise ATT&CK v19.2 (every technique active, every tactic backed by a tagged technique).

### Changelog

chore: AWS Route 53 Domain Transfer Lock Disabled - drop credential-access (not backed by T1098)
chore: AWS Route 53 Domain Transferred to Another Account - drop credential-access (not backed by T1098)
chore: Password Reset By User Account - drop credential-access (not backed by T1078.004)
chore: Remote Task Creation via ATSVC Named Pipe - Zeek - add T1021.002 to back lateral-movement
fix: Account Created And Deleted By Non Approved Users
fix: DNS Request From Windows Script Host
fix: Potentially Suspicious PowerShell Child Processes
fix: Container With A hostPath Mount Created
fix: Privileged Container Deployed
fix: AWS ElastiCache Security Group Modified or Deleted
fix: AWS Route 53 Domain Transfer Lock Disabled
fix: AWS Route 53 Domain Transferred to Another Account
fix: AWS S3 Data Management Tampering
fix: Password Reset By User Account
fix: Executable from Webdav
fix: Remote Task Creation via ATSVC Named Pipe - Zeek
fix: First Time Seen Remote Named Pipe - Zeek
fix: Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module
fix: AgentExecutor PowerShell Execution
fix: Potential CommandLine Path Traversal Via Cmd.EXE
fix: HackTool - Quarks PwDump Execution
fix: Remote Access Tool - Team Viewer Session Started On Windows Host
fix: COM Object Execution via Xwizard.EXE
fix: New DLL Added to AppCertDlls Registry Key

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
