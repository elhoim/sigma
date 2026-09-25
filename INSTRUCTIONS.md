You are opening the pull requests listed in manifest.tsv (15) on the upstream repository SigmaHQ/sigma on behalf of the user (GitHub user `elhoim`), from branches that already exist in the user's fork `elhoim/sigma`. The user explicitly asked for these PRs to be moved from their fork to upstream. Do exactly this and nothing more.

For EACH PR below, in order:
1. Load the GitHub MCP tools with ToolSearch (`select:mcp__github__create_pull_request,mcp__github__update_pull_request,mcp__github__pull_request_read`).
2. Call mcp__github__create_pull_request with owner `SigmaHQ`, repo `sigma`, base `master`, head `elhoim:<branch>`, maintainer_can_modify true, the exact title, and the exact body given (verbatim, do not reword).
3. The platform may auto-append a footer containing a Claude session link (`claude.ai/code/session_...`). The user forbids session links in PRs. Immediately call mcp__github__update_pull_request on the new PR with the SAME exact body again (this strips the auto-added footer), then mcp__github__pull_request_read method `get` and confirm the body contains no `claude.ai/code/session`. If it still does, retry the update once; if it persists, report it.

HARD LIMITS: do not push, commit, create or modify any branch, file or repository; do not post comments or reviews; do not request reviewers; do not close, merge or edit any other PR. Never include a Claude session link anywhere. If a create fails (e.g. a PR for that head already exists, permissions), do not work around it: record the exact error and continue with the next one.

After all of them: subscribe to PR activity for each created PR (mcp__github__subscribe_pr_activity) so CI results reach this session, and report a table: branch → upstream PR URL → body verified clean (yes/no). If later CI fails on one of these PRs, do not push fixes (you cannot push to the fork): tell the user which check failed and why.

Validation already done by the parent session: every branch merges cleanly onto SigmaHQ/sigma master (9e543da66), and the full repo CI replica (yamllint, test_logsource, test_rules, sigma check, 463 regression tests) passed on each; the same branches are green on the fork's GitHub Actions.
