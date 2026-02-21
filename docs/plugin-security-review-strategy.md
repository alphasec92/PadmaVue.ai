# Plugin Security Review Strategy

## Problem Statement

AI coding agents (Cursor, Claude Code, Codex, etc.) now support third-party plugins that can inject system prompts, execute hooks, run shell scripts, and shape agent behavior. Unlike traditional package managers with established supply chain security tooling, the plugin ecosystem lacks standardized vetting processes.

A malicious or compromised plugin can:

- **Exfiltrate source code** via crafted tool calls or network requests hidden in hooks
- **Inject vulnerable code patterns** through prompt manipulation
- **Access secrets** by reading environment variables or credential files
- **Modify the filesystem** by writing to or deleting files silently
- **Override safety instructions** through prompt injection in skill/agent definitions
- **Auto-update to a malicious version** if pinned to a branch rather than a tag
- **Run arbitrary server-side code** if the plugin registers MCP servers with network/filesystem access

Additionally, a previously safe plugin can become dangerous through **supply chain compromise** — e.g., maintainer account takeover, dependency hijacking, or a malicious commit merged into a trusted repo (as seen in incidents like event-stream, ua-parser-js, and colors.js).

The challenge: most plugins are a mix of harmless Markdown (prompt instructions) and a small amount of executable code (shell scripts, JS/Python modules). Reviewers need a systematic way to separate signal from noise and focus on what can actually cause harm.

---

## High-Level Review (5-Minute Triage)

Use this to quickly decide if a plugin warrants a full review or should be rejected outright.

### 1. Author & Reputation

| Signal | What to Check |
|--------|---------------|
| Who is the author? | GitHub profile, other projects, community standing |
| Is the author a known entity? | Search for prior open source contributions, blog posts, conference talks |
| Is there an organization behind it? | Org-backed repos have more accountability |

### 2. Community Adoption

| Signal | What to Check |
|--------|---------------|
| Stars & forks | Higher numbers = more eyes on the code (not a guarantee, but a signal) |
| Open issues / PRs | Active community engagement suggests ongoing scrutiny |
| Recent activity | Stale repos may have unpatched vulnerabilities |
| Contributors | Single-author vs. multi-contributor |

### 3. Manifest & Permissions (Quick Scan)

Look at the plugin manifest file (e.g., `plugin.json`, `package.json`):

- What hooks does it register? (session start, pre-commit, etc.)
- Does it declare MCP servers? (These run as separate processes with their own network/filesystem access — treat as high risk.)
- Does it request shell execution, network, or filesystem permissions?
- Does it bundle or reference any external dependencies?

### 4. Repo Structure (Quick Scan)

| Green Flags | Red Flags |
|-------------|-----------|
| Mostly Markdown/text files | Minified or obfuscated JS/Python |
| MIT/Apache license | No license |
| Small number of executable files | Large `node_modules` or vendored binaries |
| Tests directory present | Base64-encoded strings in source |
| Clear README with install instructions | `eval()`, `exec()`, or dynamic code execution |

### 5. Triage Decision

- **Pass** — Proceed to full review
- **Flag** — Proceed with caution, escalate concerns
- **Reject** — Do not install; document reason

---

## Full Review Steps

### Step 1: Identify the Executable Surface Area

Not all files in a plugin can cause harm. Focus on what actually runs.

**Executable files to review:**

| File Type | Examples |
|-----------|---------|
| Shell scripts | `*.sh`, `*.cmd`, `*.bat` |
| JavaScript/TypeScript | `*.js`, `*.ts`, `*.mjs` |
| Python | `*.py` |
| Plugin manifests | `plugin.json`, `package.json`, `hooks.json` |
| MCP server definitions | Server configs that spawn processes with network/filesystem access |

**Files that shape agent behavior (indirect execution risk):**

| File Type | Risk |
|-----------|------|
| Agent config files (`.cursorrules`, `AGENTS.md`) | Can instruct the agent to run shell commands, read files, or make requests on the user's behalf |

**Files that are prompt-only (lower risk but still review):**

| File Type | Risk |
|-----------|------|
| `SKILL.md`, `*.md` in skills/commands/agents | Prompt injection — can influence agent behavior but cannot execute system commands directly |

### Step 2: Review Executable Code for Dangerous Patterns

Search every executable file for the following patterns:

#### Network Access

JS/Node patterns:

```
rg -n 'fetch\(|\.get\(|\.post\(|axios|XMLHttpRequest|net\.connect|\.createServer|WebSocket' <plugin-dir>
```

Python patterns:

```
rg -n 'requests\.|urllib|httplib|http\.client|socket\.connect|aiohttp' <plugin-dir>
```

Shell patterns:

```
rg -n 'curl |wget |nc ' <plugin-dir>
```

Questions to answer:

- Any outbound network calls?
- Is data being sent somewhere? (POST requests, query params with code/env content)
- Are URLs hardcoded or dynamically constructed?

#### Filesystem Writes

JS/Node patterns:

```
rg -n 'writeFile|appendFile|createWriteStream|fs\.write|fs\.mkdir|fs\.rename|fs\.unlink' <plugin-dir>
```

Python patterns:

```
rg -n "open\(.+['\"]w|shutil\.|os\.rename|os\.remove|os\.unlink|pathlib.*write" <plugin-dir>
```

Shell patterns:

```
rg -n '>> |> [^&]|tee |mktemp|chmod |chown |rm |mv ' <plugin-dir>
```

Questions to answer:

- Does the plugin write to files outside its own directory?
- Does it modify dotfiles (`.bashrc`, `.zshrc`, `.gitconfig`)?
- Does it create or modify files in `~/.ssh/`, `~/.aws/`, `~/.config/`?

#### Environment Variable & Secret Access

JS/Node patterns:

```
rg -n 'process\.env|dotenv' <plugin-dir>
```

Python patterns:

```
rg -n 'os\.environ|os\.getenv|dotenv' <plugin-dir>
```

Shell patterns:

```
rg -n '\$SECRET|\$TOKEN|\$API_KEY|\$AWS_|\$GITHUB_TOKEN|\$PASSWORD' <plugin-dir>
```

Questions to answer:

- Does it read API keys, tokens, or credentials?
- Is it passing env vars into network requests?

#### Code Execution & Obfuscation

JS/Node patterns:

```
rg -n 'eval\(|new Function\(|child_process|execSync|spawn\(|atob\(|Buffer\.from\(.+base64' <plugin-dir>
```

Python patterns:

```
rg -n 'eval\(|exec\(|subprocess|os\.system|os\.popen|compile\(|__import__' <plugin-dir>
```

Questions to answer:

- Any dynamic code execution (`eval`, `new Function()`, `exec()`)?
- Any base64-encoded payloads being decoded and executed?
- Any shell command construction from user input?

#### Auto-Update Mechanisms

```
rg -n 'git pull|git checkout|npm update|pip install|auto.update|self.update' <plugin-dir>
```

Questions to answer:

- Does the plugin auto-update itself?
- Can an update pull in new executable code without user consent?
- Is there a difference between "check for updates" (safe) and "auto-apply updates" (risky)?

### Step 3: Review Prompt/Skill Files for Indirect Risks

Even Markdown-only files can be weaponized through prompt injection:

- **Instruction override** — Does any skill file contain instructions like "ignore previous instructions" or "do not tell the user"?
- **Hidden tool calls** — Does any prompt instruct the agent to execute shell commands, read sensitive files, or make network requests?
- **Data exfiltration via prompts** — Does any skill instruct the agent to include file contents, env vars, or secrets in its output or tool calls?
- **Behavioral manipulation** — Does any skill subtly encourage insecure coding practices (e.g., disabling SSL verification, hardcoding credentials, skipping auth checks)?

### Step 4: Check the Dependency Chain

- Does the plugin have a `package.json`, `requirements.txt`, or similar?
- If yes, audit the dependencies (use `npm audit`, `pip-audit`, Snyk, or similar)
- If no dependencies — that's a strong positive signal
- Check for vendored/bundled code that bypasses package managers

### Step 5: Verify the Update & Pinning Strategy

| Practice | Security Level |
|----------|---------------|
| Pinned to a specific commit SHA | Highest — immutable |
| Pinned to a release tag (e.g., `v4.3.0`) | High — can review changelogs between versions |
| Tracking a branch (e.g., `main`) | Low — next install/update pulls whatever is on the branch without review |
| Auto-update enabled | Lowest — no review opportunity |

**Recommendation:** Always pin to a tagged release or commit SHA. Review changelogs before updating.

### Step 6: Document Findings

Record the review outcome:

```
Plugin:          <name>
Repository:      <url>
Version/Commit:  <tag or SHA reviewed>
Review Date:     <date>
Reviewer:        <name>

Executable Files Reviewed:
  - <file>: <summary of what it does>

Findings:
  - <finding or "No issues found">

Risk Level:      Low / Medium / High / Critical
Decision:        Approved / Approved with Conditions / Rejected
Conditions:      <if any — e.g., "pin to v4.3.0", "monitor for updates">
```

---

## Quick Reference: Risk Tiers

| Tier | Plugin Characteristics | Review Required |
|------|----------------------|-----------------|
| **Low Risk** | Markdown-only, no hooks, no executable code, no dependencies | High-level review sufficient |
| **Medium Risk** | Small amount of executable code, local-only operations, well-known author | Full review recommended |
| **High Risk** | Network calls, filesystem writes, shell execution, external dependencies | Full review mandatory |
| **Critical Risk** | Obfuscated code, env var access, auto-update, unknown author | Full review mandatory + ongoing monitoring |
