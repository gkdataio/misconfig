<p align="center">
  <a href="https://misconfig.ai"><img src="https://raw.githubusercontent.com/gkdataio/misconfig/main/assets/banner.png" alt="misconfig.ai: Is your AI setup misconfigured?" width="100%"></a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@misconfig/cli"><img src="https://img.shields.io/npm/v/@misconfig/cli?style=flat-square&label=npm&labelColor=0a0b0d&color=eaff57" alt="npm version"></a>
  <a href="https://github.com/gkdataio/misconfig/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-eaff57?style=flat-square&labelColor=0a0b0d" alt="License: Apache-2.0"></a>
  <a href="https://github.com/gkdataio/misconfig/blob/main/package.json"><img src="https://img.shields.io/badge/dependencies-none-eaff57?style=flat-square&labelColor=0a0b0d" alt="No dependencies"></a>
  <a href="https://misconfig.ai/rules"><img src="https://img.shields.io/badge/rules-misconfig.ai%2Frules-eaff57?style=flat-square&labelColor=0a0b0d" alt="Every rule explained"></a>
</p>

# misconfig

misconfig checks the settings that control Claude Code, Codex and other coding agents. It shows which file sets a permission, starts an MCP server or runs a hook, explains the risk, and gives you a fix. Version 1.4 adds a local history of what changed on your computer and who approved it.

To hear when a release ships, choose **Watch → Custom → Releases** on the [GitHub repository](https://github.com/gkdataio/misconfig), or subscribe to the [release feed](https://github.com/gkdataio/misconfig/releases.atom). These channels also work for people who keep using 1.3.2.

## New in 1.4

The demo requires CLI 1.4 or newer and Node.js 18 or later. Try it on a sample profile. On Windows, use `npx.cmd` if PowerShell blocks `npx`.

```sh
npx @misconfig/cli@latest --demo
```

The demo changes a sample calendar server from 1.2.3 to 1.2.4. A sample Codex record identifies the editor. You can approve that update, then accept a separate warning about an unpinned mail server and see it stay in the report. All decisions use the fictional account **Demo reviewer**. The demo runs offline and deletes the sample profile when you finish. Add `--open` to keep an HTML report. From a 1.4 source checkout or the extracted demo bundle, run `node bin/misconfig.js --demo` or double-click `demo.cmd` on Windows.

### Review your computer

```sh
npx @misconfig/cli@1.4.0
npx @misconfig/cli@1.4.0 --review
npx @misconfig/cli@1.4.0 --history
```

Your first scan lists the settings available for review. **Since your last scan** shows later additions, edits and removals. **Awaiting your approval** also includes changes you skipped. The same local history follows you across project folders.

Press **Y** to approve the displayed item, **Enter** to skip it, or **Q** to finish. Each decision is saved immediately. To decide one item by ID, run `--approve ID` with the ID shown in your scan. The command checks the current value again before saving your decision.

Approving a setting records the value you expect. Accepting a risk separately adds **Risk accepted**, the date and the approving account to that warning. Its severity, fix and effect on the score stay visible in text, JSON and HTML. **Earlier risk decisions** lists accepted findings that have disappeared or whose file could not be verified. A skipped change stays pending until you approve it or the setting returns to its approved value.

misconfig compares the computer and administrator settings it discovers, including MCP servers, hooks, permissions, instructions, shell settings, installed agent versions and AI editor extensions. The report names any source it could only partly read and preserves its earlier decision. For full setting values, open the named file.

`--history` reads the saved timeline without rescanning. It shows the observation time, any evidence about the editor, and the OS account that approved the change. People sharing a login share that reviewer name. Use `--history --json` for chronological events or expand **Computer history** in an HTML report.

### Who changed a setting?

Run `npx @misconfig/cli@1.4.0 --offline --attribute` to match observed edits against local Claude Code or Codex records. This works after approval, too. To read particular sessions, pass `--session "path/to/session.jsonl"` for each one.

An agent attribution requires a completed file tool, the same file, the exact change to the setting, and a tool timestamp between the two scans. Supported records include Claude Code’s Edit and Write results and Codex’s completed file changes with numbered diffs. Reconstructed patches must also match the saved file fingerprints. A shell command, file owner, or nearby agent session alone leaves the author unknown. A matching record identifies a recorded edit. Other unlogged writes can produce the same setting, and local records are editable.

If you made an edit yourself, use its `e-` ID from `--history`. For example, `npx @misconfig/cli@1.4.0 --i-edited e-4` records your OS account as **self-reported**. Conflicting sources appear as uncertain. An edit with no matching evidence stays **Edit author unknown**.

Session records can contain private conversations and tool inputs. Only `--attribute` or `--session` reads them on your computer. Automatic discovery searches the last seven days in Claude’s projects and Codex’s sessions and archived sessions, honoring their config directory overrides. The search reads up to 48 local files, 4 MiB from the end of each, up to 32 MiB total. It reports partial coverage when a limit or read error is encountered. Only matching source labels and timestamps enter the history.

### npm release notices

Starting in 1.4, interactive computer scans check the public npm `latest` tag. A successful check is cached for 24 hours. The terminal announces the current release once, or shows both versions and the upgrade command if a newer stable version is available. Run `--check-update` at any time, including with `--json`.

`--no-update-check` or `MISCONFIG_NO_UPDATE_CHECK=1` disables automatic release checks. Offline, demo, history, JSON, CI and project-only scans skip them. The registry request contains only the public package name. Installing an update remains your choice.

<p align="center">
  <img src="https://raw.githubusercontent.com/gkdataio/misconfig/main/assets/terminal.png" alt="misconfig checking a sample project: the files that control its agents, two critical findings with their fixes, and a grade of F" width="820">
</p>

## What it checks

| Area | What it looks for |
| --- | --- |
| Permissions | Bypass and YOLO modes, allow-everything rules, auto-approve settings, shell aliases that start agents with approvals off, settings that send an agent's requests to another address |
| MCP servers | Tokens pasted into config, unpinned packages, plain-HTTP remotes, servers that run code from the project, servers that can run shell commands or read your whole disk |
| Instructions and skills | Invisible Unicode, orders hidden in HTML comments, download-and-run commands, links to data-collection endpoints |
| Hooks | Hooks and editor tasks that run on their own, download and run code, send data over the network, or run commands that can't be undone |
| Where agents run | Agents started in Downloads or your home folder, folders an agent trusts that it shouldn't, secret files git doesn't ignore |
| Installed code | MCP packages, editor extensions and skills that are known malware or copy an official name, agent versions missing security fixes, files that attacks leave behind |

It reads the settings of Claude Code, Claude Desktop, Codex, GitHub Copilot, Cursor, Gemini CLI, OpenCode, Cline, Windsurf, Zed, Grok, Amp, Goose, Continue, Roo Code, Kiro, Amazon Q, Junie and Aider.

Every rule, with why it matters and how to fix it, is at [misconfig.ai/rules](https://misconfig.ai/rules).

## Usage

Run it in the folder you open your agents in, usually the project root. It works on macOS, Windows and Linux with Node.js 18 or later. On Windows, if PowerShell blocks `npx`, type `npx.cmd` instead.

```sh
npx @misconfig/cli              # this project and the agent settings on this computer
npx @misconfig/cli --explain    # everything each file tells your agents
npx @misconfig/cli --open       # the full report as a page on your computer
npx @misconfig/cli --lookup     # also ask OSV.dev about what's installed
```

| Option | What it does |
| --- | --- |
| `--demo` | Try a version change, a risk decision and their history on a disposable sample computer |
| `--review` | Walk through pending computer changes and risk decisions in a terminal |
| `--approve ID` | Approve one current change (`c-…`) or accept one current finding (`r-…`) |
| `--history` | Read the local timeline of observed changes, approvals and risk acceptances. Add `--json` for machine-readable events |
| `--no-history` | Scan once without reading or writing computer review history |
| `--attribute` / `--session FILE` | Match observed edits with recent or explicitly chosen local agent records |
| `--i-edited ID` | Record a self-reported manual edit against its observed event ID |
| `--check-update` / `--no-update-check` | Check npm now or skip the automatic release check |
| `--explain` | Shows everything each file sets: permission modes, allowed and blocked actions, MCP servers and what they run, hooks, trusted folders, hidden text, and the agents and extensions installed |
| `--open` | Saves the full report as one page in your temp folder and opens it in your browser. The page has no scripts and loads nothing from the internet |
| `--lookup` | Also looks up the MCP packages, extensions and agent versions it found on [OSV.dev](https://osv.dev). It lists the names and versions it would send and asks first |
| `--offline` | Use bundled malware data and skip the npm version check. An explicit `--lookup` still asks to contact OSV.dev. Same as `MISCONFIG_OFFLINE=1` |
| `--project-only` | Skips the agent settings on this computer |
| `--fail-on <level>` | Exits with code 1 if it finds anything at that level or worse: `critical`, `high`, `medium` or `low` |
| `--json` | Prints the full result as JSON |
| `--yes` | Runs `--lookup` without asking, for scripts |
| `--help` / `--version` | Print the supported options or installed version |

### In CI

After checkout, run a project-only scan before installing the project's dependencies. Pin the CLI version in your workflow. This mode checks repository findings and skips personal approvals and history.

```sh
npx --yes @misconfig/cli@1.4.0 --project-only --fail-on high
```

On GitHub, copy the [example workflow](https://github.com/gkdataio/misconfig/blob/main/examples/github-actions/misconfig.yml) into `.github/workflows/misconfig.yml`. It checks out the repository, sets up Node.js and runs the CLI as a shell step. The `--yes` before the package name lets npx fetch the pinned CLI.

With `--fail-on high`, exit `0` means the scan finished below the threshold, `1` means a high or critical finding, and `2` means an error or an incomplete scan with no finding at the threshold. An interrupted prompt returns `130`.

## Privacy

- Computer scans save review history under `~/.misconfig/computer-v1/`. It contains paths, labels, short summaries, keyed fingerprints, observation times and review decisions. The OS account that owns the files can edit them. `--no-history` skips this storage. HTML and JSON reports can include paths and reviewer names, so check the contents before sharing them.
- The malware-list request to misconfig.ai carries the CLI version and operating system family. Interactive computer scans also check the public package version on npm. `--offline` skips both requests, and `DO_NOT_TRACK=1` keeps the malware-list request from being counted.
- `--lookup` sends package names and versions to OSV.dev after the prompt, or with the CLI's `--yes`. The `npx` launcher may contact npm to fetch the CLI before its own offline mode starts. An installed copy or the extracted demo works without that download.
- Credential files such as `.env` and `id_rsa`, and programs inside skills, are listed by name only and never opened. Secrets inside agent files are masked as they're read.

The [privacy policy](https://misconfig.ai/privacy) lists everything misconfig.ai receives and how long it's kept.

## Known malware

Each release bundles known malicious MCP packages and editor extensions, advisories for Claude Code, Codex and Claude Desktop, and traces left by attacks such as s1ngularity and Shai-Hulud. Each entry names its source. An online scan also downloads the malware list that misconfig.ai rebuilds from OSV.dev every hour.

misconfig isn't an antivirus. It doesn't scan programs or watch what your agents do while they run, so keep approvals on for anything you can't undo.

## Read the code

misconfig is plain JavaScript with no dependencies, so what you install is what's in this repository.

| Path | What's in it |
| --- | --- |
| [`engine/catalog.js`](https://github.com/gkdataio/misconfig/blob/main/engine/catalog.js) | The wording, level and fix of every rule |
| [`engine/index.js`](https://github.com/gkdataio/misconfig/blob/main/engine/index.js) | The checks that apply the rules, and the scoring |
| [`engine/known.js`](https://github.com/gkdataio/misconfig/blob/main/engine/known.js) | Known malware, agent advisories and attack traces, each with its source |
| [`engine/locations.js`](https://github.com/gkdataio/misconfig/blob/main/engine/locations.js) | Where each agent keeps its files on macOS, Windows and Linux |
| [`lib/discover.js`](https://github.com/gkdataio/misconfig/blob/main/lib/discover.js) | Which files the command reads, and the limits on what it reads |
| [`lib/html.js`](https://github.com/gkdataio/misconfig/blob/main/lib/html.js) | The page `--open` saves |
| [`lib/computer-review.js`](https://github.com/gkdataio/misconfig/blob/main/lib/computer-review.js) | Changes, approvals and accepted risks |
| [`lib/edit-attribution.js`](https://github.com/gkdataio/misconfig/blob/main/lib/edit-attribution.js) | How optional local edit records are matched |

## Contributing

Bug reports are the most useful help right now: a finding that's wrong for your setup, a risky setting it missed, or an agent it doesn't know yet. Please [open an issue](https://github.com/gkdataio/misconfig/issues). We aren't accepting code contributions yet. [CONTRIBUTING.md](https://github.com/gkdataio/misconfig/blob/main/CONTRIBUTING.md) explains why.

## Security

Please don't report vulnerabilities in public issues. Email [security@misconfig.ai](mailto:security@misconfig.ai) or use GitHub's private vulnerability reporting. [SECURITY.md](https://github.com/gkdataio/misconfig/blob/main/SECURITY.md) has the details.

## License

[Apache-2.0](https://github.com/gkdataio/misconfig/blob/main/LICENSE). The misconfig name and logo are trademarks of GK Data LLC and aren't covered by the license.

<sub>Made by <a href="https://gkdata.io">GK Data LLC</a>. <a href="https://misconfig.ai">misconfig.ai</a></sub>
