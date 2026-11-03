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

Your coding agents take orders from more files than you think. `CLAUDE.md` and `AGENTS.md` are the ones you see. The rest sit in your home folder and app settings: `~/.claude.json`, `~/.codex/config.toml`, editor settings, plugin and skill folders, shell aliases. Any one of them can turn approvals off, hand an agent your whole disk, or start an MCP server that runs whatever its package publishes next.

misconfig finds every one of those files, on your computer and in your project, says what each one tells your agents to do, and flags the settings that put your machine at risk, worst first, with the exact fix.

```sh
npx @misconfig/cli
```

It runs on your computer. Nothing about your setup is uploaded, and it needs no account or API key.

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
| `--explain` | Shows everything each file sets: permission modes, allowed and blocked actions, MCP servers and what they run, hooks, trusted folders, hidden text, and the agents and extensions installed |
| `--open` | Saves the full report as one page in your temp folder and opens it in your browser. The page has no scripts and loads nothing from the internet |
| `--lookup` | Also looks up the MCP packages, extensions and agent versions it found on [OSV.dev](https://osv.dev). It lists the names and versions it would send and asks first |
| `--offline` | Skips the download of today's malware list and uses the one in the release. Same as `MISCONFIG_OFFLINE=1` |
| `--project-only` | Skips the agent settings on this computer |
| `--fail-on <level>` | Exits with code 1 if it finds anything at that level or worse: `critical`, `high`, `medium` or `low` |
| `--json` | Prints the full result as JSON |
| `--yes` | Runs `--lookup` without asking, for scripts |

### In CI

Run it before installing dependencies, so a lockfile that pins a known malicious package fails the build before the package runs:

```sh
npx @misconfig/cli --project-only --fail-on high
```

Exit codes: `0` when the check ran and nothing reached `--fail-on`, `1` when something did, `2` for errors, or with `--fail-on` when the folder was too large to check completely, and `130` when you press Ctrl+C at a question.

## Privacy

- The check runs on your computer, and what it works out about your files stays there.
- Its one request on its own downloads today's list of known malware from misconfig.ai. The request carries the command's version and the kind of system, and nothing about your setup. `--offline` skips it, and `DO_NOT_TRACK=1` keeps the run from being counted.
- `--lookup` sends package names and versions to OSV.dev, and only after you approve the list.
- Credential files such as `.env` and `id_rsa`, and programs inside skills, are listed by name only and never opened. Secrets inside agent files are masked as they're read.

The [privacy policy](https://misconfig.ai/privacy) lists everything misconfig.ai receives and how long it's kept.

## Known malware

Each release bundles every MCP package and editor extension that OSV.dev has listed as malware, the Claude Code, Codex and Claude Desktop versions that are missing security fixes, and the files and workflows that attacks such as s1ngularity and Shai-Hulud leave behind, each with its source. Before every check, the command also downloads today's list, which misconfig.ai rebuilds from OSV.dev every hour, so new listings are caught without waiting for a release.

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

## Contributing

Bug reports are the most useful help right now: a finding that's wrong for your setup, a risky setting it missed, or an agent it doesn't know yet. Please [open an issue](https://github.com/gkdataio/misconfig/issues). We aren't accepting code contributions yet. [CONTRIBUTING.md](https://github.com/gkdataio/misconfig/blob/main/CONTRIBUTING.md) explains why.

## Security

Please don't report vulnerabilities in public issues. Email [security@misconfig.ai](mailto:security@misconfig.ai) or use GitHub's private vulnerability reporting. [SECURITY.md](https://github.com/gkdataio/misconfig/blob/main/SECURITY.md) has the details.

## License

[Apache-2.0](https://github.com/gkdataio/misconfig/blob/main/LICENSE). The misconfig name and logo are trademarks of GK Data LLC and aren't covered by the license.

<sub>Made by <a href="https://gkdata.io">GK Data LLC</a>. <a href="https://misconfig.ai">misconfig.ai</a></sub>
