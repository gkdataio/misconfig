# Changelog

## 1.3.2 (2026-11-03)

- misconfig is open source under the Apache License 2.0. The code, its tests and the issue tracker are at https://github.com/gkdataio/misconfig. The name and logo stay trademarks of GK Data LLC.
- The package names its repository and issue tracker, so npm links to both.
- The README on npm is the one on GitHub.
- No changes to the checks, the report or what the command sends.

## 1.3.1 (2026-11-03)

Nothing about your setup goes to misconfig.ai:

- `--open` saves the full report as one page on your computer and opens it in your browser. Nothing is uploaded. The page has no scripts, and its content security policy blocks every script and request, so nothing in it can run or load, whatever a checked file says. In CI or a script, it saves the file without opening a browser.
- Share links, README badges, private report links and the browser check at misconfig.ai/check were retired, and misconfig.ai deleted every report it stored. `--share` stops with a message that says so, and old links say the report was retired.
- The only option that sends anything about your setup is `--lookup`, which sends package names and versions to OSV.dev after you approve them. `--yes` now applies to lookups only.

Today's malware list:

- Before each check, the command downloads today's list of known malware from misconfig.ai: what OSV.dev has listed since the release, for MCP and agent packages and editor extensions, updated every hour. New malware is caught without waiting for a release. The list is a few kilobytes, kept in memory for that run, and the report says which list the check used.
- The request names the command's version and the kind of system, which is how misconfig.ai counts runs, and carries nothing about your setup. `DO_NOT_TRACK=1` downloads the list without being counted. `--offline`, or `MISCONFIG_OFFLINE=1`, skips the download and uses the list in the release. If the list doesn't arrive within 5 seconds, the check uses the release's list and says so.

Malware:

- The bundled list includes every MCP package and editor extension OSV.dev listed as malware up to this release: about 150 packages on npm and PyPI and 20 extensions, each with its listing. Before, a check without `--lookup` found 11 of the 159 MCP packages OSV.dev lists; now it finds 157.
- When a listing names only some versions of a package, usually a real package whose publishing account was taken over, only those versions count against it. A server that doesn't pin a version is told those versions were malware and to pin one, not that the package is.
- An extension listed on one marketplace, Microsoft's or Open VSX, is flagged only in editors that install from it. The same ID can be a different publisher's extension on the other.
- `--lookup` fixes:
  - An unpinned package with only some versions listed as malware was reported as malware. It's now "has had versions listed as malware", at high rather than critical.
  - Extensions whose ID has capitals, such as `AzureCdnInfo.edrtester`, were looked up in lowercase, which OSV.dev doesn't match, so their listings were missed. The ID is now read from the extension's own `package.json`, and only the publisher and name are kept from it.
  - VSCodium, Cursor, Windsurf and Kiro extensions are looked up on Open VSX, where they come from, and a VS Code extension is no longer matched with an Open VSX listing for someone else's extension with the same ID.
- The list `--lookup` shows before it sends names where each package comes from in words, npm, PyPI, VS Marketplace or Open VSX, in even columns.
- Versions numbered by date, such as `2.49.1772191521`, are read as versions.

Safer output:

- A project can't put a command of its own into a fix any more. A package name goes into a fix, such as `npm view NAME version`, only when it's a name the registry would accept, so an `.mcp.json` whose arguments hold a download piped into a shell can't make misconfig tell you to run it. That download is still reported as one.
- Marks that reorder text, such as U+202E, and invisible line breaks are shown as � in the terminal and on the page `--open` saves, so a file can't make a finding read differently from what it says.

Fewer false findings:

- Run in your home folder, the command no longer reports "Agent workspace is your home folder" on its own account: it checked the computer's settings, not a project, and each agent's settings already say if it was started there. The header says how to check a project instead. `--project-only` in a home folder still reports it.

## 1.3.0 (2026-11-02)

Everything since 1.1.0. Versions 1.1.1 and 1.2.0 were never published, so their changes are part of this release.

A new look:

- The report follows misconfig.ai: the grade on a yellow square, findings marked in each level's color, and quieter text around them. The grade comes after the findings, so it's on screen when the check finishes.
- Colors use what the terminal supports, from 16 colors to full color. Output piped to a file or a CI log is plain text, and `NO_COLOR` and `FORCE_COLOR` work as in Node.
- `--explain` lists each file's details under it, and long paths are shortened in the middle so the file name stays visible.
- Clearer summaries: long text is shortened at a word boundary, paths show your home folder as `~` and keep the folder or file name visible, servers with many environment variables show a count, and every permission mode is named.

Reading the findings:

- Every finding names its rule, such as `CC-ALLOW-ALL-BASH`, after its location. misconfig.ai/rules lists every rule with what it looks for, why it matters and how to fix it, in the words reports use.
- On report pages, critical and high findings open with why they matter and the fix showing, and the rest open on a click. A key above the findings says what each level means and how the score is worked out.
- The command explains medium findings too, not only critical and high ones.
- Each level has one definition, on misconfig.ai/rules, and every rule follows it. Critical is kept for malware, signs of an attack, instructions hidden from you and code downloaded and run automatically. A setting that turns off all of an agent's prompts is high in every agent, so Claude Code's `bypassPermissions` and Codex's YOLO mode are high, not critical. Direction marks and zero-width characters are medium, while Unicode tag characters, which can hold a whole hidden instruction, stay critical. Notes such as many MCP servers or a very large instruction file no longer change the score.
- Findings say which setting does what and what follows from it, and each fix names the setting to change. Findings about a known malicious package or extension name who reported it, and so do findings that cite an attack as an example, such as postmark-mcp (Koi Security, September 2025) and ClawHavoc (Koi Security, February 2026).
- Gemini CLI turns YOLO mode on only from the command line, so a settings file that asks for it is noted, not reported as high, and it no longer hides `autoAccept` or `auto_edit` in the same file.
- Aider's `yes-always` is low: Aider adds and edits files without asking, but shell commands still need an explicit yes.
- "Checked" counts the agent files that were read and checked, the same in the command and on every report.
- Joiners inside emoji sequences, the joiners and breaks that Persian, Hindi, Thai and other scripts use between letters, and the flags of England, Scotland and Wales are no longer reported as hidden characters.

Malware and missing fixes:

- MCP servers that run a known malicious package, a package that has shipped malware without a pinned version, or a lookalike of an official package, such as `@modelcontextprotocol/server-filesytem`. Servers that run code straight from a git repository, a web address, a temp folder or Downloads are reported too.
- Editor extensions in VS Code, Cursor, Windsurf, Kiro and VSCodium that are known malware, including the tampered Claude Code extension Cursor's marketplace served in October 2026 and the GlassWorm extensions, copies of agent extensions such as Claude Code and Cline from other publishers, and extensions installed from files.
- Claude Code, Codex and Claude Desktop versions missing security fixes, from npm, Claude Code's own installer, Homebrew, Volta, pnpm and bun installs, with the command that updates each one.
- Packages that were malware, such as the Nx releases from the s1ngularity attack: installed globally, in a project's `node_modules` (pnpm's store included), or pinned in its lockfile (npm, pnpm, Yarn or Bun), so a check in CI catches them before anything is installed.
- Files and workflows attacks leave behind: s1ngularity's secret lists and shell line, Shai-Hulud's workflows and runner, and the tampered Cursor extension's tunnel. They're found by name; their contents are never read.
- Skills that come with a program or an archive, which is listed by name and never opened, and Claude Code plugin marketplaces that Anthropic doesn't run.
- Agent files that send the agent to a paste site, give the password to an archive, turn off macOS's check on downloaded apps, or name a server used in a reported attack.
- `--lookup` also asks OSV.dev about the MCP packages, extensions and agent versions found, for malware and known vulnerabilities, including anything reported since the release. It lists the package names and versions it will send and asks first. Nothing else is sent, a name that isn't in its registry's format (a path or a repository, say) isn't either, and nothing goes to misconfig.ai. Answers are checked before they're used, and what the bundled list already reported isn't repeated.
- `--explain` and the private report list the AI agents installed and the AI agent extensions in each editor, with their versions.

New coverage:

- GitHub Copilot on the command line (`~/.copilot`), and Copilot hooks in `.github/hooks`.
- Cursor hooks, sandbox and command permissions; Cline's YOLO and auto-approve settings; Grok's `config.toml`; Amp; Goose; Continue's data destinations; Junie's MCP servers.
- Gemini CLI trusted folders, extensions, system settings and `defaultApprovalMode`.
- Claude Code plugins (only the installed ones, including hooks and MCP servers named in `plugin.json`), rules, memory files, managed settings folders, HTTP hooks, and commands run by settings such as `apiKeyHelper` and `statusLine`.
- Codex profile files, `-c` overrides that turn off the sandbox or approvals, and skills in `.agents/skills`.
- VS Code settings that let the Claude agent skip permissions, turn off the built-in terminal rules or approve edits to VS Code's own settings.
- Settings files that can't be parsed are reported, rather than passed over.

Settings and files that run code:

- MCP servers are seen through the launchers that start them, such as `cmd /c`, `sh -c`, `bash -lc`, PowerShell's `-Command`, `env`, `npm exec`, `bun x` and `deno run npm:`, so a known malicious package can't hide behind a shell.
- Settings that make every command the agent runs load other code: `NODE_OPTIONS` with `--require` or `--import`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, Java and .NET startup hooks, git's `GIT_SSH_COMMAND` and config variables, and a `PATH` that puts a project's own folders first. They're found in Claude Code's `env`, Codex's `shell_environment_policy`, Aider's `set-env` and an MCP server's environment. A value that only tunes a program, such as `--max-old-space-size`, isn't reported.
- Hooks and commands in more agents: Gemini CLI hooks and the commands that find and call its tools; Codex hooks, model provider key commands and MCP header helpers; Windsurf and Devin hooks; Kiro hooks and agents; Amazon Q agents; Grok hooks and its status line command; the commands Cursor runs for background agents; and Aider's lint, test and notification commands.
- Codex command rules in `.codex/rules` that let a shell, a downloader or every git command run outside the sandbox without asking, as one finding for each rules file, however many commands you approved. Rules are read the way Codex reads them: a rule with no decision allows, the strictest matching rule wins, and comments, text in strings and names set at the top of the file can't hide a rule.
- Kiro and Amazon Q agents that pre-approve the shell, through `allowedTools`, `toolsSettings` or Kiro's `permissions` rules. Kiro agents written in Markdown are read as instructions.
- Plugin code a project gives OpenCode, Amp or Cline, which they load as they start, without asking. It's listed by name, never opened, and shown in the list of files that control your agents.
- MCP servers in Continue's and Goose's YAML settings.
- The list of files that control your agents says what each of these does, such as which commands a rules file lets through and which hooks run when.

More accurate:

- Options that turn approvals off are credited to the command they belong to, so `npx -y` and `gemini mcp add ... npx -y` no longer count. Options for Codex, Copilot, Cursor, Aider, Amp, Grok and Kiro are recognized.
- `bypassPermissions` in a project's own settings is now medium, since Claude Code 2.1.257 and later ignore it there.
- Ignore rules are matched the way git matches them, including nested `.gitignore` files, `.git/info/exclude` and git's global ignore list, where Claude Code adds its local settings.
- Fewer false alarms, checked against public repositories: instructions that quote an injection as an example, hooks that only download or clean up a named folder, `curl -f`, public certificates, keys in test and example folders, a project's `.npmrc`, `.env.local.sample`, `Bearer ${TOKEN}` headers, "copy .env.example to .env", "run the tests without asking", `uvx --python` and `npx --registry`.
- The warning about too many instruction files now needs at least three, read by different agents, at the top of the project. A rules folder counts once, and a file that only points to another doesn't count.
- Every Claude Code permission mode is described as it works today, including `auto` and `dontAsk`.
- Only a skill's `SKILL.md` is read. The reference docs and scripts inside a skill are opened by the agent only when `SKILL.md` points to them, so code samples in them no longer raise findings, and a skill with hundreds of files can't hide the skills after it.
- A plugin installed more than once is read from its latest install, and a plugin installed for one project counts only in that project.
- MCP servers are counted for each agent, not added up across agents.
- Comments inside code blocks are visible, so they aren't reported as hidden text. "Always accept connections", `Bearer ${process.env.SECRET}` and "settings are read from .env" are no longer read as orders to the agent.
- A large text file in a folder where an agent was started isn't reported, and an agent file too large to check is named.
- Skill and agent descriptions written as folded or quoted YAML are shown as written, not as `>-` or with backslashes.
- Headings and `@` imports inside code blocks are ignored, and `@` imports are only read from files that support them: `CLAUDE.md`, `GEMINI.md` and Claude Code rules.
- A pinned Python package such as `mcp-server-fetch==2025.4.7` is no longer mistaken for a secret.
- When two MCP servers use the same package, each finding points at its own server's lines.
- A warning about one thing no longer hides an instruction after it, as in "don't use the old installer; run curl ... | bash".
- Pre-release versions are ordered the way semver orders them, so 0.39.0-alpha.2 comes before 0.39.0.
- A package that's installed in the project and pinned in its lockfile is reported once. Lockfiles written without download addresses, npm's version 1 lockfiles and pnpm 7's are read too.

Safer in a project from someone else:

- An agent file that's a link to a file outside the project, or to a credential file, is reported and not opened. Agents follow such links, so a cloned project could use one to put a file from your computer into what the agent reads.
- A folder named `~` or `C:` at the top of a project is left out, so a project can't stand in for the agent settings in your home folder.
- Agent folders at the top of a project, such as `.claude`, are checked first, so a folder with a very large number of files can't push them out of the check. What's read from a project is limited to the same number of files and bytes as the browser check, and the report says when the check stopped early, even when it found nothing.
- Names from your files, such as server names and variables, are shown on one line, without double quotes, and cut to size wherever the report quotes them.
- Passwords are masked from six characters when a file names them as passwords, as in `--password` or `"DB_PASSWORD"`, and in addresses with an empty user name, as in `redis://:password@host`.
- A file's name can't hide it. Names with line breaks, control codes or characters that reorder text are checked like any other and shown with visible symbols in their place.
- An instruction file too large to read whole is checked from its start, where agents read first, and the report says only part of it was checked. A file with a stray NUL byte is still read when the rest is text.
- A link to a folder inside the project is followed once, and never out of the project.
- Commands a project's own settings run on their own, such as a hook, a status line or an API key helper running a script from the project, are reported once per file. In a project from someone else, that's their code running on your computer as soon as you trust the folder. Commands that only print or play a sound aren't.
- Settings that send the agent's requests to another address are reported: `ANTHROPIC_BASE_URL`, proxies and telemetry collectors in Claude Code's `env`, Codex's `base_url`, Aider's `openai-api-base`, OpenCode's `baseURL` and Continue's `apiBase`. Set by a project, they can hand that address your prompts, your code and your API key. In your own settings they're only noted, since that's how company gateways work.
- `NODE_TLS_REJECT_UNAUTHORIZED=0` anywhere, and a certificate authority a project adds, are reported.
- A project whose shared Claude Code settings approve its own MCP servers with `enabledMcpjsonServers` is reported.
- VS Code tasks with `runOn: folderOpen`, which Cursor runs as soon as a folder opens because it ships with Workspace Trust off. The finding points at the `runOn` line.
- MCP servers that run a script from the project, or a shell given a download to run.
- Windsurf workflows, Gemini CLI custom commands, and files a setting names as instructions: Gemini CLI's `context.fileName`, Codex's `project_doc_fallback_filenames`, OpenCode's `instructions` and Aider's `read`. One that points out of the project, or at a web page, is reported.
- Instructions that send the agent to a web page for its steps, and more ways of downloading and running code: saving a script and then running it, `python -c "$(curl ...)"`, and `deno run` or `npx` with a web address.
- A link from an agent folder, such as `.claude` or `.cursor/rules`, to a folder outside the project.
- Codex rules made in a function or a loop, or from an expression, which the check can't read, are reported instead of passed over.
- Settings are read the way the agents read them in more spellings: YAML with quoted keys, `yes`, tags, anchors, block text and flow mappings, and TOML escapes in keys and strings.

Private reports:

- `--open` puts the full report, everything `--explain` shows included, on a private page at misconfig.ai, laid out for reading and printing. The report is encrypted on your computer before it's sent, and the key stays in the part of the link browsers never send, so misconfig.ai can't read it. It's deleted after 7 days, or sooner with the delete link.
- The private page trusts nothing in a link, since anyone can make one. Every finding is rebuilt from the rule catalog, the grade is worked out again, and names and file text are shown only as text. Commands, advice, sources and what known malware does must be misconfig's own words, so a link can't tell its reader to run something misconfig never suggested.
- Links printed after `--share` and `--open` are built from the report's ID, and replies from the server are shown on one line with control codes replaced.
- `MISCONFIG_URL` must be an https address, or http on this computer for testing.

Share links and privacy:

- A share link never drops a finding. Before it sends anything, `--share` asks misconfig.ai which set of checks it runs, and if the site doesn't know every check yet, nothing is sent; the site refuses such a report too. A finding in a file a share link can't name, such as one a setting names as instructions, also stops the share, and so do more than 400 findings. The command suggests `--open` for a private report instead.
- A finding in a file with a space or another unusual character in its name is shared under a plain name, such as `my_rule.mdc`, instead of being left out.
- Shared reports name agent files only, describe options and Docker mounts in fixed words, and leave out any value a check wouldn't produce. Claude Code memory files, whose folders are named after local paths, are never shared.
- `--project-only` and `--share` also use git's global ignore list, so a shared report agrees with what you see locally.
- From `~/.claude.json`, only the MCP servers, the folders Claude Code has been started in and the tools approved in each are kept. The API key field is no longer kept, even masked.
- Shared reports name the setting that approves tools automatically, such as `chat.tools.autoApprove`.

More reliable:

- Linked agent files, such as a `CLAUDE.md` that links to `AGENTS.md`, are read.
- Settings on a network share, such as a redirected AppData folder, and PowerShell profiles in a OneDrive Documents folder are found.
- A file that a check can't handle is reported as unchecked instead of stopping the report.
- Files saved as UTF-16 are read, and binary files are skipped.
- Large folders are walked from the top down, and the report says when a folder was too big to check completely. With `--fail-on`, that exits with code 2.
- A folder that doesn't exist is an error, not an empty report.
- Control codes and line breaks in files can't change what the terminal shows.
- Hostile files can't slow the check down.
- When the network fails, the message says why, such as an address that can't be found, a refused connection, a certificate your network replaces, or no answer within 30 seconds, and whether anything was sent. It suggests the proxy or certificate setting to try.
- Output piped into a command that stops reading, such as `head`, ends quietly.
- Ctrl+C at a question stops the command with exit code 130, and nothing is sent.
- `--open` says plainly when a site can't take private reports yet.
- A large `~/.claude.json` is read quickly whatever its formatting.

Package:

- The package includes this changelog and a license notice.

## 1.1.0 (2026-11-01)

- The report now lists every file that controls your agents, grouped by where it applies, with a plain-language summary of what each one tells them.
- New `--explain` option: shows everything each file sets, including permission modes, allowed and blocked actions, MCP servers and what they run, hooks, trusted folders, and what instruction files say, including text that's hidden when you read them.
- Shared reports leave out names taken from your files, such as MCP servers, packages, commands and environment variable names.
- The advice for an unpinned MCP server now includes the command that shows its newest version.

## 1.0.1 (2026-11-01)

- File paths in environment variables are no longer reported as secrets.
- Text files in the home folder are reported only when they contain instructions for an agent.
- `~/.codex/AGENTS.md` is attributed to Codex only.

## 1.0.0 (2026-11-01)

- First release.
