# Your own rules

misconfig's built-in rules look for risk in the settings of AI coding agents. A team's policy goes further: every request through the company gateway, one approved list of models, no project that approves the deploy script ahead of time. `--rules` adds rules like these to a check.

```sh
npx @misconfig/cli --rules company-rules.json
```

Give `--rules` again for each further file. The format is new in 1.5 and may change before it settles. The changelog will say how to update your rules when it does.

## A rule

A rule names the settings files it reads and what in them makes a finding.

```json
{
  "rules": [
    {
      "id": "ACME-GATEWAY",
      "name": "Claude Code doesn't use the company gateway",
      "severity": "high",
      "category": "permissions",
      "why": "env.ANTHROPIC_BASE_URL in {file} isn't the company gateway, so prompts and code leave without its logging and data controls.",
      "fix": "Set env.ANTHROPIC_BASE_URL to https://llm-gateway.acme.example in {file}.",
      "reference": "https://wiki.acme.example/ai-agents#gateway",
      "files": ["~/.claude/settings.json"],
      "match": [{ "not": { "path": "env.ANTHROPIC_BASE_URL", "equals": "https://llm-gateway.acme.example" } }]
    }
  ]
}
```

A rules file is JSON: one rule, a list of rules, or a list under `rules` as above. [`examples/rules/company.json`](https://github.com/gkdataio/misconfig/blob/main/examples/rules/company.json) is a file to start from.

| Key | Needed | What it is |
| --- | --- | --- |
| `id` | Yes | Capitals, digits and hyphens, up to 40 characters. Start it with your company's name: an ID that a built-in rule has is refused |
| `name` | Yes | What the rule finds, in one line of up to 120 characters. It's the finding's title, and the rule's name in SARIF |
| `title` | | A title that names the file, with `{file}`. Without it, the name is the title |
| `severity` | Yes | `critical`, `high`, `medium`, `low` or `info` |
| `category` | Yes | `permissions`, `mcp`, `instructions`, `hooks`, `workspace` or `installs` |
| `agent` | | The agent the setting belongs to, such as `Claude Code`. Without it, a finding names the agent that reads the file |
| `why` | Yes | Why it matters, in one line of up to 600 characters |
| `fix` | Yes | What to change, in one line of up to 600 characters |
| `reference` | | An `https` address where your team explains the rule. It's the rule's link in the page `--open` saves, `ruleUrl` in JSON Lines and `helpUri` in SARIF |
| `files` | Yes | 1 to 10 paths. The rule reads a file when one of them is its path |
| `scope` | | `project` for files in the checked folder, `computer` for the settings outside it. Without it, both |
| `match` | Yes | What in the file makes a finding |
| `line` | | Text on the line the finding should point at. Without it, that's the first line with the last key of the first path in `match` |

`title`, `why` and `fix` can quote the file's path with `{file}`. Any other key is a mistake, and the command says so.

## Which files

`files` lists paths as the report writes them. A file in the checked folder is named from that folder, such as `.claude/settings.json` or `packages/api/.mcp.json`. One in your home folder starts with `~/`. Any other has its full path, such as `/etc/claude-code/managed-settings.json`. Paths use `/` on every system, and capitals don't matter.

Two marks stand for more than themselves. `**/` in front of a path means in any folder, and `*` in the file's name, up to four times, means any run of characters. Nothing else is special, so a `*` in a folder's name, `?` and `[abc]` are refused.

| Path | The files it means |
| --- | --- |
| `**/.claude/settings.json` | `.claude/settings.json` in the project, at any depth, and in your home folder |
| `~/.claude/settings.json` | Only the one in your home folder |
| `.claude/settings.json` | Only the one at the top of the checked folder |
| `**/.claude/settings*.json` | `settings.json` and `settings.local.json`, anywhere |

A rule can read only the files misconfig already reads: the agent files under "What controls your agents" at the top of the report, and a few others it checks, such as the project's `package.json`. A path in `files` can't make it read another file. Settings written as JSON, TOML or YAML are all read the same way. A rule is tried only on a file that could be read as settings: one that's broken or too large gets a finding from `WS-UNPARSED`, `WS-TOO-LARGE` or `WS-PARTLY-CHECKED` instead. Secrets are masked before any rule sees a file, so a rule can check that a key is there but not what a secret is.

## What makes a finding

`match` is a list of conditions, and the rule holds when all of them do. A condition is a path and one test:

```json
{ "path": "permissions.defaultMode", "equals": "bypassPermissions" }
```

A path is keys joined by dots. For a key with a dot in its name, write the path as a list: `["amp.dangerouslyAllowAll"]`. `*` stands for every key of a mapping and every item of a list, as in `mcpServers.*.command` and `permissions.allow.*`.

| Test | It passes when |
| --- | --- |
| `equals` | The value is this text, number, `true`, `false` or `null` |
| `in` | The value is one of these, up to 50 |
| `contains` | The value has this text in it |
| `startsWith` | The value starts with this text |
| `endsWith` | The value ends with this text |
| `exists` | With `true`, the file has the key. With `false`, it doesn't |

A condition holds when any value its path leads to passes. Text is compared as written, capitals and all. A number and the same number as text are equal, because settings written in YAML are read as text. `true` is not `"true"`.

Conditions combine with `all`, `any` and `not`, nested up to 6 deep, with up to 30 conditions in a rule:

```json
{
  "match": [
    { "path": "model", "exists": true },
    { "not": { "path": "model", "in": ["claude-sonnet-5-5", "claude-opus-5-5"] } }
  ]
}
```

Two things to know about `not`:

- A setting that's missing makes `not` hold. The gateway rule above reports a file that doesn't set the address at all. To report only a file that sets something else, add an `exists` condition, as the model rule here does.
- With `*`, `not` means none. `{ "not": { "path": "mcpServers.*.command", "equals": "npx" } }` holds when no server runs `npx`, not when some server doesn't.

A rule looks at a file as a whole and reports it once. A rule that reports once for each MCP server or each hook isn't possible yet.

## What you get

A finding from your rule is a finding like any other. It's in the report, the page `--open` saves, `--json`, `--jsonl` and SARIF. It takes points off the score at its level, `--fail-on` counts it, and one about a file on your computer can be accepted in a review. In `--json`, such a finding has `custom`, with the rule's name and reference, and the result lists the rules that were checked as `customRules`.

A mistake in a rules file stops the command with exit code 2 before anything is checked. The message names the file, the rule and what to change.

## What a rule can't do

- A rule can only add a finding. It can't run anything, read a file misconfig doesn't already read, or change or hide what a built-in rule finds.
- Rules are read only from the files you name with `--rules`. Nothing in a checked project is taken as rules.
- In CI, keep the rules where a pull request can't change them, such as another repository checked out at a commit you name. A rules file in the repository being checked can be edited by the pull request it checks.
- A rule holds no regular expression. Its files are paths and its tests compare text, so a rule can't be written, by mistake or on purpose, to stall a check on a file from someone else.
- `--rules` takes up to 200 rules, from files of up to 256 KB each.

The built-in rules written in this form are in [`engine/templates.js`](https://github.com/gkdataio/misconfig/blob/main/engine/templates.js).
