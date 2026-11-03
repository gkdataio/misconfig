// What each file that controls an agent actually tells it to do, in plain
// words. This runs on the user's computer, and what it works out is shown
// only there: in --explain and the page --open saves.

import { describeMasks, maskSecrets } from "./mask.js";
import { findDangerFlag, trimWord, programName } from "./flags.js";
import { parseCodexRules, parseYAML } from "./parse.js";

const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const strs = (x) => (Array.isArray(x) ? x.filter((s) => typeof s === "string" && s.trim()) : []);
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
// Drops invisible tag characters, zero-width and direction marks, and control
// codes, so a summary shows only what can be seen.
const clean = (s) => describeMasks(String(s)).replace(/[\u{E0000}-\u{E007F}\u200b-\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\u0000-\u0008\u000b-\u001f\u007f-\u009f]/gu, "");
// Shortens text at a word boundary, so a summary never ends mid-word.
const clip = (s, n = 90) => {
	const t = clean(s).replace(/\s+/g, " ").trim();
	if (t.length <= n) return t;
	const cut = t.slice(0, n - 1);
	const space = cut.lastIndexOf(" ");
	return `${(space > n * 0.5 ? cut.slice(0, space) : cut).replace(/[\s,;:.(\-]+$/, "")}…`;
};

// Paths as people recognize them: the home folder as ~, forward slashes, and
// long paths shortened in the middle so the folder or file name stays visible.
const HOME_PREFIX = /^(?:[a-z]:\/users\/[^/]+|\/users\/[^/]+|\/home\/[^/]+|\/root)(?=\/|$)/i;
function shortPath(p, n = 60) {
	// Doubled separators, as in a Windows path written C:\\Users\\..., count once.
	const t = clean(p).trim().replace(/\\/g, "/").replace(/(?!^)\/{2,}/g, "/").replace(HOME_PREFIX, "~");
	if (t.length <= n) return t;
	const parts = t.split("/");
	const last = parts.pop();
	const short = `${parts.slice(0, 2).join("/")}/…/${last}`;
	return short.length <= n ? short : `…/${last.length > n - 2 ? `${last.slice(0, n - 3)}…` : last}`;
}
const looksLikePath = (s) => /^(?:[a-z]:[\\/]|\/|~[\\/]|\.{1,2}[\\/])/i.test(String(s));
const commandText = (command, args, n = 80) =>
	clip([command, ...args].filter(Boolean).map((part) => (looksLikePath(part) ? shortPath(part, 50) : part)).join(" "), n);
const period = (s) => (/[.!?…”"]$/.test(s) ? s : `${s}.`);
const list = (items, max = 4) => {
	const shown = items.slice(0, max);
	const rest = items.length - shown.length;
	if (rest > 0) return `${shown.join(", ")} and ${rest} more`;
	return shown.length < 2 ? shown.join("") : `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
};
const sentence = (s) => (s ? s.replace(/^./, (c) => c.toUpperCase()).replace(/([^.!?…”"])$/, "$1.") : s);

// Unicode tag characters, which no font draws, as runs of { index, length,
// decoded }. The flags of England, Scotland and Wales are written with a few
// tag letters after a black flag emoji, so a run like that is a flag, not
// hidden text.
const FLAG_TAGS = /^[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{1,7}\u{E007F}$/u;
export function hiddenTags(text) {
	const out = [];
	for (const m of text.matchAll(/[\u{E0000}-\u{E007F}]+/gu)) {
		if (text.codePointAt(m.index - 2) === 0x1f3f4 && FLAG_TAGS.test(m[0])) continue;
		const chars = [...m[0]];
		const decoded = chars.map((ch) => String.fromCharCode(ch.codePointAt(0) - 0xe0000)).join("").replace(/[^\x20-\x7e]/g, "");
		out.push({ index: m.index, length: chars.length, decoded });
	}
	return out;
}

// Where zero-width characters are in a text, leaving out the ones that are
// part of the writing: a byte order mark at the start of the text or of a
// line, the joiner inside an emoji sequence such as the technologist emoji,
// and the joiners and breaks that scripts such as Persian, Hindi and Thai
// use between letters. Two or more in a row always count, since nothing
// written needs that.
const PICTOGRAPH = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\ufe0f]/u;
const LETTER = /[\p{L}\p{M}]/u;
const LATIN = /[\p{Script=Latin}\p{Script=Common}\p{Script=Inherited}]/u;
const otherScript = (ch) => LETTER.test(ch) && !LATIN.test(ch);
const charBefore = (text, i) => (i > 0 ? String.fromCodePoint(text.codePointAt(i >= 2 && /[\udc00-\udfff]/.test(text[i - 1]) ? i - 2 : i - 1)) : "");
const charAfter = (text, i) => (i < text.length ? String.fromCodePoint(text.codePointAt(i)) : "");
export function hiddenZeroWidth(text) {
	const out = [];
	for (const m of text.matchAll(/[\u0000\u200b-\u200d\u2060\u180e\ufeff]+/g)) {
		let { index } = m;
		let run = m[0];
		if (run[0] === "\ufeff" && (index === 0 || text[index - 1] === "\n")) {
			index++;
			run = run.slice(1);
			if (!run) continue;
		}
		if (run.length === 1) {
			const before = charBefore(text, index);
			const after = charAfter(text, index + 1);
			if (run === "\u200d" && PICTOGRAPH.test(before) && PICTOGRAPH.test(after)) continue;
			if ("\u200b\u200c\u200d\u180e".includes(run) && (otherScript(before) || otherScript(after))) continue;
		}
		for (let i = 0; i < run.length; i++) out.push(index + i);
		if (out.length >= 100_000) break;
	}
	return out;
}

// HTML comments as { index, inner }, found with indexOf: a file full of
// unclosed "<!--" can't slow anything down.
export function htmlComments(text, max = 200) {
	const out = [];
	for (let from = 0; out.length < max; ) {
		const start = text.indexOf("<!--", from);
		if (start < 0) break;
		const end = text.indexOf("-->", start + 4);
		if (end < 0) break;
		out.push({ index: start, inner: text.slice(start + 4, end) });
		from = end + 3;
	}
	return out;
}

// Fenced code blocks as [start, end) offsets. A file of thousands of fences
// is still read in one pass.
export function fencedRanges(text) {
	const ranges = [];
	let open = -1;
	let marker = "";
	for (let start = 0; start < text.length; ) {
		const nl = text.indexOf("\n", start);
		const end = nl < 0 ? text.length : nl;
		const m = /^ {0,3}(`{3,}|~{3,})/.exec(text.slice(start, Math.min(end, start + 16)));
		if (m && open < 0) {
			open = start;
			marker = m[1][0];
		} else if (m && m[1][0] === marker) {
			ranges.push([open, end]);
			open = -1;
		}
		start = end + 1;
	}
	if (open >= 0) ranges.push([open, text.length]);
	return ranges;
}

// A function that finds the code block an offset is in, if any, by binary
// search, so many lookups in a file of many blocks stay fast.
export function fenceAt(text) {
	const fences = fencedRanges(text);
	return (i) => {
		let lo = 0;
		let hi = fences.length - 1;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			if (i < fences[mid][0]) hi = mid - 1;
			else if (i >= fences[mid][1]) lo = mid + 1;
			else return fences[mid];
		}
		return null;
	};
}

// HTML comments that are hidden when the Markdown is displayed. Inside a
// code block or a `code span` a comment shows as written, so it isn't.
export function hiddenComments(text, max = 200) {
	const fence = fenceAt(text);
	const inFence = (i) => fence(i) !== null;
	return htmlComments(text, max * 5).filter((c) => !inFence(c.index) && !inCodeSpan(text, c.index)).slice(0, max);
}

const withoutComments = (line) => {
	let out = "";
	let from = 0;
	for (const c of hiddenComments(line)) {
		out += line.slice(from, c.index);
		from = c.index + c.inner.length + 7;
	}
	return out + line.slice(from);
};

// Where a file's settings apply.
export function scopeOf(file) {
	const p = file.path;
	if (/(^|\/)managed-settings\.json$/i.test(p)) return "admin";
	if (file.loose) return "loose";
	if (/^(~|\/|[A-Za-z]:)/.test(p)) return "computer";
	return "project";
}

export const SCOPES = {
	admin: "Set by an administrator, for everyone on this computer",
	computer: "On this computer, for every project",
	project: "In this project",
	loose: "Loose files where agents have been started",
};

// { scope, summary, details } for one file. `json` is the parsed settings
// file (or null); `servers` are its MCP servers, already normalized.
export function explainFile(file, { json = null, servers = [] } = {}) {
	const scope = scopeOf(file);
	if (file.listed && file.kind === "Plugin code") return { scope, summary: `Code ${file.tools?.[0] ?? "the agent"} loads when it starts. misconfig lists it by name and doesn't open it.`, details: [] };
	if (!file.content) return { scope, summary: file.tooLarge ? "Too large to read." : "Not read.", details: [] };
	const p = file.path;
	let out;
	if (/(^|\/)(\.claude\/settings(\.local)?\.json|managed-settings(\.d\/[^/]+)?\.json)$/i.test(p)) out = claudeSettings(json, scope === "project");
	else if (/(^|\/)\.claude\/plugins\/installed_plugins\.json$/i.test(p)) out = claudePlugins(json);
	else if (/(^|\/)\.claude\/plugins\/known_marketplaces\.json$/i.test(p)) out = claudeMarketplaces(json);
	else if (/(^|\/)\.claude\/plugins\/.+\/hooks\/hooks\.json$/i.test(p)) out = { parts: [], details: claudeHooks(json?.hooks) };
	else if (/(^|\/)\.claude\.json$/i.test(p)) out = claudeUserConfig(json);
	else if (/(^|\/)\.codex\/([^/]+\.)?config\.toml$/i.test(p)) out = codexConfig(json);
	else if (/(^|\/)codex\/requirements\.toml$/i.test(p)) out = codexRequirements(json);
	else if (/(^|\/)(\.gemini|gemini-cli|GeminiCli)\/(system-)?settings\.json$/i.test(p)) out = geminiSettings(json);
	else if (/(^|\/)\.gemini\/trustedFolders\.json$/i.test(p)) out = trustedFolders(geminiTrusted(json));
	else if (/(^|\/)\.copilot\/config\.json$/i.test(p)) out = trustedFolders(strs(json?.trusted_folders ?? json?.trustedFolders));
	else if (/(^|\/)(\.github\/hooks\/[^/]+|\.cursor\/hooks|\.codex\/hooks|\.windsurf\/hooks|\.codeium\/windsurf\/hooks|\.devin\/hooks\.v1|\.grok\/hooks\/[^/]+)\.json$/i.test(p)) out = jsonHooks(json);
	else if (/(^|\/)\.kiro\/hooks\/[^/]+\.(json|kiro\.hook)$/i.test(p)) out = jsonHooks(json);
	else if (/(^|\/)(\.kiro\/agents|\.amazonq\/cli-agents|\.aws\/amazonq\/cli-agents)\/[^/]+\.json$/i.test(p)) out = agentConfig(json);
	else if (/(^|\/)\.cursor\/environment\.json$/i.test(p)) out = cursorEnvironment(json);
	else if (/(^|\/)\.vscode\/tasks\.json$/i.test(p)) out = vsCodeTasks(json);
	else if (/(^|\/)\.gemini\/commands\/.+\.toml$/i.test(p)) out = geminiCommand(p, json);
	else if (/(^|\/)\.codex\/rules\/[^/]+\.rules$/i.test(p)) out = codexRules(file);
	else if (/(^|\/)\.cursor\/(cli-config|cli)\.json$/i.test(p)) out = cursorCli(json);
	else if (/(^|\/)\.cursor\/sandbox\.json$/i.test(p)) out = cursorSandbox(json);
	else if (/(^|\/)(\.vscode|(Code|Code - Insiders|VSCodium|Cursor|Windsurf)\/User)\/settings\.json$/i.test(p)) out = editorSettings(json);
	else if (/(^|\/)opencode\.jsonc?$/i.test(p)) out = openCode(json);
	else if (/(^|\/)(\.zed|zed|Zed)\/settings\.json$/i.test(p)) out = zedSettings(json);
	else if (/(^|\/)\.cline\/data\/globalState\.json$/i.test(p)) out = clineState(json);
	else if (/(^|\/)\.grok\/config\.toml$/i.test(p)) out = grokConfig(json);
	else if (/(^|\/)(\.amp|\.config\/amp)\/settings\.json$/i.test(p)) out = ampSettings(json);
	else if (/(^|\/)goose\/config\.ya?ml$/i.test(p)) out = gooseConfig(file);
	else if (/(^|\/)\.continue\/config\.ya?ml$/i.test(p)) out = continueConfig(file);
	else if (/(^|\/)\.aider\.conf\.ya?ml$/i.test(p)) out = aiderConfig(file);
	else if (file.kind === "Shell profile") out = shellProfile(file);
	else if (file.kind === "Hook script") out = hookScript(file);
	else if (/\.(jsonc?|toml)$/i.test(p)) out = { parts: [], details: [] };
	else out = instructions(file);

	// MCP servers, wherever they're defined.
	if (servers.length) {
		const on = servers.filter((s) => !s.disabled);
		out.parts.push(on.length === servers.length ? `${plural(servers.length, "MCP server")}: ${list(servers.map((s) => s.name), 3)}` : `${plural(on.length, "MCP server")} on, ${servers.length - on.length} off`);
		for (const s of servers) out.details.push(serverText(s));
	}
	const summary = out.summary ?? (out.parts.length ? out.parts.map(sentence).join(" ") : "Nothing that changes how an agent behaves.");
	return { scope, summary, details: out.details };
}

function serverText(s) {
	let what;
	if (s.url) {
		let host = "";
		try {
			host = new URL(s.url).host;
		} catch {
			host = clip(s.url, 40);
		}
		what = `connects to ${host}`;
	} else what = `runs ${commandText(s.command, s.args)}`;
	const auto = s.alwaysAllow === true ? "; its tools run without asking" : strs(s.alwaysAllow).length ? `; runs ${list(strs(s.alwaysAllow), 3)} without asking` : "";
	const keys = Object.keys(s.env ?? {});
	const env = keys.length > 3 ? `; sets ${keys.length} environment variables` : keys.length ? `; sets ${list(keys, 3)}` : "";
	return period(`MCP server “${s.name}”${s.disabled ? " (turned off)" : ""}: ${what}${auto}${env}`);
}

// --- Claude Code -------------------------------------------------------------

const CLAUDE_MODES = {
	default: ["Asks before acting", "Asks the first time each tool is used."],
	manual: ["Asks before acting", "Asks the first time each tool is used."],
	acceptEdits: ["Edits files without asking", "Accepts file edits and common file commands in the project without asking, and asks before other commands."],
	plan: ["Plan mode", "Starts in plan mode: it reads and explores but changes nothing until you approve a plan."],
	auto: ["Auto mode", "Auto mode: runs without routine prompts while a classifier checks that each action matches what you asked for."],
	dontAsk: ["Refuses anything not allowed", "Never prompts: anything that isn't already allowed is refused."],
	bypassPermissions: ["Never asks", "Skips permission prompts for everything except a few protected actions."],
};

// Claude Code hook events, in plain words.
export const HOOK_EVENTS = {
	SessionStart: "When a session starts",
	Setup: "During setup",
	UserPromptSubmit: "When you send a prompt",
	UserPromptExpansion: "When a prompt is expanded",
	PreToolUse: "Before each tool runs",
	PermissionRequest: "When Claude asks for permission",
	PermissionDenied: "When a permission is denied",
	PostToolUse: "After each tool runs",
	PostToolUseFailure: "After a tool fails",
	PostToolBatch: "After a batch of tools runs",
	Notification: "When Claude sends a notification",
	MessageDisplay: "When a message is shown",
	SubagentStart: "When a subagent starts",
	SubagentStop: "When a subagent finishes",
	TaskCreated: "When a task is created",
	TaskCompleted: "When a task is completed",
	Stop: "When Claude finishes a reply",
	StopFailure: "When a reply ends with an error",
	TeammateIdle: "When a teammate goes idle",
	InstructionsLoaded: "When instruction files are loaded",
	ConfigChange: "When settings change",
	CwdChanged: "When the working folder changes",
	DirectoryAdded: "When a folder is added",
	FileChanged: "When a file changes",
	WorktreeCreate: "When a worktree is created",
	WorktreeRemove: "When a worktree is removed",
	PreCompact: "Before the conversation is compacted",
	PostCompact: "After the conversation is compacted",
	PreModelSwitch: "Before the model changes",
	PostModelSwitch: "After the model changes",
	Elicitation: "When an MCP server asks for input",
	ElicitationResult: "When you answer an MCP server",
	SessionEnd: "When a session ends",
};

// Settings that make Claude Code run a command, and what each command is for.
const CLAUDE_COMMANDS = {
	apiKeyHelper: "to get its API key",
	awsAuthRefresh: "to refresh AWS credentials",
	awsCredentialExport: "to get AWS credentials",
	gcpAuthRefresh: "to refresh Google Cloud credentials",
	otelHeadersHelper: "to get telemetry headers",
	statusLine: "to draw the status line",
	subagentStatusLine: "to draw subagent status",
	fileSuggestion: "to suggest files",
	processWrapper: "to start its background processes",
	policyHelper: "to work out managed settings",
	sshHostCommands: "to find SSH hosts",
};

const commandsOf = (value, depth = 0) =>
	typeof value === "string"
		? [value]
		: Array.isArray(value) && depth < 4
			? value.flatMap((v) => commandsOf(v, depth + 1))
			: isObj(value)
				? [value.command, value.path].filter((c) => typeof c === "string")
				: [];

function hookText(event, matcher, h) {
	const when = `${HOOK_EVENTS[event] ?? event}${matcher}`;
	if (typeof h?.command === "string") return `${when}: runs ${clip(h.command, 80)}.`;
	if (h?.type === "http" && typeof h.url === "string") {
		let host = h.url;
		try {
			host = new URL(h.url).host;
		} catch {}
		return `${when}: sends the event to ${clip(host, 50)}.`;
	}
	if (h?.type === "mcp_tool") return `${when}: calls an MCP tool${typeof h.server === "string" ? ` on “${clip(h.server, 30)}”` : ""}.`;
	if (h?.type === "prompt") return `${when}: asks a model to check it.`;
	if (h?.type === "agent") return `${when}: starts a subagent to check it.`;
	return null;
}

// `shared` is a project's own settings file, where Claude Code ignores the
// auto and bypassPermissions modes.
function claudeSettings(json, shared) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details, summary: "Couldn't read the settings in this file." };
	const p = isObj(json.permissions) ? json.permissions : {};
	const mode = CLAUDE_MODES[p.defaultMode];
	if (mode && shared && (p.defaultMode === "auto" || p.defaultMode === "bypassPermissions")) {
		parts.push(`asks for ${p.defaultMode} mode`);
		details.push(`Asks for ${p.defaultMode} mode. Claude Code ignores that in a project's own settings and starts in the default mode, but versions before 2.1.257 honor bypassPermissions.`);
	} else if (mode) {
		parts.push(mode[0]);
		details.push(mode[1]);
	} else if (typeof p.defaultMode === "string") {
		parts.push(`permission mode: ${clip(p.defaultMode, 30)}`);
		details.push(`Permission mode: ${clip(p.defaultMode, 30)}.`);
	}
	const allow = strs(p.allow);
	const ask = strs(p.ask);
	const deny = strs(p.deny);
	if (allow.length) {
		parts.push(`allows ${plural(allow.length, "action")} without asking`);
		details.push(`Allowed without asking: ${list(allow.map((r) => clip(r, 60)), 8)}.`);
	}
	if (ask.length) details.push(`Always asks first: ${list(ask.map((r) => clip(r, 60)), 6)}.`);
	if (deny.length) {
		parts.push(`blocks ${plural(deny.length, "action")}`);
		details.push(`Blocked: ${list(deny.map((r) => clip(r, 60)), 8)}.`);
	}
	const dirs = strs(p.additionalDirectories);
	if (dirs.length) details.push(`Can also work in: ${list(dirs.map((d) => clip(d, 60)), 4)}.`);

	const hooks = claudeHooks(json.hooks);
	if (hooks.length) parts.push(hooks.length === 1 ? "has a hook" : `has ${hooks.length} hooks`);
	details.push(...hooks);
	if (json.disableAllHooks === true) details.push("Turns off all hooks.");
	if (isObj(json.env) && Object.keys(json.env).length) {
		const keys = Object.keys(json.env);
		parts.push(`sets ${plural(keys.length, "environment variable")}`);
		details.push(`Sets ${list(keys, 6)} for the agent.`);
	}
	if (typeof json.model === "string") {
		parts.push(`uses the ${json.model} model`);
		details.push(`Uses the ${json.model} model.`);
	}
	if (json.enableAllProjectMcpServers === true) {
		parts.push("turns on every project MCP server");
		details.push("Turns on every MCP server a project's .mcp.json lists, without asking.");
	}
	const enabled = strs(json.enabledMcpjsonServers);
	if (enabled.length) details.push(`Turns on these project MCP servers: ${list(enabled, 5)}.`);
	for (const [key, purpose] of Object.entries(CLAUDE_COMMANDS)) {
		for (const command of commandsOf(json[key])) details.push(`Runs ${clip(command, 60)} ${purpose}.`);
	}
	if (isObj(json.sandbox) && typeof json.sandbox.enabled === "boolean") details.push(json.sandbox.enabled ? "Runs commands in a sandbox." : "Turns the command sandbox off.");
	const plugins = isObj(json.enabledPlugins) ? Object.keys(json.enabledPlugins).filter((k) => json.enabledPlugins[k]) : [];
	if (plugins.length) {
		parts.push(`turns on ${plural(plugins.length, "plugin")}`);
		details.push(`Turns on ${plural(plugins.length, "plugin")}: ${list(plugins.map((k) => clip(k, 40)), 5)}.`);
	}
	if (isObj(json.extraKnownMarketplaces) && Object.keys(json.extraKnownMarketplaces).length) {
		details.push(`Adds plugin marketplaces: ${list(Object.keys(json.extraKnownMarketplaces).map((k) => clip(k, 40)), 4)}.`);
	}
	if (typeof json.outputStyle === "string") details.push(`Uses the “${json.outputStyle}” output style.`);
	return { parts, details };
}

// One line per hook, in the order they appear.
function claudeHooks(hooks) {
	const out = [];
	if (!isObj(hooks)) return out;
	for (const [event, entries] of Object.entries(hooks)) {
		for (const entry of Array.isArray(entries) ? entries : []) {
			const matcher = typeof entry?.matcher === "string" && entry.matcher && entry.matcher !== "*" ? ` (${clip(entry.matcher, 30)})` : "";
			for (const h of Array.isArray(entry?.hooks) ? entry.hooks : [entry]) {
				const text = hookText(event, matcher, h);
				if (text) out.push(text);
			}
		}
	}
	return out;
}

// ~/.claude.json, already reduced to MCP servers and the folders Claude Code
// has been started in. MCP servers are added by the caller.
function claudeUserConfig(json) {
	const parts = [];
	const details = [];
	if (!isObj(json) || !isObj(json.projects)) return { parts, details };
	const folders = Object.keys(json.projects);
	const risky = folders.filter((d) => /^~$|\/(Downloads|Desktop)$/i.test(d) || /^([A-Za-z]:)?\/?$/.test(d));
	const named = risky.map((d) => (d === "~" ? "your home folder" : /Downloads$/i.test(d) ? "Downloads" : /Desktop$/i.test(d) ? "Desktop" : d));
	parts.push(`started in ${plural(folders.length, "folder")}${named.length ? `, including ${list(named, 3)}` : ""}`);
	const shown = folders.map((d) => (d === "~" ? "~ (your home folder)" : d));
	details.push(`Has been started in ${plural(folders.length, "folder")}: ${list(shown, 6)}.`);
	const approvals = folders.filter((d) => strs(json.projects[d]?.allowedTools).length);
	if (approvals.length) details.push(`Remembers commands you approved in ${plural(approvals.length, "folder")}: ${list(approvals, 4)}.`);
	return { parts, details };
}

// --- Codex -------------------------------------------------------------------

const CODEX_SANDBOX = {
	"read-only": ["Read-only sandbox", "Sandbox: can read files but not change them."],
	"workspace-write": ["Sandboxed to the project", "Sandbox: can change files only in the project folder."],
	"danger-full-access": ["No sandbox", "No sandbox: commands can change any file and use the network."],
};
const CODEX_APPROVAL = {
	untrusted: ["asks before most commands", "Asks before running anything outside a short list of safe commands. Newer versions of Codex don't accept this value."],
	"on-failure": ["asks only when a command fails", "Runs commands in the sandbox and asks only when one fails. Codex has deprecated this value."],
	"on-request": ["asks when it decides to", "Asks only when it decides a command needs your approval."],
	never: ["never asks", "Never asks for approval."],
};

function codexConfig(toml) {
	const parts = [];
	const details = [];
	if (!isObj(toml)) return { parts, details, summary: "Couldn't read the settings in this file." };
	const sandbox = CODEX_SANDBOX[toml.sandbox_mode];
	if (sandbox) {
		parts.push(sandbox[0]);
		details.push(sandbox[1]);
	}
	const approval = CODEX_APPROVAL[toml.approval_policy];
	if (approval) {
		parts.push(approval[0]);
		details.push(approval[1]);
	}
	if (isObj(toml.approval_policy)) {
		parts.push("approvals set per kind of action");
		details.push(`Approvals are set per kind of action: ${list(Object.keys(toml.approval_policy), 5)}.`);
	}
	if (typeof toml.approvals_reviewer === "string") details.push(`Approval requests are reviewed by: ${clip(toml.approvals_reviewer, 30)}.`);
	if (toml.sandbox_workspace_write?.network_access === true) details.push("Lets sandboxed commands use the network.");
	if (typeof toml.model === "string") details.push(`Uses the ${toml.model} model.`);
	if (isObj(toml.projects)) {
		const trusted = Object.entries(toml.projects).filter(([, s]) => s?.trust_level === "trusted").map(([d]) => shortPath(d, 50));
		const risky = (d) => d === "~" || /^~\/(downloads|desktop)$/i.test(d) || /^[a-z]:\/?$/i.test(d) || d === "/";
		const home = trusted.includes("~");
		if (trusted.length) {
			parts.push(`trusts ${plural(trusted.length, "folder")}${home ? ", including your home folder" : ""}`);
			const ordered = [...trusted.filter(risky), ...trusted.filter((d) => !risky(d))].map((d) => (d === "~" ? "~ (your home folder)" : d));
			details.push(`Trusts ${list(ordered, 4)}.`);
		}
	}
	if (isObj(toml.profiles) && Object.keys(toml.profiles).length) details.push(`Has ${plural(Object.keys(toml.profiles).length, "profile")}: ${list(Object.keys(toml.profiles), 4)}.`);
	const notify = strs(toml.notify);
	if (notify.length) details.push(`Runs ${commandText(notify[0], notify.slice(1), 60)} to send notifications.`);
	const hooks = hookLines(toml.hooks);
	parts.push(...hookParts(hooks));
	details.push(...hooks);
	namedFiles(parts, details, toml.project_doc_fallback_filenames);
	let helpers = 0;
	for (const [name, provider] of Object.entries(isObj(toml.model_providers) ? toml.model_providers : {}).slice(0, 10)) {
		if (typeof provider?.auth?.command !== "string") continue;
		helpers++;
		details.push(`Runs ${commandText(provider.auth.command, strs(provider.auth.args), 60)} to get a key for the “${clip(name, 30)}” model provider.`);
	}
	for (const [name, server] of Object.entries(isObj(toml.mcp_servers) ? toml.mcp_servers : {}).slice(0, 20)) {
		const helper = server?.http_headers_helper;
		if (typeof helper !== "string" && !strs(helper).length) continue;
		helpers++;
		details.push(`Runs ${clip(Array.isArray(helper) ? strs(helper).join(" ") : helper, 60)} to make the request headers for MCP server “${clip(name, 30)}”.`);
	}
	if (helpers) parts.push(`runs ${plural(helpers, "command")} for keys or headers`);
	const set = isObj(toml.shell_environment_policy?.set) ? Object.keys(toml.shell_environment_policy.set) : [];
	if (set.length) {
		parts.push(`sets ${plural(set.length, "environment variable")}`);
		details.push(`Sets ${plural(set.length, "environment variable")} for the commands it runs: ${list(set.map((k) => clip(k, 30)), 5)}.`);
	}
	return { parts, details };
}

// --- Gemini, editors, OpenCode, Zed, Aider -----------------------------------

function geminiSettings(json) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details };
	const mode = [json.general?.defaultApprovalMode, json.defaultApprovalMode, json.approvalMode, json.general?.approvalMode, json.tools?.approvalMode].find((v) => typeof v === "string") ?? "";
	// Gemini CLI turns YOLO mode on only from the command line, so a setting
	// that asks for it changes nothing.
	if (json.yolo === true || /^yolo$/i.test(mode)) {
		parts.push("Asks for YOLO mode, which Gemini CLI ignores in settings");
		details.push("Asks for YOLO mode. Current Gemini CLI turns YOLO on only with --yolo or --approval-mode=yolo, so this setting changes nothing.");
	} else if (/^auto_edit$/i.test(mode)) {
		parts.push("Edits files without asking");
		details.push("Approval mode auto_edit: edits files without asking, and asks before other tools.");
	} else if (/^plan$/i.test(mode)) {
		parts.push("Plan mode");
		details.push("Starts in plan mode: it reads and explores but changes nothing.");
	}
	if (json.autoAccept === true || json.tools?.autoAccept === true) {
		parts.push("Accepts some tool calls without asking");
		details.push("Accepts tool calls it considers safe without asking.");
	}
	const sandbox = json.sandbox ?? json.tools?.sandbox;
	if (sandbox !== undefined) details.push(sandbox ? `Runs tools in a sandbox${typeof sandbox === "string" ? ` (${sandbox})` : ""}.` : "Sandbox turned off.");
	const allowed = strs(json.coreTools ?? json.tools?.core ?? json.tools?.allowed);
	if (allowed.length) details.push(`Tools it may use: ${list(allowed, 6)}.`);
	const excluded = strs(json.excludeTools ?? json.tools?.exclude);
	if (excluded.length) details.push(`Tools it may not use: ${list(excluded, 6)}.`);
	namedFiles(parts, details, json.context?.fileName ?? json.contextFileName, ["GEMINI.md"]);
	const discover = [json.tools?.discoveryCommand, json.toolDiscoveryCommand].find((c) => typeof c === "string" && c.trim());
	if (discover) {
		parts.push("runs its own command to find tools");
		details.push(`Runs ${clip(discover, 60)} to find more tools.`);
	}
	const call = [json.tools?.callCommand, json.toolCallCommand].find((c) => typeof c === "string" && c.trim());
	if (call) details.push(`Runs ${clip(call, 60)} to use them.`);
	const hooks = hookLines(json.hooks);
	parts.push(...hookParts(hooks));
	details.push(...hooks);
	return { parts, details };
}

function editorSettings(json) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details };
	if (json["chat.tools.autoApprove"] === true || json["chat.tools.global.autoApprove"] === true || json["chat.permissions.default"] === "autoApprove") {
		parts.push("Runs agent tools without asking");
		details.push("Agent mode runs tools and terminal commands without asking.");
	}
	if (json["github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions"] === true) {
		parts.push("lets the Claude agent skip every permission prompt");
		details.push("The Claude agent in Copilot Chat can skip every permission prompt.");
	}
	if (json["chat.tools.terminal.ignoreDefaultAutoApproveRules"] === true) details.push("Ignores VS Code's built-in rules for terminal commands.");
	const edits = json["chat.tools.edits.autoApprove"];
	if (isObj(edits)) {
		const on = Object.keys(edits).filter((k) => edits[k] === true);
		if (on.length) details.push(`Edits that don't need approval: ${list(on.map((k) => clip(k, 40)), 5)}.`);
	}
	const terminal = json["chat.tools.terminal.autoApprove"] ?? json["github.copilot.chat.agent.terminal.allowList"];
	if (isObj(terminal)) {
		const on = Object.entries(terminal).filter(([, v]) => v === true || (isObj(v) && v.approve === true)).map(([k]) => k);
		const off = Object.entries(terminal).filter(([, v]) => v === false || (isObj(v) && v.approve === false)).map(([k]) => k);
		if (on.length) {
			parts.push(`${plural(on.length, "terminal command")} approved automatically`);
			details.push(`Terminal commands that run without asking: ${list(on.map((k) => clip(k, 40)), 6)}.`);
		}
		if (off.length) details.push(`Terminal commands that always ask: ${list(off.map((k) => clip(k, 40)), 6)}.`);
	}
	const agentKeys = Object.keys(json).filter((k) => /^(chat\.|github\.copilot|cursor\.|windsurf\.|codeium\.)/i.test(k));
	if (agentKeys.length && !parts.length) details.push(`Changes ${plural(agentKeys.length, "agent setting")}: ${list(agentKeys, 5)}.`);
	if (!agentKeys.length && !isObj(json.mcp)) return { parts, details, summary: "No agent settings changed." };
	return { parts, details };
}

function openCode(json) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details };
	const perm = isObj(json.permission) ? json.permission : {};
	for (const tool of ["edit", "bash", "webfetch"]) {
		const v = perm[tool];
		if (typeof v === "string") details.push(`${tool === "webfetch" ? "Web requests" : tool === "bash" ? "Shell commands" : "File edits"}: ${v === "allow" ? "run without asking" : v === "ask" ? "asks first" : v === "deny" ? "blocked" : v}.`);
	}
	if (perm.bash === "allow" || (isObj(perm.bash) && perm.bash["*"] === "allow")) parts.push("Runs shell commands without asking");
	if (json.share === "auto") {
		parts.push("shares every session automatically");
		details.push("Shares every session to a public link automatically.");
	} else if (typeof json.share === "string") details.push(`Session sharing: ${json.share}.`);
	if (typeof json.model === "string") details.push(`Uses the ${json.model} model.`);
	if (isObj(json.agent) && Object.keys(json.agent).length) details.push(`Defines ${plural(Object.keys(json.agent).length, "agent")}: ${list(Object.keys(json.agent), 4)}.`);
	namedFiles(parts, details, json.instructions);
	return { parts, details };
}

function zedSettings(json) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details };
	if (json.agent?.always_allow_tool_actions === true || json.assistant?.always_allow_tool_actions === true || json.agent?.tool_permissions?.default === "allow") {
		parts.push("Runs agent tools without asking");
		details.push("The agent runs tool actions without asking.");
	} else if (typeof json.agent?.tool_permissions?.default === "string") {
		details.push(`Tool permissions default to “${clip(json.agent.tool_permissions.default, 20)}”.`);
	}
	if (json.session?.trust_all_worktrees === true) {
		parts.push("trusts every project");
		details.push("Trusts every project you open, so each one's own settings apply.");
	}
	const model = json.agent?.default_model?.model ?? json.assistant?.default_model?.model;
	if (typeof model === "string") details.push(`Uses the ${model} model.`);
	if (!parts.length && !details.length && !isObj(json.context_servers)) return { parts, details, summary: "No agent settings changed." };
	return { parts, details };
}

function aiderConfig(file) {
	const parts = [];
	const details = [];
	for (const line of file.lines ?? []) {
		const colon = line.indexOf(":");
		if (colon < 0) continue;
		const key = line.slice(0, colon).trim();
		const value = line.slice(colon + 1).trim();
		if (!/^[a-z0-9-]+$/i.test(key) || !value) continue;
		if (key === "yes-always" && /^true$/i.test(value)) {
			parts.push("Confirms everything without asking");
			details.push("Answers yes to every confirmation, including running commands.");
		} else if (key === "model") details.push(`Uses the ${clip(value, 40)} model.`);
		else if (key === "auto-commits") details.push(`Commits changes automatically: ${value}.`);
	}
	// The read list, as one value, a [list] or items under the key.
	const read = [];
	let inRead = false;
	for (const line of file.lines ?? []) {
		const top = /^([A-Za-z][\w-]*)\s*:\s*(.*)$/.exec(line);
		if (top) {
			inRead = top[1] === "read";
			if (inRead && top[2].trim()) read.push(...top[2].replace(/^\[|\]$/g, "").split(",").map((x) => x.trim().replace(/^["']|["']$/g, "")));
			continue;
		}
		const item = inRead && /^\s+-\s+(.+)$/.exec(line);
		if (item) read.push(item[1].trim().replace(/^["']|["']$/g, ""));
	}
	namedFiles(parts, details, read.filter(Boolean));
	return { parts, details };
}

// --- Trusted folders, hooks and other agents' settings -----------------------

const RISKY_FOLDER = /^(~|\/|[a-z]:[\\/]?|(~|\/users\/[^/]+|\/home\/[^/]+|[a-z]:\/users\/[^/]+)(\/(downloads|desktop))?)$/i;

function trustedFolders(folders) {
	const parts = [];
	const details = [];
	const shown = folders.map((d) => shortPath(d, 50));
	if (!shown.length) return { parts, details, summary: "Trusts no folders." };
	const risky = (d) => RISKY_FOLDER.test(d);
	const home = shown.some((d) => d === "~");
	parts.push(`trusts ${plural(shown.length, "folder")}${home ? ", including your home folder" : ""}`);
	const ordered = [...shown.filter(risky), ...shown.filter((d) => !risky(d))].map((d) => (d === "~" ? "~ (your home folder)" : d));
	details.push(`Trusts ${list(ordered, 5)}.`);
	return { parts, details };
}

// Gemini CLI trusts a folder itself (TRUST_FOLDER) or the folder it's in (TRUST_PARENT).
function geminiTrusted(json) {
	if (!isObj(json)) return [];
	const parent = (d) => trimWord(d, "", "/\\").replace(/[\\/][^\\/]*$/, "") || "/";
	return Object.entries(json).flatMap(([d, v]) => (v === "TRUST_FOLDER" ? [d] : v === "TRUST_PARENT" ? [parent(d)] : []));
}

// Every hook in a hooks setting, in any agent's format: event names mapped
// to lists of hooks, groups of hooks under a matcher, or a list of hooks
// that each name what sets them off. One line per hook, such as
// "PreToolUse: runs ./check.sh."
function hookLines(value, event = "", depth = 0, out = []) {
	if (depth > 6 || out.length >= 50) return out;
	if (Array.isArray(value)) {
		for (const v of value.slice(0, 50)) hookLines(v, event, depth + 1, out);
		return out;
	}
	if (!isObj(value)) return out;
	const on = event || [value.trigger, value.when?.type, value.event].find((v) => typeof v === "string" && v.trim()) || "";
	const command = [value.command, value.bash, value.powershell, value.action?.command, value.then?.command].find((c) => (typeof c === "string" && c.trim()) || strs(c).length);
	const prompt = [value.prompt, value.action?.prompt, value.then?.prompt].find((c) => typeof c === "string" && c.trim());
	const what = command !== undefined ? `runs ${clip(Array.isArray(command) ? strs(command).join(" ") : command, 80)}` : prompt ? `asks the agent “${clip(prompt, 80)}”` : null;
	if (what) {
		out.push(on ? `${clip(on, 40)}: ${what}.` : sentence(what));
		return out;
	}
	for (const [k, v] of Object.entries(value)) if (k !== "matcher" && k !== "when") hookLines(v, depth === 0 && !event ? k : on, depth + 1, out);
	return out;
}
const hookParts = (lines) => (lines.length ? [lines.length === 1 ? "has a hook" : `has ${lines.length} hooks`] : []);

function jsonHooks(json) {
	const details = hookLines(isObj(json) && json.hooks !== undefined ? json.hooks : json);
	return { parts: hookParts(details), details };
}

// Kiro and Amazon Q agent files: hooks, and tools the agent uses without
// asking. Their MCP servers are listed with the others.
function agentConfig(json) {
	if (!isObj(json)) return { parts: [], details: [], summary: "Couldn't read the settings in this file." };
	const details = hookLines(json.hooks);
	const parts = hookParts(details);
	const allowed = strs(json.allowedTools);
	if (allowed.length) {
		parts.push(`uses ${plural(allowed.length, "tool")} without asking`);
		details.push(`Tools it uses without asking: ${list(allowed.map((t) => clip(t, 40)), 6)}.`);
	}
	if (typeof json.name === "string" && json.name.trim()) details.unshift(`Agent “${clip(json.name, 40)}”.`);
	return { parts, details };
}

// What a Cursor background agent runs on the machine it works on.
function cursorEnvironment(json) {
	if (!isObj(json)) return { parts: [], details: [], summary: "Couldn't read the settings in this file." };
	const details = [];
	if (typeof json.install === "string" && json.install.trim()) details.push(`Runs ${clip(json.install, 80)} to set up the machine.`);
	if (typeof json.start === "string" && json.start.trim()) details.push(`Runs ${clip(json.start, 80)} each time an agent starts.`);
	for (const t of (Array.isArray(json.terminals) ? json.terminals : []).filter((t) => isObj(t) && typeof t.command === "string").slice(0, 5)) {
		details.push(`Opens a terminal${typeof t.name === "string" && t.name.trim() ? ` named “${clip(t.name, 30)}”` : ""} that runs ${clip(t.command, 60)}.`);
	}
	return { parts: details.length ? [`runs ${plural(details.length, "command")} for background agents`] : [], details };
}

// A Gemini CLI custom command: its name, what it asks the agent, and the
// shell commands it runs with !{...} before the prompt is sent.
function geminiCommand(path, toml) {
	if (!isObj(toml)) return { parts: [], details: [], summary: "Couldn't read the settings in this file." };
	const name = `/${path.replace(/^.*?\.gemini\/commands\//i, "").replace(/\.toml$/i, "").split("/").join(":")}`;
	const prompt = typeof toml.prompt === "string" ? toml.prompt : "";
	const shell = [...prompt.matchAll(/!\{([^}]{1,200})\}/g)].map((m) => m[1].trim());
	const parts = [`command ${clip(name, 40)}`];
	if (shell.length) parts.push(`runs ${plural(shell.length, "shell command")} when used`);
	const details = [];
	if (typeof toml.description === "string" && toml.description.trim()) details.push(`Described as: “${clip(toml.description, 80)}”`);
	if (prompt.trim()) details.push(`Says: “${clip(prompt.trim().split("\n")[0], 80)}”`);
	for (const c of shell.slice(0, 5)) details.push(`Runs ${clip(c, 60)} first.`);
	return { parts, details };
}

// Files a setting names as instructions, beyond the agent's usual ones.
function namedFiles(parts, details, names, usual = []) {
	const given = (typeof names === "string" ? [names] : Array.isArray(names) ? names : []).filter((n) => typeof n === "string" && n.trim()).map((n) => clip(n.trim(), 60));
	if (!given.some((n) => !usual.includes(n))) return;
	parts.push(`reads instructions from ${list(given.filter((n) => !usual.includes(n)), 3)}`);
	details.push(`Reads its instructions from ${list(given, 6)}.`);
}

// VS Code tasks: what each runs, and which run as soon as the folder opens.
function vsCodeTasks(json) {
	const tasks = (Array.isArray(json?.tasks) ? json.tasks : []).filter(isObj);
	if (!tasks.length) return { parts: [], details: [] };
	const text = (t) => clip([t.command, ...strs(t.args)].filter((w) => typeof w === "string").join(" ").trim(), 70);
	const onOpen = tasks.filter((t) => t.runOptions?.runOn === "folderOpen");
	const parts = [plural(tasks.length, "task")];
	if (onOpen.length) parts.push(`${onOpen.length === 1 ? "1 runs" : `${onOpen.length} run`} when the folder opens`);
	const details = tasks.slice(0, 20).map((t) => {
		const name = typeof t.label === "string" && t.label.trim() ? `Task “${clip(t.label, 40)}”` : "A task";
		const command = text(t);
		return `${name}${command ? ` runs ${command}` : ""}${t.runOptions?.runOn === "folderOpen" ? ", as soon as the folder opens" : ""}.`;
	});
	return { parts, details };
}

// Codex command rules: which commands run without asking, which ask first
// and which are blocked.
const DECISIONS = { allow: (w) => `Lets ${w} run without asking`, prompt: (w) => `Asks before ${w}`, forbidden: (w) => `Blocks ${w}` };
function codexRules(file) {
	const rules = parseCodexRules(file.content).filter((r) => r.pattern?.length && DECISIONS[r.decision]);
	if (!rules.length) return { parts: [], details: [], summary: "No command rules this check can read." };
	// Programs by name, so C:\Windows\...\powershell.exe -Command reads as
	// powershell -Command.
	const word = (w, i) => (i === 0 ? programName(w) : w);
	const words = (r) => clip(r.pattern.slice(0, 5).map((w, i) => (Array.isArray(w) ? w.map((x) => word(x, i)).join(" or ") : w == null ? "…" : word(w, i))).join(" "), 60);
	// The summary names each pattern by its program and first word.
	const start = (r) => clip(r.pattern.slice(0, 2).map((w, i) => (Array.isArray(w) ? w.map((x) => word(x, i)).join(" or ") : w == null ? "…" : word(w, i))).join(" "), 40);
	const parts = [];
	for (const [decision, verb] of [["allow", "lets"], ["prompt", "asks before"], ["forbidden", "blocks"]]) {
		const matching = rules.filter((r) => r.decision === decision);
		if (!matching.length) continue;
		const starts = [...new Set(matching.map(start))];
		const what = matching.length === 1 ? starts[0] : `${plural(matching.length, "command")} starting with ${list(starts, 3)}`;
		parts.push(decision === "allow" ? `${verb} ${what} run without asking` : `${verb} ${what}`);
	}
	const details = rules.slice(0, 30).map((r) => `${DECISIONS[r.decision](words(r))}${r.justification.trim() ? `: “${clip(r.justification, 60)}”` : ""}.`);
	return { parts, details };
}

function cursorCli(json) {
	const parts = [];
	const details = [];
	const allow = strs(json?.permissions?.allow);
	const deny = strs(json?.permissions?.deny);
	if (allow.length) {
		parts.push(`allows ${plural(allow.length, "action")} without asking`);
		details.push(`Allowed without asking: ${list(allow.map((r) => clip(r, 60)), 8)}.`);
	}
	if (deny.length) {
		parts.push(`blocks ${plural(deny.length, "action")}`);
		details.push(`Blocked: ${list(deny.map((r) => clip(r, 60)), 8)}.`);
	}
	return { parts, details };
}

function cursorSandbox(json) {
	if (json?.type === "insecure_none") return { parts: ["No sandbox"], details: ["No sandbox: agent commands can change any file and use the network."] };
	const details = [];
	if (typeof json?.type === "string") details.push(`Sandbox type: ${clip(json.type, 30)}.`);
	if (typeof json?.networkPolicy?.default === "string") details.push(`Network access by default: ${clip(json.networkPolicy.default, 20)}.`);
	return { parts: [], details };
}

function claudePlugins(json) {
	const names = isObj(json?.plugins) ? Object.keys(json.plugins) : [];
	if (!names.length) return { parts: [], details: [], summary: "No plugins installed." };
	return { parts: [`${plural(names.length, "plugin")} installed`], details: [`Installed plugins: ${list(names.map((n) => clip(n, 50)), 8)}.`] };
}

// Where a plugin marketplace's plugins come from, by its source type: a
// GitHub repository, a git or web address, or a folder.
function marketplaceKind(m) {
	const src = isObj(m?.source) ? m.source : {};
	const repo = typeof src.repo === "string" ? src.repo : "";
	const url = typeof src.url === "string" ? src.url : "";
	const kind = typeof src.source === "string" ? src.source : repo && !url ? "github" : url && !repo ? "git" : "";
	return { kind, repo, url, path: typeof src.path === "string" ? src.path : "" };
}
export function marketplaceSource(m) {
	const { kind, repo, url, path } = marketplaceKind(m);
	return kind === "github" ? repo : kind === "git" || kind === "url" ? url : path || repo || url;
}
// True for a marketplace in Anthropic's own GitHub organization, named
// exactly: the address its source type uses, with no more path after the
// repository.
const ANTHROPIC_REPO = /^anthropics\/(?!\.\.?$)[A-Za-z0-9._-]{1,100}$/i;
const ANTHROPIC_URL = /^(?:https:\/\/github\.com\/|git@github\.com:)anthropics\/(?!\.\.?(?:\.git)?\/?$)[A-Za-z0-9._-]{1,100}\/?$/i;
export function anthropicMarketplace(m) {
	const { kind, repo, url } = marketplaceKind(m);
	if (kind === "github") return ANTHROPIC_REPO.test(repo);
	if (kind === "git" || kind === "url") return ANTHROPIC_URL.test(url);
	return false;
}

// Where Claude Code can install plugins from, and who runs each place.
function claudeMarketplaces(json) {
	const entries = isObj(json) ? Object.entries(json).filter(([, m]) => isObj(m)) : [];
	if (!entries.length) return { parts: [], details: [], summary: "No plugin marketplaces added." };
	const others = entries.filter(([, m]) => !anthropicMarketplace(m)).length;
	const who = !others ? "all run by Anthropic" : others < entries.length ? `${others} not run by Anthropic` : entries.length === 1 ? "not run by Anthropic" : "none run by Anthropic";
	return {
		parts: [`${plural(entries.length, "plugin marketplace")}, ${who}`],
		details: entries.slice(0, 50).map(([name, m]) => `Marketplace ${clip(name, 50)}: ${clip(marketplaceSource(m), 100) || "no source given"}${anthropicMarketplace(m) ? ", run by Anthropic" : ""}.`),
	};
}

function codexRequirements(toml) {
	const details = [];
	if (!isObj(toml)) return { parts: [], details };
	for (const [key, value] of Object.entries(toml)) {
		const text = (v) => (typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? String(v) : "");
		if (Array.isArray(value)) details.push(`${key}: ${list(value.map(text).filter(Boolean).map((v) => clip(v, 30)), 6)}.`);
		else if (text(value)) details.push(`${key}: ${clip(text(value), 40)}.`);
	}
	return { parts: details.length ? ["Limits what Codex settings may allow"] : [], details };
}

function clineState(json) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details };
	if (json.yoloModeToggled === true) {
		parts.push("YOLO mode: approves everything");
		details.push("YOLO mode is on: every action runs without asking.");
	}
	const auto = json.autoApprovalSettings;
	if (isObj(auto) && auto.enabled !== false && isObj(auto.actions)) {
		const on = Object.keys(auto.actions).filter((k) => auto.actions[k] === true);
		if (on.length) {
			if (!parts.length) parts.push(`auto-approves ${plural(on.length, "kind")} of action`);
			details.push(`Approved without asking: ${list(on, 6)}.`);
		}
	}
	return { parts, details };
}

function grokConfig(toml) {
	const parts = [];
	const details = [];
	if (!isObj(toml)) return { parts, details, summary: "Couldn't read the settings in this file." };
	const mode = toml.ui?.permission_mode ?? toml.permission_mode;
	if (mode === "always-approve" || mode === "yolo") {
		parts.push("Never asks");
		details.push(`Permission mode “${mode}”: runs commands and edits without asking.`);
	} else if (typeof mode === "string") details.push(`Permission mode: ${clip(mode, 30)}.`);
	if (isObj(toml.sandbox)) details.push(`Sandbox settings: ${list(Object.keys(toml.sandbox), 5)}.`);
	const status = toml.ui?.status_line?.command;
	if (typeof status === "string" && status.trim()) {
		parts.push("runs a command for its status line");
		details.push(`Runs ${clip(status, 60)} to draw the status line.`);
	}
	return { parts, details };
}

function ampSettings(json) {
	const parts = [];
	const details = [];
	if (!isObj(json)) return { parts, details };
	if (json["amp.dangerouslyAllowAll"] === true) {
		parts.push("Runs every tool without asking");
		details.push("Runs every tool, including commands, without asking.");
	}
	const keys = Object.keys(json).filter((k) => k.startsWith("amp.") && k !== "amp.mcpServers" && k !== "amp.dangerouslyAllowAll");
	if (keys.length) details.push(`Changes ${plural(keys.length, "setting")}: ${list(keys, 5)}.`);
	return { parts, details };
}

// YAML, read line by line for the few keys that matter.
function gooseConfig(file) {
	const parts = [];
	const details = [];
	const lines = file.lines ?? [];
	const mode = lines.map((l) => l.match(/^GOOSE_MODE\s*:\s*["']?([\w-]+)/)?.[1]).find(Boolean);
	if (mode === "auto") {
		parts.push("Runs tools without asking");
		details.push("Mode auto: runs tools and commands without asking.");
	} else if (mode) details.push(`Mode: ${mode}.`);
	const start = lines.findIndex((l) => /^extensions\s*:/.test(l));
	if (start >= 0) {
		const names = [];
		for (const l of lines.slice(start + 1)) {
			if (/^\S/.test(l)) break;
			const m = l.match(/^ {2}([\w.-]+)\s*:\s*$/);
			if (m) names.push(m[1]);
		}
		if (names.length) {
			parts.push(`${plural(names.length, "extension")}: ${list(names, 3)}`);
			details.push(`Extensions: ${list(names, 8)}.`);
		}
	}
	return { parts, details };
}

function continueConfig(file) {
	const parts = [];
	const details = [];
	for (const line of file.lines ?? []) {
		const m = line.match(/^\s*(?:-\s*)?destination\s*:\s*["']?([^\s"'#]+)/i);
		if (!m) continue;
		let where = m[1];
		try {
			where = /^https?:/i.test(m[1]) ? new URL(m[1]).host : shortPath(m[1].replace(/^file:\/\//i, ""), 50);
		} catch {}
		details.push(`Sends session data to ${clip(where, 50)}.`);
	}
	if (details.length) parts.push(`sends session data to ${plural(details.length, "place")}`);
	return { parts, details };
}

// --- Shell profiles and hook scripts -----------------------------------------

const AGENT_COMMANDS = /\b(claude|codex|gemini|qwen|opencode|cursor-agent|aider|amp|copilot|grok|kiro|q chat)\b/i;
const AGENT_ENV = /\b(ANTHROPIC|CLAUDE|OPENAI|CODEX|GEMINI|GOOGLE_GENAI|XAI|GROK|OPENROUTER|MISTRAL|DEEPSEEK)_[A-Z0-9_]+/;

// Lines in a shell profile that change how an agent starts or runs.
export function agentLines(file) {
	const out = [];
	for (const [i, line] of (file.lines ?? []).entries()) {
		if (/^\s*#/.test(line) || !line.trim()) continue;
		if (AGENT_COMMANDS.test(line) || AGENT_ENV.test(line)) out.push({ line: i + 1, text: line });
	}
	return out;
}

function shellProfile(file) {
	const parts = [];
	const details = [];
	const lines = agentLines(file);
	for (const { line, text } of lines) {
		const flag = findDangerFlag(text);
		const agent = text.match(AGENT_COMMANDS)?.[1];
		const env = text.match(AGENT_ENV)?.[0];
		if (flag && agent) {
			parts.push(`starts ${agent} with ${flag.flag}`);
			details.push(`Line ${line}: every time you run ${agent}, it adds ${flag.flag}.`);
		} else if (env) details.push(`Line ${line}: sets ${env} for every program you run.`);
		else details.push(`Line ${line}: ${clip(text, 80)}`);
	}
	if (!lines.length) return { parts, details, summary: "Nothing agent-related." };
	if (!parts.length) parts.push(`${plural(lines.length, "line")} about agents`);
	return { parts, details };
}

function hookScript(file) {
	const commands = (file.lines ?? []).filter((l) => l.trim() && !/^\s*(#|\/\/|rem\b)/i.test(l));
	return {
		parts: [`hook script, ${plural(commands.length, "command line")}`],
		details: commands.slice(0, 6).map((l) => `Runs: ${clip(l, 80)}`),
	};
}

// --- Instruction files -------------------------------------------------------

// Files where "@path" pulls another file in: Claude Code's CLAUDE.md files
// and rules, and Gemini CLI's GEMINI.md. Elsewhere an @ is only text, such as
// a package or model name.
export const CAN_IMPORT = /(?:^|\/)(?:claude(?:\.local)?|gemini)\.md$|(?:^|\/)\.claude\/rules\//i;
const RX_IMPORT = /(?:^|\s)@([~.\w/-][^\s]*\.[A-Za-z][\w-]{0,9})(?=$|[\s),;:.!?])/g;

// Whether an offset sits inside a `code span` on its line.
export function inCodeSpan(text, index) {
	let ticks = 0;
	for (let j = text.lastIndexOf("\n", index - 1) + 1; j < index; j++) if (text.charCodeAt(j) === 96) ticks++;
	return ticks % 2 === 1;
}

const DIRECTIVE =
	/^(?:always|never|don['’]?t|do not|must|should|use|run|prefer|avoid|make sure|ensure|keep|write|follow|add|remove|only|ignore|install|call|send|read|check|before|after|when|if|you|please|import|create|update|delete|commit|push|test|format|name|put|store|respond|reply|answer|ask|tell|do)\b/i;

// The front matter of a skill, agent or rule file, read as YAML so that
// quoted, folded and multi-line values come out the way they were written.
// Values are kept as one line of text; a block YAML can't read falls back to
// plain key: value lines.
function frontmatter(text) {
	const m = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
	if (!m) return {};
	const block = m[1].slice(0, 20_000);
	const out = {};
	let yaml = null;
	try {
		yaml = parseYAML(block);
	} catch {
		yaml = null;
	}
	if (isObj(yaml)) {
		for (const [key, value] of Object.entries(yaml)) {
			if (!/^[A-Za-z][\w-]*$/.test(key)) continue;
			const text = ["string", "number", "boolean"].includes(typeof value) ? String(value) : Array.isArray(value) ? value.filter((v) => typeof v === "string").join(", ") : null;
			if (text !== null) out[key.toLowerCase()] = text.replace(/\s+/g, " ").trim();
		}
		return out;
	}
	for (const line of block.split(/\r?\n/)) {
		const kv = line.match(/^([A-Za-z][\w-]*)\s*:\s*(.*)$/);
		if (kv) out[kv[1].toLowerCase()] = kv[2].trim().replace(/^["']|["']$/g, "");
	}
	return out;
}

function instructions(file) {
	const text = file.content.slice(0, 200_000);
	const fm = frontmatter(text);
	const body = text.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, "");
	const lines = body.split(/\r?\n/);
	const nonEmpty = lines.filter((l) => l.trim()).length;
	// Headings and imports outside code blocks: a "# comment" in a shell
	// example isn't a section, and an @ in code imports nothing.
	const headings = [];
	const imports = [];
	let code = false;
	for (const line of lines) {
		if (/^\s*(```|~~~)/.test(line)) code = !code;
		else if (code) continue;
		else if (/^#{1,3}\s+\S/.test(line)) headings.push(clip(line.replace(/^#+\s*/, ""), 40));
		else if (CAN_IMPORT.test(file.path)) {
			const visible = line.slice(0, 2000).replace(/`[^`]*`/g, " ");
			for (const m of visible.matchAll(RX_IMPORT)) imports.push(`@${m[1]}`);
		}
	}
	// What it says, in the order it says it.
	const said = [];
	let fence = false;
	for (const raw of lines) {
		if (/^\s*(```|~~~)/.test(raw)) fence = !fence;
		// Code, headings and table rows aren't sentences the file says.
		if (fence || /^\s*(?:#|```|~~~|<!--|-->|-{3,}|\|)/.test(raw)) continue;
		// Lines are cut before links are tidied, so a line of thousands of
		// brackets can't slow it down. Only the start of a line is ever shown.
		const l = withoutComments(clean(raw.slice(0, 1000)))
			.replace(/^\s*(?:[-*+]|\d+[.)])\s+/, "")
			.replace(/\*\*/g, "")
			.replace(/!?\[([^\]\n]{1,200})\]\([^)\s]{0,300}\)/g, "$1")
			.trim();
		if (l.length >= 4 && !/^@\S+$/.test(l)) said.push(l);
		if (said.length >= 40) break;
	}
	const directives = said.filter((l) => DIRECTIVE.test(l));
	const example = directives[0] ?? said[0];

	// What it says that people can't see: invisible characters and comments.
	const hidden = [];
	for (const run of hiddenTags(text)) {
		const decoded = run.decoded.trim();
		if (decoded) hidden.push(`Hidden text you can't see when it's displayed: “${clip(maskSecrets(decoded).text, 100)}”`);
		if (hidden.length >= 4) break;
	}
	for (const c of hiddenComments(text)) {
		const inner = c.inner.trim();
		if (inner.length >= 8 && !/^(prettier-|eslint-|markdownlint|toc|end|start|region|endregion)/i.test(inner)) hidden.push(`Hidden in a comment: “${clip(inner, 100)}”`);
		if (hidden.length >= 4) break;
	}

	const p = file.path;
	const name = fm.name ?? p.split("/").slice(-2, -1)[0];
	const parts = [];
	const details = [];
	const skill = /(^|\/)skills\/(?:[^/]+\/)+SKILL\.md$/i.test(p);
	if (skill || /(^|\/)\.claude\/(?:.+\/)?(agents|commands)\/[^/]+\.md$/i.test(p)) {
		const kind = skill ? "Skill" : /\/agents\/[^/]+$/i.test(p) ? "Subagent" : "Command";
		const label = kind === "Command" ? `/${p.split("/").pop().replace(/\.md$/i, "")}` : `“${name}”`;
		parts.push(`${kind} ${label}${fm.description ? `: ${clip(fm.description, 70)}` : ""}`);
		const tools = fm["allowed-tools"] ?? fm.tools;
		if (tools) details.push(`Can use: ${clip(tools, 80)}.`);
		if (fm.model) details.push(`Uses the ${fm.model} model.`);
	} else {
		const what = file.kind === "Memory" ? "saved memory" : "instructions";
		parts.push(`${plural(nonEmpty, "line")} of ${what}${example ? `, such as “${clip(example, 60)}”` : ""}`);
	}
	if (hidden.length) parts.push("also contains text that's hidden when you read it");
	if (fm.alwaysapply === "true") details.push("Applies to every request.");
	else if (fm.globs || fm.applyto) details.push(`Applies to files matching ${clip(fm.globs || fm.applyto, 60)}.`);
	else if (fm.description && !/skills|agents|commands/i.test(p)) details.push(`Applies when relevant to: ${clip(fm.description, 70)}.`);
	if (headings.length) details.push(period(`Sections: ${list(headings, 6)}`));
	if (imports.length) details.push(`Pulls in ${list([...new Set(imports)].map((i) => clip(i, 50)), 4)}.`);
	details.push(...hidden);
	for (const d of said.slice(0, 8)) details.push(`Says: “${clip(d, 90)}”`);
	// Only the first 40 lines are collected, so past that the count is a floor.
	if (said.length > 8) details.push(`And ${said.length >= 40 ? "at least " : ""}${plural(said.length - 8, "more line")}.`);
	return { parts, details };
}
