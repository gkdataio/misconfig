// The misconfig rule engine. It runs in the command, on the user's computer.
// The Worker uses its rules version, scoring text and catalog for the rules
// page, and the site publishes it so anyone can read it.

import { maskSecrets, looksLikeSecret, looksLikeToken, isMasked, isPathLike, describeMasks } from "./mask.js";
import { parseJSONC, parseTOML, parseYAML, parseCodexRules } from "./parse.js";
import { namedInstructions, NAMING_SETTINGS } from "./named.js";
import { RULES, CATEGORIES } from "./catalog.js";
import { explainFile, agentLines, hiddenComments, hiddenTags, hiddenZeroWidth, fenceAt, inCodeSpan, CAN_IMPORT, scopeOf, HOOK_EVENTS, anthropicMarketplace, marketplaceSource } from "./explain.js";
import { ignoreRules, isIgnored, globMatch } from "./glob.js";
import { HOME_MARKERS, DOWNLOADS_LIKE, TOOL_ROOT, visibleName } from "./paths.js";
import { findDangerFlag, trimWord, programName, COMMAND_BREAK } from "./flags.js";
import {
	KNOWN_PACKAGES,
	AGENT_EXTENSIONS,
	AGENT_PACKAGES,
	AGENT_ADVISORIES,
	TRACES,
	SHELL_TRACES,
	WORKFLOW_TRACES,
	KNOWN_BAD_HOSTS,
	OFFICIAL_MCP_PACKAGES,
	OFFICIAL_PYPI_MCP,
	OPEN_VSX_EDITORS,
	addKnownMalware,
	extensionListing,
	compareVersions,
	VERSION_RE,
} from "./known.js";

export { findDangerFlag };

export const RULESET_VERSION = "2026.11.7";

const WEIGHT = { critical: 30, high: 15, medium: 6, low: 2, info: 0 };
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
// The lowest score for each grade. Below the last one is F.
const GRADES = [
	["A", 90],
	["B", 80],
	["C", 65],
	["D", 50],
];

// How the score works, in the words reports and the rules page use.
export const SCORING = [
	`The score starts at 100. The first finding from a rule takes off ${WEIGHT.critical} points if it's critical, ${WEIGHT.high} if it's high, ${WEIGHT.medium} if it's medium and ${WEIGHT.low} if it's low.`,
	"Each repeat takes off a quarter of that again, up to twice that for one rule, so one noisy rule can't empty the score. Info findings take off nothing.",
	`Grades: ${GRADES.map(([g, min]) => `${g} for ${min} or more`).join(", ")} and F below ${GRADES.at(-1)[1]}. Any critical finding caps the grade at D.`,
].join(" ");
const MAX_FILE_CHARS = 450_000;

// Which agents read which files, and what each file controls. Used for the
// control map and attribution. The first match wins, so specific paths come
// before general ones.
const CONTROL = [
	// Claude Code
	[/(^|\/)claude(\.local)?\.md$/i, ["Claude Code"], "Instructions"],
	[/(^|\/)\.claude\/settings(\.local)?\.json$/i, ["Claude Code"], "Permissions & hooks"],
	[/(^|\/)managed-settings(\.d\/[^/]+)?\.json$/i, ["Claude Code"], "Admin policy"],
	[/(^|\/)managed-mcp\.json$/i, ["Claude Code"], "Admin MCP servers"],
	[/(^|\/)\.claude\/hooks\//i, ["Claude Code"], "Hook script"],
	[/(^|\/)\.claude\/(commands|agents|skills|output-styles)\//i, ["Claude Code"], "Commands & agents"],
	[/(^|\/)\.claude\/rules\//i, ["Claude Code"], "Rules"],
	[/(^|\/)\.claude\/projects\/[^/]+\/memory\//i, ["Claude Code"], "Memory"],
	[/(^|\/)\.claude\/plugins\/installed_plugins\.json$/i, ["Claude Code"], "Plugins"],
	[/(^|\/)\.claude\/plugins\/known_marketplaces\.json$/i, ["Claude Code"], "Plugin marketplaces"],
	[/(^|\/)\.claude\/plugins\/.+\/hooks\/hooks\.json$/i, ["Claude Code"], "Plugin hooks"],
	[/(^|\/)\.claude\/plugins\/.+\/\.mcp\.json$/i, ["Claude Code"], "Plugin MCP servers"],
	[/(^|\/)\.claude\/plugins\/.+\/(commands|agents|skills)\/.+\.md$/i, ["Claude Code"], "Plugin commands & agents"],
	[/(^|\/)\.claude-plugin\/plugin\.json$/i, ["Claude Code"], "Plugin manifest"],
	[/(^|\/)\.claude\.json$/i, ["Claude Code"], "User config"],
	[/(^|\/)\.mcp\.json$/i, ["Claude Code", "GitHub Copilot"], "MCP servers"],
	[/(^|\/)claude_desktop_config\.json$/i, ["Claude Desktop"], "MCP servers"],
	// Codex
	[/(^|\/)\.codex\/agents(\.override)?\.md$/i, ["Codex"], "Instructions"],
	[/(^|\/)\.codex\/config\.toml$/i, ["Codex"], "Permissions & MCP"],
	[/(^|\/)\.codex\/hooks\.json$/i, ["Codex"], "Hooks"],
	[/(^|\/)\.codex\/rules\/[^/]+\.rules$/i, ["Codex"], "Command rules"],
	[/(^|\/)\.codex\/[^/]+\.config\.toml$/i, ["Codex"], "Profile"],
	[/(^|\/)codex\/requirements\.toml$/i, ["Codex"], "Admin policy"],
	[/(^|\/)\.codex\/.+\.md$/i, ["Codex"], "Prompts"],
	[/(^|\/)\.agents\/skills\//i, ["Codex"], "Skills"],
	// Shared instruction files
	[/(^|\/)\.config\/opencode\/agents\.md$/i, ["OpenCode"], "Instructions"],
	[/(^|\/)\.junie\/agents\.md$/i, ["Junie"], "Guidelines"],
	[/(^|\/)agents(\.override)?\.md$/i, ["Codex", "OpenCode", "Cursor", "GitHub Copilot", "Zed"], "Instructions"],
	// Gemini CLI
	[/(^|\/)gemini\.md$/i, ["Gemini CLI"], "Instructions"],
	[/(^|\/)\.gemini\/settings\.json$/i, ["Gemini CLI"], "Settings & MCP"],
	[/(^|\/)(gemini-cli|GeminiCli)\/(system-)?settings\.json$/i, ["Gemini CLI"], "Admin settings"],
	[/(^|\/)\.gemini\/trustedFolders\.json$/i, ["Gemini CLI"], "Trusted folders"],
	[/(^|\/)\.gemini\/extensions\/[^/]+\/gemini-extension\.json$/i, ["Gemini CLI"], "Extension"],
	[/(^|\/)\.gemini\/.+\.md$/i, ["Gemini CLI"], "Instructions"],
	[/(^|\/)\.gemini\/commands\/.+\.toml$/i, ["Gemini CLI"], "Commands"],
	// GitHub Copilot, in VS Code and on the command line
	[/(^|\/)\.github\/copilot-instructions\.md$/i, ["GitHub Copilot"], "Instructions"],
	[/(^|\/)\.github\/(instructions|prompts|chatmodes|agents)\//i, ["GitHub Copilot"], "Instructions & prompts"],
	[/(^|\/)\.github\/hooks\/[^/]+\.json$/i, ["GitHub Copilot"], "Hooks"],
	[/(^|\/)\.github\/mcp\.json$/i, ["GitHub Copilot"], "MCP servers"],
	[/(^|\/)\.github\/copilot\/settings\.json$/i, ["GitHub Copilot"], "Settings"],
	[/(^|\/)\.copilot\/config\.json$/i, ["GitHub Copilot"], "Settings & trusted folders"],
	[/(^|\/)\.copilot\/mcp-config\.json$/i, ["GitHub Copilot"], "MCP servers"],
	[/(^|\/)\.vscode\/mcp\.json$/i, ["GitHub Copilot"], "MCP servers"],
	[/(^|\/)\.vscode\/settings\.json$/i, ["GitHub Copilot"], "Editor settings"],
	[/(^|\/)\.vscode\/tasks\.json$/i, ["Cursor", "Windsurf"], "Editor tasks"],
	[/(^|\/)(Code|Code - Insiders|VSCodium|Cursor|Windsurf)\/User\/settings\.json$/i, (p) => [editorTool(p)], "Editor settings"],
	[/(^|\/)(Code|Code - Insiders|VSCodium|Cursor)\/User\/mcp\.json$/i, (p) => [editorTool(p)], "MCP servers"],
	// Cursor
	[/(^|\/)\.cursor\/mcp\.json$/i, ["Cursor"], "MCP servers"],
	[/(^|\/)\.cursor\/hooks\.json$/i, ["Cursor"], "Hooks"],
	[/(^|\/)\.cursor\/environment\.json$/i, ["Cursor"], "Cloud agent setup"],
	[/(^|\/)\.cursor\/(cli-config|cli)\.json$/i, ["Cursor"], "CLI permissions"],
	[/(^|\/)\.cursor\/sandbox\.json$/i, ["Cursor"], "Sandbox"],
	[/(^|\/)\.cursor\/permissions\.json$/i, ["Cursor"], "Permissions"],
	[/(^|\/)\.cursor\/.+\.mdc?$/i, ["Cursor"], "Rules"],
	[/(^|\/)\.cursorrules$/i, ["Cursor"], "Rules (legacy)"],
	// Cline and Roo Code
	[/(^|\/)saoudrizwan\.claude-dev\/settings\/cline_mcp_settings\.json$/i, ["Cline"], "MCP servers"],
	[/(^|\/)\.cline\/data\/settings\/cline_mcp_settings\.json$/i, ["Cline"], "MCP servers"],
	[/(^|\/)\.cline\/data\/globalState\.json$/i, ["Cline"], "Auto-approve settings"],
	[/(^|\/)\.cline\/plugins\/[^/]+\.[cm]?[jt]sx?$/i, ["Cline"], "Plugin code"],
	[/(^|\/)(Documents\/Cline\/Rules|\.cline\/rules)\//i, ["Cline"], "Rules"],
	[/(^|\/)\.clinerules/i, ["Cline"], "Rules"],
	[/(^|\/)rooveterinaryinc\.roo-cline\/settings\/mcp_settings\.json$/i, ["Roo Code"], "MCP servers"],
	[/(^|\/)(\.roomodes|\.roo\/.+)$/i, ["Roo Code"], "Rules & modes"],
	// Others
	[/(^|\/)\.codeium\/windsurf\/mcp_config\.json$/i, ["Windsurf"], "MCP servers"],
	[/(^|\/)(\.windsurfrules|\.windsurf\/rules\/.+)$/i, ["Windsurf"], "Rules"],
	[/(^|\/)\.windsurf\/workflows\/.+\.md$/i, ["Windsurf"], "Workflows"],
	[/(^|\/)\.windsurf\/mcp_config\.json$/i, ["Windsurf"], "MCP servers"],
	[/(^|\/)(\.windsurf|\.codeium\/windsurf)\/hooks\.json$/i, ["Windsurf"], "Hooks"],
	[/(^|\/)\.devin\/hooks\.v1\.json$/i, ["Windsurf"], "Hooks"],
	[/(^|\/)opencode\.jsonc?$/i, ["OpenCode"], "Settings & MCP"],
	[/(^|\/)\.opencode\/(plugins?|tools)\/[^/]+\.[cm]?[jt]sx?$/i, ["OpenCode"], "Plugin code"],
	[/(^|\/)\.opencode\//i, ["OpenCode"], "Agents & commands"],
	[/(^|\/)\.grok\/config\.toml$/i, ["Grok"], "Permissions & MCP"],
	[/(^|\/)\.grok\/settings\.json$/i, ["Grok"], "Settings & MCP"],
	[/(^|\/)\.grok\/hooks\/[^/]+\.json$/i, ["Grok"], "Hooks"],
	[/(^|\/)(\.grok\/.+|grok)\.md$/i, ["Grok"], "Instructions"],
	[/(^|\/)(\.amp|\.config\/amp)\/settings\.json$/i, ["Amp"], "Settings & MCP"],
	[/(^|\/)(\.amp|\.config\/amp)\/plugins\/[^/]+\.[cm]?[jt]sx?$/i, ["Amp"], "Plugin code"],
	[/(^|\/)goose\/config\.ya?ml$/i, ["Goose"], "Settings & extensions"],
	[/(^|\/)\.goosehints$/i, ["Goose"], "Instructions"],
	[/(^|\/)\.kiro\/steering\//i, ["Kiro"], "Steering"],
	[/(^|\/)\.kiro\/settings\/mcp\.json$/i, ["Kiro"], "MCP servers"],
	[/(^|\/)\.kiro\/hooks\/[^/]+\.(json|kiro\.hook)$/i, ["Kiro"], "Hooks"],
	[/(^|\/)\.kiro\/agents\/[^/]+\.(json|md)$/i, ["Kiro"], "Agents"],
	[/(^|\/)\.amazonq\/rules\//i, ["Amazon Q"], "Rules"],
	[/(^|\/)\.?amazonq\/mcp\.json$/i, ["Amazon Q"], "MCP servers"],
	[/(^|\/)\.?amazonq\/cli-agents\/[^/]+\.json$/i, ["Amazon Q"], "Agents"],
	[/(^|\/)\.continue\//i, ["Continue"], "Config & rules"],
	[/(^|\/)(\.zed|zed|Zed)\/settings\.json$/i, ["Zed"], "Agent settings"],
	[/(^|\/)\.junie\/mcp\/mcp\.json$/i, ["Junie"], "MCP servers"],
	[/(^|\/)\.junie\/(guidelines\.md|rules\/)/i, ["Junie"], "Guidelines"],
	[/(^|\/)\.aider\.conf\.ya?ml$/i, ["Aider"], "Settings"],
	[/(^|\/)(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|config\.fish|[^/]*profile\.ps1)$/i, ["Your shell"], "Shell profile"],
];

function editorTool(path) {
	if (/(^|\/)Cursor\/User\//i.test(path)) return "Cursor";
	if (/(^|\/)Windsurf\/User\//i.test(path)) return "Windsurf";
	return "GitHub Copilot";
}

// Which agents read a file, and what it controls. Null for files no agent reads.
export function controlFor(path) {
	const hit = CONTROL.find(([re]) => re.test(path));
	if (!hit) return null;
	return { tools: typeof hit[1] === "function" ? hit[1](path) : hit[1], kind: hit[2] };
}

const KEY_FILE = /\.(pem|key|p12|pfx|jks|keystore|ppk)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)$|\.aws\/credentials$|service[-_]?account[^/]*\.json$|(^|\/)credentials\.json$|\.git-credentials$|\.codex\/auth\.json$|\.claude\/\.credentials\.json$|\.grok\/user-settings\.json$|\.kube\/config$|\.docker\/config\.json$/i;
const EXAMPLE_ENV = /(^|\/)\.env[\w.-]*\.(example|sample|template|dist|defaults)$/i;
// .pem files are often public certificates, such as cert.pem or ca-bundle.pem,
// which aren't secret. A name that mentions a key still counts as a key.
const CERT_NAME = /cert|crt|chain|bundle|intermediate|leaf|issuer|(^|[-_.])(root|ca|pub|public)([-_.]|$)|ca\.pem$/i;
const KEY_NAME = /privkey|private|(^|[-_.])key([-_.]|$)/i;
// A project's .npmrc usually holds registry settings, not tokens, and keys in
// test and example folders are fixtures.
const USUALLY_HARMLESS = /(^|\/)\.npmrc$|(^|\/)(tests?|__tests__|specs?|fixtures?|testdata|test-data|examples?|samples?|mocks?|demo)\//i;
const isCertificate = (path) => {
	const name = path.split("/").pop();
	return /\.pem$/i.test(name) && (/pub(?:lic)?[-_.]?key/i.test(name) || (CERT_NAME.test(name) && !KEY_NAME.test(name)));
};

// --- Text patterns -----------------------------------------------------------
//
// These run on untrusted text, so every repeat is bounded or can't overlap
// the next part of its pattern, and matching time grows with the text.

const RX_REMOTE_EXEC =
	/\b(?:curl|wget)\b[^\n|;&]{0,300}\|\s*(?:sudo(?:\s+-[A-Za-z]+)*\s+)?(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby)\b|\b(?:(?:ba|z|da|k)?sh\s+-c|eval)\s+["']?\$\(\s*(?:curl|wget)\b|\bsource\s+<\(\s*(?:curl|wget)\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,300}\|\s*(?:iex|Invoke-Expression)\b|\b(?:iex|Invoke-Expression)\b[^\n]{0,20}(?:Net\.WebClient|DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)|\bbase64\s+(?:-d|--decode)\b[^\n|]{0,120}\|\s*(?:ba)?sh\b|\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b|\bpowershell(?:\.exe)?\b[^\n]{0,60}\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\b(?:python[0-9.]*|node|perl|ruby|php)\s+-[ce]\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b|\b(?:curl|wget)\b[^\n|;&]{0,300}?\s(?:-[A-Za-z]{0,8}[oO]|--output|--output-document)[= ]?\s*["']?([\w./~][\w./~-]{0,99})["']?[^\n]{0,120}?(?:&&|;)\s*(?:sudo\s+)?(?:(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|source|\.|chmod\s+\+?[0-7]*x?)\s+)?["']?(?:\.\/)?\1(?![\w./-])|\b(?:curl|wget)\b[^\n|;&]{0,300}?https?:\/\/[^\s"'|;&]{0,200}\/([\w.-]{1,100})["']?[^\n]{0,120}?(?:&&|;)\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|source|\.|chmod\s+\+?[0-7]*x?)\s+["']?(?:\.\/)?\2(?![\w./-])|\bdeno\s+run\b[^\n|;&]{0,120}?\shttps?:\/\/|\b(?:npx|bunx|pnpx)\b(?:\s+-{1,2}[\w-]+)*\s+https?:\/\//i;
// --- Commands ------------------------------------------------------------------
//
// Hooks, scripts and settings that run commands are read one command at a
// time: a command ends at && || ; | or a new line.

function commandsOf(text) {
	const out = [];
	let start = 0;
	for (const m of String(text).matchAll(COMMAND_BREAK)) {
		out.push(text.slice(start, m.index));
		start = m.index + m[0].length;
	}
	out.push(String(text).slice(start));
	return out.filter((c) => c.trim());
}
const wordsOf = (command) => command.trim().split(/\s+/).map((w) => trimWord(w, "\"'", "\"'"));

// curl's options are case-sensitive: -d sends data, -D only saves headers.
const RX_CURL_SEND = /\bcurl\b[^\n]{0,200}\s(?:-[a-zA-Z]*[dFT]|--data(?:-binary|-raw|-urlencode|-ascii)?|--form(?:-string)?|--upload-file|--json|-X\s*["']?(?:POST|PUT|PATCH))\b/;
const RX_NET_SEND =
	/\bwget\b[^\n]{0,200}--post-(?:data|file)\b|\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]{0,200}-(?:Method\s+(?:Post|Put|Patch)|Body|InFile)\b|\b(?:nc|ncat|netcat)\s+[^\n]{0,80}\b\d{2,5}\b|\bscp\s+\S+\s+\S+@|\brsync\b[^\n]{0,100}\s[\w.-]+@[\w.-]+:/i;

// A command that sends data somewhere other than this computer.
function sendsData(text) {
	for (const command of commandsOf(text)) {
		if (!RX_CURL_SEND.test(command) && !RX_NET_SEND.test(command)) continue;
		const hosts = [...command.matchAll(/\bhttps?:\/\/([^\s/:"'`]+)/gi)].map((m) => m[1]);
		if (hosts.length && hosts.every(isLocalHost)) continue;
		return true;
	}
	return false;
}

const RX_DESTRUCTIVE = /\bgit\s+push\b[^\n|;&]{0,200}\s(?:--force\b|-f\b)|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*f|\bmkfs\b|\bdd\s+if=/i;
// Deleting the root of a drive, the home folder or everything in the current
// folder, or "$VAR/", which becomes / when the variable is empty. Cleaning up
// a named folder, such as rm -rf /tmp/build, isn't flagged.
const RISKY_TARGET =
	/^(?:\/\*?|\\\*?|~[\\/]?\*?|\$\{?HOME\}?[\\/]?\*?|\$env:(?:USERPROFILE|HOMEPATH|HOME)[\\/]?\*?|%(?:USERPROFILE|HOMEPATH)%[\\/]?\*?|[A-Za-z]:[\\/]?\*?|\*|\.[\\/]?\*?|\.\.[\\/]?\*?|\$\{?\w+\}?[\\/]\*?)$/i;
function removesTooMuch(text) {
	for (const command of commandsOf(text)) {
		const words = wordsOf(command);
		const at = words.findIndex((w) => /^(?:rm|Remove-Item|ri|rd|rmdir|del|erase)$/i.test(w));
		if (at < 0) continue;
		const args = words.slice(at + 1);
		const cmdStyle = /^(?:rd|rmdir|del|erase)$/i.test(words[at]) && args.some((a) => /^\/[a-z]$/i.test(a));
		const flags = cmdStyle ? args.filter((a) => /^\/[a-z]$/i.test(a)) : args.filter((a) => a.startsWith("-"));
		const targets = cmdStyle ? args.filter((a) => !/^\/[a-z]$/i.test(a)) : args.filter((a) => !a.startsWith("-"));
		const recursive = cmdStyle ? flags.some((a) => /^\/s$/i.test(a)) : flags.some((a) => /^-[a-z]*r[a-z]*$/i.test(a) || /^-(?:-recursive|rec(?:u(?:r(?:s(?:e)?)?)?)?)$/i.test(a));
		if (recursive && targets.some((t) => RISKY_TARGET.test(t))) return true;
	}
	return false;
}
const isDestructive = (text) => RX_DESTRUCTIVE.test(text) || removesTooMuch(text);

// A script run from Downloads or a temp folder, which isn't reviewed with
// the project. Only the program or script being run counts, not a file a
// command writes to.
const OUTSIDE_PATH = /^(?:\/tmp|\/var\/tmp|~\/Downloads|\$HOME\/Downloads|%TEMP%|%TMP%|\$env:TEMP|[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/](?:Downloads|AppData[\\/]Local[\\/]Temp))[\\/]\S+$/i;
const INTERPRETERS = /^(?:bash|sh|zsh|fish|dash|python[0-9.]*|node|deno|bun|ruby|perl|php|pwsh|powershell(?:\.exe)?|source|\.)$/i;
function runsOutsideScript(text) {
	for (const command of commandsOf(text)) {
		const words = wordsOf(command).filter((w) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(w));
		while (/^(?:sudo|exec|nohup|time|env)$/i.test(words[0] ?? "")) words.shift();
		let script = words[0];
		if (INTERPRETERS.test(script ?? "")) script = words.slice(1).find((w) => !w.startsWith("-"));
		if (script && OUTSIDE_PATH.test(script)) return true;
	}
	return false;
}
const RX_EXFIL_HOST =
	/(?:^|[^a-z0-9.-])((?:[a-z0-9-]{1,63}\.){0,8}(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|ngrok(?:-free)?\.(?:app|io|dev)|interact\.sh|oast\.(?:fun|live|me|online|pro|site)|burpcollaborator\.net|canarytokens\.(?:com|org)|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services|pastebin\.com|transfer\.sh|0x0\.st|requestcatcher\.com|beeceptor\.com|hookbin\.com|ptsv[23]\.com|postb\.in))\b/i;
const RX_OVERRIDE =
	/\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|preceding|system|safety|developer)\b[^.\n]{0,20}\b(?:instructions?|rules|prompts?|guidelines|guardrails)\b|\bdo not (?:tell|inform|alert|notify|show|mention (?:this|it) to) the user\b|\bwithout (?:telling|informing|notifying|alerting) the user\b|\bwithout the user(?:'s)? (?:knowing|knowledge|noticing|consent|permission)\b|\bnever ask (?:the user )?(?:for )?(?:permission|confirmation|approval)\b|\b(?:always|automatically|auto-)\s?(?:approve|accept|allow)\s+(?:all\s+|every\s+|any\s+)?(?:the\s+)?(?:tools?(?: (?:calls?|use|uses|requests?))?|commands?|actions?|edits?|file changes|changes|permissions?|permission (?:prompts|requests)|confirmations?|prompts|everything)\b|\b(?:disable|turn off|bypass|skip)\b[^.\n]{0,20}\b(?:sandbox|approvals?|permissions?|confirmations?|safety checks?|guardrails)\b/gi;
const RX_SECRET_ACCESS =
	/\b(?:cat|read|print|output|copy|send|upload|post|include|paste|exfiltrat\w*|grab|collect|dump)\b[^\n]{0,60}(?:~\/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|(?:^|[\s"'`(\[/=:,])\.env\b|\.npmrc|\.git-credentials|\bauth\.json|\.credentials\.json|keychain|browser (?:cookies|passwords))/ig;
const RX_INJECT_WORDS =
	/\b(?:ignore|disregard|override|secretly|silently|quietly|without (?:asking|telling)|do not (?:tell|mention|reveal|ask)|exfiltrat\w*|curl|wget|upload|send (?:it|this|the|them|all|everything)|token|api key|password|ssh|credentials?|base64|you are now|new instructions)\b/i;
const RX_BENIGN_COMMENT = /^\s*(?:markdownlint|prettier|toc|end ?toc|eslint|cspell|vale|begin|end|lint|todo|fixme|note)\b/i;
const RX_IMPORT_OUTSIDE = /(?:^|\s)@((?:~\/|\.\.\/|[A-Za-z]:[\\/]|\/(?:Users|home|etc|tmp|var|opt|root|mnt)\/)[^\s)\]]+)/g;
const RX_BASE64_RUN = /[A-Za-z0-9+/]+={0,2}/g;
const RX_DIRECTIVE = /\byou are (?:an?|the) (?:ai|assistant|agent|coding)|\bas an ai\b|\bsystem prompt\b|\b(?:claude|codex|copilot|cursor|gemini|the agent|assistant)\b[^.\n]{0,40}\b(?:must|should|always|never)\b|\binstructions? for (?:the )?(?:ai|agent|assistant|llm)\b/i;
// Paste sites, where text can change after anyone has looked at it.
// pastebin.com is reported as a data-collection endpoint instead.
const RX_PASTE_SITE =
	/(?:^|[^a-z0-9.-])((?:[a-z0-9-]{1,63}\.){0,3}(?:glot\.io|paste\.ee|hastebin\.(?:com|skyra\.pw)|rentry\.(?:co|org)|ghostbin\.[a-z]{2,6}|termbin\.com|dpaste\.(?:com|org)|paste\.rs|controlc\.com|justpaste\.it|pastes\.dev|privatebin\.net))(?![a-z0-9-])/i;
// Telling the agent to take its instructions from a web page: "follow the
// steps at https://...", or "fetch https://... and do what it says". Whoever
// runs the page decides what the agent does, after the file was reviewed.
const RX_REMOTE_INSTRUCTIONS =
	/\b(?:follow|obey|apply|carry out|execute|run|do)\b[^.\n]{0,40}?\b(?:instructions|steps|commands|directions|rules|guidance)\b[^.\n]{0,30}?\b(?:at|in|from|on)\s+<?https?:\/\/([a-z0-9.-]{1,253})|\b(?:fetch|read|load|open|download|get|visit|retrieve|curl|browse to|go to)\s+<?https?:\/\/([a-z0-9.-]{1,253})[^\s)>]{0,200}>?[^.\n]{0,80}?\b(?:and|then)\s+(?:follow|obey|apply|carry out|execute|do what|run what|run)\b[^.\n]{0,30}?\b(?:instructions|steps|commands|it says|they say|the page says|what it says|says|there|them|it)\b/i;
// A download that needs a password, the way malware hides from scanners.
// It has to give the password, as lures do: talking about password-protected
// archives isn't asking for one.
const ARCHIVE = String.raw`(?:\.(?:zip|7z|rar)\b|\b(?:zip|7z|rar|archive)\b)`;
const PASSWORD_GIVEN = String.raw`\b(?:password|passphrase|passwd)\b(?:\s*(?:is|:|=)\s*|\s+(?=["'\`“]))["'\`“]?([^\s"'\`”]{2,40})`;
const RX_ARCHIVE_PASSWORD = new RegExp(
	[
		`${ARCHIVE}[^\\n]{0,120}(?:\\n[^\\n]{0,80})?${PASSWORD_GIVEN}`,
		`${PASSWORD_GIVEN}[^\\n]{0,80}(?:\\n[^\\n]{0,80})?${ARCHIVE}`,
		String.raw`\bunzip\s+(?:-\w+\s+)*-P\s*\S+`,
		String.raw`\b7z\s+[ex]\b[^\n]{0,80}\s-p\S+`,
	].join("|"),
	"i",
);
// A lure gives the password and says to download, extract or run the file.
// "The password is in 1Password", a login password, or "move it to the
// archive folder" doesn't.
const NOT_A_PASSWORD = new Set(["in", "on", "at", "the", "a", "an", "your", "my", "our", "their", "its", "this", "that", "stored", "kept", "saved", "required", "needed", "set", "not", "available", "managed", "provided", "shared", "sent", "given", "see", "ask", "from", "via", "under", "below", "above", "same", "there", "here", "located", "written", "listed", "unknown", "optional", "empty", "blank", "none", "n/a", "changed", "rotated", "reset", "expired", "correct", "wrong", "invalid", "missing"]);
const NOT_A_GIVEN_PASSWORD = new Set(["see", "ask", "none", "n/a", "in", "your", "the"]);
const LURE_VERB = /\b(?:download|extract|unzip|unpack|decompress|open|run|install|launch|execute)/i;
const LOGIN = /\b(?:log\s?in|sign\s?in|user(?:name)?|account|admin|database|db|ssh|mysql|postgres|redis|wi-?fi)\b/i;
function givesArchivePassword(text, m) {
	// unzip -P and 7z -p extract with a password: a lure on their own.
	if (/^(?:unzip|7z)\b/i.test(m[0])) return true;
	const value = (m[1] ?? m[2] ?? "").replace(/[.,;:!?)\]]+$/, "").toLowerCase();
	const stated = /\bpass(?:word|phrase|wd)\s+is\s/i.test(m[0]);
	if (value && (stated ? NOT_A_PASSWORD : NOT_A_GIVEN_PASSWORD).has(value)) return false;
	const word = m[0].search(/\b(?:password|passphrase|passwd)\b/i);
	if (LOGIN.test(sameLineBefore(text, m.index + Math.max(0, word), 60))) return false;
	const from = Math.max(0, m.index - 200);
	const window = text.slice(from, Math.min(text.length, m.index + m[0].length + 200));
	return LURE_VERB.test(window);
}
// Removing macOS's quarantine flag or turning off Gatekeeper.
// Clearing every attribute is also a step before code signing, so that only
// counts on something in Downloads.
const RX_QUARANTINE = /\bxattr\s+(?:-[a-z]{1,8}\s+){0,4}com\.apple\.quarantine\b|\bxattr\s+-[a-z]{0,6}c[a-z]{0,6}\s[^\n]{0,60}\bDownloads\b|\bspctl\s+--(?:master|global)-disable\b|--no-quarantine\b/i;
// Servers named in attack reports, as hosts or addresses in any agent file.
const RX_KNOWN_BAD_HOST = new RegExp(
	// No lookbehind, so the engine also loads in older Safari.
	`(?:^|[^\\w.-])((?:[a-z0-9-]{1,63}\\.){0,4}?(${Object.keys(KNOWN_BAD_HOSTS).map((h) => h.replace(/[.]/g, "\\.")).join("|")}))(?![\\w-]|\\.\\w)`,
	"i",
);
// The lists in a file whose names say they block things, such as
// permissions.deny in Claude Code's settings or a TOML deny = [...], as
// [start, end] spans. Found once per file, and brackets inside quoted
// entries don't end a list.
function blockSpans(text) {
	const spans = [];
	for (const m of text.matchAll(/["']?([\w.-]{1,60})["']?\s*[:=]\s*\[/g)) {
		if (!/deny|block|disallow|forbid|exclude|reject|ban/i.test(m[1])) continue;
		const start = m.index + m[0].length;
		if (spans.length && start < spans.at(-1)[1]) continue;
		let quote = null;
		let depth = 1;
		let i = start;
		for (; i < text.length && depth > 0; i++) {
			const c = text[i];
			if (quote) {
				if (c === "\\") i++;
				else if (c === quote) quote = null;
			} else if (c === '"' || c === "'") quote = c;
			else if (c === "[") depth++;
			else if (c === "]") depth--;
		}
		spans.push([start, i]);
	}
	return spans;
}
const RX_KNOWN_BAD_HOSTS = new RegExp(RX_KNOWN_BAD_HOST.source, "gi");
// The first mention of a known malware server that's a real use: not on a
// block list and not warned against. Every mention is looked at, so warnings
// and block-list entries can't hide a use after them.
function knownBadHost(text) {
	const content = String(text ?? "");
	let spans = null;
	let at = 0;
	for (const m of content.matchAll(RX_KNOWN_BAD_HOSTS)) {
		const index = m.index + m[0].length - m[1].length;
		spans ??= blockSpans(content);
		while (at < spans.length && spans[at][1] <= index) at++;
		if (at < spans.length && spans[at][0] <= index) continue;
		if (negated(content, index)) continue;
		return { index, host: m[2].toLowerCase(), campaign: KNOWN_BAD_HOSTS[m[2].toLowerCase()] };
	}
	return null;
}
const SHELL_SERVER = /(?:^|[-_/@.])(?:shell|terminal|exec|executor|commands?|cmd|desktop-commander|ssh|powershell|bash|zsh|run-command)(?:[-_.]|$)/i;

// --- Entry point -------------------------------------------------------------

export function analyze(input) {
	const ctx = buildContext(input ?? {});
	// A file that trips up a check is reported as unchecked. It can't stop
	// the rest of the report.
	const guard = (f, check) => {
		try {
			check();
		} catch {
			f.failed = true;
		}
	};
	for (const f of ctx.files) if (f.content) guard(f, () => collectMcpServers(ctx, f));
	for (const f of ctx.files) if (f.content) guard(f, () => checkFile(ctx, f));
	for (const f of ctx.files) {
		if (f.content && f.kind && (f.failed || (/\.(jsonc?|toml)$/i.test(f.path) && parsed(f) == null))) add(ctx, "WS-UNPARSED", { file: f });
	}
	for (const server of ctx.mcpServers) guard(server.file, () => checkMcpServer(ctx, server));
	// Each agent's servers, wherever it reads them from. Servers that belong
	// to different agents aren't all in front of any one of them.
	// Agents that read the same file, such as Claude Code and Copilot with
	// .mcp.json, are reported once.
	const perAgent = new Map();
	for (const s of ctx.mcpServers) {
		if (s.disabled) continue;
		for (const t of s.file.tools ?? []) perAgent.set(t, [...(perAgent.get(t) ?? []), `${s.file.path}#${s.name}`]);
	}
	const reported = new Set();
	for (const [tool, servers] of perAgent) {
		const key = servers.sort().join("\n");
		if (servers.length <= 12 || reported.has(key)) continue;
		reported.add(key);
		add(ctx, "MCP-MANY", { tool, vars: { tool, count: servers.length } });
	}
	checkWorkspace(ctx);
	checkSprawl(ctx);
	checkExtensions(ctx);
	checkInstalls(ctx);
	checkLocked(ctx);
	checkTraces(ctx);
	checkSkillPrograms(ctx);
	checkPluginCode(ctx);
	checkAutorun(ctx);
	checkNamed(ctx);
	return summarize(ctx);
}

function checkFile(ctx, f) {
	const p = f.path;
	if (/(^|\/)(\.claude\/settings(\.local)?\.json|managed-settings(\.d\/[^/]+)?\.json)$/i.test(p)) checkClaudeSettings(ctx, f);
	else if (/(^|\/)\.claude\/plugins\/.+\/hooks\/hooks\.json$/i.test(p) || f.role === "claude-hooks") checkClaudeHooks(ctx, f, hooksOf(parsed(f)));
	else if (/(^|\/)\.claude-plugin\/plugin\.json$/i.test(p)) checkClaudeHooks(ctx, f, hooksOf(parsed(f)?.hooks));
	else if (/(^|\/)\.claude\.json$/i.test(p)) checkClaudeUserConfig(ctx, f);
	else if (/(^|\/)\.codex\/([^/]+\.)?config\.toml$/i.test(p)) checkCodex(ctx, f);
	else if (/(^|\/)(\.gemini|gemini-cli|GeminiCli)\/(system-)?settings\.json$/i.test(p)) checkGemini(ctx, f);
	else if (/(^|\/)\.gemini\/trustedFolders\.json$/i.test(p)) checkTrustedFolders(ctx, f, "Gemini CLI", geminiTrusted(parsed(f)));
	else if (/(^|\/)\.copilot\/config\.json$/i.test(p)) checkTrustedFolders(ctx, f, "GitHub Copilot", copilotTrusted(parsed(f)));
	else if (/(^|\/)\.github\/hooks\/[^/]+\.json$/i.test(p)) checkJsonHooks(ctx, f, "A GitHub Copilot hook");
	else if (/(^|\/)\.cursor\/hooks\.json$/i.test(p)) checkJsonHooks(ctx, f, "A Cursor hook");
	else if (/(^|\/)\.cursor\/environment\.json$/i.test(p)) checkCursorEnvironment(ctx, f);
	else if (/(^|\/)\.vscode\/tasks\.json$/i.test(p)) checkVsCodeTasks(ctx, f);
	else if (/(^|\/)\.codex\/hooks\.json$/i.test(p)) checkJsonHooks(ctx, f, "A Codex hook");
	else if (/(^|\/)\.codex\/rules\/[^/]+\.rules$/i.test(p)) checkCodexRules(ctx, f);
	else if (/(^|\/)((\.windsurf|\.codeium\/windsurf)\/hooks|\.devin\/hooks\.v1)\.json$/i.test(p)) checkJsonHooks(ctx, f, "A Windsurf hook");
	else if (/(^|\/)\.kiro\/hooks\//i.test(p)) checkJsonHooks(ctx, f, "A Kiro hook");
	else if (/(^|\/)\.kiro\/agents\/[^/]+\.json$/i.test(p)) checkAgentFile(ctx, f, "A Kiro hook");
	else if (/(^|\/)\.?amazonq\/cli-agents\//i.test(p)) checkAgentFile(ctx, f, "An Amazon Q hook");
	else if (/(^|\/)\.grok\/hooks\//i.test(p)) checkJsonHooks(ctx, f, "A Grok hook");
	else if (/(^|\/)\.cursor\/(cli-config|cli)\.json$/i.test(p)) checkCursorCli(ctx, f);
	else if (/(^|\/)\.cursor\/sandbox\.json$/i.test(p)) checkCursorSandbox(ctx, f);
	else if (/(^|\/)(\.vscode|(Code|Code - Insiders|VSCodium|Cursor|Windsurf)\/User)\/settings\.json$/i.test(p)) checkVSCode(ctx, f);
	else if (/(^|\/)opencode\.jsonc?$/i.test(p)) checkOpenCode(ctx, f);
	else if (/(^|\/)(\.zed|zed|Zed)\/settings\.json$/i.test(p)) checkZed(ctx, f);
	else if (/(^|\/)\.cline\/data\/globalState\.json$/i.test(p)) checkCline(ctx, f);
	else if (/(^|\/)\.grok\/config\.toml$/i.test(p)) checkGrok(ctx, f);
	else if (/(^|\/)(\.amp|\.config\/amp)\/settings\.json$/i.test(p)) checkAmp(ctx, f);
	else if (/(^|\/)goose\/config\.ya?ml$/i.test(p)) checkGoose(ctx, f);
	else if (/(^|\/)\.continue\/(?:.+\/)?[^/]+\.(?:ya?ml|json)$/i.test(p)) checkContinue(ctx, f);
	else if (f.kind === "Shell profile") checkShellProfile(ctx, f);
	else if (/(^|\/)\.aider\.conf\.ya?ml$/i.test(p)) checkAider(ctx, f);
	else if (/^package\.json$/i.test(p)) checkPackageJson(ctx, f);
	else if (/(^|\/)\.claude\/plugins\/known_marketplaces\.json$/i.test(p)) checkMarketplaces(ctx, f);
	else if (/(^|\/)\.github\/workflows\//i.test(p)) checkWorkflowTrace(ctx, f);

	const bad = knownBadHost(f.content);
	if (bad) {
		const line = lineAt(f.content, bad.index);
		add(ctx, "TXT-KNOWN-C2", { file: f, line, evidence: evidenceLine(f, line), vars: { host: bad.host, campaign: bad.campaign } });
	}

	if (/(^|\/)\.claude\/hooks\//i.test(f.path)) checkHookScript(ctx, f);
	else if (isInstructionFile(f)) checkInstructionText(ctx, f);
}

// Claude Code hooks, written as { hooks: { Event: [...] } } in hooks.json, or
// as { Event: [...] } inside a plugin's plugin.json.
const hooksOf = (json) => (isObj(json?.hooks) ? json.hooks : isObj(json) ? json : null);

// --- Context -----------------------------------------------------------------

function buildContext(input) {
	const files = [];
	const seenPaths = new Set();
	for (const raw of Array.isArray(input.files) ? input.files : []) {
		if (!raw || typeof raw.path !== "string") continue;
		const cleaned = cleanPath(raw.path);
		if (!cleaned || seenPaths.has(cleaned)) continue;
		seenPaths.add(cleaned);
		const path = visibleName(cleaned);
		const file = {
			path,
			size: toInt(raw.size),
			sensitive: raw.sensitive === true,
			tooLarge: raw.tooLarge === true,
			loose: raw.loose === true,
			// A program inside a skill folder, listed by name and never read.
			listed: raw.listed === true,
			// A link the command didn't follow: to a file outside the project, or
			// to a credential file.
			linked: raw.linked === "outside" || raw.linked === "secret" ? raw.linked : null,
			// Too large to read whole, so only its start was read.
			partial: raw.partial === true,
			// A link to a folder, listed by the command and never followed.
			folder: raw.folder === true && raw.linked === "outside",
			// Set by the command for a plugin's hooks or MCP servers kept at a
			// path its plugin.json names.
			role: raw.role === "claude-hooks" || raw.role === "mcp-servers" ? raw.role : null,
		};
		// Files past the size limit are listed as too large rather than half checked.
		if (typeof raw.content === "string" && raw.content.length > MAX_FILE_CHARS) file.tooLarge = true;
		else if (typeof raw.content === "string" && !file.sensitive && !file.listed && !file.linked) {
			file.content = maskSecrets(raw.content).text;
			file.lines = file.content.split(/\r?\n/);
		}
		const control = controlFor(path) ?? (file.role ? { tools: ["Claude Code"], kind: file.role === "claude-hooks" ? "Plugin hooks" : "Plugin MCP servers" } : null);
		file.tools = control ? control.tools : file.loose ? ["Any agent started there"] : [];
		file.kind = control ? control.kind : file.loose ? "Loose file" : null;
		files.push(file);
	}
	// Files that settings name as instructions, such as Gemini CLI's
	// context.fileName, are instructions for that agent whatever their name.
	const named = namedInstructions(files.filter((f) => f.content && NAMING_SETTINGS.some((re) => re.test(f.path))));
	for (const f of files) {
		if ((f.kind && !f.loose) || f.sensitive || f.listed || f.linked || !f.content) continue;
		const hit = named.find((n) => n.test(f.path));
		if (!hit) continue;
		f.kind = "Instructions";
		f.tools = [hit.tool];
		f.loose = false;
		f.named = true;
	}
	const shape = input.shape && typeof input.shape === "object" ? input.shape : {};
	const topLevel = Array.isArray(shape.topLevel) ? shape.topLevel.filter((s) => typeof s === "string").slice(0, 200) : [];
	return {
		root: typeof input.root === "string" ? input.root.slice(0, 120) : null,
		files,
		shape: {
			entries: toInt(shape.entries),
			topLevel,
			rootGit: shape.rootGit === true,
			gitRepos: toInt(shape.gitRepos),
			truncated: shape.truncated === true,
		},
		// git's own ignore lists, read by the command: .git/info/exclude and
		// the global list in ~/.config/git/ignore. Text only, never shown.
		ignoreLists: (Array.isArray(input.ignoreLists) ? input.ignoreLists : [])
			.filter((l) => typeof l?.content === "string")
			.slice(0, 4)
			.map((l) => l.content.slice(0, 64 * 1024)),
		maskedInBrowser: toInt(input.masked?.count),
		// Found by the command on this computer: agent installs, editor
		// extensions and files attacks leave. Each is checked against what
		// known.js expects, so nothing else can get through.
		installs: installsFrom(input.installs),
		locked: lockedFrom(input.locked),
		extensions: extensionsFrom(input.extensions),
		traces: new Set((Array.isArray(input.traces) ? input.traces : []).filter((p) => typeof p === "string" && TRACE_PATHS.has(p))),
		packages: [],
		homeLike: topLevel.filter((n) => HOME_MARKERS.has(n)).length >= 3,
		// The command was run in the home folder, so it checked the agent
		// settings there, not a project. Where the agents themselves were
		// started is in their own settings.
		ranInHome: input.scanned?.projectSkipped === true,
		// Glob matching work allowed for the whole check.
		ignoreBudget: { left: 8_000_000 },
		findings: [],
		seen: new Set(),
		mcpServers: [],
		claudeDeny: [],
		claudeSettingsFiles: [],
		// Project files whose settings run commands on their own: the first one each.
		autorun: new Map(),
		named,
	};
}

function cleanPath(p) {
	const unix = p.replace(/\\/g, "/");
	const parts = unix.split("/").filter((s) => s && s !== ".");
	// As long as a path can be. Shorter would let a deep folder hide a file.
	if (!parts.length || parts.includes("..") || parts.join("/").length > 4096) return null;
	// Keep the leading slash of system files such as /etc/claude-code/managed-settings.json.
	return (unix.startsWith("/") ? "/" : "") + parts.join("/");
}

// Strings and numbers from a JSON list, as text. Anything else is dropped.
const scalars = (x) => (Array.isArray(x) ? x.filter((v) => typeof v === "string" || typeof v === "number").map(String) : []);
// A value from a settings file as text, or "" when it isn't a string, number or boolean.
const asText = (v) => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "");
// Only numbers and number strings count: Number() on an object can call its
// own conversion code or throw.
const toInt = (n) => {
	const x = typeof n === "number" || typeof n === "string" ? Number(n) : NaN;
	return Number.isFinite(x) ? Math.max(0, Math.floor(x)) : 0;
};
const arr = (x) => (Array.isArray(x) ? x.filter((s) => typeof s === "string") : []);
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const clip = (s, n = 180) => {
	const t = String(s).replace(/\s+/g, " ").trim();
	return t.length > n ? t.slice(0, n - 1) + "…" : t;
};

function isInstructionFile(f) {
	if (f.loose || f.named) return true;
	if (!f.kind) return false;
	return /\.(md|mdc|txt)$/i.test(f.path) || /(^|\/)\.gemini\/commands\/.+\.toml$/i.test(f.path) || /(^|\/)\.(cursorrules|windsurfrules|clinerules|goosehints)$/i.test(f.path) || /(^|\/)\.clinerules\//i.test(f.path);
}

// The line that names a folder as a key. Quoted first, so "~" doesn't match
// the line for "~/Downloads".
function keyLine(file, key) {
	return lineOf(file, JSON.stringify(key)) || lineOf(file, `'${key}'`) || lineOf(file, key);
}

function lineOf(file, test) {
	if (!file.lines) return 0;
	const idx = file.lines.findIndex((line) => (typeof test === "string" ? line.includes(test) : test.test(line)));
	return idx >= 0 ? idx + 1 : 0;
}

// The first line at or after `from` that matches, else the first anywhere.
// Two servers can use the same package or key; each finding should point at
// its own server's lines.
function lineAfter(file, test, from) {
	if (!file.lines || !from) return lineOf(file, test);
	const idx = file.lines.findIndex((line, i) => i >= from - 1 && (typeof test === "string" ? line.includes(test) : test.test(line)));
	return idx >= 0 ? idx + 1 : lineOf(file, test);
}

// The warning has to reach the match: a sentence end, a semicolon or a word
// like "instead" or "then" starts something new. A dot inside a name, as in
// paste.ee, doesn't.
const NEGATED = /\b(?:never|don['’]t|do not|does not|must not|mustn['’]t|should not|shouldn['’]t|avoid|refuse to|forbidden|prohibited|no need to)\b(?:(?!\b(?:but|instead|then|rather|except|however)\b)(?:[^.!?;\n]|\.(?=\w))){0,40}$/i;

// True when the words just before `index`, on the same line, warn against it.
function negated(text, index) {
	return NEGATED.test(sameLineBefore(text, index, 60));
}

// Up to `max` characters before `index`, back to the start of its line. Only
// that much is looked at, so many matches on one long line stay fast.
function sameLineBefore(text, index, max) {
	const before = text.slice(Math.max(0, index - max), index);
	return before.slice(before.lastIndexOf("\n") + 1);
}

function firstMatch(text, re, affirmative, reject) {
	const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
	for (const m of text.matchAll(global)) {
		if (affirmative && negated(text, m.index)) continue;
		if (reject && reject(m)) continue;
		return m;
	}
	return null;
}

// True when a match is quoted as an example rather than said: it follows
// "e.g." or "such as", or sits inside quotes.
function quotedExample(text, m, quotes) {
	const before = text.slice(Math.max(0, m.index - 24), m.index);
	if (/(?:e\.g\.|i\.e\.|for example|such as|like)[,:]?\s*["'“‘(`]?\s*$/i.test(before)) return true;
	const open = before.match(/(\S)\s*$/)?.[1];
	if (!open || !quotes.includes(open)) return false;
	const close = { "“": "”", "‘": "’" }[open] ?? open;
	const after = text.slice(m.index + m[0].length, m.index + m[0].length + 40);
	const end = after.indexOf(close);
	if (end < 0 || end > 30 || after.slice(0, end).includes("\n")) return false;
	// Quotes alone don't make an example: the sentence has to say it's one.
	return RX_EXAMPLE_CONTEXT.test(sameLineBefore(text, m.index, 120));
}
const RX_EXAMPLE_CONTEXT =
	/\b(?:if|contains?|says?|such as|phrases?|text|attacks?|injections?|untrusted|examples?|patterns?|watch for|look for|don't follow|do not follow|never follow|ignore requests)\b/i;

// True when a match sits in a code block that the text just before it
// introduces as an example, as in "An injection looks like this:".
function fencedExample(text, index, fence) {
	const block = fence(index);
	return block !== null && RX_EXAMPLE_CONTEXT.test(text.slice(Math.max(0, block[0] - 160), block[0]));
}

// The first run of 300 or more base64 characters, skipping images embedded
// as data: URLs.
function longBase64(text) {
	RX_BASE64_RUN.lastIndex = 0;
	for (let m = RX_BASE64_RUN.exec(text); m; m = RX_BASE64_RUN.exec(text)) {
		if (m[0].length < 300) continue;
		if (/data:image\/[\w.+-]+;base64,$/i.test(text.slice(Math.max(0, m.index - 40), m.index))) continue;
		return { index: m.index, length: m[0].length };
	}
	return null;
}

function lineAt(text, index) {
	let n = 1;
	for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
	return n;
}

function evidenceLine(file, line) {
	return line && file.lines ? clip(file.lines[line - 1] ?? "") : undefined;
}

function add(ctx, id, opts = {}) {
	const { file, line = 0, vars = {} } = opts;
	const key = [id, file?.path ?? null, line, ...["server", "key", "rule", "place", "ext", "pkg", "known", "name", "skill", "campaign", "path"].map((k) => vars[k] ?? "")].join("|");
	if (ctx.seen.has(key)) return;
	ctx.seen.add(key);
	ctx.findings.push(makeFinding(id, opts));
}

function makeFinding(id, { file, line = 0, evidence, vars = {}, tool } = {}) {
	const rule = RULES[id];
	if (!rule) throw new Error(`Unknown rule ${id}`);
	const filePath = file?.path ?? null;
	const values = Object.fromEntries(Object.entries({ file: filePath ?? "", ...vars }).map(([k, v]) => [k, String(v ?? "")]));
	const fill = (text) => fillTemplate(text, values);
	return {
		id,
		severity: rule.severity,
		category: rule.category,
		tool: tool ?? rule.tool ?? (file?.tools?.length ? file.tools[0] : null),
		title: fill(rule.title),
		why: fill(rule.why),
		fix: fill(rule.fix),
		file: filePath,
		line: line || null,
		evidence: evidence ? describeMasks(clip(evidence, 220)) : null,
		vars: values,
	};
}

function fillTemplate(text, values) {
	return text.replace(/\{(\w+)\}/g, (_, k) => {
		const v = values[k] ?? "";
		if (FROM_FILES.has(k)) return fileValue(v, k);
		// "where" is a fixed phrase that can quote a name, as in The “deploy” script.
		if (k === "where") return v.replace(/“([^”]*)”/g, (_, name) => `“${fileValue(name, "server")}”`);
		return v;
	});
}

// Text from the user's files inside one of misconfig's own sentences: names,
// paths, commands and quoted phrases. It's kept to one line, without double
// quotes or direction marks, and cut to size, so a name in a hostile file
// can't close misconfig's quotes or carry a sentence of its own.
const FROM_FILES = new Set(["cmd", "decoded", "phrase", "host", "ref", "path", "dir", "command", "rule", "files", "list", "key", "server", "pkg", "skill"]);
const FILE_VALUE_MAX = { key: 80, server: 40, skill: 40, pkg: 80, host: 100, folder: 80 };
function fileValue(value, k) {
	let text = String(value)
		.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, " ")
		.replace(/["“”„‟]/g, "'")
		.replace(/\s+/g, " ")
		.trim();
	// Variable and header names have no spaces, so a space ends the name.
	if (k === "key") text = text.split(" ")[0];
	const max = FILE_VALUE_MAX[k] ?? 120;
	return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// The worst finding in its own words, then how many more like it. Titles
// start with names such as Codex or ~/.zshrc, so they're never lowercased.
function headlineFor(counts, top, hasControlFiles) {
	const minor = counts.medium + counts.low;
	if (!hasControlFiles && !top) return "No agent setup files found here.";
	const lead = (n, level) => (n > 1 ? `${top.title}, and ${n - 1} more ${level} issue${n === 2 ? "" : "s"}.` : `${top.title}.`);
	if (counts.critical) return lead(counts.critical, "critical");
	if (counts.high) return lead(counts.high, "high-risk");
	if (minor) return `No critical issues. ${minor} thing${minor === 1 ? "" : "s"} worth tightening.`;
	return "No issues found in these agent files.";
}

// --- Claude Code -------------------------------------------------------------

function parsed(file) {
	if (file.parsed === undefined) file.parsed = (/\.toml$/i.test(file.path) ? parseTOML(file.content) : /\.ya?ml$/i.test(file.path) ? parseYAML(file.content) : parseJSONC(file.content)) ?? null;
	return file.parsed;
}

// Environment variables that make the programs an agent runs load other
// code as they start: a Node module, a shared library, a shell script, a
// Java agent, a .NET hook, or a command git runs. Values that only tune a
// program, such as NODE_OPTIONS=--max-old-space-size=4096, don't count.
const JAVA_AGENT = (v) => /-(?:javaagent|agentpath|agentlib)[:=]/i.test(v);
const CODE_LOADING_ENV = {
	NODE_OPTIONS: (v) => /(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader)(?:[\s=]|$)/.test(v),
	LD_PRELOAD: () => true,
	LD_AUDIT: () => true,
	DYLD_INSERT_LIBRARIES: () => true,
	BASH_ENV: () => true,
	ZDOTDIR: () => true,
	PERL5OPT: (v) => /-[MmIdx]/.test(v),
	RUBYOPT: (v) => /(?:^|\s)-(?:r|I)/.test(v),
	JAVA_TOOL_OPTIONS: JAVA_AGENT,
	_JAVA_OPTIONS: JAVA_AGENT,
	JDK_JAVA_OPTIONS: JAVA_AGENT,
	DOTNET_STARTUP_HOOKS: () => true,
	// Plain ssh with options is how deploy keys are chosen; anything else runs a program.
	GIT_SSH_COMMAND: (v) => !/^\s*ssh(?:\.exe)?(?:\s+-[A-Za-z](?:\s+[^\s;&|`$()<>]+)?)*\s*$/.test(v),
	GIT_SSH: () => true,
	GIT_EXTERNAL_DIFF: () => true,
	GIT_CONFIG_PARAMETERS: (v) => /core\.(?:fsmonitor|hookspath|sshcommand|pager|editor|askpass)|alias\./i.test(v),
	CLAUDE_CODE_SHELL_PREFIX: () => true,
	// A folder named relative to wherever a command runs, or an empty entry,
	// which means the current folder: a project's own programs then stand in
	// for git, npm and the rest.
	PATH: (v) => {
		const windows = v.includes(";");
		return v.length > 0 && v.split(windows ? ";" : ":").some((p) => (p.trim() ? !/^(?:\/|~|[A-Za-z]:[\\/]|\$|%)/.test(p.trim()) : !windows));
	},
};
// The variable that loads code, or null.
function codeLoadingVariable(key, value) {
	if (typeof key !== "string" || (typeof value !== "string" && typeof value !== "number")) return null;
	const v = String(value);
	if (Object.hasOwn(CODE_LOADING_ENV, key)) return CODE_LOADING_ENV[key](v) ? key : null;
	// git reads GIT_CONFIG_KEY_0=core.fsmonitor with GIT_CONFIG_VALUE_0.
	if (/^GIT_CONFIG_KEY_\d{1,3}$/.test(key) && /^(?:core\.(?:fsmonitor|hookspath|sshcommand|pager|editor|askpass)|alias\.)/i.test(v)) return key;
	return null;
}

// Where an agent sends its requests. A base address, a proxy or a telemetry
// collector set by a project hands that host the prompts, the code and often
// the API key once the folder is trusted. In your own settings it's usually
// a company gateway, so there it's only noted.
const ENDPOINT_VARIABLES = new Set([
	"ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "ANTHROPIC_FOUNDRY_BASE_URL",
	"OPENAI_BASE_URL", "OPENAI_API_BASE", "GOOGLE_GEMINI_BASE_URL", "GEMINI_BASE_URL",
	"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
]);
const CA_VARIABLES = new Set(["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"]);
// The services' own addresses, and cloud providers that host them.
const OFFICIAL_ENDPOINT = /(?:^|\.)(?:anthropic\.com|claude\.ai|openai\.com|googleapis\.com|amazonaws\.com|azure\.com|azure\.net|windows\.net)$/i;
function endpointHost(value) {
	if (typeof value !== "string" || !value.trim() || value.length > 2000) return null;
	let url;
	try {
		url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value.trim()) ? value.trim() : `http://${value.trim()}`);
	} catch {
		return null;
	}
	const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
	return !host || isLocalHost(host) || isLocalHost(`[${host}]`) || OFFICIAL_ENDPOINT.test(host) ? null : host;
}
// { variable, host } when an environment variable points the agent elsewhere.
function endpointVariable(key, value) {
	const name = typeof key === "string" ? key.toUpperCase() : "";
	if (!ENDPOINT_VARIABLES.has(name)) return null;
	const host = endpointHost(typeof value === "number" ? String(value) : value);
	return host ? { variable: name, host } : null;
}
const tlsOff = (key, value) => typeof key === "string" && key.toUpperCase() === "NODE_TLS_REJECT_UNAUTHORIZED" && String(value).trim() === "0";
// A file in the project folder, as opposed to the settings on the computer.
const inProject = (ctx, f) => !ctx.homeLike && !/^(~|\/|[A-Za-z]:)/.test(f.path);
// Environment variables that send requests elsewhere or weaken TLS, from any
// setting that sets them for the agent.
function checkEnvironment(ctx, f, where, key, value, line) {
	const at = { file: f, line, evidence: evidenceLine(f, line) };
	const endpoint = endpointVariable(key, value);
	if (endpoint) add(ctx, inProject(ctx, f) ? "AGENT-ENDPOINT" : "AGENT-ENDPOINT-USER", { ...at, vars: { where, ...endpoint } });
	if (tlsOff(key, value)) add(ctx, "ENV-TLS-OFF", { ...at, vars: { where, variable: "NODE_TLS_REJECT_UNAUTHORIZED" } });
	const ca = typeof key === "string" ? key.toUpperCase() : "";
	if (CA_VARIABLES.has(ca) && inProject(ctx, f) && String(value).trim()) add(ctx, "ENV-CA-PROJECT", { ...at, vars: { where, variable: ca } });
}
function checkEndpointSetting(ctx, f, where, setting, value, line) {
	const host = endpointHost(value);
	if (host) add(ctx, inProject(ctx, f) ? "AGENT-ENDPOINT" : "AGENT-ENDPOINT-USER", { file: f, line, evidence: evidenceLine(f, line), vars: { where, variable: setting, host } });
}

// Settings that make Claude Code run a command, and the ones it ignores in a
// project's own settings files.
const CLAUDE_COMMAND_KEYS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper", "statusLine", "subagentStatusLine", "fileSuggestion", "processWrapper", "policyHelper", "sshHostCommands"];
const CLAUDE_USER_ONLY_KEYS = new Set(["processWrapper", "policyHelper", "sshHostCommands"]);

// A project's own .claude/settings.json or settings.local.json, as opposed to
// the user's ~/.claude/settings.json or an administrator's managed settings.
function isProjectSettings(ctx, f) {
	return !ctx.homeLike && !/^(~|\/|[A-Za-z]:)/.test(f.path) && !/(^|\/)managed-settings/i.test(f.path);
}

// The commands in a setting's value: a string, { command } or { path }, or a list of those.
function commandsIn(value, depth = 0) {
	if (typeof value === "string") return [value];
	if (Array.isArray(value) && depth < 4) return value.flatMap((v) => commandsIn(v, depth + 1));
	if (isObj(value)) return [value.command, value.path].filter((c) => typeof c === "string");
	return [];
}

function checkClaudeSettings(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	ctx.claudeSettingsFiles.push(f);
	const p = isObj(json.permissions) ? json.permissions : {};
	const shared = isProjectSettings(ctx, f);

	if (p.defaultMode === "bypassPermissions") {
		// Claude Code 2.1.257 and later ignore this in project settings.
		const line = lineOf(f, /bypassPermissions/);
		add(ctx, shared ? "CC-BYPASS-PROJECT" : "CC-BYPASS", { file: f, line, evidence: evidenceLine(f, line) });
	} else if (p.defaultMode === "acceptEdits") {
		const line = lineOf(f, /acceptEdits/);
		add(ctx, "CC-ACCEPT-EDITS", { file: f, line, evidence: evidenceLine(f, line) });
	}

	for (const rule of arr(p.allow)) {
		const r = rule.trim();
		const line = lineOf(f, r);
		const hit = (id) => add(ctx, id, { file: f, line, evidence: evidenceLine(f, line), vars: { rule: r } });
		if (/^Bash(\((\*|\*:\*|:\*|\*\*)?\))?$/i.test(r)) hit("CC-ALLOW-ALL-BASH");
		else if (/^Bash\(\s*(sudo|su|doas|rm|bash|sh|zsh|fish|pwsh|powershell|cmd|python3?|node|deno|bun|npx|perl|ruby|php|eval|exec|iex|Invoke-Expression|chmod|chown|dd|docker|kubectl|env|xargs|find)\b/i.test(r)) hit("CC-ALLOW-RISKY-BASH");
		else if (/^Bash\(\s*(curl|wget|ssh|scp|sftp|rsync|nc|ncat|netcat|ftp|telnet|Invoke-WebRequest|iwr|irm|git push|gh)\b/i.test(r)) hit("CC-ALLOW-NET-BASH");
		else if (/^(Edit|Write|MultiEdit|NotebookEdit)\(\s*(\/\/|~\/|~$|\/\*\*|[A-Za-z]:)/i.test(r)) hit("CC-ALLOW-WRITE-ANYWHERE");
		else if (/^Read\(\s*(\/\/|~\/|~$|[A-Za-z]:)/i.test(r)) hit("CC-ALLOW-READ-ANYWHERE");
		else if (/^WebFetch(\(\s*(domain:\*|\*)?\s*\))?$/i.test(r)) hit("CC-ALLOW-WEBFETCH");
		else if (/^mcp__[^_]+(__\*)?$/i.test(r)) hit("CC-ALLOW-MCP-ALL");
	}

	ctx.claudeDeny.push(...arr(p.deny));

	for (const dir of arr(p.additionalDirectories)) {
		if (isBroadPath(dir) || /^\.\.(\/\.\.)*\/?$/.test(dir.trim())) {
			const line = lineOf(f, dir);
			add(ctx, "CC-EXTRA-DIRS", { file: f, line, evidence: evidenceLine(f, line), vars: { dir } });
		}
	}

	if (json.enableAllProjectMcpServers === true) {
		const line = lineOf(f, /enableAllProjectMcpServers/);
		add(ctx, "CC-MCP-AUTO-APPROVE", { file: f, line, evidence: evidenceLine(f, line) });
	}

	if (isObj(json.env)) {
		for (const [key, value] of Object.entries(json.env)) {
			if (typeof value === "string" && isSecretValue(key, value)) {
				const line = lineOf(f, `"${key}"`);
				add(ctx, "CC-ENV-SECRET", { file: f, line, evidence: `${key} = ${redact(value)}`, vars: { key } });
			}
			const variable = codeLoadingVariable(key, value);
			if (variable) {
				const line = lineOf(f, `"${key}"`);
				add(ctx, "ENV-CODE-LOAD", { file: f, line, evidence: evidenceLine(f, line), vars: { where: "Claude Code's env setting", variable } });
			}
			checkEnvironment(ctx, f, "Claude Code's env setting", key, value, lineOf(f, `"${key}"`));
		}
	}
	// Claude Code keeps each person's approvals in settings.local.json. In the
	// shared settings, a project approves its own servers for everyone.
	if (shared && !/settings\.local\.json$/i.test(f.path) && arr(json.enabledMcpjsonServers).length) {
		const line = lineOf(f, /enabledMcpjsonServers/);
		add(ctx, "CC-MCP-PROJECT-APPROVED", { file: f, line, evidence: evidenceLine(f, line) });
	}

	for (const key of CLAUDE_COMMAND_KEYS) {
		if (shared && CLAUDE_USER_ONLY_KEYS.has(key)) continue;
		for (const command of commandsIn(json[key])) checkCommand(ctx, command, f, `Claude Code's ${key} setting`);
	}
	checkClaudeHooks(ctx, f, json.hooks);
}

// Hooks in Claude Code settings and in plugins' hooks/hooks.json. Command
// hooks run on this computer; http hooks post what Claude is doing to a URL.
function checkClaudeHooks(ctx, f, hooks) {
	if (!isObj(hooks)) return;
	for (const [event, entries] of Object.entries(hooks)) {
		const where = Object.hasOwn(HOOK_EVENTS, event) ? `A Claude Code ${event} hook` : "A Claude Code hook";
		for (const entry of Array.isArray(entries) ? entries : []) {
			for (const h of Array.isArray(entry?.hooks) ? entry.hooks : [entry]) {
				if (typeof h?.command === "string") checkCommand(ctx, h.command, f, where);
				if (h?.type === "http" && typeof h.url === "string") checkHookUrl(ctx, h.url, f, where);
			}
		}
	}
}

function checkHookUrl(ctx, url, f, where) {
	let host;
	try {
		host = new URL(url).hostname;
	} catch {
		return;
	}
	if (isLocalHost(host)) return;
	const line = lineOf(f, url.slice(0, 60)) || lineOf(f, /"url"/);
	add(ctx, "HOOK-HTTP", { file: f, line, evidence: evidenceLine(f, line), vars: { where, host } });
}

const isLocalHost = (host) => /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/i.test(host);

function checkClaudeUserConfig(ctx, f) {
	// ~/.claude.json is where Claude Code keeps its account data. A copy in a
	// project folder is the problem.
	const inProject = !/^(~|\/|[A-Za-z]:)/.test(f.path) && !ctx.homeLike;
	if (inProject && isMasked(f.content)) add(ctx, "CC-USER-SECRET", { file: f, line: lineOf(f, /«masked:/) });
	const json = parsed(f);
	if (!isObj(json)) return;
	if (isObj(json.projects)) {
		for (const dir of Object.keys(json.projects)) {
			const place = riskyPlace(dir);
			if (place) add(ctx, "WS-OPENED-IN", { file: f, line: keyLine(f, dir), tool: "Claude Code", vars: { tool: "Claude Code", place: place.name, risk: place.risk, dir } });
		}
		for (const project of Object.values(json.projects)) {
			for (const rule of arr(project?.allowedTools)) {
				if (/^Bash(\((\*|\*:\*|:\*)?\))?$/i.test(rule.trim())) {
					const line = lineOf(f, rule);
					add(ctx, "CC-ALLOW-ALL-BASH", { file: f, line, evidence: evidenceLine(f, line), vars: { rule } });
				}
			}
		}
	}
}

// --- Codex -------------------------------------------------------------------

function checkCodex(ctx, f) {
	const toml = parsed(f);
	if (!isObj(toml)) return;
	const scopes = [["", toml]];
	if (isObj(toml.profiles)) for (const [name, prof] of Object.entries(toml.profiles)) if (isObj(prof)) scopes.push([` in profile “${name}”`, prof]);

	for (const [where, scope] of scopes) {
		const approval = scope.approval_policy;
		const sandbox = scope.sandbox_mode;
		const line = lineOf(f, sandbox === "danger-full-access" ? /danger-full-access/ : /approval_policy/);
		if (approval === "never" && sandbox === "danger-full-access") add(ctx, "CX-YOLO", { file: f, line, evidence: evidenceLine(f, line), vars: { where } });
		else if (sandbox === "danger-full-access") add(ctx, "CX-FULL-ACCESS", { file: f, line, evidence: evidenceLine(f, line), vars: { where } });
		else if (approval === "never" && sandbox !== "read-only") {
			const l = lineOf(f, /approval_policy\s*=\s*["']never/);
			add(ctx, "CX-NEVER-ASK", { file: f, line: l, evidence: evidenceLine(f, l), vars: { where } });
		}
	}
	if (toml.sandbox_workspace_write?.network_access === true) {
		const line = lineOf(f, /network_access\s*=\s*true/);
		add(ctx, "CX-NETWORK", { file: f, line, evidence: evidenceLine(f, line) });
	}
	const notify = arr(toml.notify).join(" ");
	if (notify) checkCommand(ctx, notify, f, "Codex's notify command");
	if (isObj(toml.hooks)) checkJsonHooks(ctx, f, "A Codex hook", toml.hooks);
	for (const provider of isObj(toml.model_providers) ? Object.values(toml.model_providers) : []) {
		const auth = provider?.auth;
		const command = isObj(auth) && typeof auth.command === "string" ? [auth.command, ...arr(auth.args)].join(" ") : "";
		if (command) checkCommand(ctx, command, f, "Codex's model provider login command");
	}
	for (const server of isObj(toml.mcp_servers) ? Object.values(toml.mcp_servers) : []) {
		for (const command of commandsIn(server?.http_headers_helper)) checkCommand(ctx, command, f, "Codex's MCP header command");
	}
	const set = toml.shell_environment_policy?.set;
	if (isObj(set)) {
		for (const [key, value] of Object.entries(set)) {
			const variable = codeLoadingVariable(key, value);
			if (variable) {
				const line = lineOf(f, key);
				add(ctx, "ENV-CODE-LOAD", { file: f, line, evidence: evidenceLine(f, line), vars: { where: "Codex's shell_environment_policy", variable } });
			}
			// It sets the commands Codex runs, not Codex itself, so only TLS counts here.
			if (tlsOff(key, value)) {
				const line = lineOf(f, key);
				add(ctx, "ENV-TLS-OFF", { file: f, line, evidence: evidenceLine(f, line), vars: { where: "Codex's shell_environment_policy", variable: "NODE_TLS_REJECT_UNAUTHORIZED" } });
			}
		}
	}
	for (const provider of isObj(toml.model_providers) ? Object.values(toml.model_providers).slice(0, 20) : []) {
		if (typeof provider?.base_url === "string") checkEndpointSetting(ctx, f, "Codex's model_providers setting", "base_url", provider.base_url, lineOf(f, provider.base_url.slice(0, 60)) || lineOf(f, /base_url/));
	}
	for (const key of ["openai_base_url", "chatgpt_base_url"]) {
		if (typeof toml[key] === "string") checkEndpointSetting(ctx, f, "Codex's model_providers setting", "base_url", toml[key], lineOf(f, key));
	}
	if (isObj(toml.projects)) {
		for (const [dir, settings] of Object.entries(toml.projects)) {
			const place = riskyPlace(dir);
			if (place && settings?.trust_level === "trusted") add(ctx, "CX-TRUSTED-DIR", { file: f, line: keyLine(f, dir), vars: { place: place.name, risk: place.risk, dir } });
		}
	}
}

// Folders an agent should never be started in. Accepts absolute and ~ paths.
const RISK_HOME = "It can read everything there, including SSH keys, cloud credentials and your other projects.";
const RISK_DOWNLOADS = "Files saved there from websites, chats and email become context the agent reads and may act on.";
const RISK_DRIVE = "It can read and change anything on that drive.";

export function riskyPlace(dir) {
	const d = trimWord(String(dir).replace(/\\/g, "/").replace(/\/{2,}/g, "/"), "", "/");
	const last = d.split("/").pop();
	if (/^(~|\/Users\/[^/]+|\/home\/[^/]+|\/root|[A-Za-z]:\/Users\/[^/]+)$/i.test(d)) return { name: "your home folder", risk: RISK_HOME };
	if (/^(Downloads|Desktop)$/i.test(last)) return { name: `your ${folderName(last)} folder`, risk: RISK_DOWNLOADS };
	if (d === "" || /^[A-Za-z]:$/.test(d)) return { name: "the root of a drive", risk: RISK_DRIVE };
	return null;
}

function checkShellProfile(ctx, f) {
	for (const [i, line] of f.lines.entries()) {
		if (/^\s*#/.test(line)) continue;
		const trace = SHELL_TRACES.find((t) => t.line.test(line));
		if (trace) add(ctx, "ATTACK-SHELL-LINE", { file: f, line: i + 1, evidence: line, vars: { campaign: trace.campaign, what: trace.what, advice: trace.fix } });
		const hit = findDangerFlag(line);
		if (hit) add(ctx, "FLAG-ALIAS", { file: f, line: i + 1, evidence: line, tool: hit.agent, vars: { agent: hit.agent, flag: hit.flag, cmd: clip(line, 120) } });
	}
}

// --- Gemini, VS Code, OpenCode, Zed, Aider -----------------------------------

function checkGemini(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	let yolo = false;
	let autoAccept = false;
	let autoEdit = false;
	walk(json, (key, value) => {
		if (/^yolo$/i.test(key) && value === true) yolo = true;
		if (/approvalMode$/i.test(key) && /^yolo$/i.test(asText(value))) yolo = true;
		if (/approvalMode$/i.test(key) && /^auto_edit$/i.test(asText(value))) autoEdit = true;
		if (key === "autoAccept" && value === true) autoAccept = true;
	});
	// Commands Gemini CLI runs itself: to find and call project tools, and hooks.
	const at = (...keys) => keys.reduce((o, k) => (isObj(o) ? o[k] : undefined), json);
	for (const [value, where] of [
		[at("tools", "discoveryCommand"), "Gemini CLI's tool discovery command"],
		[at("toolDiscoveryCommand"), "Gemini CLI's tool discovery command"],
		[at("tools", "callCommand"), "Gemini CLI's tool call command"],
		[at("toolCallCommand"), "Gemini CLI's tool call command"],
	]) {
		for (const command of commandsIn(value)) checkCommand(ctx, command, f, where);
	}
	if (isObj(json.hooks)) checkJsonHooks(ctx, f, "A Gemini CLI hook", json.hooks);
	// Gemini CLI ignores YOLO mode in settings, so asking for it there doesn't
	// hide the settings it does apply.
	if (yolo) {
		const line = lineOf(f, /yolo/i);
		add(ctx, "GM-YOLO", { file: f, line, evidence: evidenceLine(f, line) });
	}
	if (autoAccept) {
		const line = lineOf(f, /autoAccept/);
		add(ctx, "GM-AUTO-ACCEPT", { file: f, line, evidence: evidenceLine(f, line) });
	}
	if (autoEdit) {
		const line = lineOf(f, /auto_edit/);
		add(ctx, "GM-AUTO-EDIT", { file: f, line, evidence: evidenceLine(f, line) });
	}
}

const VS_CODE_AUTO_APPROVE = ["chat.tools.autoApprove", "chat.tools.global.autoApprove", "chat.permissions.default"];
const ALWAYS_ALLOW_KEYS = ["alwaysAllow", "autoApprove", "auto_approve", "trust"];

function checkVSCode(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	const at = (key) => {
		const line = lineOf(f, key);
		return { file: f, line, evidence: evidenceLine(f, line) };
	};
	for (const key of VS_CODE_AUTO_APPROVE) {
		if (json[key] === true || json[key] === "autoApprove") add(ctx, "VS-AUTO-APPROVE", { ...at(key), vars: { setting: key } });
	}
	if (json["github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions"] === true) add(ctx, "VS-CLAUDE-SKIP", at("allowDangerouslySkipPermissions"));
	if (json["chat.tools.terminal.ignoreDefaultAutoApproveRules"] === true) add(ctx, "VS-NO-DEFAULT-RULES", at("ignoreDefaultAutoApproveRules"));
	// VS Code asks before an agent edits its own settings. Approving those
	// edits lets an agent turn on its own auto-approval.
	// The last pattern that matches a file decides, as in VS Code.
	const edits = json["chat.tools.edits.autoApprove"];
	const approves = (p) => Object.entries(edits).filter(([glob]) => globMatch(glob.replace(/^\.\//, ""), p)).pop()?.[1] === true;
	if (isObj(edits) && [".vscode/settings.json", ".vscode/mcp.json"].some(approves)) add(ctx, "VS-EDITS-AUTO", at("chat.tools.edits.autoApprove"));
	const terminal = json["chat.tools.terminal.autoApprove"] ?? json["github.copilot.chat.agent.terminal.allowList"];
	if (isObj(terminal)) {
		for (const [pattern, allowed] of Object.entries(terminal)) {
			const on = allowed === true || (isObj(allowed) && allowed.approve === true);
			if (on && (matchesEverything(pattern) || /\b(rm|curl|wget|sudo|bash|sh|pwsh|powershell|iex|python|node|npx|ssh|scp|git push)\b/i.test(pattern))) {
				const line = lineOf(f, JSON.stringify(pattern)) || lineOf(f, pattern);
				add(ctx, "VS-TERMINAL-AUTO", { file: f, line, evidence: evidenceLine(f, line), vars: { rule: pattern } });
			}
		}
	}
}

// A terminal rule written to match every command: *, .*, /.*/, /^.*$/ or /.+/.
function matchesEverything(pattern) {
	const body = pattern.startsWith("/") && pattern.lastIndexOf("/") > 0 ? pattern.slice(1, pattern.lastIndexOf("/")) : pattern;
	return ["", "*", ".*", ".+", "[\\s\\S]*", "[\\s\\S]+"].includes(trimWord(body, "^", "$"));
}

function checkOpenCode(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	for (const provider of isObj(json.provider) ? Object.values(json.provider).slice(0, 20) : []) {
		const url = provider?.options?.baseURL;
		if (typeof url === "string") checkEndpointSetting(ctx, f, "OpenCode's provider setting", "baseURL", url, lineOf(f, url.slice(0, 60)) || lineOf(f, /baseURL/));
	}
	if (json.share === "auto") {
		const line = lineOf(f, /"share"/);
		add(ctx, "OC-AUTO-SHARE", { file: f, line, evidence: evidenceLine(f, line) });
	}
	const bashAllows = (perm) => perm?.bash === "allow" || (isObj(perm?.bash) && perm.bash["*"] === "allow");
	if (bashAllows(json.permission)) {
		const line = lineOf(f, /"bash"/);
		add(ctx, "OC-BASH-ALLOW", { file: f, line, evidence: evidenceLine(f, line), vars: { where: "" } });
	}
	if (isObj(json.agent)) {
		for (const [name, agent] of Object.entries(json.agent)) {
			if (bashAllows(agent?.permission)) {
				add(ctx, "OC-BASH-ALLOW", { file: f, line: lineOf(f, `"${name}"`), vars: { where: ` for the “${name}” agent`, rule: name } });
			}
		}
	}
}

function checkZed(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	if (json.agent?.always_allow_tool_actions === true || json.assistant?.always_allow_tool_actions === true || json.agent?.tool_permissions?.default === "allow") {
		const line = lineOf(f, /always_allow_tool_actions|"default"\s*:\s*"allow"/);
		add(ctx, "ZED-ALWAYS-ALLOW", { file: f, line, evidence: evidenceLine(f, line) });
	}
	if (json.session?.trust_all_worktrees === true) {
		const line = lineOf(f, /trust_all_worktrees/);
		add(ctx, "ZED-TRUST-ALL", { file: f, line, evidence: evidenceLine(f, line) });
	}
}

// --- Trusted folders, hooks and settings of other agents ---------------------

// Gemini CLI: { "/path": "TRUST_FOLDER" | "TRUST_PARENT" | "DO_NOT_TRUST" }.
function geminiTrusted(json) {
	if (!isObj(json)) return [];
	const parent = (d) => trimWord(d, "", "/\\").replace(/[\\/][^\\/]*$/, "") || "/";
	return Object.entries(json).flatMap(([dir, level]) => (level === "TRUST_FOLDER" ? [[dir, dir]] : level === "TRUST_PARENT" ? [[parent(dir), dir]] : []));
}

// GitHub Copilot CLI: a list of trusted folders in ~/.copilot/config.json.
function copilotTrusted(json) {
	return arr(json?.trusted_folders ?? json?.trustedFolders).map((dir) => [dir, dir]);
}

// Folders the settings on this computer say agents have been started in or
// trust. The command also checks the loose files in the risky ones.
export function agentFolders(path, content) {
	const json = /\.toml$/i.test(path) ? parseTOML(content) : parseJSONC(content);
	if (!isObj(json)) return [];
	if (/(^|\/)\.claude\.json$/i.test(path)) return isObj(json.projects) ? Object.keys(json.projects) : [];
	if (/(^|\/)\.codex\/config\.toml$/i.test(path)) return isObj(json.projects) ? Object.entries(json.projects).filter(([, s]) => s?.trust_level === "trusted").map(([d]) => d) : [];
	if (/(^|\/)\.gemini\/trustedFolders\.json$/i.test(path)) return geminiTrusted(json).map(([d]) => d);
	if (/(^|\/)\.copilot\/config\.json$/i.test(path)) return copilotTrusted(json).map(([d]) => d);
	return [];
}

// [folder trusted, folder as written in the file] pairs.
function checkTrustedFolders(ctx, f, tool, trusted) {
	for (const [dir, written] of trusted) {
		const place = riskyPlace(dir);
		if (place) add(ctx, "WS-TRUSTED-DIR", { file: f, line: keyLine(f, written), tool, vars: { tool, place: place.name, risk: place.risk, dir } });
	}
}

// Every command in a hooks file, such as .github/hooks/*.json or Cursor's
// hooks.json, or in `value` when hooks sit inside other settings. Hooks name
// their command "command", "bash" or "powershell".
function checkJsonHooks(ctx, f, where, value = parsed(f)) {
	const visit = (v, key, depth) => {
		if (depth > 8) return;
		if (typeof v === "string" && ["command", "bash", "powershell"].includes(key)) checkCommand(ctx, v, f, where);
		else if (Array.isArray(v)) {
			// A command written as a list of arguments.
			if (key === "command" && v.length && v.every((x) => typeof x === "string")) checkCommand(ctx, v.join(" "), f, where);
			else for (const x of v) visit(x, key, depth + 1);
		} else if (isObj(v)) for (const [k, x] of Object.entries(v)) visit(x, k, depth + 1);
	};
	visit(value, "", 0);
}

// Cursor's cloud agents run install on every build, start on every boot and
// each terminal's command, in a virtual machine with the repo's secrets.
function checkCursorEnvironment(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	const where = "Cursor's cloud agent setup";
	for (const key of ["install", "start"]) for (const command of commandsIn(json[key])) checkCommand(ctx, command, f, where);
	for (const t of Array.isArray(json.terminals) ? json.terminals.slice(0, 20) : []) for (const command of commandsIn(t?.command)) checkCommand(ctx, command, f, where);
}

// Codex rules that let a command run outside the sandbox without asking:
// prefix_rule(pattern = ["git", "push"], decision = "allow"). Only programs
// that run other code, change or delete files broadly, or reach the network
// are reported.
const RISKY_PROGRAM = /^(?:sudo|su|doas|rm|dd|chmod|chown|bash|sh|zsh|fish|dash|pwsh|powershell|cmd|python3?|node|deno|bun|npx|npm|pnpm|yarn|perl|ruby|php|eval|exec|env|xargs|find|docker|kubectl|curl|wget|ssh|scp|sftp|rsync|nc|ncat|netcat|ftp|telnet|git)$/i;
// The words a rule's pattern matches at one place: a word, or a list of
// alternatives. A program is matched by its name, so /bin/bash and bash.exe
// count as bash.
const ruleWords = (pattern, i) => (Array.isArray(pattern[i]) ? pattern[i] : [pattern[i]]).filter((w) => typeof w === "string").map((w) => w.trim());
// True when rule a matches every command rule b matches: a is no longer than
// b, and at each place a allows every word b does.
const ruleCovers = (a, b) => a.length <= b.length && a.every((_, i) => ruleWords(b, i).every((w) => ruleWords(a, i).includes(w)));
// git is only risky when every git command is allowed, or one that pushes,
// changes settings or brings in code from elsewhere.
const RISKY_GIT = /^(?:push|config|submodule|clone|fetch|pull|remote|-c|filter-branch|filter-repo)$/i;

function checkCodexRules(ctx, f) {
	const all = parseCodexRules(f.content);
	// A rule that may allow something, built in a way this check can't follow.
	const hidden = all.find((r) => r.unread && r.decision !== "prompt" && r.decision !== "forbidden");
	if (hidden) {
		const line = lineAt(f.content, hidden.index);
		add(ctx, "CX-RULES-UNREAD", { file: f, line, evidence: evidenceLine(f, line) });
	}
	const rules = all.filter((r) => !r.unread && r.pattern?.length && r.pattern.every((w) => w !== null && (!Array.isArray(w) || w.length)));
	const allowing = [];
	for (const rule of rules) {
		if (rule.decision !== "allow") continue;
		// When rules overlap, Codex applies the strictest one.
		if (rules.some((r) => (r.decision === "prompt" || r.decision === "forbidden") && ruleCovers(r.pattern, rule.pattern))) continue;
		const program = ruleWords(rule.pattern, 0).map(programName).find((p) => RISKY_PROGRAM.test(p) && (!/^git$/i.test(p) || rule.pattern.length === 1 || ruleWords(rule.pattern, 1).some((w) => RISKY_GIT.test(w))));
		if (!program) continue;
		// The command as the rule allows it, naming the risky choice where it
		// gives several, as in git push.
		const pick = (i) => (i === 1 && /^git$/i.test(program) ? ruleWords(rule.pattern, 1).find((w) => RISKY_GIT.test(w)) : null) ?? ruleWords(rule.pattern, i)[0] ?? "";
		allowing.push({ line: lineAt(f.content, rule.index), start: [program, pick(1)].filter(Boolean).join(" ") });
	}
	// One finding for the file: a Codex user can have dozens of these rules,
	// one for each command they approved. The patterns are named by program
	// and first word, such as powershell -Command; --explain lists each rule.
	if (allowing.length) {
		const starts = [...new Set(allowing.map((a) => clip(a.start, 40)))];
		const { line } = allowing[0];
		add(ctx, "CX-RULE-ALLOW", {
			file: f,
			line,
			evidence: evidenceLine(f, line),
			vars: { commands: allowing.length === 1 ? "a command" : `${allowing.length} commands`, list: listNames(starts, 4) },
		});
	}
}

// Kiro and Amazon Q agent files: hooks, and tools the agent uses without
// asking. Kiro's shell tool is "shell", also known by its Amazon Q names.
// allowedTools entries can use * and ? as wildcards. Commands allowed in
// toolsSettings are regular expressions that must match the whole command,
// and the newer permissions rules match commands by prefix.
const SHELL_TOOLS = ["shell", "execute_bash", "execute_cmd"];
function wildcardMatch(glob, text) {
	let g = 0;
	let t = 0;
	let star = -1;
	let mark = 0;
	while (t < text.length) {
		if (g < glob.length && (glob[g] === "?" || glob[g] === text[t])) {
			g++;
			t++;
		} else if (g < glob.length && glob[g] === "*") {
			star = g++;
			mark = t;
		} else if (star >= 0) {
			g = star + 1;
			t = ++mark;
		} else return false;
	}
	while (glob[g] === "*") g++;
	return g === glob.length;
}
// A command pattern that lets through any command, or any use of a program
// that can run anything: ".*", "curl .*", "bash*".
const MATCH_ALL = /^\^?(?:\.\*|\.\+|\(\.\*\)|\[\\s\\S\]\*)\??\$?$/;
function openCommand(pattern, regex) {
	const text = pattern.trim();
	if (!text || text === "*" || text === "**" || (regex && MATCH_ALL.test(text))) return true;
	const word = programName(/^\^?([^\s*.\\(]+)/.exec(text)?.[1] ?? "");
	const rest = text.slice(text.indexOf(word) + word.length);
	const open = regex ? /^(?:\s|\\s|\[ \])*(?:\.\*|\.\+|\(\.\*\))/.test(rest) || rest === "" : /^\s*\*/.test(rest) || rest.trim() === "";
	return RISKY_PROGRAM.test(word) && open;
}
function checkAgentFile(ctx, f, where) {
	checkJsonHooks(ctx, f, where);
	const json = parsed(f);
	if (!isObj(json)) return;
	const found = [];
	for (const tool of arr(json.allowedTools).slice(0, 200)) {
		const t = tool.trim();
		if (t === "*" || t === "@builtin" || SHELL_TOOLS.some((name) => wildcardMatch(t, name) || wildcardMatch(t, `@builtin/${name}`))) found.push({ rule: t, setting: "allowedTools" });
	}
	for (const name of SHELL_TOOLS) {
		const pattern = arr(json.toolsSettings?.[name]?.allowedCommands).slice(0, 200).find((c) => openCommand(c, true));
		if (pattern !== undefined) found.push({ rule: pattern.trim(), setting: "toolsSettings" });
	}
	for (const rule of Array.isArray(json.permissions?.rules) ? json.permissions.rules.slice(0, 200) : []) {
		if (!isObj(rule) || rule.capability !== "shell" || rule.effect !== "allow") continue;
		// A rule with no commands to match matches every one.
		const match = arr(rule.match);
		const open = match.length === 0 ? "*" : match.find((m) => openCommand(m, false));
		if (open !== undefined) found.push({ rule: open.trim(), setting: "permissions" });
	}
	if (!found.length) return;
	const line = lineOf(f, new RegExp(`"${found[0].setting}"`));
	add(ctx, "AGENT-ALLOW-SHELL", { file: f, line, evidence: evidenceLine(f, line), vars: found[0] });
}

function checkCursorCli(ctx, f) {
	const json = parsed(f);
	for (const rule of arr(json?.permissions?.allow)) {
		if (/^Shell(\((\*|\*\*|\*:\*)?\))?$/i.test(rule.trim())) {
			const line = lineOf(f, rule);
			add(ctx, "CU-ALLOW-ALL-SHELL", { file: f, line, evidence: evidenceLine(f, line), vars: { rule } });
		}
	}
}

function checkCursorSandbox(ctx, f) {
	if (parsed(f)?.type === "insecure_none") {
		const line = lineOf(f, /insecure_none/);
		add(ctx, "CU-NO-SANDBOX", { file: f, line, evidence: evidenceLine(f, line) });
	}
}

// Cline keeps its approval settings in ~/.cline/data/globalState.json.
function checkCline(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	if (json.yoloModeToggled === true) {
		const line = lineOf(f, /yoloModeToggled/);
		add(ctx, "CL-YOLO", { file: f, line, evidence: evidenceLine(f, line) });
	} else if (json.autoApprovalSettings?.enabled !== false && json.autoApprovalSettings?.actions?.executeAllCommands === true) {
		const line = lineOf(f, /executeAllCommands/);
		add(ctx, "CL-AUTO-COMMANDS", { file: f, line, evidence: evidenceLine(f, line) });
	}
}

function checkGrok(ctx, f) {
	const toml = parsed(f);
	for (const command of commandsIn(toml?.ui?.status_line?.command)) checkCommand(ctx, command, f, "Grok's status line command");
	const mode = toml?.ui?.permission_mode ?? toml?.permission_mode;
	if (mode === "always-approve" || mode === "yolo") {
		const line = lineOf(f, /permission_mode/);
		add(ctx, "GROK-ALWAYS-APPROVE", { file: f, line, evidence: evidenceLine(f, line), vars: { mode } });
	}
}

function checkAmp(ctx, f) {
	if (parsed(f)?.["amp.dangerouslyAllowAll"] === true) {
		const line = lineOf(f, /dangerouslyAllowAll/);
		add(ctx, "AMP-ALLOW-ALL", { file: f, line, evidence: evidenceLine(f, line) });
	}
}

// YAML, read line by line: GOOSE_MODE sits at the top level.
function checkGoose(ctx, f) {
	const line = lineOf(f, /^GOOSE_MODE\s*:\s*["']?auto["']?\s*(#.*)?$/);
	if (line) add(ctx, "GOOSE-AUTO", { file: f, line, evidence: evidenceLine(f, line) });
}

// Continue's data destinations send session events to a URL.
function checkContinue(ctx, f) {
	for (const [i, text] of f.lines.entries()) {
		const api = text.match(/^\s*(?:-\s*)?["']?apiBase["']?\s*:\s*["']?([^\s"',#]+)/);
		if (api) checkEndpointSetting(ctx, f, "Continue's model settings", "apiBase", api[1], i + 1);
		const m = text.match(/^\s*(?:-\s*)?destination\s*:\s*["']?(https?:\/\/[^\s"'#]+)/i);
		if (!m) continue;
		let host;
		try {
			host = new URL(m[1]).hostname;
		} catch {
			continue;
		}
		if (!isLocalHost(host)) add(ctx, "CONT-DATA", { file: f, line: i + 1, evidence: text, vars: { host } });
	}
}

// YAML, read line by line. lint-cmd runs after every change Aider makes
// (auto-lint is on by default), test-cmd after changes when auto-test is on,
// and the notification command when Aider is waiting.
const AIDER_COMMANDS = { "lint-cmd": "Aider's lint command", "test-cmd": "Aider's test command", "notifications-command": "Aider's notification command" };
const unquote = (v) => v.trim().replace(/^(["'])(.*)\1$/, "$2");
function checkAider(ctx, f) {
	const yaml = parsed(f);
	if (!isObj(yaml)) return checkAiderLines(ctx, f);
	// The line a key is on, for keys written plain or quoted.
	const keyAt = (key) => lineOf(f, new RegExp(`^[ \\t]*(?:-[ \\t]+)?["']?${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?[ \\t]*:`, "m")) || lineOf(f, key);
	const valueAt = (key, value) => (typeof value === "string" && value.trim() && lineOf(f, value.trim().split("\n")[0].slice(0, 60))) || keyAt(key);
	if (yaml["yes-always"] === true) {
		const line = keyAt("yes-always");
		add(ctx, "AIDER-YES", { file: f, line, evidence: evidenceLine(f, line) });
	}
	for (const key of [...Object.keys(AIDER_COMMANDS), "set-env", "openai-api-base"]) {
		const raw = yaml[key];
		// One value, a list of them, or "- python: flake8" items read as mappings.
		const values = (Array.isArray(raw) ? raw : [raw]).flatMap((v) => (isObj(v) ? Object.entries(v).map(([k, x]) => (key === "lint-cmd" ? `${k}: ${x}` : `${k}=${x}`)) : typeof v === "string" || typeof v === "number" ? [String(v)] : [])).slice(0, 50);
		for (const value of values) aiderValue(ctx, f, key, value, valueAt(key, value));
	}
}
// Aider's settings read line by line, for a file the YAML reader can't read.
function checkAiderLines(ctx, f) {
	const line = lineOf(f, /^\s*yes-always\s*:\s*true\b/i);
	if (line) add(ctx, "AIDER-YES", { file: f, line, evidence: evidenceLine(f, line) });
	let key = null;
	for (const [i, text] of f.lines.entries()) {
		const top = /^([A-Za-z][\w-]*)\s*:\s*(.*)$/.exec(text);
		if (top) {
			key = top[1].toLowerCase();
			const value = unquote(top[2].replace(/\s+#.*$/, ""));
			if (value) aiderValue(ctx, f, key, value, i + 1);
			continue;
		}
		// A list under the key: lint-cmd as "- python: flake8 --select", set-env as "- NAME=value".
		const item = /^\s+-\s+(.*)$/.exec(text);
		if (item && key) aiderValue(ctx, f, key, unquote(item[1]), i + 1);
	}
}
function aiderValue(ctx, f, key, value, line) {
	if (key === "openai-api-base") checkEndpointSetting(ctx, f, "Aider's openai-api-base setting", "openai-api-base", value, line);
	if (Object.hasOwn(AIDER_COMMANDS, key)) {
		const command = key === "lint-cmd" ? value.replace(/^[\w+#.-]{1,30}:\s+/, "") : value;
		if (command && !command.startsWith("[")) checkCommand(ctx, command, f, AIDER_COMMANDS[key], { line });
	} else if (key === "set-env") {
		const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(value);
		const variable = m && codeLoadingVariable(m[1], unquote(m[2]));
		if (variable) add(ctx, "ENV-CODE-LOAD", { file: f, line, evidence: evidenceLine(f, line), vars: { where: "Aider's set-env setting", variable } });
		if (m) checkEnvironment(ctx, f, "Aider's set-env setting", m[1], unquote(m[2]), line);
	}
}

function checkPackageJson(ctx, f) {
	const json = parsed(f);
	if (!isObj(json?.scripts)) return;
	for (const [name, script] of Object.entries(json.scripts)) {
		const hit = typeof script === "string" && findDangerFlag(script);
		if (hit) {
			const line = lineOf(f, `"${name}"`);
			add(ctx, "FLAG-SCRIPT", { file: f, line, evidence: evidenceLine(f, line), tool: hit.agent, vars: { flag: hit.flag, rule: name, where: `The “${name}” script in package.json` } });
		}
	}
}

// --- Commands run by hooks ---------------------------------------------------

function checkCommand(ctx, command, f, where, { autorun = true, line: near = 0 } = {}) {
	const line = lineOf(f, command.split("\n")[0].slice(0, 60)) || near || lineOf(f, /"command"/);
	const cmd = clip(command, 140);
	const vars = { where, cmd };
	const remote = RX_REMOTE_EXEC.test(command);
	const sends = !remote && sendsData(command);
	if (remote) add(ctx, "HOOK-REMOTE-EXEC", { file: f, line, evidence: command, vars });
	else if (sends) add(ctx, "HOOK-NETWORK", { file: f, line, evidence: command, vars });
	const destructive = isDestructive(command);
	if (destructive) add(ctx, "HOOK-DESTRUCTIVE", { file: f, line, evidence: command, vars });
	const outside = runsOutsideScript(command);
	if (outside) add(ctx, "HOOK-OUTSIDE", { file: f, line, evidence: command, vars });
	const hit = findDangerFlag(command);
	if (hit) add(ctx, "FLAG-SCRIPT", { file: f, line, evidence: command, tool: hit.agent, vars: { flag: hit.flag, where } });
	// Anything else a project's settings run on their own is still the
	// project's code running on this computer, reported once per file.
	if (autorun && !remote && !sends && !destructive && !outside && !hit && inProject(ctx, f) && !harmlessCommand(command)) {
		if (!ctx.autorun.has(f)) ctx.autorun.set(f, { line, evidence: command, vars });
	}
}

// Commands that only print, wait or make a sound, such as a notification.
const HARMLESS_PROGRAMS = new Set(["echo", "printf", "true", "false", ":", "date", "pwd", "exit", "sleep", "notify-send", "terminal-notifier", "say", "afplay", "paplay", "aplay", "tput", "clear"]);
function harmlessCommand(command) {
	if (/\$\(|`|<\(|>\(/.test(command)) return false;
	const segments = commandSegments(shellWords(command));
	return (
		segments.length > 0 &&
		segments.every((segment) => {
			let i = 0;
			while (i < segment.length - 1 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(segment[i])) i++;
			return HARMLESS_PROGRAMS.has(segment[i].split(/[\\/]/).pop().toLowerCase()) && !segment.slice(i + 1).some((w) => /^[<>]|^\d?>/.test(w));
		})
	);
}

// A settings file that has the agent read instructions from outside the
// project, or from a web page.
function checkNamed(ctx) {
	for (const n of ctx.named) {
		const f = ctx.files.find((x) => x.path === n.from);
		if (!f || (!n.outside && !n.web)) continue;
		const line = lineOf(f, n.name.slice(0, 60));
		if (n.web) {
			let host = "";
			try {
				host = new URL(n.name).hostname;
			} catch {}
			if (host) add(ctx, "TXT-REMOTE-INSTRUCTIONS", { file: f, line, evidence: evidenceLine(f, line), vars: { host } });
		} else add(ctx, "TXT-IMPORT-OUTSIDE", { file: f, line, evidence: evidenceLine(f, line), vars: { ref: clip(n.name, 80) } });
	}
}

function checkAutorun(ctx) {
	for (const [f, found] of ctx.autorun) add(ctx, "PROJECT-AUTORUN", { file: f, ...found });
}

// VS Code tasks, which every editor built on VS Code runs. A task with
// runOn: folderOpen runs when the folder opens: in Cursor without asking,
// since Workspace Trust is off there by default.
function checkVsCodeTasks(ctx, f) {
	const json = parsed(f);
	const tasks = Array.isArray(json?.tasks) ? json.tasks.slice(0, 200) : [];
	for (const task of tasks) {
		if (!isObj(task) || task.runOptions?.runOn !== "folderOpen") continue;
		const commands = [task, task.windows, task.osx, task.linux]
			.filter(isObj)
			.map((t) => [t.command, ...(Array.isArray(t.args) ? t.args : [])].filter((w) => typeof w === "string" || (isObj(w) && typeof w.value === "string")).map((w) => (typeof w === "string" ? w : w.value)).join(" ").trim())
			.filter(Boolean);
		const label = typeof task.label === "string" ? task.label : "";
		// The "folderOpen" line nearest the task's label, so the evidence is the
		// setting itself.
		const labelLine = label ? lineOf(f, `"${label.slice(0, 60)}"`) : 0;
		const opens = (f.lines ?? []).flatMap((l, i) => (/"folderOpen"/.test(l) ? [i + 1] : []));
		const line = opens.length ? opens.reduce((a, b) => (labelLine && Math.abs(b - labelLine) < Math.abs(a - labelLine) ? b : a)) : labelLine || lineOf(f, /folderOpen/);
		const command = commands[0] ?? label;
		add(ctx, "TASK-FOLDER-OPEN", { file: f, line, evidence: evidenceLine(f, line), vars: { cmd: clip(command || "a task", 140) } });
		for (const c of new Set(commands)) checkCommand(ctx, c, f, "A task that runs when the folder opens", { autorun: false });
	}
}

function checkHookScript(ctx, f) {
	const where = "This hook script";
	for (const [i, line] of f.lines.entries()) {
		if (!line.trim() || /^\s*(#|\/\/|REM\b)/i.test(line)) continue;
		const vars = { where, cmd: clip(line, 140) };
		const opts = { file: f, line: i + 1, evidence: line, vars };
		if (RX_REMOTE_EXEC.test(line)) add(ctx, "HOOK-REMOTE-EXEC", opts);
		else if (sendsData(line)) add(ctx, "HOOK-NETWORK", opts);
		if (isDestructive(line)) add(ctx, "HOOK-DESTRUCTIVE", opts);
		const hit = findDangerFlag(line);
		if (hit) add(ctx, "FLAG-SCRIPT", { ...opts, tool: hit.agent, vars: { flag: hit.flag, where } });
	}
}

// --- Instruction files -------------------------------------------------------

function checkInstructionText(ctx, f) {
	const text = f.content;
	const at = (index) => {
		const line = lineAt(text, index);
		return { file: f, line, evidence: evidenceLine(f, line) };
	};

	const tags = hiddenTags(text);
	if (tags.length) {
		const decoded = tags.map((t) => t.decoded).join("");
		const count = tags.reduce((n, t) => n + t.length, 0);
		add(ctx, "TXT-TAGS", { ...at(tags[0].index), evidence: null, vars: { count, decoded: clip(maskSecrets(decoded).text, 140) } });
	}
	const bidi = text.search(/[\u202a-\u202e\u2066-\u2069]/);
	if (bidi >= 0) add(ctx, "TXT-BIDI", { ...at(bidi), evidence: null });
	const zeroWidth = hiddenZeroWidth(text);
	if (zeroWidth.length >= 3) add(ctx, "TXT-ZERO-WIDTH", { ...at(zeroWidth[0]), evidence: null, vars: { count: zeroWidth.length } });

	for (const c of hiddenComments(text)) {
		const inner = c.inner.trim();
		if (inner && !RX_BENIGN_COMMENT.test(inner) && RX_INJECT_WORDS.test(inner)) {
			add(ctx, "TXT-HIDDEN-COMMENT", { ...at(c.index), evidence: inner });
			break;
		}
	}

	// Rules marked `affirmative` ignore lines that warn against the thing,
	// such as "Never read .env files" or "Do not disable the sandbox".
	const textRule = (id, re, varsFrom, { affirmative = false, reject } = {}) => {
		const m = firstMatch(text, re, affirmative, reject);
		if (m) add(ctx, id, { ...at(m.index + (m[0].length - m[0].trimStart().length)), vars: varsFrom ? varsFrom(m) : {} });
	};
	textRule("TXT-REMOTE-EXEC", RX_REMOTE_EXEC, null, { affirmative: true });
	textRule("TXT-EXFIL", RX_EXFIL_HOST, (m) => ({ host: m[1] }));
	textRule("TXT-PASTE-SITE", RX_PASTE_SITE, (m) => ({ host: m[1].toLowerCase() }), { affirmative: true });
	// A paste site already has its own finding.
	textRule("TXT-REMOTE-INSTRUCTIONS", RX_REMOTE_INSTRUCTIONS, (m) => ({ host: (m[1] ?? m[2]).toLowerCase() }), { affirmative: true, reject: (m) => RX_PASTE_SITE.test(` ${m[1] ?? m[2]}`) });
	textRule("TXT-ARCHIVE-PASSWORD", RX_ARCHIVE_PASSWORD, null, { affirmative: true, reject: (m) => !givesArchivePassword(text, m) });
	textRule("TXT-QUARANTINE", RX_QUARANTINE, null, { affirmative: true });
	// Defensive instructions quote injections as examples, as in: if a page
	// says "ignore previous instructions", don't follow it.
	let fence = null;
	textRule("TXT-OVERRIDE", RX_OVERRIDE, (m) => ({ phrase: clip(m[0], 80) }), {
		affirmative: true,
		reject: (m) => quotedExample(text, m, "\"'“‘`") || fencedExample(text, m.index, (fence ??= fenceAt(text))),
	});
	// Setting up a project ("copy .env.example to .env", "add .env to
	// .gitignore") isn't handing secrets to the agent.
	textRule("TXT-SECRET-ACCESS", RX_SECRET_ACCESS, (m) => ({ phrase: clip(m[0], 80) }), {
		affirmative: true,
		reject: (m) =>
			quotedExample(text, m, "\"'“‘") ||
			/\.env\.(?:example|sample|template|dist|defaults)\b|gitignore/i.test(text.slice(m.index, m.index + m[0].length + 40)) ||
			// "Settings are read from .env" says what a program does, not what the agent should.
			/\b(?:is|are|be|been|being|was|were|gets?|got)\s+(?:\w+ly\s+)?$/i.test(text.slice(Math.max(text.lastIndexOf("\n", m.index - 1) + 1, m.index - 40), m.index)),
	});
	const blob = longBase64(text);
	if (blob) add(ctx, "TXT-BLOB", { ...at(blob.index), vars: { length: blob.length.toLocaleString("en-US") } });
	// Only files that import can pull a file in, and never from inside code.
	if (CAN_IMPORT.test(f.path)) {
		textRule("TXT-IMPORT-OUTSIDE", RX_IMPORT_OUTSIDE, (m) => ({ ref: "@" + clip(m[1], 80) }), {
			reject: (m) => (fence ??= fenceAt(text))(m.index) !== null || inCodeSpan(text, m.index),
		});
	}
	const flag = findDangerFlag(text, (index) => negated(text, index));
	if (flag) add(ctx, "FLAG-DOCS", { ...at(flag.index), tool: flag.agent, vars: { flag: flag.flag } });

	// A file read only in part is reported as that instead.
	if (text.length > 60_000 && !f.loose && !f.partial) add(ctx, "TXT-HUGE", { file: f, vars: { size: `${Math.round(text.length / 1024)} KB` } });
}

// --- MCP servers -------------------------------------------------------------

// The MCP servers a file defines, wherever its agent keeps them.
function collectMcpServers(ctx, f) {
	const p = f.path;
	let groups = [];
	if (/(^|\/)(\.codex\/([^/]+\.)?config|\.grok\/config)\.toml$/i.test(p)) groups = [parsed(f)?.mcp_servers];
	// Continue lists servers with a name each; Goose calls them extensions.
	else if (/(^|\/)\.continue\/(config|mcpServers\/[^/]+)\.ya?ml$/i.test(p)) {
		const list = parsed(f)?.mcpServers;
		groups = [Array.isArray(list) ? Object.fromEntries(list.slice(0, 200).filter(isObj).map((x, n) => [typeof x.name === "string" ? x.name : `server ${n + 1}`, x])) : null];
	} else if (/(^|\/)goose\/config\.ya?ml$/i.test(p)) groups = [parsed(f)?.extensions];
	else if (/\.jsonc?$/i.test(p)) {
		const json = parsed(f);
		if (!isObj(json)) return;
		if (/(^|\/)(\.vscode|\.github)\/mcp\.json$/i.test(p)) groups = [json.servers, json.mcpServers];
		else if (/(^|\/)(\.amp|\.config\/amp)\/settings\.json$/i.test(p)) groups = [json["amp.mcpServers"]];
		else if (/(^|\/)opencode\.jsonc?$/i.test(p)) groups = [json.mcp];
		else if (/(^|\/)(\.zed|zed|Zed)\/settings\.json$/i.test(p)) groups = [json.context_servers];
		else if (/\/User\/mcp\.json$/i.test(p)) groups = [json.servers, json.mcpServers];
		else if (/\/User\/settings\.json$/i.test(p)) groups = [json.mcp?.servers];
		else if (/(^|\/)\.claude\.json$/i.test(p)) groups = [json.mcpServers, ...(isObj(json.projects) ? Object.values(json.projects).map((x) => x?.mcpServers) : [])];
		else if (/(^|\/)\.vscode\/settings\.json$/i.test(p)) groups = [json.mcp?.servers];
		else if (f.role === "mcp-servers") groups = [json.mcpServers ?? json];
		else groups = [json.mcpServers];
	}
	for (const group of groups) {
		if (!isObj(group)) continue;
		for (const [name, def] of Object.entries(group)) ctx.mcpServers.push(normalizeServer(name, def, f));
	}
}

function normalizeServer(name, def, file) {
	const d = isObj(def) ? def : {};
	let command = d.command ?? d.cmd;
	let args = scalars(d.args);
	if (Array.isArray(command)) {
		args = [...scalars(command.slice(1)), ...args];
		command = command[0];
	} else if (isObj(command)) {
		args = Array.isArray(command.args) ? scalars(command.args) : args;
		command = command.path ?? command.command;
	}
	const url = [d.url, d.serverUrl, d.httpUrl].find((u) => typeof u === "string") ?? null;
	return {
		name,
		file,
		command: typeof command === "string" ? command : null,
		args,
		env: isObj(d.env) ? d.env : isObj(d.environment) ? d.environment : isObj(d.envs) ? d.envs : {},
		headers: isObj(d.headers) ? d.headers : isObj(d.http_headers) ? d.http_headers : {},
		extra: d,
		url,
		alwaysAllow: d.alwaysAllow ?? d.autoApprove ?? d.auto_approve ?? (d.trust === true ? true : undefined),
		alwaysAllowKey: ALWAYS_ALLOW_KEYS.find((k) => d[k] !== undefined) ?? null,
		disabled: d.disabled === true || d.enabled === false,
	};
}

const REFERENCE = /^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^\{env:[^}]+\}$|^%[A-Za-z_][A-Za-z0-9_]*%$|\$\{(?:env|input):/i;

// References such as ${GITHUB_TOKEN}, {env:KEY} or %API_KEY%, anywhere in a value.
const REFERENCES = /\$\{[^}]{0,200}\}|\{env:[^}]{0,200}\}|%[A-Za-z_][A-Za-z0-9_]{0,100}%|\$[A-Za-z_][A-Za-z0-9_]*/g;

function isSecretValue(key, value) {
	if (typeof value !== "string" || REFERENCE.test(value.trim()) || isPathLike(value)) return false;
	if (isMasked(value)) return true;
	// What's left once references and an auth scheme are taken out, so
	// "Bearer ${GITHUB_TOKEN}" counts as a reference too.
	const rest = value.replace(REFERENCES, "").replace(/^\s*(?:Bearer|Basic|Token|Bot)\b\s*/i, "").trim();
	if (rest.length < 8 || /^(true|false|\d+|https?:\/\/[^@]*)$/i.test(rest)) return false;
	if (/(token|secret|key|password|passwd|auth|credential|bearer|cookie|session)/i.test(key)) return looksLikeSecret(rest) || (rest.length >= 20 && !/\s/.test(rest));
	return looksLikeToken(rest) && rest.length >= 24;
}

function redact(value) {
	return isMasked(value) ? value : `•••• (${value.length} chars)`;
}

function checkMcpServer(ctx, s) {
	const f = s.file;
	const tool = f.tools[0] ?? null;
	const nameLine = lineOf(f, `"${s.name}"`) || lineOf(f, s.name);
	const base = (line = nameLine) => ({ file: f, line, tool, evidence: evidenceLine(f, line) });
	const near = (test) => lineAfter(f, test, nameLine);

	for (const [key, value] of [...Object.entries(s.env), ...Object.entries(s.headers)]) {
		if (isSecretValue(key, value)) {
			const line = near(`"${key}"`) || near(key) || nameLine;
			add(ctx, "MCP-SECRET", { ...base(line), evidence: `${key} = ${redact(value)}`, vars: { server: s.name, key } });
		}
	}
	for (const [key, value] of Object.entries(s.env)) {
		const variable = codeLoadingVariable(key, value);
		if (variable) add(ctx, "MCP-ENV-CODE-LOAD", { ...base(near(`"${key}"`) || near(key) || nameLine), vars: { server: s.name, variable } });
		if (tlsOff(key, value)) add(ctx, "ENV-TLS-OFF", { ...base(near(`"${key}"`) || near(key) || nameLine), vars: { where: "An MCP server's env setting", variable: "NODE_TLS_REJECT_UNAUTHORIZED" } });
	}
	for (const key of ["bearer_token", "bearerToken", "apiKey", "api_key", "token"]) {
		const value = s.extra[key];
		if (typeof value === "string" && isSecretValue(key, value)) {
			add(ctx, "MCP-SECRET", { ...base(near(key) || nameLine), evidence: `${key} = ${redact(value)}`, vars: { server: s.name, key } });
		}
	}
	const secretArg = s.args.find((a) => isMasked(a) || (looksLikeToken(a) && a.length >= 24 && !a.includes("/")));
	if (secretArg) add(ctx, "MCP-SECRET", { ...base(near(secretArg.slice(0, 20)) || nameLine), evidence: `args contain ${redact(secretArg)}`, vars: { server: s.name, key: "args" } });

	if (s.url) {
		let u = null;
		try {
			u = new URL(s.url);
		} catch {}
		if (u) {
			if (u.protocol === "http:" && !isLocalHost(u.hostname)) add(ctx, "MCP-HTTP", { ...base(near(s.url) || nameLine), vars: { server: s.name, host: u.hostname } });
			if ([...u.searchParams.keys()].some((k) => /token|key|secret|auth|sig|password/i.test(k)) || u.password || isMasked(s.url)) {
				add(ctx, "MCP-URL-TOKEN", { ...base(near(u.hostname) || nameLine), vars: { server: s.name } });
			}
		}
	}

	const pkg = packageSpec(s.command, s.args);
	const flagged = checkMcpPackage(ctx, s, base, near);
	if (pkg && !pkg.pinned && !flagged) {
		add(ctx, "MCP-UNPINNED", {
			...base(near(pkg.spec) || nameLine),
			vars: { server: s.name, command: clip([s.command, ...s.args].join(" "), 90), pkg: pkg.name, lookup: pkg.python ? `pip index versions ${pkg.name}` : `npm view ${pkg.name} version` },
		});
	}

	if (/(^|[\\/])(docker|podman)(\.exe)?$/i.test(s.command ?? "")) {
		const risk = dockerRisk(s.args);
		if (risk) add(ctx, "MCP-DOCKER", { ...base(near(risk.arg) || nameLine), vars: { server: s.name, flag: risk.flag } });
	}

	// What the command runs, whatever launches it: a download piped into a
	// shell, or, in a project's own settings, a file from the project.
	if (typeof s.command === "string" && s.command) {
		const line = [s.command, ...s.args].join(" ");
		if (RX_REMOTE_EXEC.test(line)) add(ctx, "HOOK-REMOTE-EXEC", { ...base(near(s.command) || nameLine), evidence: line, vars: { where: "An MCP server's command", cmd: clip(line, 140) } });
		else if (!pkg && inProject(ctx, f)) {
			const local = localCode(s.command, s.args);
			if (local) add(ctx, "MCP-LOCAL-CODE", { ...base(near(local.slice(0, 60)) || nameLine), vars: { server: s.name, path: clip(local, 120) } });
		}
	}

	const broad = s.args.find((a) => isBroadPath(a));
	if (broad && !/(^|[\\/])(docker|podman)(\.exe)?$/i.test(s.command ?? "")) {
		add(ctx, "MCP-FS-BROAD", { ...base(near(`"${broad}"`) || nameLine), vars: { server: s.name, path: broad } });
	}

	if (SHELL_SERVER.test(s.name) || (pkg && SHELL_SERVER.test(pkg.name))) add(ctx, "MCP-SHELL", { ...base(), vars: { server: s.name } });

	if (s.alwaysAllow === true || (Array.isArray(s.alwaysAllow) && s.alwaysAllow.length)) {
		const count = s.alwaysAllow === true ? "every tool" : `${s.alwaysAllow.length} tool${s.alwaysAllow.length === 1 ? "" : "s"}`;
		add(ctx, "MCP-ALWAYS-ALLOW", { ...base(near(s.alwaysAllowKey) || nameLine), vars: { server: s.name, setting: s.alwaysAllowKey, count } });
	}
}

// The project file an MCP server's command runs, or the code a shell is given
// inline: ./server.js, node tools/server.js, python3 -m pkg isn't one.
const RUNS_FILES = /^(?:node|nodejs|deno|bun|python[0-9.]*|py|ruby|perl|php|bash|sh|zsh|dash|pwsh|powershell|cmd|tsx|ts-node)$/i;
const relativeFile = (w) => typeof w === "string" && !/^(?:~|\/|[A-Za-z]:|-|[a-z][a-z0-9+.-]*:)/i.test(w) && (/^\.{1,2}[\\/]/.test(w) || /[\\/]/.test(w) || /\.(?:[cm]?[jt]sx?|py|rb|pl|php|sh|bash|ps1|bat|cmd)$/i.test(w));
function localCode(command, args) {
	const name = command.split(/[\\/]/).pop().replace(/\.(?:exe|cmd|bat)$/i, "");
	if (relativeFile(command) && !RUNS_FILES.test(name)) return command;
	// uv run server.py runs a file from the project too.
	if (/^uv$/i.test(name) && args[0] === "run") return args.slice(1).find((a) => relativeFile(a)) ?? null;
	if (!RUNS_FILES.test(name)) return null;
	const inline = args.findIndex((a) => /^(?:-c|\/c|\/k|-Command|-e|--eval)$/i.test(a));
	if (inline >= 0 && typeof args[inline + 1] === "string") return args[inline + 1];
	return args.find((a) => relativeFile(a)) ?? null;
}

// Launcher options that name the package, and options that take a value, so
// the value isn't read as the package (npx --registry URL pkg, uvx --python
// 3.12 pkg). For uvx, -p is the Python version.
const LAUNCHER_OPTIONS = {
	node: { pkg: ["-p", "--package"], valued: ["--registry", "--cache", "--prefix", "--userconfig", "-c", "--call", "--node-options", "-w", "--workspace"] },
	python: {
		pkg: ["--from", "--spec"],
		valued: ["-p", "--python", "--with", "--with-editable", "--with-requirements", "--index", "--index-url", "--extra-index-url", "--default-index", "--find-links", "--constraints", "--overrides", "--cache-dir", "--directory", "--project", "--env-file", "--pip-args"],
	},
};

export function packageSpec(command, args) {
	const raw = launcherSpec(command, args);
	return raw ? judgeSpec(raw.spec, raw.python) : null;
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"]);

// A command line split into words the way a shell would, for simple quoting:
// "a b" and 'a b' are one word. Kept short, since it runs on untrusted text.
function shellWords(text) {
	const words = [];
	let word = null;
	let quote = null;
	for (const ch of String(text).slice(0, 2000)) {
		if (quote) {
			if (ch === quote) quote = null;
			else word += ch;
		} else if (ch === '"' || ch === "'") {
			quote = ch;
			word ??= "";
		} else if (/\s/.test(ch)) {
			if (word !== null) words.push(word);
			word = null;
		} else if (";|&".includes(ch)) {
			if (word !== null) words.push(word);
			words.push(ch);
			word = null;
		} else word = (word ?? "") + ch;
	}
	if (word !== null) words.push(word);
	return words;
}

// The separate commands in a list of words: a; b && c | d.
function commandSegments(words) {
	const segments = [[]];
	for (const w of words) {
		if (w === ";" || w === "|" || w === "&") segments.push([]);
		else segments.at(-1).push(w);
	}
	return segments.filter((s) => s.length).slice(0, 10);
}

// The argument a launcher such as npx or uvx runs, as { spec, python }. A
// launcher can sit inside a wrapper: cmd /c, a shell's -c string,
// PowerShell's -Command, env, npm exec, bun x or deno's npm: names.
function launcherSpec(command, args, depth = 0) {
	if (typeof command !== "string" || !command || depth > 3) return null;
	const base = command.split(/[\\/]/).pop().replace(/\.(cmd|exe|bat)$/i, "").toLowerCase();
	let rest = args.filter((a) => typeof a === "string").slice(0, 60);
	const inner = (words) => {
		for (const segment of commandSegments(words)) {
			// Past FOO=1 and exec, command, nohup or time in front of the command.
			let i = 0;
			while (i < segment.length - 1 && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(segment[i]) || /^(?:exec|command|nohup|time|builtin)$/.test(segment[i]))) i++;
			const found = launcherSpec(segment[i], segment.slice(i + 1), depth + 1);
			if (found) return found;
		}
		return null;
	};
	if (base === "cmd") {
		const c = rest.findIndex((a) => /^\/[ck]$/i.test(a));
		return c < 0 ? null : inner(rest.slice(c + 1).flatMap(shellWords));
	}
	if (SHELLS.has(base)) {
		const c = rest.findIndex((a) => /^-[a-z]*c[a-z]*$/i.test(a));
		return c < 0 || typeof rest[c + 1] !== "string" ? null : inner(shellWords(rest[c + 1]));
	}
	if (base === "pwsh" || base === "powershell") {
		const c = rest.findIndex((a) => /^-(?:c|command)$/i.test(a));
		return c < 0 ? null : inner(rest.slice(c + 1).flatMap(shellWords));
	}
	if (base === "env") {
		let i = 0;
		while (i < rest.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[i]) || rest[i].startsWith("-"))) {
			if (/^(?:-S|--split-string)$/.test(rest[i])) return inner(shellWords(rest[i + 1] ?? ""));
			i += /^(?:-u|--unset|-C|--chdir)$/.test(rest[i]) ? 2 : 1;
		}
		return inner(rest.slice(i));
	}
	if (base === "deno") {
		const spec = rest.find((a) => /^npm:/i.test(a));
		return spec ? { spec: spec.slice(4), python: false } : null;
	}
	if ((base === "npm" && (rest[0] === "exec" || rest[0] === "x")) || (base === "bun" && rest[0] === "x")) return launcherSpec("npx", rest.slice(1), depth + 1);
	if (base === "pnpm" || base === "yarn") {
		if (rest[0] !== "dlx") return null;
		rest = rest.slice(1);
	} else if (base === "pipx") {
		if (rest[0] !== "run") return null;
		rest = rest.slice(1);
	} else if (base === "uv") {
		if (rest[0] !== "tool" || rest[1] !== "run") return null;
		rest = rest.slice(2);
	} else if (!["npx", "bunx", "pnpx", "uvx"].includes(base)) return null;

	const python = ["uvx", "pipx", "uv"].includes(base);
	const { pkg, valued } = LAUNCHER_OPTIONS[python ? "python" : "node"];
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i];
		const eq = a.startsWith("--") ? a.indexOf("=") : -1;
		const name = eq > 0 ? a.slice(0, eq) : a;
		if (pkg.includes(name)) {
			const spec = eq > 0 ? a.slice(eq + 1) : rest[i + 1];
			return spec ? { spec, python } : null;
		}
		if (a.startsWith("-")) {
			if (eq < 0 && valued.includes(name)) i++;
			continue;
		}
		return { spec: a, python };
	}
	return null;
}

// Package names as the registries allow them. The name goes into the fix a
// report gives, such as "npm view NAME version", so anything else, such as
// "x; curl ... | bash" in a hostile project's args, isn't treated as a package.
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]{0,100}\/)?[a-z0-9][a-z0-9._~-]{0,213}$/i;
const PYTHON_NAME = /^[a-z0-9](?:[a-z0-9._-]{0,200}[a-z0-9])?$/i;

function judgeSpec(spec, python) {
	if (!spec) return null;
	// Local paths and URLs, such as ./server or git+https://..., aren't from a registry.
	if (/^(\.|\/|~|%|\$|[a-z][a-z0-9+.-]*:)/i.test(spec) || spec.includes("\\")) return null;
	if (python) {
		const name = spec.split(/[=@<>~!\[]/)[0].trim();
		if (!PYTHON_NAME.test(name)) return null;
		const exact = spec.match(/(?:==|@)\s*(\d+(?:\.\d+){1,3})\s*$/);
		return { name, spec, pinned: /==\s*\d|@\s*\d/.test(spec), python: true, version: exact ? exact[1] : "" };
	}
	const at = spec.lastIndexOf("@");
	const name = at > 0 ? spec.slice(0, at) : spec;
	if (!NPM_NAME.test(name)) return null;
	const version = at > 0 ? spec.slice(at + 1) : "";
	const pinned = /^\d+\.\d+\.\d+([-+][\w.]+)?$/.test(version);
	return { name, spec, pinned, version: pinned ? version : "" };
}

// The Docker option that gives a container control of the host, as
// { flag, arg }. `flag` is a fixed description such as "--network=host" or
// "-v ~", so the folder names in the real option never reach a report.
function dockerRisk(args) {
	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		const next = args[i + 1] ?? "";
		if (/^--privileged$/i.test(a)) return { flag: "--privileged", arg: a };
		let m = a.match(/^--(pid|network|net|ipc|uts)=host$/i) ?? (next === "host" ? a.match(/^--(pid|network|net|ipc|uts)$/i) : null);
		if (m) return { flag: `--${m[1].toLowerCase() === "net" ? "network" : m[1].toLowerCase()}=host`, arg: a };
		m = a.match(/^--cap-add=(ALL|SYS_ADMIN)$/i) ?? (a === "--cap-add" ? next.match(/^(ALL|SYS_ADMIN)$/i) : null);
		if (m) return { flag: `--cap-add=${m[1].toUpperCase()}`, arg: a };
		const volume = a === "-v" || a === "--volume" ? next : a.startsWith("--volume=") ? a.slice(9) : null;
		const mount = a === "--mount" ? next : a.startsWith("--mount=") ? a.slice(8) : null;
		const source = volume ? mountSource(volume) : mount ? (mount.match(/(?:^|,)(?:source|src)=([^,]+)/)?.[1] ?? "") : null;
		const label = source ? hostPathLabel(source) : null;
		if (label) return { flag: `${mount !== null ? "--mount" : "-v"} ${label}`, arg: a };
	}
	return null;
}

// "/", "~", "/etc", "C:\" or the Docker socket, for a mount source that
// exposes the host. Null for anything narrower.
function hostPathLabel(source) {
	if (/docker\.sock|docker_engine/i.test(source)) return "/var/run/docker.sock";
	if (!isBroadPath(source)) return null;
	const v = trimWord(String(source).trim().replace(/\\/g, "/"), "", "/");
	if (v === "") return "/";
	if (/^[A-Za-z]:$/.test(v)) return `${v.toUpperCase()}\\`;
	const system = v.match(/^\/(root|etc|var|opt|usr)$/i);
	return system ? `/${system[1].toLowerCase()}` : "~";
}

function mountSource(volume) {
	const win = volume.match(/^([A-Za-z]:[\\/][^:]*)/);
	return win ? win[1] : volume.split(":")[0];
}

export function isBroadPath(value) {
	const raw = String(value).trim();
	if (raw === "/" || raw === "\\") return true;
	const v = trimWord(raw.replace(/\\/g, "/"), "", "/");
	return (
		/^(~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\$env:USERPROFILE|[A-Za-z]:)$/i.test(v) ||
		/^\/(Users|home)(\/[^/]+)?$/i.test(v) ||
		/^[A-Za-z]:\/Users(\/[^/]+)?$/i.test(v) ||
		/^\/(root|etc|var|opt|usr)?$/i.test(v)
	);
}

// Folder names the checks write the usual way, such as Downloads.
const FOLDER_NAMES = { downloads: "Downloads", download: "Downloads", desktop: "Desktop", temp: "Temp", tmp: "tmp" };
const folderName = (name) => FOLDER_NAMES[String(name).toLowerCase()] ?? String(name);

// A folder agents read their settings from, such as .claude or .cursor/rules.
const agentFolder = (p) => typeof p === "string" && TOOL_ROOT.test(p.split("/")[0]) && p.split("/").length <= 4;

// --- Workspace ---------------------------------------------------------------

function checkWorkspace(ctx) {
	const root = ctx.root ?? "";
	const markers = [...HOME_MARKERS].filter((m) => ctx.shape.topLevel.includes(m));
	const homeLike = ctx.homeLike;
	const downloadsLike = DOWNLOADS_LIKE.test(root);

	// The command in a home folder with --project-only checks the folder
	// someone opens agents in. Run in the home folder as a
	// whole, the command only says where it ran, and the agents' own settings
	// say whether they were started there.
	if (homeLike && !ctx.ranInHome) add(ctx, "WS-HOME", { vars: { markers: listNames(markers.filter((m) => m.startsWith(".") || m === "AppData").concat(markers).slice(0, 3)) } });
	if (downloadsLike) add(ctx, "WS-DOWNLOADS", { vars: { root: folderName(root) } });

	if (downloadsLike) {
		const steering = ctx.files.filter((f) => f.content && (f.kind || f.loose) && isInstructionFile(f) && (!f.loose || steers(ctx, f)));
		if (steering.length) add(ctx, "WS-POISON-RISK", { vars: { files: listNames(steering.map((f) => f.path), 3), place: `your ${folderName(root)} folder` } });
	}

	const looseByDir = new Map();
	for (const f of ctx.files) {
		if (!f.loose || !f.content || !f.path.includes("/")) continue;
		const dir = f.path.slice(0, f.path.lastIndexOf("/"));
		if (!looseByDir.has(dir)) looseByDir.set(dir, []);
		looseByDir.get(dir).push(f);
	}
	for (const [dir, list] of looseByDir) {
		if (!riskyPlace(dir)) continue;
		const steering = list.filter((f) => steers(ctx, f));
		if (steering.length) add(ctx, "WS-POISON-RISK", { vars: { files: listNames(steering.map((f) => f.path.split("/").pop()), 3), place: riskyPlace(dir).name } });
	}

	if (ctx.shape.gitRepos >= 3) add(ctx, "WS-MULTI-REPO", { vars: { count: ctx.shape.gitRepos } });

	const sensitive = ctx.files.filter((f) => f.sensitive && !EXAMPLE_ENV.test(f.path) && !isCertificate(f.path) && !USUALLY_HARMLESS.test(f.path));
	const keys = sensitive.filter((f) => KEY_FILE.test(f.path));
	const others = sensitive.filter((f) => !KEY_FILE.test(f.path));
	if (keys.length) add(ctx, "WS-KEYS", { vars: { files: listNames(keys.map((f) => f.path), 4) } });
	if (others.length) {
		const denied = (f) => ctx.claudeDeny.some((d) => denyCovers(d, f.path, ctx.ignoreBudget));
		const exposed = others.filter((f) => !denied(f));
		if (ctx.claudeSettingsFiles.length && exposed.length) {
			add(ctx, "CC-NO-SECRET-DENY", { file: ctx.claudeSettingsFiles[0], vars: { files: listNames(exposed.map((f) => f.path), 4) } });
		} else if (!ctx.claudeSettingsFiles.length) {
			add(ctx, "WS-SECRETS", { vars: { files: listNames(others.map((f) => f.path), 4) } });
		}
	}

	const gitignore = ctx.files.find((f) => f.path === ".gitignore" && f.content);
	if (ctx.shape.rootGit) {
		const rules = gitIgnoreRules(ctx);
		const exposed = (list) => list.filter((f) => !isIgnored(rules, f.path, ctx.ignoreBudget));
		const envFiles = exposed(others.filter((f) => /(^|\/)\.env(\.|$)/i.test(f.path)));
		if (envFiles.length) add(ctx, "WS-ENV-COMMITTED", { file: gitignore ?? null, vars: { files: listNames(envFiles.map((f) => f.path), 3) } });
		const local = exposed(ctx.files.filter((f) => /(^|\/)(\.claude\/settings\.local\.json|claude\.local\.md)$/i.test(f.path)));
		if (local.length) add(ctx, "WS-LOCAL-SETTINGS", { file: gitignore ?? null, vars: { files: listNames(local.map((f) => f.path), 3) } });
	}

	for (const f of ctx.files.filter((x) => x.tooLarge && x.kind).slice(0, 5)) add(ctx, "WS-TOO-LARGE", { file: f });
	for (const f of ctx.files.filter((x) => x.partial && !x.tooLarge && x.kind).slice(0, 5)) add(ctx, "WS-PARTLY-CHECKED", { file: f });
	for (const f of ctx.files.filter((x) => x.linked && x.kind).slice(0, 20)) add(ctx, f.linked === "secret" ? "WS-LINK-SECRET" : "WS-LINK-OUTSIDE", { file: f });
	for (const f of ctx.files.filter((x) => x.linked === "outside" && x.folder && agentFolder(x.path)).slice(0, 20)) add(ctx, "WS-LINK-FOLDER", { file: f });
}

// Ignore rules for the project, lowest precedence first: git's global list,
// .git/info/exclude, then .gitignore files from the top folder down.
function gitIgnoreRules(ctx) {
	const rules = ctx.ignoreLists.flatMap((text) => ignoreRules(text, ""));
	const files = ctx.files
		.filter((f) => f.content && /(^|\/)\.gitignore$/.test(f.path) && !/^(~|\/|[A-Za-z]:)/.test(f.path))
		.sort((a, b) => a.path.split("/").length - b.path.split("/").length);
	for (const f of files) rules.push(...ignoreRules(f.content, f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : ""));
	return rules;
}

// Whether a Read(...) deny rule in Claude Code settings covers a project file.
// The patterns follow .gitignore syntax: "//" starts an absolute path, "~/"
// the home folder, "/" and "./" the project, and a bare name matches at any
// depth. A rule outside the project covers it only through **, as in ~/**/.env.
const denyCache = new Map();
function denyCovers(rule, path, budget) {
	const m = /^Read\((.+)\)$/i.exec(rule.trim());
	if (!m) return false;
	let pattern = m[1].trim();
	if (/^(?:\/\/|~\/)/.test(pattern)) {
		pattern = pattern.replace(/^(?:\/\/|~\/)/, "");
		if (!pattern.startsWith("**")) return false;
	}
	pattern = pattern.replace(/^\.\//, "/");
	if (!denyCache.has(pattern)) {
		if (denyCache.size > 500) denyCache.clear();
		denyCache.set(pattern, ignoreRules(pattern));
	}
	return isIgnored(denyCache.get(pattern), path, budget);
}

// A plugin's plugin.json that sets no hooks or MCP servers only names the
// plugin. The plugin's skills, commands and agents are listed on their own.
function emptyManifest(ctx, f) {
	if (!/(^|\/)\.claude-plugin\/plugin\.json$/i.test(f.path) || !f.content) return false;
	const json = parsed(f);
	return isObj(json) && json.hooks == null && json.mcpServers == null && !ctx.findings.some((x) => x.file === f.path);
}

// A loose file counts as steering an agent only when it reads like orders to
// one, or carries an injection pattern. Size and encoded blobs don't count:
// page dumps and logs are full of both.
const STEERING_RULES = new Set(["TXT-TAGS", "TXT-BIDI", "TXT-ZERO-WIDTH", "TXT-HIDDEN-COMMENT", "TXT-REMOTE-EXEC", "TXT-EXFIL", "TXT-OVERRIDE", "TXT-SECRET-ACCESS", "FLAG-DOCS"]);
function steers(ctx, f) {
	return Boolean(f.content) && (RX_DIRECTIVE.test(f.content) || ctx.findings.some((x) => x.file === f.path && STEERING_RULES.has(x.id)));
}

function listNames(names, max = 4) {
	const unique = [...new Set(names)];
	const shown = unique.slice(0, max);
	const rest = unique.length - shown.length;
	if (!shown.length) return "";
	const text = shown.length === 1 ? shown[0] : `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
	return rest > 0 ? `${shown.join(", ")} and ${rest} more` : text;
}

function walk(obj, visit, depth = 0) {
	if (!isObj(obj) || depth > 6) return;
	for (const [k, v] of Object.entries(obj)) {
		visit(k, v);
		if (isObj(v)) walk(v, visit, depth + 1);
	}
}

// --- Sprawl ------------------------------------------------------------------

// Instruction files at the top of the project that different agents read
// first, counting a rules folder once. A short file that only points to
// another, such as a CLAUDE.md that says "@AGENTS.md", and an exact copy or
// link of another file, don't count.
function checkSprawl(ctx) {
	const entries = new Map();
	const seen = new Set();
	for (const f of ctx.files) {
		if (!f.content || !f.kind || f.loose || !isInstructionFile(f) || /^(~|\/|[A-Za-z]:)/.test(f.path)) continue;
		const key = entryPoint(f.path);
		if (!key || seen.has(f.content) || pointsElsewhere(f.content)) continue;
		seen.add(f.content);
		if (!entries.has(key)) entries.set(key, new Set());
		for (const t of f.tools) entries.get(key).add(t);
	}
	const tools = new Set([...entries.values()].flatMap((t) => [...t]));
	if (entries.size >= 3 && tools.size >= 3) add(ctx, "SPRAWL", { vars: { count: entries.size, list: listNames([...entries.keys()], 4) } });
}

function entryPoint(path) {
	if (!path.includes("/")) return path;
	if (/^\.github\/copilot-instructions\.md$/i.test(path)) return path;
	if (/^\.roo\/rules[^/]*\//i.test(path)) return ".roo/rules/";
	const folder = path.match(/^(\.clinerules|\.cursor\/rules|\.windsurf\/rules|\.kiro\/steering|\.amazonq\/rules|\.github\/instructions|\.claude\/rules|\.continue\/rules|\.junie)\//i);
	return folder ? `${folder[1]}/` : null;
}

const pointsElsewhere = (text) => {
	const t = text.trim();
	return t.length < 300 && /(^|\s)@\S+\.md\b|\b(?:AGENTS|CLAUDE|GEMINI|README)\.md\b/i.test(t);
};

// --- Installed code ----------------------------------------------------------
//
// MCP packages, editor extensions, agent installs, skills and files attacks
// leave behind, checked against known.js with no network requests. With
// --lookup, the command adds OSV.dev's answers afterwards (applyLookup).

const TRACE_PATHS = new Set(TRACES.flatMap((t) => t.paths));
const EDITORS = new Set(["VS Code", "VS Code Insiders", "VSCodium", "Cursor", "Windsurf", "Kiro"]);
const EXT_ID = /^[a-z0-9][a-z0-9-]{0,99}\.[a-z0-9][a-z0-9._-]{0,99}$/i;
// How an agent was installed, in words.
export const INSTALLED_BY = { npm: "npm", native: "Claude Code's installer", local: "local install", homebrew: "Homebrew", volta: "Volta", bun: "bun", pnpm: "pnpm", project: "in this project", app: "app" };
const INSTALL_VIA = new Set(Object.keys(INSTALLED_BY));
const PLATFORMS = new Set(["mac", "windows", "linux"]);
const cleanVersion = (v) => (typeof v === "string" && VERSION_RE.test(v) ? v.replace(/^v/, "") : "");

function installsFrom(list) {
	return (Array.isArray(list) ? list : [])
		.slice(0, 200)
		.filter((i) => isObj(i) && typeof i.package === "string" && (Object.hasOwn(AGENT_PACKAGES, i.package) || knownPackage("npm", i.package)))
		.filter((i) => cleanVersion(i.version) && INSTALL_VIA.has(i.via) && typeof i.path === "string" && cleanPath(i.path))
		.map((i) => ({ package: i.package, version: cleanVersion(i.version), via: i.via, path: cleanPath(i.path), platform: PLATFORMS.has(i.platform) ? i.platform : null }));
}

// Versions pinned in the project's lockfile, by name and version. Only known
// lockfile names and packages known.js lists get through.
export const LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]);
function lockedFrom(list) {
	return (Array.isArray(list) ? list : [])
		.slice(0, 500)
		.filter((l) => isObj(l) && LOCKFILES.has(l.file) && typeof l.package === "string" && knownPackage("npm", l.package) && cleanVersion(l.version))
		.map((l) => ({ file: l.file, package: l.package, version: cleanVersion(l.version) }));
}

function extensionsFrom(list) {
	return (Array.isArray(list) ? list : [])
		.slice(0, 12)
		.filter((g) => isObj(g) && EDITORS.has(g.editor) && typeof g.dir === "string" && cleanPath(g.dir))
		.map((g) => ({
			editor: g.editor,
			dir: cleanPath(g.dir),
			items: (Array.isArray(g.items) ? g.items : [])
				.slice(0, 3000)
				.filter((x) => isObj(x) && typeof x.id === "string" && EXT_ID.test(x.id))
				.map((x) => ({
					id: x.id.toLowerCase(),
					// The ID with the capitals its publisher gave it, which OSV.dev
					// needs to find the extension. Only the same ID is accepted.
					published: typeof x.published === "string" && EXT_ID.test(x.published) && x.published.toLowerCase() === x.id.toLowerCase() ? x.published : null,
					version: cleanVersion(x.version),
					source: x.source === "vsix" || x.source === "gallery" ? x.source : null,
				})),
		}));
}
// Where each editor installs extensions from, as OSV.dev names it.
const OPEN_VSX = "VSCode:https://open-vsx.org";
const extensionRegistry = (editor) => (OPEN_VSX_EDITORS.includes(editor) ? OPEN_VSX : "VSCode");

// The name known.js lists a package under: Python names are compared the way
// PyPI compares them.
const knownName = (ecosystem, name) => (ecosystem === "PyPI" ? String(name).toLowerCase().replace(/[-_.]+/g, "-") : String(name));
const knownPackage = (ecosystem, name) => {
	const key = `${ecosystem}:${knownName(ecosystem, name)}`;
	return Object.hasOwn(KNOWN_PACKAGES, key) ? KNOWN_PACKAGES[key] : null;
};
const affects = (entry, version) => entry.versions === "all" || Boolean(version && entry.versions.includes(version));
// "Version 1.12.14 ... was" or "Versions 20.9.0, 20.10.0 and 21.5.0 ... were".
function badVersions(entry) {
	const list = Array.isArray(entry.versions) ? entry.versions : [];
	const one = list.length === 1;
	const versions = one ? `Version ${list[0]}` : `Versions ${list.slice(0, -1).join(", ")} and ${list.at(-1)}`;
	return { versions, were: one ? "was" : "were", one: one ? "it" : "one of them" };
}

// Damerau-Levenshtein distance between two names, giving up past `max`.
function nearness(a, b, max = 2) {
	if (Math.abs(a.length - b.length) > max) return max + 1;
	let prev2 = null;
	let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
	for (let i = 1; i <= a.length; i++) {
		const row = [i];
		let low = i;
		for (let j = 1; j <= b.length; j++) {
			let d = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
			if (prev2 && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d = Math.min(d, prev2[j - 2] + 1);
			row.push(d);
			low = Math.min(low, d);
		}
		if (low > max) return max + 1;
		prev2 = prev;
		prev = row;
	}
	return prev[b.length];
}

const OFFICIAL_SCOPES = [...new Set(OFFICIAL_MCP_PACKAGES.filter((n) => n.startsWith("@")).map((n) => n.split("/")[0]))];
// Unscoped copies of the official reference servers, such as mcp-server-github.
const SCOPE_COPIES = new Map(
	OFFICIAL_MCP_PACKAGES.filter((n) => n.startsWith("@modelcontextprotocol/server-")).flatMap((n) => {
		const short = n.split("/")[1];
		return [short, `mcp-${short}`, `modelcontextprotocol-${short}`].map((copy) => [copy, n]);
	}),
);

// The official package or scope a package name imitates, or null.
function lookalikeOf(name, python) {
	const lower = python ? knownName("PyPI", name) : String(name).toLowerCase();
	const official = python ? OFFICIAL_PYPI_MCP : OFFICIAL_MCP_PACKAGES;
	if (official.includes(lower) || lower.length > 100) return null;
	if (!python && SCOPE_COPIES.has(lower)) return SCOPE_COPIES.get(lower);
	for (const o of official) if (o.length >= 8 && nearness(lower, o) <= 2) return o;
	if (!python && lower.startsWith("@") && lower.includes("/")) {
		const scope = lower.split("/")[0];
		// One letter off for a short scope, two for a long one: @strapi is a real
		// scope two letters from @stripe.
		for (const s of OFFICIAL_SCOPES) if (scope !== s && s.length >= 6 && nearness(scope, s) <= (s.length >= 10 ? 2 : 1)) return s;
	}
	return null;
}

// "a git repository" or "a web address" for a launcher argument that runs
// code from outside a registry, unless it's pinned to a commit.
function remoteOrigin(spec, python) {
	if (typeof spec !== "string" || /[#@][0-9a-f]{40}$/i.test(spec)) return null;
	if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:)/i.test(spec)) return "a git repository";
	if (/^https?:\/\//i.test(spec)) return /\.git(?:$|[#@])|^https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[^/]+\/[^/]+\/?$/i.test(spec) ? "a git repository" : "a web address";
	// npx user/repo installs straight from GitHub.
	if (!python && /^[a-z0-9][\w.-]{0,38}\/[\w.-]{1,100}$/i.test(spec)) return "a git repository";
	return null;
}

// Where a server's program lives, when that's a downloads, desktop or temp folder.
function programPlace(command, args) {
	let program = command ?? "";
	if (INTERPRETERS.test(program.split(/[\\/]/).pop() ?? "")) program = args.find((a) => !a.startsWith("-")) ?? "";
	const p = program.replace(/\\/g, "/");
	if (/^(?:~|\$HOME|%USERPROFILE%|\/(?:Users|home)\/[^/]+|[A-Za-z]:\/Users\/[^/]+)\/Downloads\//i.test(p)) return "your Downloads folder";
	if (/^(?:~|\$HOME|%USERPROFILE%|\/(?:Users|home)\/[^/]+|[A-Za-z]:\/Users\/[^/]+)\/Desktop\//i.test(p)) return "your Desktop folder";
	if (/^(?:\/tmp|\/var\/tmp|\/private\/tmp|%TEMP%|%TMP%|\$env:TEMP|[A-Za-z]:\/Users\/[^/]+\/AppData\/Local\/Temp|[A-Za-z]:\/Windows\/Temp)\//i.test(p)) return "a temp folder";
	return null;
}

// True when the package itself is flagged: known malware or a lookalike.
function checkMcpPackage(ctx, s, base, near) {
	const raw = launcherSpec(s.command, s.args);
	const pkg = raw ? judgeSpec(raw.spec, raw.python) : null;
	let flagged = false;
	if (pkg) {
		const ecosystem = pkg.python ? "PyPI" : "npm";
		ctx.packages.push({ ecosystem, name: pkg.name, version: pkg.version || null, where: `Used by MCP server “${s.name}” in ${s.file.path}`, file: s.file.path, via: "mcp" });
		const known = knownPackage(ecosystem, pkg.name);
		const line = near(pkg.name) || undefined;
		const official = known ? null : lookalikeOf(pkg.name, pkg.python);
		const name = knownName(ecosystem, pkg.name);
		if (known && affects(known, pkg.version)) add(ctx, "PKG-MALICIOUS", { ...base(line), vars: { server: s.name, known: name, what: known.what, source: known.source } });
		else if (known && !pkg.version) add(ctx, "PKG-MALICIOUS-VERSION", { ...base(line), vars: { server: s.name, known: name, ...badVersions(known), source: known.source } });
		else if (official) add(ctx, "PKG-LOOKALIKE", { ...base(line), vars: { server: s.name, pkg: pkg.name, official } });
		flagged = Boolean((known && (affects(known, pkg.version) || !pkg.version)) || official);
	}
	const origin = raw ? remoteOrigin(raw.spec, raw.python) : null;
	if (origin) add(ctx, "PKG-REMOTE-SOURCE", { ...base(near(raw.spec.slice(0, 40)) || undefined), vars: { server: s.name, origin } });
	const place = programPlace(s.command, s.args);
	if (place) add(ctx, "PKG-RISKY-PLACE", { ...base(), vars: { server: s.name, place } });
	return flagged;
}

// The official agent extension an extension's ID copies, or null: the same
// name from another publisher, or the name with something added from a
// publisher whose name starts the same way.
function imitates(id) {
	if (Object.hasOwn(AGENT_EXTENSIONS, id)) return null;
	const dot = id.indexOf(".");
	const publisher = id.slice(0, dot);
	const name = id.slice(dot + 1);
	for (const [officialId, label] of Object.entries(AGENT_EXTENSIONS)) {
		const od = officialId.indexOf(".");
		const op = officialId.slice(0, od);
		const on = officialId.slice(od + 1);
		if (publisher === op) continue;
		const sameStart = [...op].findIndex((c, i) => publisher[i] !== c);
		if ((name === on && on !== "continue") || (on.length >= 6 && name.startsWith(on) && (sameStart < 0 ? op.length : sameStart) >= 5)) return { officialId, label };
	}
	return null;
}

function checkExtensions(ctx) {
	for (const group of ctx.extensions) {
		const file = { path: group.dir, tools: group.editor === "Cursor" || group.editor === "Windsurf" ? [group.editor] : [] };
		const fromFiles = [];
		for (const x of group.items) {
			ctx.packages.push({ ecosystem: extensionRegistry(group.editor), name: x.published ?? x.id, version: x.version || null, where: `Installed as a ${group.editor} extension`, file: group.dir, via: "extension" });
			const known = extensionListing(x.id, group.editor);
			// A bad build one marketplace served doesn't apply to a copy installed from a file.
			if (known && (!known.editors || x.source !== "vsix") && affects(known, x.version)) {
				const advice = known.advice ?? EXT_ADVICE;
				add(ctx, "EXT-MALICIOUS", { file, vars: { editor: group.editor, ext: x.id, version: x.version || "", what: known.what, source: known.source, advice } });
				continue;
			}
			const copy = imitates(x.id);
			if (copy) add(ctx, "EXT-IMPERSONATION", { file, tool: copy.label in AGENT_LABEL_TOOLS ? AGENT_LABEL_TOOLS[copy.label] : null, vars: { editor: group.editor, ext: x.id, official: copy.label, officialId: copy.officialId } });
			if (x.source === "vsix") fromFiles.push(x.id);
		}
		if (fromFiles.length) {
			const shown = fromFiles.slice(0, 4).join(", ") + (fromFiles.length > 4 ? ` and ${fromFiles.length - 4} more` : "");
			add(ctx, "EXT-VSIX", { file, vars: { editor: group.editor, list: shown, fromFiles: fromFiles.length === 1 ? "an extension installed from a file" : `${fromFiles.length} extensions installed from files` } });
		}
	}
}
const EXT_ADVICE = "Uninstall it, then change the keys and tokens on this computer it could reach";
const AGENT_LABEL_TOOLS = { "Claude Code": "Claude Code", Cline: "Cline", "Roo Code": "Roo Code", "GitHub Copilot": "GitHub Copilot", "GitHub Copilot Chat": "GitHub Copilot", Continue: "Continue", "Amazon Q": "Amazon Q" };

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// What an agent version is missing, from known.js: the rule, and the words
// that go in it. Null when it has every known fix.
function agentAdvice(pkg, version, platform) {
	const advisories = (Object.hasOwn(AGENT_ADVISORIES, pkg) ? AGENT_ADVISORIES[pkg] : []).filter((a) => !a.platforms || a.platforms.includes(platform));
	const affected = (v) => advisories.filter((a) => compareVersions(v, a.introduced) >= 0 && compareVersions(v, a.fixed) < 0);
	const hits = affected(version);
	if (!hits.length) return null;
	hits.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || compareVersions(b.fixed, a.fixed));
	const worst = hits[0];
	// The first version with none of the known problems: past every fix this
	// install is missing, and past any problem a later version brought in.
	let fixed = hits.reduce((top, a) => (compareVersions(a.fixed, top) > 0 ? a.fixed : top), "0.0.0");
	for (let later = affected(fixed), rounds = 0; later.length && rounds < 50; later = affected(fixed), rounds++) {
		fixed = later.reduce((top, a) => (compareVersions(a.fixed, top) > 0 ? a.fixed : top), fixed);
	}
	const one = hits.length === 1;
	return {
		worst,
		id: worst.severity === "high" ? "AGENT-VULN" : worst.severity === "medium" ? "AGENT-VULN-MINOR" : "AGENT-VULN-LOW",
		vars: { fixes: one ? "a security fix" : `${hits.length} security fixes`, lead: one ? "The issue" : "The most serious", worst: worst.title, ref: worst.cve ?? worst.id, fixed, every: one ? "the fix" : "every fix" },
	};
}
// How to update a package installed globally with something other than npm.
const GLOBAL_UPDATE = { pnpm: (p) => `pnpm add -g ${p}@latest`, bun: (p) => `bun add -g ${p}@latest`, volta: (p) => `volta install ${p}` };

function checkInstalls(ctx) {
	for (const inst of ctx.installs) {
		const file = { path: inst.path, tools: [] };
		const known = knownPackage("npm", inst.package);
		if (known && affects(known, inst.version)) {
			add(ctx, "DEP-MALICIOUS", { file, vars: { known: inst.package, version: inst.version, status: known.versions === "all" ? "a package listed as malicious" : "a version that was malware", what: known.what, source: known.source } });
			continue;
		}
		const meta = Object.hasOwn(AGENT_PACKAGES, inst.package) ? AGENT_PACKAGES[inst.package] : null;
		if (!meta) continue;
		if (inst.package !== "Claude Desktop") ctx.packages.push({ ecosystem: "npm", name: inst.package, version: inst.version, where: `This is your ${meta.tool} install`, file: inst.path, via: "install" });
		const advice = agentAdvice(inst.package, inst.version, inst.platform);
		if (!advice) continue;
		add(ctx, advice.id, {
			file: { path: inst.path, tools: [meta.tool] },
			tool: meta.tool,
			vars: {
				tool: meta.tool,
				version: inst.version,
				...advice.vars,
				update: meta.update[inst.via] ?? GLOBAL_UPDATE[inst.via]?.(inst.package) ?? Object.values(meta.update)[0],
			},
		});
	}
}

// A lockfile that pins a version that was malware installs it on the next
// clean install, in CI or on a teammate's computer.
function checkLocked(ctx) {
	// A version installed in the project is reported already, with a fix that
	// covers the lockfile, so the lockfile's copy of it adds nothing.
	const installed = new Set(ctx.installs.filter((i) => i.via === "project").map((i) => `${i.package}@${i.version}`));
	for (const l of ctx.locked) {
		const known = knownPackage("npm", l.package);
		if (!affects(known, l.version) || installed.has(`${l.package}@${l.version}`)) continue;
		add(ctx, "DEP-LOCKFILE", {
			file: { path: l.file, tools: [] },
			vars: { known: l.package, version: l.version, status: known.versions === "all" ? "a package listed as malicious" : "a version that was malware", what: known.what, source: known.source, remedy: lockRemedy(l.package, known) },
		});
	}
}
// A package that's malicious in every version has to go; otherwise a version
// that wasn't malware will do.
const lockRemedy = (name, entry) => (entry.versions === "all" ? `Remove ${name} from the project and update the lockfile` : `Move ${name} to a version that wasn't malware and update the lockfile`);

function checkTraces(ctx) {
	const strong = new Set();
	for (const t of TRACES) {
		const found = t.paths.filter((p) => ctx.traces.has(p));
		if (!found.length || (!t.strong && strong.has(t.campaign))) continue;
		if (t.strong) strong.add(t.campaign);
		add(ctx, t.strong ? "ATTACK-TRACE" : "ATTACK-TRACE-WEAK", { file: { path: found[0], tools: [] }, vars: { campaign: t.campaign, what: t.what, files: found.join(", "), advice: t.fix } });
	}
}

// A workflow a worm adds, by its name and, where it helps, its content.
function checkWorkflowTrace(ctx, f) {
	const t = WORKFLOW_TRACES.find((w) => w.name.test(f.path) && (!w.content || w.content(f.content)));
	if (t) add(ctx, t.strong ? "ATTACK-WORKFLOW" : "ATTACK-WORKFLOW-WEAK", { file: f, vars: { campaign: t.campaign, what: t.what, advice: t.fix } });
}

// Programs listed by name inside skill folders, one finding per skill.
// Plugins and tools a project gives OpenCode, Amp or the Cline command line,
// which load them as code when they start, without asking. Listed by name,
// never read. The user's own, in the home folder, aren't reported.
function checkPluginCode(ctx) {
	for (const f of ctx.files.filter((x) => x.listed && x.kind === "Plugin code" && !/^(~|\/|[A-Za-z]:)/.test(x.path)).slice(0, 10)) {
		add(ctx, "PLUGIN-CODE", { file: f, vars: { tool: f.tools[0] } });
	}
}

function checkSkillPrograms(ctx) {
	const bySkill = new Map();
	for (const f of ctx.files) {
		if (!f.listed) continue;
		const m = f.path.match(/^(.*?\/skills\/([^/]+))\/(.+)$/i);
		if (!m) continue;
		if (!bySkill.has(m[1])) bySkill.set(m[1], { skill: m[2], file: f, names: [] });
		// An app bundle is one program, however many files are inside it.
		const name = m[3].replace(/^(.*?\.app)\/.*$/i, "$1");
		if (!bySkill.get(m[1]).names.includes(name)) bySkill.get(m[1]).names.push(name);
	}
	for (const [dir, { skill, file, names }] of bySkill) {
		const files = names.slice(0, 3).join(", ") + (names.length > 3 ? ` and ${names.length - 3} more` : "");
		// The finding points at the skill's SKILL.md when there is one, rather
		// than at the program.
		// Without one, it points at the skill's folder, never at a program.
		const skillMd = ctx.files.find((x) => x.path.toLowerCase() === `${dir}/skill.md`.toLowerCase());
		const one = names.length === 1;
		add(ctx, "SKILL-BINARY", { file: skillMd ?? { path: dir, tools: file.tools }, vars: { skill, files, programs: one ? "a program" : `${names.length} programs`, them: one ? "it" : "them" } });
	}
}

// Claude Code's plugin marketplaces. Anthropic's own come from GitHub's
// anthropics organization.
function checkMarketplaces(ctx, f) {
	const json = parsed(f);
	if (!isObj(json)) return;
	const others = [];
	for (const [name, m] of Object.entries(json).slice(0, 200)) {
		if (!isObj(m) || anthropicMarketplace(m)) continue;
		const from = marketplaceSource(m);
		others.push(`${clip(name, 60)}${from ? ` (${clip(from, 80)})` : ""}`);
	}
	if (!others.length) return;
	const line = lineOf(f, `"${others[0].split(" (")[0]}"`);
	const list = others.slice(0, 4).join(", ") + (others.length > 4 ? ` and ${others.length - 4} more` : "");
	add(ctx, "PLUGIN-MARKETPLACE", { file: f, line, evidence: evidenceLine(f, line), vars: { list, marketplaces: others.length === 1 ? "a marketplace" : `${others.length} marketplaces` } });
}

// OSV.dev's answers about the packages, extensions and installs a result
// names, added as findings: one per package, for each place it's used.
// `hits` comes from the network, so each one must name a package the result
// already lists, and every value is checked. What the bundled list already
// reported (a package it knows is malware, an agent advisory it already
// counted) isn't repeated.
const LOOKUP_REF = /^[A-Z][A-Z0-9]{1,9}-[A-Za-z0-9._:-]{1,60}$/;
const MALWARE_RULES = new Set(["PKG-MALICIOUS", "PKG-MALICIOUS-VERSION", "DEP-MALICIOUS", "EXT-MALICIOUS"]);
const LOOKUP_RANK = { high: 0, medium: 1, low: 2 };
const LOOKUP_RULES = ["LOOKUP-VULN", "LOOKUP-VULN-MINOR", "LOOKUP-VULN-LOW"];
const LOOKUP_NO_FIX = "No fixed version is listed yet. Update when one is out, and until then limit what it can reach";
const LOOKUP_SOME_FIXED = " for the ones that are fixed. The rest have no fix listed yet, so limit what it can reach";
const LOOKUP_UNKNOWN = "Update to the newest version. Some details didn't load from OSV.dev, so run --lookup again to see which version fixes each one";
function safeSummary(text) {
	return String(text ?? "")
		.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, " ")
		.replace(/\b(?:[a-z][a-z0-9+.-]*:\/\/|www\.)\S*/gi, "a link")
		.replace(/[|`$]/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}
export function applyLookup(result, hits) {
	if (!isObj(result) || !Array.isArray(result.findings)) return result;
	const packages = Array.isArray(result.packages) ? result.packages.filter(isObj) : [];
	// Names as the bundled list's findings write them: extension IDs in
	// lowercase, Python names the way PyPI compares them.
	const loose = (name) => String(name).toLowerCase().replace(/[-_.]+/g, "-");
	const flagged = new Set(result.findings.filter((f) => MALWARE_RULES.has(f.id)).map((f) => `${loose(f.vars?.known ?? f.vars?.ext)}|${f.file}`));
	const counted = (name) => new Set((Object.hasOwn(AGENT_ADVISORIES, name) ? AGENT_ADVISORIES[name] : []).flatMap((a) => [a.id, a.cve]).filter(Boolean));
	const uses = new Map();
	for (const h of (Array.isArray(hits) ? hits : []).slice(0, 300)) {
		if (!isObj(h) || typeof h.ref !== "string" || !LOOKUP_REF.test(h.ref)) continue;
		const malicious = h.malicious === true;
		for (const pkg of packages) {
			if (pkg.ecosystem !== h.ecosystem || pkg.name !== h.name || (pkg.version ?? null) !== (h.version ?? null)) continue;
			// Without a version, only "this package is malware" applies.
			if (!malicious && !pkg.version) continue;
			if (malicious && flagged.has(`${loose(pkg.name)}|${pkg.file}`)) continue;
			if (!malicious && pkg.via === "install" && counted(pkg.name).has(h.ref)) continue;
			const use = uses.get(pkg) ?? { malicious: null, vulns: new Map() };
			if (malicious) use.malicious ??= h;
			else if (!use.vulns.has(h.ref)) use.vulns.set(h.ref, h);
			uses.set(pkg, use);
		}
	}

	const extra = [];
	for (const [pkg, use] of uses) {
		const file = { path: typeof pkg.file === "string" ? pkg.file : null, tools: [] };
		const common = { name: pkg.name, version: pkg.version ?? "", where: pkg.where };
		if (use.malicious) {
			// Without a pinned version, a listing that names only some versions,
			// often of a real package whose account was taken over, says those
			// versions were malware, not the package.
			const some = !pkg.version && use.malicious.allVersions !== true;
			extra.push(makeFinding(some ? "LOOKUP-MALICIOUS-VERSION" : "LOOKUP-MALICIOUS", { file, vars: { ...common, ref: use.malicious.ref } }));
			continue;
		}
		const vulns = [...use.vulns.values()];
		if (!vulns.length) continue;
		const rank = (h) => LOOKUP_RANK[h.severity] ?? 1;
		vulns.sort((a, b) => rank(a) - rank(b));
		const worst = vulns[0];
		const one = vulns.length === 1;
		// The newest fixed version fixes every one that has a fix.
		const fixes = vulns.map((h) => cleanVersion(h.fixed));
		const newest = fixes.filter(Boolean).reduce((top, v) => (!top || compareVersions(v, top) > 0 ? v : top), "");
		const unknown = vulns.some((h) => h.detailed === false);
		const advice = unknown ? LOOKUP_UNKNOWN : !newest ? LOOKUP_NO_FIX : `Update to ${newest} or later${fixes.every(Boolean) ? "" : LOOKUP_SOME_FIXED}`;
		const summary = safeSummary(typeof worst.summary === "string" ? worst.summary : "");
		extra.push(
			makeFinding(LOOKUP_RULES[rank(worst)], {
				file,
				vars: {
					...common,
					vulns: one ? "a published vulnerability" : `${vulns.length} published vulnerabilities`,
					lead: one ? "The issue" : "The most serious",
					summary: clip(summary || (worst.detailed === false ? "Its details didn't load from OSV.dev" : "No summary was published"), 200).replace(/[.\s]+$/, "") || "No summary was published",
					ref: worst.ref,
					advice,
				},
			}),
		);
	}
	if (!extra.length) return result;
	const findings = [...result.findings, ...extra].sort(bySeverity);
	const controlMap = (result.controlMap ?? []).map((f) => ({ ...f, findings: findings.filter((x) => x.file === f.path).length }));
	const { counts, score, grade } = scoreFindings(findings, controlMap.length > 0);
	return { ...result, findings, controlMap, counts, score, grade, headline: headlineFor(counts, findings[0], controlMap.length > 0), lookedUp: true };
}

// --- Score -------------------------------------------------------------------

const bySeverity = (a, b) =>
	SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.category.localeCompare(b.category) || (a.file ?? "").localeCompare(b.file ?? "");

// Score, grade and counts from a list of findings, for a check and again
// after a lookup.
function scoreFindings(findings, hasControlFiles) {
	const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
	// Repeats of the same rule count less, so one noisy pattern can't zero the score.
	const byRule = new Map();
	for (const f of findings) byRule.set(f.id, (byRule.get(f.id) ?? 0) + 1);
	let penalty = 0;
	for (const [id, n] of byRule) penalty += WEIGHT[RULES[id].severity] * Math.min(2, 1 + 0.25 * (n - 1));
	const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
	let grade = GRADES.find(([, min]) => score >= min)?.[0] ?? "F";
	if (counts.critical && "ABC".includes(grade)) grade = "D";
	if (!hasControlFiles && !findings.length) grade = "–";
	return { counts, score: grade === "–" ? null : score, grade };
}

// What each rule's findings take off the score, most first: the order to fix
// things in. The points are the same ones scoreFindings counts.
export function pointsOff(findings) {
	const byRule = new Map();
	for (const f of findings) {
		if (!Object.hasOwn(RULES, f.id)) continue;
		const entry = byRule.get(f.id) ?? { id: f.id, severity: RULES[f.id].severity, findings: [] };
		entry.findings.push(f);
		byRule.set(f.id, entry);
	}
	const rules = [...byRule.values()].map((r) => ({ ...r, points: WEIGHT[r.severity] * Math.min(2, 1 + 0.25 * (r.findings.length - 1)) }));
	rules.sort((a, b) => b.points - a.points || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
	return { rules: rules.filter((r) => r.points > 0), total: rules.reduce((sum, r) => sum + r.points, 0) };
}

function agentsIn(controlMap) {
	// Agents with files of their own. A file several agents read, such as
	// AGENTS.md or .mcp.json, doesn't show that each of them is in use.
	const specific = controlMap.filter((f) => f.tools.length === 1);
	return [...new Set((specific.length ? specific : controlMap).flatMap((f) => f.tools))].filter((t) => t !== "Any agent started there" && t !== "Your shell");
}

function explainSafely(f, ctx) {
	try {
		return explainFile(f, { json: f.content && /\.(jsonc?|toml|kiro\.hook)$/i.test(f.path) ? parsed(f) : null, servers: ctx.mcpServers.filter((s) => s.file === f) });
	} catch {
		return { scope: scopeOf(f), summary: "Couldn't be summarized.", details: [] };
	}
}

function summarize(ctx) {
	const findings = ctx.findings.sort(bySeverity);
	// Plugin code is listed by name, never read, but it controls the agent
	// that loads it, so it's in the map.
	const controlFiles = ctx.files.filter(
		(f) =>
			f.kind &&
			(!f.listed || f.kind === "Plugin code") &&
			(!f.loose || steers(ctx, f)) &&
			(f.kind !== "Shell profile" || !f.content || agentLines(f).length) &&
			!emptyManifest(ctx, f),
	);
	// Each agent's files together, agents in the order they were first found.
	const firstSeen = new Map();
	for (const f of controlFiles) if (!firstSeen.has(f.tools.join())) firstSeen.set(f.tools.join(), firstSeen.size);
	controlFiles.sort((a, b) => firstSeen.get(a.tools.join()) - firstSeen.get(b.tools.join()));
	const { counts, score, grade } = scoreFindings(findings, controlFiles.length > 0);
	const toolNames = agentsIn(controlFiles);
	const headline = headlineFor(counts, findings[0], controlFiles.length > 0);

	return {
		version: RULESET_VERSION,
		checkedAt: Date.now(),
		root: ctx.root,
		score,
		grade,
		headline,
		counts,
		findings,
		categories: CATEGORIES,
		tools: toolNames,
		// What each file tells its agents, worked out here, for --explain and
		// the page --open saves.
		controlMap: controlFiles.map((f) => ({
			path: f.path,
			kind: f.kind,
			tools: f.tools,
			size: f.size,
			lines: f.lines ? f.lines.length : null,
			findings: findings.filter((x) => x.file === f.path).length,
			...(f.listed ? { listed: true } : {}),
			...explainSafely(f, ctx),
		})),
		stats: {
			// Agent files read and checked. Files read only for a check, such as
			// .gitignore, and plugin code, which is listed, aren't counted.
			filesChecked: controlFiles.filter((f) => f.content).length,
			secretFilesListed: ctx.files.filter((f) => f.sensitive).length,
			maskedInBrowser: ctx.maskedInBrowser,
			mcpServers: ctx.mcpServers.length,
			entriesScanned: ctx.shape.entries,
			truncated: ctx.shape.truncated,
			agentInstalls: ctx.installs.filter((i) => Object.hasOwn(AGENT_PACKAGES, i.package)).length,
			extensions: ctx.extensions.reduce((n, g) => n + g.items.length, 0),
		},
		// What's installed, for --explain, --open and --lookup.
		installed: {
			agents: ctx.installs.filter((i) => Object.hasOwn(AGENT_PACKAGES, i.package)).map((i) => ({ tool: AGENT_PACKAGES[i.package].tool, version: i.version, via: i.via, path: i.path })),
			editors: ctx.extensions.map((g) => ({
				editor: g.editor,
				dir: g.dir,
				count: g.items.length,
				agents: g.items.filter((x) => Object.hasOwn(AGENT_EXTENSIONS, x.id)).map((x) => ({ name: AGENT_EXTENSIONS[x.id], id: x.id, version: x.version })),
			})),
		},
		packages: ctx.packages.slice(0, 2000),
	};
}

// --- Today's list ------------------------------------------------------------------
//
// Adds the malware misconfig.ai lists since this release (addKnownMalware in
// known.js). Call it before a check; calling it again with a newer list
// replaces what the last one added. Returns when the list was made and how
// many entries it holds, or null when it isn't a list.
export function useKnownMalware(feed) {
	const added = addKnownMalware(feed);
	return added ? { updated: added.updated, packages: added.packages.length, extensions: added.extensions.length } : null;
}
