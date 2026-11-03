// Command-line options that turn off an agent's approval prompts or sandbox,
// and which agent each one belongs to. Used for shell aliases, scripts, hooks
// and instruction files.

// How each agent's command looks on a command line, after any folder,
// extension or version is taken off.
const AGENT_COMMANDS = [
	["Claude Code", /^(?:claude|@anthropic-ai\/claude-code)$/],
	["Codex", /^(?:codex|@openai\/codex)$/],
	["Gemini CLI", /^(?:gemini|@google\/gemini-cli)$/],
	["Qwen Code", /^(?:qwen|@qwen-code\/qwen-code)$/],
	["GitHub Copilot", /^(?:copilot|@github\/copilot)$/],
	["Cursor", /^cursor-agent$/],
	["Aider", /^(?:aider|aider-chat)$/],
	["Amp", /^(?:amp|@sourcegraph\/amp)$/],
	["Grok", /^(?:grok|@vibe-kit\/grok-cli)$/],
	["Kiro", /^kiro-cli$/],
	["OpenCode", /^(?:opencode|opencode-ai)$/],
];

// Each option by the name reports show. A `shared` option also exists in
// other programs (npx -y, rm -f, bash -c), so it counts only after that
// agent's own command name. `value` is the option's value, in lower case.
const DANGER_FLAGS = [
	{ flag: "--dangerously-skip-permissions", agents: ["Claude Code"] },
	{ flag: "--allow-dangerously-skip-permissions", agents: ["Claude Code"] },
	{ flag: "--permission-mode bypassPermissions", agents: ["Claude Code"], names: ["--permission-mode"], value: "bypasspermissions" },
	{ flag: "--dangerously-bypass-approvals-and-sandbox", agents: ["Codex"] },
	{ flag: "--sandbox danger-full-access", agents: ["Codex"], names: ["--sandbox", "-s"], value: "danger-full-access" },
	{ flag: "-c sandbox_mode=danger-full-access", agents: ["Codex"], names: ["-c", "--config"], value: "sandbox_mode=danger-full-access", shared: true },
	{ flag: "--ask-for-approval never", agents: ["Codex"], names: ["--ask-for-approval", "-a"], value: "never", shared: true },
	{ flag: "-c approval_policy=never", agents: ["Codex"], names: ["-c", "--config"], value: "approval_policy=never", shared: true },
	{ flag: "--yolo", agents: ["Codex", "Gemini CLI", "Qwen Code", "GitHub Copilot", "Cursor"], shared: true },
	{ flag: "--approval-mode yolo", agents: ["Gemini CLI", "Qwen Code"], names: ["--approval-mode"], value: "yolo" },
	{ flag: "-y", agents: ["Gemini CLI", "Qwen Code"], shared: true },
	{ flag: "--allow-all-tools", agents: ["GitHub Copilot"] },
	{ flag: "--allow-all", agents: ["GitHub Copilot"], shared: true },
	{ flag: "--force", agents: ["Cursor"], names: ["--force", "-f"], shared: true },
	{ flag: "--yes-always", agents: ["Aider"] },
	{ flag: "--dangerously-allow-all", agents: ["Amp"] },
	{ flag: "--always-approve", agents: ["Grok"], shared: true },
	{ flag: "--trust-all-tools", agents: ["Kiro"] },
];
const QUICK_FLAGS = /--(?:dangerously|allow-dangerously|permission-mode|sandbox|ask-for-approval|yolo|approval-mode|allow-all|force|yes-always|always-approve|trust-all|config)|\s-[ysafc]\b/i;

// A program by its name alone, wherever it's installed: C:\\Windows\\...\\powershell.exe
// is powershell.
export const programName = (word) => String(word).split(/[\\/]/).pop().replace(/\.(?:exe|cmd|bat|com|ps1)$/i, "");

// A command line ends at && || ; | or a new line, and in Markdown at a
// backtick, so an option is only credited to the command it belongs to.
export const COMMAND_BREAK = /&&|\|\||[;|`\n]|\$\(/g;
// After the agent's name, its own options end at "--" or at another program.
const PROGRAMS = /^(?:npx|npm|pnpm|pnpx|yarn|bunx|bun|uvx|uv|pipx|node|deno|python[0-9.]*|docker|podman|bash|sh|zsh|fish|cmd|pwsh|powershell|sudo|env)$/;

// Strips quotes, brackets and punctuation from the ends of a word, with a
// loop rather than a pattern, so a long run of them can't slow it down.
export function trimWord(word, lead = "\"'({[", trail = "\"',;:)}].") {
	let a = 0;
	let b = word.length;
	while (a < b && lead.includes(word[a])) a++;
	while (b > a && trail.includes(word[b - 1])) b--;
	return word.slice(a, b);
}

function commandWord(token) {
	const eq = token.indexOf("=");
	// FOO=1 claude, or alias cc='claude
	let t = trimWord(/^[\w.-]*=/.test(token) ? token.slice(eq + 1) : token).toLowerCase();
	if (!t.startsWith("@")) t = t.split(/[\\/]/).pop();
	return t.replace(/\.(?:exe|cmd|bat|ps1)$/, "").replace(/(.)@[^/@]*$/, "$1");
}

// The first option in `text` that turns approvals off, as { flag, agent, index }.
// `skip(index)` can reject a match, for example one in a "never use" sentence.
export function findDangerFlag(text, skip = () => false) {
	const s = String(text);
	if (!QUICK_FLAGS.test(s)) return null;
	let start = 0;
	const breaks = [...s.matchAll(COMMAND_BREAK)].map((m) => m.index).concat(s.length);
	for (const end of breaks) {
		const hit = flagInCommand(s, start, end, skip);
		if (hit) return hit;
		start = end + 1;
	}
	return null;
}

function flagInCommand(s, from, to, skip) {
	const tokens = [...s.slice(from, to).matchAll(/\S+/g)].map((m) => ({ raw: m[0], at: from + m.index }));
	if (!tokens.length) return null;
	// Which agent's options each token falls under.
	const owner = new Array(tokens.length).fill(null);
	let current = null;
	for (const [i, t] of tokens.entries()) {
		const word = commandWord(t.raw);
		const agent = AGENT_COMMANDS.find(([, re]) => re.test(word))?.[0];
		if (agent) current = agent;
		else if (word === "--" || PROGRAMS.test(word)) current = null;
		else owner[i] = current;
	}
	for (const [i, t] of tokens.entries()) {
		const raw = trimWord(t.raw);
		if (!raw.startsWith("-")) continue;
		const eq = raw.indexOf("=");
		const name = eq > 0 && raw.startsWith("--") ? raw.slice(0, eq) : raw;
		const inline = eq > 0 && raw.startsWith("--") ? raw.slice(eq + 1) : undefined;
		const value = trimWord(inline ?? tokens[i + 1]?.raw ?? "", "\"'", "\"',;:)}].")
			.toLowerCase()
			.replace(/["']/g, "");
		for (const spec of DANGER_FLAGS) {
			const names = spec.names ?? [spec.flag];
			if (!names.includes(name)) continue;
			if (spec.value && value !== spec.value) continue;
			if (spec.shared && !spec.agents.includes(owner[i])) continue;
			if (skip(t.at)) continue;
			return { flag: spec.flag, agent: owner[i] && spec.agents.includes(owner[i]) ? owner[i] : spec.agents[0], index: t.at };
		}
	}
	return null;
}
