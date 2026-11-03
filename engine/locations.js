// Where each agent keeps the files that control it. The command line tool
// reads these paths; the website shows them so people know where to look.
//
// Tokens: "~" is the home folder. "{config}" is the per-user app settings
// folder: ~/Library/Application Support on macOS, %APPDATA% on Windows and
// ~/.config on Linux. A path ending in "/" is a folder of agent files, and
// "*" stands for any one folder or file name.

export const LOCATIONS = [
	{
		agent: "Claude Code",
		controls: "Permissions, hooks, MCP servers, plugins, memory, and every folder it has been started in",
		user: [
			"~/.claude/settings.json",
			"~/.claude/settings.local.json",
			"~/.claude.json",
			"~/.claude/CLAUDE.md",
			"~/.claude/rules/",
			"~/.claude/agents/",
			"~/.claude/commands/",
			"~/.claude/skills/",
			"~/.claude/hooks/",
			"~/.claude/projects/*/memory/MEMORY.md",
			"~/.claude/plugins/installed_plugins.json",
			"~/.claude/plugins/known_marketplaces.json",
		],
		system: {
			mac: ["/Library/Application Support/ClaudeCode/managed-settings.json", "/Library/Application Support/ClaudeCode/managed-settings.d/", "/Library/Application Support/ClaudeCode/managed-mcp.json"],
			windows: ["C:/Program Files/ClaudeCode/managed-settings.json", "C:/Program Files/ClaudeCode/managed-settings.d/", "C:/Program Files/ClaudeCode/managed-mcp.json"],
			linux: ["/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.d/", "/etc/claude-code/managed-mcp.json"],
		},
		project: ["CLAUDE.md", ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".claude/rules/", ".claude/agents/", ".claude/commands/", ".claude/skills/"],
	},
	{
		agent: "Claude Desktop",
		controls: "MCP servers for the desktop app",
		user: ["{config}/Claude/claude_desktop_config.json"],
		project: [],
	},
	{
		agent: "Codex",
		controls: "Sandbox, approvals, hooks, command rules, MCP servers, skills and trusted folders",
		user: ["~/.codex/config.toml", "~/.codex/*.config.toml", "~/.codex/hooks.json", "~/.codex/rules/", "~/.codex/AGENTS.md", "~/.agents/skills/"],
		system: { mac: ["/etc/codex/config.toml", "/etc/codex/requirements.toml"], linux: ["/etc/codex/config.toml", "/etc/codex/requirements.toml"] },
		project: ["AGENTS.md", ".codex/config.toml", ".codex/hooks.json", ".codex/rules/", ".agents/skills/"],
	},
	{
		agent: "GitHub Copilot",
		controls: "Instructions, auto-approval, hooks, MCP servers and trusted folders, in VS Code and on the command line",
		user: ["{config}/Code/User/settings.json", "{config}/Code/User/mcp.json", "~/.copilot/config.json", "~/.copilot/mcp-config.json"],
		project: [".github/copilot-instructions.md", ".github/instructions/", ".github/prompts/", ".github/agents/", ".github/hooks/", ".github/mcp.json", ".vscode/settings.json", ".vscode/mcp.json", ".mcp.json", "AGENTS.md"],
	},
	{
		agent: "Cursor",
		controls: "Rules, hooks, sandbox, command permissions and MCP servers",
		user: ["~/.cursor/mcp.json", "~/.cursor/hooks.json", "~/.cursor/cli-config.json", "~/.cursor/sandbox.json", "~/.cursor/permissions.json", "{config}/Cursor/User/settings.json"],
		project: [".cursor/rules/", ".cursor/mcp.json", ".cursor/hooks.json", ".cursor/cli.json", ".cursorrules", "AGENTS.md"],
	},
	{
		agent: "Gemini CLI",
		controls: "Approval mode, trusted folders, extensions, MCP servers and instructions",
		user: ["~/.gemini/settings.json", "~/.gemini/GEMINI.md", "~/.gemini/trustedFolders.json", "~/.gemini/extensions/*/gemini-extension.json", "~/.gemini/extensions/*/GEMINI.md"],
		system: {
			mac: ["/Library/Application Support/GeminiCli/settings.json"],
			windows: ["C:/ProgramData/gemini-cli/settings.json"],
			linux: ["/etc/gemini-cli/settings.json"],
		},
		project: ["GEMINI.md", ".gemini/settings.json"],
	},
	{
		agent: "Your shell",
		controls: "Aliases that start an agent with approvals off",
		user: {
			mac: ["~/.zshrc", "~/.zprofile", "~/.bash_profile", "~/.bashrc"],
			linux: ["~/.bashrc", "~/.zshrc", "~/.profile", "~/.config/fish/config.fish"],
			windows: [
				"~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
				"~/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
				"~/OneDrive*/Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
				"~/OneDrive*/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
			],
		},
		project: [],
	},
	{
		agent: "OpenCode",
		controls: "Permissions, session sharing, plugins and MCP servers",
		user: ["~/.config/opencode/opencode.json", "~/.config/opencode/AGENTS.md", "~/.config/opencode/plugins/"],
		project: ["opencode.json", ".opencode/", "AGENTS.md"],
	},
	{
		agent: "Cline",
		controls: "Auto-approval, YOLO mode, MCP servers and rules",
		user: ["{config}/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "~/.cline/data/settings/cline_mcp_settings.json", "~/.cline/data/globalState.json", "~/Documents/Cline/Rules/"],
		project: [".clinerules", ".cline/plugins/"],
	},
	{
		agent: "Windsurf",
		controls: "Rules, hooks and MCP servers",
		user: ["~/.codeium/windsurf/mcp_config.json", "~/.codeium/windsurf/hooks.json", "{config}/Windsurf/User/settings.json"],
		project: [".windsurf/rules/", ".windsurf/hooks.json", ".devin/hooks.v1.json", ".windsurfrules"],
	},
	{
		agent: "Zed",
		controls: "Agent tool permissions, trusted projects and context servers",
		user: { mac: ["~/.config/zed/settings.json"], linux: ["~/.config/zed/settings.json"], windows: ["{config}/Zed/settings.json"] },
		project: [".zed/settings.json"],
	},
	{
		agent: "Grok",
		controls: "Permission mode, sandbox, hooks and MCP servers",
		user: ["~/.grok/config.toml", "~/.grok/settings.json", "~/.grok/hooks/"],
		project: [".grok/config.toml", ".grok/settings.json", ".grok/hooks/", ".grok/GROK.md"],
	},
	{
		agent: "Amp",
		controls: "Permissions, plugins and MCP servers",
		user: ["~/.config/amp/settings.json", "~/.config/amp/plugins/"],
		project: [".amp/settings.json", ".amp/plugins/", "AGENTS.md"],
	},
	{
		agent: "Goose",
		controls: "Approval mode, extensions and hints",
		user: { mac: ["~/.config/goose/config.yaml"], linux: ["~/.config/goose/config.yaml"], windows: ["{config}/Block/goose/config/config.yaml"] },
		project: [".goosehints"],
	},
	{
		agent: "Continue",
		controls: "Models, MCP servers, rules and where session data is sent",
		user: ["~/.continue/config.yaml", "~/.continue/config.json"],
		project: [".continue/"],
	},
	{
		agent: "Roo Code",
		controls: "MCP servers, modes and rules",
		user: ["{config}/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"],
		project: [".roo/", ".roomodes"],
	},
	{
		agent: "Kiro",
		controls: "Steering files, hooks, agents and MCP servers",
		user: ["~/.kiro/settings/mcp.json", "~/.kiro/steering/", "~/.kiro/hooks/", "~/.kiro/agents/"],
		project: [".kiro/steering/", ".kiro/settings/mcp.json", ".kiro/hooks/", ".kiro/agents/"],
	},
	{
		agent: "Amazon Q",
		controls: "Rules, agents and MCP servers",
		user: ["~/.aws/amazonq/mcp.json", "~/.aws/amazonq/cli-agents/"],
		project: [".amazonq/rules/", ".amazonq/mcp.json", ".amazonq/cli-agents/"],
	},
	{
		agent: "Junie",
		controls: "Guidelines and MCP servers",
		user: [],
		project: [".junie/guidelines.md", ".junie/AGENTS.md", ".junie/mcp/mcp.json"],
	},
	{
		agent: "Aider",
		controls: "Auto-confirm and model settings",
		user: ["~/.aider.conf.yml"],
		project: [".aider.conf.yml"],
	},
];

const CONFIG_DIR = { mac: "~/Library/Application Support", windows: "~/AppData/Roaming", linux: "~/.config" };

// Paths for one OS, with "{config}" expanded and "~" kept.
export function userPaths(entry, os) {
	const list = Array.isArray(entry.user) ? entry.user : entry.user?.[os] ?? [];
	const system = entry.system?.[os] ?? [];
	return [...list, ...system].map((p) => p.replace("{config}", CONFIG_DIR[os]));
}

// How to write a path so people recognize it on their system.
export function displayPath(path, os) {
	if (os !== "windows") return path;
	return path
		.replace(/^~\/AppData\/Roaming/, "%APPDATA%")
		.replace(/^~\//, "%USERPROFILE%/")
		.replace(/\//g, "\\");
}
