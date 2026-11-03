// Which files steer AI agents. Shared by the command, which finds and reads
// them, and the rule engine, so both agree on what gets read.

export const SKIP_DIRS = new Set([
	"node_modules", ".git", ".hg", ".svn", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
	".turbo", ".cache", ".parcel-cache", "coverage", "vendor", "target", ".venv", "venv",
	"__pycache__", ".gradle", ".idea", ".vs", "bin", "obj", "Pods", "DerivedData", ".terraform",
	".pnpm-store", ".yarn", "AppData", "Library", "Application Data", "$RECYCLE.BIN",
	"System Volume Information", ".Trash", ".npm", ".cargo", ".rustup", ".m2", ".nuget",
]);

export const HOME_MARKERS = new Set([
	".ssh", "AppData", "Library", "NTUSER.DAT", ".bashrc", ".zshrc", ".profile", "Downloads",
	"Documents", "Desktop", ".config", ".local", "Pictures", "Music", "Videos",
]);

// Agent control files: read, masked, then checked.
export const CONTENT = [
	/(^|\/)(claude|claude\.local|agents|agents\.override|gemini|grok)\.md$/i,
	/(^|\/)\.claude\/(settings(\.local)?\.json|(commands|agents|skills|output-styles|rules)\/.+\.md|hooks\/.+)$/i,
	/(^|\/)\.agents\/skills\/.+\.md$/i,
	/(^|\/)\.claude\/projects\/[^/]+\/memory\/[^/]+\.md$/i,
	/(^|\/)\.claude\/plugins\/(installed_plugins\.json|known_marketplaces\.json|.+\/hooks\/hooks\.json|.+\/\.mcp\.json|.+\/\.claude-plugin\/plugin\.json|.+\/(commands|agents|skills)\/.+\.md)$/i,
	/(^|\/)managed-settings\.d\/[^/]+\.json$/i,
	/(^|\/)(Documents\/Cline\/Rules|\.cline\/rules)\/.+\.md$/i,
	/(^|\/)\.mcp\.json$/i,
	/(^|\/)\.claude\.json$/i,
	/(^|\/)\.codex\/(config\.toml|hooks\.json|rules\/[^/]+\.rules|.+\.md)$/i,
	/(^|\/)\.cursor\/(rules\/.+\.mdc?|mcp\.json|hooks\.json|environment\.json|cli\.json|sandbox\.json|permissions\.json|.+\.md)$/i,
	/(^|\/)\.cursorrules$/i,
	/(^|\/)\.github\/(copilot-instructions\.md|(instructions|prompts|chatmodes|agents)\/.+\.md|hooks\/[^/]+\.json|mcp\.json|copilot\/settings\.json)$/i,
	/(^|\/)\.vscode\/(mcp|settings|tasks)\.json$/i,
	/(^|\/)\.gemini\/(settings\.json|extensions\/[^/]+\/gemini-extension\.json|.+\.md|commands\/.+\.toml)$/i,
	/(^|\/)opencode\.jsonc?$/i,
	/(^|\/)\.opencode\/.+\.(md|json|jsonc)$/i,
	/(^|\/)\.grok\/(settings\.json|config\.toml|hooks\/[^/]+\.json|.+\.md)$/i,
	/(^|\/)\.amp\/settings\.json$/i,
	/(^|\/)\.goosehints$/i,
	/(^|\/)\.windsurfrules$/i,
	/(^|\/)\.windsurf\/(rules\/.+|workflows\/.+\.md|mcp_config\.json|hooks\.json)$/i,
	/(^|\/)\.codeium\/windsurf\/(mcp_config|hooks)\.json$/i,
	/(^|\/)\.devin\/hooks\.v1\.json$/i,
	/(^|\/)\.clinerules(\/.+)?$/i,
	/(^|\/)\.roomodes$/i,
	/(^|\/)\.roo\/.+\.(md|json)$/i,
	/(^|\/)\.kiro\/(steering\/.+\.md|settings\/mcp\.json|hooks\/[^/]+\.(json|kiro\.hook)|agents\/[^/]+\.(json|md))$/i,
	/(^|\/)\.amazonq\/(rules\/.+\.md|mcp\.json|cli-agents\/[^/]+\.json)$/i,
	/(^|\/)\.aws\/amazonq\/(mcp|cli-agents\/[^/]+)\.json$/i,
	/(^|\/)\.continue\/.+\.(json|ya?ml|md)$/i,
	/(^|\/)\.zed\/settings\.json$/i,
	/(^|\/)\.junie\/(guidelines\.md|agents\.md|rules\/.+\.md|mcp\/mcp\.json)$/i,
	/(^|\/)\.aider\.conf\.ya?ml$/i,
	/^(?:[^/]+\/){0,3}\.gitignore$/i,
	/^package\.json$/i,
	// Workflows the Shai-Hulud 2.0 worm adds to repositories it reaches.
	/(^|\/)\.github\/workflows\/(?:discussion\.ya?ml|formatter_\d{3,}\.ya?ml|shai-?hulud-?workflow\.ya?ml)$/i,
];

// Credential files: name and size only.
export const SENSITIVE = [
	/(^|\/)\.env(\.[\w.-]+)?$/i,
	/(^|\/)[^/]+\.(pem|key|p12|pfx|jks|keystore|ppk)$/i,
	/(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i,
	/(^|\/)\.(npmrc|pypirc|netrc|git-credentials)$/i,
	/(^|\/)\.aws\/credentials$/i,
	/(^|\/)\.docker\/config\.json$/i,
	/(^|\/)\.kube\/config$/i,
	/(^|\/)\.codex\/auth\.json$/i,
	/(^|\/)\.claude\/\.credentials\.json$/i,
	/(^|\/)\.grok\/user-settings\.json$/i,
	/(^|\/)\.copilot\/providers\.json$/i,
	/(^|\/)\.cline\/data\/secrets\.json$/i,
	/(^|\/)goose\/secrets\.ya?ml$/i,
	/(^|\/)(credentials|secrets?|service[-_]?account[^/]*)\.json$/i,
];

export const DOWNLOADS_LIKE = /^(downloads?|desktop|temp|tmp)$/i;

// The folders agents keep their settings in at the top of a project, such
// as .claude. A check reads these first.
export const TOOL_ROOT = /^\.(claude|codex|gemini|cursor|grok|opencode|windsurf|roo|kiro|amazonq|continue|zed|junie|github|vscode)$/i;

// A name at the top of a project that would read as a place on the computer,
// such as a folder named "~" or "C:". The checks tell files on the computer
// from the project's by how their paths start, so these are left out: a
// project can't stand in for the settings in the home folder.
export const computerLikeName = (name) => /^(?:~|[A-Za-z]:)/.test(name);

// Control characters in a name, shown as the symbols Unicode has for them
// (␊ for a line break, ␛ for escape), and characters that reorder text shown
// as the replacement character, U+FFFD. A name then can't break a line or
// color a terminal, and the patterns here, which don't match line breaks,
// still see the file. Agents read a file whatever its name.
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
export const visibleName = (text) =>
	text.replace(CONTROL_CHARS, (c) => {
		const n = c.charCodeAt(0);
		return n < 0x20 ? String.fromCharCode(0x2400 + n) : n === 0x7f ? "\u2421" : "\ufffd";
	});

// Code an agent loads as plugins or tools as soon as it starts in a project.
// Listed by name, never read.
export const PLUGIN_CODE = /(^|\/)(\.opencode\/(plugins?|tools)|\.amp\/plugins|\.cline\/plugins)\/[^/]+\.[cm]?[jt]sx?$/i;

// Instruction files too large to read whole are checked from their start,
// where an agent reads first. Settings files aren't: half a JSON file can't
// be read at all.
export const readsInPart = (path) => /\.(md|mdc|txt)$/i.test(path) || /(^|\/)\.(cursorrules|windsurfrules|clinerules|goosehints)$/i.test(path);

export const LIMITS = {
	maxEntries: 60000,
	maxFiles: 300,
	maxFileBytes: 400 * 1024,
	maxTotalBytes: 4 * 1024 * 1024,
	maxLooseMarkdown: 25,
};

// A skill is a folder. Agents read its SKILL.md and open the other files in
// it, such as reference docs and scripts, only when SKILL.md sends them
// there, so those files are part of the skill, not settings of their own.
const IN_SKILL = /(^|\/)\.[^/]+\/(?:.+\/)?skills\/[^/]+\/.+$/i;
const SKILL_MD = /(^|\/)SKILL\.md$/i;
// Compiled programs, native modules and installers in a skill folder are
// listed by name, never read: a skill is meant to be text you can review.
// Archives count too: what's inside can't be read either.
export const SKILL_PROGRAM = /\.(?:exe|dll|so(?:\.\d+)*|dylib|node|bin|pkg|dmg|msi|msix|deb|rpm|jar|scr|apk|appimage|wasm|zip|7z|rar|tar|tgz|gz|xz|bz2)$|\.app\//i;

// A folder inside a skill that's worth looking in. Folders that are skipped
// elsewhere, such as bin and dist, are looked in there, since that's where a
// skill would keep a program. Package installs and version control never
// are: they can hold tens of thousands of files.
const HEAVY_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".pnpm-store", ".yarn", ".npm", ".cargo", ".rustup", ".m2", ".nuget", ".gradle", ".terraform"]);
export const insideSkill = (relDir) => IN_SKILL.test(visibleName(`${relDir}/x`)) && !HEAVY_DIRS.has(relDir.split("/").pop());

export function classifyPath(rawPath, { looseMarkdown = false } = {}) {
	const relPath = visibleName(rawPath);
	if (SENSITIVE.some((re) => re.test(relPath))) return "sensitive";
	// Only what's inside the skill's folder counts, and never its SKILL.md, so
	// a skill folder named like an app bundle is still read.
	if (IN_SKILL.test(relPath) && !SKILL_MD.test(relPath) && SKILL_PROGRAM.test(relPath.replace(/^.*?\/skills\/[^/]+\//i, ""))) return "listed";
	if (PLUGIN_CODE.test(relPath)) return "listed";
	if (CONTENT.some((re) => re.test(relPath))) return IN_SKILL.test(relPath) && !SKILL_MD.test(relPath) ? null : "content";
	if (looseMarkdown && !relPath.includes("/") && /\.(md|mdc|txt)$/i.test(relPath)) return "loose";
	return null;
}

export function isSkippedDir(name) {
	return SKIP_DIRS.has(name);
}
