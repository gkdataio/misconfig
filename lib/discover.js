// Finds the files that control AI agents: in the project folder, in the home
// folder and app settings, and in risky folders an agent has been started in.
// Everything is read and checked on this computer.

import { promises as fs, constants } from "node:fs";
import os from "node:os";
import path from "node:path";
import { maskSecrets } from "../engine/mask.js";
import { decodeText } from "../engine/decode.js";
import { classifyPath, isSkippedDir, insideSkill, computerLikeName, readsInPart, LIMITS, HOME_MARKERS, DOWNLOADS_LIKE, TOOL_ROOT } from "../engine/paths.js";
import { LOCATIONS, userPaths } from "../engine/locations.js";
import { riskyPlace, agentFolders } from "../engine/index.js";
import { namedInstructions, pickNamed, NAMING_SETTINGS } from "../engine/named.js";
import { TRACES, AGENT_PACKAGES, KNOWN_PACKAGES, VERSION_RE } from "../engine/known.js";

export const PLATFORM = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "mac" : "linux";
const LOOSE_NAMES = /\.(md|mdc|txt)$/i;

// `limits` is for tests; the command always uses LIMITS from the engine.
export async function discover({ dir = process.cwd(), includeUser = true, home = homeDir(), env = process.env, limits = LIMITS } = {}) {
	const projectDir = path.resolve(dir);
	const info = await fs.stat(projectDir).catch(() => null);
	if (!info?.isDirectory()) throw new Error(`There's no folder at ${projectDir}.`);
	const withUser = includeUser && Boolean(home);
	const files = [];
	const seen = new Set();
	const lineMaps = {};
	let masked = 0;

	const tilde = (abs) => {
		if (home) {
			const rel = path.relative(home, abs);
			if (!rel) return "~";
			if (!rel.startsWith("..") && !path.isAbsolute(rel)) return "~/" + rel.split(path.sep).join("/");
		}
		return abs.split(path.sep).join("/");
	};
	const add = (enginePath, raw, size, extra = {}) => {
		if (seen.has(enginePath)) return;
		seen.add(enginePath);
		if (raw === null) return files.push({ path: enginePath, size, ...extra });
		const m = maskSecrets(raw);
		masked += m.count;
		files.push({ path: enginePath, size, content: m.text, ...extra });
	};
	// `budget` limits what's read in all from the project.
	const addFile = async (abs, enginePath, kind, maxBytes = LIMITS.maxFileBytes, extra = {}, budget = null) => {
		const stat = await fs.stat(abs).catch(() => null);
		if (!stat?.isFile()) return;
		if (kind === "sensitive") return add(enginePath, null, stat.size, { sensitive: true });
		if (kind === "listed") return add(enginePath, null, stat.size, { listed: true });
		// A loose text file only counts when it reads like orders to an agent,
		// which a file too large to read can't show.
		const room = budget ? Math.min(maxBytes, limits.maxTotalBytes - budget.bytes) : maxBytes;
		// Too large: an instruction file is checked from its start, anything else is listed.
		const tooLarge = async () => {
			if (kind === "loose") return;
			if (stat.size > maxBytes && room === maxBytes && readsInPart(enginePath)) {
				const start = await readLimited(abs, maxBytes, true);
				if (start.text !== null) {
					if (budget) budget.bytes += start.bytes;
					return add(enginePath, start.text, stat.size, { partial: true, ...extra });
				}
			}
			add(enginePath, null, stat.size, { tooLarge: true, ...extra });
		};
		if (stat.size > room) return tooLarge();
		const read = await readLimited(abs, room);
		if (read.tooLarge) return tooLarge();
		if (budget) budget.bytes += read.bytes;
		add(enginePath, read.text, stat.size, kind === "loose" ? { loose: true } : extra);
	};

	// --- The project folder --------------------------------------------------
	// Breadth first, so the files near the top, where agents look, are found
	// even in a folder too big to walk completely.
	const top = await readdir(projectDir);
	const topLevel = top.map((d) => d.name);
	const homeLike = topLevel.filter((n) => HOME_MARKERS.has(n)).length >= 3;
	const shape = { entries: 0, topLevel: topLevel.slice(0, 200), rootGit: topLevel.includes(".git"), gitRepos: 0, truncated: false };
	const scanningHome = Boolean(home) && samePath(projectDir, home);

	if (!scanningHome) {
		const looseMarkdown = DOWNLOADS_LIKE.test(path.basename(projectDir)) || homeLike;
		const gitRepos = new Set();
		const candidates = [];
		const consider = (abs, rel, entry) => {
			// Linked files count, since agents follow the link (CLAUDE.md is
			// often a link to AGENTS.md). Linked folders aren't followed.
			if (!entry.isFile() && !entry.isSymbolicLink()) return;
			const kind = classifyPath(rel, { looseMarkdown });
			if (kind) candidates.push({ abs, rel, kind, link: entry.isSymbolicLink() });
			// Kept by name, in case a settings file names it as instructions.
			else if (others.length < 120_000) others.push({ abs, rel, kind: "content", link: entry.isSymbolicLink() });
		};
		const others = [];
		// A linked folder is followed when it leads to a folder inside the
		// project, as agents follow it (.claude can be a link to config/claude).
		// Each real folder is walked once, so links can't make a loop.
		const root = await fs.realpath(projectDir).catch(() => projectDir);
		const walked = new Set([root]);
		const linkedFolder = async (abs, entry) => {
			if (!entry.isSymbolicLink() || !(await fs.stat(abs).catch(() => null))?.isDirectory()) return false;
			const real = await fs.realpath(abs).catch(() => null);
			if (!real) return null;
			// Agents follow a link out of the project too, so the check names it.
			if (!isInside(real, root)) return "outside";
			if (walked.has(real)) return null;
			walked.add(real);
			return true;
		};
		const outsideFolders = [];
		// The top of the folder first, all of it, then the agent folders there
		// (.claude, .cursor, .github and so on), each walk with its own
		// allowance, so a folder too big to walk still has them checked.
		const firstDirs = [];
		const otherDirs = [];
		for (const entry of top) {
			shape.entries++;
			if (computerLikeName(entry.name)) continue;
			const abs = path.join(projectDir, entry.name);
			const linked = await linkedFolder(abs, entry);
			if (linked === "outside") outsideFolders.push(entry.name);
			if (linked === null || linked === "outside") continue;
			if (entry.isDirectory() || linked) {
				if (entry.name === ".git") gitRepos.add("");
				if (TOOL_ROOT.test(entry.name)) firstDirs.push([abs, 1]);
				else if (!isSkippedDir(entry.name) || insideSkill(entry.name)) otherDirs.push([abs, 1]);
				continue;
			}
			consider(abs, entry.name, entry);
		}
		const walk = async (starts) => {
			const queue = [...starts];
			let entries = 0;
			for (let q = 0; q < queue.length; q++) {
				const [current, depth] = queue[q];
				for (const entry of await readdir(current)) {
					if (++entries > limits.maxEntries) return true;
					shape.entries++;
					const abs = path.join(current, entry.name);
					const rel = path.relative(projectDir, abs).split(path.sep).join("/");
					const linked = await linkedFolder(abs, entry);
					if (linked === "outside") outsideFolders.push(rel);
					if (linked === null || linked === "outside") continue;
					if (entry.isDirectory() || linked) {
						if (entry.name === ".git") gitRepos.add(path.relative(projectDir, current));
						if ((!isSkippedDir(entry.name) || insideSkill(rel)) && depth < 12) queue.push([abs, depth + 1]);
						continue;
					}
					consider(abs, rel, entry);
				}
			}
			return false;
		};
		if (await walk(firstDirs)) shape.truncated = true;
		if (await walk(otherDirs)) shape.truncated = true;
		shape.gitRepos = gitRepos.size;

		// Files that settings name as instructions, such as Gemini CLI's
		// context.fileName: the project's settings, and with the settings on
		// this computer, Gemini CLI's and Codex's own.
		const naming = [];
		for (const c of candidates.filter((x) => x.kind === "content" && !x.link && NAMING_SETTINGS.some((re) => re.test(x.rel)))) {
			const content = await readText(c.abs, limits.maxFileBytes);
			if (content !== null) naming.push({ path: c.rel, content });
		}
		if (withUser) {
			for (const [rel, abs] of [["~/.gemini/settings.json", path.join(home, ".gemini", "settings.json")], ["~/.codex/config.toml", path.join(env.CODEX_HOME || path.join(home, ".codex"), "config.toml")]]) {
				const content = await readText(abs, limits.maxFileBytes);
				if (content !== null) naming.push({ path: rel, content });
			}
		}
		candidates.push(...pickNamed(namedInstructions(naming), others, (o) => o.rel));
		// Read in order of importance, up to LIMITS: agent files, then the
		// .gitignore and package.json files some checks use, then files listed
		// by name, then loose text files.
		const helper = (p) => /(^|\/)(\.gitignore|package\.json)$/i.test(p);
		const order = (c) => (c.kind === "content" ? (helper(c.rel) ? 1 : 0) : c.kind === "sensitive" || c.kind === "listed" ? 2 : 3);
		candidates.sort((a, b) => order(a) - order(b) || a.rel.split("/").length - b.rel.split("/").length || (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
		for (const rel of outsideFolders.slice(0, 20)) add(rel, null, 0, { linked: "outside", folder: true });
		const budget = { files: 0, bytes: 0, loose: 0 };
		for (const c of candidates) {
			if (budget.files >= limits.maxFiles) {
				shape.truncated = true;
				break;
			}
			if (c.kind === "loose" && ++budget.loose > limits.maxLooseMarkdown) continue;
			budget.files++;
			// A link is only followed to a file inside the project that isn't a
			// credential file. Agents follow any link, so the others are reported.
			if (c.link && c.kind !== "sensitive" && c.kind !== "listed") {
				const target = await fs.realpath(c.abs).catch(() => null);
				if (!target) continue;
				const inside = isInside(target, root);
				if (!inside || classifyPath(path.relative(root, target).split(path.sep).join("/")) === "sensitive") {
					if (c.kind !== "loose") add(c.rel, null, 0, { linked: inside ? "secret" : "outside" });
					continue;
				}
			}
			await addFile(c.abs, c.rel, c.kind, limits.maxFileBytes, {}, budget);
		}
	}

	// git's own ignore lists, so files ignored there aren't reported as
	// exposed. Claude Code adds its local settings to the global one. These
	// apply to the project, so they're read with --project-only too.
	const ignoreLists = [];
	if (shape.rootGit) await readIgnoreList(path.join(projectDir, ".git", "info", "exclude"), ignoreLists);
	if (home) await readIgnoreList(path.join(env.XDG_CONFIG_HOME || path.join(home, ".config"), "git", "ignore"), ignoreLists);

	// --- The home folder and app settings ------------------------------------
	// Each file keeps its usual name (~/.claude/settings.json) even when an
	// environment variable moved it, so the checks still recognize it.
	if (withUser) {
		const userFiles = [];
		for (const entry of LOCATIONS) {
			for (const p of userPaths(entry, PLATFORM)) {
				for (const { abs, name } of await expand(resolveUserPath(p, { home, env }), p.startsWith("~") ? p : null)) {
					const enginePath = name ?? tilde(abs);
					if (!p.endsWith("/")) {
						userFiles.push({ abs, enginePath });
						continue;
					}
					// In a folder, only the files agents read.
					const nameOf = (f) => enginePath.replace(/\/?$/, "/") + path.relative(abs, f).split(path.sep).join("/");
					for (const f of await listFiles(abs, 4, (f) => ["content", "listed"].includes(classifyPath(nameOf(f))), (d) => insideSkill(nameOf(d)))) userFiles.push({ abs: f, enginePath: nameOf(f) });
				}
			}
		}
		// With CLAUDE_CONFIG_DIR set, ~/.claude.json may live in that folder.
		if (env.CLAUDE_CONFIG_DIR) userFiles.push({ abs: path.join(home, ".claude.json"), enginePath: "~/.claude.json" });
		for (const { abs, enginePath } of userFiles) {
			if (seen.has(enginePath)) continue;
			// Credential files belong in the home folder; only report them inside projects.
			const kind = classifyPath(enginePath);
			if (kind === "sensitive") continue;
			if (/(^|[\\/])\.claude\.json$/.test(abs)) {
				const stat = await fs.stat(abs).catch(() => null);
				const raw = stat?.isFile() ? await readText(abs) : null;
				if (raw === null) continue;
				const reduced = reduceClaudeJson(raw, tilde);
				add(enginePath, reduced.text, stat.size);
				if (reduced.lineMap) lineMaps[enginePath] = reduced.lineMap;
				continue;
			}
			await addFile(abs, enginePath, kind === "listed" ? "listed" : "content");
		}
	}

	// --- Claude Code plugins ---------------------------------------------------
	// The hooks, MCP servers, commands and agents of each installed plugin.
	// The user's installed_plugins.json says where each one is; other copies
	// on disk, such as whole marketplaces, aren't in use and aren't read.
	const installed = withUser ? files.find((f) => f.path === "~/.claude/plugins/installed_plugins.json" && f.content) : null;
	if (installed) {
		const root = path.dirname(resolveUserPath("~/.claude/plugins/installed_plugins.json", { home, env }));
		for (const dir of pluginFolders(installed.content, projectDir).slice(0, 100)) {
			const abs = path.resolve(root, dir);
			if (!isInside(abs, root)) continue;
			for (const f of await listFiles(abs, 4, (f) => ["content", "listed"].includes(classifyPath(tilde(f))), (d) => insideSkill(tilde(d)))) await addFile(f, tilde(f), classifyPath(tilde(f)));
			// plugin.json can keep hooks and MCP servers somewhere else in the plugin.
			const manifest = files.find((f) => f.path === tilde(path.join(abs, ".claude-plugin", "plugin.json")) && f.content);
			for (const [key, role] of [["hooks", "claude-hooks"], ["mcpServers", "mcp-servers"]]) {
				const target = manifestPath(manifest?.content, key);
				const file = target && path.resolve(abs, target);
				if (file && isInside(file, abs)) await addFile(file, tilde(file), "content", LIMITS.maxFileBytes, { role });
			}
		}
	}

	// --- Risky folders an agent has been started in --------------------------
	// If an agent has run in, or trusts, Downloads or the home folder, check
	// the loose instruction files there too. Only the settings on this
	// computer say where agents have run; a project's own copies don't count.
	const risky = new Set();
	for (const f of withUser ? files : []) {
		if (!f.content || !/^(~|\/|[A-Za-z]:)/.test(f.path)) continue;
		for (const d of agentFolders(f.path, f.content)) if (riskyPlace(d)) risky.add(d.startsWith("~") ? d : tilde(path.resolve(d)));
	}
	for (const d of risky) {
		const abs = d === "~" ? home : d.startsWith("~/") ? path.join(home, ...d.slice(2).split("/")) : d;
		if (samePath(abs, projectDir)) continue;
		let count = 0;
		for (const entry of await readdir(abs)) {
			if (!(entry.isFile() || entry.isSymbolicLink()) || !LOOSE_NAMES.test(entry.name) || ++count > LIMITS.maxLooseMarkdown) continue;
			await addFile(path.join(abs, entry.name), tilde(path.join(abs, entry.name)), "loose", 200 * 1024);
		}
	}

	// --- What's installed -----------------------------------------------------
	// Agent installs and editor extensions on this computer, and files that
	// attacks leave, by name and version only. The project's own copies of
	// packages that were malware are checked even with --project-only.
	const installs = scanningHome ? [] : await projectPackages(projectDir);
	const locked = scanningHome ? [] : await lockedPackages(projectDir);
	let extensions = [];
	let traces = [];
	if (withUser) {
		installs.push(...(await agentInstalls({ home, env, tilde })));
		extensions = await editorExtensions({ home, env, tilde });
		traces = await traceFiles({ home, env });
	}

	return {
		root: path.basename(projectDir) || projectDir,
		shape,
		files,
		ignoreLists,
		masked: { count: masked },
		lineMaps,
		installs,
		locked,
		extensions,
		traces,
		scanned: { project: tilde(projectDir), projectSkipped: scanningHome, user: withUser },
	};
}

const byVersion = (a, b) => a.localeCompare(b, undefined, { numeric: true });

// package.json's name and version, or null. Small files only.
async function packageVersion(file) {
	const stat = await fs.stat(file).catch(() => null);
	if (!stat?.isFile() || stat.size > 512 * 1024) return null;
	try {
		const json = JSON.parse((await readText(file)) ?? "");
		return typeof json?.name === "string" && typeof json?.version === "string" && VERSION_RE.test(json.version) ? { name: json.name, version: json.version } : null;
	} catch {
		return null;
	}
}

// The npm packages known.js lists, including any added from today's list.
const npmKnown = () => Object.keys(KNOWN_PACKAGES).filter((k) => k.startsWith("npm:")).map((k) => k.slice(4));

// The package names in a node_modules folder, scoped ones included.
async function installedNames(dir) {
	const names = new Set();
	for (const entry of (await readdir(dir)).slice(0, 20_000)) {
		if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
		if (!entry.name.startsWith("@")) names.add(entry.name);
		else for (const inner of (await readdir(path.join(dir, entry.name))).slice(0, 5000)) names.add(`${entry.name}/${inner.name}`);
	}
	return names;
}

// Versions of packages that were malware, in the project's node_modules.
async function projectPackages(projectDir) {
	const out = [];
	const here = await installedNames(path.join(projectDir, "node_modules"));
	for (const name of npmKnown().filter((n) => here.has(n))) {
		const found = await packageVersion(path.join(projectDir, "node_modules", ...name.split("/"), "package.json"));
		if (found?.name === name) out.push({ package: name, version: found.version, via: "project", path: `node_modules/${name}` });
	}
	// pnpm keeps every package, including ones other packages pulled in, in
	// node_modules/.pnpm, in folders named name@version (@scope+name@version).
	// The names say enough; nothing in them is read.
	const known = new Set(npmKnown());
	for (const entry of (await readdir(path.join(projectDir, "node_modules", ".pnpm"))).slice(0, 30_000)) {
		const m = entry.isDirectory() ? entry.name.match(/^((?:@[^+@/]+\+)?[^+@/]+)@([^_/]+)/) : null;
		const name = m ? m[1].replace("+", "/") : null;
		if (!name || !known.has(name) || !VERSION_RE.test(m[2])) continue;
		if (out.some((i) => i.package === name && i.version === m[2])) continue;
		out.push({ package: name, version: m[2], via: "project", path: `node_modules/.pnpm/${entry.name}/node_modules/${name}` });
	}
	return out;
}

// Versions of packages that were malware, pinned in the project's lockfile,
// so a check before installing (in CI, say) still finds them. Only names and
// versions are looked for: in the registry addresses npm and Yarn write
// (/nx/-/nx-21.5.0.tgz), in npm's entries ("node_modules/nx": { "version":
// "21.5.0" }, which have no address when omit-lockfile-registry-resolved is
// set), and in the name@version keys pnpm, Bun and Yarn 2+ write (/nx/21.5.0
// in pnpm's older lockfiles). Nothing else in the file is kept.
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];
const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const SEMVER = String.raw`\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,40})?`;
// Any package name; the ones that count are picked out after, so the patterns
// stay as fast with thousands of known names as with a few.
const NAME = String.raw`(?:@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9][a-z0-9._~-]{0,213}`;
const LOCKED_URL = new RegExp(String.raw`/(${NAME})/-/[a-z0-9][a-z0-9._~-]{0,213}-(${SEMVER})\.tgz`, "g");
const LOCKED_KEY = new RegExp(String.raw`(?:^|["'/\s])(${NAME})@(?:npm:)?(${SEMVER})(?=["'\s:(_,]|$)`, "gm");
// npm's own entries, nested or not, and lockfile version 1's "nx": { "version" }.
const LOCKED_ENTRY = new RegExp(String.raw`"(?:node_modules/(?:[^"\n]{0,400}?/node_modules/)?)?(${NAME})":\s{0,20}\{[^{}]{0,2000}?"version":\s{0,20}"(${SEMVER})"`, "g");
const LOCKED_PNPM = new RegExp(String.raw`^\s{0,8}['"]?/(${NAME})/(${SEMVER})(?=[:_('"]|$)`, "gm");
async function lockedPackages(projectDir) {
	const known = new Set(npmKnown());
	const out = [];
	for (const file of LOCKFILES) {
		const abs = path.join(projectDir, file);
		const stat = await fs.stat(abs).catch(() => null);
		if (!stat?.isFile() || stat.size > MAX_LOCKFILE_BYTES) continue;
		const text = await fs.readFile(abs, "utf8").catch(() => "");
		const seen = new Set();
		for (const re of [LOCKED_URL, LOCKED_KEY, LOCKED_ENTRY, LOCKED_PNPM]) {
			for (const m of text.matchAll(re)) {
				const key = `${m[1]}@${m[2]}`;
				// An npm alias ("node_modules/nx": { "name": "other" }) is some other package.
				if (re === LOCKED_ENTRY && m[0].includes('"name":')) continue;
				if (!known.has(m[1]) || seen.has(key) || seen.size >= 200) continue;
				seen.add(key);
				out.push({ file, package: m[1], version: m[2] });
			}
		}
	}
	return out;
}

// Folders where npm, pnpm, bun and Node version managers keep global packages.
async function globalPackageDirs({ home, env }) {
	const at = (...parts) => path.join(home, ...parts);
	const each = async (pattern) => (await expand(pattern, null)).map((x) => x.abs);
	const dirs =
		PLATFORM === "windows"
			? [
					env.APPDATA && path.join(env.APPDATA, "npm", "node_modules"),
					env.ProgramFiles && path.join(env.ProgramFiles, "nodejs", "node_modules"),
					...(env.APPDATA ? await each(path.join(env.APPDATA, "nvm", "v*", "node_modules")) : []),
					env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, "pnpm", "global", "5", "node_modules"),
					at(".bun", "install", "global", "node_modules"),
				]
			: [
					"/usr/local/lib/node_modules",
					"/opt/homebrew/lib/node_modules",
					"/usr/lib/node_modules",
					at(".npm-global", "lib", "node_modules"),
					at(".local", "lib", "node_modules"),
					at(".bun", "install", "global", "node_modules"),
					...(await each(at(".nvm", "versions", "node", "*", "lib", "node_modules"))),
					...(await each(at(".asdf", "installs", "nodejs", "*", "lib", "node_modules"))),
					...(await each(at(".local", "share", "fnm", "node-versions", "*", "installation", "lib", "node_modules"))),
					...(await each(at("Library", "Application Support", "fnm", "node-versions", "*", "installation", "lib", "node_modules"))),
					...(await each(at(".local", "share", "pnpm", "global", "*", "node_modules"))),
					...(await each(at("Library", "pnpm", "global", "*", "node_modules"))),
				];
	if (env.NPM_CONFIG_PREFIX) dirs.push(PLATFORM === "windows" ? path.join(env.NPM_CONFIG_PREFIX, "node_modules") : path.join(env.NPM_CONFIG_PREFIX, "lib", "node_modules"));
	return [...new Set(dirs.filter(Boolean))].slice(0, 60);
}

// Installed AI agents and their versions, read from package.json files,
// version folders and app bundles. Nothing is run.
async function agentInstalls({ home, env, tilde }) {
	const out = [];
	const seen = new Set();
	const push = (pkg, version, via, abs) => {
		const key = `${pkg}|${version}|${abs}`;
		if (seen.has(key) || !VERSION_RE.test(version)) return;
		seen.add(key);
		out.push({ package: pkg, version, via, path: tilde(abs), platform: PLATFORM });
	};
	const npmPackages = [...Object.keys(AGENT_PACKAGES).filter((p) => p !== "Claude Desktop"), ...npmKnown()];
	for (const dir of await globalPackageDirs({ home, env })) {
		// Only the names installed there are looked at, so a long list of known
		// packages costs one folder listing, not a look for each name.
		const here = await installedNames(dir);
		for (const name of npmPackages.filter((n) => here.has(n))) {
			const found = await packageVersion(path.join(dir, ...name.split("/"), "package.json"));
			if (found?.name === name) push(name, found.version, /pnpm/i.test(dir) ? "pnpm" : /[\\/]\.bun[\\/]/.test(dir) ? "bun" : "npm", path.join(dir, ...name.split("/")));
		}
	}
	const voltaRoot = PLATFORM === "windows" && env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, "Volta") : path.join(home, ".volta");
	const volta = await installedNames(path.join(voltaRoot, "tools", "image", "packages"));
	for (const name of npmPackages.filter((n) => volta.has(n))) {
		const image = path.join(voltaRoot, "tools", "image", "packages", ...name.split("/"));
		// Volta keeps the package under lib/node_modules, or node_modules on Windows.
		for (const lib of [["lib", "node_modules"], ["node_modules"]]) {
			const found = await packageVersion(path.join(image, ...lib, ...name.split("/"), "package.json"));
			if (found?.name === name) push(name, found.version, "volta", image);
		}
	}
	// Claude Code's own installer keeps each version in a folder named after
	// it and links the one in use from ~/.local/bin. Its older local install
	// has a package.json.
	const versions = path.join(home, ".local", "share", "claude", "versions");
	const launcher = await fs.readlink(path.join(home, ".local", "bin", PLATFORM === "windows" ? "claude.exe" : "claude")).catch(() => null);
	const native = (await readdir(versions)).map((d) => d.name).filter((n) => VERSION_RE.test(n)).sort(byVersion);
	const active = launcher ? path.basename(launcher) : null;
	const current = active && native.includes(active) ? active : native.pop();
	if (current) push("@anthropic-ai/claude-code", current, "native", path.join(versions, current));
	const local = await packageVersion(path.join(home, ".claude", "local", "node_modules", "@anthropic-ai", "claude-code", "package.json"));
	if (local?.name === "@anthropic-ai/claude-code") push("@anthropic-ai/claude-code", local.version, "local", path.join(home, ".claude", "local"));
	// Homebrew formulas and casks, by their version folders.
	if (PLATFORM !== "windows") {
		const brews = [["@anthropic-ai/claude-code", "Caskroom/claude-code"], ["@openai/codex", "Cellar/codex"], ["@openai/codex", "Caskroom/codex"], ["@google/gemini-cli", "Cellar/gemini-cli"]];
		for (const prefix of ["/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"]) {
			for (const [pkg, name] of brews) {
				const dir = path.join(prefix, ...name.split("/"));
				// A rebuilt formula's folder ends in _1, _2 and so on.
				const found = (await readdir(dir)).map((d) => d.name).filter((n) => VERSION_RE.test(n.replace(/_\d+$/, ""))).sort(byVersion).pop();
				if (found) push(pkg, found.replace(/_\d+$/, ""), "homebrew", path.join(dir, found));
			}
		}
	}
	// Claude Desktop: the app bundle's version on macOS, the app-<version>
	// folders on Windows.
	if (PLATFORM === "mac") {
		for (const app of ["/Applications/Claude.app", path.join(home, "Applications", "Claude.app")]) {
			const file = path.join(app, "Contents", "Info.plist");
			const stat = await fs.stat(file).catch(() => null);
			const plist = stat?.isFile() && stat.size < 200_000 ? ((await readText(file)) ?? "") : "";
			const m = plist.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]{1,40})<\/string>/);
			if (m) push("Claude Desktop", m[1].trim(), "app", app);
		}
	} else if (PLATFORM === "windows" && env.LOCALAPPDATA) {
		const dir = path.join(env.LOCALAPPDATA, "AnthropicClaude");
		const latest = (await readdir(dir)).map((d) => d.name.match(/^app-(.+)$/)?.[1]).filter((v) => v && VERSION_RE.test(v)).sort(byVersion).pop();
		if (latest) push("Claude Desktop", latest, "app", path.join(dir, `app-${latest}`));
	}
	return out;
}

// Editor extensions: VS Code and the editors built on it keep a list in
// extensions.json and a folder per extension named publisher.name-version.
const EDITOR_DIRS = [
	["VS Code", ".vscode"],
	["VS Code Insiders", ".vscode-insiders"],
	["VSCodium", ".vscode-oss"],
	["Cursor", ".cursor"],
	["Windsurf", ".windsurf"],
	["Kiro", ".kiro"],
];
const EXTENSION_FOLDER = /^([a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*?)-(\d+\.\d+\.\d+(?:-[0-9a-z.]+?)?)(?:-(?:darwin|linux|win32|alpine|web)(?:-[a-z0-9]+)?)?$/i;
async function editorExtensions({ home, env, tilde }) {
	const out = [];
	for (const [editor, folder] of EDITOR_DIRS) {
		const dir = editor === "VS Code" && env.VSCODE_EXTENSIONS ? env.VSCODE_EXTENSIONS : path.join(home, folder, "extensions");
		const entries = await readdir(dir);
		if (!entries.length) continue;
		const items = new Map();
		const list = path.join(dir, "extensions.json");
		const stat = await fs.stat(list).catch(() => null);
		if (stat?.isFile() && stat.size <= 4 * 1024 * 1024) {
			let json = null;
			try {
				json = JSON.parse((await readText(list)) ?? "");
			} catch {}
			for (const e of Array.isArray(json) ? json.slice(0, 3000) : []) {
				const id = typeof e?.identifier?.id === "string" ? e.identifier.id.toLowerCase() : null;
				const version = typeof e?.version === "string" ? e.version : "";
				const folder = typeof e?.relativeLocation === "string" && /^[^/\\]{1,250}$/.test(e.relativeLocation) && e.relativeLocation !== ".." ? e.relativeLocation : null;
				if (id) items.set(`${id}@${version}`, { id, version, source: typeof e?.metadata?.source === "string" ? e.metadata.source : null, folder });
			}
		}
		// Folders on disk too, including old versions not cleaned up yet.
		for (const entry of entries.slice(0, 3000)) {
			const m = entry.isDirectory() ? entry.name.match(EXTENSION_FOLDER) : null;
			if (m && !items.has(`${m[1].toLowerCase()}@${m[2]}`)) items.set(`${m[1].toLowerCase()}@${m[2]}`, { id: m[1].toLowerCase(), version: m[2], source: null, folder: entry.name });
		}
		const found = [...items.values()];
		for (let i = 0; i < found.length; i += 16) await Promise.all(found.slice(i, i + 16).map(async (x) => (x.published = await publishedId(dir, x))));
		if (found.length) out.push({ editor, dir: tilde(dir), items: found.map(({ folder, ...x }) => x) });
	}
	return out;
}

// An extension's ID with the capitals its publisher gave it, from the
// publisher and name fields of its package.json, or null. OSV.dev needs it
// to find the extension; nothing else in the file is kept.
async function publishedId(dir, item) {
	if (!item.folder) return null;
	const file = path.join(dir, item.folder, "package.json");
	const stat = await fs.stat(file).catch(() => null);
	if (!stat?.isFile() || stat.size > 4 * 1024 * 1024) return null;
	try {
		const json = JSON.parse((await readText(file)) ?? "");
		const id = typeof json?.publisher === "string" && typeof json?.name === "string" ? `${json.publisher}.${json.name}` : "";
		return id.toLowerCase() === item.id ? id : null;
	} catch {
		return null;
	}
}

// Files attacks leave, checked by name only. Their contents are never read.
async function traceFiles({ home, env }) {
	const found = [];
	for (const t of TRACES) {
		if (t.platforms && !t.platforms.includes(PLATFORM)) continue;
		for (const p of t.paths) {
			if (p.startsWith("~/AppData/") && PLATFORM !== "windows") continue;
			// Where the attack wrote them: the home folder itself, not a folder
			// an environment variable points at.
			const abs = p.startsWith("~/AppData/Roaming/") && env.APPDATA ? path.join(env.APPDATA, ...p.slice("~/AppData/Roaming/".length).split("/")) : p.startsWith("~/") ? path.join(home, ...p.slice(2).split("/")) : path.normalize(p);
			if (await fs.lstat(abs).catch(() => null)) found.push(p);
		}
	}
	return found;
}


// "~/..." and "{config}" style paths from locations.js, honoring the
// environment variables agents use to move their settings.
export function resolveUserPath(p, { home, env }) {
	const rel = p;
	if (env.CLAUDE_CONFIG_DIR && rel === "~/.claude.json") return path.join(env.CLAUDE_CONFIG_DIR, ".claude.json");
	if (env.CLAUDE_CONFIG_DIR && rel.startsWith("~/.claude/")) return path.join(env.CLAUDE_CONFIG_DIR, rel.slice("~/.claude/".length));
	if (env.CODEX_HOME && rel.startsWith("~/.codex/")) return path.join(env.CODEX_HOME, rel.slice("~/.codex/".length));
	if (env.COPILOT_HOME && rel.startsWith("~/.copilot/")) return path.join(env.COPILOT_HOME, rel.slice("~/.copilot/".length));
	if (PLATFORM === "windows" && env.APPDATA && rel.startsWith("~/AppData/Roaming/")) return path.join(env.APPDATA, rel.slice("~/AppData/Roaming/".length));
	if (PLATFORM === "linux" && env.XDG_CONFIG_HOME && rel.startsWith("~/.config/")) return path.join(env.XDG_CONFIG_HOME, rel.slice("~/.config/".length));
	if (rel.startsWith("~/")) return path.join(home, ...rel.slice(2).split("/"));
	return path.normalize(rel);
}

// ~/.claude.json can be large and holds account data. Keep only what the
// checks need, in the original order: MCP servers, the folders Claude Code
// has been started in and their tool approvals. lineMap[i] is the line in
// the real file that reduced line i + 1 came from, so findings point at
// lines people can open.
function reduceClaudeJson(raw, tilde) {
	let json;
	try {
		json = JSON.parse(raw);
	} catch {
		return { text: "{}", lineMap: null };
	}
	if (!json || typeof json !== "object") return { text: "{}", lineMap: null };
	const keys = new Map(); // reduced key, as JSON, -> key in the real file, as JSON
	const out = {};
	for (const [k, v] of Object.entries(json)) {
		if (k === "mcpServers") out[k] = v;
		if (k !== "projects" || !v || typeof v !== "object") continue;
		out.projects = {};
		for (const [dir, p] of Object.entries(v)) {
			const key = tilde(path.resolve(dir));
			keys.set(JSON.stringify(key), JSON.stringify(dir));
			out.projects[key] = Object.fromEntries(Object.entries(p && typeof p === "object" ? p : {}).filter(([name]) => name === "allowedTools" || name === "mcpServers"));
		}
	}
	const text = JSON.stringify(out, null, 2);
	const norm = (line) => line.trim().replace(/,$/, "");
	// Where each line of the real file is, by its text, so finding the next
	// match is a lookup however the file is formatted.
	const at = new Map();
	raw.split(/\r?\n/).forEach((line, i) => {
		const key = norm(line);
		if (!at.has(key)) at.set(key, []);
		at.get(key).push(i);
	});
	const next = (want, from) => {
		const list = at.get(want);
		if (!list) return -1;
		let lo = 0;
		let hi = list.length;
		while (lo < hi) {
			const mid = (lo + hi) >> 1;
			if (list[mid] < from) lo = mid + 1;
			else hi = mid;
		}
		return lo < list.length ? list[lo] : -1;
	};
	let cursor = 0;
	const lineMap = text.split("\n").map((line) => {
		let want = norm(line);
		const colon = want.indexOf('": ');
		if (colon > 0 && keys.has(want.slice(0, colon + 1))) want = keys.get(want.slice(0, colon + 1)) + want.slice(colon + 1);
		const exact = next(want, cursor);
		const open = want.endsWith("{}") ? next(want.slice(0, -1), cursor) : -1;
		const i = exact < 0 ? open : open < 0 ? exact : Math.min(exact, open);
		if (i < 0) return null;
		cursor = i + 1;
		return i + 1;
	});
	return { text, lineMap };
}

// Where each installed plugin that applies here lives. Version 1 of the file
// maps each plugin to one install, version 2 to a list: installs for the
// user apply everywhere, and project and local installs only in their own
// project. A plugin installed more than once runs from its latest install.
function pluginFolders(text, projectDir) {
	let json;
	try {
		json = JSON.parse(text);
	} catch {
		return [];
	}
	const plugins = json && typeof json.plugins === "object" && !Array.isArray(json.plugins) ? Object.values(json.plugins) : [];
	const applies = (p) =>
		p && typeof p === "object" && typeof p.installPath === "string" &&
		(p.scope === undefined || p.scope === "user" || p.scope === "managed" || (typeof p.projectPath === "string" && samePath(p.projectPath, projectDir)));
	const when = (p) => Date.parse(p.lastUpdated ?? p.installedAt ?? "") || 0;
	return plugins
		.map((p) => (Array.isArray(p) ? p : [p]).filter(applies))
		.filter((installs) => installs.length)
		.map((installs) => installs.reduce((a, b) => (when(b) >= when(a) ? b : a)).installPath);
}

// A path that plugin.json gives for its hooks or MCP servers, such as
// "./config/hooks.json". Hooks written into plugin.json itself are checked
// with the manifest.
function manifestPath(text, key) {
	try {
		const value = JSON.parse(text ?? "null")?.[key];
		return typeof value === "string" ? value : null;
	} catch {
		return null;
	}
}

function isInside(child, parent) {
	const rel = path.relative(parent, child);
	return Boolean(rel) && !rel.startsWith("..") && !path.isAbsolute(rel);
}

// The real paths a location names, as { abs, name }. "*" matches any one
// folder or file name. `name` is the "~/..." form with the matches filled
// in, when the location is written that way.
async function expand(abs, pattern) {
	// The root, such as /, C:\ or \\server\share\, is kept as it is.
	const { root } = path.parse(abs);
	let found = [{ abs: root, names: [] }];
	for (const part of abs.slice(root.length).split(/[\\/]+/)) {
		if (!part) continue;
		if (!part.includes("*")) {
			found = found.map((f) => ({ ...f, abs: path.join(f.abs, part) }));
			continue;
		}
		const re = new RegExp(`^${part.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
		const next = [];
		for (const f of found) {
			for (const entry of await readdir(f.abs)) if (re.test(entry.name) && next.length < 200) next.push({ abs: path.join(f.abs, entry.name), names: [...f.names, entry.name] });
		}
		found = next;
	}
	return found.map((f) => {
		let i = 0;
		const name = pattern ? pattern.split("/").map((seg) => (seg.includes("*") ? f.names[i++] : seg)).join("/") : null;
		return { abs: f.abs, name };
	});
}

// A file's text, read through one handle and never past `max` bytes, so a
// file that grows while it's read, or a special file put in its place, can't
// be read past the limit or hold the check up. `bytes` is how much was read.
async function readLimited(abs, max, start = false) {
	let handle = null;
	try {
		handle = await fs.open(abs, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
		if (!(await handle.stat()).isFile()) return { text: null, bytes: 0 };
		const chunks = [];
		const chunk = Buffer.alloc(64 * 1024);
		let size = 0;
		for (;;) {
			const { bytesRead } = await handle.read(chunk, 0, chunk.length, size);
			if (!bytesRead) break;
			const keep = Math.min(bytesRead, max - size);
			if (start && keep > 0) chunks.push(Buffer.from(chunk.subarray(0, keep)));
			size += bytesRead;
			// With `start`, the first `max` bytes are kept and the rest isn't read.
			if (size > max) return start ? { text: decodeText(Buffer.concat(chunks, max)), bytes: max } : { text: null, bytes: size, tooLarge: true };
			if (!start) chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
		}
		return { text: decodeText(Buffer.concat(chunks, size)), bytes: size };
	} catch {
		return { text: null, bytes: 0 };
	} finally {
		await handle?.close().catch(() => {});
	}
}

async function readText(abs, max = 32 * 1024 * 1024) {
	return (await readLimited(abs, max)).text;
}

async function readIgnoreList(abs, into) {
	const stat = await fs.stat(abs).catch(() => null);
	if (!stat?.isFile() || stat.size > 64 * 1024) return;
	const content = await readText(abs);
	if (content) into.push({ content });
}

async function readdir(dir) {
	try {
		return await fs.readdir(dir, { withFileTypes: true });
	} catch {
		return [];
	}
}

// The files under `dir`, up to `depth` folders down, that `accept` takes.
// Breadth first, so each skill's SKILL.md is found before the reference
// files beneath it, and the limits count only accepted files plus a cap on
// everything looked at, so a folder of thousands of docs can't hide the
// files after it or hold up the check.
async function listFiles(dir, depth, accept, enter = () => false) {
	const out = [];
	const queue = [[dir, 0]];
	let looked = 0;
	for (let q = 0; q < queue.length; q++) {
		const [current, level] = queue[q];
		for (const entry of await readdir(current)) {
			if (++looked > 20_000 || out.length >= 300) return out;
			const abs = path.join(current, entry.name);
			if (entry.isDirectory()) {
				if (level < depth && (!isSkippedDir(entry.name) || enter(abs))) queue.push([abs, level + 1]);
			} else if ((entry.isFile() || entry.isSymbolicLink()) && accept(abs)) out.push(abs);
		}
	}
	return out;
}

function homeDir() {
	try {
		return os.homedir() || null;
	} catch {
		return null;
	}
}

function samePath(a, b) {
	const norm = (p) => path.resolve(p).replace(/[\\/]+$/, "");
	return PLATFORM === "linux" ? norm(a) === norm(b) : norm(a).toLowerCase() === norm(b).toLowerCase();
}
