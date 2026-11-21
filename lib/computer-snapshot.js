import { createHmac } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { controlFor, normalizeServer, packageSpec } from "../engine/index.js";
import { agentLines } from "../engine/explain.js";
import { parseJSONC, parseTOML, parseYAML } from "../engine/parse.js";
import { maskSecrets, isMasked, looksLikeToken } from "../engine/mask.js";
import { resolveUserPath } from "./discover.js";
import { LIMITS } from "../engine/paths.js";

const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const sortKeys = (_key, value) => object(value)
	? Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k]]))
	: value;

// Only the keyed digest of a value is kept. A credential rotation must change
// that digest even when both values have the same masked representation.
export function fingerprint(secret, value) {
	return createHmac("sha256", Buffer.from(secret, "hex")).update(JSON.stringify(value, sortKeys)).digest("hex");
}

function name(text) {
	return maskSecrets(String(text)).text.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, "�").slice(0, 160);
}

function word(value) {
	return typeof value === "string" && /^[\w.@/-]{1,100}$/.test(value) && !isMasked(maskSecrets(value).text) && !looksLikeToken(value);
}

function program(command) {
	const first = typeof command === "string" ? command.trim().match(/^[\w./\\-]+/)?.[0] : null;
	const base = first?.split(/[\\/]/).at(-1);
	return word(base) ? base : "command";
}

function serverSummary(def) {
	if (!object(def)) return "server definition";
	const { command, args, url } = normalizeServer("", def, null);
	const pkg = command ? packageSpec(command, args) : null;
	if (pkg && word(pkg.name) && (!pkg.version || /^\d+\.\d+\.\d+(?:[-+][\w.]+)?$/.test(pkg.version))) return pkg.name + (pkg.version ? "@" + pkg.version : " (unpinned)");
	// URLs can carry account names, private hostnames and token-like path
	// components. The history only needs to distinguish a remote server.
	if (typeof url === "string") return "remote server";
	return command ? program(command) : "server definition";
}

function hookSummary(hook) {
	const command = typeof hook === "string" ? hook : hook?.command ?? hook?.bash ?? hook?.powershell;
	if (typeof command !== "string") return typeof hook?.type === "string" && word(hook.type) ? hook.type : "hook definition";
	const exe = program(command);
	const args = command.trim().split(/\s+/);
	if (/^(?:npm|pnpm|yarn|bun)$/.test(exe) && args[1] === "run" && word(args[2])) return exe + " run " + args[2];
	const script = args[1]?.split(/[\\/]/).at(-1);
	if (/^(?:node|python3?|bash|sh|pwsh)$/.test(exe) && word(script) && /\.(js|mjs|cjs|py|sh|ps1)$/i.test(script)) return exe + " " + script;
	return exe;
}

const readableModes = new Set(["workspace-write", "read-only", "danger-full-access", "on-request", "on-failure", "never", "untrusted", "default", "plan", "acceptEdits", "bypassPermissions", "auto", "ask", "allow", "deny"]);
const privateValueContainer = /^(?:env|environment|envs|headers?|http[_-]?headers?)$/i;
const shellPolicy = /^shell[_-]?environment[_-]?policy$/i;
export const PRIVATE_SETTING_SUMMARY = "private setting";

function privateValueTrail(trail) {
	const parents = trail.slice(0, -1);
	if (parents.some((part) => privateValueContainer.test(part))) return true;
	return parents.some((part, index) => shellPolicy.test(part) && /^(?:set|env|environment)$/i.test(parents[index + 1] ?? ""));
}

// Kept separate for migration of histories written by the early 1.4 preview.
export function privateValueLabel(label) {
	const parts = String(label).split(" / ");
	return privateValueTrail(parts);
}

function settingSummary(value, key, privateValue) {
	if (privateValue) return PRIVATE_SETTING_SUMMARY;
	if (/token|secret|passw|credential|api.?key|auth.?key/i.test(key)) return "credential setting";
	if (typeof value === "boolean" || typeof value === "number") return String(value);
	if (readableModes.has(value)) return value;
	if (/^(model|provider|version|logLevel)$/i.test(key) && word(value)) return value;
	if (Array.isArray(value)) return value.length + (value.length === 1 ? " entry" : " entries");
	return value === null ? "unset" : "configured value";
}

// File contents live only during discovery. The ledger receives names, short
// descriptions and hashes, never argument lists, hook bodies or env values.
export function computerSnapshot(secret, { home = homedir(), env = process.env } = {}) {
	const items = {};
	const fileRevisions = new Map();
	const verified = new Set();
	const uncertain = new Set();
	const riskSources = new Map();
	const hash = (v) => fingerprint(secret, v);
	function collect(file, raw, flags = {}, original = raw) {
		if (flags.sensitive || flags.listed) return;
		const kind = controlFor(file)?.kind ?? flags.role;
		if (!kind) return;
		if (raw === null || flags.partial || flags.tooLarge || flags.invalid || raw.length > LIMITS.maxFileBytes) {
			uncertain.add(file);
			return;
		}
		const entries = {};
		function add(trail, label, value, summary, fields, subject) {
			const key = hash([file, trail]);
			const parts = fields && Object.fromEntries(Object.entries(fields).map(([k,v]) => [k, hash(v)]));
			entries[key] = { file, label: name(label), summary, hash: hash(value), ...(parts ? { parts } : {}), ...(subject ? { subject } : {}) };
		}
		function server(trail, id, def) {
			const fields = {};
			if (object(def)) for (const [k,v] of Object.entries(def)) {
				const group = /^(env|environment|envs)$/.test(k) ? "environment" : /header/i.test(k) ? "headers" : /^(args|command|cmd)$/.test(k) ? "launch" : /^(url|httpUrl|serverUrl)$/.test(k) ? "address" : "settings";
				(fields[group] ??= []).push([k,v]);
			}
			for (const list of Object.values(fields)) list.sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0);
			const scope = trail[0] === "projects" ? " in " + name(trail[1]) : "";
			add([...trail, id], "MCP " + name(id) + scope, def, serverSummary(def), fields, hash(["server", id]));
		}
		function hooks(trail, event, nodes) {
			const list = Array.isArray(nodes) ? nodes : [nodes];
			let ordinal = 0;
			for (const node of list) {
				const nested = object(node) && Array.isArray(node.hooks);
				const group = nested ? Object.fromEntries(Object.entries(node).filter(([k]) => k !== "hooks")) : null;
				for (const hook of nested ? node.hooks : [node]) {
					ordinal++;
					add([...trail, event, ordinal], "Hook " + event + " #" + ordinal, [group, hook], hookSummary(hook), { matcher: group, action: hook });
				}
			}
		}
		function visit(value, trail = []) {
			const key = trail.at(-1) ?? "";
			if (trail.length === 1 && kind === "Editor settings" && !/^(mcp$|mcp\.|chat\.|github\.copilot|cursor\.|windsurf\.|codeium\.|claudeCode\.)/i.test(key)) return;
			if (trail.length === 1 && /\/\.cline\/data\/globalState\.json$/i.test(file) && !["yoloModeToggled", "autoApprovalSettings"].includes(key)) return;
			const servers = /^(mcpServers|mcp_servers|context_servers|amp\.mcpServers)$/.test(key)
				|| (key === "mcp" && /opencode\.jsonc?$/i.test(file))
				|| (key === "servers" && (trail.at(-2) === "mcp" || /mcp\.json$/i.test(file)))
				|| (key === "extensions" && /goose\/config\.ya?ml$/i.test(file))
				|| (!trail.length && flags.role === "mcp-servers" && !value?.mcpServers);
			if (servers && object(value)) {
				for (const [id, def] of Object.entries(value)) server(trail, id, def);
			} else if (servers && Array.isArray(value)) {
				value.forEach((def, i) => server(trail, typeof def?.name === "string" ? def.name : String(i + 1), def));
			} else if (trail.at(-2) === "permissions" && /^(allow|ask|deny)$/.test(key) && Array.isArray(value) && value.every((v) => typeof v === "string")) {
				for (const rule of new Set(value)) {
					const tool = rule.match(/^([\w.*-]+)(?:\((.*)\))?$/);
					const what = tool && word(tool[1]) ? tool[1] + (tool[2] === "*" ? "(*)" : tool[2] ? " (" + program(tool[2]) + ")" : "") : "tool rule";
					add([...trail, rule], "Permission " + key, rule, what);
				}
			} else if (key === "hooks" && object(value)) {
				for (const [event, nodes] of Object.entries(value)) hooks(trail, event, nodes);
			} else if (key === "hooks" && Array.isArray(value)) {
				hooks(trail, "configured", value);
			} else if (object(value) && trail.length < 32) {
				for (const [k, v] of Object.entries(value)) visit(v, [...trail, k]);
			} else if (!(trail[0] === "projects" && key === "allowedTools" && !value?.length)) {
				add(trail, trail.map(name).join(" / ") || kind, value, settingSummary(value, key, privateValueTrail(trail)));
			}
		}
		try {
			const parser = /\.(jsonc?|kiro\.hook)$/i.test(file) ? parseJSONC : /\.toml$/i.test(file) ? parseTOML : /\.ya?ml$/i.test(file) ? parseYAML : null;
			if (parser) {
				const config = parser(raw);
				const unparsed = object(config) && !Object.keys(config).length && parser !== parseJSONC && raw.split(/\r?\n/).some((l) => l.trim() && !l.trim().startsWith("#") && l.trim() !== "{}");
				if (config === undefined || config === null || typeof config !== "object" || unparsed) {
					uncertain.add(file);
					return;
				}
				visit(config);
			} else if (kind === "Shell profile") {
				const lines = agentLines({ lines: raw.split(/\r?\n/) }).map((l) => l.text.trim());
				if (lines.length) add([], kind, lines, lines.length + " agent-related line(s)");
			} else {
				const text = raw.replace(/\r\n/g, "\n");
				const lines = text === "" ? 0 : text.replace(/\n$/, "").split("\n").length;
				add([], kind, text, lines + (lines === 1 ? " line" : " lines"));
			}
			Object.assign(items, entries);
			verified.add(file);
			if (typeof original === "string" && original.length <= LIMITS.maxFileBytes) fileRevisions.set(file, hash(original.replace(/\r\n/g, "\n")));
		} catch (err) {
			if (!(err instanceof RangeError)) throw err;
			uncertain.add(file);
		}
	}
	function inventory(input, installed) {
		// Use the same versions the scanner found. Native installers commonly
		// name the last path component after the version being replaced.
		for (const agent of installed.agents) {
			if (agent.via === "project") continue;
			const leaf = agent.path.split("/").at(-1);
			const file = [agent.version, "app-" + agent.version].includes(leaf) ? agent.path.slice(0, -(leaf.length + 1)) : agent.path;
			const key = hash(["install", file, agent.tool, agent.via]);
			items[key] = { file, label: agent.tool + " (" + agent.via + ")", summary: agent.version, hash: hash(agent.version) };
			verified.add(file);
		}
		for (const editor of installed.editors) {
			verified.add(editor.dir);
			const versions = new Map();
			for (const agent of editor.agents) {
				if (!versions.has(agent.id)) versions.set(agent.id, new Set());
				versions.get(agent.id).add(agent.version || "unknown version");
			}
			for (const [id, found] of versions) {
				const list = [...found].sort();
				items[hash(["extension", editor.dir, id])] = { file: editor.dir, label: editor.editor + " extension " + id, summary: list.join(", "), hash: hash(list), inventoryDirectory: true };
			}
		}
		for (const inst of input.installs) if (inst.via !== "project") riskSources.set(inst.path, hash([inst.package, inst.version]));
		for (const editor of input.extensions) {
			const items = editor.items.map((v) => [v.id, v.version, v.source]);
			items.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
			riskSources.set(editor.dir, hash(items));
		}
		for (const file of input.traces) riskSources.set(file, hash(["present", file]));
	}
	// Discovery can skip an unreadable file or directory. Only a confirmed
	// missing file is a removal; a file still on disk needs another check.
	async function checkMissing(prior) {
		const files = new Map(Object.values(prior).map((item) => [item.file, item]));
		await Promise.all([...files].filter(([f]) => !verified.has(f) && !uncertain.has(f)).map(async ([file, item]) => {
			try {
				const abs = resolveUserPath(file, { home, env });
				await stat(abs);
				if (item.inventoryDirectory && !(await readdir(abs)).length) return;
				uncertain.add(file);
			} catch (err) {
				if (err.code !== "ENOENT" && err.code !== "ENOTDIR") uncertain.add(file);
			}
		}));
	}
	return { items, verified, uncertain, riskSources, fileRevisions, collect, inventory, checkMissing };
}
