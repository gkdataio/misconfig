// --fix: makes the changes the report says it can, after showing each one
// and a yes. Only these, each one setting in one file:
//
//   permissions.defaultMode "bypassPermissions" -> "default" (Claude Code)
//   an allow rule that lets Claude Code run anything, taken out
//   approval_policy "never" -> "on-request", at the top of a Codex config
//   chat.tools.autoApprove true -> false (VS Code)
//   an MCP server's npx package pinned to the version npx has here
//
// Each file is read again from disk, never through a link, and changed in
// place in its own format, comments and all. A change is kept only if the
// file then reads back as exactly that change and nothing else. Every file
// is backed up to ~/.misconfig/backups before any is written, and each is
// replaced in one step, only if it's still what was read. Files outside the
// project and the home folder are never changed, and nothing goes over the
// network.

import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readdir, realpath, rm, stat } from "node:fs/promises";
import path from "node:path";
import { parseJSONC, parseTOML } from "../engine/parse.js";
import { FileError, makeFolder, moveInto, readUntrusted, shown, stageText } from "./files.js";
import { below, homeFolder, realFolder, samePath, within } from "./home.js";

const MAX_BYTES = 1024 * 1024;
const UNSAFE_KEY = new Set(["__proto__", "constructor", "prototype"]);
// A version the checks count as pinned.
const VERSION = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:[-+][\w.]{1,60})?$/;
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]{0,100}\/)?[a-z0-9][a-z0-9._~-]{0,213}$/i;
const sha256 = (data) => createHash("sha256").update(data).digest("hex");

// --- Planning ------------------------------------------------------------------

// What --fix would change, file by file: the edits that check out, and the
// ones that don't with why. Reads files, writes nothing.
export async function planFixes(result, input, { dir, home = homeFolder(), env = process.env }) {
	const project = await realFolder(dir);
	// Each file once, by where it is on disk: two names can lead to one file,
	// as with CLAUDE_CONFIG_DIR or CODEX_HOME.
	const files = [];
	for (const f of result.findings) {
		for (const place of [{ file: f.file, autofix: f.autofix }, ...(f.also ?? [])]) {
			if (!place.autofix || !place.file) continue;
			const abs = input.paths?.get(place.file) ?? null;
			const real = abs ? await realpath(abs).catch(() => null) : null;
			let entry = files.find((x) => (real && x.real ? samePath(x.real, real) : x.names[0] === place.file));
			if (!entry) files.push((entry = { names: [], abs, real, edits: [] }));
			if (!entry.names.includes(place.file)) entry.names.push(place.file);
			// Two findings can ask for the same change, as Codex's do.
			const key = JSON.stringify([place.autofix.type, place.autofix.path, place.autofix.value]);
			const same = entry.edits.find((x) => x.key === key);
			if (same) same.findings.push(f);
			else entry.edits.push({ key, fix: place.autofix, findings: [f] });
		}
	}
	const plans = [];
	for (const entry of files) plans.push(await planFile(entry, { project, home, env }));
	return plans;
}

async function planFile({ names, abs, real, edits }, { project, home, env }) {
	// Named by where the file is, which is what's changed and backed up.
	const inProject = real ? below(real, project) : null;
	const inHome = real && home ? within(real, home) || null : null;
	const file = inProject !== null && !(home && within(project, home) === "") ? inProject : inHome !== null ? `~/${inHome}` : names[0];
	const plan = { file, names, abs, edits: [], skipped: [], before: null, after: null, mode: null, hash: null };
	const skip = (why) => {
		plan.skipped.push(...edits.map((e) => ({ ...e, why })));
		return plan;
	};
	if (!abs) return skip("it wasn't read from disk");
	const info = await lstat(abs).catch(() => null);
	if (!info) return skip("it's gone");
	if (info.isSymbolicLink()) return skip("it's a link, and --fix doesn't change the file a link points to");
	if (!info.isFile()) return skip("it isn't a regular file");
	if (!real || (inProject === null && inHome === null)) return skip("it's outside this project and your home folder");
	if ((info.mode & 0o200) === 0) return skip("it's read-only");
	if (typeof process.getuid === "function" && info.uid !== process.getuid()) return skip("it belongs to another user on this computer");
	let read;
	try {
		read = await readUntrusted(abs, MAX_BYTES, "a file --fix changes", { bytes: true });
	} catch (error) {
		if (error instanceof FileError) return skip(error.message.replace(/\.$/, ""));
		return skip(`it couldn't be read (${error.code ?? "error"})`);
	}
	if (!read) return skip("it's gone");
	const original = read.buffer.toString("utf8");
	if (!Buffer.from(original, "utf8").equals(read.buffer)) return skip("it isn't UTF-8 text");
	const toml = /\.toml$/i.test(names[0]);
	const parse = toml ? parseTOML : parseJSONC;
	let expected = readValue(parse, original);
	if (expected == null) return skip("it can't be read as settings");
	// A file that's plain JSON stays plain JSON.
	const strict = !toml && isJSON(original);
	let text = original;
	for (const e of edits) {
		// A risk you've accepted is a setting you chose to keep.
		if (e.findings.some((f) => f.review?.acceptedAt != null)) {
			plan.skipped.push({ ...e, why: "you accepted this risk, so the setting stays as it is" });
			continue;
		}
		const r = await edit(text, e.fix, expected, { toml, home, env }).catch(() => ({ why: "it can't be read as settings" }));
		if (r.why) {
			plan.skipped.push({ ...e, why: r.why });
			continue;
		}
		const back = readValue(parse, r.text);
		if (back == null || !same(back, r.expected) || (strict && !isJSON(r.text))) {
			plan.skipped.push({ ...e, why: "the change couldn't be made without changing something else in the file" });
			continue;
		}
		plan.edits.push({ ...e, does: r.does ?? e.fix.does, hunk: hunk(text, r.text) });
		text = r.text;
		expected = r.expected;
	}
	if (plan.edits.length) Object.assign(plan, { before: original, after: text, mode: read.mode, hash: sha256(read.buffer) });
	return plan;
}

function readValue(parse, text) {
	try {
		return parse(text) ?? null;
	} catch {
		return null;
	}
}
function isJSON(text) {
	try {
		JSON.parse(text.replace(/^\ufeff/, ""));
		return true;
	} catch {
		return false;
	}
}

// One edit on the text: the new text and the settings it should read as.
async function edit(text, fix, expected, { toml, home, env }) {
	const keys = fix.path;
	if (!Array.isArray(keys) || !keys.length || keys.some((k) => typeof k !== "string" || UNSAFE_KEY.has(k))) return { why: "it can't be found in the file" };
	if (toml) return fix.type === "toml-set" ? tomlSet(text, fix, expected) : { why: "it can't be found in the file" };
	let tree;
	try {
		tree = spans(text);
	} catch {
		return { why: "it can't be read as settings" };
	}
	const node = find(tree, keys);
	if (node === "duplicate") return { why: "the setting is in the file more than once" };
	if (!node) return { why: "it changed since the check" };
	const next = structuredClone(expected);
	if (fix.type === "json-set") {
		if (!same(valueAt(expected, keys), fix.was)) return { why: "it changed since the check" };
		setAt(next, keys, fix.value);
		return { text: splice(text, node.start, node.end, JSON.stringify(fix.value)), expected: next };
	}
	if (node.type !== "array") return { why: "it changed since the check" };
	if (fix.type === "json-remove") {
		const target = String(fix.value).trim();
		const hit = (v) => v.type === "string" && v.value.trim() === target;
		if (!node.items.some(hit)) return { why: "it changed since the check" };
		// Every copy of the rule, one at a time, reading the list again after each.
		let out = text;
		for (let list = node, n = 0; list && n < 100; n++) {
			const i = list.items.findLastIndex(hit);
			if (i < 0) break;
			out = removeItem(out, list, i);
			list = find(spans(out), keys);
		}
		setAt(next, keys, valueAt(expected, keys).filter((v) => !(typeof v === "string" && v.trim() === target)));
		return { text: out, expected: next };
	}
	if (fix.type === "pin") {
		if (!NPM_NAME.test(fix.package ?? "")) return { why: "the package name isn't one npm uses" };
		// npx -p NAME runs a command by another name, and NAME@1 asks for a
		// range the version in the cache may not be in.
		if (node.items.some((v) => v.type === "string" && /^(-p|--package)(=|$)/.test(v.value))) return { why: "npx is told the package with --package, so pin it by hand" };
		if (fix.value !== fix.package && fix.value !== `${fix.package}@latest`) return { why: "it asks for a version or a range, so pin it by hand" };
		const at = node.items.map((v, i) => [v, i]).filter(([v]) => v.type === "string" && v.value === fix.value);
		if (at.length !== 1) return { why: "it changed since the check" };
		const found = await npxVersion(fix.package, { home, env });
		if (!found) return { why: `npx has no copy of ${fix.package} on this computer to take the version from; run npm view ${fix.package} version and pin it by hand` };
		const spec = `${fix.package}@${found.version}`;
		const list = valueAt(expected, keys).slice();
		list[at[0][1]] = spec;
		setAt(next, keys, list);
		return { text: splice(text, at[0][0].start, at[0][0].end, JSON.stringify(spec)), expected: next, does: `Pin ${fix.package} to ${found.version}, the version npx last installed on this computer` };
	}
	return { why: "it can't be found in the file" };
}

// A top-level TOML setting, before the first [table], set to a new string.
// Only a line that holds exactly the old value as a plain string changes.
function tomlSet(text, fix, expected) {
	if (fix.path.length !== 1 || !/^[A-Za-z0-9_-]+$/.test(fix.path[0]) || typeof fix.value !== "string" || typeof fix.was !== "string") return { why: "it can't be found in the file" };
	if (expected?.[fix.path[0]] !== fix.was) return { why: "it changed since the check" };
	const lines = text.split(/(?<=\n)/);
	const key = fix.path[0].replace(/-/g, "\\-");
	const at = topLevel(lines).filter((i) => new RegExp(`^\\s*["']?${key}["']?\\s*=`).test(lines[i]));
	if (at.length !== 1) return { why: at.length ? "the setting is in the file more than once" : "it changed since the check" };
	const was = fix.was.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	const m = new RegExp(`^(\\s*${key}\\s*=\\s*)(?:"${was}"|'${was}')(\\s*(?:#[^\\r\\n]*)?)(\\r?\\n)?$`).exec(lines[at[0]]);
	if (!m) return { why: "it's written in a way --fix doesn't change" };
	lines[at[0]] = `${m[1]}${JSON.stringify(fix.value)}${m[2]}${m[3] ?? ""}`;
	const next = structuredClone(expected);
	next[fix.path[0]] = fix.value;
	return { text: lines.join(""), expected: next };
}

// The lines of a TOML file that start a top-level setting: before the first
// [table], and not inside a list, an inline table or a multi-line string
// that started on a line before.
function topLevel(lines) {
	const out = [];
	let depth = 0;
	let multi = null;
	for (const [i, line] of lines.entries()) {
		const start = depth === 0 && multi === null;
		if (start && /^\s*\[/.test(line)) break;
		if (start) out.push(i);
		for (let j = 0; j < line.length; j++) {
			if (multi) {
				if (line.startsWith(multi, j)) {
					multi = null;
					j += 2;
				} else if (multi === '"""' && line[j] === "\\") j++;
				continue;
			}
			const c = line[j];
			if (c === "#") break;
			if (line.startsWith('"""', j) || line.startsWith("'''", j)) {
				multi = line.slice(j, j + 3);
				j += 2;
			} else if (c === '"') {
				for (j++; j < line.length && line[j] !== '"'; j++) if (line[j] === "\\") j++;
			} else if (c === "'") {
				while (++j < line.length && line[j] !== "'");
			} else if (c === "[" || c === "{") depth++;
			else if ((c === "]" || c === "}") && depth > 0) depth--;
		}
	}
	return out;
}

// The version of a package that npx last installed, from its cache. npm
// keeps each one in its own folder under _npx, by when it was installed.
export async function npxVersion(pkg, { home = homeFolder(), env = process.env } = {}) {
	if (!NPM_NAME.test(pkg)) return null;
	const cache = env.npm_config_cache || env.NPM_CONFIG_CACHE || (process.platform === "win32" ? (env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, "npm-cache") : null) : home ? path.join(home, ".npm") : null);
	if (!cache) return null;
	const root = path.join(cache, "_npx");
	const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
	let best = null;
	for (const e of entries.slice(0, 2000)) {
		if (!e.isDirectory() || !/^[0-9a-f]{6,64}$/i.test(e.name)) continue;
		const folder = path.join(root, e.name);
		let text = null;
		try {
			text = await readUntrusted(path.join(folder, "node_modules", ...pkg.split("/"), "package.json"), MAX_BYTES, "a package.json");
		} catch {
			continue;
		}
		let json = null;
		try {
			json = text === null ? null : JSON.parse(text);
		} catch {
			continue;
		}
		if (json?.name !== pkg || typeof json.version !== "string" || !VERSION.test(json.version)) continue;
		// Files from a package all carry the same old date, so the time is
		// from the folder npx made for it.
		const when = ((await stat(path.join(folder, "package.json")).catch(() => null)) ?? (await stat(folder).catch(() => null)))?.mtimeMs ?? 0;
		if (!best || when > best.when) best = { version: json.version, when };
	}
	return best;
}

// --- JSON with comments, with where each value is ---------------------------------

// The same grammar as the engine's parser: JSON, with // and /* */ comments
// and trailing commas. Each value keeps where it starts and ends.
function spans(text) {
	let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
	const n = text.length;
	const fail = () => {
		throw new SyntaxError("unreadable");
	};
	const space = () => {
		for (;;) {
			while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
			if (text[i] === "/" && text[i + 1] === "/") while (i < n && text[i] !== "\n" && !(text[i] === "\r" && text[i + 1] !== "\n")) i++;
			else if (text[i] === "/" && text[i + 1] === "*") {
				const end = text.indexOf("*/", i + 2);
				if (end < 0) fail();
				i = end + 2;
			} else return;
		}
	};
	const string = () => {
		const start = i++;
		while (i < n && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
		if (i >= n) fail();
		i++;
		return { type: "string", start, end: i, value: JSON.parse(text.slice(start, i)) };
	};
	const value = (depth) => {
		if (depth > 200) fail();
		space();
		const start = i;
		if (text[i] === "{") {
			i++;
			const members = [];
			space();
			while (text[i] !== "}") {
				if (text[i] !== '"') fail();
				const key = string().value;
				space();
				if (text[i++] !== ":") fail();
				members.push({ key, value: value(depth + 1) });
				space();
				if (text[i] === ",") {
					i++;
					space();
				} else if (text[i] !== "}") fail();
			}
			i++;
			return { type: "object", start, end: i, members };
		}
		if (text[i] === "[") {
			i++;
			const items = [];
			space();
			while (text[i] !== "]") {
				const item = value(depth + 1);
				space();
				if (text[i] === ",") {
					item.comma = i++;
					space();
				} else if (text[i] !== "]") fail();
				items.push(item);
			}
			i++;
			return { type: "array", start, end: i, items };
		}
		if (text[i] === '"') return string();
		const m = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 400));
		if (!m) fail();
		i += m[0].length;
		return { type: "scalar", start, end: i };
	};
	const root = value(0);
	space();
	if (i !== n) fail();
	return root;
}

function find(node, keys) {
	for (const k of keys) {
		if (node?.type !== "object") return null;
		const hits = node.members.filter((m) => m.key === k);
		if (hits.length > 1) return "duplicate";
		if (!hits.length) return null;
		node = hits[0].value;
	}
	return node;
}

const splice = (text, start, end, insert) => text.slice(0, start) + insert + text.slice(end);

// An item out of a list, with its comma. An item on a line of its own goes
// with its line, comment and all, so the other lines and their comments stay
// as they are. Otherwise it goes up to the next item, or for the last one
// from the end of the one before. The only item leaves [].
function removeItem(text, list, i) {
	const items = list.items;
	const item = items[i];
	const last = i === items.length - 1;
	const end = item.comma !== undefined ? item.comma + 1 : item.end;
	if (items.length === 1) {
		const rest = text.slice(list.start + 1, item.start) + text.slice(end, list.end - 1);
		if (/^\s*$/.test(rest)) return splice(text, list.start + 1, list.end - 1, "");
	}
	const lineStart = text.lastIndexOf("\n", item.start - 1) + 1;
	let j = end;
	while (text[j] === " " || text[j] === "\t") j++;
	if (text[j] === "/" && text[j + 1] === "/") while (j < text.length && text[j] !== "\n" && text[j] !== "\r") j++;
	const lineEnd = text[j] === "\r" && text[j + 1] === "\n" ? j + 2 : text[j] === "\n" ? j + 1 : -1;
	const ownLine = lineEnd > 0 && /^[ \t]*$/.test(text.slice(lineStart, item.start)) && !/[\r\n]/.test(text.slice(item.end, end));
	if (ownLine) {
		const out = splice(text, lineStart, lineEnd, "");
		// The last item had no comma, so the one before it mustn't keep one.
		const before = items[i - 1];
		return last && item.comma === undefined && before?.comma !== undefined ? splice(out, before.comma, before.comma + 1, "") : out;
	}
	if (!last) return splice(text, item.start, items[i + 1].start, "");
	if (i === 0) return splice(text, item.start, end, "");
	return splice(text, items[i - 1].end, item.end, "");
}

// --- Settings as values ----------------------------------------------------------

function valueAt(obj, keys) {
	for (const k of keys) {
		if (obj === null || typeof obj !== "object" || !Object.hasOwn(obj, k)) return undefined;
		obj = obj[k];
	}
	return obj;
}
function setAt(obj, keys, value) {
	const parent = valueAt(obj, keys.slice(0, -1));
	if (parent && typeof parent === "object") parent[keys.at(-1)] = value;
}
function same(a, b) {
	if (a === b) return true;
	if (typeof a !== "object" || typeof b !== "object" || a === null || b === null || Array.isArray(a) !== Array.isArray(b)) return false;
	const ka = Object.keys(a);
	const kb = Object.keys(b);
	return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && same(a[k], b[k]));
}

// The lines one edit changes, to show before it's made: ["-", line] for a
// line that goes and ["+", line] for one that comes, in order. Lines the
// edit keeps aren't listed.
function hunk(before, after) {
	const a = before.split(/\r?\n/);
	const b = after.split(/\r?\n/);
	let s = 0;
	while (s < a.length && s < b.length && a[s] === b[s]) s++;
	let e = 0;
	while (e < a.length - s && e < b.length - s && a[a.length - 1 - e] === b[b.length - 1 - e]) e++;
	const x = a.slice(s, a.length - e);
	const y = b.slice(s, b.length - e);
	// The longest run of lines both keep, for the few lines an edit touches.
	if (x.length * y.length > 40_000) return [...x.map((l) => ["-", l]), ...y.map((l) => ["+", l])];
	const keep = Array.from({ length: x.length + 1 }, () => new Array(y.length + 1).fill(0));
	for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) keep[i][j] = x[i] === y[j] ? keep[i + 1][j + 1] + 1 : Math.max(keep[i + 1][j], keep[i][j + 1]);
	const out = [];
	let i = 0;
	let j = 0;
	while (i < x.length || j < y.length) {
		if (i < x.length && j < y.length && x[i] === y[j]) {
			i++;
			j++;
		} else if (j >= y.length || (i < x.length && keep[i + 1][j] >= keep[i][j + 1])) out.push(["-", x[i++]]);
		else out.push(["+", y[j++]]);
	}
	return out;
}

// --- Making the changes ------------------------------------------------------------

const backupsOf = (home) => path.join(home, ".misconfig", "backups");

// A file of misconfig's own, written in one step.
async function writeOwn(file, data, mode, outcome) {
	const temp = await stageText(file, data, mode, outcome);
	try {
		if (process.platform !== "win32") await chmod(temp, mode);
		await moveInto(temp, file);
	} finally {
		await rm(temp, { force: true }).catch(() => {});
	}
}

// Backs up every file, with a list of what's about to change that --undo
// reads, then replaces each one that's still what was read. Nothing is
// changed if the backups can't all be made.
export async function applyFixes(plans, { home = homeFolder(), now = new Date() } = {}) {
	const ready = plans.filter((p) => p.edits.length);
	if (!home) throw new Error("--fix keeps a backup of each file in your home folder, and there isn't one. Nothing was changed.");
	// A folder of its own for this run, never one an earlier run made.
	await makeFolder(backupsOf(home), "nothing was changed");
	const stamp = now.toISOString().replace(/[:.]/g, "-");
	let folder = null;
	for (let n = 0; n < 100 && !folder; n++) {
		const name = path.join(backupsOf(home), n ? `${stamp}-${String(n).padStart(2, "0")}` : stamp);
		folder = await mkdir(name, { mode: 0o700 }).then(
			() => name,
			(error) => {
				if (error.code === "EEXIST") return null;
				throw new Error(`${shown(name)} couldn't be made (${error.code ?? "error"}), so nothing was changed.`);
			},
		);
	}
	if (!folder) throw new Error("A folder for the backups couldn't be made, so nothing was changed.");
	const listed = [];
	for (const p of ready) {
		const parts = p.file.startsWith("~/") ? ["home", ...p.file.slice(2).split("/")] : ["project", ...p.file.split("/")];
		if (parts.some((x) => !x || x === "." || x === ".." || x.includes("\\"))) throw new Error(`${p.file} can't be backed up. Nothing was changed.`);
		const dest = path.join(folder, ...parts);
		await makeFolder(path.dirname(dest), "nothing was changed");
		await writeOwn(dest, p.before, 0o600, "nothing was changed");
		listed.push({ path: p.abs, name: p.file, backup: parts.join("/"), before: p.hash, after: sha256(Buffer.from(p.after, "utf8")) });
	}
	await writeOwn(path.join(folder, MANIFEST), `${JSON.stringify({ format: FORMAT, version: 1, at: now.toISOString(), files: listed }, null, 2)}\n`, 0o600, "nothing was changed");
	const changed = [];
	const failed = [];
	for (const p of ready) {
		try {
			// Changed since it was read, by you or something else: left alone.
			const current = await readUntrusted(p.abs, MAX_BYTES, "a file --fix changes", { bytes: true }).catch(() => null);
			if (!current || sha256(current.buffer) !== p.hash) {
				failed.push({ plan: p, why: "it changed while --fix ran, so it was left as it is" });
				continue;
			}
			await writeOwn(p.abs, p.after, p.mode & 0o777, "it wasn't changed");
			changed.push(p);
		} catch (error) {
			failed.push({ plan: p, why: error instanceof FileError ? error.message.replace(/^.*?couldn't be written/, "it couldn't be written").replace(/\.$/, "") : `it couldn't be written (${error.code ?? "error"})` });
		}
	}
	return { changed, failed, backups: shown(folder) };
}

// --- Undoing ---------------------------------------------------------------------

// --undo puts back the files the last --fix changed, from its backups. A
// file is put back only while it's still exactly what --fix wrote, so an
// edit made since is never lost, and a deleted file stays deleted. The
// backups stay where they are.
//
// The list of changes is read as untrusted input: a file someone else put
// in ~/.misconfig/backups can only name settings files, and a backup is used
// only if it's the file as --fix found it, by its hash.
const FORMAT = "misconfig-fix";
const MANIFEST = "changes.json";
const DONE = "undone";
const RUN = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z(-\d{2})?$/;
const HEX = /^[0-9a-f]{64}$/;

function listedFiles(m) {
	if (!m || typeof m !== "object" || m.format !== FORMAT || m.version !== 1 || typeof m.at !== "string" || Number.isNaN(Date.parse(m.at)) || !Array.isArray(m.files) || m.files.length > 1000) return null;
	const ok = (f) =>
		f && typeof f === "object" &&
		typeof f.path === "string" && f.path.length < 4096 && path.isAbsolute(f.path) && /\.(jsonc?|toml)$/i.test(f.path) &&
		typeof f.name === "string" && f.name.length < 4096 &&
		typeof f.backup === "string" && /^(home|project)\//.test(f.backup) && f.backup.split("/").every((x) => x && x !== "." && x !== ".." && !x.includes("\\")) &&
		HEX.test(f.before) && HEX.test(f.after);
	return m.files.every(ok) ? m.files : null;
}

// What --undo would do: the latest --fix that wasn't undone, and for each
// file it changed, whether it can be put back. Null when there's none.
export async function planUndo({ home = homeFolder() } = {}) {
	if (!home) return null;
	const root = backupsOf(home);
	const runs = (await readdir(root, { withFileTypes: true }).catch(() => [])).filter((e) => e.isDirectory() && RUN.test(e.name)).map((e) => e.name).sort().reverse();
	for (const name of runs.slice(0, 500)) {
		const folder = path.join(root, name);
		if (await lstat(path.join(folder, DONE)).then(() => true, () => false)) continue;
		let files = null;
		let at = null;
		try {
			const text = await readUntrusted(path.join(folder, MANIFEST), MAX_BYTES, "a list of changes");
			if (text === null) continue;
			const m = JSON.parse(text);
			files = listedFiles(m);
			at = m?.at;
		} catch {
			files = null;
		}
		if (!files) return { folder: shown(folder), error: `The list of changes in ${shown(folder)} isn't one misconfig wrote, so nothing can be undone from it. The backups are in that folder.` };
		const items = [];
		for (const f of files) items.push(await undoItem(folder, f));
		return { folder: shown(folder), root: folder, at, items };
	}
	return null;
}

async function undoItem(folder, f) {
	const backup = path.join(folder, ...f.backup.split("/"));
	const item = { name: f.name, path: f.path, backup: shown(backup), state: null };
	if (below(backup, folder) === null) return { ...item, state: "no backup" };
	const saved = await readUntrusted(backup, MAX_BYTES, "a backup", { bytes: true }).catch(() => null);
	if (!saved || sha256(saved.buffer) !== f.before) return { ...item, state: "no backup" };
	const info = await lstat(f.path).catch(() => null);
	if (!info) return { ...item, state: "gone" };
	if (info.isSymbolicLink() || !info.isFile()) return { ...item, state: "not a file" };
	if (typeof process.getuid === "function" && info.uid !== process.getuid()) return { ...item, state: "another user's" };
	const current = await readUntrusted(f.path, MAX_BYTES, "a file --undo puts back", { bytes: true }).catch(() => null);
	const hash = current ? sha256(current.buffer) : null;
	if (hash === f.before) return { ...item, state: "as it was" };
	if (hash !== f.after) return { ...item, state: "changed" };
	return { ...item, state: "ready", data: saved.buffer, current: current.buffer, mode: info.mode, hash };
}

// Puts back each file that's ready and still what --fix wrote, then marks
// the run as undone, so the next --undo goes to the one before.
export async function applyUndo(plan) {
	const restored = [];
	const failed = [];
	for (const item of plan.items.filter((x) => x.state === "ready")) {
		try {
			const current = await readUntrusted(item.path, MAX_BYTES, "a file --undo puts back", { bytes: true }).catch(() => null);
			if (!current || sha256(current.buffer) !== item.hash) {
				failed.push({ item, why: "it changed while --undo ran, so it was left as it is" });
				continue;
			}
			await writeOwn(item.path, item.data, item.mode & 0o777, "it wasn't put back");
			restored.push(item);
		} catch (error) {
			failed.push({ item, why: error instanceof FileError ? error.message.replace(/^.*?couldn't be written/, "it couldn't be written").replace(/\.$/, "") : `it couldn't be written (${error.code ?? "error"})` });
		}
	}
	await writeOwn(path.join(plan.root, DONE), `${new Date().toISOString()}\n`, 0o600, "it wasn't marked as undone").catch(() => {});
	return { restored, failed };
}
