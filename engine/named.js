// Files that settings name as instructions for an agent, beyond the usual
// names: Gemini CLI's context file names, Codex's fallback names for
// AGENTS.md, OpenCode's instructions list and Aider's read list. A project
// can use them to keep its instructions in a file the usual names don't
// cover, so the command and the checks both read them as instructions.

import { parseJSONC, parseTOML, parseYAML } from "./parse.js";
import { globMatch } from "./glob.js";

const names = (v) =>
	(typeof v === "string" ? [v] : Array.isArray(v) ? v.filter((x) => typeof x === "string") : [])
		.map((x) => x.trim())
		.filter((x) => x && x.length <= 300)
		.slice(0, 50);

// For each settings file: where it is, the agent, how to read it, the names
// it gives, and whether a name is a file name found anywhere ("name"), or a
// path or glob from the top of the project ("path").
const SOURCES = [
	{ re: /(^|\/)\.gemini\/settings\.json$/i, tool: "Gemini CLI", parse: parseJSONC, list: (j) => names(j?.context?.fileName ?? j?.contextFileName), match: "name" },
	{ re: /(^|\/)\.codex\/config\.toml$/i, tool: "Codex", parse: parseTOML, list: (t) => names(t?.project_doc_fallback_filenames), match: "name" },
	{ re: /^(?:\.opencode\/)?opencode\.jsonc?$/i, tool: "OpenCode", parse: parseJSONC, list: (j) => names(j?.instructions), match: "path" },
	{ re: /(^|\/)\.aider\.conf\.ya?ml$/i, tool: "Aider", parse: parseYAML, list: (y) => names(y?.read), match: "path" },
];

export const NAMING_SETTINGS = SOURCES.map((s) => s.re);

// A name that points out of the project, or to a web address.
export const outsideName = (name) => /^(?:~|\/|[A-Za-z]:|\\\\)/.test(name) || /(^|[\\/])\.\.([\\/]|$)/.test(name);
export const webName = (name) => /^https?:\/\//i.test(name);

// What the settings files given as { path, content } name:
// [{ tool, from, name, outside, web, test(path) }].
export function namedInstructions(files) {
	const out = [];
	for (const f of Array.isArray(files) ? files : []) {
		if (typeof f?.path !== "string" || typeof f.content !== "string") continue;
		const source = SOURCES.find((s) => s.re.test(f.path));
		if (!source) continue;
		let value;
		try {
			value = source.parse(f.content);
		} catch {
			continue;
		}
		for (const name of source.list(value)) {
			const plain = name.replace(/\\/g, "/").replace(/^\.\//, "");
			const outside = outsideName(name);
			const web = webName(name);
			const test =
				outside || web
					? () => false
					: source.match === "name"
						? (path) => path.split("/").pop().toLowerCase() === plain.split("/").pop().toLowerCase()
						: (path) => path.toLowerCase() === plain.toLowerCase() || (/[*?[]/.test(plain) && globMatch(plain, path));
			out.push({ tool: source.tool, from: f.path, name, outside, web, test });
			if (out.length >= 200) return out;
		}
	}
	return out;
}

// The entries a collector found that the names pick out, without testing
// every name against every file: a name is looked up, an exact path too, and
// globs are tried only on text files. `pathOf` gives an entry's project path.
const TEXT = /\.(?:md|mdc|markdown|txt|rst|adoc)$/i;
export function pickNamed(named, entries, pathOf) {
	if (!named.length) return [];
	const byName = new Map();
	const byPath = new Map();
	for (const e of entries) {
		const p = pathOf(e);
		const base = p.split("/").pop().toLowerCase();
		if (!byName.has(base)) byName.set(base, []);
		byName.get(base).push(e);
		byPath.set(p.toLowerCase(), e);
	}
	const picked = new Set();
	for (const n of named.filter((x) => !x.outside && !x.web)) {
		const plain = n.name.replace(/\\/g, "/").replace(/^\.\//, "");
		if (/[*?[]/.test(plain)) {
			for (const e of entries) if (TEXT.test(pathOf(e)) && n.test(pathOf(e))) picked.add(e);
		} else {
			for (const e of byName.get(plain.split("/").pop().toLowerCase()) ?? []) if (n.test(pathOf(e))) picked.add(e);
			const exact = byPath.get(plain.toLowerCase());
			if (exact && n.test(pathOf(exact))) picked.add(exact);
		}
		if (picked.size >= 50) break;
	}
	return [...picked];
}
