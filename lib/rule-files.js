// --rules: a company's own rules, from the files named on the command line.
// A file is JSON: one rule, a list of rules, or { "rules": [...] }, each in
// the form templates.js reads. Nothing looks for rules files by itself, so a
// checked project can't bring rules of its own.

import { open, stat } from "node:fs/promises";
import { readTemplate } from "../engine/templates.js";

const MAX_BYTES = 256 * 1024;
const MAX_RULES = 200;
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);

async function readText(file) {
	let handle;
	try {
		handle = await open(file, "r");
		const info = await handle.stat();
		if (info.isDirectory()) throw Object.assign(new Error(), { code: "EISDIR" });
		// A pipe or a device has no size to check before it's read.
		if (!info.isFile()) throw new Error("it isn't a file");
		if (info.size > MAX_BYTES) throw new Error("it's larger than 256 KB");
		return (await handle.readFile("utf8")).replace(/^\ufeff/, "");
	} catch (err) {
		let code = err?.code;
		// Windows won't open a folder, and says so the way it does for a file this account can't read.
		if ((code === "EPERM" || code === "EACCES") && (await stat(file).then((info) => info.isDirectory(), () => false))) code = "EISDIR";
		const why = { ENOENT: "there's no file there", ENOTDIR: "there's no file there", EISDIR: "it's a folder", EACCES: "this account can't read it", EPERM: "this account can't read it" }[code] ?? (code ? `the system answered ${code}` : err.message);
		throw new Error(`The rules file ${file} couldn't be read: ${why}.`);
	} finally {
		await handle?.close();
	}
}

// The rules in these files, ready for a check. Throws an Error that names
// the file, the rule and what to change.
export async function loadRules(files) {
	const rules = [];
	const from = new Map();
	for (const file of files) {
		const text = await readText(file);
		let data;
		try {
			data = JSON.parse(text);
		} catch {
			throw new Error(`The rules file ${file} isn't valid JSON.`);
		}
		const list = Array.isArray(data) ? data : isObj(data) && Array.isArray(data.rules) && Object.keys(data).length === 1 ? data.rules : isObj(data) && !Object.hasOwn(data, "rules") ? [data] : null;
		if (!list?.length) throw new Error(`The rules file ${file} needs one rule, a list of rules, or a list of them under "rules" and nothing beside it.`);
		for (const [i, raw] of list.entries()) {
			let rule;
			try {
				rule = readTemplate(raw);
			} catch (err) {
				throw new Error(`${file}, rule ${i + 1}: ${err.message}`);
			}
			if (from.has(rule.id)) throw new Error(`${file}, rule ${i + 1}: ${rule.id} is already a rule in ${from.get(rule.id)}. Each rule needs its own ID.`);
			from.set(rule.id, file);
			rules.push(rule);
			if (rules.length > MAX_RULES) throw new Error(`--rules takes up to ${MAX_RULES} rules.`);
		}
	}
	return rules;
}
