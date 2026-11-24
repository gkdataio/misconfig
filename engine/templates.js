// Rules written as data. A template names the settings files it reads and
// what in them makes a finding, and one reader applies them all, so a rule
// like this needs no code of its own. The rules built in this way are at the
// end of the file, with their wording in catalog.js. --rules adds a company's
// own, which bring their wording with them.
//
// A template can only add a finding. It can't run anything, read a file or
// take a finding away. A company's rule holds no regular expression either:
// its files are paths and its tests compare text, so nothing in a rules file
// can be written to stall a check on a file from someone else.

import { CATEGORIES, LEVELS, RULES } from "./catalog.js";

// Capitals, digits and hyphens, as in CC-BYPASS.
const ID = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){0,6}$/;
const WORDING = ["name", "title", "severity", "category", "agent", "why", "fix", "reference"];
// Every key a rule can have, and every test a condition can make.
export const RULE_KEYS = ["id", ...WORDING, "files", "scope", "match", "line"];
export const RULE_TESTS = ["equals", "in", "contains", "startsWith", "endsWith", "exists"];
const MAX = { id: 40, name: 120, text: 600, files: 10, file: 300, stars: 4, line: 200, address: 300, path: 12, key: 200, depth: 6, conditions: 30, values: 50 };

const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const isValue = (x) => x === null || typeof x === "boolean" || (typeof x === "number" && Number.isFinite(x)) || (typeof x === "string" && x.length <= MAX.text);
const oneLine = (x, max) => typeof x === "string" && x.trim() !== "" && x.length <= max && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(x);

// Where a rule's files are. A pattern is a path: **/ in front of it means in
// any folder, and * in the file's name stands for any run of characters.
// Nothing else in it is special, so trying one on a file takes about as long
// as the pattern and the file's name are, however long a path a project
// comes up with. Null for text that isn't such a pattern.
function filePattern(text) {
	if (!oneLine(text, MAX.file)) return null;
	const anywhere = text.startsWith("**/");
	const rest = (anywhere ? text.slice(3) : text).toLowerCase();
	const cut = rest.lastIndexOf("/") + 1;
	const dir = rest.slice(0, cut);
	const parts = rest.slice(cut).split("*");
	if (cut === rest.length || /[*?[\]\\]/.test(dir) || parts.length - 1 > MAX.stars || parts.some((part, i) => /[?[\]\\]/.test(part) || (part === "" && i > 0 && i < parts.length - 1))) return null;
	return { anywhere, dir, under: `/${dir}`, parts };
}

// True when a file's name fits a pattern's name, split where its *s were.
function named(parts, name) {
	const first = parts[0];
	const last = parts[parts.length - 1];
	if (parts.length === 1) return name === first;
	if (name.length < first.length + last.length || !name.startsWith(first) || !name.endsWith(last)) return false;
	let at = first.length;
	const end = name.length - last.length;
	for (let i = 1; i < parts.length - 1; i++) {
		const found = name.indexOf(parts[i], at);
		if (found < 0 || found + parts[i].length > end) return false;
		at = found + parts[i].length;
	}
	return true;
}

// The templates that read the file at this path, whatever its case, as
// macOS and Windows open it.
export function readers(templates, path) {
	const lower = path.toLowerCase();
	const cut = lower.lastIndexOf("/") + 1;
	const dir = lower.slice(0, cut);
	const name = lower.slice(cut);
	return templates.filter((t) => t.files.some((p) => (p.anywhere ? dir === p.dir || dir.endsWith(p.under) : dir === p.dir) && named(p.parts, name)));
}

// A template as the reader uses it, with every key checked, so a mistake is
// reported when the rules are loaded and not passed over during a check.
// Throws an Error that says what to change. The message quotes the rule's
// ID, or a key that's a plain word, and nothing else from the rule, so a
// rules file can't write to a log in words of its own.
//
// A built-in template takes its wording from the catalog, and can point at
// its line with a regular expression, `linePattern`. Any other brings its
// own wording and can't use a built-in rule's ID.
export function readTemplate(raw, { builtIn = false } = {}) {
	const known = isObj(raw) && typeof raw.id === "string" && raw.id.length <= MAX.id && ID.test(raw.id);
	const fail = (message) => {
		throw new Error(`${known ? `${raw.id}: ` : ""}${message}`);
	};
	if (!isObj(raw)) fail("A rule is a set of keys, such as id, files and match.");
	const allowed = builtIn ? ["id", "files", "scope", "match", "line", "linePattern"] : RULE_KEYS;
	for (const key of Object.keys(raw)) {
		if (allowed.includes(key)) continue;
		if (builtIn && WORDING.includes(key)) fail(`A built-in rule's ${key} is in the catalog.`);
		fail(`${/^[\w-]{1,30}$/.test(key) ? `“${key}”` : "One of its keys"} isn't a key a rule can have. The keys are ${allowed.join(", ")}.`);
	}
	if (!known) fail("id needs capitals, digits and hyphens, such as ACME-NO-YOLO.");

	const files = Array.isArray(raw.files) && raw.files.length && raw.files.length <= MAX.files ? raw.files.map(filePattern) : [null];
	if (files.includes(null)) fail(`files needs a list of 1 to ${MAX.files} paths, such as **/.claude/settings.json. **/ in front means in any folder, and * in the file's name, up to ${MAX.stars} times, means any run of characters.`);
	if (raw.scope !== undefined && raw.scope !== "project" && raw.scope !== "computer") fail("scope is project, for files in the checked folder, or computer, for the settings outside it.");

	let conditions = 0;
	const condition = (node, depth) => {
		if (depth > MAX.depth) fail(`match is nested more than ${MAX.depth} deep.`);
		// A list on its own means all of them.
		if (Array.isArray(node)) {
			if (!node.length) fail("A list in match needs at least one condition.");
			node = { all: node };
		}
		if (!isObj(node)) fail("Each part of match is a condition with a path, or all, any or not.");
		const keys = Object.keys(node);
		for (const group of ["all", "any"]) {
			if (!Object.hasOwn(node, group)) continue;
			if (keys.length !== 1 || !Array.isArray(node[group]) || !node[group].length) fail(`${group} needs a list of conditions and nothing beside it.`);
			return { [group]: node[group].map((n) => condition(n, depth + 1)) };
		}
		if (Object.hasOwn(node, "not")) {
			if (keys.length !== 1) fail("not needs one condition and nothing beside it.");
			return { not: condition(node.not, depth + 1) };
		}
		if (++conditions > MAX.conditions) fail(`match has more than ${MAX.conditions} conditions.`);
		// A path is keys joined by dots, or a list of keys for a key that has
		// a dot in it. * stands for every key, or every item of a list.
		const path = typeof node.path === "string" ? node.path.split(".") : node.path;
		if (!Array.isArray(path) || !path.length || path.length > MAX.path || !path.every((key) => typeof key === "string" && key !== "" && key.length <= MAX.key)) {
			fail("path needs keys joined by dots, such as permissions.defaultMode, or a list of keys.");
		}
		const tests = keys.filter((key) => key !== "path");
		if (tests.length !== 1 || !RULE_TESTS.includes(tests[0])) fail(`A condition needs a path and one of ${RULE_TESTS.join(", ")}.`);
		const [test] = tests;
		const value = node[test];
		if (test === "exists" && typeof value !== "boolean") fail("exists is true or false.");
		if (test === "equals" && !isValue(value)) fail("equals needs text, a number, true, false or null.");
		if (test === "in" && !(Array.isArray(value) && value.length && value.length <= MAX.values && value.every(isValue))) fail(`in needs a list of up to ${MAX.values} values. Each is text, a number, true, false or null.`);
		if (["contains", "startsWith", "endsWith"].includes(test) && !(typeof value === "string" && value !== "" && value.length <= MAX.text)) fail(`${test} needs text of up to ${MAX.text} characters.`);
		return { path, test, value };
	};
	if (raw.match === undefined) fail("match says what in the file makes a finding. It needs at least one condition.");
	const match = condition(raw.match, 0);

	// The line a finding points at is the first one that has this text.
	// Without `line`, that's the last key of the first path.
	const firstPath = (node) => node.path ?? firstPath((node.all ?? node.any ?? [node.not])[0]);
	if (raw.line !== undefined && !oneLine(raw.line, MAX.line)) fail(`line needs text of up to ${MAX.line} characters that's on the line a finding should point at.`);
	const line = raw.line ?? firstPath(match).filter((key) => key !== "*").pop() ?? null;

	const template = { id: raw.id, files, scope: raw.scope ?? null, match, line, rule: null };
	if (builtIn) {
		if (!Object.hasOwn(RULES, raw.id)) fail("A built-in rule needs its wording in the catalog.");
		return raw.linePattern === undefined ? template : { ...template, line: new RegExp(raw.linePattern) };
	}

	if (Object.hasOwn(RULES, raw.id)) fail("That ID belongs to a built-in rule. Choose another, such as one that starts with your company's name.");
	if (!oneLine(raw.name, MAX.name) || raw.name.includes("{file}")) fail(`name says what the rule finds, in one line of up to ${MAX.name} characters, without {file}.`);
	if (raw.title !== undefined && !oneLine(raw.title, MAX.name)) fail(`title needs one line of up to ${MAX.name} characters.`);
	for (const word of ["why", "fix"]) if (!oneLine(raw[word], MAX.text)) fail(`${word} needs one line of up to ${MAX.text} characters.`);
	if (!Object.hasOwn(LEVELS, raw.severity)) fail(`severity is one of ${Object.keys(LEVELS).join(", ")}.`);
	if (!Object.hasOwn(CATEGORIES, raw.category)) fail(`category is one of ${Object.keys(CATEGORIES).join(", ")}.`);
	if (raw.agent !== undefined && !oneLine(raw.agent, 40)) fail("agent names the agent the setting belongs to, such as Claude Code, in up to 40 characters.");
	let reference = null;
	if (raw.reference !== undefined) {
		try {
			const url = new URL(oneLine(raw.reference, MAX.address) && !/\s/.test(raw.reference) ? raw.reference : "");
			if (url.protocol !== "https:" || url.username || url.password) throw new Error();
			reference = url.href;
		} catch {
			fail("reference needs an https address where the rule is explained.");
		}
	}
	return {
		...template,
		rule: { severity: raw.severity, category: raw.category, ...(raw.agent ? { tool: raw.agent } : {}), title: raw.title ?? raw.name, name: raw.name, why: raw.why, fix: raw.fix, reference },
	};
}

// Every value a path leads to in a parsed settings file, however many: a
// list padded with harmless items can't keep the last one from a rule. Only
// a file's own keys count, so a path can't lead to what every object carries.
function valuesAt(data, path) {
	let found = [data];
	for (const key of path) {
		const next = [];
		for (const value of found) {
			if (key !== "*") {
				if (isObj(value) && Object.hasOwn(value, key)) next.push(value[key]);
				continue;
			}
			const items = Array.isArray(value) ? value : isObj(value) ? Object.values(value) : [];
			for (const item of items) next.push(item);
		}
		found = next;
		if (!found.length) break;
	}
	return found;
}

// A number and its spelling as text are the same value: settings written in
// YAML are read as text.
const same = (a, b) => a === b || (typeof a === "number" && typeof b === "string" && String(a) === b) || (typeof a === "string" && typeof b === "number" && a === String(b));
const spelled = (v) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : null);

// True when a template's match holds for a parsed settings file. A condition
// holds when a value its path leads to passes its test. Text is compared
// whole, so padding around a value can't hide the rest of it.
export function holds(node, data) {
	if (node.all) return node.all.every((n) => holds(n, data));
	if (node.any) return node.any.some((n) => holds(n, data));
	if (node.not) return !holds(node.not, data);
	const found = valuesAt(data, node.path);
	if (node.test === "exists") return found.length > 0 === node.value;
	if (node.test === "equals") return found.some((v) => same(v, node.value));
	if (node.test === "in") return found.some((v) => node.value.some((w) => same(v, w)));
	if (node.test === "contains") return found.some((v) => spelled(v)?.includes(node.value) === true);
	if (node.test === "startsWith") return found.some((v) => spelled(v)?.startsWith(node.value) === true);
	return found.some((v) => spelled(v)?.endsWith(node.value) === true);
}

// --- Built-in rules ----------------------------------------------------------------

// Zed's own folder is named .zed in a project and zed or Zed on a computer.
const ZED = ["**/.zed/settings.json", "**/zed/settings.json"];
// Cline keeps its approval settings in ~/.cline/data/globalState.json.
const CLINE = ["**/.cline/data/globalState.json"];

export const TEMPLATES = [
	{ id: "CU-NO-SANDBOX", files: ["**/.cursor/sandbox.json"], match: [{ path: "type", equals: "insecure_none" }], line: "insecure_none" },
	{
		id: "ZED-ALWAYS-ALLOW",
		files: ZED,
		match: { any: [{ path: "agent.always_allow_tool_actions", equals: true }, { path: "assistant.always_allow_tool_actions", equals: true }, { path: "agent.tool_permissions.default", equals: "allow" }] },
		linePattern: 'always_allow_tool_actions|"default"\\s*:\\s*"allow"',
	},
	{ id: "ZED-TRUST-ALL", files: ZED, match: [{ path: "session.trust_all_worktrees", equals: true }] },
	{ id: "CL-YOLO", files: CLINE, match: [{ path: "yoloModeToggled", equals: true }] },
	// YOLO mode already approves everything, so this is for when it's off.
	{
		id: "CL-AUTO-COMMANDS",
		files: CLINE,
		match: [{ not: { path: "yoloModeToggled", equals: true } }, { not: { path: "autoApprovalSettings.enabled", equals: false } }, { path: "autoApprovalSettings.actions.executeAllCommands", equals: true }],
		line: "executeAllCommands",
	},
	{ id: "AMP-ALLOW-ALL", files: ["**/.amp/settings.json", "**/.config/amp/settings.json"], match: [{ path: ["amp.dangerouslyAllowAll"], equals: true }], line: "dangerouslyAllowAll" },
].map((raw) => readTemplate(raw, { builtIn: true }));
