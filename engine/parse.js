// Small tolerant parsers for agent config files. They never throw: a file
// that can't be parsed returns undefined, and the report says it couldn't be
// read. Keys that could change object prototypes are ignored.

// JSON with comments and trailing commas (VS Code, OpenCode, Zed settings).
export function parseJSONC(text) {
	const s = String(text).replace(/^\ufeff/, "");
	let out = "";
	let inString = false;
	for (let i = 0; i < s.length; i++) {
		const c = s[i];
		const n = s[i + 1];
		if (inString) {
			out += c;
			if (c === "\\") {
				out += n ?? "";
				i++;
			} else if (c === '"') inString = false;
			continue;
		}
		if (c === '"') {
			inString = true;
			out += c;
		} else if (c === "/" && n === "/") {
			while (i < s.length && s[i] !== "\n") i++;
			out += "\n";
		} else if (c === "/" && n === "*") {
			i += 2;
			while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) {
				if (s[i] === "\n") out += "\n";
				i++;
			}
			i++;
		} else if (c === ",") {
			// A trailing comma may be followed by comments before the closing bracket.
			let j = i + 1;
			for (;;) {
				while (j < s.length && /\s/.test(s[j])) j++;
				if (s[j] === "/" && s[j + 1] === "/") {
					while (j < s.length && s[j] !== "\n") j++;
				} else if (s[j] === "/" && s[j + 1] === "*") {
					const end = s.indexOf("*/", j + 2);
					j = end < 0 ? s.length : end + 2;
				} else break;
			}
			if (s[j] !== "}" && s[j] !== "]") out += c;
		} else out += c;
	}
	try {
		return JSON.parse(out);
	} catch {
		return undefined;
	}
}

// Enough TOML for Codex config.toml: tables, dotted and quoted keys,
// strings, numbers, booleans, arrays and inline tables.
export function parseTOML(text) {
	const root = {};
	let table = root;
	const lines = String(text).replace(/^\ufeff/, "").split(/\r?\n/);
	try {
		for (let i = 0; i < lines.length; i++) {
			const line = stripComment(lines[i]).trim();
			if (!line) continue;
			// Table headers, [name] and [[name]], read without a regular
			// expression so a long header can't slow parsing down.
			if (line.startsWith("[") && line.endsWith("]")) {
				const array = line.startsWith("[[") && line.endsWith("]]");
				const keys = splitKey((array ? line.slice(2, -2) : line.slice(1, -1)).trim());
				if (keys.some((k) => UNSAFE_KEYS.has(k))) {
					table = {};
					continue;
				}
				if (!array) {
					table = ensure(root, keys);
					continue;
				}
				const parent = ensure(root, keys.slice(0, -1));
				const last = keys[keys.length - 1];
				if (!Array.isArray(parent[last])) parent[last] = [];
				table = {};
				parent[last].push(table);
				continue;
			}
			const eq = findTopLevel(line, "=");
			if (eq < 0) continue;
			const keys = splitKey(line.slice(0, eq).trim());
			let raw = line.slice(eq + 1).trim();
			const state = scan(raw, { depth: 0, quote: null, triple: null });
			for (let added = 0; (state.depth > 0 || state.triple) && i + 1 < lines.length && added < 5000; added++) {
				i++;
				const next = stripComment(lines[i]);
				raw += "\n" + next;
				scan("\n" + next, state);
			}
			const last = keys[keys.length - 1];
			if (UNSAFE_KEYS.has(last) || keys.some((k) => UNSAFE_KEYS.has(k))) continue;
			const parent = ensure(table, keys.slice(0, -1));
			parent[last] = parseValue(raw.trim());
		}
		return root;
	} catch {
		return undefined;
	}
}

const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function ensure(obj, keys) {
	let cur = obj;
	for (const k of keys) {
		if (UNSAFE_KEYS.has(k)) return {};
		if (cur[k] === undefined || typeof cur[k] !== "object" || cur[k] === null) cur[k] = {};
		cur = Array.isArray(cur[k]) ? cur[k][cur[k].length - 1] ?? (cur[k][0] = {}) : cur[k];
	}
	return cur;
}

function splitKey(raw) {
	const keys = [];
	let i = 0;
	const s = raw.trim();
	while (i < s.length) {
		while (s[i] === " " || s[i] === "\t") i++;
		if (s[i] === '"' || s[i] === "'") {
			const q = s[i];
			let j = i + 1;
			let key = "";
			while (j < s.length && s[j] !== q) {
				if (q === '"' && s[j] === "\\") {
					const length = s[j + 1] === "u" ? 6 : s[j + 1] === "U" ? 10 : 2;
					key += s.slice(j, j + length);
					j += length;
					continue;
				}
				key += s[j++];
			}
			keys.push(q === '"' ? tomlBasic(key) : key);
			i = j + 1;
		} else {
			let j = i;
			while (j < s.length && s[j] !== ".") j++;
			keys.push(s.slice(i, j).trim());
			i = j;
		}
		while (s[i] === " " || s[i] === "\t") i++;
		if (s[i] === ".") i++;
	}
	return keys.filter((k) => k !== "");
}

function stripComment(line) {
	let quote = null;
	for (let i = 0; i < line.length; i++) {
		const c = line[i];
		if (quote) {
			if (c === "\\" && quote === '"') i++;
			else if (c === quote) quote = null;
		} else if (c === '"' || c === "'") quote = c;
		else if (c === "#") return line.slice(0, i);
	}
	return line;
}

function findTopLevel(s, ch) {
	let quote = null;
	for (let i = 0; i < s.length; i++) {
		const c = s[i];
		if (quote) {
			if (c === "\\" && quote === '"') i++;
			else if (c === quote) quote = null;
		} else if (c === '"' || c === "'") quote = c;
		else if (c === ch) return i;
	}
	return -1;
}

// Updates bracket depth and string state for one more chunk of a value.
function scan(chunk, state) {
	for (let i = 0; i < chunk.length; i++) {
		const c = chunk[i];
		if (state.triple) {
			if (chunk.startsWith(state.triple, i)) {
				i += 2;
				state.triple = null;
			}
		} else if (state.quote) {
			if (c === "\\" && state.quote === '"') i++;
			else if (c === state.quote || c === "\n") state.quote = null;
		} else if (chunk.startsWith('"""', i) || chunk.startsWith("'''", i)) {
			state.triple = chunk.slice(i, i + 3);
			i += 2;
		} else if (c === '"' || c === "'") state.quote = c;
		else if (c === "[" || c === "{") state.depth++;
		else if (c === "]" || c === "}") state.depth--;
	}
	return state;
}

function splitTopLevel(inner) {
	const parts = [];
	let depth = 0;
	let quote = null;
	let start = 0;
	for (let i = 0; i < inner.length; i++) {
		const c = inner[i];
		if (quote) {
			if (c === "\\" && quote === '"') i++;
			else if (c === quote) quote = null;
		} else if (c === '"' || c === "'") quote = c;
		else if (c === "[" || c === "{") depth++;
		else if (c === "]" || c === "}") depth--;
		else if (c === "," && depth === 0) {
			parts.push(inner.slice(start, i));
			start = i + 1;
		}
	}
	parts.push(inner.slice(start));
	return parts.map((p) => p.trim()).filter(Boolean);
}

// Arrays and tables nested deeper than this are left as text.
const MAX_DEPTH = 32;

// The text of a basic string, escapes and all: \\n, \\uXXXX and \\UXXXXXXXX,
// and in a multi-line string a backslash at the end of a line, which joins
// it to the next one.
function tomlBasic(text) {
	let out = "";
	for (let i = 0; i < text.length; i++) {
		const c = text[i];
		if (c !== "\\") {
			out += c;
			continue;
		}
		const n = text[i + 1];
		if (n === undefined) break;
		const simple = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", e: "\x1b", '"': '"', "\\": "\\" }[n];
		if (simple !== undefined) {
			out += simple;
			i++;
		} else if (n === "u" || n === "U") {
			const hex = text.slice(i + 2, i + (n === "u" ? 6 : 10));
			const code = hex.length === (n === "u" ? 4 : 8) && /^[0-9A-Fa-f]+$/.test(hex) ? Number.parseInt(hex, 16) : NaN;
			out += code <= 0x10ffff ? String.fromCodePoint(code) : "";
			i += 1 + hex.length;
		} else if (/[ \t\r\n]/.test(n)) {
			// The end of a line: skip it and the spaces that start the next.
			let j = i + 1;
			while (j < text.length && /[ \t]/.test(text[j])) j++;
			if (text[j] === "\r") j++;
			if (text[j] !== "\n") {
				out += c;
				continue;
			}
			while (j < text.length && /\s/.test(text[j])) j++;
			i = j - 1;
		} else {
			out += n;
			i++;
		}
	}
	return out;
}

function parseValue(raw, depth = 0) {
	if (depth > MAX_DEPTH) return raw;
	if (raw.startsWith('"""')) return tomlBasic(raw.slice(3, raw.lastIndexOf('"""')).replace(/^\r?\n/, ""));
	if (raw.startsWith("'''")) return raw.slice(3, raw.lastIndexOf("'''")).replace(/^\r?\n/, "");
	if (raw.startsWith('"')) return tomlBasic(raw.slice(1, raw.lastIndexOf('"')));
	if (raw.startsWith("'")) return raw.slice(1, raw.lastIndexOf("'"));
	if (raw === "true") return true;
	if (raw === "false") return false;
	if (/^[+-]?\d[\d_]*(\.\d+)?$/.test(raw)) return Number(raw.replace(/_/g, ""));
	if (raw.startsWith("[")) {
		return splitTopLevel(raw.slice(1, raw.lastIndexOf("]")).replace(/\n/g, " ")).map((part) => parseValue(part, depth + 1));
	}
	if (raw.startsWith("{")) {
		const obj = {};
		for (const part of splitTopLevel(raw.slice(1, raw.lastIndexOf("}")))) {
			const eq = findTopLevel(part, "=");
			if (eq < 0) continue;
			const keys = splitKey(part.slice(0, eq));
			if (keys.some((k) => UNSAFE_KEYS.has(k))) continue;
			ensure(obj, keys.slice(0, -1))[keys[keys.length - 1]] = parseValue(part.slice(eq + 1).trim(), depth + 1);
		}
		return obj;
	}
	return raw;
}

// Enough YAML for the agent settings written in it (Continue's config.yaml
// and Goose's config.yaml): block mappings and lists, plain and quoted
// scalars, comments, and simple [a, b] and {a: b} values on one line.
// Anchors, tags and multi-line strings aren't used there and are kept as
// text. Returns undefined when the top isn't a mapping or a list.
export function parseYAML(text) {
	const items = [];
	for (const raw of String(text).replace(/^\ufeff/, "").split(/\r?\n/).slice(0, 20_000)) {
		if (/^\s*(?:#|$)/.test(raw) || /^(?:---|\.\.\.)(?:\s|$)/.test(raw)) continue;
		// Tabs count as indentation here, as a lenient reader would take them.
		const indent = /^[ \t]*/.exec(raw)[0].length;
		items.push({ indent, text: yamlStripComment(raw.slice(indent)).trimEnd() });
	}
	// A document written as one flow mapping or list, such as {a: 1, b: 2}.
	const whole = items.map((x) => x.text).join(" ").trim();
	if (/^\{[\s\S]*\}$|^\[[\s\S]*\]$/.test(whole) && whole.length <= 200_000) {
		const flow = yamlScalar(whole);
		return flow && typeof flow === "object" ? flow : undefined;
	}
	const anchors = new Map();
	// Aliases share what they point to, so a chain of them can describe a
	// huge document in a few lines. Past this many nodes, aliases read as null.
	let aliasBudget = 20_000;
	const sizeOf = (v, cap = 20_001) => {
		let n = 0;
		const stack = [v];
		while (stack.length && n < cap) {
			const x = stack.pop();
			n++;
			if (x && typeof x === "object") stack.push(...(Array.isArray(x) ? x : Object.values(x)).slice(0, cap));
		}
		return n;
	};
	let i = 0;
	const node = (indent, depth) => {
		if (i >= items.length || items[i].indent < indent || depth > 20) return null;
		return /^-(?:\s|$)/.test(items[i].text) ? list(items[i].indent, depth) : map(items[i].indent, depth);
	};
	// A value after "key:" or "- ": tags are dropped, &name records it and
	// *name uses what was recorded, and | or > take the lines indented below.
	const value = (rest, indent, depth) => {
		let text = rest.replace(/^!{1,2}[^\s]*\s*/, "");
		const anchor = /^&([^\s]{1,100})\s*/.exec(text);
		if (anchor) text = text.slice(anchor[0].length).replace(/^!{1,2}[^\s]*\s*/, "");
		let out;
		const alias = /^\*([^\s]{1,100})$/.exec(text);
		if (alias) {
			out = anchors.has(alias[1]) ? anchors.get(alias[1]) : null;
			if (out && typeof out === "object" && (aliasBudget -= sizeOf(out)) < 0) out = null;
		}
		else if (/^[|>][+-]?\d?$/.test(text)) {
			const lines = [];
			while (i < items.length && items[i].indent > indent && lines.length < 10_000) lines.push(items[i++].text);
			out = lines.join(text.startsWith("|") ? "\n" : " ");
		} else if (text) out = yamlScalar(text, depth);
		else if (i < items.length && (items[i].indent > indent || (items[i].indent === indent && /^-(?:\s|$)/.test(items[i].text)))) out = node(items[i].indent, depth + 1);
		else out = null;
		if (anchor && anchors.size < 1000) anchors.set(anchor[1], out);
		return out;
	};
	const list = (indent, depth) => {
		const out = [];
		while (i < items.length && items[i].indent === indent && /^-(?:\s|$)/.test(items[i].text) && out.length < 10_000) {
			const rest = items[i].text.slice(1).trimStart();
			if (rest && yamlKey(rest)) {
				// "- name: x" starts a mapping whose keys line up after the dash.
				items[i] = { indent: indent + (items[i].text.length - rest.length), text: rest };
				out.push(map(items[i].indent, depth + 1));
			} else {
				i++;
				out.push(value(rest, indent, depth));
			}
		}
		return out;
	};
	const map = (indent, depth) => {
		const out = {};
		while (i < items.length && items[i].indent === indent && !/^-(?:\s|$)/.test(items[i].text)) {
			const kv = yamlKey(items[i].text);
			i++;
			if (!kv) continue;
			const [key, rest] = kv;
			const v = value(rest, indent, depth);
			if (!UNSAFE_KEYS.has(key)) out[key] = v;
		}
		return out;
	};
	const top = node(0, 0);
	return top && typeof top === "object" ? top : undefined;
}

// The text before a comment: "#" at the start or after a space, outside quotes.
function yamlStripComment(line) {
	let quote = null;
	for (let j = 0; j < line.length; j++) {
		const c = line[j];
		if (quote) {
			if (c === quote) quote = null;
		} else if (c === '"' || c === "'") quote = c;
		else if (c === "#" && (j === 0 || /\s/.test(line[j - 1]))) return line.slice(0, j);
	}
	return line;
}

// "key: value" or "key:", with a plain or quoted key, as [key, value].
function yamlKey(text) {
	const m = /^(?:"((?:[^"\\]|\\.){0,200})"|'((?:[^']|''){0,200})'|([^\s"'[\]{}#,:][^:#]{0,200}?))\s*:(?:\s+(.*))?$/.exec(text);
	if (!m) return null;
	const key = m[1] ?? (m[2] !== undefined ? m[2].replace(/''/g, "'") : m[3].trim());
	return [key, (m[4] ?? "").trim()];
}

function yamlScalar(text, depth = 0) {
	const t = text.trim();
	if (t.startsWith('"') && t.endsWith('"') && t.length >= 2) return t.slice(1, -1).replace(/\\(["\\/])/g, "$1").replace(/\\n/g, "\n").replace(/\\t/g, "\t");
	if (t.startsWith("'") && t.endsWith("'") && t.length >= 2) return t.slice(1, -1).replace(/''/g, "'");
	if (depth < 10 && t.startsWith("[") && t.endsWith("]")) return yamlFlowItems(t.slice(1, -1)).map((x) => yamlScalar(x, depth + 1));
	if (depth < 10 && t.startsWith("{") && t.endsWith("}")) {
		const out = {};
		for (const part of yamlFlowItems(t.slice(1, -1))) {
			const kv = yamlKey(part);
			if (kv && !UNSAFE_KEYS.has(kv[0])) out[kv[0]] = yamlScalar(kv[1], depth + 1);
		}
		return out;
	}
	if (/^(?:true|yes|on)$/i.test(t)) return true;
	if (/^(?:false|no|off)$/i.test(t)) return false;
	if (/^(?:null|~)$/i.test(t) || t === "") return null;
	return t;
}

// The items of a one-line [..] or {..}, split at commas outside quotes and brackets.
function yamlFlowItems(inner) {
	const parts = [];
	let depth = 0;
	let quote = null;
	let start = 0;
	for (let j = 0; j < inner.length; j++) {
		const c = inner[j];
		if (quote) {
			if (c === quote) quote = null;
		} else if (c === '"' || c === "'") quote = c;
		else if (c === "[" || c === "{") depth++;
		else if (c === "]" || c === "}") depth--;
		else if (c === "," && depth === 0) {
			parts.push(inner.slice(start, j));
			start = j + 1;
		}
	}
	parts.push(inner.slice(start));
	return parts.map((p) => p.trim()).filter(Boolean).slice(0, 1000);
}

// --- Codex rules files -------------------------------------------------------
//
// A Codex .rules file is Starlark. Only its prefix_rule(...) calls matter
// here: each one's pattern, a list whose items are a word or a list of
// alternative words, and its decision, which is "allow" when a rule doesn't
// give one. Comments and the text inside strings are skipped, so a rule
// can't hide behind a parenthesis in its justification, and a name set to a
// string or list at the top of the file is looked up where a rule uses it.
// Rules made by functions or loops aren't followed.

const RULES_MAX = 200_000;

function starSpace(src, i) {
	while (i < src.length) {
		if (/\s/.test(src[i])) i++;
		else if (src[i] === "#") {
			const nl = src.indexOf("\n", i);
			i = nl < 0 ? src.length : nl + 1;
		} else break;
	}
	return i;
}

// A string literal at i, as [text, end], or null. Handles '', "", triple
// quotes and one r or b prefix.
function starString(src, i) {
	let j = i;
	let raw = false;
	if (/[rRbB]/.test(src[j]) && /["']/.test(src[j + 1] ?? "")) {
		raw = /[rR]/.test(src[j]);
		j++;
	}
	const q = src[j];
	if (q !== '"' && q !== "'") return null;
	const close = src.startsWith(q.repeat(3), j) ? q.repeat(3) : q;
	let k = j + close.length;
	let text = "";
	while (k < src.length) {
		if (src.startsWith(close, k)) return [text, k + close.length];
		const c = src[k];
		if (close.length === 1 && c === "\n") return [text, k];
		if (c === "\\" && k + 1 < src.length) {
			const n = src[k + 1];
			text += raw ? c + n : n === "n" ? "\n" : n === "t" ? "\t" : n;
			k += 2;
			continue;
		}
		text += c;
		k++;
	}
	return [text, k];
}

// A value at i, as [value, end]: a string, a list, or { name } for anything
// else, such as a name or a number.
function starValue(src, i, depth = 0) {
	i = starSpace(src, i);
	const str = starString(src, i);
	if (str) return str;
	const open = src[i];
	if ((open === "[" || open === "(") && depth < 4) {
		const close = open === "[" ? "]" : ")";
		const items = [];
		let j = i + 1;
		// Anything but values and commas, such as "pu" + "sh", is code this
		// reader doesn't run, so the list holds a null where it was.
		let odd = false;
		for (let n = 0; n < 200; n++) {
			j = starSpace(src, j);
			if (j >= src.length) break;
			if (src[j] === close) return [odd ? [...items, null] : items, j + 1];
			const [v, next] = starValue(src, j, depth + 1);
			if (next <= j) {
				odd = true;
				j++;
				continue;
			}
			items.push(v);
			j = starSpace(src, next);
			if (src[j] === ",") j++;
			else if (src[j] !== close) odd = true;
		}
		return [odd ? [...items, null] : items, j];
	}
	const m = /^(?:[A-Za-z_][\w.]*|-?\d[\w.]*)/.exec(src.slice(i, i + 200));
	return m ? [{ name: m[0] }, i + m[0].length] : [undefined, i];
}

// The arguments of a call whose "(" is just before i, as [{ named,
// positional }, end].
function starArgs(src, i) {
	const named = {};
	const positional = [];
	let complex = false;
	let j = i;
	for (let n = 0; n < 50; n++) {
		j = starSpace(src, j);
		if (j >= src.length) break;
		if (src[j] === ")") return [{ named, positional, complex }, j + 1];
		const key = /^([A-Za-z_]\w*)\s*=(?!=)/.exec(src.slice(j, j + 100));
		if (key) j = starSpace(src, j + key[0].length);
		const [v, next] = starValue(src, j);
		if (next <= j) {
			complex = true;
			j++;
			continue;
		}
		if (key) {
			if (!Object.hasOwn(named, key[1]) && !UNSAFE_KEYS.has(key[1])) named[key[1]] = v;
		} else positional.push(v);
		j = starSpace(src, next);
		if (src[j] === ",") j++;
		else if (src[j] !== ")") complex = true;
	}
	return [{ named, positional, complex: true }, j];
}

export function parseCodexRules(text) {
	const src = String(text ?? "").slice(0, RULES_MAX);
	const names = new Map();
	const calls = [];
	let i = 0;
	while (i < src.length && calls.length < 500) {
		const c = src[i];
		if (c === "#") {
			const nl = src.indexOf("\n", i);
			i = nl < 0 ? src.length : nl + 1;
			continue;
		}
		const str = /\w/.test(src[i - 1] ?? "") ? null : starString(src, i);
		if (str) {
			i = Math.max(str[1], i + 1);
			continue;
		}
		const word = /\w/.test(src[i - 1] ?? "") || src[i - 1] === "." ? null : /^[A-Za-z_]\w*/.exec(src.slice(i, i + 100))?.[0];
		if (!word) {
			i++;
			continue;
		}
		let j = starSpace(src, i + word.length);
		if (word === "prefix_rule" && src[j] === "(") {
			const [args, end] = starArgs(src, j + 1);
			calls.push({ index: i, ...args });
			i = end;
			continue;
		}
		// A name set at the start of a line, such as SHELLS = ["bash", "sh"].
		const lineStart = i === 0 || src[i - 1] === "\n";
		if (lineStart && src[j] === "=" && src[j + 1] !== "=") {
			const [v, end] = starValue(src, j + 1);
			if (typeof v === "string" || Array.isArray(v)) names.set(word, v);
			i = Math.max(end, j + 1);
			continue;
		}
		i += word.length;
	}
	const resolve = (v, depth = 0) => {
		if (v && typeof v === "object" && !Array.isArray(v)) return depth < 4 && names.has(v.name) ? resolve(names.get(v.name), depth + 1) : undefined;
		if (Array.isArray(v)) return depth < 6 ? v.map((x) => resolve(x, depth + 1)) : [];
		return v;
	};
	// A rule this reader can't follow: made in a function or a loop from a
	// name it doesn't know, or from an expression such as "pu" + "sh".
	return calls.map(({ index, named, positional, complex }) => {
		const pattern = resolve(named.pattern ?? positional[0]);
		const decision = named.decision === undefined ? "allow" : resolve(named.decision);
		const justification = resolve(named.justification);
		const words = Array.isArray(pattern) ? pattern.map((w) => (Array.isArray(w) ? (w.every((x) => typeof x === "string") ? w : null) : typeof w === "string" ? w : null)) : null;
		return {
			index,
			pattern: words,
			decision: typeof decision === "string" ? decision.trim().toLowerCase() : "",
			justification: typeof justification === "string" ? justification : "",
			unread: complex || !words || words.includes(null) || typeof decision !== "string",
		};
	});
}
