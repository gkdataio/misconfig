// Glob and .gitignore matching for paths in a project. The patterns come from
// the files being checked, so they're matched by stepping through the path
// once, never by building a regular expression a crafted pattern could stall.

// Tokens: a literal character, "?" (one character in a name), "*" (any run in
// a name), "**" as a whole name (any run, across folders), "**/" (any number
// of whole folders) and character classes such as [abc] or [!0-9]. As in git,
// "**" next to other characters, as in a**b, is an ordinary "*".
function tokenize(glob) {
	const tokens = [];
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i];
		if (c === "\\" && i + 1 < glob.length) {
			tokens.push({ lit: glob[++i].toLowerCase() });
		} else if (c === "*") {
			let j = i;
			while (glob[j + 1] === "*") j++;
			const wholeName = j > i && (i === 0 || glob[i - 1] === "/");
			if (wholeName && glob[j + 1] === "/") {
				tokens.push({ folders: true });
				j++;
			} else if (wholeName && j + 1 === glob.length) tokens.push({ any: true });
			else tokens.push({ star: true });
			i = j;
		} else if (c === "?") {
			tokens.push({ one: true });
		} else if (c === "[") {
			const end = glob.indexOf("]", i + 2);
			if (end < 0) {
				tokens.push({ lit: c });
				continue;
			}
			let body = glob.slice(i + 1, end).toLowerCase();
			const negate = body[0] === "!" || body[0] === "^";
			if (negate) body = body.slice(1);
			tokens.push({ set: body, negate });
			i = end;
		} else {
			tokens.push({ lit: c.toLowerCase() });
		}
	}
	return tokens;
}

function inSet(token, c) {
	const s = token.set;
	let hit = false;
	for (let i = 0; i < s.length && !hit; i++) {
		if (s[i + 1] === "-" && i + 2 < s.length) {
			hit = c >= s[i] && c <= s[i + 2];
			i += 2;
		} else hit = c === s[i];
	}
	return hit !== token.negate;
}

// Whether `path` matches the whole glob, case-insensitively like git on
// Windows and macOS. Takes time proportional to path length × pattern length.
export function globMatch(glob, path) {
	const tokens = typeof glob === "string" ? tokenize(glob) : glob;
	const n = tokens.length;
	// at[i]: matched up to token i. inside[i]: part way through the folders
	// of a "**/" token.
	let at = new Uint8Array(n + 1);
	let inside = new Uint8Array(n + 1);
	let nextAt = new Uint8Array(n + 1);
	let nextInside = new Uint8Array(n + 1);
	const reach = (set, i) => {
		while (i <= n && !set[i]) {
			set[i] = 1;
			const t = tokens[i];
			if (!t || !(t.star || t.any || t.folders)) break;
			i++;
		}
	};
	reach(at, 0);
	for (const c of path.toLowerCase()) {
		nextAt.fill(0);
		nextInside.fill(0);
		let alive = false;
		for (let i = 0; i < n; i++) {
			const t = tokens[i];
			if (t.folders) {
				if (!at[i] && !inside[i]) continue;
				nextInside[i] = 1;
				alive = true;
				if (c === "/") reach(nextAt, i + 1);
			} else if (!at[i]) {
				continue;
			} else if (t.star) {
				if (c !== "/") reach(nextAt, i);
			} else if (t.any) {
				reach(nextAt, i);
			} else if (t.one) {
				if (c !== "/") reach(nextAt, i + 1);
			} else if (t.set) {
				if (c !== "/" && inSet(t, c)) reach(nextAt, i + 1);
			} else if (t.lit === c) {
				reach(nextAt, i + 1);
			}
		}
		[at, nextAt] = [nextAt, at];
		[inside, nextInside] = [nextInside, inside];
		if (!alive && !at.includes(1)) return false;
	}
	return at[n] === 1;
}

// One line of an ignore file. `base` is the folder the file applies to,
// relative to the project, or "" for the whole project.
function compileRule(line, base) {
	let p = line.replace(/\r$/, "");
	if (!p || p.startsWith("#")) return null;
	// Trailing spaces don't count unless escaped with a backslash.
	let end = p.length;
	while (end > 0 && p[end - 1] === " " && p[end - 2] !== "\\") end--;
	p = p.slice(0, end);
	if (!p) return null;
	let negate = false;
	if (p.startsWith("!")) {
		negate = true;
		p = p.slice(1);
	} else if (p.startsWith("\\!") || p.startsWith("\\#")) {
		p = p.slice(1);
	}
	let dirOnly = false;
	if (p.endsWith("/")) {
		dirOnly = true;
		p = p.replace(/\/+$/, "");
	}
	if (!p) return null;
	// A slash at the start or in the middle ties the pattern to the folder the
	// file is in. Without one, it matches a name at any depth.
	const anchored = p.includes("/");
	p = p.replace(/^\/+/, "");
	return { tokens: tokenize(anchored ? p : `**/${p}`), negate, dirOnly, base };
}

export function ignoreRules(content, base = "") {
	return String(content)
		.split("\n")
		.slice(0, 2000)
		.map((line) => compileRule(line.slice(0, 300), base))
		.filter(Boolean);
}

// Pattern work allowed for one question, unless the caller shares a budget
// across many. Rules built to be slow are treated as ignoring everything
// rather than holding up the check.
const BUDGET = 4_000_000;

function decide(rules, path, isDir, budget) {
	let ignored = false;
	for (const r of rules) {
		if (r.dirOnly && !isDir) continue;
		let rel = path;
		if (r.base) {
			if (!path.startsWith(`${r.base}/`)) continue;
			rel = path.slice(r.base.length + 1);
		}
		budget.left -= rel.length * (r.tokens.length + 1);
		if (budget.left < 0) return true;
		if (globMatch(r.tokens, rel)) ignored = !r.negate;
	}
	return ignored;
}

// Whether git ignores a file, by git's rules. `rules` run from lowest
// precedence to highest, the last one that matches wins, "!" brings a file
// back, and a file inside an ignored folder stays ignored.
export function isIgnored(rules, path, budget = { left: BUDGET }) {
	if (!rules.length) return false;
	const parts = path.split("/");
	for (let i = 1; i < parts.length; i++) {
		if (decide(rules, parts.slice(0, i).join("/"), true, budget)) return true;
	}
	return decide(rules, path, false, budget);
}
