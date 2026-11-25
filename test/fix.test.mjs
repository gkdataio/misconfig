// --fix: the changes it makes, and the ones it won't. A file it changes
// must read back as exactly the change, keep its comments and format, and be
// backed up first; a file that's a link, outside the project and home
// folder, or changed while it ran is left alone.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, rm, stat, symlink, chmod, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../engine/index.js";
import { discover } from "../lib/discover.js";
import { planFixes, applyFixes, npxVersion } from "../lib/fix.js";

const BIN = fileURLToPath(new URL("../bin/misconfig.js", import.meta.url));
const J = (value) => JSON.stringify(value, null, 2);
const POSIX = process.platform !== "win32";

let base;
before(async () => {
	base = await mkdtemp(path.join(tmpdir(), "misconfig-fix-"));
});
after(async () => {
	await rm(base, { recursive: true, force: true });
});

// A made-up home folder, with a project in it and npx's cache.
async function setup(name, files) {
	const home = path.join(base, name);
	const project = path.join(home, "code", "shop");
	await mkdir(project, { recursive: true });
	for (const [rel, content] of Object.entries(files)) {
		const abs = path.join(home, ...rel.split("/"));
		await mkdir(path.dirname(abs), { recursive: true });
		await writeFile(abs, content);
	}
	const read = (rel) => readFile(path.join(home, ...rel.split("/")), "utf8");
	return { home, project, read };
}

// npx's copy of a package, as npm keeps it.
async function npxCache(home, pkg, version, folder = "0123456789abcdef") {
	const dir = path.join(home, ".npm", "_npx", folder);
	await mkdir(path.join(dir, "node_modules", ...pkg.split("/")), { recursive: true });
	await writeFile(path.join(dir, "package.json"), J({ dependencies: { [pkg]: "*" } }));
	await writeFile(path.join(dir, "node_modules", ...pkg.split("/"), "package.json"), J({ name: pkg, version }));
	return dir;
}

function run({ home, project }, args, { input = null, env: extra = {} } = {}) {
	const env = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, "AppData", "Roaming"), LOCALAPPDATA: path.join(home, "AppData", "Local"), NO_COLOR: "1", COLUMNS: "100", MISCONFIG_OFFLINE: "1" };
	for (const key of ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "FORCE_COLOR", "MISCONFIG_URL", "DO_NOT_TRACK", "npm_config_cache", "NPM_CONFIG_CACHE"]) delete env[key];
	// The tests run in CI too, where --fix refuses to run.
	for (const key of Object.keys(env)) if (/^(?:CI|GITHUB_ACTIONS|GITHUB_WORKSPACE|GITHUB_STEP_SUMMARY|TF_BUILD|JENKINS_URL|TEAMCITY_VERSION|GITLAB_CI|BUILDKITE|CIRCLECI|TRAVIS|CODEBUILD_BUILD_ID|BITBUCKET_BUILD_NUMBER|DRONE|APPVEYOR|BUILD_BUILDID)$/.test(key)) delete env[key];
	if (!POSIX) env.npm_config_cache = path.join(home, ".npm");
	Object.assign(env, extra);
	return new Promise((resolve) => {
		const child = spawn(process.execPath, [BIN, ...args], { cwd: project, env, stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d) => (stdout += d));
		child.stderr.on("data", (d) => (stderr += d));
		child.stdin.end(input ?? undefined);
		child.on("close", (code) => resolve({ code, stdout, stderr }));
	});
}
// Output with its lines joined, for text that wraps.
const flat = (s) => s.replace(/\s+/g, " ");
const ids = async (s, args = []) => JSON.parse((await run(s, ["--json", ...args])).stdout).findings.map((f) => f.id);

const SETTINGS = `{
  // Team settings. Keep this comment.
  "permissions": {
    /* "defaultMode": "bypassPermissions" in a comment stays as it is */
    "defaultMode": "bypassPermissions",
    "allow": [
      "Bash(*)",
      "Read", // reading is fine
      "Bash(*)",
    ],
  },
}
`;

test("--fix makes each change in place, keeps comments and format, and backs the files up", async () => {
	const s = await setup("all", {
		"code/shop/.claude/settings.json": SETTINGS,
		"code/shop/.mcp.json": J({ mcpServers: { fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "."] } } }),
		"code/shop/.vscode/settings.json": '{\n\t"editor.tabSize": 2,\n\t"chat.tools.autoApprove": true\n}\n',
		".codex/config.toml": '# mine\nmodel = "o4"\napproval_policy = "never" # for now\nsandbox_mode = "workspace-write"\n\n[profiles.fast]\napproval_policy = "never"\n',
	});
	await npxCache(s.home, "@modelcontextprotocol/server-filesystem", "2025.8.21", "aaaaaaaaaaaaaaaa");
	if (POSIX) await chmod(path.join(s.project, ".claude", "settings.json"), 0o640);
	const before = await ids(s);
	for (const id of ["CC-BYPASS-PROJECT", "CC-ALLOW-ALL-BASH", "MCP-UNPINNED", "VS-AUTO-APPROVE", "CX-NEVER-ASK"]) assert.ok(before.includes(id), id);

	const { code, stdout: text } = await run(s, ["--fix", "--yes"]);
	assert.equal(code, 0, text);
	const stdout = flat(text);
	assert.match(stdout, /Set permissions\.defaultMode to "default"/);
	assert.match(stdout, /Pin @modelcontextprotocol\/server-filesystem to 2025\.8\.21/);
	assert.match(stdout, /The originals are in ~\/\.misconfig\/backups\//);
	// What the grade will be is worked out before anything changes.
	assert.match(stdout, /With these changes the grade goes from [A-F] \(\d+\) to [A-F] \(\d+\)\./);
	// Codex's profile is all that's left.
	assert.match(stdout, /1 finding is left after these/);

	assert.equal(
		await s.read("code/shop/.claude/settings.json"),
		`{
  // Team settings. Keep this comment.
  "permissions": {
    /* "defaultMode": "bypassPermissions" in a comment stays as it is */
    "defaultMode": "default",
    "allow": [
      "Read", // reading is fine
    ],
  },
}
`,
	);
	assert.match(await s.read("code/shop/.mcp.json"), /"@modelcontextprotocol\/server-filesystem@2025\.8\.21"/);
	assert.equal(await s.read("code/shop/.vscode/settings.json"), '{\n\t"editor.tabSize": 2,\n\t"chat.tools.autoApprove": false\n}\n');
	// The top level changes; a profile is changed by hand.
	assert.equal(await s.read(".codex/config.toml"), '# mine\nmodel = "o4"\napproval_policy = "on-request" # for now\nsandbox_mode = "workspace-write"\n\n[profiles.fast]\napproval_policy = "never"\n');
	if (POSIX) assert.equal((await stat(path.join(s.project, ".claude", "settings.json"))).mode & 0o777, 0o640);

	// The originals, as they were, readable only by you.
	const backups = path.join(s.home, ".misconfig", "backups");
	const [stamp] = await readdir(backups);
	assert.equal(await readFile(path.join(backups, stamp, "project", ".claude", "settings.json"), "utf8"), SETTINGS);
	assert.match(await readFile(path.join(backups, stamp, "home", ".codex", "config.toml"), "utf8"), /approval_policy = "never" # for now/);
	if (POSIX) assert.equal((await stat(path.join(backups, stamp, "project", ".claude", "settings.json"))).mode & 0o777, 0o600);

	const after = await ids(s);
	for (const id of ["CC-BYPASS-PROJECT", "CC-ALLOW-ALL-BASH", "MCP-UNPINNED", "VS-AUTO-APPROVE"]) assert.ok(!after.includes(id), id);
	// Only the profile's is left.
	assert.equal(after.filter((id) => id === "CX-NEVER-ASK").length, 1);
	// Run again, nothing is left to fix.
	const again = await run(s, ["--fix", "--yes"]);
	assert.equal(again.code, 0);
	assert.match(again.stdout, /Nothing here can be fixed for you/);
});

test("--fix asks first: without a terminal or --yes nothing changes", async () => {
	const s = await setup("ask", { "code/shop/.claude/settings.json": J({ permissions: { allow: ["Bash"] } }) });
	const { code, stdout, stderr } = await run(s, ["--fix"]);
	assert.equal(code, 2);
	assert.match(stdout, /Remove Bash from permissions\.allow/);
	assert.match(stderr, /Nothing was changed\. Add --yes/);
	assert.equal(await s.read("code/shop/.claude/settings.json"), J({ permissions: { allow: ["Bash"] } }));
	assert.ok(!(await stat(path.join(s.home, ".misconfig")).catch(() => null)));
});

test("a plain JSON file stays plain JSON, and the only rule in a list leaves []", async () => {
	const s = await setup("plain", { "code/shop/.claude/settings.json": '{\n  "permissions": {\n    "allow": [\n      "Bash(*)"\n    ]\n  }\n}\n' });
	assert.equal((await run(s, ["--fix", "--yes", "--project-only"])).code, 0);
	const text = await s.read("code/shop/.claude/settings.json");
	assert.equal(text, '{\n  "permissions": {\n    "allow": []\n  }\n}\n');
	JSON.parse(text);
});

test("--fix won't change a link, a setting that's in a file twice, or a template", async () => {
	const s = await setup("refuse", {
		"code/shop/real/settings.json": J({ permissions: { defaultMode: "bypassPermissions" } }),
		"code/shop/.cursor/mcp.json": '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}',
		"code/shop/.vscode/settings.json": '{"chat.tools.autoApprove": false, "chat.tools.autoApprove": true}',
		"code/shop/templates/agent/.claude/settings.json": J({ permissions: { allow: ["Bash(*)"] } }),
	});
	await mkdir(path.join(s.project, ".claude"), { recursive: true });
	const linked = await symlink(path.join(s.project, "real", "settings.json"), path.join(s.project, ".claude", "settings.json")).then(
		() => true,
		() => false,
	);
	const { code, stdout: text } = await run(s, ["--fix", "--yes", "--project-only"]);
	assert.equal(code, 0);
	const stdout = flat(text);
	if (linked) assert.match(stdout, /it's a link, and --fix doesn't change the file a link points to/);
	assert.match(stdout, /the setting is in the file more than once/);
	assert.match(stdout, /npx has no copy of @modelcontextprotocol\/server-filesystem on this computer/);
	assert.doesNotMatch(stdout, /templates\/agent/);
	assert.equal(await s.read("code/shop/real/settings.json"), J({ permissions: { defaultMode: "bypassPermissions" } }));
	assert.equal(await s.read("code/shop/.vscode/settings.json"), '{"chat.tools.autoApprove": false, "chat.tools.autoApprove": true}');
	assert.equal(await s.read("code/shop/templates/agent/.claude/settings.json"), J({ permissions: { allow: ["Bash(*)"] } }));
	assert.ok(!(await stat(path.join(s.home, ".misconfig")).catch(() => null)));
});

test("a file changed after --fix read it is left with your change", async () => {
	const s = await setup("race", { "code/shop/.claude/settings.json": J({ permissions: { defaultMode: "bypassPermissions" } }) });
	const input = await discover({ dir: s.project, includeUser: false, home: s.home });
	const result = analyze(input);
	const plans = await planFixes(result, input, { dir: s.project, home: s.home });
	assert.equal(plans[0].edits.length, 1);
	await writeFile(path.join(s.project, ".claude", "settings.json"), J({ permissions: { defaultMode: "acceptEdits" } }));
	const done = await applyFixes(plans, { home: s.home });
	assert.equal(done.changed.length, 0);
	assert.match(done.failed[0].why, /changed while --fix ran/);
	assert.equal(await s.read("code/shop/.claude/settings.json"), J({ permissions: { defaultMode: "acceptEdits" } }));
});

test("--fix doesn't run in CI or with options that check", async () => {
	const s = await setup("ci", { "code/shop/.claude/settings.json": J({ permissions: { allow: ["Bash"] } }) });
	const ci = await run(s, ["--fix", "--yes"], { env: { CI: "true" } });
	assert.equal(ci.code, 2);
	assert.match(ci.stderr, /doesn't run in CI/);
	const json = await run(s, ["--fix", "--json"]);
	assert.equal(json.code, 2);
	assert.match(json.stderr, /--fix runs on its own, without --json/);
	assert.equal(await s.read("code/shop/.claude/settings.json"), J({ permissions: { allow: ["Bash"] } }));
});

test("an attack path is fixed only by a change that ends it", async () => {
	const mcp = J({ mcpServers: { github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github@2025.4.8"] }, slack: { command: "npx", args: ["-y", "@modelcontextprotocol/server-slack@2025.4.25"] } } });
	// The GitHub server reads issues, can read private repositories and can
	// write to public ones: removing its one allow rule ends the path.
	const one = await setup("path-one", { "code/shop/.mcp.json": mcp, "code/shop/.claude/settings.json": J({ permissions: { allow: ["mcp__github"] } }) });
	const found = analyze(await discover({ dir: one.project, includeUser: false, home: one.home })).findings.find((f) => f.id === "AGENT-ATTACK-PATH");
	assert.ok(found);
	assert.deepEqual(found.autofix && [found.autofix.type, found.autofix.value], ["json-remove", "mcp__github"]);
	// Two servers each send data out: removing one rule doesn't end it.
	const two = await setup("path-two", { "code/shop/.mcp.json": mcp, "code/shop/.claude/settings.json": J({ permissions: { allow: ["mcp__github", "mcp__slack"] } }) });
	const both = analyze(await discover({ dir: two.project, includeUser: false, home: two.home })).findings.find((f) => f.id === "AGENT-ATTACK-PATH");
	if (both) assert.equal(both.autofix, undefined);
});

test("npx's newest copy of a package gives the version, and anything else is ignored", async () => {
	const home = path.join(base, "npx");
	const old = await npxCache(home, "mcp-thing", "1.0.0", "1111111111111111");
	const recent = await npxCache(home, "mcp-thing", "1.2.0", "2222222222222222");
	await npxCache(home, "mcp-thing", "not-a-version", "3333333333333333");
	await mkdir(path.join(home, ".npm", "_npx", "not-npx", "node_modules", "mcp-thing"), { recursive: true });
	const { utimes } = await import("node:fs/promises");
	await utimes(path.join(old, "package.json"), new Date(2026, 0, 1), new Date(2026, 0, 1));
	await utimes(path.join(recent, "package.json"), new Date(2026, 5, 1), new Date(2026, 5, 1));
	await utimes(path.join(home, ".npm", "_npx", "3333333333333333", "package.json"), new Date(2026, 9, 1), new Date(2026, 9, 1));
	const env = { npm_config_cache: path.join(home, ".npm") };
	assert.equal((await npxVersion("mcp-thing", { home, env }))?.version, "1.2.0");
	assert.equal(await npxVersion("../mcp-thing", { home, env }), null);
	assert.equal(await npxVersion("other", { home, env }), null);
});

test("a pin is made only for npx PACKAGE with no version, so the server still starts", async () => {
	const s = await setup("pins", {
		"code/shop/.mcp.json": J({
			mcpServers: {
				named: { command: "npx", args: ["-y", "--package=mcp-thing", "mcp-thing"] },
				ranged: { command: "npx", args: ["-y", "mcp-thing@1"] },
				listed: { command: ["npx", "-y", "mcp-thing"] },
				plain: { command: "npx", args: ["-y", "mcp-thing@latest"] },
			},
		}),
	});
	await npxCache(s.home, "mcp-thing", "2.0.0");
	const { code, stdout } = await run(s, ["--fix", "--yes", "--project-only"]);
	assert.equal(code, 0, stdout);
	const mcp = JSON.parse(await s.read("code/shop/.mcp.json")).mcpServers;
	assert.deepEqual(mcp.named.args, ["-y", "--package=mcp-thing", "mcp-thing"]);
	assert.deepEqual(mcp.ranged.args, ["-y", "mcp-thing@1"]);
	assert.deepEqual(mcp.listed.command, ["npx", "-y", "mcp-thing"]);
	assert.deepEqual(mcp.plain.args, ["-y", "mcp-thing@2.0.0"]);
});

test("a file is named by where it is, and a list in a TOML file isn't taken for a table", async () => {
	const s = await setup("two-names", {
		"dotfiles/codex/config.toml": 'notify = [\n  ["say", "done"],\n]\napproval_policy = "never"\n',
	});
	// CODEX_HOME moves ~/.codex/config.toml somewhere else in the home folder.
	const { code, stdout: text } = await run(s, ["--fix", "--yes"], { env: { CODEX_HOME: path.join(s.home, "dotfiles", "codex") } });
	const stdout = flat(text);
	assert.equal(code, 0, text);
	assert.match(stdout, /~\/dotfiles\/codex\/config\.toml Set approval_policy/);
	assert.doesNotMatch(stdout, /changed while --fix ran/);
	assert.equal(stdout.match(/Set approval_policy/g).length, 1);
	assert.equal(await s.read("dotfiles/codex/config.toml"), 'notify = [\n  ["say", "done"],\n]\napproval_policy = "on-request"\n');
	const [stamp] = await readdir(path.join(s.home, ".misconfig", "backups"));
	assert.ok(await stat(path.join(s.home, ".misconfig", "backups", stamp, "home", "dotfiles", "codex", "config.toml")));
});

test("a read-only file is left as it is", { skip: !POSIX && "file modes are POSIX" }, async () => {
	const s = await setup("read-only", { "code/shop/.claude/settings.json": J({ permissions: { allow: ["Bash"] } }) });
	await chmod(path.join(s.project, ".claude", "settings.json"), 0o444);
	const { code, stdout } = await run(s, ["--fix", "--yes", "--project-only"]);
	assert.equal(code, 0);
	assert.match(flat(stdout), /\.claude\/settings\.json: it's read-only\./);
	assert.equal(await s.read("code/shop/.claude/settings.json"), J({ permissions: { allow: ["Bash"] } }));
});

test("--fix doesn't run in CI systems that don't set CI", async () => {
	const s = await setup("azure", { "code/shop/.claude/settings.json": J({ permissions: { allow: ["Bash"] } }) });
	for (const env of [{ TF_BUILD: "True" }, { JENKINS_URL: "https://ci.example/" }, { GITHUB_ACTIONS: "true" }]) {
		const r = await run(s, ["--fix", "--yes"], { env });
		assert.equal(r.code, 2);
		assert.match(r.stderr, /doesn't run in CI/);
	}
	assert.equal(await s.read("code/shop/.claude/settings.json"), J({ permissions: { allow: ["Bash"] } }));
});

test("a project file that's also this computer's settings is changed once", async () => {
	const s = await setup("same-file", { "code/shop/.codex/config.toml": 'approval_policy = "never"\n' });
	const { code, stdout: text } = await run(s, ["--fix", "--yes"], { env: { CODEX_HOME: path.join(s.project, ".codex") } });
	const stdout = flat(text);
	assert.equal(code, 0, text);
	assert.equal(stdout.match(/Set approval_policy/g)?.length, 1, text);
	assert.doesNotMatch(stdout, /changed while --fix ran/);
	assert.match(stdout, /Changed \.codex\/config\.toml\./);
	assert.equal(await s.read("code/shop/.codex/config.toml"), 'approval_policy = "on-request"\n');
});

// --- --undo ----------------------------------------------------------------------

test("--undo puts back what --fix changed, byte for byte, and keeps edits made since", async () => {
	const s = await setup("undo", {
		"code/shop/.claude/settings.json": SETTINGS,
		"code/shop/.vscode/settings.json": '{\r\n\t"chat.tools.autoApprove": true\r\n}\r\n',
		".codex/config.toml": 'approval_policy = "never"\n',
	});
	const before = { claude: await s.read("code/shop/.claude/settings.json"), codex: await s.read(".codex/config.toml") };
	assert.equal((await run(s, ["--fix", "--yes"])).code, 0);
	assert.notEqual(await s.read("code/shop/.claude/settings.json"), before.claude);
	// You change one of the files after --fix: that change stays.
	await writeFile(path.join(s.project, ".vscode", "settings.json"), '{\r\n\t"chat.tools.autoApprove": false,\r\n\t"editor.tabSize": 2\r\n}\r\n');
	const ask = await run(s, ["--undo"]);
	assert.equal(ask.code, 2);
	assert.match(ask.stderr, /Nothing was changed\. Add --yes/);
	const { code, stdout: text } = await run(s, ["--undo", "--yes"]);
	const stdout = flat(text);
	assert.equal(code, 0, text);
	assert.match(stdout, /\.vscode\/settings\.json Changed since --fix changed it, so it's left as it is\. The original is in ~\/\.misconfig\/backups\//);
	assert.match(stdout, /Put back \.claude\/settings\.json and ~\/\.codex\/config\.toml\./);
	assert.equal(await s.read("code/shop/.claude/settings.json"), before.claude);
	assert.equal(await s.read(".codex/config.toml"), before.codex);
	assert.equal(await s.read("code/shop/.vscode/settings.json"), '{\r\n\t"chat.tools.autoApprove": false,\r\n\t"editor.tabSize": 2\r\n}\r\n');
	// The backups stay, and the run is done.
	const [stamp] = await readdir(path.join(s.home, ".misconfig", "backups"));
	assert.ok(await stat(path.join(s.home, ".misconfig", "backups", stamp, "project", ".claude", "settings.json")));
	assert.match((await run(s, ["--undo", "--yes"])).stdout, /There's no --fix to undo\./);
});

test("each --undo goes back one --fix", async () => {
	const s = await setup("undo-twice", { "code/shop/.claude/settings.json": J({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash"] } }) });
	const original = await s.read("code/shop/.claude/settings.json");
	// Two runs: the first fixes one thing, then a second fixes what's back.
	assert.equal((await run(s, ["--fix", "--yes", "--project-only"])).code, 0);
	const fixed = await s.read("code/shop/.claude/settings.json");
	await writeFile(path.join(s.project, ".claude", "settings.json"), J({ permissions: { defaultMode: "default", allow: ["Bash", "Bash(*)"] } }));
	const second = await s.read("code/shop/.claude/settings.json");
	await new Promise((done) => setTimeout(done, 5));
	assert.equal((await run(s, ["--fix", "--yes", "--project-only"])).code, 0);
	assert.equal((await run(s, ["--undo", "--yes"])).code, 0);
	assert.equal(await s.read("code/shop/.claude/settings.json"), second);
	// The first run's file was changed by hand since, so it stays.
	const again = await run(s, ["--undo", "--yes"]);
	assert.match(flat(again.stdout), /Changed since --fix changed it/);
	assert.equal(await s.read("code/shop/.claude/settings.json"), second);
	assert.notEqual(fixed, original);
});

test("a list of changes someone else wrote can't make --undo write anything", async () => {
	const s = await setup("undo-forged", { "code/shop/notes.txt": "mine\n", "code/shop/.mcp.json": J({ mcpServers: {} }) });
	const run1 = path.join(s.home, ".misconfig", "backups", "2026-11-04T10-00-00-000Z");
	await mkdir(path.join(run1, "project"), { recursive: true });
	const { createHash } = await import("node:crypto");
	const hash = (t) => createHash("sha256").update(t).digest("hex");
	await writeFile(path.join(run1, "project", "evil"), "evil\n");
	const forged = {
		format: "misconfig-fix",
		version: 1,
		at: "2026-11-04T10:00:00.000Z",
		files: [
			// Not a settings file.
			{ path: path.join(s.project, "notes.txt"), name: "notes.txt", backup: "project/evil", before: hash("evil\n"), after: hash("mine\n") },
		],
	};
	await writeFile(path.join(run1, "changes.json"), JSON.stringify(forged));
	let r = await run(s, ["--undo", "--yes"]);
	assert.equal(r.code, 2);
	assert.match(flat(r.stdout), /isn't one misconfig wrote, so nothing can be undone from it/);
	// A settings file, but a backup that isn't what the list says it is, or outside the run.
	forged.files = [
		{ path: path.join(s.project, ".mcp.json"), name: ".mcp.json", backup: "project/evil", before: hash("other\n"), after: hash(J({ mcpServers: {} })) },
		{ path: path.join(s.project, ".mcp.json"), name: ".mcp.json", backup: "project/../../x", before: hash("evil\n"), after: hash(J({ mcpServers: {} })) },
	];
	await writeFile(path.join(run1, "changes.json"), JSON.stringify(forged));
	r = await run(s, ["--undo", "--yes"]);
	assert.equal(r.code, 2);
	forged.files = forged.files.slice(0, 1);
	await writeFile(path.join(run1, "changes.json"), JSON.stringify(forged));
	r = await run(s, ["--undo", "--yes"]);
	assert.equal(r.code, 0);
	assert.match(flat(r.stdout), /Its backup is missing or was changed, so it can't be put back\./);
	assert.equal(await s.read("code/shop/notes.txt"), "mine\n");
	assert.equal(await s.read("code/shop/.mcp.json"), J({ mcpServers: {} }));
});

test("two runs at the same moment keep their own backups", async () => {
	const s = await setup("same-moment", { "code/shop/.claude/settings.json": J({ permissions: { allow: ["Bash"] } }) });
	const now = new Date("2026-11-04T12:00:00.000Z");
	for (let n = 0; n < 2; n++) {
		await writeFile(path.join(s.project, ".claude", "settings.json"), J({ permissions: { allow: ["Bash", `Read(${n})`] } }));
		const fresh = await discover({ dir: s.project, includeUser: false, home: s.home });
		const plans = await planFixes(analyze(fresh), fresh, { dir: s.project, home: s.home });
		await applyFixes(plans, { home: s.home, now });
	}
	const runs = (await readdir(path.join(s.home, ".misconfig", "backups"))).sort();
	assert.deepEqual(runs, ["2026-11-04T12-00-00-000Z", "2026-11-04T12-00-00-000Z-01"]);
	assert.match(await readFile(path.join(s.home, ".misconfig", "backups", runs[0], "project", ".claude", "settings.json"), "utf8"), /Read\(0\)/);
	assert.match(await readFile(path.join(s.home, ".misconfig", "backups", runs[1], "project", ".claude", "settings.json"), "utf8"), /Read\(1\)/);
});

// --- The computer's history ----------------------------------------------------

const history = async (s) => JSON.parse((await run(s, ["--history", "--json"])).stdout).events;
const review = async (s) => JSON.parse((await run(s, ["--json"])).stdout).computerReview;
const setting = (e) => [e.label, e.before, e.after].join(" ");

test("what --fix changes on the computer is in its history as --fix's edit, approved by you", async () => {
	const s = await setup("history", { ".claude/settings.json": J({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)", "Read"] } }) });
	// The computer's first check starts its history.
	await run(s, []);
	// Something else changes a setting in the same file before --fix runs.
	await writeFile(path.join(s.home, ".claude", "settings.json"), J({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)", "Read", "WebFetch"] } }));
	const fixed = await run(s, ["--fix", "--yes"]);
	assert.equal(fixed.code, 0, fixed.stderr);
	assert.match(flat(fixed.stdout), /1 setting on this computer changed since your last check/);
	assert.match(flat(fixed.stdout), /In this computer's history as changes you approved/);
	assert.deepEqual(JSON.parse(await s.read(".claude/settings.json")), { permissions: { defaultMode: "default", allow: ["Read", "WebFetch"] } });

	const events = await history(s);
	const by = (action, name) => events.filter((e) => e.action === action && e.editor?.name === name).map(setting).sort();
	assert.deepEqual(by("observed", "misconfig --fix"), ["Permission allow Bash(*) ", "permissions / defaultMode bypassPermissions default"]);
	assert.equal(by("approved", "misconfig --fix").length, 2);
	assert.ok(events.filter((e) => e.action === "approved").every((e) => typeof e.actor === "string" && e.actor));
	// The other change has no author, and nothing was approved for it.
	const other = events.find((e) => e.action === "observed" && e.after === "WebFetch");
	assert.equal(other.editor, null);
	assert.ok(!events.some((e) => e.action === "approved" && e.after === "WebFetch"));

	// The next check has nothing new, and asks only about what --fix didn't change.
	const next = await review(s);
	assert.deepEqual(next.changes, []);
	assert.deepEqual(next.pending.map((r) => r.after).sort(), ["Read", "WebFetch"]);

	// --undo shows the files, not each setting, so what it puts back waits for approval.
	const undone = await run(s, ["--undo", "--yes"]);
	assert.equal(undone.code, 0, undone.stderr);
	assert.doesNotMatch(undone.stdout, /you approved/);
	const back = await review(s);
	assert.deepEqual(back.changes, []);
	const waiting = back.pending.filter((r) => r.editor?.name === "misconfig --undo").map(setting).sort();
	assert.deepEqual(waiting, ["Permission allow  Bash(*)", "permissions / defaultMode default bypassPermissions"]);
});

test("a risk you accepted is a setting --fix leaves as it is", async () => {
	const s = await setup("accepted", { ".claude/settings.json": J({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)"] } }) });
	const first = JSON.parse((await run(s, ["--json"])).stdout);
	const risk = first.findings.find((f) => f.id === "CC-BYPASS").review.id;
	assert.equal((await run(s, ["--approve", risk])).code, 0);
	const fixed = await run(s, ["--fix", "--yes"]);
	assert.equal(fixed.code, 0, fixed.stderr);
	assert.match(flat(fixed.stdout), /Set permissions\.defaultMode to "default" in ~\/\.claude\/settings\.json: you accepted this risk, so the setting stays as it is\./);
	assert.deepEqual(JSON.parse(await s.read(".claude/settings.json")), { permissions: { defaultMode: "bypassPermissions", allow: [] } });
});

test("--fix starts no history, and --no-history leaves the one there alone", async () => {
	const s = await setup("no-history", { ".claude/settings.json": J({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)"] } }) });
	// Before the computer's first check.
	const fixed = await run(s, ["--fix", "--yes"]);
	assert.equal(fixed.code, 0, fixed.stderr);
	assert.doesNotMatch(fixed.stdout, /history/);
	assert.deepEqual(await readdir(path.join(s.home, ".misconfig")), ["backups"]);
	// With a history, and asked to leave it alone.
	await run(s, ["--undo", "--yes"]);
	await run(s, []);
	const before = await history(s);
	assert.equal((await run(s, ["--fix", "--yes", "--no-history"])).code, 0);
	assert.deepEqual(await history(s), before);
	// The next check finds the change as it would any other.
	const next = await review(s);
	assert.equal(next.changes.length, 2);
	assert.ok(next.changes.every((r) => r.editor === null));
});
