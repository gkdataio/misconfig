// The GitHub Action, run the way a runner starts it: inputs in INPUT_
// variables, a workspace, a temp folder and a file for outputs.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseYAML } from "../engine/parse.js";

const ACTION = fileURLToPath(new URL("../action/main.js", import.meta.url));
const read = (file) => readFile(new URL(`../${file}`, import.meta.url), "utf8");
const J = (value) => JSON.stringify(value, null, 2);
const exists = (file) => readFile(file).then(() => true, () => false);
let base;
let workspace;

before(async () => {
	base = await mkdtemp(path.join(tmpdir(), "misconfig-action-"));
	workspace = await folder("repo", {
		"CLAUDE.md": "# Shop\nRun npm test before you commit.\n",
		".claude/settings.json": J({ permissions: { allow: ["Bash(*)"] } }),
		".mcp.json": J({ mcpServers: { fetch: { command: "npx", args: ["-y", "@kazuph/mcp-fetch"] } } }),
	});
});

after(async () => {
	await rm(base, { recursive: true, force: true });
});

async function folder(name, files) {
	const dir = path.join(base, name);
	await mkdir(dir, { recursive: true });
	for (const [rel, content] of Object.entries(files)) {
		const abs = path.join(dir, ...rel.split("/"));
		await mkdir(path.dirname(abs), { recursive: true });
		await writeFile(abs, content);
	}
	return dir;
}

// One run of the action. The home folder is made up, so nothing on this
// computer is read, and the check stays offline.
async function act(inputs = {}, { dir = workspace } = {}) {
	const temp = await mkdtemp(path.join(base, "temp-"));
	const output = path.join(temp, "output.txt");
	await writeFile(output, "");
	const home = path.join(base, "home");
	const env = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, "AppData", "Roaming"), NO_COLOR: "1", COLUMNS: "100", MISCONFIG_OFFLINE: "1", GITHUB_WORKSPACE: dir, RUNNER_TEMP: temp, GITHUB_OUTPUT: output };
	for (const key of Object.keys(env)) if (key.startsWith("INPUT_") || ["FORCE_COLOR", "MISCONFIG_URL", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"].includes(key)) delete env[key];
	for (const [name, value] of Object.entries(inputs)) env[`INPUT_${name.toUpperCase()}`] = value;
	const { code, stdout, stderr } = await new Promise((resolve) => {
		const child = spawn(process.execPath, [ACTION], { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (d) => (stdout += d));
		child.stderr.on("data", (d) => (stderr += d));
		child.on("close", (code) => resolve({ code, stdout, stderr }));
	});
	// Outputs are written as name<<mark, the value, then the mark again.
	const outputs = {};
	const lines = (await readFile(output, "utf8")).split("\n");
	for (let i = 0; i + 2 < lines.length; i += 3) {
		const [name, mark] = lines[i].split("<<");
		assert.equal(lines[i + 2], mark, "an output is closed by its own mark");
		outputs[name] = lines[i + 1];
	}
	return { code, stdout, stderr, outputs, temp, log: stdout.split("\n") };
}

// A line a runner would take for a workflow command: ::name:: once leading
// spaces are dropped, or ##[name] anywhere in it.
const isCommand = (line) => line.trimStart().startsWith("::") || line.includes("##[");

// The commands GitHub would run: the ones outside the stop and its matching
// resume. Between the two it reads none.
function commands(log) {
	const stop = log.findIndex((l) => l.startsWith("::stop-commands::"));
	assert.ok(stop >= 0, "commands were never stopped");
	const token = log[stop].slice("::stop-commands::".length);
	assert.match(token, /^[0-9a-f-]{36}$/);
	const resume = log.indexOf(`::${token}::`);
	assert.ok(resume > stop, "commands were never resumed");
	return [...log.slice(0, stop), ...log.slice(resume + 1)].filter(isCommand);
}

test("the action's metadata matches what its script reads", async () => {
	const action = parseYAML(await read("action.yml"));
	assert.deepEqual(action.runs, { using: "node24", main: "action/main.js" });
	assert.ok(await exists(ACTION));
	const script = await read("action/main.js");
	const used = [...script.matchAll(/input\("([a-z-]+)"\)/g)].map((m) => m[1]);
	assert.deepEqual([...new Set(used)].sort(), Object.keys(action.inputs).sort());
	assert.deepEqual(Object.keys(action.outputs), ["sarif"]);
	assert.equal(action.inputs["fail-on"].default, "high");
	// The script runs the command in this repository and installs nothing.
	assert.ok(script.includes('new URL("../bin/misconfig.js", import.meta.url)'));
	assert.ok(!/\bnpx\b|\bnpm\b/.test(script.replace(/^\s*\/\/.*$/gm, "")));
});

test("the action checks the repository, saves SARIF and names the file", async () => {
	const { code, log, outputs, temp, stdout } = await act({ "fail-on": "none" });
	assert.equal(code, 0, stdout);
	// A long path to the temp folder moves where the line wraps.
	assert.match(stdout, /Checked .+\.\s+Everything\s+ran\s+here;\s+nothing\s+was\s+uploaded\./);
	assert.equal(outputs.sarif, path.join(temp, "misconfig.sarif"));
	const [sarif] = JSON.parse(await readFile(outputs.sarif, "utf8")).runs;
	assert.deepEqual(sarif.results.map((r) => r.ruleId).sort(), ["CC-ALLOW-ALL-BASH", "MCP-UNPINNED"]);
	// Only the repository is checked, never the runner's own settings.
	for (const r of sarif.results) assert.equal(r.locations[0].physicalLocation.artifactLocation.uriBaseId, "%SRCROOT%");
	assert.deepEqual(commands(log), []);
});

test("the action fails at the fail-on level and still names the file", async () => {
	const high = await act({ "fail-on": "HIGH" });
	assert.equal(high.code, 1);
	assert.ok(await exists(high.outputs.sarif));
	assert.deepEqual(commands(high.log), ["::error title=misconfig::A finding is high or worse. The log lists each finding with its fix."]);
	// The default is the action.yml's, which GitHub passes; with no input at
	// all, as here, findings are reported and the step passes.
	assert.equal((await act()).code, 0);
	assert.equal((await act({ "fail-on": "critical" })).code, 0);
	const wrong = await act({ "fail-on": "sometimes" });
	assert.equal(wrong.code, 2);
	assert.match(wrong.stderr, /--fail-on needs one of: critical, high, medium, low\./);
	assert.deepEqual(wrong.outputs, {});
});

test("the action resolves its path and sarif inputs in the workspace", async () => {
	const dir = await folder("nested", { "checkout/.claude/settings.json": J({ permissions: { allow: ["Bash(*)"] } }), "reports/.keep": "" });
	const { code, outputs } = await act({ path: "checkout", sarif: "reports/agents.sarif", "fail-on": "none" }, { dir });
	assert.equal(code, 0);
	assert.equal(outputs.sarif, path.join(dir, "reports", "agents.sarif"));
	const [sarif] = JSON.parse(await readFile(outputs.sarif, "utf8")).runs;
	// Paths are from the folder the repository is checked out in.
	assert.equal(sarif.results[0].locations[0].physicalLocation.artifactLocation.uri, ".claude/settings.json");
});

test("a check that doesn't finish names no file, not even one left from before", async () => {
	const dir = await folder("stale", { "CLAUDE.md": "# Notes\n", "old.sarif": J({ version: "2.1.0", runs: [{ invocations: [{ executionSuccessful: true }], results: [] }] }) });
	const { code, outputs, log, stderr } = await act({ path: "no-such-folder", sarif: "old.sarif" }, { dir });
	assert.equal(code, 2);
	assert.match(stderr, /There's no folder at/);
	assert.deepEqual(outputs, {});
	assert.ok(!(await exists(path.join(dir, "old.sarif"))), "the earlier file is still there");
	assert.deepEqual(commands(log), ["::error title=misconfig::The check didn't finish. The log says why."]);
});

test("a check that stopped early names no file, since uploading it would close findings it missed", async () => {
	// More agent files than one check reads.
	const files = Object.fromEntries(Array.from({ length: 320 }, (_, i) => [`.claude/commands/c${i}.md`, "Run the tests.\n"]));
	const dir = await folder("crowded", { ...files, ".mcp.json": J({ mcpServers: { fetch: { command: "npx", args: ["-y", "@kazuph/mcp-fetch"] } } }) });
	const quiet = await act({ "fail-on": "none" }, { dir });
	assert.equal(quiet.code, 0, quiet.stdout);
	assert.match(quiet.stdout, /The check stopped early, and the file says so\./);
	assert.equal(JSON.parse(await readFile(path.join(quiet.temp, "misconfig.sarif"), "utf8")).runs[0].invocations[0].executionSuccessful, false);
	assert.deepEqual(quiet.outputs, {});
	assert.deepEqual(commands(quiet.log), ["::warning title=misconfig::The check stopped early, so its SARIF file isn't an output. Uploading it would mark the findings it didn't reach as fixed."]);
	// With a level to fail on, a check that couldn't see everything fails.
	const gated = await act({ "fail-on": "high" }, { dir });
	assert.equal(gated.code, 2);
	assert.deepEqual(gated.outputs, {});
	assert.equal(commands(gated.log)[0], "::error title=misconfig::The check didn't finish. The log says why.");
});

test("the action tells GitHub to read no commands while the report prints", async () => {
	// The command neutralizes these itself. The action is a second guard, for
	// anything a later release prints from a checked file.
	const dir = await folder("commands", { ".mcp.json": J({ mcpServers: { "##[error]Leaked": { command: "npx", args: ["-y", "docs-mcp"] } } }) });
	const { code, log, stdout } = await act({ "fail-on": "medium" }, { dir });
	assert.equal(code, 1, stdout);
	const stop = log.findIndex((l) => l.startsWith("::stop-commands::"));
	const resume = log.indexOf(`::${log[stop].slice("::stop-commands::".length)}::`);
	const report = log.findIndex((l) => l.includes("Leaked"));
	assert.ok(stop === 0 && report > stop && resume > report, stdout);
	assert.ok(log.slice(stop + 1, resume).some((l) => l.startsWith("Findings saved as SARIF")), "everything the check prints is between them");
	// Only the action's own verdict is a command.
	assert.deepEqual(commands(log), ["::error title=misconfig::A finding is medium or worse. The log lists each finding with its fix."]);
});
