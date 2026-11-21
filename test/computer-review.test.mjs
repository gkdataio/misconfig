import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const bin = fileURLToPath(new URL("../bin/misconfig.js", import.meta.url));
const server = (version) => ({ command: "npx", args: ["-y", "@example/calendar" + (version ? "@" + version : "")] });

async function setup(t) {
	const home = await mkdtemp(path.join(tmpdir(), "misconfig-computer-test-"));
	t.after(() => rm(home, { recursive: true, force: true }));
	const repo = path.join(home, "project");
	await mkdir(repo);
	const env = {
		HOME: home, USERPROFILE: home, APPDATA: path.join(home, "AppData", "Roaming"),
		LOCALAPPDATA: path.join(home, "AppData", "Local"), TMP: home, TEMP: home, TMPDIR: home, NO_COLOR: "1",
		...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
	};
	async function run(...args) {
		try {
			const { stdout, stderr } = await exec(process.execPath, [bin, "--offline", ...args], { cwd: repo, env });
			return { code: 0, stdout, stderr };
		} catch (err) { return { code: err.code, stdout: err.stdout, stderr: err.stderr }; }
	}
	async function scan(...args) {
		const r = await run("--json", ...args);
		assert.equal(r.code, 0, r.stderr);
		return JSON.parse(r.stdout);
	}
	async function put(file, value) {
		const abs = path.join(home, file);
		await mkdir(path.dirname(abs), { recursive: true });
		await writeFile(abs, typeof value === "string" ? value : JSON.stringify(value, null, 2));
	}
	return { home, run, scan, put, dir: path.join(home, ".misconfig", "computer-v1") };
}

test("last scan and last approval stay distinct across add, bump, revert and removal", async (t) => {
	const { home, scan, put, run } = await setup(t);
	const set = (v) => put(".claude.json", { mcpServers: { calendar: server(v) } });
	await set("1.2.3");
	const first = (await scan()).computerReview;
	assert.equal(first.previousScanAt, null);
	assert.deepEqual(first.changes, []);
	const initial = first.pending.find((r) => r.label === "MCP calendar");
	await scan("--approve", initial.id);
	await set("1.2.4");
	const next = (await scan()).computerReview;
	assert.deepEqual(next.changes.map((r) => [r.kind,r.before,r.after]), [["changed","@example/calendar@1.2.3","@example/calendar@1.2.4"]]);
	const pending = (await scan()).computerReview;
	assert.deepEqual(pending.changes, []);
	assert.equal(pending.pending[0].id, next.pending[0].id);
	await set("1.3.0");
	assert.equal((await run("--approve", next.pending[0].id)).code, 2);
	await set("1.2.3");
	assert.equal((await scan()).computerReview.pending.length, 0);
	await rm(path.join(home, ".claude.json"));
	const gone = (await scan()).computerReview;
	assert.equal(gone.changes[0].kind, "removed");
	assert.equal(gone.pending[0].before, "@example/calendar@1.2.3");
	assert.equal((await scan("--approve", gone.pending[0].id)).computerReview.pending.length, 0);
	await set("1.2.3");
	assert.equal((await scan()).computerReview.pending[0].kind, "added");
});

test("risk acceptance stays visible in text, HTML, JSON and scoring; unrelated server edits keep it", async (t) => {
	const { home, put, scan, run } = await setup(t);
	const config = { mcpServers: { calendar: server(""), mail: server("1.0.0") } };
	await put(".claude.json", config);
	const first = await scan();
	const finding = first.findings.find((f) => f.id === "MCP-UNPINNED");
	const change = first.computerReview.pending.find((r) => r.label === "MCP calendar");
	await scan("--approve", change.id);
	assert.equal((await scan()).findings.find((f) => f.id === finding.id).review.acceptedAt, null);
	const accepted = await scan("--approve", finding.review.id);
	assert.ok(accepted.findings.find((f) => f.id === finding.id).review.acceptedAt);
	assert.equal(accepted.score, first.score);
	assert.deepEqual(accepted.counts, first.counts);
	config.mcpServers.mail = server("2.0.0");
	await put(".claude.json", config);
	const text = await run("--fail-on", "medium", "--open");
	assert.equal(text.code, 1);
	assert.match(text.stdout, /Risk accepted on/);
	const [reportDir] = (await readdir(home)).filter((f) => f.startsWith("misconfig-report-"));
	const html = await readFile(path.join(home, reportDir, "report.html"), "utf8");
	assert.match(html, /Risk accepted/);
	assert.match(html, /Computer review/);
	assert.match(html, /MCP-UNPINNED/);
	assert.doesNotMatch(html, /<script\b/i);
	config.mcpServers.calendar.args.push("--verbose");
	await put(".claude.json", config);
	const changed = await scan();
	assert.equal(changed.findings.find((f) => f.id === finding.id).review.acceptedAt, null);
	assert.ok(changed.computerReview.earlierRisks.some((r) => r.id === finding.review.id && r.rule === "MCP-UNPINNED"));
	assert.equal((await run("--approve", finding.review.id)).code, 2);
	await put(".claude.json", "{");
	const incomplete = (await scan()).computerReview;
	assert.equal(incomplete.earlierRisks.find((r) => r.id === finding.review.id).status, "unverified");
});

test("one hook is one decision; object formatting is quiet and equal-length credentials still change", async (t) => {
	const { dir, put, scan } = await setup(t);
	const firstKey = "ghp_" + "a".repeat(36), nextKey = "ghp_" + "b".repeat(36);
	const hooks = { Stop: [{ matcher: "*", hooks: [{ type: "command", command: "node hooks/lint.js" }, { type: "command", command: "node hooks/report.js" }] }] };
	await put(".claude/settings.json", { hooks, env: { SERVICE_TOKEN: firstKey } });
	const a = (await scan()).computerReview;
	assert.equal(a.pending.filter((p) => p.label.startsWith("Hook ")).length, 2);
	const hook = a.pending.find((p) => p.after === "node lint.js");
	const b = (await scan("--approve=" + hook.id)).computerReview;
	assert.ok(b.pending.some((p) => p.after === "node report.js"));
	await put(".claude/settings.json", JSON.stringify({ env: { SERVICE_TOKEN: firstKey }, hooks }));
	assert.deepEqual((await scan()).computerReview.changes, []);
	await put(".claude/settings.json", { env: { SERVICE_TOKEN: nextKey }, hooks });
	const changes = (await scan()).computerReview.changes;
	assert.equal(changes.length, 1);
	assert.match(changes[0].label, /SERVICE_TOKEN/);
	for (const f of await readdir(dir)) {
		const text = await readFile(path.join(dir, f), "utf8");
		for (const value of [firstKey,nextKey,"node hooks/lint.js"]) assert.ok(!text.includes(value));
		if (process.platform !== "win32") assert.equal((await stat(path.join(dir,f))).mode & 0o777, 0o600);
	}
});

test("partly read and invalid files keep prior decisions until a complete observation", async (t) => {
	const { put, scan, run } = await setup(t);
	await put(".claude/CLAUDE.md", "Keep headings short.\n");
	await put(".claude.json", { mcpServers: { calendar: server("1.0.0") } });
	const start = await scan();
	for (const row of start.computerReview.pending) await scan("--approve", row.id);
	await put(".claude/CLAUDE.md", "Keep headings short.\n".repeat(25000));
	await put(".claude.json", "{");
	const partial = (await scan()).computerReview;
	assert.ok(partial.unverified.includes("~/.claude/CLAUDE.md"));
	assert.ok(partial.unverified.includes("~/.claude.json"));
	assert.deepEqual(partial.pending, []);
	assert.deepEqual(partial.changes, []);
	assert.equal((await run("--approve", start.computerReview.pending[0].id)).code, 2);
	await put(".claude/CLAUDE.md", "Keep headings short.\n");
	await put(".claude.json", { mcpServers: { calendar: server("1.0.0") } });
	const recovered = (await scan()).computerReview;
	assert.deepEqual(recovered.unverified, []);
	assert.deepEqual(recovered.pending, []);
});

test("project scans and one-off scans leave personal history untouched; concurrent decisions both survive", async (t) => {
	const { dir, put, scan, run } = await setup(t);
	await put("project/.mcp.json", { mcpServers: { projectSecret: server("1.0.0") } });
	await put(".claude.json", { mcpServers: { calendar: server("1.0.0"), mail: server("2.0.0") } });
	assert.equal((await scan("--project-only")).computerReview, undefined);
	assert.equal((await scan("--no-history")).computerReview, undefined);
	await assert.rejects(stat(dir), { code: "ENOENT" });
	const start = (await scan()).computerReview;
	assert.ok(start.pending.every((row) => !row.label.includes("projectSecret")));
	const ids = start.pending.filter((row) => row.file === "~/.claude.json").map((r) => r.id);
	await Promise.all(ids.map((id) => scan("--approve", id)));
	const later = await scan();
	assert.equal(later.computerReview.pending.filter((r) => r.file === "~/.claude.json").length, 0);
	assert.deepEqual(later.computerReview.history.events.filter((e) => e.action === "approved" && ids.includes(e.reviewId)).map((e) => e.reviewId).sort(), ids.slice().sort());
	const repeat = await run("--approve", ids[0]);
	assert.equal(repeat.code, 0, repeat.stderr);
	const files = await readdir(dir);
	assert.ok(files.filter((f) => f.endsWith(".json")).length <= 2);
});

test("Codex package pins, editor extension versions and multiple permission changes have their own rows", async (t) => {
	const { put, scan } = await setup(t);
	const setupVersion = async (version, permissions) => {
		await put(".codex/config.toml", '[mcp_servers.calendar]\ncommand = "npx"\nargs = ["-y", "@example/calendar@' + version + '"]\n');
		await put(".vscode/extensions/extensions.json", [{ identifier: { id: "anthropic.claude-code" }, version }]);
		await put(".claude/settings.json", { permissions: { allow: permissions } });
	};
	await setupVersion("1.2.3", []);
	await scan();
	await setupVersion("1.2.4", ["Read", "Edit"]);
	const v = (await scan()).computerReview;
	assert.equal(v.changes.find((r) => r.label === "MCP calendar").after, "@example/calendar@1.2.4");
	assert.equal(v.changes.find((r) => r.label.includes("extension anthropic.claude-code")).before, "1.2.3");
	assert.deepEqual(v.changes.filter((r) => r.label === "Permission allow").map((r) => r.after).sort(), ["Edit","Read"]);
});

test("damaged history is reported alongside findings and never silently replaced", async (t) => {
	const { dir, put, run, scan } = await setup(t);
	await put(".claude.json", { mcpServers: { calendar: server("") } });
	const initial = await scan();
	const [filename] = await readdir(dir);
	await writeFile(path.join(dir, filename), "{unfinished");
	const read = await run("--json");
	assert.equal(read.code, 2);
	const json = JSON.parse(read.stdout);
	assert.match(json.computerReviewError, /Could not read computer review history/);
	assert.ok(json.findings.some((f) => f.id === "MCP-UNPINNED"));
	const decision = await run("--approve", initial.computerReview.pending[0].id);
	assert.equal(decision.code, 2);
	assert.equal(await readFile(path.join(dir, filename), "utf8"), "{unfinished");
});

test("the ID beside a new diff approves the current state, even with older decisions still pending", async (t) => {
	const { home, put, scan } = await setup(t);
	await put(".claude.json", { mcpServers: { calendar: server("1.0.0"), mail: server("2.0.0") } });
	await scan();
	await put(".claude.json", { mcpServers: { calendar: server("1.1.0"), mail: server("2.0.0") } });
	const bump = (await scan()).computerReview.changes[0];
	assert.equal(bump.before, "@example/calendar@1.0.0");
	await scan("--approve", bump.id);
	await rm(path.join(home, ".claude.json"));
	const removed = (await scan()).computerReview;
	const mail = removed.changes.find((r) => r.label === "MCP mail");
	assert.ok(mail.id);
	assert.ok((await scan()).computerReview.pending.some((r) => r.id === mail.id));
	await scan("--approve", mail.id);
	assert.deepEqual((await scan()).computerReview.pending.map((r) => r.label), ["MCP calendar"]);
});

test("history is read-only and records observed edits separately from the accounts making decisions", async (t) => {
	const { home, dir, put, scan, run } = await setup(t);
	const history = async () => JSON.parse((await run("--history", "--json")).stdout);
	const account = userInfo().username;
	assert.deepEqual(await history(), { incomplete: false, events: [] });
	await assert.rejects(stat(dir), { code: "ENOENT" });
	const set = (version) => put(".claude.json", { mcpServers: { calendar: server(version) } });
	await set("1.2.3");
	const initial = (await scan()).computerReview.pending.find((r) => r.label === "MCP calendar");
	await scan("--approve", initial.id);
	await set("1.2.4");
	// Reading past decisions must leave the next scan's diff intact.
	const files = await readdir(dir);
	const saved = await Promise.all(files.map((f) => readFile(path.join(dir, f), "utf8")));
	assert.ok(!(await history()).events.some((e) => e.after === "@example/calendar@1.2.4"));
	assert.deepEqual(await readdir(dir), files);
	assert.deepEqual(await Promise.all(files.map((f) => readFile(path.join(dir, f), "utf8"))), saved);
	const bump = (await scan()).computerReview.pending.find((r) => r.label === "MCP calendar");
	await Promise.all([scan("--approve", bump.id), scan("--approve", bump.id)]);
	await set("");
	const warning = (await scan()).findings.find((f) => f.id === "MCP-UNPINNED");
	await scan("--approve", warning.review.id);
	await scan("--approve", warning.review.id);
	await rm(path.join(home, ".claude.json"));
	const removed = (await scan()).computerReview.pending.find((r) => r.label === "MCP calendar");
	await scan("--approve", removed.id);
	const events = (await history()).events;
	const edits = events.filter((e) => e.action === "observed" && e.label === "MCP calendar");
	assert.deepEqual(edits.map((e) => e.kind), ["changed", "changed", "removed"]);
	assert.deepEqual(edits.map((e) => e.actor), [null, null, null]);
	assert.deepEqual([edits[0].before, edits[0].after], ["@example/calendar@1.2.3", "@example/calendar@1.2.4"]);
	const approvals = events.filter((e) => e.action === "approved" && e.label === "MCP calendar");
	assert.deepEqual(approvals.map((e) => e.reviewId), [initial.id, bump.id, removed.id]);
	assert.ok(approvals.every((e) => e.actor === account));
	const accepted = events.filter((e) => e.reviewId === warning.review.id);
	assert.equal(accepted.length, 1);
	assert.equal(accepted[0].actor, account);
	assert.equal(accepted[0].rule, warning.id);
	assert.ok(events.every((e) => Number.isFinite(e.at)));
	const printed = (await run("--history")).stdout;
	assert.match(printed, /Edit author unknown/);
	assert.ok(printed.includes(account + " approved removing MCP calendar"));
	assert.ok(printed.includes(account + " accepted medium risk MCP-UNPINNED"));
});

test("previous preview decisions survive the upgrade without invented actors or timestamps", async (t) => {
	const { dir, put, scan, run } = await setup(t);
	await put(".claude.json", { mcpServers: { calendar: server("") } });
	const first = await scan();
	const risk = first.findings.find((f) => f.id === "MCP-UNPINNED").review;
	await scan("--approve", first.computerReview.pending.find((r) => r.label === "MCP calendar").id);
	const decided = await scan("--approve", risk.id);
	const at = decided.findings.find((f) => f.id === "MCP-UNPINNED").review.acceptedAt;
	for (const f of await readdir(dir)) {
		const file = path.join(dir, f);
		const state = JSON.parse(await readFile(file, "utf8"));
		delete state.history;
		for (const r of Object.values(state.acceptedRisks)) delete r.by;
		state.schema = 1;
		await writeFile(file, JSON.stringify(state));
	}
	const oldHistory = JSON.parse((await run("--history", "--json")).stdout);
	assert.equal(oldHistory.incomplete, true);
	assert.deepEqual(oldHistory.events.map((e) => [e.action, e.at, e.actor]), [["accepted-risk", at, null]]);
	assert.match((await run("--history")).stdout, /Account unknown accepted medium risk/);
	const upgraded = await scan();
	assert.deepEqual(upgraded.computerReview.history, oldHistory);
	assert.equal(upgraded.computerReview.pending.filter((r) => r.label === "MCP calendar").length, 0);
	assert.equal(upgraded.findings.find((f) => f.id === "MCP-UNPINNED").review.acceptedBy, null);
	await put(".claude.json", { mcpServers: { calendar: server("2.0.0") } });
	const next = await scan();
	const item = next.computerReview.pending.find((r) => r.label === "MCP calendar");
	await scan("--approve", item.id);
	assert.equal(JSON.parse((await run("--history", "--json")).stdout).events.at(-1).actor, userInfo().username);
});

test("the offline demo uses a disposable profile and shows the sample risk after acceptance", async (t) => {
	const { home, dir, put, run } = await setup(t);
	await put(".claude.json", { mcpServers: { personalCanary: server("9.9.9") } });
	await put("project/CLAUDE.md", "Personal project canary");
	const original = await readFile(path.join(home, ".claude.json"), "utf8");
	const json = await run("--demo", "--json");
	assert.equal(json.code, 0, json.stderr);
	assert.doesNotMatch(json.stdout, /personalCanary|Personal project canary|9\.9\.9/);
	const sample = JSON.parse(json.stdout);
	assert.equal(sample.demo, true);
	assert.equal(sample.knownMalware.from, "offline");
	assert.deepEqual(sample.controlMap.map((f) => f.path), ["~/.claude.json"]);
	assert.deepEqual(sample.computerReview.changes.map((r) => [r.before, r.after]), [["@example/calendar@1.2.3", "@example/calendar@1.2.4"]]);
	assert.deepEqual(sample.computerReview.pending, []);
	assert.equal(sample.findings.find((f) => f.id === "MCP-UNPINNED").review.acceptedBy, "Demo reviewer");
	assert.equal(sample.computerReview.history.events.find((e) => e.action === "observed").actor, null);
	assert.ok(sample.computerReview.history.events.every((e) => [null, "Demo reviewer", "Demo setup"].includes(e.actor)));
	assert.equal(await readFile(path.join(home, ".claude.json"), "utf8"), original);
	await assert.rejects(stat(dir), { code: "ENOENT" });
	assert.ok(!(await readdir(home)).some((f) => f.startsWith("misconfig-demo-")));
	const report = await run("--demo", "--open");
	assert.equal(report.code, 0, report.stderr);
	const reportDir = (await readdir(home)).find((f) => f.startsWith("misconfig-report-"));
	const html = await readFile(path.join(home, reportDir, "report.html"), "utf8");
	assert.match(html, /Computer history \(6\)/);
	assert.match(html, /Demo reviewer approved the change to MCP calendar/);
	assert.match(html, /Edited by Codex \(local tool record\)/);
	assert.doesNotMatch(html, /<script\b/i);
	await assert.rejects(stat(dir), { code: "ENOENT" });
});

test("a successful Claude file edit can be matched after approval and a separate edit can be claimed without approval", async (t) => {
	const { home, dir, put, scan, run } = await setup(t);
	const file = path.join(home, ".claude.json");
	const values = (calendar, mail) => ({ mcpServers: { calendar: server(calendar), mail: server(mail) } });
	const old = values("1.2.3", "2.0.0");
	await put(".claude.json", old);
	const first = await scan();
	for (const item of first.computerReview.pending.filter((r) => r.file === "~/.claude.json")) await scan("--approve", item.id);
	const stamp = new Date().toISOString();
	const id = "toolu_calendar";
	const input = { file_path: file, old_string: "calendar@1.2.3", new_string: "calendar@1.2.4", replace_all: false };
	const call = { type: "assistant", sessionId: "sample", message: { role: "assistant", content: [{ type: "tool_use", name: "Edit", id, input }] } };
	const reply = { type: "user", timestamp: stamp, sessionId: "sample", message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: "Updated" }] },
		toolUseResult: { filePath: file, originalFile: JSON.stringify(old), oldString: input.old_string, newString: input.new_string, userModified: false } };
	await put(".claude.json", values("1.2.4", "2.0.1"));
	const changed = (await scan()).computerReview;
	const calendar = changed.pending.find((e) => e.label === "MCP calendar");
	const mail = changed.pending.find((e) => e.label === "MCP mail");
	await scan("--approve", calendar.id);
	const log = path.join(home, ".claude/projects/demo/session.jsonl");
	const lines = (rows) => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
	await put(".claude/projects/demo/session.jsonl", lines([call, { ...reply, toolUseResult: { ...reply.toolUseResult, userModified: true } },
		call, { ...reply, timestamp: "2000-01-01T00:00:00Z" }, call, { ...reply, toolUseResult: { ...reply.toolUseResult, filePath: path.join(home, "other/.claude.json") } },
		call, { ...reply, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, is_error: true }] } }]));
	assert.equal((await scan("--attribute")).computerReview.attribution.matchedEdits, 0);
	await put(".claude/projects/demo/session.jsonl", lines([call, reply, { type: "user", message: { role: "user", content: "private-chat-canary-472" } }]));
	const attributed = (await scan("--session", log)).computerReview;
	assert.equal(attributed.attribution.matchedEdits, 1);
	const approval = attributed.history.events.find((e) => e.reviewId === calendar.id);
	assert.equal(approval.actor, userInfo().username);
	assert.equal(approval.editor.name, "Claude Code");
	assert.equal(approval.editor.basis, "tool-record");
	assert.equal(approval.observationId, calendar.observationId);
	assert.equal(attributed.pending.find((e) => e.id === mail.id).editor, null);
	const declaration = JSON.parse((await run("--i-edited", mail.observationId, "--json")).stdout);
	assert.equal(declaration.editor.name, userInfo().username);
	assert.equal(declaration.editor.basis, "self-reported");
	assert.ok((await scan()).computerReview.pending.some((e) => e.id === mail.id));
	assert.equal(JSON.parse((await run("--i-edited", mail.observationId, "--json")).stdout).editor.at, declaration.editor.at);
	const history = (await run("--history")).stdout;
	assert.match(history, /Edited by Claude Code \(local tool record\)/);
	assert.ok(history.includes("Edited by " + userInfo().username + " (self-reported)"));
	for (const f of await readdir(dir)) assert.ok(!(await readFile(path.join(dir, f), "utf8")).includes("private-chat-canary-472"));
});

test("Codex completed file-change records require exact content and contradictory editors stay uncertain", async (t) => {
	const { home, put, scan, run } = await setup(t);
	const file = path.join(home, ".codex/config.toml");
	const before = 'model = "alpha"\n', after = 'model = "beta"\n';
	await put(".codex/config.toml", before);
	await scan();
	const timestamp = new Date().toISOString();
	await put(".codex/config.toml", after);
	const e = (await scan()).computerReview.changes.find((r) => r.label === "model");
	const record = (status, diff) => ({ type: "event_msg", timestamp, payload: { type: "item_completed", item: { type: "FileChange", status, changes: { [file]: { type: "update", unified_diff: diff, move_path: null } } } } });
	const diff = '@@ -1 +1 @@\n-model = "alpha"\n+model = "beta"\n';
	const save = (...rows) => put(".codex/sessions/2026/11/21/rollout-example.jsonl", rows.map((r) => JSON.stringify(r)).join("\n"));
	await save(record("failed", diff), record("completed", diff.replace('"alpha"', '"other"')));
	assert.equal((await scan("--attribute")).computerReview.attribution.matchedEdits, 0);
	await save(record("completed", diff));
	const matched = await scan("--attribute");
	assert.equal(matched.computerReview.pending.find((r) => r.key === e.key).editor.name, "Codex");
	await run("--i-edited", e.observationId);
	const state = (await scan("--attribute")).computerReview;
	const editor = state.pending.find((r) => r.key === e.key).editor;
	assert.equal(editor.basis, "conflicting");
	assert.deepEqual(editor.sources.map((s) => s.basis).sort(), ["self-reported", "tool-record"]);
	assert.match((await run("--history")).stdout, /Edit author uncertain/);
});

test("a partial patch cannot claim other changes and the last editor is scoped on a multi-edit approval", async (t) => {
	const { home, put, scan, run } = await setup(t);
	const name = ".codex/config.toml", abs = path.join(home, name);
	await put(name, 'model = "alpha"\n# original\n');
	const start = await scan();
	await scan("--approve", start.computerReview.pending.find((r) => r.label === "model").id);
	const timestamp = new Date().toISOString();
	await put(name, 'model = "beta"\n# separately edited\n');
	const patch = '@@ -1 +1 @@\n-model = "alpha"\n+model = "beta"\n';
	await put(".codex/sessions/test.jsonl", JSON.stringify({ type: "event_msg", timestamp, payload: {
		type: "patch_apply_end", success: true, status: "completed", changes: { [abs]: { type: "update", unified_diff: patch } }
	} }));
	const middle = await scan("--attribute");
	assert.equal(middle.computerReview.attribution.matchedEdits, 0);
	await put(name, 'model = "gamma"\n# separately edited\n');
	const latest = (await scan()).computerReview.changes.find((r) => r.label === "model");
	await run("--i-edited", latest.observationId);
	const decision = (await scan("--approve", latest.id)).computerReview.history.events.at(-1);
	assert.deepEqual([decision.before, decision.after, decision.editorScope], ["alpha", "gamma", "latest"]);
	assert.match((await run("--history")).stdout, /Latest observed edit by/);
});
