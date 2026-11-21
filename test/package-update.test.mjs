import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { automaticUpdateCheck, compareVersions, packageUpdate, updateMessage } from "../lib/package-update.js";
import { beforePatch } from "../lib/edit-records.js";

test("npm notices compare stable releases and prereleases numerically", () => {
	for (const [a, b, expected] of [
		["1.10.0", "1.9.10", 1], ["1.4.0-rc.10", "1.4.0-rc.2", 1], ["1.4.0-rc.1", "1.4.0", -1],
		["1.4.0+build.4", "1.4.0", 0], ["01.4.0", "1.3.2", null], ["1.4.0-01", "1.4.0", null],
	]) assert.equal(compareVersions(a, b), expected);
	assert.ok(automaticUpdateCheck({}, {}, true));
	for (const k of ["demo", "offline", "json", "projectOnly", "noHistory", "noUpdate", "failOn"]) assert.equal(automaticUpdateCheck({ [k]: true }, {}, true), false);
	assert.equal(automaticUpdateCheck({}, { CI: "true" }, true), false);
	assert.equal(automaticUpdateCheck({}, { NO_UPDATE_NOTIFIER: "1" }, true), false);
	assert.equal(automaticUpdateCheck({}, {}, false), false);
});

test("a newer npm tag gives a notice, the next run reuses it and an upgrade is announced once", async (t) => {
	const dir = await mkdtemp(path.join(tmpdir(), "misconfig-update-"));
	t.after(() => rm(dir, { recursive: true, force: true }));
	const cache = path.join(dir, "state", "npm-update.json");
	let requests = 0, version = "1.5.0";
	const fetchImpl = async (url, init) => {
		requests++;
		assert.equal(decodeURIComponent(url), "https://registry.npmjs.org/@misconfig/cli/latest");
		assert.equal(init.redirect, "error");
		assert.deepEqual(init.headers, { accept: "application/json" });
		return new Response(JSON.stringify({ name: "@misconfig/cli", version }));
	};
	const check = (installed, args = {}) => packageUpdate(installed, { fetchImpl, cache, now: 1000, ...args });
	assert.equal((await check("1.4.0", { offline: true })).status, "offline");
	await assert.rejects(stat(cache), { code: "ENOENT" });
	const newer = await check("1.4.0");
	assert.match(updateMessage(newer), /1\.5\.0 is available on npm.*@misconfig\/cli@latest/);
	assert.equal((await check("1.4.0")).status, "available");
	assert.equal(requests, 1);
	assert.match(updateMessage(await check("1.5.0")), /updated from 1\.4\.0/);
	assert.equal(updateMessage(await check("1.5.0")), "");
	assert.equal((await check("1.6.0")).status, "ahead");
	assert.equal(requests, 1);
	version = "1.6.0";
	const published = await check("1.6.0", { now: 1000 + 86400000 });
	assert.equal(published.status, "current");
	assert.match(updateMessage(published), /latest npm release/);
	assert.equal(updateMessage(await check("1.6.0", { now: 1001 + 86400000 })), "");
	assert.equal(requests, 2);
	const prior = await readFile(cache, "utf8");
	for (const bad of ["bogus", "2.0.0-rc.1", "2.0.0\n"]){
		version = bad;
		assert.equal((await check("1.6.0", { force: true })).status, "unavailable");
	}
	assert.equal(await readFile(cache, "utf8"), prior);
	const failed = await check("1.6.0", { force: true, fetchImpl: async () => { throw new Error("network down"); } });
	assert.equal(failed.status, "unavailable");
	assert.equal(updateMessage(failed), "");
});

test("numbered Codex diffs reverse multiple exact hunks and reject misplaced or incomplete records", () => {
	const diff = "@@ -1 +1 @@\n-A\n+B\n@@ -4,2 +4,2 @@\n d\n-old\n+new\n\\ No newline at end of file\n";
	assert.equal(beforePatch("B\nx\ny\nd\nnew", diff), "A\nx\ny\nd\nold\n");
	assert.equal(beforePatch("B\nx\ny\nd\nnew\n", diff), undefined);
	assert.equal(beforePatch("B\nx\ny\nd\nnew", diff.replace("-4,2", "-5,2")), undefined);
	assert.equal(beforePatch("other\n", "@@ -1 +1 @@\n-a\n+b\n"), undefined);
	assert.equal(beforePatch("a\nb\n", "@@ -1,0 +2 @@\n+b\n"), "a\n");
});
