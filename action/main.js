// The GitHub Action. It checks the checked-out repository with the copy of
// the command in this repository, at the commit the workflow names. Nothing
// is fetched from npm, and the checked project's own files can't change what
// runs. The findings are saved as SARIF for GitHub code scanning.

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { appendFileSync, readFileSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../bin/misconfig.js", import.meta.url));
// GitHub passes each input in a variable named INPUT_ and the input's name
// in capitals.
const input = (name) => (process.env[`INPUT_${name.toUpperCase()}`] ?? "").trim();

const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
const temp = process.env.RUNNER_TEMP || tmpdir();
const dir = path.resolve(workspace, input("path") || ".");
const sarif = path.resolve(workspace, input("sarif") || path.join(temp, "misconfig.sarif"));
const failOn = input("fail-on").toLowerCase();

const args = [CLI, dir, "--project-only", "--sarif", sarif];
if (failOn && failOn !== "none") args.push("--fail-on", failOn);

// A file left at that path by an earlier step can't stand in for this run's.
try {
	rmSync(sarif, { force: true });
} catch {}

// The report quotes names from the checked project, and GitHub reads ::name::
// at the start of a line, or ##[name] anywhere in one, as a workflow command.
// GitHub is told to read none until the check is done, so a name in a project
// can't add an annotation to the run or mask text in its log. This process
// outlives the check, and switches commands back on however the check ends.
const pause = randomUUID();
let paused = false;
const resume = () => {
	if (paused) say(`::${pause}::`);
	paused = false;
};
process.on("exit", resume);
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => process.exit(2));

say(`::stop-commands::${pause}`);
paused = true;
const code = await new Promise((resolve) => {
	const child = spawn(process.execPath, args, { cwd: temp, stdio: "inherit" });
	child.on("error", () => resolve(2));
	child.on("close", (status) => resolve(status ?? 2));
});
resume();

// The file is an output only when the check read everything. Uploading a
// partial file would mark the findings it didn't reach as fixed.
const complete = code === 0 || code === 1 ? finished(sarif) : null;
if (complete && process.env.GITHUB_OUTPUT) {
	const mark = `misconfig-${randomUUID()}`;
	appendFileSync(process.env.GITHUB_OUTPUT, `sarif<<${mark}\n${sarif}\n${mark}\n`);
}
if (code === 1 && complete !== null) say(`::error title=misconfig::A finding is ${failOn} or worse. The log lists each finding with its fix.`);
else if (code !== 0) say("::error title=misconfig::The check didn't finish. The log says why.");
if (complete === false) say("::warning title=misconfig::The check stopped early, so its SARIF file isn't an output. Uploading it would mark the findings it didn't reach as fixed.");
process.exitCode = code;

// A line for the runner. The check shares this pipe and can leave it set to
// refuse a write while it's full, so the write is tried until it lands: the
// line that switches commands back on can't be lost.
function say(line) {
	for (;;) {
		try {
			writeSync(1, `${line}\n`);
			return;
		} catch (err) {
			if (err?.code !== "EAGAIN") throw err;
		}
	}
}

// Whether the check behind a SARIF file read everything, or null when there's
// no file to tell from.
function finished(file) {
	try {
		return JSON.parse(readFileSync(file, "utf8")).runs[0].invocations[0].executionSuccessful === true;
	} catch {
		return null;
	}
}
