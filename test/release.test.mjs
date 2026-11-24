import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const read = (file) => readFile(new URL(`../${file}`, import.meta.url), "utf8");

test("the package is Apache-2.0, with its notice, and names its repository", async () => {
	const pkg = JSON.parse(await read("package.json"));
	assert.equal(pkg.license, "Apache-2.0");
	assert.equal(pkg.repository?.url, "git+https://github.com/gkdataio/misconfig.git");
	assert.equal(pkg.bugs?.url, "https://github.com/gkdataio/misconfig/issues");
	assert.ok(pkg.files.includes("LICENSE") && pkg.files.includes("NOTICE"));
	assert.match(await read("LICENSE"), /^\s*Apache License\n\s*Version 2\.0, January 2004\n/);
	assert.match(await read("NOTICE"), /Copyright 2026 GK Data LLC/);
	// npm shows the README without the repository's files, so its links and images are absolute.
	const readme = await read("README.md");
	assert.deepEqual([...readme.matchAll(/(?:src|href)="(?!https:\/\/|mailto:)([^"]+)"|\]\((?!https:\/\/|mailto:)([^)]+)\)/g)].map((m) => m[1] ?? m[2]), []);
});

test("the report's marks are only the drawing", async () => {
	for (const name of ["mark.svg", "mark-black.svg"]) {
		const svg = await read(`report/${name}`);
		assert.ok(svg.startsWith("<svg") && !svg.includes("<metadata"), name);
	}
});

test("the README, changelog and example workflow match the shipping CLI", async () => {
	const { version } = JSON.parse(await read("package.json"));
	const readme = await read("README.md");
	const workflow = await read("examples/github-actions/misconfig.yml");
	assert.ok(readme.includes("## New in " + version.split(".").slice(0, 2).join(".")));
	assert.ok((await read("CHANGELOG.md")).startsWith("# Changelog\n\n## " + version + "\n"));
	for (const text of [readme, workflow]) {
		const pins = [...text.matchAll(/@misconfig\/cli@(\d+\.\d+\.\d+)/g)].map((match) => match[1]);
		assert.ok(pins.length && pins.every((pin) => pin === version));
	}
	assert.ok(readme.includes("npx @misconfig/cli@latest --demo"));
	assert.ok(workflow.includes("--project-only --fail-on high"));
});

test("the code scanning workflow names this release and pins every other action to a commit", async () => {
	const { version } = JSON.parse(await read("package.json"));
	const readme = await read("README.md");
	const workflow = await read("examples/github-actions/code-scanning.yml");
	for (const text of [readme, workflow]) {
		const tags = [...text.matchAll(/gkdataio\/misconfig@v(\d+\.\d+\.\d+)/g)].map((match) => match[1]);
		assert.ok(tags.length && tags.every((tag) => tag === version));
	}
	for (const file of ["misconfig.yml", "code-scanning.yml"]) {
		const uses = [...(await read(`examples/github-actions/${file}`)).matchAll(/uses: (\S+)@(\S+)/g)];
		assert.ok(uses.length, file);
		for (const [, action, ref] of uses) if (action !== "gkdataio/misconfig") assert.match(ref, /^[0-9a-f]{40}$/, `${file}: ${action}`);
	}
	// The README shows the workflow's own upload step.
	const upload = /github\/codeql-action\/upload-sarif@[0-9a-f]{40} # v[\d.]+/;
	assert.ok(workflow.match(upload));
	assert.equal(readme.match(upload)?.[0], workflow.match(upload)[0]);
	assert.ok(workflow.includes("security-events: write") && workflow.includes("steps.misconfig.outputs.sarif != ''"));
});

test("this repository's workflows pin every action to a commit and run its own action", async () => {
	for (const file of ["tests.yml", "misconfig.yml"]) {
		const workflow = await read(`.github/workflows/${file}`);
		const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((match) => match[1]);
		assert.ok(uses.length, file);
		for (const action of uses) if (action !== "./") assert.match(action, /@[0-9a-f]{40}$/, `${file}: ${action}`);
		assert.ok(workflow.includes("persist-credentials: false"), file);
	}
	// The tests run on every system and Node.js version the README names.
	const tests = await read(".github/workflows/tests.yml");
	for (const name of ["ubuntu-latest", "macos-latest", "windows-latest", "'18'"]) assert.ok(tests.includes(name), name);
	assert.ok((await read(".github/workflows/misconfig.yml")).includes("uses: ./"));
});
