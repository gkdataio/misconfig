import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { CATEGORIES, LEVELS } from "../engine/catalog.js";
import { RULE_KEYS, RULE_TESTS, readTemplate } from "../engine/templates.js";

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
	for (const file of ["tests.yml", "misconfig.yml", "release.yml"]) {
		const workflow = await read(`.github/workflows/${file}`);
		const uses = [...workflow.matchAll(/uses: (\S+)/g)].map((match) => match[1]);
		assert.ok(uses.length, file);
		// What isn't in this repository is named by its commit.
		for (const action of uses) if (!action.startsWith("./")) assert.match(action, /@[0-9a-f]{40}$/, `${file}: ${action}`);
		// No checkout leaves its token behind for the steps after it.
		const count = (text) => workflow.split(text).length - 1;
		assert.ok(count("actions/checkout@") > 0 && count("actions/checkout@") === count("persist-credentials: false"), file);
	}
	// The tests run on every system and Node.js version the README names.
	const tests = await read(".github/workflows/tests.yml");
	for (const name of ["ubuntu-latest", "macos-latest", "windows-latest", "'18'"]) assert.ok(tests.includes(name), name);
	assert.ok((await read(".github/workflows/misconfig.yml")).includes("uses: ./"));
});

test("the release workflow stages a release for approval and can't publish one", async () => {
	const workflow = await read(".github/workflows/release.yml");
	const job = (name) => new RegExp(`\\n  ${name}:\\n([\\s\\S]*?)(?=\\n  \\w+:\\n|$)`).exec(workflow)[1];
	const count = (text) => workflow.split(text).length - 1;
	// Only a version tag releases, and a release branch only rehearses.
	assert.ok(workflow.includes("tags: ['v[0-9]+.[0-9]+.[0-9]+']") && workflow.includes("branches: ['release-*']"));
	for (const name of ["tests", "stage", "draft"]) assert.ok(job(name).includes("if: github.ref_type == 'tag'"), name);
	// Only one job can show npm which workflow it is. It stages with provenance
	// and never publishes, waits for the tests and for the archive to run on
	// every system, and runs nothing from the repository.
	assert.match(workflow, /\npermissions:\n  contents: read\n/);
	assert.equal(count("id-token: write"), 1);
	const stage = job("stage");
	assert.ok(stage.includes("id-token: write") && stage.includes("environment: npm") && stage.includes("needs: [pack, try, tests]"));
	// It's off until the repository says otherwise, and the setup steps name the same switch.
	assert.ok(stage.includes("if: github.ref_type == 'tag' && vars.STAGE_ON_NPM == 'true'\n"));
	assert.ok(stage.includes('npm stage publish "./archive/$FILE" --provenance --access public'));
	assert.ok(!stage.includes("actions/checkout") && !workflow.includes("npm publish"));
	// The archive that's staged is the one that was packed and tried.
	assert.equal(count('echo "$SHA256  archive/$FILE" | sha256sum --check --strict'), 2);
	const tried = job("try");
	for (const name of ["needs: pack", "ubuntu-latest", "macos-latest", "windows-latest", "'18'", "'24'", "node .github/scripts/try-archive.mjs"]) assert.ok(tried.includes(name), name);
	const script = fileURLToPath(new URL("../.github/scripts/try-archive.mjs", import.meta.url));
	assert.equal(spawnSync(process.execPath, ["--check", script]).status, 0);
	// Only the job that drafts the GitHub release can write to the repository.
	assert.equal(count("contents: write"), 1);
	assert.ok(job("draft").includes("contents: write") && job("draft").includes("gh release create") && job("draft").includes("--draft"));
	// The setup steps name the workflow and its environment as the workflow has
	// them, and let npm take a staged release from it and nothing more.
	const doc = await read("docs/releasing.md");
	assert.ok(doc.includes("npm trust github @misconfig/cli --file release.yml --repo gkdataio/misconfig --env npm --allow-stage-publish"));
	assert.ok(!doc.includes("--allow-publish") && doc.includes("`STAGE_ON_NPM` with the value `true`"));
});

test("the rules format is documented as the command reads it", async () => {
	const doc = await read("docs/rules.md");
	const readme = await read("README.md");
	// Every key and test has its row, and every level and category is named.
	for (const key of [...RULE_KEYS, ...RULE_TESTS]) assert.ok(doc.includes(`\n| \`${key}\` |`), `${key} has no row`);
	for (const word of [...Object.keys(LEVELS), ...Object.keys(CATEGORIES)]) assert.ok(doc.includes(`\`${word}\``), word);
	// The rules shown load, and say what the example file's rule of the same name says.
	const shown = (text) => JSON.parse(/```json\n(\{\n  "rules": [\s\S]*?)```/.exec(text)[1]).rules;
	const example = JSON.parse(await read("examples/rules/company.json")).rules;
	for (const rules of [shown(doc), shown(readme), example]) for (const rule of rules) assert.equal(readTemplate(rule).id, rule.id);
	for (const rule of [...shown(doc), ...shown(readme)]) {
		const same = example.find((r) => r.id === rule.id);
		for (const key of ["name", "severity", "why", "fix", "files", "match"]) assert.deepEqual(rule[key], same[key], `${rule.id}: ${key}`);
	}
	assert.ok(readme.includes("https://github.com/gkdataio/misconfig/blob/main/docs/rules.md") && readme.includes("https://github.com/gkdataio/misconfig/blob/main/examples/rules/company.json"));
});
