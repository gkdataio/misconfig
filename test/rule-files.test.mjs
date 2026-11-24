// --rules: reading a company's own rules from the files named on the command
// line.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadRules } from "../lib/rule-files.js";

const EXAMPLE = fileURLToPath(new URL("../examples/rules/company.json", import.meta.url));
const rule = (id, changes = {}) => ({
	id,
	name: "A setting the company doesn't allow",
	severity: "low",
	category: "permissions",
	why: "{file} sets it.",
	fix: "Remove it from {file}.",
	files: ["**/settings.json"],
	match: [{ path: "forbidden", exists: true }],
	...changes,
});

let dir;
before(async () => {
	dir = await mkdtemp(path.join(tmpdir(), "misconfig-rules-"));
});
after(async () => {
	await rm(dir, { recursive: true, force: true });
});
const save = async (name, content) => {
	const file = path.join(dir, name);
	await writeFile(file, typeof content === "string" ? content : JSON.stringify(content));
	return file;
};

test("a rules file holds one rule, a list of rules, or a list under rules", async () => {
	const one = await save("one.json", rule("ACME-ONE"));
	const list = await save("list.json", [rule("ACME-TWO"), rule("ACME-THREE")]);
	// Saved by an editor that starts the file with a byte-order mark.
	const named = await save("named.json", `\ufeff${JSON.stringify({ rules: [rule("ACME-FOUR")] }, null, "\t")}\r\n`);
	const rules = await loadRules([one, list, named]);
	assert.deepEqual(rules.map((r) => r.id), ["ACME-ONE", "ACME-TWO", "ACME-THREE", "ACME-FOUR"]);
	assert.ok(rules.every((r) => r.rule.name === "A setting the company doesn't allow" && r.files.length === 1));
});

test("the example rules file is one the command reads", async () => {
	const rules = await loadRules([EXAMPLE]);
	assert.deepEqual(rules.map((r) => [r.id, r.scope]), [["ACME-GATEWAY", null], ["ACME-DEPLOY-APPROVED", "project"]]);
});

test("a rules file that can't be used stops the command and says why", async () => {
	const folder = path.join(dir, "folder");
	await mkdir(folder);
	const cases = [
		[[path.join(dir, "missing.json")], /^The rules file .*missing\.json couldn't be read: there's no file there\.$/],
		[[folder], /couldn't be read: it's a folder\.$/],
		[[await save("big.json", `[${" ".repeat(300 * 1024)}]`)], /couldn't be read: it's larger than 256 KB\.$/],
		[[await save("broken.json", '{ "id": "ACME-X", ')], /^The rules file .*broken\.json isn't valid JSON\.$/],
		[[await save("yaml.yaml", "rules:\n  - id: ACME-X\n")], /isn't valid JSON\.$/],
		[[await save("empty.json", "[]")], /needs one rule, a list of rules, or a list of them under "rules" and nothing beside it\.$/],
		[[await save("text.json", '"ACME-X"')], /needs one rule, a list of rules/],
		[[await save("beside.json", { rules: [rule("ACME-X")], version: 1 })], /needs one rule, a list of rules, or a list of them under "rules" and nothing beside it\.$/],
		[[await save("not-a-list.json", { rules: rule("ACME-X") })], /needs one rule, a list of rules/],
		// The file, which rule in it, the rule's ID once it has one, and what to change.
		[[await save("second.json", [rule("ACME-GOOD"), rule("ACME-BAD", { severity: "urgent" })])], /second\.json, rule 2: ACME-BAD: severity is one of critical, high, medium, low, info\.$/],
		[[await save("no-id.json", [{ name: "x" }])], /no-id\.json, rule 1: id needs capitals, digits and hyphens/],
		[[await save("built-in.json", rule("CC-BYPASS"))], /built-in\.json, rule 1: CC-BYPASS: That ID belongs to a built-in rule\./],
		[[await save("twice.json", [rule("ACME-SAME"), rule("ACME-SAME")])], /twice\.json, rule 2: ACME-SAME is already a rule in .*twice\.json\. Each rule needs its own ID\.$/],
		[[await save("a.json", rule("ACME-SHARED")), await save("b.json", rule("ACME-SHARED"))], /b\.json, rule 1: ACME-SHARED is already a rule in .*a\.json\./],
		[[await save("many.json", Array.from({ length: 201 }, (_, i) => rule(`ACME-${i}`)))], /^--rules takes up to 200 rules\.$/],
	];
	for (const [files, message] of cases) await assert.rejects(loadRules(files), { message }, files.join(" "));
});
