// A finished check in the two formats other programs read: JSON Lines, one
// finding on each line, and SARIF 2.1.0, which GitHub code scanning and other
// viewers load. Nothing here reads a file or the network, so the same code
// can run wherever the engine does.

import { LEVELS, RULES } from "../engine/catalog.js";

const RULES_URL = "https://misconfig.ai/rules";

// JSON that's safe to print and to split into lines. A checked file can hold
// marks that reorder text on screen, and characters some programs treat as
// line breaks. A name in one can also spell a command that a CI system reads
// from its log, such as ##[error] or ##vso[task.setvariable]. JSON.stringify
// leaves all of these as they are, so they're written as \u escapes, which
// every JSON parser reads back unchanged.
const UNSAFE = /[\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
export const stringify = (value, space) =>
	JSON.stringify(value, null, space)
		.replace(UNSAFE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
		.replace(/##(?=[a-z]*\[)/gi, "#\\u0023");

// --- JSON Lines ----------------------------------------------------------------

// One finding as a record. The keys are a contract: a 1.x release can add
// keys, and none is renamed or removed. Every key is always there, null when
// it doesn't apply. Each record names the check that made it, so lines from
// different runs and computers can share one file.
export function findingRecord(f, { version, ruleset, checkedAt }) {
	return {
		type: "finding",
		rule: f.id,
		severity: f.severity,
		category: f.category,
		agent: f.tool ?? null,
		title: f.title,
		why: f.why,
		fix: f.fix,
		file: f.file ?? null,
		line: f.line ?? null,
		evidence: f.evidence ?? null,
		// For one of your own rules, its reference, or null without one.
		ruleUrl: f.custom ? f.custom.reference : `${RULES_URL}#${f.id}`,
		checkedAt: new Date(checkedAt).toISOString(),
		ruleset,
		cli: version,
	};
}

// The findings, worst first, one JSON object on each line.
export function jsonLines(result, { version }) {
	const run = { version, ruleset: result.version, checkedAt: result.checkedAt };
	return result.findings.map((f) => `${stringify(findingRecord(f, run))}\n`).join("");
}

// --- SARIF -----------------------------------------------------------------------

// Each level as SARIF and GitHub read it. SARIF has three levels. GitHub
// also reads a security severity from 0.1 to 10 and shows it as critical
// (over 9.0), high (7.0 to 8.9), medium (4.0 to 6.9) or low, so each level
// gets a number inside its band. Info findings are notes with no number.
const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "2.5" };

// What each base in a file's address stands for. Neither is spelled out, so
// an address doesn't carry this computer's folder names.
const BASES = {
	"%SRCROOT%": "The folder that was checked.",
	HOME: "The home folder of the account that ran the check.",
};

// A rule as SARIF lists it. Its name says what it finds without one
// finding's values, and misconfig.ai/rules has the rest. One of your own
// rules isn't in the catalog, so its finding describes it, and its reference
// is where it's explained.
function ruleDescriptor(f) {
	const rule = f.custom ? { name: f.custom.name, severity: f.severity, category: f.category } : RULES[f.id];
	const name = rule.name ?? rule.title;
	const url = f.custom ? f.custom.reference : `${RULES_URL}#${f.id}`;
	const help = `What ${f.id} looks for, why it matters and how to fix it`;
	return {
		id: f.id,
		shortDescription: { text: name },
		fullDescription: { text: `${name}. ${LEVELS[rule.severity]}` },
		...(url ? { help: { text: `${help}: ${url}`, ...(f.custom ? {} : { markdown: `[${help}](${url})` }) }, helpUri: url } : {}),
		defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
		properties: {
			tags: ["security", rule.category],
			...(SECURITY_SEVERITY[rule.severity] ? { "security-severity": SECURITY_SEVERITY[rule.severity] } : {}),
		},
	};
}

// A file's address. A file in the checked folder is relative to it, which is
// how GitHub matches it to the repository. A file under the home folder is
// relative to HOME, so its address doesn't hold the account's name. Anything
// else, such as an administrator's settings, is a file: address.
function artifactLocation(file) {
	// A name can hold half of a character pair, which can't be encoded.
	const whole = (part) => part.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "\ufffd");
	const encode = (p) => p.split("/").map((part) => encodeURIComponent(whole(part))).join("/");
	if (file.startsWith("~/")) return { uri: encode(file.slice(2)), uriBaseId: "HOME" };
	if (/^[A-Za-z]:\//.test(file)) return { uri: `file:///${file.slice(0, 2)}${encode(file.slice(2))}` };
	if (file.startsWith("//")) return { uri: `file:${encode(file)}` };
	if (file.startsWith("/")) return { uri: `file://${encode(file)}` };
	return { uri: encode(file), uriBaseId: "%SRCROOT%" };
}

// A finding's own words: its title as a sentence, why it matters, and the
// fix. SARIF reads [text](address) in a message as a link, and names from a
// checked file are in these sentences, so the two marks are kept apart and a
// file can't put a link of its own in an alert.
function message(f) {
	const title = /[.!?…]$/.test(f.title) ? f.title : `${f.title}.`;
	return [title, f.why, `Fix: ${f.fix}`].join("\n").replace(/\]\(/g, "] (");
}

// GitHub refuses a file with more results than this, so a project crowded
// with findings can't keep the rest out of code scanning. The worst come
// first.
const MAX_RESULTS = 25000;

// The whole check as one SARIF run. Only the rules with findings are listed.
// A finding about a whole file points at its first line, which is where
// GitHub shows it. GitHub shows no finding that names no file.
export function sarif(result, { version }) {
	const findings = result.findings.slice(0, MAX_RESULTS);
	const ids = [...new Set(findings.map((f) => f.id))];
	const results = findings.map((f) => ({
		ruleId: f.id,
		ruleIndex: ids.indexOf(f.id),
		level: SARIF_LEVEL[f.severity],
		message: { text: message(f) },
		...(f.file ? { locations: [{ physicalLocation: { artifactLocation: artifactLocation(f.file), region: { startLine: f.line ?? 1 } } }] } : {}),
		properties: { severity: f.severity, ...(f.tool ? { agent: f.tool } : {}) },
	}));
	const bases = [...new Set(results.map((r) => r.locations?.[0].physicalLocation.artifactLocation.uriBaseId).filter(Boolean))];
	// A check that stopped early is marked as unfinished, so nothing that
	// reads the file takes a finding it didn't reach for one that was fixed.
	const stopped = result.stats.truncated;
	const count = (n) => n.toLocaleString("en-US");
	const notes = [];
	if (stopped) notes.push({ level: "error", message: { text: `The check stopped after ${count(result.stats.entriesScanned)} files and folders, so agent files deeper in the folder may have been missed.` } });
	const left = result.findings.length - MAX_RESULTS;
	if (left > 0) notes.push({ level: "warning", message: { text: `This file has the ${count(MAX_RESULTS)} worst findings. ${count(left)} more ${left === 1 ? "was" : "were"} left out.` } });
	return {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: { driver: { name: "misconfig", semanticVersion: version, informationUri: "https://misconfig.ai", rules: ids.map((id) => ruleDescriptor(findings.find((f) => f.id === id))) } },
				invocations: [{ executionSuccessful: !stopped, ...(notes.length ? { toolExecutionNotifications: notes } : {}) }],
				...(bases.length ? { originalUriBaseIds: Object.fromEntries(bases.map((b) => [b, { description: { text: BASES[b] } }])) } : {}),
				results,
				properties: { ruleset: result.version },
			},
		],
	};
}
