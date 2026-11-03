import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { analyze, applyLookup, useKnownMalware } from "../engine/index.js";
import { KNOWN_AS_OF } from "../engine/known.js";
import { discover } from "./discover.js";
import { printReport, printOpenResult, printLookupPreview, printLookupResult } from "./print.js";
import { writeReport, openInBrowser } from "./html.js";
import { lookupQueries, osvLookup, installsOnly } from "./lookup.js";

const HELP = `Usage: npx @misconfig/cli [folder] [options]

Finds every file that controls your AI coding agents, on this computer and in
the folder (the current folder by default), and checks them for risky
settings. It also checks the MCP servers, editor extensions, skills and agent
versions installed for known malware and missing security fixes. Everything
runs here. It downloads today's list of known malware from misconfig.ai
first, a request that carries nothing about your setup. Nothing else is sent
unless you use --lookup.

Options
  --explain           Show everything each file tells your agents: rules,
                      permissions, MCP servers, hooks and hidden text, and
                      what's installed
  --lookup            Also look up the MCP packages, editor extensions and
                      agent versions found on OSV.dev, for malware and known
                      vulnerabilities, including ones newer than this
                      release. Sends only package names and versions, and
                      asks first.
  --open              Save the full report as a page on this computer and
                      open it in your browser. Nothing is uploaded.
  --offline           Don't download today's list of known malware. The check
                      uses the list in this release. Same as setting
                      MISCONFIG_OFFLINE=1.
  --yes               Look up without asking, for scripts and CI
  --json              Print the full result as JSON
  --project-only      Skip the agent settings on this computer
  --fail-on <level>   Exit with code 1 if anything at this level or worse is
                      found: critical, high, medium or low. Useful in CI.
                      Exits with code 2 if the folder was too big to check
                      completely.
  -v, --version       Print the version
  -h, --help          Show this help
`;

const LEVELS = ["critical", "high", "medium", "low"];

export async function main(argv) {
	const opts = { dir: process.cwd(), open: false, lookup: false, offline: process.env.MISCONFIG_OFFLINE === "1", yes: false, json: false, explain: false, projectOnly: false, failOn: null };
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === "-h" || a === "--help") {
			process.stdout.write(HELP);
			return 0;
		}
		if (a === "-v" || a === "--version") {
			console.log(await version());
			return 0;
		}
		if (a === "--share") throw new Error("--share was removed in 1.3.1: misconfig.ai no longer publishes reports. Use --open for the full report on your computer.");
		if (a === "--open") opts.open = true;
		else if (a === "--lookup") opts.lookup = true;
		else if (a === "--offline") opts.offline = true;
		else if (a === "--yes" || a === "-y") opts.yes = true;
		else if (a === "--json") opts.json = true;
		else if (a === "--explain") opts.explain = true;
		else if (a === "--project-only") opts.projectOnly = true;
		else if (a === "--fail-on" || a.startsWith("--fail-on=")) {
			opts.failOn = (a.includes("=") ? a.split("=")[1] : argv[++i] ?? "").toLowerCase();
			if (!LEVELS.includes(opts.failOn)) throw new Error(`--fail-on needs one of: ${LEVELS.join(", ")}.`);
		} else if (a.startsWith("-")) throw new Error(`Unknown option ${a}. Run npx @misconfig/cli --help for the options.`);
		else opts.dir = a;
	}

	const known = opts.offline ? { asOf: `${KNOWN_AS_OF}T00:00:00Z`, from: "offline" } : await todaysList();
	const input = await discover({ dir: opts.dir, includeUser: !opts.projectOnly });
	let result = { ...check(input), knownMalware: known };
	let lookedUp = false;
	if (opts.lookup) ({ result, lookedUp } = await lookup(opts, result));

	if (opts.json) process.stdout.write(JSON.stringify(result, null, 2) + "\n");
	else printReport(result, { version: await version(), scanned: input.scanned, explain: opts.explain, open: opts.open, lookedUp, known });

	if (opts.open) await openReport(opts, input, result);

	if (opts.failOn) {
		const worst = LEVELS.slice(0, LEVELS.indexOf(opts.failOn) + 1);
		if (result.findings.some((f) => worst.includes(f.severity))) return 1;
		// A check that couldn't see everything shouldn't pass a CI gate.
		if (result.stats.truncated) return 2;
	}
	return 0;
}

// Today's list of known malware from misconfig.ai, added to the one in this
// release. The request says only which version of the command is asking and
// the kind of system, which is how misconfig.ai counts runs; with
// DO_NOT_TRACK=1 it asks not to be counted. If the list doesn't come within
// a few seconds, the check uses the one in this release and says so.
async function todaysList() {
	const fallback = { asOf: `${KNOWN_AS_OF}T00:00:00Z`, from: "release" };
	try {
		const system = { darwin: "mac", win32: "windows", linux: "linux" }[process.platform];
		const headers = { "user-agent": `misconfig-cli/${await version()}${system ? ` (${system})` : ""}`, ...doNotTrack() };
		const res = await fetch(`${serviceBase()}/api/known`, { headers, signal: AbortSignal.timeout(5000) });
		if (!res.ok || !res.body) return fallback;
		// Read only up to 4 MB: the list is a few kilobytes.
		const parts = [];
		let size = 0;
		const reader = res.body.getReader();
		for (let part = await reader.read(); !part.done; part = await reader.read()) {
			size += part.value.byteLength;
			if (size > 4 * 1024 * 1024) {
				reader.cancel().catch(() => {});
				return fallback;
			}
			parts.push(part.value);
		}
		const list = useKnownMalware(JSON.parse(Buffer.concat(parts).toString("utf8")));
		return list ? { asOf: list.updated, from: "misconfig.ai" } : fallback;
	} catch {
		return fallback;
	}
}

// DO_NOT_TRACK=1 asks misconfig.ai not to count a run.
const doNotTrack = () => (/^(?:1|true)$/i.test(process.env.DO_NOT_TRACK ?? "") ? { dnt: "1" } : {});

// Runs the checks, then points findings in reduced files back at real lines.
function check(input) {
	const result = analyze(input);
	for (const f of result.findings) {
		const map = f.file && input.lineMaps?.[f.file];
		if (map && f.line) f.line = map[f.line - 1] ?? null;
	}
	return result;
}

// Asks OSV.dev about what's installed, after showing exactly what will be sent.
async function lookup(opts, result) {
	const out = opts.json ? process.stderr : process.stdout;
	const base = serviceBase("MISCONFIG_OSV_URL", "https://api.osv.dev");
	const queries = lookupQueries(result);
	printLookupPreview(out, queries);
	if (!queries.length) return { result, lookedUp: false };
	if (!(await confirmed(opts, out, "\nLook these up on OSV.dev? [y/N] ", "Nothing was sent. Add --yes to look up without a prompt."))) return { result, lookedUp: false };
	const { hits, failed, asked } = await osvLookup(queries, { base, installs: installsOnly(result) });
	const next = applyLookup(result, hits);
	printLookupResult(out, { asked, failed, found: next.findings.length - result.findings.length });
	return { result: next, lookedUp: true };
}

// A yes from someone at the terminal, or --yes. Without a terminal and
// without --yes, nothing is sent.
async function confirmed(opts, out, question, refusal) {
	if (opts.yes) return true;
	if (!process.stdin.isTTY) throw new Error(refusal);
	const answer = await ask(out, question);
	if (answer === "y" || answer === "yes") return true;
	out.write("Nothing was sent.\n");
	return false;
}

// A question at the terminal. Ctrl+C, or the input ending, cancels it with an
// AbortError, which stops the command with nothing sent.
async function ask(out, question) {
	const rl = createInterface({ input: process.stdin, output: out });
	const stop = new AbortController();
	rl.once("SIGINT", () => stop.abort());
	rl.once("close", () => stop.abort());
	try {
		return (await rl.question(question, { signal: stop.signal })).trim().toLowerCase();
	} finally {
		rl.close();
	}
}

// Where requests go: misconfig.ai and OSV.dev, or for testing the addresses
// MISCONFIG_URL and MISCONFIG_OSV_URL name. Only https addresses, or http on
// this computer.
function serviceBase(name = "MISCONFIG_URL", fallback = "https://misconfig.ai") {
	const raw = process.env[name] || fallback;
	let url;
	try {
		url = new URL(raw);
	} catch {
		throw new Error(`${name} isn't a web address. Nothing was sent.`);
	}
	const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Error(`${name} must start with https://. Nothing was sent.`);
	return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

// The full report as a file on this computer, opened in the browser for
// someone at a terminal. Nothing is uploaded.
async function openReport(opts, input, result) {
	const out = opts.json ? process.stderr : process.stdout;
	// The list of packages is only for --lookup; the report doesn't show it.
	const report = { ...result };
	delete report.packages;
	const file = await writeReport(report, { version: await version(), scanned: input.scanned });
	// A browser opens only for someone at a terminal, never in CI or a script.
	const opening = Boolean(process.stdout.isTTY && process.stdin.isTTY);
	printOpenResult(out, { file, opening });
	if (opening) openInBrowser(file);
}

let cachedVersion = null;
async function version() {
	cachedVersion ??= JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).version;
	return cachedVersion;
}
