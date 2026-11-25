import { randomUUID } from "node:crypto";
import { readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { analyze, applyLookup, useKnownMalware } from "../engine/index.js";
import { KNOWN_AS_OF } from "../engine/known.js";
import { maskSecrets } from "../engine/mask.js";
import { discover } from "./discover.js";
import { printReport, printOpenResult, printSarifResult, printLookupPreview, printLookupResult, printFixPreview, printFixResult, printUndoPreview, printUndoResult, oneLine } from "./print.js";
import { planFixes, applyFixes, planUndo, applyUndo } from "./fix.js";
import { jsonLines, sarif, stringify } from "./formats.js";
import { loadRules } from "./rule-files.js";
import { writeReport, openInBrowser } from "./html.js";
import { lookupQueries, osvLookup, installsOnly } from "./lookup.js";
import { computerSnapshot } from "./computer-snapshot.js";
import { observe, approve, showApproval, changeText } from "./computer-review.js";
import { readHistory, updateReview } from "./review-store.js";
import { claimEdit, earlierBuildNote, historyLine } from "./review-history.js";
import { withDemo } from "./demo.js";
import { attributeEdits, attributeOwnEdits } from "./edit-attribution.js";
import { samePath } from "./home.js";
import { automaticUpdateCheck, packageUpdate, updateMessage } from "./package-update.js";
import { LIMITS } from "../engine/paths.js";

const HELP = `Usage: npx @misconfig/cli [folder] [options]

Finds the files that control your AI coding agents on this computer and in
the folder (the current folder by default). It checks the settings for risks
and records changes to computer settings. It also checks the installed MCP
servers, editor extensions, skills and agent versions for known malware and
missing security fixes. Everything
runs here. It downloads today's list of known malware from misconfig.ai
first. Interactive computer scans also check for a newer CLI on npm.
Neither request sends your files or settings. --offline skips both.
Nothing else is sent unless you use --lookup.

Options
  --demo              Try the review offline on a disposable sample computer
  --history           Show recorded computer changes and who approved them
  --attribute         Match edits against recent local Claude and Codex records
  --session FILE      Use this local JSONL session for attribution (repeatable)
  --i-edited ID       Mark an observed edit (such as e-4) as yours, independently of approval
  --check-update      Check npm for a newer stable CLI release
  --no-update-check   Skip the automatic npm release check
  --review            Review pending computer changes and risks one at a time
  --approve ID        Approve one exact change or accept one visible risk
  --no-history        Scan without reading or updating computer review history
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
  --fix               Make the fixes that can be made for you, such as turning
                      off bypassPermissions or pinning an MCP package to its
                      version. Shows each change and asks first, and backs
                      each file up to ~/.misconfig/backups.
  --undo              Put back the files the last --fix changed, from its
                      backups, if they're still what it wrote. Asks first.
  --offline           Use bundled malware data and skip the npm update check.
                      An explicit --lookup still asks to contact OSV.dev.
                      Same as setting MISCONFIG_OFFLINE=1.
  --yes               Look up, fix or undo without asking, for scripts
  --json              Print the full result as JSON
  --jsonl             Print the findings as JSON Lines, one finding on each
                      line, for jq, grep and log collectors
  --sarif FILE        Also save the findings in FILE as SARIF 2.1.0, for
                      GitHub code scanning and other SARIF viewers
  --rules FILE        Also check with your own rules, from a JSON file.
                      Repeat it for more files.
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
		else if (a === "--jsonl") opts.jsonl = true;
		else if (a === "--sarif" || a.startsWith("--sarif=")) {
			if (opts.sarif) throw new Error("Choose one file for --sarif.");
			opts.sarif = a === "--sarif" ? argv[++i] : a.slice(8);
			if (!opts.sarif || opts.sarif.startsWith("-")) throw new Error("--sarif needs a file to save the findings in, such as misconfig.sarif.");
		}
		else if (a === "--rules" || a.startsWith("--rules=")) {
			const file = a === "--rules" ? argv[++i] : a.slice(8);
			if (!file || file.startsWith("-")) throw new Error("--rules needs a file of your own rules, such as rules.json.");
			(opts.rules ??= []).push(file);
		}
		else if (a === "--explain") opts.explain = true;
		else if (a === "--fix") opts.fix = true;
		else if (a === "--undo") opts.undo = true;
		else if (a === "--project-only") opts.projectOnly = true;
		else if (a === "--no-history") opts.noHistory = true;
		else if (a === "--history") opts.history = true;
		else if (a === "--attribute") opts.attribute = true;
		else if (a === "--check-update") opts.checkUpdate = true;
		else if (a === "--no-update-check") opts.noUpdate = true;
		else if (a === "--session") {
			const file = argv[++i];
			if (!file || file.startsWith("-")) throw new Error("--session needs a local session JSONL file.");
			(opts.sessions ??= []).push(file);
			opts.attribute = true;
		}
		else if (a === "--i-edited") {
			const id = argv[++i];
			if (opts.claim || !/^e-[1-9][0-9]*$/.test(id ?? "")) throw new Error("--i-edited needs one observed edit ID from --history.");
			opts.claim = id;
		}
		else if (a === "--demo") opts.demo = true;
		else if (a === "--review") opts.review = true;
		else if (a === "--approve" || a.startsWith("--approve=")) {
			if (opts.approve) throw new Error("Choose one review ID at a time.");
			opts.approve = a === "--approve" ? argv[++i] : a.slice(10);
			if (!/^[cr]-[0-9a-f]{20}$/.test(opts.approve ?? "")) throw new Error("--approve needs the ID beside one computer change or risk.");
		}
		else if (a === "--fail-on" || a.startsWith("--fail-on=")) {
			opts.failOn = (a.includes("=") ? a.split("=")[1] : argv[++i] ?? "").toLowerCase();
			if (!LEVELS.includes(opts.failOn)) throw new Error(`--fail-on needs one of: ${LEVELS.join(", ")}.`);
		} else if (a.startsWith("-")) throw new Error(`Unknown option ${a}. Run npx @misconfig/cli --help for the options.`);
		else { opts.dir = a; opts.folderGiven = true; }
	}

	if (opts.json && opts.jsonl) throw new Error("Choose --json or --jsonl. Each prints on its own.");
	if (opts.undo) return undo(opts);
	if (opts.fix) return fix(opts);
	if (opts.history || opts.claim || opts.checkUpdate) {
		if ([opts.history, opts.claim, opts.checkUpdate].filter(Boolean).length > 1 || opts.demo || opts.projectOnly || opts.noHistory || opts.review || opts.approve || opts.open || opts.lookup || opts.explain || opts.failOn || opts.yes || opts.folderGiven || opts.attribute || opts.jsonl || opts.sarif || opts.rules) throw new Error("Use --history, --i-edited ID or --check-update as a separate command. Each supports --json.");
		if (opts.checkUpdate) {
			const update = await packageUpdate(await version(), { force: true, offline: opts.offline });
			console.log(opts.json ? stringify(update, 2) : updateMessage(update, true));
			return ["unavailable", "offline"].includes(update.status) ? 2 : 0;
		}
		if (opts.claim) {
			const event = await updateReview((state) => claimEdit(state.history, opts.claim));
			console.log(opts.json ? stringify(event, 2) : oneLine(historyLine(event)));
			return 0;
		}
		const history = await readHistory();
		if (opts.json) console.log(stringify(history, 2));
		else {
			const lines = ["Computer history (newest first)"];
			if (history.incomplete) lines.push(earlierBuildNote);
			if (!history.events.length) lines.push("No events recorded yet.");
			for (const event of history.events.slice().reverse()) lines.push(historyLine(event));
			console.log(lines.map(oneLine).join("\n"));
		}
		return 0;
	}
	if (opts.demo && (opts.attribute || opts.projectOnly || opts.noHistory || opts.approve || opts.lookup || opts.failOn || opts.yes || opts.folderGiven || opts.jsonl || opts.sarif || opts.rules)) throw new Error("Use --demo to review the sample computer. It also supports --open, --explain and --json.");
	if ((opts.attribute || opts.review || opts.approve) && (opts.noHistory || opts.projectOnly)) throw new Error("Computer review needs a scan with computer history enabled.");
	if (opts.review && (opts.approve || opts.json || opts.jsonl || !process.stdin.isTTY || !process.stdout.isTTY)) throw new Error("Use --review in a terminal, or run --approve ID to choose one item directly.");
	if (opts.demo) return withDemo((demo) => runScan({ ...opts, offline: true }, demo));
	return runScan(opts);
}

async function runScan(opts, demo) {
	// A mistake in a rules file stops the command before anything is checked.
	const rules = opts.rules ? await loadRules(opts.rules) : [];
	const update = automaticUpdateCheck(opts) ? packageUpdate(await version()) : null;
	const known = opts.offline ? { asOf: `${KNOWN_AS_OF}T00:00:00Z`, from: "offline" } : await todaysList();
	// A concurrent local scan can cause the transaction to retry. Reuse an
	// OSV answer only for the same packages the user agreed to look up.
	let lookupCache;
	async function scan(state, lookupAuthors = true) {
		const snapshot = state && computerSnapshot(state.key, demo?.discovery);
		const currentFiles = (opts.attribute || demo) && snapshot && lookupAuthors ? new Map() : null;
		const collect = currentFiles ? (file, raw, flags, original) => {
			snapshot.collect(file, raw, flags, original);
			if (typeof original === "string" && original.length <= LIMITS.maxFileBytes && snapshot.verified.has(file)) currentFiles.set(file, original);
		} : snapshot?.collect;
		const input = await discover({ dir: opts.dir, includeUser: !opts.projectOnly, ...demo?.discovery, onComputerFile: collect });
		let result = { ...check(input, rules), knownMalware: known };
		// The rules of your own that the check ran with. Every report says how many.
		if (rules.length) result.customRules = rules.map((rule) => rule.id);
		if (demo) { result.demo = true; input.scanned.demo = true; }
		let lookedUp = false;
		if (opts.lookup) {
			const key = JSON.stringify(lookupQueries(result));
			if (lookupCache?.key !== key) lookupCache = { key, ...await lookup(opts, result) };
			lookedUp = lookupCache.lookedUp;
			if (lookedUp) result = applyLookup(result, lookupCache.hits);
		}
		if (state) {
			result.computerReview = await record(state, snapshot, input, result);
			if (currentFiles) result.computerReview.attribution = await attributeEdits(state, result.computerReview, currentFiles,
				demo ? { ...demo.discovery, sessions: [demo.session] } : { sessions: opts.sessions });
		}
		return { input, result, lookedUp };
	}
	if (demo) {
		await updateReview(async (state) => {
			const { result } = await scan(state);
			for (const row of result.computerReview.pending) approve(state, row.id, "Demo setup");
		}, demo.store);
		await demo.bump();
		if (!opts.json) console.log("Demo · A sample Codex tool record accompanies the calendar update from 1.2.3 to 1.2.4. The mail server has an unpinned package.\nThis run uses a fresh sample profile and deletes it when you finish.");
	}
	let report;
	if (opts.projectOnly || opts.noHistory) report = await scan(null);
	else {
		try {
			report = await updateReview(async (state) => {
				const next = await scan(state);
				if (opts.approve) showApproval(next.result.computerReview, next.result.findings, approve(state, opts.approve));
				return next;
			}, demo?.store);
		}
		catch (err) {
			if (demo || opts.approve || opts.review || !err.reviewStorage) throw err;
			report = await scan(null);
			report.result.computerReviewError = "Computer history unavailable. " + err.message;
		}
	}
	const { input, result, lookedUp } = report;
	const decide = (id, account) => updateReview(async (state) => {
		// A prompt may have been left open while the file changed.
		await scan(state, false);
		return approve(state, id, account);
	}, demo?.store);
	if (opts.review || (demo && process.stdin.isTTY && process.stdout.isTTY && !opts.json)) await reviewAtTerminal(result, decide, Boolean(demo));
	else if (demo) {
		if (!opts.json) console.log("Playing the sample decisions as Demo reviewer.");
		const review = result.computerReview;
		for (const item of [...review.pending, ...review.risks]) showApproval(review, result.findings, await decide(item.id, "Demo reviewer"));
	}

	if (opts.json) process.stdout.write(stringify(result, 2) + "\n");
	else if (opts.jsonl) process.stdout.write(jsonLines(result, { version: await version() }));
	else printReport(result, { version: await version(), scanned: input.scanned, explain: opts.explain, open: opts.open, lookedUp, known });
	if (update) {
		const notice = updateMessage(await update);
		if (notice) console.error("\n" + notice);
	}

	if (opts.open) await openReport(opts, input, result);
	if (opts.sarif) await saveSarif(opts, result);

	if (opts.failOn) {
		const worst = LEVELS.slice(0, LEVELS.indexOf(opts.failOn) + 1);
		if (result.findings.some((f) => worst.includes(f.severity))) return 1;
		// A check that couldn't see everything shouldn't pass a CI gate.
		if (result.stats.truncated) return 2;
	}
	return result.computerReviewError ? 2 : 0;
}

async function reviewAtTerminal(result, decide, demo) {
	const review = result.computerReview;
	process.stdout.write("\nReview " + (demo ? "the sample computer" : "this computer") + ". Y approves, Enter skips, and Q finishes. Each decision is saved immediately.\n");
	for (const file of review.unverified) process.stdout.write("Could not fully verify " + oneLine(file) + ".\n");
	const prompts = [
		...review.pending.map((row) => ({ id: row.id, text: changeText(row), question: "Approve this change?" })),
		...review.risks.filter((r) => !r.acceptedAt).map((r) => ({ id: r.id, text: r.severity + " · " + r.title + " · " + r.file, question: "Accept this risk and keep its warning visible?" })),
	];
	for (const p of prompts) {
		process.stdout.write("\n" + oneLine(p.text) + "\n");
		const finding = result.findings.find((f) => f.review?.id === p.id);
		if (finding) process.stdout.write(oneLine(finding.why) + "\nFix: " + oneLine(finding.fix) + "\n");
		else {
			const file = review.pending.find((r) => r.id === p.id)?.file;
			for (const risk of review.risks.filter((r) => r.file === file)) process.stdout.write("  Risk in this file: " + oneLine(risk.title) + "\n");
		}
		const answer = await ask(process.stdout, p.question + " [y/N/q] ");
		if (answer === "q" || answer === "quit") break;
		if (answer !== "y" && answer !== "yes") continue;
		const decision = await decide(p.id, demo ? "Demo reviewer" : undefined);
		showApproval(review, result.findings, decision);
		process.stdout.write(review.confirmation + "\n");
	}
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

// What a check adds to the computer's history: its settings as they are
// now, against what the last check saw.
async function record(state, snapshot, input, result) {
	snapshot.inventory(input, result.installed);
	await snapshot.checkMissing({ ...state.removedPending, ...state.approved, ...state.seen });
	return observe(state, snapshot, result.findings);
}

// Runs the checks, then points findings in reduced files back at real lines.
function check(input, rules) {
	const result = analyze(input, { rules });
	for (const f of result.findings) {
		const map = f.file && input.lineMaps?.[f.file];
		if (map && f.line) f.line = map[f.line - 1] ?? null;
	}
	return result;
}

// --fix and --undo change files, so each runs on its own and never in CI.
// These are the options either one is refused with.
const WITH_A_CHECK = [["json", "--json"], ["jsonl", "--jsonl"], ["sarif", "--sarif"], ["rules", "--rules"], ["open", "--open"], ["lookup", "--lookup"], ["explain", "--explain"], ["failOn", "--fail-on"], ["history", "--history"], ["review", "--review"], ["approve", "--approve"], ["attribute", "--attribute"], ["claim", "--i-edited"], ["checkUpdate", "--check-update"], ["demo", "--demo"]];
const others = (opts, more = []) => [...more, ...WITH_A_CHECK].filter(([key]) => opts[key]).map(([, flag]) => flag);
// CI systems, by the variables they set. Most set CI; these are the ones
// that may not.
const CI_VARIABLES = ["GITHUB_ACTIONS", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "TRAVIS", "CODEBUILD_BUILD_ID", "BITBUCKET_BUILD_NUMBER", "DRONE", "APPVEYOR", "BUILD_BUILDID"];
const inCI = (env = process.env) => (Boolean(env.CI) && !/^(?:false|0)$/i.test(env.CI)) || CI_VARIABLES.some((name) => env[name]);

// --fix: the changes the report says can be made for you, shown, asked
// about, backed up and made. It makes no network request: the fixes don't
// depend on today's list of known malware.
async function fix(opts) {
	const other = others(opts);
	if (other.length) throw new Error(`--fix runs on its own, without ${other.join(" or ")}. Check again after it.`);
	if (inCI()) throw new Error("--fix changes files, so it doesn't run in CI. Run it on your computer and commit what it changes.");
	// Where the computer has a history, this check goes in it like any other.
	// That also says which risks you've accepted: those settings are left alone.
	let history = await keepsHistory(opts);
	const recorded = history ? await recordedCheck(opts).catch((error) => {
		if (!error.reviewStorage) throw error;
		history = false;
		return null;
	}) : null;
	const input = recorded?.input ?? (await discover({ dir: opts.dir, includeUser: !opts.projectOnly }));
	const result = recorded?.result ?? check(input);
	const plans = await planFixes(result, input, { dir: opts.dir });
	// The check again, on the files as they'd be, for what's left and the grade.
	const after = new Map(plans.filter((p) => p.edits.length).flatMap((p) => p.names.map((name) => [name, p.after])));
	const next = check({ ...input, files: input.files.map((f) => (after.has(f.path) ? { ...f, content: maskSecrets(after.get(f.path)).text, settings: undefined } : f)) });
	printFixPreview(process.stdout, plans, { byHand: next.findings.filter((f) => f.severity !== "info").length, grade: [result, next], observed: result.computerReview?.changes.length ?? 0 });
	if (!plans.some((p) => p.edits.length)) return 0;
	if (!(await confirmed(opts, process.stdout, "\nMake these changes? [y/N] ", "Nothing was changed. Add --yes to make the changes without a prompt.", "Nothing was changed."))) return 0;
	const since = Date.now();
	const done = await applyFixes(plans);
	const approved = history ? await intoHistory(opts, done.changed.map((p) => ({ path: p.abs, before: p.before, after: p.after })), "misconfig --fix", since, { approved: true }) : 0;
	printFixResult(process.stdout, { ...done, approved });
	return done.failed.length ? 2 : 0;
}

// --fix and --undo keep the computer's history the way a check does, once
// the computer has one. Its first check starts it, not a fix.
async function keepsHistory(opts) {
	if (opts.projectOnly || opts.noHistory) return false;
	return readHistory().then((history) => history.events.length > 0, () => false);
}

// A check that goes in the computer's history, as every check with a history
// does. `then` works on the same record before it's saved.
function recordedCheck(opts, then = () => null) {
	return updateReview(async (state) => {
		const snapshot = computerSnapshot(state.key);
		const input = await discover({ dir: opts.dir, includeUser: true, onComputerFile: snapshot.collect });
		const result = check(input);
		result.computerReview = await record(state, snapshot, input, result);
		return { input, result, outcome: await then(state, input, result.computerReview) };
	});
}

// What --fix or --undo changed in the computer's settings goes in its history
// as their edit, so the next check doesn't ask who made the change. --fix
// showed each change before the yes, so its changes are approved by the
// account that gave it. --undo shows only the files, so what it puts back
// waits for approval like any other change. Returns how many settings were
// approved.
async function intoHistory(opts, edits, tool, since, { approved = false } = {}) {
	if (!edits.length) return 0;
	try {
		const { outcome } = await recordedCheck(opts, (state, input, review) => {
			const named = edits.map((edit) => ({ ...edit, files: [...input.paths].filter(([, abs]) => samePath(abs, edit.path)).map(([name]) => name) }));
			const mine = attributeOwnEdits(state, named, tool, since);
			if (!approved) return 0;
			for (const row of review.pending) if (mine.has(row.key)) approve(state, row.id);
			return mine.size;
		});
		return outcome;
	} catch (error) {
		if (!error.reviewStorage) throw error;
		console.error(`This computer's history couldn't be updated (${oneLine(error.message)}). The next check lists these changes for you to approve.`);
		return 0;
	}
}

// --undo: the files the last --fix changed, put back from its backups.
async function undo(opts) {
	const other = others(opts, [["fix", "--fix"], ["projectOnly", "--project-only"]]);
	if (other.length) throw new Error(`--undo runs on its own, without ${other.join(" or ")}.`);
	if (inCI()) throw new Error("--undo changes files, so it doesn't run in CI.");
	const plan = await planUndo();
	printUndoPreview(process.stdout, plan);
	if (!plan) return 0;
	if (plan.error) return 2;
	if (!plan.items.some((x) => x.state === "ready")) return 0;
	if (!(await confirmed(opts, process.stdout, "Put these back? [y/N] ", "Nothing was changed. Add --yes to undo without a prompt.", "Nothing was changed."))) return 0;
	const history = await keepsHistory(opts);
	const since = Date.now();
	const done = await applyUndo(plan);
	if (history) await intoHistory(opts, done.restored.map((x) => ({ path: x.path, before: x.current.toString("utf8"), after: x.data.toString("utf8") })), "misconfig --undo", since);
	printUndoResult(process.stdout, plan, done);
	return done.failed.length ? 2 : 0;
}

// Asks OSV.dev about what's installed, after showing exactly what will be sent.
async function lookup(opts, result) {
	const out = notes(opts);
	const base = serviceBase("MISCONFIG_OSV_URL", "https://api.osv.dev");
	const queries = lookupQueries(result);
	printLookupPreview(out, queries);
	if (!queries.length) return { result, lookedUp: false };
	if (!(await confirmed(opts, out, "\nLook these up on OSV.dev? [y/N] ", "Nothing was sent. Add --yes to look up without a prompt."))) return { result, lookedUp: false };
	const { hits, failed, asked } = await osvLookup(queries, { base, installs: installsOnly(result) });
	const next = applyLookup(result, hits);
	printLookupResult(out, { asked, failed, found: next.findings.length - result.findings.length });
	return { result: next, lookedUp: true, hits };
}

// A yes from someone at the terminal, or --yes. Without a terminal and
// without --yes, nothing is sent or changed.
async function confirmed(opts, out, question, refusal, declined = "Nothing was sent.") {
	if (opts.yes) return true;
	if (!process.stdin.isTTY) throw new Error(refusal);
	const answer = await ask(out, question);
	if (answer === "y" || answer === "yes") return true;
	out.write(`${declined}\n`);
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

// With --json or --jsonl, stdout is for the program reading it, so what the
// command has to say to a person goes to stderr.
const notes = (opts) => (opts.json || opts.jsonl ? process.stderr : process.stdout);

// The full report as a file on this computer, opened in the browser for
// someone at a terminal. Nothing is uploaded.
async function openReport(opts, input, result) {
	const out = notes(opts);
	// The list of packages is only for --lookup; the report doesn't show it.
	const report = { ...result };
	delete report.packages;
	const file = await writeReport(report, { version: await version(), scanned: input.scanned });
	// A browser opens only for someone at a terminal, never in CI or a script.
	const opening = Boolean(process.stdout.isTTY && process.stdin.isTTY);
	printOpenResult(out, { file, opening });
	if (opening) openInBrowser(file);
}

// --sarif: the findings as a file. It's written under another name and moved
// into place, so a link that a project from someone else left at that name
// is replaced, not followed into a file somewhere else.
async function saveSarif(opts, result) {
	const file = path.resolve(opts.sarif);
	const temp = `${file}.${randomUUID()}.tmp`;
	try {
		await writeFile(temp, stringify(sarif(result, { version: await version() }), 2) + "\n", { flag: "wx", mode: 0o600 });
		await rename(temp, file);
	} catch (err) {
		await unlink(temp).catch(() => {});
		const why = { ENOENT: "the folder it's in doesn't exist", ENOTDIR: "the folder it's in doesn't exist", EACCES: "this account can't write there", EPERM: "this account can't write there", EROFS: "this account can't write there", EISDIR: "a folder has that name" }[err?.code];
		throw new Error(`The SARIF file wasn't saved at ${opts.sarif}: ${why ?? err?.message ?? err}.`);
	}
	printSarifResult(notes(opts), { file, stopped: result.stats.truncated });
}

let cachedVersion = null;
async function version() {
	cachedVersion ??= JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).version;
	return cachedVersion;
}
