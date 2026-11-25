// Terminal output, in misconfig.ai's visual language: quiet text, bold where
// it matters, and color in two places only, the grade's square and the
// severity marks.

import { SCOPES } from "../engine/explain.js";
import { INSTALLED_BY } from "../engine/index.js";
import { maskSecrets } from "../engine/mask.js";
import { reviewLines } from "./computer-review.js";

const env = process.env;

// --- Color -------------------------------------------------------------------

// Color depth in bits: 24, 8, 4, or 1 for none. FORCE_COLOR and NO_COLOR
// work as in Node, and output that isn't a terminal is plain unless forced.
function colorDepth(stream) {
	if ("FORCE_COLOR" in env) {
		if (/^(0|false)$/i.test(env.FORCE_COLOR)) return 1;
		if (stream.isTTY && stream.getColorDepth) return Math.max(stream.getColorDepth(), 4);
		return env.FORCE_COLOR === "3" ? 24 : env.FORCE_COLOR === "2" ? 8 : 4;
	}
	if (!stream.isTTY || env.NO_COLOR || env.TERM === "dumb") return 1;
	return stream.getColorDepth?.() ?? 4;
}
const depth = colorDepth(process.stdout);

// The site's colors, with the nearest of 256 and of 16 for older terminals.
const COLORS = {
	signal: { rgb: [0xea, 0xff, 0x57], ansi: 93 },
	ink: { rgb: [0x00, 0x00, 0x00], ansi: 30 },
	critical: { rgb: [0xd7, 0x26, 0x3d], ansi: 31 },
	high: { rgb: [0xe8, 0x63, 0x0a], ansi: 91 },
	medium: { rgb: [0xb9, 0x89, 0x00], ansi: 33 },
	low: { rgb: [0x25, 0x63, 0xeb], ansi: 34 },
	info: { rgb: [0x8a, 0x90, 0x9c], ansi: 90 },
};
const LEVELS = [0, 95, 135, 175, 215, 255];
const nearest = (c) => LEVELS.reduce((best, v, i) => (Math.abs(v - c) < Math.abs(LEVELS[best] - c) ? i : best), 0);
const cube = ([r, g, b]) => 16 + 36 * nearest(r) + 6 * nearest(g) + nearest(b);
function code(name, layer) {
	const { rgb, ansi } = COLORS[name];
	const base = layer === "bg" ? 48 : 38;
	if (depth >= 24) return `${base};2;${rgb.join(";")}`;
	if (depth >= 8) return `${base};5;${cube(rgb)}`;
	return String(layer === "bg" ? ansi + 10 : ansi);
}
const on = depth > 1;
const style = (open, close) => (s) => (on ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
export const bold = style("1", "22");
export const dim = style("2", "22");
const color = (name) => (s) => (on ? `\x1b[${code(name, "fg")}m${s}\x1b[39m` : String(s));

// --- Text --------------------------------------------------------------------

// Text from the files being checked can hold terminal control codes that
// would rewrite the screen, or bidirectional marks that reorder it. They're
// shown as the replacement character (U+FFFD) instead.
//
// A CI system also reads parts of its log as commands. GitHub Actions takes
// ##[name] anywhere in a line, Azure Pipelines takes ##vso[name], and
// TeamCity reads ##teamcity[name]. A name in a checked file could spell one,
// so the same character goes inside it and the line stays text.
const safe = (s) =>
	String(s ?? "")
		.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "\ufffd")
		.replace(/#(?=#[a-z]*\[)/gi, "#\ufffd");
// For text printed on one line, such as a title or a path: line breaks in it
// would start a new line that looks like part of the report.
export const oneLine = (s) => safe(s).replace(/[\t\n]/g, " ");

const width = () => Math.min(Math.max(process.stdout.columns || Number(env.COLUMNS) || 100, 60), 100);

// Words wrapped to the width, each line indented. `first` replaces the
// indent on the first line, for a bullet or a label.
function wrap(text, indent, first = null) {
	const max = width() - indent;
	const lines = [];
	let line = "";
	for (const w of safe(text).split(/\s+/).filter(Boolean)) {
		if (line && line.length + 1 + w.length > max) {
			lines.push(line);
			line = w;
		} else line = line ? `${line} ${w}` : w;
	}
	if (line) lines.push(line);
	return lines.map((l, i) => (i === 0 && first !== null ? first : " ".repeat(indent)) + l);
}

// A path that fits the line: long ones keep their start and as much of the
// end as fits, so the file name and the folders just above it stay visible.
function fitPath(p, max) {
	const s = oneLine(p);
	if (s.length <= max) return s;
	const parts = s.split("/");
	const head = parts.slice(0, parts[0] === "~" ? 2 : 1).join("/");
	let tail = parts[parts.length - 1];
	for (let i = parts.length - 2; i >= 1 && `${head}/…/${parts[i]}/${tail}`.length <= max; i--) tail = `${parts[i]}/${tail}`;
	const out = `${head}/…/${tail}`;
	return out.length <= max ? out : `…${s.slice(-(max - 1))}`;
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// A report's lines as one piece of text. GitHub Actions reads a line that
// starts with ::name:: as a command, spaces before it or not, and a wrapped
// line can start with a word from a checked file. Such a line gets the
// replacement character between its colons.
const page = (lines) => lines.map((line) => line.replace(/^(\s*):(?=:)/, "$1:\ufffd")).join("\n") + "\n";
const npx = process.platform === "win32" ? "npx.cmd" : "npx";

// --- Report ------------------------------------------------------------------

const SEVERITY = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const MARK = "■";

export function printReport(result, { version, scanned, explain = false, open = false, lookedUp = false, known = null }) {
	const out = [];
	// One blank line between blocks, never two.
	const gap = () => out.length && out[out.length - 1] !== "" && out.push("");
	const where = scanned.demo ? "the sample computer" : scanned.projectSkipped ? "your home folder" : scanned.project;
	const sent = lookedUp ? "Everything ran here. Only package names and versions went to OSV.dev, to look them up." : "Everything ran here; nothing was uploaded.";
	out.push(`${bold("misconfig")} ${dim(version)}`);
	const project = scanned.projectSkipped && !scanned.demo ? " To check a project, run it in the project's folder." : "";
	const ownRules = result.customRules?.length ?? 0;
	const own = ownRules ? ` ${plural(ownRules, "rule")} of your own ${ownRules === 1 ? "was" : "were"} checked too.` : "";
	out.push(...wrap(`Checked ${where}${scanned.user && !scanned.demo ? " and the agent settings on this computer" : ""}. ${sent}${knownLine(known)}${own}${project}`, 0).map(dim));
	out.push("");
	if (result.computerReview) {
		out.push(bold("Computer review"), ...reviewLines(result.computerReview, scanned.demo).map(oneLine), "");
	}
	if (result.computerReviewError) out.push(oneLine(result.computerReviewError), "");

	// Every file that directs an agent, where it applies, and what it tells the
	// agent. Worked out on this computer and shown only here and in the page
	// --open saves.
	const map = result.controlMap;
	if (map.length) {
		out.push(`${bold("What controls your agents")}  ${dim(plural(map.length, "file"))}`);
		for (const scope of ["admin", "computer", "project", "loose"]) {
			const files = map.filter((f) => (f.scope ?? "project") === scope);
			if (!files.length) continue;
			out.push("", `  ${dim(SCOPES[scope])}`);
			for (const f of files) {
				const agents = f.tools.filter((t) => t !== "Any agent started there").join(", ");
				const room = width() - 4 - (agents ? agents.length + 2 : 0);
				if (explain) out.push("");
				out.push(`    ${bold(fitPath(f.path, Math.max(room, 30)))}${agents ? `  ${dim(oneLine(agents))}` : ""}`);
				if (f.summary) out.push(...wrap(f.summary, 6));
				if (explain) for (const d of f.details ?? []) out.push(...wrap(d, 8, `      ${dim("·")} `));
			}
		}
	}

	// What's installed: agents and editor extensions, with --explain.
	const installed = result.installed ?? { agents: [], editors: [] };
	if (explain && (installed.agents.length || installed.editors.length)) {
		gap();
		out.push(bold("What's installed"));
		if (installed.agents.length) {
			out.push("", `  ${dim("AI agents")}`);
			for (const a of installed.agents) out.push(`    ${bold(oneLine(`${a.tool} ${a.version}`))}  ${dim(oneLine(`${INSTALLED_BY[a.via] ?? a.via}, ${fitPath(a.path, width() - 30)}`))}`);
		}
		for (const e of installed.editors) {
			out.push("", `  ${dim(oneLine(`${e.editor} extensions, ${e.dir}`))}`);
			const agents = e.agents.map((x) => `${x.name} ${x.version}`.trim());
			const named = agents.length <= 1 ? agents.join("") : `${agents.slice(0, -1).join(", ")} and ${agents.at(-1)}`;
			out.push(...wrap(`${plural(e.count, "extension")}${agents.length ? `, including ${named}` : ""}.`, 4));
		}
	}

	// What to fix, worst first.
	const findings = result.findings;
	if (findings.length) {
		gap();
		out.push(`${bold("Findings")}  ${dim(String(findings.length))}`);
		for (const sev of Object.keys(SEVERITY)) {
			const group = findings.filter((f) => f.severity === sev);
			if (!group.length) continue;
			const paint = color(sev);
			out.push("", `  ${paint(bold(SEVERITY[sev]))}  ${dim(String(group.length))}`);
			for (const [n, f] of group.entries()) {
				if (n) out.push("");
				out.push(...wrap(f.title, 6).map((l, i) => `${i === 0 ? `    ${paint(MARK)} ` : "      "}${bold(l.slice(6))}`));
				// Where it is, then the rule, which misconfig.ai/rules explains.
				const at = f.file ? fitPath(f.file, width() - 16 - f.id.length) + (f.line ? `:${f.line}` : "") : "";
				out.push(`      ${dim(at ? `${at}  ${f.id}` : f.id)}`);
				if (f.review) out.push("      " + (f.review.acceptedAt ? "Risk accepted on " + new Date(f.review.acceptedAt).toISOString().slice(0, 10) + " by " + oneLine(f.review.acceptedBy ?? "an unknown account") : scanned.demo ? "Awaiting risk review" : "Accept risk: --approve " + f.review.id));
				if (sev === "critical" || sev === "high" || sev === "medium") out.push(...wrap(f.why, 6));
				out.push(...wrap(f.fix, 11, `      ${dim("Fix")}  `));
			}
		}
	}

	gap();
	const stopped = () => wrap(`The check stopped after ${result.stats.entriesScanned.toLocaleString("en-US")} files and folders, so agent files deeper in this folder may have been missed. Run it in a smaller folder to check everything.`, 0);
	if (!map.length && !findings.length) {
		out.push(...wrap("No files that control AI agents were found here. Run the check in the folder you open your agent in, usually the project root.", 0));
		if (result.stats.truncated) out.push("", ...stopped());
		process.stdout.write(page(out));
		return;
	}
	// The verdict, last, where it's on screen when the check finishes.
	out.push(...verdict(result), "");
	if (result.stats.truncated) out.push(...stopped(), "");
	if (scanned.demo) {
		out.push("Run --demo again to start a fresh sample.");
		process.stdout.write(page(out));
		return;
	}
	const next = [];
	// A risk you've accepted is one --fix leaves alone.
	if (findings.some((f) => f.autofix && !f.review?.acceptedAt)) next.push(["Fix what can be fixed for you", `${npx} @misconfig/cli${scanned.user ? "" : " --project-only"} --fix`]);
	if (!explain && map.some((f) => f.details?.length)) next.push(["Everything each file says", `${npx} @misconfig/cli --explain`]);
	if (!open) next.push(["Full report in your browser", `${npx} @misconfig/cli --open`]);
	if (!lookedUp && result.packages?.length) next.push(["Look up installs on OSV.dev", `${npx} @misconfig/cli --lookup`]);
	if (findings.some((f) => !f.custom)) next.push(["Every rule explained", "https://misconfig.ai/rules"]);
	next.push(["Full details as JSON", `${npx} @misconfig/cli --json`]);
	const pad = Math.max(...next.map(([label]) => label.length)) + 3;
	for (const [label, command] of next) out.push(`${dim(label.padEnd(pad))}${command}`);
	process.stdout.write(page(out));
}

// Which list of known malware the check used.
function knownLine(known) {
	if (!known) return "";
	const day = new Date(known.asOf).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
	if (known.from === "misconfig.ai") return ` Known malware as of ${day}.`;
	if (known.from === "offline") return ` Known malware as of ${day}, the list in this release.`;
	return ` Known malware as of ${day}: today's list couldn't be downloaded, so the check used the one in this release.`;
}

// The grade on its square, beside the score, the counts and what was checked.
// Without color it's plain lines that read the same in a log.
function verdict(result) {
	const counts = ["critical", "high", "medium", "low"].filter((s) => result.counts[s]);
	const score = `${result.score} out of 100`;
	const s = result.stats;
	const parts = [plural(s.filesChecked, "agent file"), s.mcpServers ? plural(s.mcpServers, "MCP server") : null, s.agentInstalls ? plural(s.agentInstalls, "agent install") : null, s.extensions ? plural(s.extensions, "editor extension") : null].filter(Boolean);
	const checked = `Checked ${parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts[0]}.`;
	if (!on) {
		return [`Grade ${result.grade}, ${score}`, counts.length ? counts.map((s) => `${result.counts[s]} ${s}`).join(", ") : "No issues found", checked];
	}
	const tile = (s) => `\x1b[${code("signal", "bg")};${code("ink", "fg")}m${s}\x1b[0m`;
	const tally = counts.length ? counts.map((s) => `${color(s)(MARK)} ${result.counts[s]} ${s}`).join("   ") : "No issues found";
	return [
		`  ${tile("       ")}   ${bold(score)}`,
		`  ${tile(`   \x1b[1m${result.grade}\x1b[22m   `)}   ${tally}`,
		`  ${tile("       ")}   ${dim(checked)}`,
	];
}


// --- Looking up installs ---------------------------------------------------------

// Where each package is published, in words, for OSV.dev's ecosystem names.
const REGISTRIES = { npm: "npm", PyPI: "PyPI", VSCode: "VS Marketplace", "VSCode:https://open-vsx.org": "Open VSX" };
const registryName = (ecosystem) => (Object.hasOwn(REGISTRIES, ecosystem) ? REGISTRIES[ecosystem] : ecosystem);

// Everything --lookup sends, listed before anything is sent.
export function printLookupPreview(out, queries) {
	const lines = ["", bold("Look up what's installed on OSV.dev")];
	if (!queries.length) {
		lines.push(...wrap("There's nothing to look up: no MCP packages, agent installs or editor extensions were found.", 2), "");
		out.write(page(lines));
		return;
	}
	lines.push(
		...wrap(
			`This sends ${plural(queries.length, "package name")} and their versions to OSV.dev, the open source vulnerability database. Nothing else is sent: no paths, file contents, server names or settings. The names come from your setup, so if one is private to your company, answer no.`,
			2,
		),
		"",
	);
	const shown = queries.slice(0, 40);
	const width = Math.max(...shown.map((q) => registryName(q.ecosystem).length));
	for (const q of shown) lines.push(oneLine(`    ${registryName(q.ecosystem).padEnd(width)}  ${q.name}${q.version ? ` ${q.version}` : ""}`) + (q.version ? "" : dim(" (any version)")));
	if (queries.length > shown.length) lines.push(dim(`    and ${queries.length - shown.length} more`));
	out.write(page(lines));
}

export function printLookupResult(out, { asked, failed, found }) {
	const parts =
		failed >= asked
			? ["OSV.dev didn't answer, so nothing was looked up. Try again later."]
			: [
					`Looked up ${plural(asked - failed, "package")} on OSV.dev.`,
					found ? `${plural(found, "finding")} added to the report.` : "Nothing new turned up.",
					failed ? `${plural(failed, "package")} couldn't be looked up; try again later.` : "",
				];
	out.write(page(["", ...wrap(parts.filter(Boolean).join(" "), 2), ""]));
}

// --- Fixes -----------------------------------------------------------------------

const fit = (s, max) => (s.length <= max ? s : `${s.slice(0, Math.max(max - 1, 1))}…`);
const when = (iso) => new Date(iso).toLocaleString("en-US", { dateStyle: "long", timeStyle: "short" });

// The lines an edit changes, with secrets hidden, up to eight.
function hunkLines(h) {
	const room = width() - 9;
	const clean = (l) => oneLine(maskSecrets(l).text).trim();
	// One long line changed in place: shown from a little before the change,
	// so the change itself is in view.
	let from = 0;
	if (h.length === 2 && h[0][0] === "-" && h[1][0] === "+") {
		const [a, b] = [clean(h[0][1]), clean(h[1][1])];
		let same = 0;
		while (same < a.length && a[same] === b[same]) same++;
		if (Math.max(a.length, b.length) > room && same > 30) from = same - 30;
	}
	const cut = (l) => (from ? fit(`…${l.slice(from)}`, room) : fit(l, room));
	const lines = h.slice(0, 8).map(([mark, l]) => (mark === "-" ? dim : String)(`      ${mark} ${cut(clean(l))}`));
	if (h.length > 8) lines.push(`        ${dim(`and ${plural(h.length - 8, "more line")}`)}`);
	return lines;
}

// --fix, before it asks: each change it would make, with the lines it
// touches, and each one it can't make with why.
export function printFixPreview(out, plans, { byHand = 0, grade = null, observed = 0 } = {}) {
	const lines = [];
	// Settings something changed since the last check are in the history, with no author.
	if (observed) lines.push("", ...wrap(`${plural(observed, "setting")} on this computer changed since your last check. ${npx} @misconfig/cli --history shows ${observed === 1 ? "it" : "them"}.`, 0));
	lines.push("", bold("Fix what can be fixed"));
	const ready = plans.filter((p) => p.edits.length);
	const skipped = plans.flatMap((p) => p.skipped.map((e) => [p, e]));
	if (!ready.length && !skipped.length) {
		lines.push(...wrap(`Nothing here can be fixed for you. Each finding's Fix line in ${npx} @misconfig/cli says what to change by hand.`, 2), "");
		out.write(page(lines));
		return;
	}
	for (const p of ready) {
		lines.push("", `  ${bold(fitPath(p.file, width() - 4))}`);
		for (const e of p.edits) lines.push(...wrap(e.does, 4), ...hunkLines(e.hunk));
	}
	if (skipped.length) {
		lines.push("", `  ${bold("Not fixed")}`);
		for (const [p, e] of skipped) lines.push(...wrap(`${e.fix.does} in ${p.file}: ${e.why}.`, 4, `  ${dim("·")} `));
	}
	lines.push("");
	const [now, then] = grade ?? [];
	if (ready.length && now && then && typeof now.score === "number" && then.score !== now.score) lines.push(...wrap(`With these changes the grade goes from ${now.grade} (${now.score}) to ${then.grade} (${then.score}).`, 2));
	if (ready.length) lines.push(...wrap(`Each file is backed up to ~/.misconfig/backups first, and changed only if it reads back as exactly this change. ${npx} @misconfig/cli --undo puts them back. Nothing is uploaded.`, 2).map(dim));
	// What's left once these are made: changes to make by hand.
	const one = byHand === 1;
	if (byHand) lines.push(...wrap(`${plural(byHand, "finding")} ${ready.length ? `${one ? "is" : "are"} left after these` : `${one ? "needs" : "need"} a change by hand`}: ${npx} @misconfig/cli lists ${one ? "it" : "them"} with ${one ? "its fix" : "their fixes"}.`, 2).map(dim));
	out.write(page(lines));
}

export function printFixResult(out, { changed, failed, backups, approved = 0 }) {
	const lines = [""];
	const names = changed.map((p) => p.file);
	if (changed.length) lines.push(...wrap(`Changed ${names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names.at(-1)}` : names[0]}. The originals are in ${backups}.`, 0));
	for (const { plan, why } of failed) lines.push(...wrap(`! ${plan.file} wasn't changed: ${why}.`, 2, ""));
	if (changed.length) lines.push(dim(`Check again: ${npx} @misconfig/cli`), dim(`Put them back: ${npx} @misconfig/cli --undo`));
	// Changes to the computer's settings are in its history as ones you approved.
	if (approved) lines.push(dim(`In this computer's history as changes you approved: ${npx} @misconfig/cli --history`));
	lines.push("");
	out.write(page(lines));
}

// --undo, before it asks: each file the last --fix changed, and whether it
// can be put back.
const UNDO_STATE = {
	ready: () => "Put back as it was before --fix.",
	"as it was": () => "Already as it was before --fix.",
	changed: (x) => `Changed since --fix changed it, so it's left as it is. The original is in ${x.backup}.`,
	gone: () => "Deleted since --fix changed it, so it stays deleted.",
	"not a file": () => "No longer a regular file, so it's left as it is.",
	"another user's": () => "Now another user's file, so it's left as it is.",
	"no backup": () => "Its backup is missing or was changed, so it can't be put back.",
};
export function printUndoPreview(out, plan) {
	const lines = ["", bold("Undo the last --fix")];
	if (!plan) lines.push(...wrap("There's no --fix to undo.", 2));
	else if (plan.error) lines.push(...wrap(`! ${plan.error}`, 4, "  "));
	else {
		lines.push(...wrap(`The changes made on ${when(plan.at)}. Each file is put back only if it's still exactly what --fix wrote, so nothing you changed since is lost.`, 2));
		for (const x of plan.items) lines.push("", `  ${bold(fitPath(x.name, width() - 4))}`, ...wrap(UNDO_STATE[x.state](x), 4).map(x.state === "ready" ? String : dim));
	}
	lines.push("");
	out.write(page(lines));
}

export function printUndoResult(out, plan, { restored, failed }) {
	const lines = [];
	const names = restored.map((x) => x.name);
	if (names.length) lines.push(...wrap(`Put back ${names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names.at(-1)}` : names[0]}. The backups stay in ${plan.folder}.`, 0));
	for (const { item, why } of failed) lines.push(...wrap(`! ${item.name} wasn't put back: ${why}. The original is in ${item.backup}.`, 2, ""));
	lines.push("");
	out.write(page(lines));
}

// --- The findings as a file ----------------------------------------------------

// Where --sarif saved the findings.
export function printSarifResult(out, { file, stopped }) {
	const note = stopped
		? "The check stopped early, and the file says so. Don't upload it to code scanning: findings it didn't reach would be marked as fixed."
		: "Nothing was uploaded. The file names the files with findings and what was found in each, so read it before you share it.";
	out.write(page(["", bold("Findings saved as SARIF"), `  ${oneLine(file)}`, "", ...wrap(note, 2).map(dim), ""]));
}

// --- The report in a browser ---------------------------------------------------

// Where --open saved the report.
export function printOpenResult(out, { file, opening }) {
	out.write(
		page([
			"",
			bold("Full report saved on this computer"),
			`  ${file}`,
			"",
			...wrap(`${opening ? "Opening it in your browser. " : ""}Nothing was uploaded. Anyone you send the file to can read everything in it, including the paths and settings on this computer.`, 2).map(dim),
			"",
		]),
	);
}
