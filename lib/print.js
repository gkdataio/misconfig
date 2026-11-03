// Terminal output, in misconfig.ai's visual language: quiet text, bold where
// it matters, and color in two places only, the grade's square and the
// severity marks.

import { SCOPES } from "../engine/explain.js";
import { INSTALLED_BY } from "../engine/index.js";

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
const safe = (s) => String(s ?? "").replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "\ufffd");
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
const npx = process.platform === "win32" ? "npx.cmd" : "npx";

// --- Report ------------------------------------------------------------------

const SEVERITY = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const MARK = "■";

export function printReport(result, { version, scanned, explain = false, open = false, lookedUp = false, known = null }) {
	const out = [];
	// One blank line between blocks, never two.
	const gap = () => out.length && out[out.length - 1] !== "" && out.push("");
	const where = scanned.projectSkipped ? "your home folder" : scanned.project;
	const sent = lookedUp ? "Everything ran here. Only package names and versions went to OSV.dev, to look them up." : "Everything ran here; nothing was uploaded.";
	out.push(`${bold("misconfig")} ${dim(version)}`);
	const project = scanned.projectSkipped ? " To check a project, run it in the project's folder." : "";
	out.push(...wrap(`Checked ${where}${scanned.user ? " and the agent settings on this computer" : ""}. ${sent}${knownLine(known)}${project}`, 0).map(dim));
	out.push("");

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
		process.stdout.write(out.join("\n") + "\n");
		return;
	}
	// The verdict, last, where it's on screen when the check finishes.
	out.push(...verdict(result), "");
	if (result.stats.truncated) out.push(...stopped(), "");
	const next = [];
	if (!explain && map.some((f) => f.details?.length)) next.push(["Everything each file says", `${npx} @misconfig/cli --explain`]);
	if (!open) next.push(["Full report in your browser", `${npx} @misconfig/cli --open`]);
	if (!lookedUp && result.packages?.length) next.push(["Look up installs on OSV.dev", `${npx} @misconfig/cli --lookup`]);
	if (findings.length) next.push(["Every rule explained", "https://misconfig.ai/rules"]);
	next.push(["Full details as JSON", `${npx} @misconfig/cli --json`]);
	const pad = Math.max(...next.map(([label]) => label.length)) + 3;
	for (const [label, command] of next) out.push(`${dim(label.padEnd(pad))}${command}`);
	process.stdout.write(out.join("\n") + "\n");
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
		out.write(lines.join("\n") + "\n");
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
	out.write(lines.join("\n") + "\n");
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
	out.write(["", ...wrap(parts.filter(Boolean).join(" "), 2), ""].join("\n") + "\n");
}

// --- The report in a browser ---------------------------------------------------

// Where --open saved the report.
export function printOpenResult(out, { file, opening }) {
	out.write(
		[
			"",
			bold("Full report saved on this computer"),
			`  ${file}`,
			"",
			...wrap(`${opening ? "Opening it in your browser. " : ""}Nothing was uploaded. Anyone you send the file to can read everything in it, including the paths and settings on this computer.`, 2).map(dim),
			"",
		].join("\n") + "\n",
	);
}
