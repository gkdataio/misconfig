// --open: the full report as one HTML file, saved in this computer's temp
// folder and opened in the browser. Nothing is uploaded.
//
// The file has no scripts, and its content security policy allows none, so
// nothing in it can run, whatever a checked file says. Everything that comes
// from the files is escaped as text. Styles and fonts are inside the file, so
// it loads nothing from anywhere.

import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { SCOPES } from "../engine/explain.js";
import { INSTALLED_BY } from "../engine/index.js";
import { findingsHtml, LABEL } from "./findings.js";
import { changeLabel } from "./computer-review.js";
import { changeValue, earlierBuildNote, historyDescription } from "./review-history.js";

const ASSETS = new URL("../report/", import.meta.url);
// Lines of what a file says shown in the report; --explain shows them all.
const MAX_DETAILS = 300;

// Text is escaped, and control codes and marks that reorder text, which a
// checked file can hold, are shown as the replacement character, as in the
// terminal.
const esc = (value) =>
	String(value ?? "")
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "\ufffd")
		.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const plural = (n, word) => `${n.toLocaleString("en-US")} ${n === 1 ? word : `${word}s`}`;
const listText = (items) => (items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`);
const fmtDate = (ms) => new Date(ms).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

// Writes the report and returns the file's path. The folder is new and only
// readable by you.
export async function writeReport(result, { version, scanned, checkedAt = Date.now() }) {
	const dir = await mkdtemp(path.join(tmpdir(), "misconfig-report-"));
	const file = path.join(dir, "report.html");
	await writeFile(file, await reportHtml(result, { version, scanned, checkedAt }), { mode: 0o600 });
	return file;
}

export async function reportHtml(result, { version, scanned, checkedAt }) {
	const [css, sans, mono, mark, printMark] = await Promise.all([
		readFile(new URL("styles.css", ASSETS), "utf8"),
		readFile(new URL("fonts/recursive-sans.woff2", ASSETS)),
		readFile(new URL("fonts/recursive-mono.woff2", ASSETS)),
		readFile(new URL("mark.svg", ASSETS)),
		readFile(new URL("mark-black.svg", ASSETS)),
	]);
	const styles = css
		.replace('url("/fonts/recursive-sans.woff2")', `url("data:font/woff2;base64,${sans.toString("base64")}")`)
		.replace('url("/fonts/recursive-mono.woff2")', `url("data:font/woff2;base64,${mono.toString("base64")}")`)
		.replace('url("/mark-black.svg")', `url("data:image/svg+xml;base64,${printMark.toString("base64")}")`);
	const title = `${result.grade === "–" ? "No grade" : `Grade ${result.grade}`}: misconfig report`;
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
<style>${styles}</style>
</head>
<body>
<header class="site-header">
	<div class="wrap header-inner">
		<a class="brand" href="https://misconfig.ai" rel="noopener noreferrer"><img src="data:image/svg+xml;base64,${mark.toString("base64")}" alt="" width="38" height="28">misconfig.ai</a>
	</div>
</header>
<main class="wrap report-page local-report">
${body(result, { version, scanned, checkedAt })}
</main>
<footer class="site-footer">
	<div class="wrap footer-base">
		<span>Made by misconfig ${esc(version)} on ${esc(fmtDate(checkedAt))}. To save it as a PDF, print it from your browser.</span>
	</div>
</footer>
</body>
</html>
`;
}

function body(r, { version, scanned }) {
	const where = scanned.demo ? "the sample computer" : scanned.projectSkipped ? "your home folder" : scanned.project || "a project";
	const checked = [
		plural(r.stats.filesChecked, "agent file"),
		r.stats.mcpServers ? plural(r.stats.mcpServers, "MCP server") : null,
		r.stats.agentInstalls ? plural(r.stats.agentInstalls, "agent install") : null,
		r.stats.extensions ? plural(r.stats.extensions, "editor extension") : null,
	].filter(Boolean);
	const tilt = typeof r.score === "number" ? Math.round(14 * (1 - r.score / 100)) : 0;
	const known = r.knownMalware ? ` Known malware as of ${new Date(r.knownMalware.asOf).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" })}.` : "";
	return `
	<section class="result-head" aria-labelledby="report-headline">
		<div class="grade-tile${r.grade === "–" ? " grade-none" : ""}" role="img" aria-label="${esc(typeof r.score === "number" ? `Grade ${r.grade}, score ${r.score} out of 100` : "No grade")}">
			<span class="square grade-square tilt-${tilt}" aria-hidden="true">${esc(r.grade)}</span>
		</div>
		<div>
			<h1 class="result-headline" id="report-headline">${esc(r.headline)}</h1>
			${countsList(r.counts)}
			<div class="result-meta">
				${typeof r.score === "number" ? `<p>Score ${esc(r.score)} out of 100.</p>` : ""}
				<p>Checked ${scanned.projectSkipped || !scanned.project ? esc(where) : `<code>${esc(where)}</code>`}${scanned.user && !scanned.demo ? " and the agent settings on this computer" : ""}.${esc(known)}</p>
				<p>${esc(listText(checked))}.${r.tools.length ? ` Agents found: ${esc(listText(r.tools))}.` : ""}</p>
			</div>
		</div>
	</section>

	<section class="report-note" aria-label="About this report">
		<span class="note-mark" aria-hidden="true"></span>
		<div>
			<p class="note-title">Saved on this computer only</p>
			<p class="note-detail">misconfig ${esc(version)} wrote this file in your temp folder. Nothing was uploaded, and nobody else can see it unless you send them the file.</p>
		</div>
	</section>

	${computerReviewHtml(r.computerReview, r.computerReviewError, scanned.demo)}
	<section class="chapter" aria-labelledby="findings-title">
		<h2 id="findings-title">Findings</h2>
		${r.findings.length ? findingsHtml(r.findings, scanned.demo) : '<p class="empty">No issues found in these agent files.</p>'}
		${r.findings.length && !scanned.demo ? `<p class="next-step">After you change a setting, run this version again with <code>--open</code> to see the updated report.</p>` : ""}
	</section>

	<section class="chapter" aria-labelledby="map-title">
		<h2 id="map-title">What controls your agents</h2>
		<p class="chapter-intro">${esc(plural(r.controlMap.length, "file"))} that tell agents what to do, and what each one says.</p>
		${controlMap(r.controlMap)}
	</section>
	${installedSection(r.installed ?? { agents: [], editors: [] })}`;
}

function computerReviewHtml(review, error, demo) {
	if (!review && !error) return "";
	const heading = '<h2 id="computer-review-title">Computer review</h2>';
	const section = (content) => `<section class="chapter" aria-labelledby="computer-review-title">${heading}${content}</section>`;
	if (error) return section(`<p class="chapter-intro">${esc(error)}</p>`);
	const first = review.previousScanAt === null;
	const shown = new Set(review.changes.map((r) => r.id));
	const outstanding = review.pending.filter((r) => !shown.has(r.id));
	const intro = first ? "First scan on this computer." : review.changes.length ? plural(review.changes.length, "change") + " since your last scan." :
		review.unverified.length ? "No changes in the settings we could verify." : "No changes since your last scan.";
	const rows = (list, existing) => `<ul class="computer-changes">${list.map((row) => `<li>
		<div><strong>${esc(changeLabel(row, existing))}</strong><p class="computer-value"><code>${esc(changeValue(row))}</code></p><p class="computer-file">${esc(row.file)}</p></div>
		<div class="computer-decision">${row.id ? `Awaiting approval<code>${esc(row.id)}</code>` : "Approved"}</div>
	</li>`).join("")}</ul>`;
	const notes = review.unverified.map((f) => "Could not fully verify " + f + ". Any earlier decision is kept.");
	const accepted = review.risks.filter((r) => r.acceptedAt).length;
	if (accepted) notes.push(plural(accepted, "accepted risk") + (accepted === 1 ? " is" : " are") + " still present. See Findings.");
	if (review.confirmation) notes.push(review.confirmation);
	const past = review.earlierRisks.map((r) => `<li><code>${esc(r.rule)}</code> · ${esc(r.file)} · accepted ${esc(fmtDate(r.acceptedAt))} by ${esc(r.acceptedBy ?? "an unknown account")} · ${esc(r.status)}</li>`).join("");
	const history = review.history ?? { events: [], incomplete: true };
	const events = history.events.slice().reverse().map((e) => {
		const iso = new Date(e.at).toISOString();
		return `<li><time datetime="${iso}">${iso.replace("T", " ").replace("Z", " UTC")}</time><span>${esc(historyDescription(e))}</span></li>`;
	}).join("");
	return section(`<p class="chapter-intro">${esc(intro)}</p>
		${review.changes.length ? rows(review.changes, false) : ""}
		${outstanding.length ? `<h3 class="map-scope">Awaiting your approval (${outstanding.length})</h3>${rows(outstanding, first)}` : ""}
		${notes.map((n) => `<p class="computer-note">${esc(n)}</p>`).join("")}
		${past ? `<h3 class="map-scope">Earlier risk decisions</h3><ul>${past}</ul>` : ""}
		${!demo && (review.pending.length || review.risks.some((r) => !r.acceptedAt)) ? '<p class="next-step">Run again with <code>--review</code> to decide one at a time, or <code>--approve ID</code> to choose one.</p>' : ""}
		<details class="computer-history"${demo ? " open" : ""}><summary>Computer history (${history.events.length})</summary>
		${history.incomplete ? `<p>${esc(earlierBuildNote)}</p>` : ""}
		${events ? `<ol aria-label="Newest events first">${events}</ol>` : "<p>No events recorded yet.</p>"}</details>`);
}

function countsList(counts) {
	const items = ["critical", "high", "medium", "low"]
		.filter((s) => counts[s])
		.map((s) => `<li><span class="sq sev-${s}" aria-hidden="true"></span><span><b>${esc(counts[s])}</b> ${LABEL[s].toLowerCase()}</span></li>`);
	return `<ul class="counts">${items.length ? items.join("") : '<li><span class="sq sev-none" aria-hidden="true"></span>No issues found</li>'}</ul>`;
}

function controlMap(map) {
	if (!map.length) return '<p class="empty">No files that steer agents were found.</p>';
	return Object.entries(SCOPES)
		// Files with issues first, so they're not lost among the rest.
		.map(([scope, label]) => [label, map.filter((f) => f.scope === scope).sort((a, b) => Number(b.findings > 0) - Number(a.findings > 0))])
		.filter(([, files]) => files.length)
		.map(([label, files]) => `<section class="map-group"><h3 class="map-scope">${esc(label)}</h3><ul class="map-list">${files.map(mapItem).join("")}</ul></section>`)
		.join("");
}

function mapItem(f) {
	const agents = (f.tools ?? []).filter((t) => t !== "Any agent started there").join(", ");
	const issues = f.findings ? `<span class="map-issues has-issues">${esc(plural(f.findings, "issue"))}</span>` : '<span class="map-issues">No issues</span>';
	const details = Array.isArray(f.details) ? f.details : [];
	const more = details.length > MAX_DETAILS ? `<li class="map-more">And ${esc(plural(details.length - MAX_DETAILS, "more line"))}. Run the command with --explain to see them all.</li>` : "";
	const list = details.length
		? `<details class="map-details"><summary>Everything it says</summary><ul>${details
				.slice(0, MAX_DETAILS)
				.map((d) => `<li>${esc(d)}</li>`)
				.join("")}${more}</ul></details>`
		: "";
	return `<li class="map-item">
		<div class="map-head"><code>${esc(f.path)}</code>${agents ? `<span class="map-agents">${esc(agents)}</span>` : ""}${issues}</div>
		<p class="map-summary">${esc(f.summary || f.kind)}</p>
		${list}
	</li>`;
}

// AI agents and editor extensions on this computer.
function installedSection({ agents, editors }) {
	if (!agents.length && !editors.length) return "";
	const item = (name, label, text, place) =>
		`<li class="map-item"><div class="map-head"><code>${esc(name)}</code>${label ? `<span class="map-agents">${esc(label)}</span>` : ""}</div>${text ? `<p class="map-summary">${esc(text)}</p>` : ""}${place ? `<code class="map-path">${esc(place)}</code>` : ""}</li>`;
	const group = (title, items) => (items.length ? `<section class="map-group"><h3 class="map-scope">${esc(title)}</h3><ul class="map-list">${items.join("")}</ul></section>` : "");
	return `<section class="chapter" aria-labelledby="installed-title">
		<h2 id="installed-title">What's installed</h2>
		<p class="chapter-intro">The AI agents on this computer, by name and version, and how many extensions each editor has, with the AI agent extensions among them.</p>
		${group("AI agents", agents.map((a) => item(`${a.tool} ${a.version}`, INSTALLED_BY[a.via] ?? a.via, "", a.path)))}
		${group(
			"Editor extensions",
			editors.map((e) => {
				const named = e.agents.map((x) => `${x.name} ${x.version}`.trim());
				return item(`${e.editor} extensions`, "", `${plural(e.count, "extension")}${named.length ? `, including ${listText(named)}` : ""}.`, e.dir);
			}),
		)}
	</section>`;
}

// Opens a file or address in the default browser. Nothing is shown if it
// can't, and the command has already printed where the report is.
export function openInBrowser(target) {
	const [command, args] =
		process.platform === "win32"
			? ["rundll32", ["url.dll,FileProtocolHandler", target]]
			: process.platform === "darwin"
				? ["open", [target]]
				: ["xdg-open", [target]];
	try {
		const child = spawn(command, args, { stdio: "ignore", detached: true });
		child.on("error", () => {});
		child.unref();
	} catch {}
}
