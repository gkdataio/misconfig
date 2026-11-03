// How findings are drawn in the report --open writes. It makes HTML text
// only, with no page or DOM.
//
// A short list of what to fix first comes before the findings, with what each
// rule takes off the score. Critical and high findings open with why they
// matter and the fix showing; the rest open on a click. Each names its rule,
// which misconfig.ai/rules explains, and the levels are explained beside the
// list. Everything that comes from the files is escaped as text.

import { LEVELS } from "../engine/catalog.js";
import { SCORING, pointsOff } from "../engine/index.js";
import { describeMasks } from "../engine/mask.js";

export const LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const SEVERITIES = Object.keys(LABEL);

// Text is escaped, and control codes and marks that reorder text, which a
// checked file can hold, are shown as the replacement character, as in the
// terminal.
const esc = (value) =>
	String(value ?? "")
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, "\ufffd")
		.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
// Rule IDs are capitals, digits and hyphens, such as CC-BYPASS.
const RULE_ID = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){0,6}$/;
const OPEN = new Set(["critical", "high"]);

function findingHtml(f, id = "") {
	const sev = Object.hasOwn(LABEL, f.severity) ? f.severity : "info";
	const where = f.file ? f.file + (f.line ? `:${f.line}` : "") : "";
	const evidence = f.evidence
		? `<pre class="evidence"><span class="evidence-where">${esc(f.file ? `${f.file}${f.line ? `, line ${f.line}` : ""}` : "Evidence")}</span>${esc(describeMasks(f.evidence))}</pre>`
		: "";
	const rule = typeof f.id === "string" && RULE_ID.test(f.id) ? `<a class="f-rule" href="https://misconfig.ai/rules#${f.id}" target="_blank" rel="noopener noreferrer">${f.id}</a>` : "";
	const meta = [f.tool ? `<span>Affects ${esc(f.tool)}</span>` : "", rule].filter(Boolean).join("");
	return `<details class="finding sev-${sev}"${id ? ` id="${esc(id)}"` : ""}${OPEN.has(sev) ? " open" : ""}>
		<summary><span class="sq" aria-hidden="true"></span><span class="f-title">${esc(f.title)}</span>${where ? `<span class="f-where">${esc(where)}</span>` : ""}</summary>
		<div class="f-body">
			<p><b>Why it matters.</b> ${esc(f.why)}</p>
			<p><b>Fix.</b> ${esc(f.fix)}</p>
			${evidence}
			${meta ? `<p class="f-meta">${meta}</p>` : ""}
		</div>
	</details>`;
}

// What the levels mean and how the score is worked out, folded away under
// one line.
function legendHtml() {
	return `<details class="legend">
		<summary>What the levels mean</summary>
		<dl>${SEVERITIES.map((s) => `<div><dt><span class="sq sev-${s}" aria-hidden="true"></span>${LABEL[s]}</dt><dd>${esc(LEVELS[s])}</dd></div>`).join("")}</dl>
		<p>${esc(SCORING)}</p>
		<p><a href="https://misconfig.ai/rules" target="_blank" rel="noopener noreferrer">Every rule, what it checks and how to fix it</a></p>
	</details>`;
}

const points = (n) => `${n} ${n === 1 ? "point" : "points"}`;
const FIX_FIRST_MAX = 12;

// The rules to fix, most points first, each linked to its first finding.
function fixFirstHtml(findings, anchorOf) {
	const { rules, total } = pointsOff(findings);
	if (!rules.length) return "";
	const off = Math.round(total);
	const score = Math.max(0, 100 - off);
	const shown = rules.slice(0, FIX_FIRST_MAX);
	const rest = rules.length - shown.length;
	const item = (r) => {
		const f = r.findings[0];
		const where = f.file ? f.file + (f.line ? `:${f.line}` : "") : "";
		const more = r.findings.length > 1 ? `<span class="ff-more">and ${r.findings.length - 1} more like it</span>` : "";
		return `<li class="sev-${r.severity}"><span class="sq" aria-hidden="true"></span><span class="ff-main"><a href="#${anchorOf.get(f)}">${esc(f.title)}</a>${more}${where ? `<span class="ff-where">${esc(where)}</span>` : ""}</span><span class="ff-points">${points(Math.round(r.points))}</span></li>`;
	};
	return `<section class="fix-first" aria-labelledby="fix-first-title">
		<h3 id="fix-first-title">Where to start</h3>
		<p>${off >= 100 ? `Together these take off ${points(off)}, more than the 100 a check starts with, so the score is 0.` : `Together these take off ${points(off)}, for a score of ${score}.`} Each fix gives its points back.</p>
		<ol>${shown.map(item).join("")}</ol>
		${rest > 0 ? `<p class="ff-rest">Plus ${rest} smaller ${rest === 1 ? "one" : "ones"} in the list below.</p>` : ""}
	</section>`;
}

// What to fix first, then the findings in groups, worst first, after the
// legend. In each group, findings in the same file sit together, so a file
// can be fixed in one pass.
export function findingsHtml(findings) {
	const groups = SEVERITIES.map((sev) => [
		sev,
		findings
			.filter((f) => f.severity === sev)
			.map((f, i) => [f, i])
			.sort(([a, i], [b, j]) => (a.file ?? "\uffff").localeCompare(b.file ?? "\uffff") || (a.line ?? 0) - (b.line ?? 0) || i - j)
			.map(([f]) => f),
	]).filter(([, group]) => group.length);
	const anchorOf = new Map();
	for (const [, group] of groups) for (const f of group) anchorOf.set(f, `finding-${anchorOf.size + 1}`);
	return (
		fixFirstHtml(findings, anchorOf) +
		legendHtml() +
		groups
			.map(
				([sev, group]) => `<section class="group">
			<h3 class="group-title"><span class="sq sev-${sev}" aria-hidden="true"></span>${LABEL[sev]}<span class="group-count">${group.length}</span></h3>
			${group.map((f) => findingHtml(f, anchorOf.get(f))).join("")}
		</section>`,
			)
			.join("")
	);
}
