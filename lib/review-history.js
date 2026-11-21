import { userInfo } from "node:os";

const observation = { added: "addition of ", changed: "change to ", removed: "removal of " };
const approval = { added: "", changed: "the change to ", removed: "removing " };

// Read the effective OS account only when a decision is made. A scan cannot
// identify the person or process that wrote a config file.
export function localAccount() {
	try { return userInfo().username || null; }
	catch { return null; }
}

export function changeEvent(action, row, at, actor = null) {
	const { kind, label, file, before, after, changedFields } = row;
	return { action, at, actor, kind, label, file, before, after, changedFields, ...(action === "approved" ? { reviewId: row.id } : {}) };
}

export function editorText(editor, scope) {
	if (!editor) return "Edit author unknown";
	if (editor.basis === "conflicting") return "Edit author uncertain (" + editor.sources.map((s) => s.name + ", " + (s.basis === "tool-record" ? "tool record" : "self-reported")).join(" / ") + ")";
	if (scope === "latest") return "Latest observed edit by " + editor.name + (editor.basis === "tool-record" ? " (local tool record)" : " (self-reported)");
	return "Edited by " + editor.name + (editor.basis === "tool-record" ? " (local tool record)" : " (self-reported)");
}

// Approvals keep pointing at the same observed edit even after another scan,
// or when the user imports evidence after approving.
export function linkEditors(history, rows) {
	const latest = new Map();
	for (const e of history.events) if (e.action === "observed" && e.subject) latest.set(e.subject, e);
	for (const row of rows) {
		const observed = latest.get(row.key);
		if (observed) {
			if (row.observationId !== observed.id) row.editorScope = observed.transition === row.id ? "change" : "latest";
			Object.assign(row, { observationId: observed.id, editor: observed.editor ?? null });
		}
	}
}

export function addEditorEvidence(history, observed, source) {
	const existing = observed.editor;
	const sources = existing?.basis === "conflicting" ? existing.sources : existing ? [existing] : [];
	if (sources.some((s) => s.name === source.name && s.basis === source.basis)) return;
	observed.editor = sources.length ? { name: null, basis: "conflicting", sources: [...sources, source] } : source;
	for (const e of history.events) if (e.action === "approved" && e.observationId === observed.id) e.editor = observed.editor;
}

export function claimEdit(history, id, account = localAccount()) {
	const observed = history.events.find((e) => e.id === id && e.action === "observed");
	if (!observed) throw new Error("Choose an observed edit ID from --history.");
	if (!account) throw new Error("The OS account name is unavailable. The edit could not be claimed.");
	addEditorEvidence(history, observed, { name: account, basis: "self-reported", at: Date.now() });
	return observed;
}

export function riskEvent(id, risk) {
	const { at, file, rule, severity, label } = risk;
	return { action: "accepted-risk", at, actor: risk.by ?? null, file, rule, severity, label: label ?? null, reviewId: id };
}

export function validHistory(history) {
	if (typeof history?.incomplete !== "boolean" || !Array.isArray(history.events)) return false;
	return history.events.every((e) => {
		if (!e || !Number.isFinite(e.at) || Number.isNaN(new Date(e.at).getTime()) || !(e.actor === null || typeof e.actor === "string")) return false;
		if (e.editor != null) {
			const sources = e.editor.basis === "conflicting" ? e.editor.sources : [e.editor];
			if (!Array.isArray(sources) || !sources.length || !sources.every((s) => s && typeof s.name === "string" && ["self-reported", "tool-record"].includes(s.basis) && Number.isFinite(s.at))) return false;
		}
		if (e.action === "baseline") return e.actor === null && Number.isInteger(e.count) && e.count >= 0;
		if (typeof e.file !== "string") return false;
		if (e.action === "accepted-risk") return typeof e.rule === "string" && typeof e.severity === "string" && (e.label === null || typeof e.label === "string") && typeof e.reviewId === "string";
		return (e.action === "observed" && e.actor === null || e.action === "approved" && typeof e.reviewId === "string")
			&& ["added", "changed", "removed"].includes(e.kind) && typeof e.label === "string"
			&& [e.before, e.after].every((s) => s === null || typeof s === "string") && Array.isArray(e.changedFields) && e.changedFields.every((s) => typeof s === "string");
	});
}

export function changeValue(row) {
	if (row.kind === "changed" && row.before === row.after) {
		const detail = row.changedFields.length ? row.changedFields.join(", ") + " changed" : "content changed";
		return row.after + " (" + detail + ")";
	}
	return [row.before, row.after].filter((v) => v !== null).join(" → ");
}

export const earlierBuildNote = "Earlier builds recorded some risk acceptance dates. They did not record review accounts or a full change history.";

export function historyDescription(event) {
	if (event.action === "baseline") return "First scan recorded " + event.count + (event.count === 1 ? " setting." : " settings.");
	const account = event.actor ?? "Account unknown";
	if (event.action === "accepted-risk") return [account + " accepted " + event.severity + " risk " + event.rule, event.label, event.file].filter(Boolean).join(" · ");
	const action = event.action === "approved" ? account + " approved " + approval[event.kind] + event.label
		: "Observed " + observation[event.kind] + event.label;
	const authorship = event.action === "observed" || event.observationId ? editorText(event.editor, event.editorScope) : null;
	return [action, changeValue(event), event.file, authorship, event.action === "observed" ? event.id : null].filter(Boolean).join(" · ");
}

export function historyLine(event) {
	return new Date(event.at).toISOString() + "  " + historyDescription(event);
}
