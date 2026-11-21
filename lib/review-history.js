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

export function riskEvent(id, risk) {
	const { at, file, rule, severity, label } = risk;
	return { action: "accepted-risk", at, actor: risk.by ?? null, file, rule, severity, label: label ?? null, reviewId: id };
}

export function validHistory(history) {
	if (typeof history?.incomplete !== "boolean" || !Array.isArray(history.events)) return false;
	return history.events.every((e) => {
		if (!e || !Number.isFinite(e.at) || Number.isNaN(new Date(e.at).getTime()) || !(e.actor === null || typeof e.actor === "string")) return false;
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
	return [action, changeValue(event), event.file, event.action === "observed" ? "Edit author unknown" : null].filter(Boolean).join(" · ");
}

export function historyLine(event) {
	return new Date(event.at).toISOString() + "  " + historyDescription(event);
}
