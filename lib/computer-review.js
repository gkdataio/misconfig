import { fingerprint } from "./computer-snapshot.js";

function differences(secret, before, after, uncertain) {
	const rows = [];
	for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
		const a = before[key], b = after[key], entry = b ?? a;
		if (a?.hash === b?.hash || uncertain.has(entry.file)) continue;
		const kind = !a ? "added" : !b ? "removed" : "changed";
		const fields = new Set([...Object.keys(a?.parts ?? {}), ...Object.keys(b?.parts ?? {})]);
		const changedFields = [...fields].filter((k) => a?.parts?.[k] !== b?.parts?.[k]).sort();
		rows.push({
			key, id: "c-" + fingerprint(secret, [key, a?.hash ?? null, b?.hash ?? null]).slice(0, 20),
			kind, file: entry.file, label: entry.label, before: a?.summary ?? null, after: b?.summary ?? null, changedFields,
		});
	}
	return rows.sort((a,b) => a.file.localeCompare(b.file) || a.label.localeCompare(b.label) || a.key.localeCompare(b.key));
}

export function observe(state, snapshot, findings) {
	const previousScanAt = state.scannedAt;
	const seen = { ...snapshot.items };
	for (const [key, item] of Object.entries(state.seen)) {
		if (snapshot.uncertain.has(item.file)) seen[key] = item;
	}
	const changes = previousScanAt === null ? [] : differences(state.key, state.seen, seen, snapshot.uncertain);
	for (const row of changes) {
		if (row.kind === "removed" && !state.approved[row.key] && !state.receipts[row.key]) state.removedPending[row.key] = state.seen[row.key];
		else if (row.kind !== "removed") delete state.removedPending[row.key];
	}
	state.seen = seen;
	state.uncertain = [...snapshot.uncertain].sort();
	state.scannedAt = Date.now();

	const byFile = new Map();
	for (const [key, item] of Object.entries(seen).sort(([a],[b]) => a.localeCompare(b))) {
		if (!byFile.has(item.file)) byFile.set(item.file, []);
		byFile.get(item.file).push([key, item]);
	}
	state.offeredRisks = {};
	const risks = new Map();
	for (const finding of findings) {
		if (finding.severity === "info" || (!snapshot.verified.has(finding.file) && !snapshot.riskSources.has(finding.file))) continue;
		const entries = byFile.get(finding.file) ?? [];
		const server = finding.vars?.server;
		const owners = server ? entries.filter(([,v]) => v.subject === fingerprint(state.key, ["server", server])) : [];
		const scope = owners.length ? owners : entries;
		const revision = snapshot.riskSources.get(finding.file)
			?? (!owners.length && finding.evidence ? finding.evidence.trim() : scope.map(([k,v]) => [k,v.hash]));
		const id = "r-" + fingerprint(state.key, [finding.file, finding.id, finding.severity, finding.title, finding.vars, revision]).slice(0, 20);
		state.offeredRisks[id] = { file: finding.file, rule: finding.id, severity: finding.severity, label: owners.length === 1 ? owners[0][1].label : null };
		finding.review = { id, acceptedAt: state.acceptedRisks[id]?.at ?? null };
		risks.set(id, { id, file: finding.file, rule: finding.id, title: finding.title, severity: finding.severity, acceptedAt: finding.review.acceptedAt });
	}
	const awaiting = pending(state);
	const approvalIds = new Map(awaiting.map((r) => [r.key, r.id]));
	for (const row of changes) row.id = approvalIds.get(row.key) ?? null;
	const earlierRisks = Object.entries(state.acceptedRisks).filter(([id]) => !risks.has(id)).map(([id, r]) => ({
		id, file: r.file, rule: r.rule, severity: r.severity, label: r.label, acceptedAt: r.at,
		status: snapshot.uncertain.has(r.file) ? "unverified" : "not observed on this scan",
	}));
	return { previousScanAt, changes, pending: awaiting, unverified: state.uncertain, risks: [...risks.values()], earlierRisks };
}

function pending(state) {
	return differences(state.key, { ...state.removedPending, ...state.approved }, state.seen, new Set(state.uncertain));
}

export function approve(state, id) {
	const row = pending(state).find((r) => r.id === id);
	if (row) {
		if (row.kind === "removed") {
			delete state.approved[row.key];
			delete state.removedPending[row.key];
		}
		else state.approved[row.key] = state.seen[row.key];
		state.receipts[row.key] = id;
		return { id, kind: "change" };
	}
	if (Object.hasOwn(state.offeredRisks, id)) {
		state.acceptedRisks[id] ??= { at: Date.now(), ...state.offeredRisks[id] };
		return { id, kind: "risk", acceptedAt: state.acceptedRisks[id].at };
	}
	for (const [key, receipt] of Object.entries(state.receipts)) {
		if (receipt !== id || state.approved[key]?.hash !== state.seen[key]?.hash) continue;
		if (state.uncertain.includes(state.approved[key]?.file)) break;
		return { id, kind: "change" };
	}
	throw new Error("That review ID is no longer current. Scan again and choose the ID beside the change or risk you just reviewed.");
}

export function showApproval(review, findings, decision) {
	if (decision.kind === "risk") {
		for (const risk of review.risks) if (risk.id === decision.id) risk.acceptedAt = decision.acceptedAt;
		for (const f of findings) if (f.review?.id === decision.id) f.review.acceptedAt = decision.acceptedAt;
		review.confirmation = "Risk accepted. Its severity, score and fix are still shown.";
	} else {
		review.pending = review.pending.filter((r) => r.id !== decision.id);
		for (const row of review.changes) if (row.id === decision.id) row.id = null;
		review.confirmation = "Change approved on this computer.";
	}
}

export function changeText(row, existing = false) {
	const action = existing ? "Existing" : row.kind[0].toUpperCase() + row.kind.slice(1);
	const label = action + " " + row.label;
	if (row.kind === "changed" && row.before === row.after) {
		const detail = row.changedFields.length ? row.changedFields.join(", ") + " changed" : "content changed";
		return label + " · " + row.after + " (" + detail + ") · " + row.file;
	}
	return label + " · " + [row.before, row.after].filter((v) => v !== null).join(" → ") + " · " + row.file;
}

export function reviewLines(review) {
	const lines = [];
	const displayedIds = new Set();
	if (review.previousScanAt === null) lines.push("First scan on this computer. Review the settings you want to keep.");
	else {
		lines.push(review.changes.length ? "Since your last scan" : review.unverified.length ? "No changes in the settings we could verify." : "No changes since your last scan.");
		for (const row of review.changes) {
			lines.push("  " + changeText(row) + (row.id ? " · awaiting approval " + row.id : ""));
			if (row.id) displayedIds.add(row.id);
		}
	}
	const outstanding = review.pending.filter((r) => !displayedIds.has(r.id));
	if (outstanding.length) lines.push("Awaiting your approval (" + outstanding.length + ")");
	else if (!review.pending.length) lines.push(review.unverified.length ? "Approval is paused for the unverified sources below." : "No computer changes awaiting approval.");
	for (const row of outstanding) lines.push("  " + row.id + "  " + changeText(row, review.previousScanAt === null));
	for (const file of review.unverified) lines.push("Could not fully verify " + file + ". Any earlier decision is kept.");
	const accepted = review.risks.filter((r) => r.acceptedAt).length;
	if (accepted) lines.push(accepted + (accepted === 1 ? " accepted risk is" : " accepted risks are") + " still present. See Findings.");
	if (review.earlierRisks.length) {
		lines.push("Earlier risk decisions");
		for (const r of review.earlierRisks) lines.push("  " + [r.rule, r.label, r.file, "accepted " + new Date(r.acceptedAt).toISOString().slice(0, 10), r.status].filter(Boolean).join(" · "));
	}
	if (review.pending.length || review.risks.some((r) => !r.acceptedAt)) lines.push("Run again with --review to decide one at a time, or --approve ID to choose one.");
	if (review.confirmation) lines.push(review.confirmation);
	return lines;
}
