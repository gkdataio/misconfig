import { lstat, open, opendir } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { LIMITS } from "../engine/paths.js";
import { computerSnapshot, fingerprint } from "./computer-snapshot.js";
import { displayUserPath, reduceClaudeJson, resolveUserPath } from "./discover.js";
import { visitEdits } from "./edit-records.js";
import { addEditorEvidence, linkEditors } from "./review-history.js";

const WEEK = 7 * 86400000;
const TAIL = 4 * 1024 * 1024;
const BUDGET = 32 * 1024 * 1024;
const pathKey = (s) => process.platform === "win32" ? s.toLowerCase() : s;

async function recentSessions(home, env, since, report) {
	const roots = [path.join(env.CLAUDE_CONFIG_DIR || path.join(home, ".claude"), "projects"),
		...["sessions", "archived_sessions"].map((dir) => path.join(env.CODEX_HOME || path.join(home, ".codex"), dir))];
	const queue = roots.slice(), found = [];
	let entries = 0;
	for (let i = 0; i < queue.length; i++) {
		try {
			if (!(await lstat(queue[i])).isDirectory()) continue;
			const dir = await opendir(queue[i]);
			for await (const entry of dir) {
				if (++entries > 8192) { report.limited = true; break; }
				const file = path.join(queue[i], entry.name);
				if (entry.isDirectory()) queue.push(file);
				if (!entry.isFile() || !entry.name.endsWith(".jsonl")) continue;
				const info = await lstat(file);
				if (info.mtimeMs >= since) found.push({ file, time: info.mtimeMs });
			}
		} catch (e) { if (e.code !== "ENOENT") report.limited = true; }
		if (entries > 8192) break;
	}
	return found.sort((a,b) => b.time - a.time).map((x) => x.file);
}

async function readTail(file, room, report) {
	if (!(await lstat(file)).isFile()) { report.limited = true; return; }
	const fd = await open(file, "r");
	try {
		const stat = await fd.stat();
		if (!stat.isFile()) { report.limited = true; return; }
		const size = Math.min(room, TAIL, stat.size);
		const data = Buffer.alloc(size);
		let length = 0;
		while (length < size) {
			const { bytesRead } = await fd.read(data, length, size - length, stat.size - size + length);
			if (!bytesRead) break;
			length += bytesRead;
		}
		if (length < size) report.limited = true;
		let text = data.toString("utf8", 0, length);
		if (size < stat.size) {
			report.limited = true;
			const newline = text.indexOf("\n");
			text = newline < 0 ? "" : text.slice(newline + 1);
		}
		return { length, text };
	} finally { await fd.close(); }
}

function itemsFor(key, file, raw, home) {
	if (raw === null) return {};
	if (typeof raw !== "string" || Buffer.byteLength(raw) > LIMITS.maxFileBytes) return;
	if (file === "~/.claude.json") {
		const reduced = reduceClaudeJson(raw, (p) => displayUserPath(p, home));
		if (reduced.invalid) return;
		raw = reduced.text;
	}
	const snapshot = computerSnapshot(key);
	snapshot.collect(file, raw);
	if (snapshot.verified.has(file)) return snapshot.items;
}

export async function attributeEdits(state, review, currentFiles, { sessions = [], home = homedir(), env = process.env } = {}) {
	const report = { filesRead: 0, matchedEdits: 0, limited: false };
	const since = sessions.length ? 0 : Date.now() - WEEK;
	const targets = new Map();
	for (const event of state.history.events) {
		if (event.action !== "observed" || !event.transition || event.at < since) continue;
		const abs = pathKey(resolveUserPath(event.file, { home, env }));
		if (!targets.has(abs)) targets.set(abs, { file: event.file, events: [] });
		targets.get(abs).events.push(event);
	}
	if (!targets.size) return report;
	const matched = new Set();
	function visit(target, at, name, reconstruct) {
		const eligible = target.events.filter((e) => e.since <= at && at <= e.at);
		if (!eligible.length || at < since) return;
		const pair = reconstruct(currentFiles.get(target.file));
		if (!pair) return;
		// A hunk alone cannot prove which occurrence it changed after files
		// have moved around. Bind reconstructed text to both scan snapshots.
		const digests = pair[2] ? pair.slice(0, 2).map((s) => s === null ? null : fingerprint(state.key, s.replace(/\r\n/g, "\n"))) : null;
		const before = itemsFor(state.key, target.file, pair[0], home);
		const after = itemsFor(state.key, target.file, pair[1], home);
		if (!before || !after) return;
		for (const e of eligible) {
			if (digests && (digests[0] !== e.priorFile || digests[1] !== e.nextFile)) continue;
			const a = before[e.subject]?.hash ?? null, b = after[e.subject]?.hash ?? null;
			if (a === b || e.transition !== "c-" + fingerprint(state.key, [e.subject, a, b]).slice(0, 20)) continue;
			addEditorEvidence(state.history, e, { name, basis: "tool-record", at });
			matched.add(e.id);
		}
	}
	const files = sessions.length ? [...new Set(sessions)] : await recentSessions(home, env, since, report);
	let remaining = BUDGET;
	if (files.length > 48) report.limited = true;
	for (const file of files.slice(0, 48)) {
		if (!remaining) { report.limited = true; break; }
		let part;
		try { part = await readTail(file, remaining, report); } catch { report.limited = true; }
		if (!part) continue;
		remaining -= part.length;
		report.filesRead++;
		visitEdits(part.text, (abs) => abs && targets.get(pathKey(abs)), visit);
	}
	report.matchedEdits = matched.size;
	linkEditors(state.history, [...review.changes, ...review.pending]);
	return report;
}

// An edit misconfig made itself, with --fix or --undo, given as the file's
// whole text before and after. It's matched the way a tool's record is: to
// edits observed since it was made, by both texts and by the setting's value
// before and after. Anything else that changed in the file at the same moment
// matches neither text, and stays without an author. Returns the settings
// that matched.
export function attributeOwnEdits(state, edits, name, since, { home = homedir() } = {}) {
	const matched = new Set();
	for (const { files, before, after } of edits) {
		const [prior, next] = [before, after].map((text) => fingerprint(state.key, text.replace(/\r\n/g, "\n")));
		for (const file of files) {
			const events = state.history.events.filter((e) => e.action === "observed" && e.transition && e.file === file && e.at >= since && e.priorFile === prior && e.nextFile === next);
			if (!events.length) continue;
			const [was, now] = [itemsFor(state.key, file, before, home), itemsFor(state.key, file, after, home)];
			if (!was || !now) continue;
			for (const e of events) {
				const [a, b] = [was[e.subject]?.hash ?? null, now[e.subject]?.hash ?? null];
				if (a === b || e.transition !== "c-" + fingerprint(state.key, [e.subject, a, b]).slice(0, 20)) continue;
				addEditorEvidence(state.history, e, { name, basis: "tool-record", at: since });
				matched.add(e.subject);
			}
		}
	}
	return matched;
}
