import path from "node:path";
import { LIMITS } from "../engine/paths.js";

function absolute(file, cwd) {
	if (typeof file !== "string" || !file || file.includes("\0")) return null;
	if (path.isAbsolute(file)) return path.normalize(file);
	return typeof cwd === "string" && path.isAbsolute(cwd) ? path.resolve(cwd, file) : null;
}

// Reverse only numbered, exact unified-diff hunks. A context or line-count
// mismatch means the current file cannot establish the earlier setting.
export function beforePatch(after, diff) {
	if (typeof after !== "string" || typeof diff !== "string") return;
	if (diff.length > LIMITS.maxFileBytes * 3) return;
	const current = after.replace(/\r\n/g, "\n").match(/[^\n]*\n|[^\n]+$/g) ?? [];
	const patch = diff.replace(/\r\n/g, "\n").split("\n");
	if (patch.at(-1) === "") patch.pop();
	let i = 0, cursor = 0, hunks = 0;
	const original = [];
	if (patch[0]?.startsWith("--- ") && patch[1]?.startsWith("+++ ")) i = 2;
	while (i < patch.length) {
		const h = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*$/.exec(patch[i++]);
		if (!h) return;
		const oldCount = Number(h[2] ?? 1), newCount = Number(h[4] ?? 1);
		const start = Number(h[3]) - (newCount ? 1 : 0);
		if (start < cursor || start > current.length || original.length + start - cursor !== Number(h[1]) - (oldCount ? 1 : 0)) return;
		while (cursor < start) original.push(current[cursor++]);
		let oldLines = 0, newLines = 0;
		while (i < patch.length && !patch[i].startsWith("@@ ")) {
			const line = patch[i++], op = line[0];
			if (![" ", "+", "-"].includes(op)) return;
			let value = line.slice(1) + "\n";
			if (patch[i] === "\\ No newline at end of file") { value = line.slice(1); i++; }
			if (op !== "-") { if (current[cursor++] !== value) return; newLines++; }
			if (op !== "+") { original.push(value); oldLines++; }
		}
		if (oldLines !== oldCount || newLines !== newCount) return;
		hunks++;
	}
	if (hunks) return original.join("") + current.slice(cursor).join("");
}

function replaceLiteral(text, oldValue, newValue, all) {
	if (typeof text !== "string" || typeof oldValue !== "string" || !oldValue || typeof newValue !== "string") return;
	if ([text, oldValue, newValue].some((s) => s.length > LIMITS.maxFileBytes)) return;
	const at = text.indexOf(oldValue);
	if (at < 0 || (!all && text.indexOf(oldValue, at + 1) !== -1)) return;
	if (!all) return text.slice(0, at) + newValue + text.slice(at + oldValue.length);
	const fragments = text.split(oldValue);
	if (text.length + (fragments.length - 1) * (newValue.length - oldValue.length) > LIMITS.maxFileBytes) return;
	return fragments.join(newValue);
}

function claudeEdit(call, result, current) {
	const { input, name } = call;
	if (result.userModified === true || result.success === false || result.is_error || result.error) return;
	if (name === "Write") {
		if (typeof input.content !== "string" || (result.content !== undefined && result.content !== input.content)) return;
		if (typeof result.originalFile === "string") return [result.originalFile, input.content];
		if (result.type === "create" && result.originalFile == null) return [null, input.content];
	} else {
		const { old_string: oldValue, new_string: newValue, replace_all: all } = input;
		if (typeof oldValue !== "string" || typeof newValue !== "string" || oldValue === newValue) return;
		if ((result.oldString !== undefined && result.oldString !== oldValue) || (result.newString !== undefined && result.newString !== newValue)) return;
		if (typeof result.originalFile === "string") {
			const after = replaceLiteral(result.originalFile, oldValue, newValue, all);
			if (after !== undefined) return [result.originalFile, after];
		} else if (result.success === true && !all) {
			const before = replaceLiteral(current, newValue, oldValue, false);
			if (before !== undefined) return [before, current, true];
		}
	}
}

// Only completed file-tool records qualify. Conversations, shell commands,
// pending patches and user-modified tool calls cannot establish an editor.
export function visitEdits(text, targetFor, visit) {
	const calls = new Map();
	let cwd;
	for (const line of text.split("\n")) {
		if (!line.includes("tool_use") && !line.includes("tool_result") && !line.includes("patch_apply_end") && !line.includes("item_completed") && !line.includes("session_meta") && !line.includes("turn_context")) continue;
		let r;
		try { r = JSON.parse(line); } catch { continue; }
		if (!r || typeof r !== "object") continue;
		const p = r.payload;
		if ((r.type === "session_meta" || r.type === "turn_context") && typeof p?.cwd === "string") { cwd = p.cwd; continue; }
		if (r.type === "assistant" && r.message?.role === "assistant" && Array.isArray(r.message.content)) {
			for (const call of r.message.content) {
				if (call?.type !== "tool_use" || !["Edit", "Write"].includes(call.name) || typeof call.id !== "string") continue;
				const target = targetFor(absolute(call.input?.file_path, r.cwd));
				if (target) calls.set(call.id, { ...call, target, session: r.sessionId });
			}
			continue;
		}
		const at = typeof r.timestamp === "string" ? Date.parse(r.timestamp) : NaN;
		if (!Number.isFinite(at)) continue;
		if (r.type === "user" && r.message?.role === "user" && Array.isArray(r.message.content) && r.toolUseResult) {
			const replies = r.message.content.filter((c) => c?.type === "tool_result");
			if (replies.length !== 1) continue;
			const reply = replies[0], call = calls.get(reply.tool_use_id);
			calls.delete(reply.tool_use_id);
			if (!call || call.session !== r.sessionId || reply.is_error === true || typeof r.toolUseResult !== "object") continue;
			const target = targetFor(absolute(r.toolUseResult.filePath, r.cwd));
			if (target !== call.target) continue;
			visit(target, at, "Claude Code", (current) => claudeEdit(call, r.toolUseResult, current));
		}
		if (r.type !== "event_msg" || !p) continue;
		let changes;
		if (p.type === "patch_apply_end" && p.success === true && (p.status === undefined || p.status === "completed")) changes = p.changes;
		if (p.type === "item_completed" && p.item?.type === "FileChange" && p.item.status === "completed") changes = p.item.changes;
		if (!changes || typeof changes !== "object" || Array.isArray(changes)) continue;
		for (const [name, change] of Object.entries(changes)) {
			const target = targetFor(absolute(name, cwd));
			if (!target || !change || change.move_path) continue;
			visit(target, at, "Codex", (current) => {
				if (change.type === "add" && typeof change.content === "string") return [null, change.content, true];
				if (change.type === "delete" && typeof change.content === "string") return [change.content, null, true];
				if (change.type === "update") {
					const before = beforePatch(current, change.unified_diff);
					if (before !== undefined) return [before, current, true];
				}
			});
		}
	}
}
