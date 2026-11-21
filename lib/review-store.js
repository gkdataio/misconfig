import { randomBytes, randomUUID } from "node:crypto";
import { link, mkdir, open, readdir, readFile, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { riskEvent, validHistory } from "./review-history.js";

const revisionName = (n) => "state-" + n + ".json";
const dict = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hex = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const entries = (map) => dict(map) && Object.entries(map).every(([k,v]) => hex(k) && dict(v) && hex(v.hash)
	&& typeof v.file === "string" && typeof v.label === "string" && typeof v.summary === "string");

async function storage(operation) {
	try { return await operation(); }
	catch (err) { err.reviewStorage = true; throw err; }
}

function fresh() {
	return { schema: 2, key: randomBytes(32).toString("hex"), scannedAt: null, seen: {}, approved: {}, removedPending: {}, receipts: {}, uncertain: [], offeredRisks: {}, acceptedRisks: {}, history: { incomplete: false, events: [] } };
}

async function revisions(dir, clean = false) {
	const files = await readdir(dir);
	if (clean) {
		for (const f of files) {
			const writing = /^\.writing-(\d+)-[0-9a-f-]{36}$/.exec(f);
			if (!writing || Number(writing[1]) === process.pid) continue;
			try { process.kill(Number(writing[1]), 0); }
			catch (err) {
				if (err.code === "ESRCH") await unlink(path.join(dir, f)).catch(() => {});
			}
		}
	}
	return files.filter((f) => /^state-[1-9]\d{0,14}\.json$/.test(f))
		.map((f) => Number(f.slice(6, -5))).sort((a,b) => b - a);
}

async function latest(dir) {
	for (;;) {
		const [revision = 0] = await revisions(dir);
		if (!revision) return { revision, state: fresh() };
		const file = path.join(dir, revisionName(revision));
		try {
			const state = JSON.parse(await readFile(file, "utf8"));
			if (!dict(state) || ![1, 2].includes(state.schema) || !hex(state.key) || !Array.isArray(state.uncertain)
				|| !entries(state.seen) || !entries(state.approved) || !entries(state.removedPending ?? {}) || ![state.receipts, state.offeredRisks, state.acceptedRisks].every(dict)
				|| !Object.values(state.acceptedRisks).every((r) => dict(r) && Number.isFinite(r.at) && !Number.isNaN(new Date(r.at).getTime()))) throw new Error("Unexpected state format");
			state.removedPending ??= {};
			if (state.schema === 1) {
				const events = Object.entries(state.acceptedRisks).map(([id, risk]) => riskEvent(id, risk)).sort((a,b) => a.at - b.at);
				state.history = { incomplete: state.scannedAt !== null, events };
				state.schema = 2;
			}
			if (!validHistory(state.history)) throw new Error("Unexpected event history format");
			return { revision, state };
		} catch (err) {
			if (err.code === "ENOENT") continue;
			throw new Error("Could not read computer review history at " + file + ". Your saved approvals were left in place.", { cause: err });
		}
	}
}

const reviewDirectory = () => path.join(homedir(), ".misconfig", "computer-v1");

// A history lookup never scans, creates a directory or publishes a revision.
export async function readHistory(dir = reviewDirectory()) {
	try { return (await latest(dir)).state.history; }
	catch (err) {
		if (err.code === "ENOENT") return { incomplete: false, events: [] };
		throw err;
	}
}

// Publishing the next generation with an exclusive hard link is atomic on
// Windows, macOS and Linux. Readers can only open completed JSON. A competing
// writer rereads the winner and replays its edit, with no abandoned lock.
export async function updateReview(edit, dir = reviewDirectory()) {
	await storage(() => mkdir(dir, { mode: 0o700, recursive: true }));
	for (let attempt = 0; attempt < 16; attempt++) {
		const { revision, state } = await storage(() => latest(dir));
		const result = await edit(state);
		const next = revision + 1;
		const temp = path.join(dir, ".writing-" + process.pid + "-" + randomUUID());
		const handle = await storage(() => open(temp, "wx", 0o600));
		try {
			try {
				await storage(() => handle.writeFile(JSON.stringify(state)));
				await storage(() => handle.sync());
			} finally {
				await handle.close();
			}
			try {
				await storage(() => link(temp, path.join(dir, revisionName(next))));
			} catch (err) {
				if (err.code === "EEXIST") continue;
				throw err;
			}
			const versions = await storage(() => revisions(dir, true));
			if (versions[0] > next) continue;
			// Keep the previous complete file as well. Never clean up a newer
			// generation that another scanner has just published.
			await Promise.all(versions.filter((n) => n < next - 1).map((n) =>
				unlink(path.join(dir, revisionName(n))).catch(() => {})));
			return result;
		} finally {
			await unlink(temp).catch(() => {});
		}
	}
	throw new Error("Other scans are updating your computer review. Run the command again.");
}
