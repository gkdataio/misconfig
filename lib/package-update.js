import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

const LATEST = "https://registry.npmjs.org/@misconfig%2fcli/latest";
const DAY = 86400000;
const core = "(0|[1-9][0-9]*)";
const semver = new RegExp("^" + [core, core, core].join("\\.") + "(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$");

function parts(version) {
	if (typeof version !== "string" || version.length > 128) return null;
	const m = semver.exec(version);
	if (!m) return null;
	const pre = m[4]?.split(".");
	if (pre?.some((s) => /^0\d+$/.test(s))) return null;
	return { main: m.slice(1, 4).map((s) => BigInt(s)), pre };
}

export function compareVersions(a, b) {
	const x = parts(a), y = parts(b);
	if (!x || !y) return null;
	for (let i = 0; i < 3; i++) if (x.main[i] !== y.main[i]) return x.main[i] > y.main[i] ? 1 : -1;
	if (!x.pre || !y.pre) return x.pre ? -1 : y.pre ? 1 : 0;
	for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
		const p = x.pre[i], q = y.pre[i];
		if (p === q) continue;
		const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
		if (pn !== qn) return pn ? -1 : 1;
		return (pn ? BigInt(p) > BigInt(q) : p > q) ? 1 : -1;
	}
	return Math.sign(x.pre.length - y.pre.length);
}

async function registryVersion(fetchImpl) {
	const res = await fetchImpl(LATEST, { headers: { accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(1800) });
	if (!res.ok || !res.body) return null;
	const chunks = [];
	let size = 0;
	for await (const chunk of res.body) {
		size += chunk.length;
		if (size > 128 * 1024) return null;
		chunks.push(chunk);
	}
	const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
	const parsed = parts(data.version);
	return data.name === "@misconfig/cli" && parsed && !parsed.pre ? data.version : null;
}

export function automaticUpdateCheck(opts, env = process.env, terminal = process.stdout.isTTY && process.stdin.isTTY) {
	return Boolean(terminal && !opts.offline && !opts.demo && !opts.json && !opts.projectOnly && !opts.noHistory && !opts.noUpdate
		&& !opts.failOn && !env.CI && !env.NO_UPDATE_NOTIFIER && env.MISCONFIG_NO_UPDATE_CHECK !== "1");
}

export async function packageUpdate(installed, { force = false, offline = false, fetchImpl = fetch,
	cache = path.join(homedir(), ".misconfig", "npm-update.json"), now = Date.now() } = {}) {
	if (offline) return { installed, latest: null, status: "offline" };
	let prior;
	try { prior = JSON.parse(await readFile(cache, "utf8")); } catch {}
	const upgradedFrom = compareVersions(installed, prior?.installed) === 1 ? prior.installed : null;
	const fresh = Number.isFinite(prior?.checkedAt) && now >= prior.checkedAt && now - prior.checkedAt < DAY;
	let latest = prior?.latest, checkedAt = prior?.checkedAt;
	if (force || !fresh || !parts(latest) || parts(latest).pre) {
		try { latest = await registryVersion(fetchImpl); } catch { latest = null; }
		if (!latest) return { installed, latest: null, status: "unavailable" };
		checkedAt = now;
	}
	const order = compareVersions(latest, installed);
	const status = order > 0 ? "available" : order < 0 ? "ahead" : "current";
	// An explicit registry query can be consumed as JSON by a script. Leave
	// the first interactive release announcement available for the next scan.
	const firstReleaseNotice = !force && status === "current" && prior?.announced !== installed;
	const announced = firstReleaseNotice ? installed : prior?.announced;
	if (checkedAt !== prior?.checkedAt || installed !== prior?.installed || latest !== prior?.latest || firstReleaseNotice) {
		const tmp = cache + "." + randomUUID();
		try {
			await mkdir(path.dirname(cache), { recursive: true, mode: 0o700 });
			await writeFile(tmp, JSON.stringify({ installed, latest, checkedAt, announced }), { flag: "wx", mode: 0o600 });
			await rename(tmp, cache);
		} catch {} finally { await unlink(tmp).catch(() => {}); }
	}
	return { installed, latest, status, upgradedFrom, firstReleaseNotice };
}

export function updateMessage(update, explicit = false) {
	switch (update.status) {
		case "available": return "misconfig " + update.latest + " is available on npm (installed " + update.installed + "). Run " + (process.platform === "win32" ? "npx.cmd" : "npx") + " @misconfig/cli@latest to use it.";
		case "offline": return explicit ? "Offline mode is on. The npm registry was not contacted." : "";
		case "unavailable": return explicit ? "Could not check the npm registry for a stable release." : "";
		default:
			if (update.upgradedFrom && update.status === "current") return "Now running misconfig " + update.installed + ", updated from " + update.upgradedFrom + ".";
			if (update.firstReleaseNotice) return "You're running misconfig " + update.installed + ", the latest npm release." + (update.installed === "1.4.0" ? " Try --demo to see the new computer review and edit history." : "");
			return explicit ? "Installed misconfig " + update.installed + ". Latest stable release on npm is " + update.latest + "." : "";
	}
}
