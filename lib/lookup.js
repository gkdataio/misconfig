// --lookup: asks OSV.dev, the open source vulnerability database, about the
// MCP packages, editor extensions and agent installs the check found. Only
// package names, ecosystems and versions are sent: no paths, file contents,
// server names or settings. OSV.dev includes the OpenSSF list of malicious
// packages (IDs starting MAL-) and GitHub's advisories.
//
// Everything that comes back is checked before it's used: IDs must look like
// IDs, versions like versions, and text is cut to size. Anything else is
// dropped.

import { compareVersions, AGENT_ADVISORIES } from "../engine/known.js";

// Package names as each registry writes them. Anything else, such as a path,
// a GitHub repository or a name with spaces, isn't sent. Extension IDs keep
// their publisher's capitals, since OSV.dev matches them exactly.
const EXTENSION_RE = /^[a-z0-9][a-z0-9-]{0,99}\.[a-z0-9][a-z0-9._-]{0,99}$/i;
const NAME_RE = {
	npm: /^(?:@[A-Za-z0-9~][A-Za-z0-9._~-]{0,100}\/)?[A-Za-z0-9~][A-Za-z0-9._~-]{0,213}$/,
	PyPI: /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/,
	// Microsoft's marketplace, and Open VSX, which VSCodium, Cursor, Windsurf
	// and Kiro install from.
	VSCode: EXTENSION_RE,
	"VSCode:https://open-vsx.org": EXTENSION_RE,
};
const isExtension = (ecosystem) => ecosystem.startsWith("VSCode");
const ID_RE = /^[A-Z][A-Z0-9]{1,9}-[A-Za-z0-9._:-]{1,60}$/;
const VERSION_RE = /^v?\d{1,10}(?:\.\d{1,10}){1,3}(?:[-+][0-9A-Za-z.-]{1,40})?$/;
const MAX_QUERIES = 500;
const MAX_DETAILS = 150;
// Advisories the bundled list already counts for an agent install.
const COUNTED = new Set(Object.values(AGENT_ADVISORIES).flat().flatMap((a) => [a.id, a.cve]).filter(Boolean));

const queryKey = (q) => `${q.ecosystem}|${q.name}|${typeof q.version === "string" && VERSION_RE.test(q.version) ? q.version.replace(/^v/, "") : null}`;

// Queries whose every use is an agent install. The bundled list already
// counts those agents' advisories, so OSV.dev's copies aren't fetched. An
// agent package used another way, such as by an MCP server, is looked up in full.
export function installsOnly(result) {
	const all = new Map();
	for (const p of Array.isArray(result?.packages) ? result.packages : []) all.set(queryKey(p), (all.get(queryKey(p)) ?? true) && p.via === "install");
	return new Set([...all].filter(([, only]) => only).map(([key]) => key));
}

// The packages a result names, once each, as OSV queries.
export function lookupQueries(result) {
	const seen = new Set();
	const out = [];
	for (const p of Array.isArray(result?.packages) ? result.packages : []) {
		if (!Object.hasOwn(NAME_RE, p.ecosystem) || typeof p.name !== "string" || p.name.length > 214 || !NAME_RE[p.ecosystem].test(p.name)) continue;
		const version = typeof p.version === "string" && VERSION_RE.test(p.version) ? p.version.replace(/^v/, "") : null;
		const key = queryKey(p);
		if (seen.has(key)) continue;
		seen.add(key);
		out.push({ ecosystem: p.ecosystem, name: p.name, version });
		if (out.length >= MAX_QUERIES) break;
	}
	return out;
}

// Asks OSV about each query. Returns { hits, failed } where each hit names
// the query it answers.
export async function osvLookup(queries, { base = "https://api.osv.dev", timeoutMs = 20_000, fetchImpl = fetch, installs = new Set() } = {}) {
	const hits = [];
	let failed = 0;
	const post = async (batch) => {
		const res = await fetchImpl(`${base}/v1/querybatch`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ queries: batch.map((q) => ({ package: { name: q.name, ecosystem: q.ecosystem }, ...(q.version ? { version: q.version } : {}) })) }),
			signal: AbortSignal.timeout(timeoutMs),
		});
		if (!res.ok) throw new Error(`OSV.dev answered ${res.status}`);
		const json = await readJson(res, 8 * 1024 * 1024);
		if (!Array.isArray(json?.results) || json.results.length !== batch.length) throw new Error("OSV.dev's answer didn't match the question");
		return json.results.map((r) => (Array.isArray(r?.vulns) ? r.vulns.slice(0, 50).map((v) => v?.id).filter((id) => typeof id === "string" && ID_RE.test(id)) : []));
	};

	// Extensions go in their own request, so a problem with one kind of
	// package doesn't lose the answers for the others.
	const answers = new Map();
	for (const group of [queries.filter((q) => !isExtension(q.ecosystem)), queries.filter((q) => isExtension(q.ecosystem))]) {
		for (let i = 0; i < group.length; i += 250) {
			const batch = group.slice(i, i + 250);
			try {
				const ids = await post(batch);
				// What the bundled list already counted isn't fetched again.
				const counted = (q) => q.ecosystem === "npm" && Object.hasOwn(AGENT_ADVISORIES, q.name) && installs.has(queryKey(q));
				batch.forEach((q, k) => answers.set(q, counted(q) ? ids[k].filter((id) => !COUNTED.has(id)) : ids[k]));
			} catch {
				failed += batch.length;
			}
		}
	}

	// The details of each vulnerability, for its summary and fixed version.
	// Malware listings first: whether one applies can depend on them.
	const wanted = [...new Set([...answers.values()].flat())].sort((a, b) => b.startsWith("MAL-") - a.startsWith("MAL-")).slice(0, MAX_DETAILS);
	const details = new Map();
	for (let i = 0; i < wanted.length; i += 6) {
		await Promise.all(
			wanted.slice(i, i + 6).map(async (id) => {
				try {
					const res = await fetchImpl(`${base}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(timeoutMs) });
					if (res.ok) details.set(id, await readJson(res, 2 * 1024 * 1024));
				} catch {}
			}),
		);
	}

	for (const [q, ids] of answers) {
		for (const id of ids) {
			const record = details.get(id);
			if (record && record.id !== id) continue;
			// OSV.dev answers a question about Microsoft's marketplace with Open
			// VSX listings too, and the same ID there can be someone else's
			// extension, so a listing has to name the marketplace asked about.
			// Without the listing's details that can't be told, so a hit for an
			// extension from Microsoft's marketplace is left out.
			if (isExtension(q.ecosystem) && (record ? !affectedEntries(record, q).length : q.ecosystem === "VSCode")) continue;
			const malicious = id.startsWith("MAL-");
			hits.push({
				ecosystem: q.ecosystem,
				name: q.name,
				version: q.version,
				ref: preferredRef(id, record),
				malicious,
				severity: malicious ? "critical" : severityOf(record),
				summary: typeof record?.summary === "string" ? record.summary.slice(0, 300) : "",
				fixed: q.version && record ? fixedVersion(record, q) : null,
				// Whether the listing covers every version, or names some: a
				// package whose account was taken over has only those versions
				// listed. Unknown without its details.
				allVersions: record ? everyVersion(record, q) : null,
				// Without its details, whether there's a fix isn't known.
				detailed: Boolean(record),
			});
		}
	}
	return { hits, failed, asked: queries.length };
}

// A response body as JSON, read only up to `max` bytes.
async function readJson(res, max) {
	const reader = res.body?.getReader();
	if (!reader) return null;
	const parts = [];
	let size = 0;
	for (let part = await reader.read(); !part.done; part = await reader.read()) {
		size += part.value.byteLength;
		if (size > max) {
			// Not awaited: stopping the download shouldn't wait on the server.
			reader.cancel().catch(() => {});
			throw new Error("OSV.dev's answer was too large");
		}
		parts.push(part.value);
	}
	return JSON.parse(Buffer.concat(parts).toString("utf8"));
}

// The CVE when there is one, since that's the name people search for.
function preferredRef(id, record) {
	const cve = Array.isArray(record?.aliases) ? record.aliases.find((a) => typeof a === "string" && /^CVE-\d{4}-\d{4,7}$/.test(a)) : null;
	return id.startsWith("MAL-") ? id : (cve ?? id);
}

// GitHub's advisories give a severity word; others are treated as medium.
function severityOf(record) {
	const word = typeof record?.database_specific?.severity === "string" ? record.database_specific.severity.toUpperCase() : "";
	return word === "CRITICAL" || word === "HIGH" ? "high" : word === "LOW" ? "low" : "medium";
}

// Whether two names are the same package. PyPI treats -, _ and . alike, and
// case doesn't matter; npm names are exact, apart from case in old packages.
function sameName(a, b, ecosystem) {
	const norm = (n) => (ecosystem === "PyPI" ? n.toLowerCase().replace(/[-_.]+/g, "-") : n.toLowerCase());
	return norm(a) === norm(b);
}

// The parts of a listing about the package asked about.
function affectedEntries(record, q) {
	return (Array.isArray(record?.affected) ? record.affected.slice(0, 50) : []).filter((a) => a?.package?.ecosystem === q.ecosystem && sameName(String(a.package.name), q.name, q.ecosystem));
}

// True when a listing covers every version: a range from the first version
// with no fix.
function everyVersion(record, q) {
	return affectedEntries(record, q).some((a) =>
		(Array.isArray(a.ranges) ? a.ranges.slice(0, 20) : []).some((r) => {
			const events = Array.isArray(r?.events) ? r.events.slice(0, 100) : [];
			return events.some((e) => e?.introduced === "0") && !events.some((e) => e?.fixed !== undefined || e?.last_affected !== undefined);
		}),
	);
}

// The first version that fixes the range the queried version is in.
function fixedVersion(record, q) {
	for (const affected of affectedEntries(record, q)) {
		for (const range of Array.isArray(affected.ranges) ? affected.ranges.slice(0, 20) : []) {
			if (range?.type !== "SEMVER" && range?.type !== "ECOSYSTEM") continue;
			let introduced = null;
			for (const event of Array.isArray(range.events) ? range.events.slice(0, 100) : []) {
				if (typeof event?.introduced === "string") introduced = event.introduced === "0" ? "0.0.0" : event.introduced;
				const fixed = typeof event?.fixed === "string" ? event.fixed : null;
				if (introduced && fixed && VERSION_RE.test(fixed) && VERSION_RE.test(introduced) && compareVersions(q.version, introduced) >= 0 && compareVersions(q.version, fixed) < 0) return fixed;
			}
		}
	}
	return null;
}
