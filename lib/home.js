// The home folder, and how two paths on this computer are compared.
//
// A folder can have two names: the one it's given and the one the disk gives
// it. On macOS temporary folders live in /private/var behind the /var link,
// on FreeBSD /home is a link to /usr/home, and on Windows a short name such
// as RUNNER~1 stands for a longer one. Paths that come from the environment,
// such as NPM_CONFIG_PREFIX, use the name $HOME has, and the current folder
// and anything resolved use the disk's. `within` takes both names as the one
// folder, so "is this in the home folder" has one answer.

import { realpathSync } from "node:fs";
import { realpath } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// Windows and macOS ignore case in file names by default.
const FOLD = process.platform === "win32" || process.platform === "darwin";

// The home folder by the name the environment gives it, or null.
let cached;
export function homeFolder() {
	if (cached !== undefined) return cached;
	try {
		cached = os.homedir() ? path.resolve(os.homedir()) : null;
	} catch {
		cached = null;
	}
	return cached;
}

// A folder as the disk names it, or as given when it can't be resolved.
export async function realFolder(dir) {
	const abs = path.resolve(dir);
	return realpath(abs).catch(() => abs);
}

// A path made absolute, without a separator at the end except a root's own,
// as in "/" and "C:\".
const plain = (p) => {
	const abs = path.resolve(p);
	return abs.length > path.parse(abs).root.length ? abs.replace(/[\\/]+$/, "") : abs;
};
const fold = (p) => (FOLD ? p.toLowerCase() : p);

export function samePath(a, b) {
	return fold(plain(a)) === fold(plain(b));
}

// The part of child below parent, with / between names, or null when child
// isn't inside parent. A folder named "..config" is inside.
export function below(child, parent) {
	const c = plain(child);
	const p = plain(parent);
	const base = p.endsWith(path.sep) ? p : p + path.sep;
	if (c.length <= base.length || fold(c.slice(0, base.length)) !== fold(base)) return null;
	return c.slice(base.length).split(path.sep).join("/");
}

// A folder's names: the one given, then the disk's when it differs. Looked
// up once for each folder.
const names = new Map();
function namesOf(folder) {
	const given = plain(folder);
	let list = names.get(given);
	if (!list) {
		let real = null;
		try {
			real = realpathSync.native(given);
		} catch {
			// Not there, or not readable: the name given is the only one.
		}
		list = real && !samePath(real, given) ? [given, real] : [given];
		names.set(given, list);
	}
	return list;
}

// Where a path is in a folder, by either of the folder's names: "" for the
// folder itself, the part below it with / between names, or null when the
// path isn't in it.
export function within(child, folder) {
	for (const name of namesOf(folder)) {
		if (samePath(child, name)) return "";
		const rel = below(child, name);
		if (rel !== null) return rel;
	}
	return null;
}
