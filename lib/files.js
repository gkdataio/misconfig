// Reading and writing files with care, for the commands that change
// something on this computer: --fix and --undo.
//
// A file to change may be someone else's, or may have been swapped for a
// link since it was checked. So a file is read only if it's a regular file,
// never through a link, and only up to a size, and it's replaced in one step
// from a new file written beside it, never written over in place.

import { constants } from "node:fs";
import { randomBytes } from "node:crypto";
import { lstat, mkdir, open, rename, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { homeFolder, within } from "./home.js";

// What went wrong, in a sentence that can be shown as it is.
export class FileError extends Error {}

// The file's place in words: ~ for the home folder.
export function shown(path) {
	const home = homeFolder();
	const rel = home ? within(path, home) : null;
	return rel === null ? path : rel ? `~/${rel}` : "~";
}

// A file someone else may have written, read as untrusted input: a regular
// file only, opened without following a link and without waiting on a pipe,
// checked again once open in case it was swapped, and read only up to a
// size. Null when there's no file. With `bytes`, the file's bytes and mode.
export async function readUntrusted(path, limit, what, { bytes = false } = {}) {
	const name = shown(path);
	let info;
	try {
		info = await lstat(path);
	} catch (error) {
		if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
		throw error;
	}
	if (!info.isFile()) throw new FileError(`${name} isn't a regular file, so misconfig won't read it.`);
	const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)).catch(() => {
		throw new FileError(`${name} couldn't be opened.`);
	});
	try {
		const stat = await handle.stat();
		if (!stat.isFile()) throw new FileError(`${name} isn't a regular file, so misconfig won't read it.`);
		if (stat.size > limit) throw new FileError(`${name} is larger than ${Math.round(limit / 1024 / 1024)} MB, more than ${what} can be.`);
		const buffer = Buffer.alloc(Math.min(stat.size, limit));
		const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
		return bytes ? { buffer: buffer.subarray(0, bytesRead), mode: stat.mode } : buffer.subarray(0, bytesRead).toString("utf8");
	} finally {
		await handle.close();
	}
}

// A folder of misconfig's own in the home folder, readable only by this user.
export async function makeFolder(dir, outcome) {
	await mkdir(dir, { recursive: true, mode: 0o700 }).catch((error) => {
		throw new FileError(`${shown(dir)} couldn't be made (${error.code ?? "error"}), so ${outcome}.`);
	});
}

// Writes text or bytes next to a file, to replace it with in one step: never
// over anything but a regular file, under a name no one else would use, made
// with "wx" so it's never someone else's file, and removed if the write
// doesn't finish. Returns the new file's path.
export async function stageText(path, data, mode, outcome) {
	try {
		const info = await lstat(path);
		if (!info.isFile()) throw new FileError(`${shown(path)} isn't a regular file, so misconfig won't write over it.`);
	} catch (error) {
		if (error.code !== "ENOENT") throw error;
	}
	const temp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
	const handle = await open(temp, "wx", mode).catch((error) => {
		throw new FileError(`${shown(path)} couldn't be written (${error.code ?? "error"}), so ${outcome}.`);
	});
	try {
		await handle.writeFile(data, "utf8");
		await handle.sync();
	} catch (error) {
		await handle.close().catch(() => {});
		await rm(temp, { force: true }).catch(() => {});
		throw error;
	}
	await handle.close();
	return temp;
}

// Puts the new file in the old one's place. On Windows a virus scanner, the
// search indexer or a sync app can hold a file for a moment, and replacing
// it fails until they let go.
export async function moveInto(temp, path) {
	for (let attempt = 0; ; attempt++) {
		try {
			return await rename(temp, path);
		} catch (error) {
			if (process.platform !== "win32" || !["EPERM", "EACCES", "EBUSY"].includes(error.code) || attempt >= 8) throw error;
			await new Promise((done) => setTimeout(done, Math.min(25 * 2 ** attempt, 500)));
		}
	}
}
