// Turns file bytes into text. Editors and PowerShell save agent files as
// UTF-8, with or without a byte order mark, or as UTF-16. A file with many
// zero bytes in it is binary: decodeText returns null and it isn't read. A
// few stray zero bytes don't make a file binary, so they can't hide one from
// the checks while an agent still reads it as text.

const utf8 = (bytes) => new TextDecoder("utf-8").decode(bytes);
const utf16le = (bytes) => new TextDecoder("utf-16le").decode(bytes);
const utf16be = (bytes) => {
	const swapped = new Uint8Array(bytes.length - (bytes.length % 2));
	for (let i = 0; i < swapped.length; i += 2) {
		swapped[i] = bytes[i + 1];
		swapped[i + 1] = bytes[i];
	}
	return utf16le(swapped);
};

export function decodeText(input) {
	const b = input instanceof Uint8Array ? input : new Uint8Array(input);
	if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return utf8(b.subarray(3));
	if (b[0] === 0xff && b[1] === 0xfe) return utf16le(b.subarray(2));
	if (b[0] === 0xfe && b[1] === 0xff) return utf16be(b.subarray(2));
	// Without a byte order mark, UTF-16 text in a Latin script has a zero in
	// every other byte.
	const sample = b.subarray(0, 4096);
	let even = 0;
	let odd = 0;
	for (let i = 0; i < sample.length; i++) if (sample[i] === 0) i % 2 ? odd++ : even++;
	if (!even && !odd) return utf8(b);
	const pairs = sample.length / 2;
	if (!even && odd > pairs * 0.9) return utf16le(b);
	if (!odd && even > pairs * 0.9) return utf16be(b);
	// Stray zero bytes in otherwise clean UTF-8 text. Real binary files have
	// other control bytes too, or bytes that aren't UTF-8.
	for (const x of sample) if ((x > 0 && x < 9) || (x > 13 && x < 32 && x !== 27)) return null;
	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(b);
	} catch {
		return null;
	}
}
