// Secret masking. Likely secrets are replaced with «masked:<kind>:<length>» as
// files are read, before any check runs, so they never appear in results.
// Line breaks are kept, so line numbers still match the original file.
//
// Every pattern here runs on untrusted files, so each one is written to take
// time in proportion to the text: no nested or adjacent open-ended repeats.

const MARK_OPEN = "«masked:";

const KEY_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/g;
const KEY_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----/y;

// Patterns with a leading group keep that character: it stops a match from
// starting in the middle of a longer token.
const TOKEN_PATTERNS = [
	["anthropic-key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
	["openai-key", /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g],
	["github-token", /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/g],
	["aws-key-id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
	["slack-token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
	["google-key", /\bAIza[0-9A-Za-z_-]{35}/g],
	["stripe-key", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g],
	["xai-key", /\bxai-[A-Za-z0-9]{20,}/g],
	["groq-key", /\bgsk_[A-Za-z0-9]{20,}/g],
	["huggingface-token", /\bhf_[A-Za-z0-9]{30,}/g],
	["npm-token", /\bnpm_[A-Za-z0-9]{36}\b/g],
	["jwt", /(^|[^A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g],
];

// key = value, "key": "value", KEY=value, --api-key value ...
const ASSIGNMENT =
	/((?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|token|secret|password|passwd|pwd|private[_-]?key)["']?(?:\s*[:=]\s*|\s+)["']?)([^\s"'`,;{}()<>[\]«»]{12,})/gi;
const BEARER = /(\bBearer\s+)([A-Za-z0-9._~+/=-]{16,})/g;
// The user name can be empty, as in redis://:password@host.
const URL_PASSWORD = /(\b[a-z][a-z0-9+.-]{0,30}:\/\/[^\s/:@"']{0,64}:)([^\s/@"']{6,})(?=@)/gi;
// Passwords are often short and plain, so a value named as one is masked from
// six characters: --password value, password: value, "DB_PASSWORD": "value".
const PASSWORD = /((?:--?(?:password|passwd|passphrase)[ \t]+|(?:password|passwd|passphrase)["']?[ \t]*[:=][ \t]*)["']?)([^\s"'`,;{}()<>[\]«»]{6,})/gi;
const URL_TOKEN = /([?&](?:token|key|api[_-]?key|apikey|access[_-]?token|auth|secret|sig|signature|password)=)([^&#\s"']{8,})/gi;

const PLACEHOLDER =
	/^(?:\$|%|<|\{|\[)|\$\{|\{\{|your[_-]?|example|placeholder|changeme|change[_-]?me|redacted|dummy|sample|test[_-]?key|x{4,}|\*{3,}|\.{3}|^(?:true|false|null|none|undefined)$|^process\.env|^env[.:]/i;

export function isMasked(value) {
	return typeof value === "string" && value.includes(MARK_OPEN);
}

export function marker(kind, length) {
	return `«masked:${kind}:${length}»`;
}

export function entropy(value) {
	const counts = new Map();
	for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
	let bits = 0;
	for (const n of counts.values()) {
		const p = n / value.length;
		bits -= p * Math.log2(p);
	}
	return bits;
}

// True when a value looks like a real credential rather than a reference
// such as ${GITHUB_TOKEN}, {env:KEY} or "your-key-here".
export function looksLikeSecret(value) {
	if (typeof value !== "string") return false;
	const v = value.trim();
	if (isMasked(v)) return true;
	if (v.length < 12 || PLACEHOLDER.test(v)) return false;
	if (hasToken(v)) return true;
	const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(v)).length;
	return v.length >= 16 && classes >= 2 && entropy(v) >= 3.3 && !/\s/.test(v);
}

// File paths and path lists, such as C:\Users\sam\AppData\..., /usr/lib/node,
// ~/.config/app or %APPDATA%\app. A path can point at a secret, but it isn't one.
export function isPathLike(value) {
	const first = String(value).trim().split(";")[0];
	return /^(?:[A-Za-z]:[\\/]|\\\\|\/(?!\/)[^/\s]*\/|~[\\/]|\.{1,2}[\\/]|%[A-Za-z_][A-Za-z0-9_]*%[\\/]?|\$(?:HOME|\{HOME\})[\\/])/.test(first);
}

// Stricter, for strings with no key name to go on, such as command arguments.
// Random tokens mix letters and digits; names like GITHUB_TOKEN, flags like
// --dangerously-skip-permissions and package names are made of words and
// version numbers.
const WORDY = /^(?:[A-Za-z]+[0-9]{0,2}|[0-9]{1,4})$/;
export function looksLikeToken(value) {
	if (typeof value !== "string") return false;
	const v = value.trim();
	if (isMasked(v) || hasToken(v)) return true;
	if (!/[0-9]/.test(v) || !/[A-Za-z]/.test(v) || isPathLike(v)) return false;
	// Names and versions, as in mcp-server-fetch==2025.4.7 or tool[cli]>=1.2.
	if (v.split(/[-_.:@+=<>!~,[\]]/).every((part) => !part || WORDY.test(part))) return false;
	return looksLikeSecret(v);
}

function hasToken(v) {
	KEY_BEGIN.lastIndex = 0;
	if (KEY_BEGIN.test(v)) return true;
	for (const [, re] of TOKEN_PATTERNS) {
		re.lastIndex = 0;
		if (re.test(v)) return true;
	}
	return false;
}

// Private key blocks as [start, end] spans. Found with indexOf, so a file full
// of BEGIN lines without an END can't slow the check down.
function privateKeySpans(text) {
	const spans = [];
	KEY_BEGIN.lastIndex = 0;
	for (let m = KEY_BEGIN.exec(text); m; m = KEY_BEGIN.exec(text)) {
		let at = m.index + m[0].length;
		let end = -1;
		for (let i = text.indexOf("-----END ", at); i >= 0; i = text.indexOf("-----END ", at)) {
			KEY_END.lastIndex = i;
			const e = KEY_END.exec(text);
			if (e) {
				end = i + e[0].length;
				break;
			}
			at = i + 9;
		}
		if (end < 0) break;
		spans.push([m.index, end]);
		KEY_BEGIN.lastIndex = end;
	}
	return spans;
}

export function maskSecrets(text) {
	let count = 0;
	const kinds = {};
	const note = (kind) => {
		count++;
		kinds[kind] = (kinds[kind] || 0) + 1;
	};
	const hide = (kind, match) => {
		note(kind);
		const newlines = (match.match(/\n/g) || []).length;
		return marker(kind, match.length) + "\n".repeat(newlines);
	};

	let out = String(text);
	const spans = privateKeySpans(out);
	if (spans.length) {
		let rebuilt = "";
		let last = 0;
		for (const [start, end] of spans) {
			rebuilt += out.slice(last, start) + hide("private-key", out.slice(start, end));
			last = end;
		}
		out = rebuilt + out.slice(last);
	}
	for (const [kind, re] of TOKEN_PATTERNS) {
		out = out.replace(re, (match, ...groups) => {
			if (typeof groups[0] !== "string") return hide(kind, match);
			const [lead, token] = groups;
			return lead + hide(kind, token);
		});
	}
	const keepPrefix = (kind) => (match, prefix, value) => {
		if (isMasked(value) || PLACEHOLDER.test(value)) return match;
		if (kind === "assigned-secret" && (!looksLikeSecret(value) || isPathLike(value))) return match;
		note(kind);
		return prefix + marker(kind, value.length);
	};
	out = out.replace(URL_PASSWORD, keepPrefix("url-password"));
	out = out.replace(PASSWORD, keepPrefix("password"));
	out = out.replace(URL_TOKEN, keepPrefix("url-token"));
	out = out.replace(BEARER, keepPrefix("bearer-token"));
	out = out.replace(ASSIGNMENT, keepPrefix("assigned-secret"));
	return { text: out, count, kinds };
}

// "«masked:openai-key:51»" -> "•••• (openai key, 51 chars)"
export function describeMasks(text) {
	return String(text).replace(/«masked:([a-z0-9-]+):(\d+)»/g, (_, kind, len) => `•••• (${kind.replace(/-/g, " ")}, ${len} chars)`);
}
