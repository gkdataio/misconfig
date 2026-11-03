#!/usr/bin/env node
import { main } from "../lib/main.js";
import { oneLine } from "../lib/print.js";

// Older versions of Node print a warning that fetch is experimental the first
// time the command downloads today's malware list or --lookup asks OSV.dev.
// Other warnings still print.
const warn = process.emitWarning;
process.emitWarning = function (warning, ...rest) {
	const type = typeof rest[0] === "string" ? rest[0] : rest[0]?.type;
	if (type === "ExperimentalWarning" && /\bfetch\b/i.test(String(warning?.message ?? warning))) return;
	return warn.call(this, warning, ...rest);
};

// Output piped into something that stops reading, such as head, isn't an error.
for (const stream of [process.stdout, process.stderr]) {
	stream.on("error", (err) => {
		if (err?.code !== "EPIPE") throw err;
		process.exit(process.exitCode ?? 0);
	});
}

main(process.argv.slice(2)).then(
	(code) => {
		process.exitCode = code;
	},
	(err) => {
		// Ctrl+C at a question: nothing was sent, and the shell hears it was
		// interrupted.
		if (err?.code === "ABORT_ERR") {
			console.error("\nmisconfig: Stopped. Nothing was sent.");
			process.exitCode = 130;
			return;
		}
		// Messages can quote a path or a reply from the server, so control
		// codes in them are shown, not run.
		console.error(`misconfig: ${oneLine(err?.message ?? err)}`);
		process.exitCode = 2;
	},
);
