import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

// Each run owns a new sample home. Nothing in the fixture is executed, and
// the caller uses the normal scanner, review transactions and report writers.
export async function withDemo(run) {
	const home = await mkdtemp(path.join(tmpdir(), "misconfig-demo-"));
	const setCalendar = (version) => writeFile(path.join(home, ".claude.json"), JSON.stringify({
		mcpServers: {
			calendar: { command: "npx", args: ["-y", "@example/calendar@" + version] },
			mail: { command: "npx", args: ["-y", "@example/mail"] },
		},
	}), { mode: 0o600 });
	try {
		await setCalendar("1.2.3");
		return await run({
			discovery: { dir: home, home, env: {}, sampleFiles: ["~/.claude.json"] },
			store: path.join(home, ".misconfig", "computer-v1"),
			bump: () => setCalendar("1.2.4"),
		});
	} finally {
		await rm(home, { recursive: true, force: true });
	}
}
