import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

// Each run owns a new sample home. Nothing in the fixture is executed, and
// the caller uses the normal scanner, review transactions and report writers.
export async function withDemo(run) {
	const home = await mkdtemp(path.join(tmpdir(), "misconfig-demo-"));
	const file = path.join(home, ".claude.json"), session = path.join(home, "sample-codex.jsonl");
	const config = (version) => JSON.stringify({
		mcpServers: {
			calendar: { command: "npx", args: ["-y", "@example/calendar@" + version] },
			mail: { command: "npx", args: ["-y", "@example/mail"] },
		},
	});
	try {
		await writeFile(file, config("1.2.3") + "\n", { mode: 0o600 });
		return await run({
			discovery: { dir: home, home, env: {}, sampleFiles: ["~/.claude.json"] },
			store: path.join(home, ".misconfig", "computer-v1"),
			session,
			bump: async () => {
				await writeFile(file, config("1.2.4") + "\n");
				const diff = "@@ -1 +1 @@\n-" + config("1.2.3") + "\n+" + config("1.2.4") + "\n";
				const payload = { type: "patch_apply_end", call_id: "demo", success: true, status: "completed", changes: { [file]: { type: "update", unified_diff: diff, move_path: null } } };
				await writeFile(session, JSON.stringify({ timestamp: new Date().toISOString(), type: "event_msg", payload }) + "\n", { mode: 0o600 });
			},
		});
	} finally {
		await rm(home, { recursive: true, force: true });
	}
}
