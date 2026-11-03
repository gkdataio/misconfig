// What misconfig knows to be malicious, or to be missing security fixes,
// from public reports. It ships with each release and is checked on the
// computer, with no network requests. Add --lookup to also ask OSV.dev, which
// is updated every day. Every entry names its source, and only facts the
// source states are used.
//
// Shared and private reports repeat these words, and misconfig.ai accepts
// only words this file gives. When the wording of a fact changes after a
// release, keep the old wording in the entry's `was` (for example
// was: { what: ["..."] }), so reports made by earlier versions still open.

// The day the OSV.dev listings below were taken. misconfig.ai publishes the
// ones listed since (see addKnownMalware).
export const KNOWN_AS_OF = "2026-11-02";

// MCP packages OSV.dev lists as malware (IDs starting MAL-), as of
// KNOWN_AS_OF, with the versions each listing names, or "all". A package with a
// few versions listed is often a real one whose publishing account was taken
// over, so only those versions count against it.
const OSV_MALWARE = [
	["npm", "@ifasn/md-doc-mcp", "MAL-2026-18486", "1.0.3 1.0.4 1.0.5"],
	["npm", "@ifasn/mmd-doc-mcp", "MAL-2026-18488", "1.0.0 1.0.2"],
	["npm", "@ifasn/mmdd-doc-mcp", "MAL-2026-18489", "1.0.1 1.0.3 1.0.4 1.0.4-2 1.0.5 1.0.6 1.1.0 1.1.1 1.1.2 1.1.3 1.1.5 1.1.6 1.1.7 1.1.8 1.1.9-2 2.0.1 2.0.4"],
	["npm", "@ifasn/mdd-doc-mcp", "MAL-2026-18487", "1.0.7 1.0.8 2.0.6"],
	["npm", "mcp-consultasdeveiculos-client", "MAL-2026-15869", "0.0.2 0.1.0 0.1.1"],
	["npm", "feishu-docx-mcp", "MAL-2026-16032", "all"],
	["npm", "@yongot/canary-mcp-isolation", "MAL-2026-16061", "1.0.0 1.0.1 1.0.2"],
	["npm", "@yongot/canary-mcp-test", "MAL-2026-16062", "1.0.0 2.0.0 3.0.0 4.0.0"],
	["npm", "mcp-real-chrome", "MAL-2026-14414", "all"],
	["npm", "homekit-mcp", "MAL-2026-14297", "1.0.0"],
	["npm", "code-assist-mcp", "MAL-2026-14233", "1.0.0"],
	["npm", "@httttt/mcp-demo", "MAL-2026-14315", "all"],
	["npm", "chrome-enterprise-premium-mcp", "MAL-2026-14230", "1.0.0"],
	["npm", "mcp-dev-toolkit", "MAL-2026-14295", "1.5.0"],
	["npm", "broadcast-graphics-mcp", "MAL-2026-14228", "1.0.0"],
	["npm", "fa-mcp-sdk", "MAL-2026-12789", "0.12.72"],
	["npm", "devplatform-react-mcp", "MAL-2026-13502", "35.5.6"],
	["npm", "agenthub-multiagent-mcp", "MAL-2026-13399", "1.57.0"],
	["npm", "xrblocks-mcp", "MAL-2026-13988", "6.3.1"],
	["npm", "mcp-util-helpers", "MAL-2026-13880", "1.0.0"],
	["npm", "@kolbo/mcp", "MAL-2026-13938", "1.57.1"],
	["npm", "mcp-audit-sync-internal", "MAL-2026-12401", "99.9.9"],
	["npm", "@or-sdk/mcp-tools", "MAL-2026-11713", "0.5.2 0.5.3 0.5.4"],
	["npm", "@servicetitan/anvil2-mcp", "MAL-2026-11829", "0.0.9 0.0.10 0.0.11 0.0.12 0.0.13 0.0.14 0.0.15"],
	["npm", "hit-mcp", "MAL-2026-11466", "1.0.0"],
	["npm", "@copilot-mcp/apex", "MAL-2026-12314", "1.0.0 1.0.1 1.0.2 1.0.3 1.0.4 1.0.5 1.0.6 1.0.7 1.0.8 1.0.16 1.0.17 1.0.21 1.0.22"],
	["npm", "code-analyzer-mcp", "MAL-2026-12354", "1.0.0"],
	["npm", "iwomm-mcp", "MAL-2026-11469", "1.0.0"],
	["npm", "sap-mcp-facilitator", "MAL-2026-11482", "1.0.0"],
	["npm", "mcp-server-boilerplate", "MAL-2026-11472", "1.0.0"],
	["npm", "gtm-mcp-auth", "MAL-2026-11464", "1.0.0"],
	["npm", "refbase-mcp", "MAL-2026-11477", "1.0.0"],
	["npm", "chaos-mcp", "MAL-2026-11458", "1.0.0"],
	["npm", "maximumsats-mcp", "MAL-2026-11471", "1.0.0"],
	["npm", "kip-mcp-http", "MAL-2026-11470", "1.0.0"],
	["npm", "pm-claude-skills-mcp", "MAL-2026-11475", "1.0.0"],
	["npm", "smart-npv-mcp", "MAL-2026-11486", "1.0.0"],
	["npm", "routerbase-mcp", "MAL-2026-11480", "1.0.0"],
	["npm", "sap-mcp-config", "MAL-2026-11481", "1.0.0"],
	["npm", "@vite-mcp/vite-type", "MAL-2026-10525", "all"],
	["npm", "proxy-seller-mcp", "MAL-2026-10541", "0.1.7"],
	["npm", "sensorium-mcp", "MAL-2026-10747", "3.0.95"],
	["npm", "mcp-notes-server-poc-praetorian", "MAL-2026-10210", "all"],
	["npm", "sidecar-mcp", "MAL-2026-10161", "all"],
	["npm", "polymarket-mcp-v2", "MAL-2026-10481", "all"],
	["npm", "mcp-ci-runner-poc", "MAL-2026-7318", "1.0.0"],
	["npm", "cue-mcp", "MAL-2026-6294", "9999.99.99"],
	["npm", "zomato-mcp", "MAL-2026-6270", "1.0.0"],
	["npm", "@mastra/mcp-docs-server", "MAL-2026-5956", "1.1.47"],
	["npm", "@mastra/mcp-registry-registry", "MAL-2026-6027", "1.0.2"],
	["npm", "@mastra/mcp", "MAL-2026-5955", "1.10.1"],
	["npm", "mcp-server-pg", "MAL-2026-6922", "all"],
	["npm", "sp-api-dev-assistant-mcp-server", "MAL-2026-5853", "all"],
	["npm", "claude-token-tracker-mcp", "MAL-2026-10693", "all"],
	["npm", "mcp-server-git", "MAL-2026-5478", "all"],
	["npm", "mcp-server-fetch", "MAL-2026-5476", "all"],
	["npm", "mcp-server-postgres", "MAL-2026-5481", "all"],
	["npm", "mcp-server-redis", "MAL-2026-5482", "all"],
	["npm", "mcp-server-sequential-thinking", "MAL-2026-5484", "all"],
	["npm", "mcp-server-figma", "MAL-2026-5477", "all"],
	["npm", "mcp-server-notion", "MAL-2026-5480", "all"],
	["npm", "mcp-server-sentry", "MAL-2026-5483", "all"],
	["npm", "mcp-server-supabase", "MAL-2026-5485", "all"],
	["npm", "screenpipe-mcp-http", "MAL-2026-5402", "9999.99.99"],
	["npm", "create-docs-mcp", "MAL-2026-5397", "9999.99.99"],
	["npm", "t-invest-mcp-server", "MAL-2026-5403", "9999.99.99"],
	["npm", "autotel-mcp", "MAL-2026-5223", "0.1.14 2.0.1 3.0.1 4.0.1 5.0.1 6.0.1 7.0.1 8.0.1 9.0.1 10.0.1 11.0.1 13.0.1 14.0.1 15.0.2 16.0.1 17.0.2 18.0.1 19.0.1 20.0.1 21.1.1 22.0.1 23.0.1 24.0.1 25.0.1 26.0.2 27.0.1 28.0.3 29.0.1"],
	["npm", "autotel-mcp-instrumentation", "MAL-2026-5224", "29.0.2 30.0.5 31.0.1 32.0.1 33.0.2 34.0.1"],
	["npm", "executable-stories-mcp", "MAL-2026-5255", "0.3.3"],
	["npm", "brave-search-mcp-server", "MAL-2026-5182", "1.0.0"],
	["npm", "@redhat-cloud-services/hcc-feo-mcp", "MAL-2026-5129", "0.3.1 0.3.2 0.3.4"],
	["npm", "@redhat-cloud-services/hcc-kessel-mcp", "MAL-2026-5139", "0.3.1 0.3.2 0.3.4"],
	["npm", "@redhat-cloud-services/hcc-pf-mcp", "MAL-2026-5140", "0.6.1 0.6.2 0.6.4"],
	["npm", "@cloudplatform-single-spa/ml-ai-agents-mcp-server", "MAL-2026-4938", "all"],
	["npm", "explorhub-mcp-server", "MAL-2026-4312", "all"],
	["npm", "mcp-dashboards-shared", "MAL-2026-4296", "all"],
	["npm", "@djessicatony/folk-mcp-canary", "MAL-2026-4382", "0.0.1"],
	["npm", "bitrix24-tasks-mcp-server", "MAL-2026-4498", "1.1.0 1.2.0 1.4.0 1.5.0 1.5.1"],
	["npm", "bricks-builder-mcp", "MAL-2026-4500", "3.6.1 3.10.0 3.11.2 3.12.3"],
	["npm", "@antv/mcp-server-antv", "MAL-2026-4068", "0.2.8 0.3.8"],
	["npm", "@antv/mcp-server-chart", "MAL-2026-4069", "0.10.10 0.11.10"],
	["npm", "mcp-echarts", "MAL-2026-4146", "0.8.1 0.9.1"],
	["npm", "mcp-mermaid", "MAL-2026-4147", "0.5.1 0.6.1"],
	["npm", "nextmove-mcp", "MAL-2026-3589", "0.1.3 0.1.4 0.1.5 0.1.6 0.1.7"],
	["npm", "cmux-agent-mcp", "MAL-2026-3588", "0.1.3 0.1.4 0.1.5 0.1.6 0.1.7 0.1.8"],
	["npm", "@squawk/mcp", "MAL-2026-3448", "0.9.1 0.9.2 0.9.3 0.9.4 0.9.5"],
	["npm", "pi-exa-mcp", "MAL-2026-3280", "all"],
	["npm", "claudcode-mcp", "MAL-2026-2974", "all"],
	["npm", "mcp-server-todo", "MAL-2026-2328", "all"],
	["npm", "@iflow-mcp/watercrawl-watercrawl-mcp", "MAL-2026-1930", "1.3.0 1.3.1 1.3.2 1.3.3 1.3.4"],
	["npm", "@upstashed/context7-mcp", "MAL-2026-1642", "1.0.2"],
	["npm", "excluder-mcp", "MAL-2025-192746", "all"],
	["npm", "excluder-mcp-package", "MAL-2025-192747", "all"],
	["npm", "vscode-azure-mcp-server", "MAL-2025-192601", "all"],
	["npm", "solana-dev-mcp", "MAL-2025-191527", "all"],
	["npm", "mcp-polymarket", "MAL-2025-191465", "all"],
	["npm", "@browserbasehq/mcp-server-browserbase", "MAL-2025-191196", "2.4.2"],
	["npm", "@browserbasehq/mcp", "MAL-2025-191195", "all"],
	["npm", "@seezo/sdr-mcp-server", "MAL-2025-191053", "0.0.5"],
	["npm", "@relyt/mcp-server-relytone", "MAL-2025-191052", "all"],
	["npm", "@relyt/claude-context-mcp", "MAL-2025-191051", "all"],
	["npm", "ids-enterprise-mcp-server", "MAL-2025-191107", "0.0.2"],
	["npm", "web-scraper-mcp", "MAL-2025-190943", "1.1.4"],
	["npm", "@mcp-use/cli", "MAL-2025-190867", "2.2.6 2.2.7"],
	["npm", "@mcp-use/inspector", "MAL-2025-190868", "0.6.2 0.6.3"],
	["npm", "@mcp-use/mcp-use", "MAL-2025-190869", "1.0.1 1.0.2"],
	["npm", "@postman/mcp-ui-client", "MAL-2025-190902", "5.5.1 5.5.2 5.5.3"],
	["npm", "@postman/postman-mcp-cli", "MAL-2025-190908", "1.0.3 1.0.4 1.0.5"],
	["npm", "@postman/postman-mcp-server", "MAL-2025-190909", "2.4.10 2.4.11 2.4.12"],
	["npm", "@zapier/mcp-integration", "MAL-2025-190918", "3.0.1 3.0.2 3.0.3"],
	["npm", "create-mcp-use-app", "MAL-2025-190922", "0.5.3 0.5.4"],
	["npm", "mcp-use", "MAL-2025-190923", "1.4.2 1.4.3"],
	["npm", "lite-serper-mcp-server", "MAL-2025-190848", "all"],
	["npm", "rce-poc-test-honor-mcp", "MAL-2025-49383", "all"],
	["npm", "revenuecat-mcp-extension", "MAL-2025-49378", "all"],
	["npm", "demo-mercadopago-mcp-server", "MAL-2025-48558", "99.0.0 99.0.1 99.0.2 99.0.3 99.0.4 99.0.5"],
	["npm", "shiprocket-mcp", "MAL-2025-48761", "all"],
	["npm", "mcp-server-fixthis", "MAL-2025-47929", "all"],
	["npm", "mcp-knowledge-graph", "MAL-2025-47327", "1.2.1"],
	["npm", "mcp-knowledge-base", "MAL-2025-47326", "all"],
	["npm", "mcp-lumin", "MAL-2025-47076", "all"],
	["npm", "mcp-chat-client", "MAL-2025-47098", "all"],
	["npm", "mcp-server-everything", "MAL-2025-46986", "all"],
	["npm", "wealthsimple-mcp-server", "MAL-2025-42116", "all"],
	["npm", "auth0-mcp-server", "MAL-2025-15093", "all"],
	["npm", "mcp-menu", "MAL-2025-26053", "all"],
	["npm", "mcp-opencage-server", "MAL-2025-26054", "all"],
	["npm", "@jaswanthlanka/mcp-proxy", "MAL-2025-6139", "all"],
	["npm", "glean-mcp-server", "MAL-2025-5813", "all"],
	["npm", "rush-mcp-example-plugin", "MAL-2025-5286", "all"],
	["npm", "yaml-mcp-wrapper", "MAL-2025-4635", "all"],
	["PyPI", "marketing-mcp", "MAL-2026-16250", "0.1.0"],
	["PyPI", "mcp-search-server", "MAL-2026-11198", "1.0.0 2.0.0 2.0.1"],
	["PyPI", "openai-mcp", "MAL-2026-5320", "2.41.1 2.41.2"],
	["PyPI", "tiktoken-mcp", "MAL-2026-5326", "0.13.1 0.13.2"],
	["PyPI", "instructor-mcp", "MAL-2026-5317", "1.15.2 1.15.3"],
	["PyPI", "langchain-core-mcp", "MAL-2026-5318", "1.4.2 1.4.3"],
	["PyPI", "ray-mcp-server", "MAL-2026-5325", "0.2.1"],
	["PyPI", "docontrol-mcp", "MAL-2026-4811", "999.0.0"],
	["PyPI", "vulndify-mcp-server", "MAL-2026-4774", "0.3.0"],
	["PyPI", "ant-mcp-proxy-for-test", "MAL-2026-2669", "0.10.0"],
	["PyPI", "latinum-wallet-mcp", "MAL-2026-2315", "0.0.32 0.0.33 0.0.34 0.0.35 0.0.36"],
	["PyPI", "mcp-transport-proto", "MAL-2026-1990", "9.9.9"],
	["PyPI", "mcp-pdftool-plus", "MAL-2026-603", "0.1.3 0.1.4 0.1.5"],
	["PyPI", "mcp-weather-full", "MAL-2025-191789", "0.8.0 0.8.1 0.8.2 0.8.3 0.8.4 0.8.5 0.8.6 0.8.7 0.8.8 0.8.9 0.9.0 0.9.1 0.9.2 0.9.3 0.9.4 0.9.5 0.9.6 1.0.0 1.0.1"],
	["PyPI", "mcp-runcmd-server", "MAL-2025-191788", "1.0 2.0"],
	["PyPI", "mcp-runcommand-server2", "MAL-2025-191648", "1.0.6"],
	["PyPI", "mcp-runcommand-server", "MAL-2025-191647", "1.0.5 1.0.7 1.0.8 1.0.9 1.0.10 1.0.11 1.0.12 1.0.13"],
	["PyPI", "groq-mcp", "MAL-2025-6007", "0.0.1 9.9.9"],
	["PyPI", "story-mcp-hub", "MAL-2025-3471", "9999.0.0"],
	["PyPI", "mcp-xyz", "MAL-2025-4223", "0.1.0"],
];

// Packages, by "ecosystem:name". `versions` is "all" when every version is
// unsafe (including a copy that looks harmless), or the versions that were
// malware.
const listedPackage = (ref, versions, kind) =>
	versions === "all"
		? { versions: "all", what: `${kind} listed as malware`, source: `OSV ${ref}` }
		: { versions: versions.split(" "), what: `${kind} with versions listed as malware`, source: `OSV ${ref}` };
export const KNOWN_PACKAGES = {
	...Object.fromEntries(OSV_MALWARE.map(([ecosystem, name, ref, versions]) => [`${ecosystem}:${name}`, listedPackage(ref, versions, versions === "all" ? "an MCP server" : "an MCP package")])),
	"npm:postmark-mcp": {
		versions: "all",
		what: "a copy of Postmark's MCP server published by someone else. From version 1.0.16 it secretly copied every email it sent to the publisher",
		source: "Koi Security, September 2025",
		was: { source: ["Dark Reading, September 2025"] },
	},
	"npm:@lanyer640/mcp-runcommand-server": {
		versions: "all",
		what: "an MCP server that, from version 1.0.6, opens a reverse shell to the attacker as soon as it's installed",
		source: "Checkmarx, October 2025",
	},
	"npm:mcp-server-github": {
		versions: "all",
		what: "a lookalike of the official @modelcontextprotocol/server-github that reports details of every computer it's installed on",
		source: "OSV MAL-2026-5479",
	},
	"npm:@atlisp/mcp": {
		versions: ["1.12.14"],
		what: "an MCP package whose version 1.12.14 is malware that can take over the computer",
		source: "Helix threat watch, October 2026",
	},
	"npm:@revizahoshii/hoshino-mcp-server": { versions: "all", what: "an MCP server listed as malware", source: "OSV MAL-2026-17825" },
	"npm:@httttt/mcp-npx-fetch-1": { versions: "all", what: "an MCP server listed as malware", source: "OSV MAL-2026-16422" },
	"npm:ubiquiti-agents-link-mcp": { versions: "all", what: "an MCP server listed as malware", source: "OSV MAL-2026-16409" },
	// The s1ngularity attack: malicious Nx releases that used installed AI
	// agents (claude, gemini, q) with their safety flags off to hunt for secrets.
	...Object.fromEntries(
		[
			["nx", ["20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0"]],
			["@nx/devkit", ["20.9.0", "21.5.0"]],
			["@nx/js", ["20.9.0", "21.5.0"]],
			["@nx/node", ["20.9.0", "21.5.0"]],
			["@nx/workspace", ["20.9.0", "21.5.0"]],
			["@nx/eslint", ["21.5.0"]],
			["@nx/enterprise-cloud", ["3.2.0"]],
			["@nx/key", ["3.2.0"]],
		].map(([name, versions]) => [
			`npm:${name}`,
			{
				versions,
				what: "a release replaced with malware in the s1ngularity attack. It ran the AI agents on the computer with their safety checks off to find secrets, and published them",
				source: "Nx advisory GHSA-cxm3-wv7p-598c",
			},
		]),
	),
};

// Editor extensions, by lowercase "publisher.name". `editors` limits an entry
// to the editors whose marketplace served the bad build.
const GLASSWORM = {
	versions: "all",
	what: "one of the extensions in the GlassWorm campaign, which installs remote-access malware",
	source: "The Hacker News, December 2025",
};
// Editors that install from Open VSX, and those that use Microsoft's
// marketplace. The same extension ID can belong to different publishers on
// each, so a listing for one doesn't apply to the other.
export const OPEN_VSX_EDITORS = ["VSCodium", "Cursor", "Windsurf", "Kiro"];
const MICROSOFT_EDITORS = ["VS Code", "VS Code Insiders"];
// Extensions OSV.dev lists as malware, as of November 2, 2026: ID, the
// marketplace it names, the listing, and the versions it names or "all".
const OSV_EXTENSIONS = [
	["azurecdninfo.edrtester", "microsoft", "MAL-2026-16010", "1.0.4"],
	["nrwl.angular-console", "both", "MAL-2026-5161", "18.95.0"],
	["checkmarx.ast-results", "open-vsx", "MAL-2026-2231", "2.35.0 2.36.0 2.37.0 2.38.0 2.39.0 2.40.0 2.42.0 2.43.0 2.44.0 2.45.0 2.46.0 2.47.0 2.48.0 2.49.0 2.49.1772191521 2.49.1772192163 2.50.0 2.51.0 2.52.0 2.53.0 2.56.0"],
	["checkmarx.cx-dev-assist", "open-vsx", "MAL-2026-2232", "1.1.0 1.2.0 1.3.0 1.3.1772191535 1.3.1772192178 1.4.0 1.5.0 1.6.0 1.7.0 1.10.0"],
	["aquasecurityofficial.trivy-vulnerability-scanner", "open-vsx", "MAL-2026-2230", "1.8.12 1.8.13"],
	["effetmer.darkgpt", "microsoft", "MAL-2025-192568", "all"],
	["cline-ai-main.cline-ai-agent", "microsoft", "MAL-2025-191157", "all"],
	["codeinklingon.git-worktree-menu", "open-vsx", "MAL-2025-191158", "all"],
	["codejoy.codejoy-vscode-extension", "open-vsx", "MAL-2025-191159", "all"],
	["ellacrity.recoil", "open-vsx", "MAL-2025-191160", "all"],
	["ginfuru.better-nunjucks", "open-vsx", "MAL-2025-191161", "all"],
	["grrrck.positron-plus-1-e", "open-vsx", "MAL-2025-191162", "all"],
	["jeronimoekerdt.color-picker-universal", "open-vsx", "MAL-2025-191163", "all"],
	["jscearcy.rust-doc-viewer", "open-vsx", "MAL-2025-191164", "all"],
	["kleinesfilmroellchen.serenity-dsl-syntaxhighlight", "open-vsx", "MAL-2025-191165", "all"],
	["l-igh-t.vscode-theme-seti-folder", "open-vsx", "MAL-2025-191166", "all"],
	["sirilmp.dark-theme-sm", "open-vsx", "MAL-2025-191167", "all"],
	["sissel.shopify-liquid", "open-vsx", "MAL-2025-191168", "all"],
	["srcery-colors.srcery-colors", "open-vsx", "MAL-2025-191169", "all"],
	["tretinv3.forts-api-extention", "open-vsx", "MAL-2025-191170", "all"],
];
const listedExtension = (marketplace, ref, versions) => ({
	versions: versions === "all" ? "all" : versions.split(" "),
	...(marketplace === "both" ? {} : { editors: marketplace === "open-vsx" ? OPEN_VSX_EDITORS : MICROSOFT_EDITORS }),
	what: versions === "all" ? "an extension listed as malware" : "a release listed as malware",
	source: `OSV ${ref}`,
});
export const KNOWN_EXTENSIONS = {
	...Object.fromEntries(OSV_EXTENSIONS.map(([id, marketplace, ref, versions]) => [id, listedExtension(marketplace, ref, versions)])),
	"anthropic.claude-code": {
		versions: ["2.1.312", "2.1.313"],
		editors: ["Cursor"],
		what: "a tampered build of the Claude Code extension that Cursor's marketplace served on October 29, 2026. It adds an SSH key to ~/.ssh/authorized_keys and opens a tunnel to the attacker",
		source: "StepSecurity, October 2026",
		advice: "Uninstall it, delete any key ending in svc-telemetry from ~/.ssh/authorized_keys, and follow Cursor's security notice for this extension",
	},
	...Object.fromEntries(
		[
			"iconkieftwo.icon-theme-materiall",
			"prisma-inc.prisma-studio-assistance",
			"prettier-vsc.vsce-prettier",
			"flutcode.flutter-extension",
			"csvmech.csvrainbow",
			"codevsce.codelddb-vscode",
			"saoudrizvsce.claude-devsce",
			"saoudrizvsce.claude-dev",
			"clangdcode.clangd-vsce",
			"cweijamysq.sync-settings-vscode",
			"bphpburnsus.iconesvscode",
			"bphpburn.icons-vscode",
			"klustfix.kluster-code-verify",
			"vims-vsce.vscode-vim",
			"yamlcode.yaml-vscode-extension",
			"solblanco.svetle-vsce",
			"vsceue.volar-vscode",
			"redmat.vscode-quarkus-pro",
			"msjsdreact.react-native-vsce",
			"tailwind-nuxt.tailwindcss-for-react",
			"vitalik.solidity",
		].map((id) => [id, GLASSWORM]),
	),
};

// Malware OSV.dev has listed since KNOWN_AS_OF, as misconfig.ai publishes it
// at /api/known: {v: 1, updated, packages: [["npm:name", ref, versions]],
// extensions: [[id, marketplace, ref, versions]]}, where versions is "all" or
// the versions listed, separated by spaces, and an extension listed on both
// marketplaces comes once for each. It comes over the network, so every value
// must match the shape the lists above use, and anything else is dropped.
// Entries in the lists above are never changed. What an earlier list added is
// replaced, so a listing that's changed or withdrawn is changed or gone here
// too. Returns the keys it holds and when the list was made, or null if it
// isn't a list.
const LISTED_REF = /^MAL-\d{4}-\d{1,7}$/;
const LISTED_NAME = {
	npm: /^(?:@[a-z0-9~][a-z0-9._~-]{0,100}\/)?[a-z0-9~][a-z0-9._~-]{0,213}$/,
	PyPI: /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/,
};
const LISTED_EXTENSION = /^[a-z0-9][a-z0-9-]{0,99}\.[a-z0-9][a-z0-9._-]{0,99}$/;
export const MAX_LISTED_VERSIONS = 2000;
const listedVersions = (v) => typeof v === "string" && (v === "all" || (v.length <= 40_000 && v.split(" ").length <= MAX_LISTED_VERSIONS && v.split(" ").every((x) => VERSION_RE.test(x))));
const FROM_LIST = { packages: new Set(), extensions: new Set() };
export function addKnownMalware(feed) {
	const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
	if (!isObj(feed) || feed.v !== 1 || typeof feed.updated !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(feed.updated) || Number.isNaN(Date.parse(feed.updated))) return null;
	const ours = (list, key) => !Object.hasOwn(list === "packages" ? KNOWN_PACKAGES : KNOWN_EXTENSIONS, key) || FROM_LIST[list].has(key);
	const packages = new Map();
	for (const p of Array.isArray(feed.packages) ? feed.packages.slice(0, 20_000) : []) {
		if (!Array.isArray(p) || p.length !== 3) continue;
		const [key, ref, versions] = p;
		const m = typeof key === "string" ? /^(npm|PyPI):(.+)$/.exec(key) : null;
		if (!m || !LISTED_NAME[m[1]].test(m[2]) || typeof ref !== "string" || !LISTED_REF.test(ref) || !listedVersions(versions) || !ours("packages", key) || packages.has(key)) continue;
		packages.set(key, listedPackage(ref, versions, "a package"));
	}
	const extensions = new Map();
	for (const x of Array.isArray(feed.extensions) ? feed.extensions.slice(0, 5000) : []) {
		if (!Array.isArray(x) || x.length !== 4) continue;
		const [id, marketplace, ref, versions] = x;
		if (typeof id !== "string" || !LISTED_EXTENSION.test(id) || !["microsoft", "open-vsx", "both"].includes(marketplace) || typeof ref !== "string" || !LISTED_REF.test(ref) || !listedVersions(versions) || !ours("extensions", id)) continue;
		const entry = listedExtension(marketplace, ref, versions);
		const had = extensions.get(id);
		// A listing for each marketplace: the second is kept beside the first,
		// for the editors that install from there.
		if (!had) extensions.set(id, entry);
		else if (!had.alt && had.editors && entry.editors && had.editors !== entry.editors) had.alt = entry;
	}
	for (const [list, now, into] of [["packages", packages, KNOWN_PACKAGES], ["extensions", extensions, KNOWN_EXTENSIONS]]) {
		for (const key of FROM_LIST[list]) if (!now.has(key)) delete into[key];
		for (const [key, entry] of now) into[key] = entry;
		FROM_LIST[list] = new Set(now.keys());
	}
	return { updated: feed.updated, packages: [...packages.keys()], extensions: [...extensions.keys()] };
}

// The listing of an extension that applies to an editor: listings for one
// marketplace apply only to the editors that install from it.
export function extensionListing(id, editor) {
	const entry = Object.hasOwn(KNOWN_EXTENSIONS, id) ? KNOWN_EXTENSIONS[id] : null;
	for (const e of entry ? [entry, entry.alt] : []) if (e && (!e.editors || e.editors.includes(editor))) return e;
	return null;
}

// The official extensions of AI coding agents. Another publisher's extension
// with the same name, or a near copy of the name and publisher, is flagged.
export const AGENT_EXTENSIONS = {
	"anthropic.claude-code": "Claude Code",
	"saoudrizwan.claude-dev": "Cline",
	"rooveterinaryinc.roo-cline": "Roo Code",
	"kilocode.kilo-code": "Kilo Code",
	"github.copilot": "GitHub Copilot",
	"github.copilot-chat": "GitHub Copilot Chat",
	"google.geminicodeassist": "Gemini Code Assist",
	"amazonwebservices.amazon-q-vscode": "Amazon Q",
	"continue.continue": "Continue",
};

// Agents installed as npm packages, and their published security advisories:
// GitHub's advisory pages for anthropics/claude-code and openai/codex.
// Versions from `introduced` up to, not including, `fixed` are affected.
// Gemini CLI had none published there.
export const AGENT_PACKAGES = {
	"@anthropic-ai/claude-code": { tool: "Claude Code", update: { npm: "npm install -g @anthropic-ai/claude-code@latest", native: "claude update", homebrew: "brew upgrade claude-code", local: "claude update" } },
	"@openai/codex": { tool: "Codex", update: { npm: "npm install -g @openai/codex@latest", homebrew: "brew upgrade codex" } },
	"@google/gemini-cli": { tool: "Gemini CLI", update: { npm: "npm install -g @google/gemini-cli@latest", homebrew: "brew upgrade gemini-cli" } },
	"@github/copilot": { tool: "GitHub Copilot", update: { npm: "npm install -g @github/copilot@latest" } },
	"opencode-ai": { tool: "OpenCode", update: { npm: "npm install -g opencode-ai@latest" } },
	"@sourcegraph/amp": { tool: "Amp", update: { npm: "npm install -g @sourcegraph/amp@latest" } },
	"Claude Desktop": { tool: "Claude Desktop", update: { app: "Open Claude Desktop and install the update it offers, or download the latest from claude.ai/download" } },
};

const cc = (id, cve, severity, title, introduced, fixed) => ({ id, cve, severity, title, introduced, fixed });
export const AGENT_ADVISORIES = {
	"@anthropic-ai/claude-code": [
		cc("GHSA-pq7j-f95f-qfcv", "CVE-2026-86063", "high", "a plugin's pinned commit could be bypassed to install attacker-controlled code", "0.0.0", "2.1.179"),
		cc("GHSA-5j29-h97v-84ch", "CVE-2026-103435", "high", "a symlink could redirect a file write anywhere", "0.0.0", "2.1.129"),
		cc("GHSA-gfvf-j8jh-jxxw", "CVE-2026-103012", "low", "managed settings weren't applied when a stored API key was used", "2.0.68", "2.1.260"),
		cc("GHSA-7835-87q9-rgvv", "CVE-2026-55607", "high", "a git worktree could escape the sandbox", "2.1.38", "2.1.163"),
		cc("GHSA-fg94-h982-f3mm", "CVE-2026-54316", "medium", "data could leak through a pre-approved domain in WebFetch", "0.2.54", "2.1.163"),
		cc("GHSA-4vp2-6q8c-pvq2", "CVE-2026-46406", "medium", "the /copy command used an insecure temporary file", "2.1.59", "2.1.128"),
		cc("GHSA-5cwg-9f6j-9jvx", "CVE-2026-35603", "medium", "system-wide settings were loaded insecurely on Windows", "0.0.0", "2.1.75"),
		cc("GHSA-q5hj-mxqh-vv77", "CVE-2026-40068", "high", "a spoofed git worktree could skip the trust dialog and run code", "2.1.63", "2.1.84"),
		cc("GHSA-vp62-r36r-9xqp", "CVE-2026-39861", "high", "a symlink could write files outside the workspace and escape the sandbox", "0.0.0", "2.1.64"),
		cc("GHSA-mmgp-wc2j-qcv7", "CVE-2026-33068", "high", "a repository's settings file could skip the workspace trust dialog", "0.0.0", "2.1.53"),
		cc("GHSA-ff64-7w26-62rf", "CVE-2026-25725", "high", "settings.json could be changed to escape the sandbox", "0.0.0", "2.1.2"),
		cc("GHSA-4q92-rfm6-2cqx", "CVE-2026-25724", "low", "symbolic links could get around deny rules", "0.0.0", "2.1.7"),
		cc("GHSA-66q4-vfjg-2qhh", "CVE-2026-25722", "high", "changing directory could bypass write protection", "0.0.0", "2.0.57"),
		cc("GHSA-mhg7-666j-cqg4", "CVE-2026-25723", "high", "a piped sed command could bypass file write restrictions", "0.0.0", "2.0.55"),
		cc("GHSA-vhw5-3g5m-8ggf", "CVE-2026-24052", "high", "domain checks could be bypassed to reach attacker-controlled sites", "0.0.0", "1.0.111"),
		cc("GHSA-qgqw-h4xq-7w8w", "CVE-2026-24887", "high", "a find command could run without the approval prompt", "0.0.0", "2.0.72"),
		cc("GHSA-q728-gf8j-w49r", "CVE-2026-24053", "high", "a zsh feature could write files outside allowed paths", "0.0.0", "2.0.74"),
		cc("GHSA-jh7p-qr78-84p7", "CVE-2026-21852", "medium", "a repository's configuration could leak data before the trust prompt", "0.0.0", "2.0.65"),
		cc("GHSA-xq4m-mc3c-vvg3", "CVE-2025-66032", "high", "command validation could be bypassed to run any code", "0.0.0", "1.0.93"),
		cc("GHSA-5hhx-v7f6-x7gv", "CVE-2025-65099", "high", "commands could run before the startup trust dialog", "0.0.0", "1.0.39"),
		cc("GHSA-7mv8-j34q-vp7q", "CVE-2025-64755", "high", "a sed command could write files without approval", "0.0.0", "2.0.31"),
		cc("GHSA-66m2-gx93-v996", "CVE-2025-59829", "low", "a symlink could get around deny rules", "0.0.0", "1.0.120"),
		cc("GHSA-2jjv-qf24-vfm4", "CVE-2025-59828", "high", "plugins could autoload and run code with some Yarn versions", "0.0.0", "1.0.39"),
		cc("GHSA-4fgq-fpq9-mr3g", "CVE-2025-59536", "high", "commands could run before the startup trust dialog", "0.0.0", "1.0.111"),
		cc("GHSA-j4h9-wv2m-wrf7", "CVE-2025-59041", "high", "a crafted git email setting could run code", "0.0.0", "1.0.105"),
		cc("GHSA-qxfv-fcpc-w36x", "CVE-2025-58764", "high", "an rg command could run without the approval prompt", "0.0.0", "1.0.105"),
		cc("GHSA-ph6w-f82w-28w6", null, "high", "the startup warning wasn't enough to stop code from running", "0.0.0", "1.0.87"),
		cc("GHSA-x5gv-jw7f-j6xj", "CVE-2025-55284", "high", "a permissive default allowlist let files be read and sent out", "0.0.0", "1.0.4"),
		cc("GHSA-x56v-x2h6-7j34", "CVE-2025-54795", "high", "an echo command could run without the approval prompt", "0.0.0", "1.0.20"),
		cc("GHSA-pmw4-pwvc-3hx2", "CVE-2025-54794", "high", "similar path names could get around path restrictions", "0.0.0", "0.2.111"),
		cc("GHSA-9f65-56v6-gxw7", "CVE-2025-52882", "high", "the IDE extensions accepted connections from any website", "0.2.117", "1.0.24"),
	],
	"@openai/codex": [cc("GHSA-w5fx-fh39-j5rw", "CVE-2025-59532", "high", "a bug in path handling could bypass the sandbox", "0.2.0", "0.39.0")],
	// Claude Desktop builds are on GitHub's anthropics/claude-code advisory pages too.
	"Claude Desktop": [
		{ ...cc("GHSA-v234-4jrq-mgg6", null, "high", "opening a file from a Cowork folder could run commands", "1.1.3918", "1.15962.0"), platforms: ["mac"] },
		{ ...cc("GHSA-4p2j-qj3c-6x84", "CVE-2026-88066", "high", "a malicious git program could be run from the search path", "0.0.0", "1.8089.0"), platforms: ["windows"] },
		{ ...cc("GHSA-5p5x-5294-qhp3", "CVE-2026-44470", "high", "a directory junction could give local administrator access", "0.0.0", "1.3834.0"), platforms: ["windows"] },
		cc("GHSA-3rwf-2g6p-c2f9", "CVE-2026-44467", "high", "SSH host keys weren't checked for remote sessions", "1.2581.0", "1.4304.0"),
	],
};

// Files that attacks on AI agents and their users leave behind, checked by
// name only. `strong` marks names nothing else is likely to use.
export const TRACES = [
	{
		paths: ["/tmp/inventory.txt.bak"],
		strong: true,
		campaign: "s1ngularity",
		what: "The s1ngularity attack used AI agents on the computer to list secret files here",
		fix: "Rotate your GitHub, npm and cloud keys, check ~/.bashrc and ~/.zshrc for a line that shuts the computer down, and remove the file once you've looked at it",
		platforms: ["mac", "linux"],
	},
	{
		paths: ["/tmp/inventory.txt"],
		strong: false,
		campaign: "s1ngularity",
		what: "The s1ngularity attack used AI agents on the computer to list secret files under this name. Other tools can use the same name",
		fix: "If you didn't make it, open it: a list of key and wallet files means the attack ran. Then rotate your GitHub, npm and cloud keys",
		platforms: ["mac", "linux"],
	},
	{
		paths: ["~/.dev-env/.runner", "~/.dev-env/run.sh", "~/.dev-env/config.sh"],
		strong: true,
		campaign: "Shai-Hulud 2.0",
		what: "Shai-Hulud 2.0 installs a GitHub Actions runner in ~/.dev-env so its owners can run code on this computer",
		fix: "Disconnect the runner, delete ~/.dev-env, rotate your GitHub, npm and cloud keys, and check your repositories for workflows you didn't add",
	},
	{
		paths: ["~/Library/LaunchAgents/com.apple.sysmond.plist"],
		strong: true,
		campaign: "the tampered Claude Code extension for Cursor",
		what: "The tampered Claude Code extension served by Cursor's marketplace in October 2026 starts an SSH tunnel to the attacker from this file at login",
		fix: "Remove the file and the extension, delete any key ending in svc-telemetry from ~/.ssh/authorized_keys, and follow Cursor's security notice",
		platforms: ["mac"],
	},
	{
		paths: ["~/.config/.smt", "~/.config/.smtk", "~/.config/smt.cmd", "~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/sysmon.cmd"],
		strong: true,
		campaign: "the tampered Claude Code extension for Cursor",
		what: "The tampered Claude Code extension served by Cursor's marketplace in October 2026 keeps its SSH tunnel running with a file in ~/.config or the Windows Startup folder",
		fix: "Remove the extension and what it left, delete any key ending in svc-telemetry from ~/.ssh/authorized_keys (and the SysMon scheduled task on Windows), and follow Cursor's security notice",
		was: {
			what: ["The tampered Claude Code extension served by Cursor's marketplace in October 2026 keeps its SSH tunnel running with these files"],
			fix: ["Remove the files and the extension, delete any key ending in svc-telemetry from ~/.ssh/authorized_keys (and the SysMon scheduled task on Windows), and follow Cursor's security notice"],
		},
	},
];

// A line attacks add to shell startup files.
export const SHELL_TRACES = [
	{
		line: /^\s*sudo\s+shutdown\s+-h\s+0\s*$/,
		campaign: "s1ngularity",
		what: "The s1ngularity attack added this line, which shuts the computer down whenever a terminal opens",
		fix: "Delete the line, then change your GitHub, npm and cloud keys: the same attack collected them",
	},
];

// Workflows worms add to repositories they reach. `strong` marks a match
// on the workflow's content or a name nothing else uses.
export const WORKFLOW_TRACES = [
	{
		name: /(^|\/)\.github\/workflows\/discussion\.ya?ml$/i,
		content: (text) => /github\.event\.discussion\.body/.test(text) && /self-hosted/i.test(text),
		strong: true,
		campaign: "Shai-Hulud 2.0",
		what: "Shai-Hulud 2.0 adds this workflow so anyone who opens a GitHub discussion can run code on a self-hosted runner",
		fix: "Delete the workflow, remove self-hosted runners you didn't add, and change the repository's secrets and your GitHub and npm tokens",
	},
	{
		name: /(^|\/)\.github\/workflows\/formatter_\d{3,}\.ya?ml$/i,
		strong: false,
		campaign: "Shai-Hulud 2.0",
		what: "Shai-Hulud 2.0 adds a workflow named like this that copies the repository's secrets",
		fix: "If you didn't add it, delete it and change the repository's secrets and your GitHub and npm tokens",
	},
	{
		name: /(^|\/)\.github\/workflows\/shai-?hulud-?workflow\.ya?ml$/i,
		strong: true,
		campaign: "Shai-Hulud",
		what: "The Shai-Hulud worm adds this workflow to repositories it reaches",
		fix: "Delete the workflow, then change the repository's secrets and your GitHub and npm tokens",
	},
];

// Hosts and addresses named in these reports as attackers' servers.
export const KNOWN_BAD_HOSTS = {
	"91.92.242.30": "the ClawHub skills attack (Snyk, February 2026)",
	"134.209.82.225": "the tampered Claude Code extension for Cursor (StepSecurity, October 2026)",
	"45.115.38.27": "the @lanyer640/mcp-runcommand-server reverse shell (Checkmarx, October 2025)",
	"giftshop.club": "the postmark-mcp email theft (Koi Security, September 2025)",
	"npx-canary-log.vulnerable-live.workers.dev": "the mcp-server-github lookalike (OSV MAL-2026-5479)",
};

// Official MCP packages people mean to install. A name a letter or two away,
// or one copied without its scope, is flagged as a lookalike.
export const OFFICIAL_MCP_PACKAGES = [
	...["filesystem", "github", "gitlab", "memory", "puppeteer", "brave-search", "google-maps", "slack", "postgres", "everything", "sequential-thinking", "gdrive", "aws-kb-retrieval", "redis", "everart"].map((s) => `@modelcontextprotocol/server-${s}`),
	"@playwright/mcp",
	"@upstash/context7-mcp",
	"@notionhq/notion-mcp-server",
	"@stripe/mcp",
	"@supabase/mcp-server-supabase",
	"@sentry/mcp-server",
	"@cloudflare/mcp-server-cloudflare",
	"@azure/mcp",
	"mcp-remote",
	"firecrawl-mcp",
	"@anthropic-ai/claude-code",
	"@openai/codex",
	"@google/gemini-cli",
];
export const OFFICIAL_PYPI_MCP = ["mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp"];

// Versions in the order semver gives them: numbers part by part, and a
// pre-release such as 2.0.0-beta.1 before its release. Build data after +
// doesn't count.
export function compareVersions(a, b) {
	const parse = (v) => {
		const text = String(v).replace(/^v/, "").split("+")[0];
		const dash = text.indexOf("-");
		return {
			main: (dash < 0 ? text : text.slice(0, dash)).split(".").map((n) => Number.parseInt(n, 10) || 0),
			pre: dash < 0 ? [] : text.slice(dash + 1).split("."),
		};
	};
	const pa = parse(a);
	const pb = parse(b);
	for (let i = 0; i < Math.max(pa.main.length, pb.main.length, 3); i++) {
		const d = (pa.main[i] ?? 0) - (pb.main[i] ?? 0);
		if (d) return d < 0 ? -1 : 1;
	}
	if (!pa.pre.length || !pb.pre.length) return pa.pre.length === pb.pre.length ? 0 : pa.pre.length ? -1 : 1;
	for (let i = 0; i < Math.max(pa.pre.length, pb.pre.length); i++) {
		const x = pa.pre[i];
		const y = pb.pre[i];
		if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
		if (x === y) continue;
		const nx = /^\d+$/.test(x);
		const ny = /^\d+$/.test(y);
		if (nx && ny) return Number(x) < Number(y) ? -1 : 1;
		if (nx !== ny) return nx ? -1 : 1;
		return x < y ? -1 : 1;
	}
	return 0;
}

// Up to ten digits a part, for builds numbered by date, such as 2.49.1772191521.
export const VERSION_RE = /^v?\d{1,10}(?:\.\d{1,10}){1,3}(?:[-+][0-9A-Za-z.-]{1,40})?$/;
