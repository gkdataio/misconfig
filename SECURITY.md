# Security policy

misconfig reads the files that control AI coding agents, so a bug in it can matter more than a bug in most tools. If you find one, please tell us privately.

## Reporting a vulnerability

Email [security@misconfig.ai](mailto:security@misconfig.ai), or use **Report a vulnerability** on this repository's Security tab. Please include:

- what you found and where,
- the steps or files that reproduce it,
- what an attacker could do with it.

Please don't open a public issue for a vulnerability, and don't include anyone else's data.

## What to expect

- A reply within 3 business days, and updates until it's fixed.
- A disclosure date agreed with you. Unless we agree otherwise, please wait until it's fixed or 90 days have passed, whichever comes first.
- Credit in the release notes, if you'd like it.

## In scope

- The `@misconfig/cli` command and everything in this repository.
- A file or folder that makes a check run code, read something it says it doesn't, send something it says it doesn't, or hang.
- A crafted file that makes the terminal report or the page `--open` saves show markup or words its checks wouldn't produce.
- Ways a risky setting can hide from the checks. These are welcome even when they aren't vulnerabilities in the strict sense.

Issues with the misconfig.ai website are covered by the policy at [misconfig.ai/security](https://misconfig.ai/security).
