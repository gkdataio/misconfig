# Releasing

A release of `@misconfig/cli` is packed by GitHub Actions from a tagged commit on `main`, tried on Linux, macOS and Windows, and staged on npm. Nobody can install it until a maintainer approves it on npm with two-factor authentication. GitHub holds no npm token.

## Make a release

1. On a branch named `release-` and the version, set the version in `package.json`, write its section at the top of `CHANGELOG.md`, and update the version the README and the example workflows name. `node --test` fails until they agree. Each push to the branch runs the tests and a rehearsal, which packs the archive and tries it on every system.
2. Merge the branch into `main`.
3. Tag the merged commit with `v` and the version, and push the tag.

   ```sh
   git tag v1.5.0
   git push origin v1.5.0
   ```

   [The release workflow](../.github/workflows/release.yml) checks that the tag matches `package.json` and is on `main`. It runs the tests, packs the archive, and installs and runs that archive on Linux, macOS and Windows with Node.js 18 and 24. Then it stages the archive on npm with its provenance, and drafts a GitHub release with the archive attached.
4. On npmjs.com, open the staged packages, check the staged version and approve it. `npm stage list @misconfig/cli` and `npm stage approve` with the ID it shows do the same from a terminal. Until then, npm installs the version it did before.
5. Publish the draft release on GitHub.

To take a staged release back, reject it on npm instead of approving it.

## Set up once

Staging is off until both of these are done. Until then, a tag is tested, packed and tried, and nothing is sent to npm.

1. Tell npm that this repository's release workflow may stage releases. The command needs npm 11.15.0 or later, and asks for two-factor authentication.

   ```sh
   npm trust github @misconfig/cli --file release.yml --repo gkdataio/misconfig --env npm --allow-stage-publish
   ```

   The package's settings on npmjs.com can do the same, as a trusted publisher: GitHub Actions, with `gkdataio`, `misconfig`, `release.yml` and the environment `npm`, allowed to stage and not to publish.
2. In the repository's settings on GitHub, under the variables for Actions, add a repository variable named `STAGE_ON_NPM` with the value `true`.

The workflow stages from an environment named `npm`, which GitHub creates the first time it's used. In the repository's settings, the environment can be limited to tags that start with `v`, and can wait for a reviewer before staging.
